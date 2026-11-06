//! Alarms (CO-07): rule evaluation queries + alarm table.

use serde_json::Value as Json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::scope::scope_param;
use crate::{DeviceFilter, DeviceScope, Result, Store};

/// Raised or cleared alarm.
#[derive(Debug, Clone, PartialEq)]
pub struct Alarm {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub rule: String,
    /// `critical`, `major`, `minor` or `warning`.
    pub severity: String,
    /// `active` or `cleared`.
    pub state: String,
    /// Summary for humans.
    pub message: String,
    /// Rule-specific values.
    pub detail: Json,
    pub raised_at: OffsetDateTime,
    pub cleared_at: Option<OffsetDateTime>,
    pub acked_at: Option<OffsetDateTime>,
    pub acked_by: Option<String>,
    /// Silence active at raise -> not notified.
    pub silenced_by: Option<Uuid>,
}

/// Device a rule matches now + observed value.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleHit {
    pub device_id: Uuid,
    /// Minutes offline, metric value, event count or minutes without WireGuard handshake.
    pub value: f64,
}

impl Store {
    /// Raise alarm unless one active for device + rule -> new alarm.
    #[allow(clippy::too_many_arguments)]
    pub async fn raise_alarm(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        rule: &str,
        severity: &str,
        message: &str,
        detail: &Json,
        silenced_by: Option<Uuid>,
    ) -> Result<Option<Alarm>> {
        Ok(sqlx::query_as!(
            Alarm,
            r#"
            INSERT INTO alarms (id, tenant_id, device_id, rule, severity, message, detail,
                                silenced_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (device_id, rule) WHERE state = 'active' DO NOTHING
            RETURNING id, tenant_id, device_id, rule, severity, state, message, detail,
                      raised_at, cleared_at, acked_at, acked_by, silenced_by
            "#,
            Uuid::now_v7(),
            tenant_id,
            device_id,
            rule,
            severity,
            message,
            detail,
            silenced_by
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Clear active alarms of the rule, except on `still_matching` devices -> cleared alarms.
    pub async fn clear_alarms_except(
        &self,
        tenant_id: Uuid,
        rule: &str,
        still_matching: &[Uuid],
    ) -> Result<Vec<Alarm>> {
        Ok(sqlx::query_as!(
            Alarm,
            r#"
            UPDATE alarms SET state = 'cleared', cleared_at = now()
            WHERE tenant_id = $1 AND rule = $2 AND state = 'active'
              AND NOT (device_id = ANY($3))
            RETURNING id, tenant_id, device_id, rule, severity, state, message, detail,
                      raised_at, cleared_at, acked_at, acked_by, silenced_by
            "#,
            tenant_id,
            rule,
            still_matching
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Active devices matching `filter`, no contact for `minutes`.
    pub async fn offline_devices(
        &self,
        tenant_id: Uuid,
        filter: &DeviceFilter,
        minutes: i64,
    ) -> Result<Vec<RuleHit>> {
        let rows = sqlx::query!(
            r#"
            SELECT d.id, EXTRACT(EPOCH FROM now() - d.last_contact_at)::float8 / 60 AS "minutes!"
            FROM devices d
            WHERE d.tenant_id = $1 AND d.status = 'active'
              AND d.last_contact_at < now() - make_interval(mins => $2::int)
              AND ($3::text IS NULL OR d.protocol = $3)
              AND ($4::text IS NULL OR d.oui = $4)
              AND ($5::text IS NULL OR d.product_class = $5)
              AND (cardinality($6::text[]) = 0 OR d.software_version = ANY($6))
              AND d.tags @> $7::text[]
              AND (cardinality($8::uuid[]) = 0 OR d.id = ANY($8))
              AND d.attributes @> $9::jsonb
            "#,
            tenant_id,
            i32::try_from(minutes).unwrap_or(i32::MAX),
            filter.protocol,
            filter.oui,
            filter.product_class,
            &filter.software_version,
            &filter.tags,
            &filter.device_ids,
            filter.attributes_json()
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| RuleHit {
                device_id: r.id,
                value: r.minutes,
            })
            .collect())
    }

    /// Active devices matching `filter`, WireGuard handshake stale for `minutes`.
    ///
    /// Member: live device member, applied on the CPE, older than `minutes`.
    /// Hub reported within `HUB_SILENT_SECS` (5 min) + no handshake from member for `minutes`
    /// (or never).
    /// Silent hub -> tells nothing about handshakes -> its members = no hits.
    /// Value = max minutes without handshake over the members (no handshake -> since creation).
    pub async fn wg_handshake_stale_devices(
        &self,
        tenant_id: Uuid,
        filter: &DeviceFilter,
        minutes: i64,
    ) -> Result<Vec<RuleHit>> {
        let rows = sqlx::query!(
            r#"
            SELECT d.id,
                   max(EXTRACT(EPOCH FROM now() - COALESCE(s.latest_handshake, m.created_at)))::float8
                       / 60 AS "minutes!"
            FROM devices d
            JOIN wg_members m ON m.device_id = d.id
            JOIN wg_networks n ON n.id = m.network_id AND n.tenant_id = d.tenant_id
            JOIN wg_hubs h ON h.id = n.hub_id
            LEFT JOIN wg_peer_status s ON s.member_id = m.id
            WHERE d.tenant_id = $1 AND d.status = 'active'
              AND m.kind = 'device' AND m.revoked_at IS NULL AND m.device_state = 'applied'
              AND m.created_at < now() - make_interval(mins => $2::int)
              AND h.last_seen_at > now() - make_interval(secs => $10::int8)
              AND (s.latest_handshake IS NULL
                   OR s.latest_handshake < now() - make_interval(mins => $2::int))
              AND ($3::text IS NULL OR d.protocol = $3)
              AND ($4::text IS NULL OR d.oui = $4)
              AND ($5::text IS NULL OR d.product_class = $5)
              AND (cardinality($6::text[]) = 0 OR d.software_version = ANY($6))
              AND d.tags @> $7::text[]
              AND (cardinality($8::uuid[]) = 0 OR d.id = ANY($8))
              AND d.attributes @> $9::jsonb
            GROUP BY d.id
            "#,
            tenant_id,
            i32::try_from(minutes).unwrap_or(i32::MAX),
            filter.protocol,
            filter.oui,
            filter.product_class,
            &filter.software_version,
            &filter.tags,
            &filter.device_ids,
            filter.attributes_json(),
            dhonomos_wireguard::HUB_SILENT_SECS
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| RuleHit {
                device_id: r.id,
                value: r.minutes,
            })
            .collect())
    }

    /// Devices matching `filter`, latest value of `path` above `above` or below `below`.
    pub async fn metric_breaches(
        &self,
        tenant_id: Uuid,
        filter: &DeviceFilter,
        path: &str,
        above: Option<f64>,
        below: Option<f64>,
    ) -> Result<Vec<RuleHit>> {
        let rows = sqlx::query!(
            r#"
            SELECT d.id, dm.last_value
            FROM device_metrics dm
            JOIN metric_names n ON n.id = dm.metric_id
            JOIN devices d ON d.id = dm.device_id
            WHERE d.tenant_id = $1 AND d.status = 'active' AND n.path = $2
              AND (($3::float8 IS NOT NULL AND dm.last_value > $3)
                   OR ($4::float8 IS NOT NULL AND dm.last_value < $4))
              AND ($5::text IS NULL OR d.protocol = $5)
              AND ($6::text IS NULL OR d.oui = $6)
              AND ($7::text IS NULL OR d.product_class = $7)
              AND (cardinality($8::text[]) = 0 OR d.software_version = ANY($8))
              AND d.tags @> $9::text[]
              AND (cardinality($10::uuid[]) = 0 OR d.id = ANY($10))
              AND d.attributes @> $11::jsonb
            "#,
            tenant_id,
            path,
            above,
            below,
            filter.protocol,
            filter.oui,
            filter.product_class,
            &filter.software_version,
            &filter.tags,
            &filter.device_ids,
            filter.attributes_json()
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| RuleHit {
                device_id: r.id,
                value: r.last_value,
            })
            .collect())
    }

    /// Devices matching `filter`, at least `count` events of `kind` in the last `minutes`.
    /// Event detail must contain `detail`.
    pub async fn event_bursts(
        &self,
        tenant_id: Uuid,
        filter: &DeviceFilter,
        kind: &str,
        detail: &Json,
        count: i64,
        minutes: i64,
    ) -> Result<Vec<RuleHit>> {
        let rows = sqlx::query!(
            r#"
            SELECT e.device_id AS "id!", count(*) AS "n!"
            FROM events e JOIN devices d ON d.id = e.device_id
            WHERE e.tenant_id = $1 AND e.kind = $2 AND e.detail @> $3
              AND e.occurred_at > now() - make_interval(mins => $4::int)
              AND d.status = 'active'
              AND ($6::text IS NULL OR d.protocol = $6)
              AND ($7::text IS NULL OR d.oui = $7)
              AND ($8::text IS NULL OR d.product_class = $8)
              AND (cardinality($9::text[]) = 0 OR d.software_version = ANY($9))
              AND d.tags @> $10::text[]
              AND (cardinality($11::uuid[]) = 0 OR d.id = ANY($11))
              AND d.attributes @> $12::jsonb
            GROUP BY e.device_id HAVING count(*) >= $5
            "#,
            tenant_id,
            kind,
            detail,
            i32::try_from(minutes).unwrap_or(i32::MAX),
            count,
            filter.protocol,
            filter.oui,
            filter.product_class,
            &filter.software_version,
            &filter.tags,
            &filter.device_ids,
            filter.attributes_json()
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| RuleHit {
                device_id: r.id,
                value: r.n as f64,
            })
            .collect())
    }

    /// Alarms of a tenant, newest first.
    /// Optional filters: state, 1 device, devices inside `scope`.
    pub async fn list_alarms(
        &self,
        tenant_id: Uuid,
        state: Option<&str>,
        device_id: Option<Uuid>,
        scope: Option<&DeviceScope>,
        limit: i64,
    ) -> Result<Vec<Alarm>> {
        Ok(sqlx::query_as!(
            Alarm,
            r#"
            SELECT id, tenant_id, device_id, rule, severity, state, message, detail,
                   raised_at, cleared_at, acked_at, acked_by, silenced_by
            FROM alarms
            WHERE tenant_id = $1 AND ($2::text IS NULL OR state = $2)
              AND ($3::uuid IS NULL OR device_id = $3)
              AND ($5::jsonb IS NULL OR device_id IN (
                  SELECT d.id FROM devices d WHERE d.tenant_id = $1 AND device_in_scope(d, $5)))
            ORDER BY raised_at DESC LIMIT $4
            "#,
            tenant_id,
            state,
            device_id,
            limit,
            scope_param(scope)
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Alarms raised, cleared or acked at or after `since`.
    /// Optional filters: 1 device, devices inside `scope`.
    pub async fn alarms_changed_since(
        &self,
        tenant_id: Uuid,
        device_id: Option<Uuid>,
        scope: Option<&DeviceScope>,
        since: OffsetDateTime,
    ) -> Result<Vec<Alarm>> {
        Ok(sqlx::query_as!(
            Alarm,
            r#"
            SELECT id, tenant_id, device_id, rule, severity, state, message, detail,
                   raised_at, cleared_at, acked_at, acked_by, silenced_by
            FROM alarms
            WHERE tenant_id = $1 AND ($2::uuid IS NULL OR device_id = $2)
              AND (raised_at >= $3 OR cleared_at >= $3 OR acked_at >= $3)
              AND ($4::jsonb IS NULL OR device_id IN (
                  SELECT d.id FROM devices d WHERE d.tenant_id = $1 AND device_in_scope(d, $4)))
            ORDER BY raised_at LIMIT 1000
            "#,
            tenant_id,
            device_id,
            since,
            scope_param(scope)
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn active_alarm_rules(&self, tenant_id: Uuid) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar!(
            "SELECT DISTINCT rule FROM alarms WHERE tenant_id = $1 AND state = 'active'",
            tenant_id
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Active alarm count per severity (devices inside `scope`).
    pub async fn active_alarm_counts(
        &self,
        tenant_id: Uuid,
        scope: Option<&DeviceScope>,
    ) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query!(
            r#"
            SELECT severity, count(*) AS "n!" FROM alarms
            WHERE tenant_id = $1 AND state = 'active'
              AND ($2::jsonb IS NULL OR device_id IN (
                  SELECT d.id FROM devices d WHERE d.tenant_id = $1 AND device_in_scope(d, $2)))
            GROUP BY severity
            "#,
            tenant_id,
            scope_param(scope)
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| (r.severity, r.n)).collect())
    }

    /// Ack alarm of a device inside `scope` -> alarm, `None` if unknown.
    pub async fn ack_alarm(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        by: &str,
        scope: Option<&DeviceScope>,
    ) -> Result<Option<Alarm>> {
        Ok(sqlx::query_as!(
            Alarm,
            r#"
            UPDATE alarms SET acked_at = COALESCE(acked_at, now()), acked_by = COALESCE(acked_by, $3)
            WHERE id = $1 AND tenant_id = $2
              AND ($4::jsonb IS NULL OR device_id IN (
                  SELECT d.id FROM devices d WHERE d.tenant_id = $2 AND device_in_scope(d, $4)))
            RETURNING id, tenant_id, device_id, rule, severity, state, message, detail,
                      raised_at, cleared_at, acked_at, acked_by, silenced_by
            "#,
            id,
            tenant_id,
            by,
            scope_param(scope)
        )
        .fetch_optional(&self.pool)
        .await?)
    }
}
