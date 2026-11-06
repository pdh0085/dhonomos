//! Alarm silences (maintenance windows).

use time::OffsetDateTime;
use uuid::Uuid;

use crate::{DeviceFilter, Result, Store, StoreError};

/// Silence: alarm of `rule` (or any rule) on matching devices, raised between
/// `starts_at` and `ends_at` -> recorded, not notified.
#[derive(Debug, Clone, PartialEq)]
pub struct Silence {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// Rule name. `None` = every rule.
    pub rule: Option<String>,
    /// Devices it covers.
    pub devices: DeviceFilter,
    pub starts_at: OffsetDateTime,
    pub ends_at: OffsetDateTime,
    /// Reason, e.g. maintenance ticket.
    pub comment: String,
    pub created_by: Option<String>,
    pub created_at: OffsetDateTime,
}

impl Silence {
    /// Covers alarms of `rule` at `now`.
    pub fn applies_to(&self, rule: &str, now: OffsetDateTime) -> bool {
        self.rule.as_deref().is_none_or(|r| r == rule)
            && self.starts_at <= now
            && now < self.ends_at
    }
}

struct Row {
    id: Uuid,
    tenant_id: Uuid,
    rule: Option<String>,
    devices: serde_json::Value,
    starts_at: OffsetDateTime,
    ends_at: OffsetDateTime,
    comment: String,
    created_by: Option<String>,
    created_at: OffsetDateTime,
}

impl TryFrom<Row> for Silence {
    type Error = StoreError;

    fn try_from(r: Row) -> Result<Self> {
        Ok(Self {
            id: r.id,
            tenant_id: r.tenant_id,
            rule: r.rule,
            devices: serde_json::from_value(r.devices)
                .map_err(|e| StoreError::Database(sqlx::Error::Decode(Box::new(e))))?,
            starts_at: r.starts_at,
            ends_at: r.ends_at,
            comment: r.comment,
            created_by: r.created_by,
            created_at: r.created_at,
        })
    }
}

impl Store {
    #[allow(clippy::too_many_arguments)]
    pub async fn create_silence(
        &self,
        tenant_id: Uuid,
        rule: Option<&str>,
        devices: &DeviceFilter,
        starts_at: OffsetDateTime,
        ends_at: OffsetDateTime,
        comment: &str,
        created_by: Option<&str>,
    ) -> Result<Silence> {
        let devices = serde_json::to_value(devices)
            .map_err(|e| StoreError::Database(sqlx::Error::Encode(Box::new(e))))?;
        sqlx::query_as!(
            Row,
            r#"
            INSERT INTO alarm_silences
                (id, tenant_id, rule, devices, starts_at, ends_at, comment, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, tenant_id, rule, devices, starts_at, ends_at, comment, created_by,
                      created_at
            "#,
            Uuid::now_v7(),
            tenant_id,
            rule,
            devices,
            starts_at,
            ends_at,
            comment,
            created_by
        )
        .fetch_one(&self.pool)
        .await?
        .try_into()
    }

    /// Silences not ended (current + future), newest first. `include_ended` -> all.
    pub async fn list_silences(
        &self,
        tenant_id: Uuid,
        include_ended: bool,
    ) -> Result<Vec<Silence>> {
        sqlx::query_as!(
            Row,
            r#"
            SELECT id, tenant_id, rule, devices, starts_at, ends_at, comment, created_by,
                   created_at
            FROM alarm_silences
            WHERE tenant_id = $1 AND ($2 OR ends_at > now())
            ORDER BY created_at DESC LIMIT 1000
            "#,
            tenant_id,
            include_ended
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(Silence::try_from)
        .collect()
    }

    pub async fn get_silence(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<Silence>> {
        sqlx::query_as!(
            Row,
            r#"
            SELECT id, tenant_id, rule, devices, starts_at, ends_at, comment, created_by,
                   created_at
            FROM alarm_silences WHERE id = $1 AND tenant_id = $2
            "#,
            id,
            tenant_id
        )
        .fetch_optional(&self.pool)
        .await?
        .map(Silence::try_from)
        .transpose()
    }

    /// End a silence now; row kept for the record. Unknown -> `None`.
    pub async fn end_silence(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<Silence>> {
        sqlx::query_as!(
            Row,
            r#"
            UPDATE alarm_silences
            SET ends_at = GREATEST(starts_at + interval '1 microsecond', LEAST(ends_at, now()))
            WHERE id = $1 AND tenant_id = $2
            RETURNING id, tenant_id, rule, devices, starts_at, ends_at, comment, created_by,
                      created_at
            "#,
            id,
            tenant_id
        )
        .fetch_optional(&self.pool)
        .await?
        .map(Silence::try_from)
        .transpose()
    }

    /// `devices` that match `filter` (any device status).
    pub async fn devices_in_filter(
        &self,
        tenant_id: Uuid,
        filter: &DeviceFilter,
        devices: &[Uuid],
    ) -> Result<Vec<Uuid>> {
        Ok(sqlx::query_scalar!(
            r#"
            SELECT d.id FROM devices d
            WHERE d.tenant_id = $1 AND d.id = ANY($2)
              AND ($3::text IS NULL OR d.protocol = $3)
              AND ($4::text IS NULL OR d.oui = $4)
              AND ($5::text IS NULL OR d.product_class = $5)
              AND (cardinality($6::text[]) = 0 OR d.software_version = ANY($6))
              AND d.tags @> $7::text[]
              AND (cardinality($8::uuid[]) = 0 OR d.id = ANY($8))
              AND d.attributes @> $9::jsonb
            "#,
            tenant_id,
            devices,
            filter.protocol,
            filter.oui,
            filter.product_class,
            &filter.software_version,
            &filter.tags,
            &filter.device_ids,
            filter.attributes_json()
        )
        .fetch_all(&self.pool)
        .await?)
    }
}
