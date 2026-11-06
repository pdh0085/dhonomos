//! Device registry (CO-01).

use std::collections::HashMap;
use std::net::IpAddr;

use time::OffsetDateTime;
use uuid::Uuid;

use sqlx::{Postgres, QueryBuilder};

use crate::scope::scope_param;
use crate::{Result, Store};

/// CWMP device identity from the Inform `DeviceId`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CwmpIdentity {
    pub oui: String,
    /// May be empty.
    pub product_class: String,
    pub serial_number: String,
}

/// Device list filters (UI-01). Unset field = match all.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DeviceSearch {
    /// Case-insensitive substring of: serial number, EndpointID, model, software version,
    /// product class, OUI, address, attribute value.
    pub q: Option<String>,
    /// `cwmp` or `usp`.
    pub protocol: Option<String>,
    /// `active`, `quarantined` or `retired`.
    pub status: Option<String>,
    /// Exact match.
    pub product_class: Option<String>,
    /// Exact match.
    pub oui: Option<String>,
    /// Exact match.
    pub model_name: Option<String>,
    /// Exact match.
    pub software_version: Option<String>,
    /// Has this tag.
    pub tag: Option<String>,
    /// Exact attribute value: `(key, value)`.
    pub attribute: Option<(String, String)>,
    /// Only devices in this scope (the caller's, ADR-074).
    pub scope: Option<crate::DeviceScope>,
    /// Filter expression (NB-01).
    pub filter: Option<crate::FilterExpr>,
}

/// Refreshed on every Inform. `None` field -> stored value kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InformUpdate {
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    /// Firmware version.
    pub software_version: Option<String>,
    pub hardware_version: Option<String>,
    /// Root data model, e.g. `Device:2.21`.
    pub data_model: Option<String>,
    pub connection_request_url: Option<String>,
    /// Negotiated version.
    pub cwmp_version: Option<String>,
    /// Source address of the session.
    pub remote_addr: Option<IpAddr>,
    /// Inform had `1 BOOT` or `0 BOOTSTRAP`.
    pub booted: bool,
    /// Status of a device seen 1st time (default `active`, CO-12).
    pub new_device_status: Option<String>,
}

/// Descriptive device info. `None` -> stored value kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceInfo {
    pub manufacturer: Option<String>,
    pub oui: Option<String>,
    pub product_class: Option<String>,
    pub serial_number: Option<String>,
    pub model_name: Option<String>,
    /// Firmware version.
    pub software_version: Option<String>,
    pub hardware_version: Option<String>,
    /// Root data model.
    pub data_model: Option<String>,
}

/// Result of an upsert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpsertOutcome {
    pub id: Uuid,
    /// Device not known before.
    pub created: bool,
    /// Current status: `active`, `quarantined` or `retired`.
    pub status: String,
    /// SoftwareVersion before this contact (CWMP Inform only; else `None`).
    pub previous_software_version: Option<String>,
}

/// Device found or created by a batched pre-registration or lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownDevice {
    pub id: Uuid,
    /// Created by this call (lookup -> always false).
    pub created: bool,
    /// `active`, `quarantined` or `retired`.
    pub status: String,
}

/// USP Agent to create with other changes, with its first tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUspDevice {
    /// Chosen by the caller -> records can refer to it before it exists.
    /// EndpointID registered meanwhile -> existing device used, not this ID.
    pub id: Uuid,
    pub endpoint_id: String,
    pub tags: Vec<String>,
}

/// Registered device.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Device {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// `cwmp` or `usp`.
    pub protocol: String,
    pub oui: Option<String>,
    pub product_class: String,
    pub serial_number: Option<String>,
    pub endpoint_id: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    /// Firmware version.
    pub software_version: Option<String>,
    pub hardware_version: Option<String>,
    /// Root data model.
    pub data_model: Option<String>,
    pub connection_request_url: Option<String>,
    /// Negotiated CWMP version.
    pub cwmp_version: Option<String>,
    /// `active`, `quarantined` or `retired`.
    pub status: String,
    pub tags: Vec<String>,
    /// First contact.
    pub first_seen_at: OffsetDateTime,
    pub last_contact_at: Option<OffsetDateTime>,
    /// Last reported boot.
    pub last_boot_at: Option<OffsetDateTime>,
    pub last_remote_addr: Option<String>,
    /// Subscriber links + custom attributes (CO-13), JSON object of strings.
    pub attributes: serde_json::Value,
    /// WebSocket server of a USP Agent, Controller connects to it (US-05).
    pub usp_ws_url: Option<String>,
    /// Start of current XMPP session (ADR-104); `None` = no session.
    pub xmpp_connected_at: Option<OffsetDateTime>,
    /// Where the device gets UDP CRs (`host:port`, ADR-040), if known.
    pub udp_cr_address: Option<String>,
    /// Last confirmation of `udp_cr_address`.
    pub udp_cr_seen_at: Option<OffsetDateTime>,
    /// Last wake, any outcome.
    pub last_wake_at: Option<OffsetDateTime>,
    /// `xmpp`, `http`, `udp` or `usp`; `None` = that wake sent nothing.
    pub last_wake_method: Option<String>,
    /// Result of that wake, in API words ("sent over XMPP", "failed: ...").
    pub last_wake_outcome: Option<String>,
}

/// `{"key": "value"}` for an attribute filter.
fn attribute_filter(search: &DeviceSearch) -> Option<serde_json::Value> {
    search
        .attribute
        .as_ref()
        .map(|(k, v)| serde_json::json!({ k: v }))
}

/// `ILIKE` pattern for substring search. `%`, `_`, `\` in the query = literal.
fn like_pattern(search: &DeviceSearch) -> Option<String> {
    search
        .q
        .as_deref()
        .filter(|q| !q.trim().is_empty())
        .map(|q| {
            let escaped = q
                .trim()
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            format!("%{escaped}%")
        })
}

/// Distinct value of a device column + its device count.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct FacetValue {
    /// Column value, never empty.
    pub value: String,
    /// Devices with this value.
    pub count: i64,
    /// OUI facet only: manufacturer most of these devices report.
    pub manufacturer: Option<String>,
}

/// Values the device list can be narrowed to (UI-01).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceFacets {
    /// With the manufacturer most of their devices report.
    pub oui: Vec<FacetValue>,
    pub product_class: Vec<FacetValue>,
    pub model_name: Vec<FacetValue>,
}

/// Max values per facet; most common kept.
const MAX_FACET_VALUES: i64 = 500;

/// Columns of [`Device`] for queries built at run time.
const DEVICE_SELECT: &str = "SELECT d.id, d.tenant_id, d.protocol, d.oui, d.product_class, \
    d.serial_number, d.endpoint_id, d.manufacturer, d.model_name, d.software_version, \
    d.hardware_version, d.data_model, d.connection_request_url, d.cwmp_version, d.status, \
    d.tags, d.first_seen_at, d.last_contact_at, d.last_boot_at, \
    host(d.last_remote_addr) AS last_remote_addr, d.attributes, d.usp_ws_url, \
    d.xmpp_connected_at, d.udp_cr_address, d.udp_cr_seen_at, d.last_wake_at, \
    d.last_wake_method, d.last_wake_outcome FROM devices d";

/// `WHERE` clause of a device search. Values bound, never spliced.
fn push_search(q: &mut QueryBuilder<Postgres>, tenant_id: Uuid, search: &DeviceSearch) {
    q.push(" WHERE d.tenant_id = ").push_bind(tenant_id);
    if let Some(p) = like_pattern(search) {
        q.push(" AND (d.serial_number ILIKE ")
            .push_bind(p.clone())
            .push(" OR d.endpoint_id ILIKE ")
            .push_bind(p.clone())
            .push(" OR d.model_name ILIKE ")
            .push_bind(p.clone())
            .push(" OR d.software_version ILIKE ")
            .push_bind(p.clone())
            .push(" OR d.product_class ILIKE ")
            .push_bind(p.clone())
            .push(" OR d.oui ILIKE ")
            .push_bind(p.clone())
            .push(" OR host(d.last_remote_addr) ILIKE ")
            .push_bind(p.clone())
            .push(" OR EXISTS (SELECT 1 FROM jsonb_each_text(d.attributes) a WHERE a.value ILIKE ")
            .push_bind(p)
            .push("))");
    }
    let exact = [
        ("d.protocol", &search.protocol),
        ("d.status", &search.status),
        ("d.product_class", &search.product_class),
        ("d.oui", &search.oui),
        ("d.model_name", &search.model_name),
        ("d.software_version", &search.software_version),
    ];
    for (column, value) in exact {
        if let Some(v) = value {
            q.push(format!(" AND {column} = ")).push_bind(v.clone());
        }
    }
    if let Some(tag) = &search.tag {
        q.push(" AND ")
            .push_bind(tag.clone())
            .push(" = ANY(d.tags)");
    }
    if let Some(attr) = attribute_filter(search) {
        q.push(" AND d.attributes @> ").push_bind(attr);
    }
    if let Some(scope) = scope_param(search.scope.as_ref()) {
        q.push(" AND device_in_scope(d, ")
            .push_bind(scope)
            .push(")");
    }
    if let Some(filter) = &search.filter {
        q.push(" AND ");
        filter.push_sql(q);
    }
}

/// `unnest` columns for a list of CWMP identities.
fn identity_columns(identities: &[CwmpIdentity]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut ouis = Vec::with_capacity(identities.len());
    let mut classes = Vec::with_capacity(identities.len());
    let mut serials = Vec::with_capacity(identities.len());
    for i in identities {
        ouis.push(i.oui.clone());
        classes.push(i.product_class.clone());
        serials.push(i.serial_number.clone());
    }
    (ouis, classes, serials)
}

impl Store {
    /// Register a CWMP device or refresh it from an Inform.
    pub async fn upsert_cwmp_device(
        &self,
        tenant_id: Uuid,
        identity: &CwmpIdentity,
        update: &InformUpdate,
    ) -> Result<UpsertOutcome> {
        // CTE sees the row before this statement -> previous firmware back with the upsert.
        // One statement -> no race.
        let row = sqlx::query!(
            r#"
            WITH prev AS (
                SELECT software_version FROM devices
                WHERE tenant_id = $2 AND oui = $3 AND product_class = $4
                  AND serial_number = $5 AND protocol = 'cwmp'
            )
            INSERT INTO devices (
                id, tenant_id, protocol, oui, product_class, serial_number,
                manufacturer, model_name, software_version, hardware_version, data_model,
                connection_request_url, cwmp_version, last_contact_at, last_boot_at, last_remote_addr,
                status
            ) VALUES (
                $1, $2, 'cwmp', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now(),
                CASE WHEN $13 THEN now() END, $14::text::inet, COALESCE($15, 'active')
            )
            ON CONFLICT (tenant_id, oui, product_class, serial_number) WHERE protocol = 'cwmp'
            DO UPDATE SET
                manufacturer = COALESCE(EXCLUDED.manufacturer, devices.manufacturer),
                model_name = COALESCE(EXCLUDED.model_name, devices.model_name),
                software_version = COALESCE(EXCLUDED.software_version, devices.software_version),
                hardware_version = COALESCE(EXCLUDED.hardware_version, devices.hardware_version),
                data_model = COALESCE(EXCLUDED.data_model, devices.data_model),
                connection_request_url =
                    COALESCE(EXCLUDED.connection_request_url, devices.connection_request_url),
                cwmp_version = COALESCE(EXCLUDED.cwmp_version, devices.cwmp_version),
                last_contact_at = now(),
                last_boot_at = COALESCE(EXCLUDED.last_boot_at, devices.last_boot_at),
                last_remote_addr = COALESCE(EXCLUDED.last_remote_addr, devices.last_remote_addr)
            RETURNING id, (xmax = 0) AS "created!", status,
                (SELECT software_version FROM prev) AS previous_software_version
            "#,
            Uuid::now_v7(),
            tenant_id,
            identity.oui,
            identity.product_class,
            identity.serial_number,
            update.manufacturer,
            update.model_name,
            update.software_version,
            update.hardware_version,
            update.data_model,
            update.connection_request_url,
            update.cwmp_version,
            update.booted,
            update.remote_addr.map(|a| a.to_string()),
            update.new_device_status,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(UpsertOutcome {
            id: row.id,
            created: row.created,
            status: row.status,
            previous_software_version: row.previous_software_version,
        })
    }

    /// Register a USP Agent or refresh its contact time.
    /// `new_device_status`: new device only; `None` -> `active`.
    pub async fn upsert_usp_device(
        &self,
        tenant_id: Uuid,
        endpoint_id: &str,
        new_device_status: Option<&str>,
    ) -> Result<UpsertOutcome> {
        let row = sqlx::query!(
            r#"
            INSERT INTO devices (id, tenant_id, protocol, endpoint_id, last_contact_at, status)
            VALUES ($1, $2, 'usp', $3, now(), COALESCE($4, 'active'))
            ON CONFLICT (tenant_id, endpoint_id) WHERE protocol = 'usp'
            DO UPDATE SET last_contact_at = now()
            RETURNING id, (xmax = 0) AS "created!", status
            "#,
            Uuid::now_v7(),
            tenant_id,
            endpoint_id,
            new_device_status
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(UpsertOutcome {
            id: row.id,
            created: row.created,
            status: row.status,
            previous_software_version: None,
        })
    }

    /// Register a USP Agent before 1st connect. Existing one -> returned as is.
    pub async fn preregister_usp_device(
        &self,
        tenant_id: Uuid,
        endpoint_id: &str,
        tags: &[String],
    ) -> Result<UpsertOutcome> {
        let row = sqlx::query!(
            r#"
            WITH inserted AS (
                INSERT INTO devices (id, tenant_id, protocol, endpoint_id, tags)
                VALUES ($1, $2, 'usp', $3, $4)
                ON CONFLICT (tenant_id, endpoint_id) WHERE protocol = 'usp' DO NOTHING
                RETURNING id, status
            )
            SELECT id AS "id!", status AS "status!", true AS "created!" FROM inserted
            UNION ALL
            SELECT id, status, false FROM devices
            WHERE tenant_id = $2 AND protocol = 'usp' AND endpoint_id = $3
              AND NOT EXISTS (SELECT 1 FROM inserted)
            "#,
            Uuid::now_v7(),
            tenant_id,
            endpoint_id,
            tags
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(UpsertOutcome {
            id: row.id,
            created: row.created,
            status: row.status,
            previous_software_version: None,
        })
    }

    /// Update descriptive fields learned from the device (e.g. USP `Device.DeviceInfo.`).
    /// Also last contact = now.
    pub async fn update_device_info(&self, id: Uuid, info: &DeviceInfo) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE devices SET
                manufacturer = COALESCE($2, manufacturer),
                oui = COALESCE($3, oui),
                product_class = COALESCE($4, product_class),
                serial_number = COALESCE($5, serial_number),
                model_name = COALESCE($6, model_name),
                software_version = COALESCE($7, software_version),
                hardware_version = COALESCE($8, hardware_version),
                data_model = COALESCE($9, data_model),
                last_contact_at = now()
            WHERE id = $1
            "#,
            id,
            info.manufacturer,
            info.oui,
            info.product_class,
            info.serial_number,
            info.model_name,
            info.software_version,
            info.hardware_version,
            info.data_model
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Device has just booted -> `last_boot_at` = now.
    pub async fn mark_booted(&self, id: Uuid) -> Result<()> {
        sqlx::query!("UPDATE devices SET last_boot_at = now() WHERE id = $1", id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn find_usp_device(
        &self,
        tenant_id: Uuid,
        endpoint_id: &str,
    ) -> Result<Option<Uuid>> {
        Ok(sqlx::query_scalar!(
            "SELECT id FROM devices WHERE tenant_id = $1 AND protocol = 'usp' AND endpoint_id = $2",
            tenant_id,
            endpoint_id
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Register a CWMP device before 1st connect (CO-12 pre-registration).
    /// Existing device -> returned unchanged, `created == false`.
    pub async fn preregister_cwmp_device(
        &self,
        tenant_id: Uuid,
        identity: &CwmpIdentity,
        tags: &[String],
    ) -> Result<UpsertOutcome> {
        let inserted = sqlx::query!(
            r#"
            INSERT INTO devices (id, tenant_id, protocol, oui, product_class, serial_number, tags)
            VALUES ($1, $2, 'cwmp', $3, $4, $5, $6)
            ON CONFLICT (tenant_id, oui, product_class, serial_number) WHERE protocol = 'cwmp'
            DO NOTHING
            RETURNING id, status
            "#,
            Uuid::now_v7(),
            tenant_id,
            identity.oui,
            identity.product_class,
            identity.serial_number,
            tags
        )
        .fetch_optional(&self.pool)
        .await?;
        if let Some(r) = inserted {
            return Ok(UpsertOutcome {
                id: r.id,
                created: true,
                status: r.status,
                previous_software_version: None,
            });
        }
        let r = sqlx::query!(
            r#"
            SELECT id, status FROM devices
            WHERE tenant_id = $1 AND protocol = 'cwmp'
              AND oui = $2 AND product_class = $3 AND serial_number = $4
            "#,
            tenant_id,
            identity.oui,
            identity.product_class,
            identity.serial_number
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(UpsertOutcome {
            id: r.id,
            created: false,
            status: r.status,
            previous_software_version: None,
        })
    }

    /// Registered USP Agents among `endpoint_ids`, by EndpointID.
    pub async fn find_usp_devices(
        &self,
        tenant_id: Uuid,
        endpoint_ids: &[String],
    ) -> Result<HashMap<String, KnownDevice>> {
        let rows = sqlx::query!(
            r#"
            SELECT endpoint_id AS "endpoint_id!", id, status FROM devices
            WHERE tenant_id = $1 AND protocol = 'usp' AND endpoint_id = ANY($2)
            "#,
            tenant_id,
            endpoint_ids
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.endpoint_id,
                    KnownDevice {
                        id: r.id,
                        created: false,
                        status: r.status,
                    },
                )
            })
            .collect())
    }

    /// Register USP Agents of `endpoint_ids` not known yet, all with `tags`, one statement.
    /// Others returned as is (`created == false`).
    /// Answer: each given EndpointID once.
    pub async fn preregister_usp_devices(
        &self,
        tenant_id: Uuid,
        endpoint_ids: &[String],
        tags: &[String],
    ) -> Result<HashMap<String, KnownDevice>> {
        let ids: Vec<Uuid> = endpoint_ids.iter().map(|_| Uuid::now_v7()).collect();
        let rows = sqlx::query!(
            r#"
            WITH inserted AS (
                INSERT INTO devices (id, tenant_id, protocol, endpoint_id, tags)
                SELECT w.id, $1, 'usp', w.endpoint_id, $4
                FROM unnest($2::uuid[], $3::text[]) AS w(id, endpoint_id)
                ON CONFLICT (tenant_id, endpoint_id) WHERE protocol = 'usp' DO NOTHING
                RETURNING id, endpoint_id, status
            )
            SELECT id AS "id!", endpoint_id AS "endpoint_id!", status AS "status!",
                   true AS "created!"
            FROM inserted
            UNION ALL
            SELECT d.id, d.endpoint_id, d.status, false FROM devices d
            WHERE d.tenant_id = $1 AND d.protocol = 'usp' AND d.endpoint_id = ANY($3)
              AND NOT EXISTS (SELECT 1 FROM inserted i WHERE i.id = d.id)
            "#,
            tenant_id,
            &ids,
            endpoint_ids,
            tags
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.endpoint_id,
                    KnownDevice {
                        id: r.id,
                        created: r.created,
                        status: r.status,
                    },
                )
            })
            .collect())
    }

    /// Registered CWMP devices among `identities`, by identity.
    pub async fn find_cwmp_devices(
        &self,
        tenant_id: Uuid,
        identities: &[CwmpIdentity],
    ) -> Result<HashMap<CwmpIdentity, KnownDevice>> {
        let (ouis, classes, serials) = identity_columns(identities);
        let rows = sqlx::query!(
            r#"
            SELECT d.id, d.status,
                   d.oui AS "oui!", d.product_class, d.serial_number AS "serial_number!"
            FROM devices d
            JOIN unnest($2::text[], $3::text[], $4::text[]) AS w(oui, product_class, serial_number)
              ON d.oui = w.oui AND d.product_class = w.product_class
             AND d.serial_number = w.serial_number
            WHERE d.tenant_id = $1 AND d.protocol = 'cwmp'
            "#,
            tenant_id,
            &ouis,
            &classes,
            &serials
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    CwmpIdentity {
                        oui: r.oui,
                        product_class: r.product_class,
                        serial_number: r.serial_number,
                    },
                    KnownDevice {
                        id: r.id,
                        created: false,
                        status: r.status,
                    },
                )
            })
            .collect())
    }

    /// Register CWMP devices of `identities` not known yet, all with `tags`, one statement.
    /// Others returned as is (`created == false`).
    pub async fn preregister_cwmp_devices(
        &self,
        tenant_id: Uuid,
        identities: &[CwmpIdentity],
        tags: &[String],
    ) -> Result<HashMap<CwmpIdentity, KnownDevice>> {
        let (ouis, classes, serials) = identity_columns(identities);
        let ids: Vec<Uuid> = identities.iter().map(|_| Uuid::now_v7()).collect();
        let rows = sqlx::query!(
            r#"
            WITH inserted AS (
                INSERT INTO devices (id, tenant_id, protocol, oui, product_class, serial_number,
                                     tags)
                SELECT w.id, $1, 'cwmp', w.oui, w.product_class, w.serial_number, $6
                FROM unnest($2::uuid[], $3::text[], $4::text[], $5::text[])
                     AS w(id, oui, product_class, serial_number)
                ON CONFLICT (tenant_id, oui, product_class, serial_number) WHERE protocol = 'cwmp'
                DO NOTHING
                RETURNING id, oui, product_class, serial_number, status
            )
            SELECT id AS "id!", oui AS "oui!", product_class AS "product_class!",
                   serial_number AS "serial_number!", status AS "status!", true AS "created!"
            FROM inserted
            UNION ALL
            SELECT d.id, d.oui, d.product_class, d.serial_number, d.status, false
            FROM devices d
            JOIN unnest($3::text[], $4::text[], $5::text[]) AS w(oui, product_class, serial_number)
              ON d.oui = w.oui AND d.product_class = w.product_class
             AND d.serial_number = w.serial_number
            WHERE d.tenant_id = $1 AND d.protocol = 'cwmp'
              AND NOT EXISTS (SELECT 1 FROM inserted i WHERE i.id = d.id)
            "#,
            tenant_id,
            &ids,
            &ouis,
            &classes,
            &serials,
            tags
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    CwmpIdentity {
                        oui: r.oui,
                        product_class: r.product_class,
                        serial_number: r.serial_number,
                    },
                    KnownDevice {
                        id: r.id,
                        created: r.created,
                        status: r.status,
                    },
                )
            })
            .collect())
    }

    /// Current status, `None` if no such device.
    pub async fn device_status(&self, id: Uuid) -> Result<Option<String>> {
        Ok(
            sqlx::query_scalar!("SELECT status FROM devices WHERE id = $1", id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Set `active`, `quarantined` or `retired`. `true` = device exists.
    pub async fn set_device_status(&self, tenant_id: Uuid, id: Uuid, status: &str) -> Result<bool> {
        let done = sqlx::query!(
            "UPDATE devices SET status = $3 WHERE id = $1 AND tenant_id = $2",
            id,
            tenant_id,
            status
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Record source address of a USP Agent connection (WebSocket or STOMP to Dhonomos).
    pub async fn set_usp_remote_addr(&self, id: Uuid, addr: std::net::IpAddr) -> Result<()> {
        sqlx::query!(
            "UPDATE devices SET last_remote_addr = $2::text::inet WHERE id = $1 AND protocol = 'usp'",
            id,
            addr.to_string()
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Last contact of USP Agents: each `(endpoint ID, instant)` -> last contact = instant,
    /// unless already that late or later.
    /// Contact never moves back; unchanged Agent -> no row write.
    /// Result = count of devices moved.
    pub async fn touch_usp_devices(
        &self,
        tenant_id: Uuid,
        heard: &[(String, OffsetDateTime)],
    ) -> Result<u64> {
        if heard.is_empty() {
            return Ok(0);
        }
        let (endpoint_ids, instants): (Vec<String>, Vec<OffsetDateTime>) =
            heard.iter().cloned().unzip();
        let done = sqlx::query!(
            r#"
            UPDATE devices SET last_contact_at = h.heard_at
            FROM unnest($2::text[], $3::timestamptz[]) AS h(endpoint_id, heard_at)
            WHERE devices.tenant_id = $1 AND devices.protocol = 'usp'
              AND devices.endpoint_id = h.endpoint_id
              AND (devices.last_contact_at IS NULL OR devices.last_contact_at < h.heard_at)
            "#,
            tenant_id,
            &endpoint_ids,
            &instants
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// Record where a CPE gets UDP CRs (`host:port`). `true` = CWMP device in the tenant.
    pub async fn set_udp_cr_address(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        address: &str,
    ) -> Result<bool> {
        let done = sqlx::query!(
            r#"
            UPDATE devices SET udp_cr_address = $3, udp_cr_seen_at = now()
            WHERE id = $1 AND tenant_id = $2 AND protocol = 'cwmp'
            "#,
            id,
            tenant_id,
            address
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// UDP CR address of the device + time of last confirmation.
    pub async fn udp_cr_address(&self, id: Uuid) -> Result<Option<(String, OffsetDateTime)>> {
        let row = sqlx::query!(
            "SELECT udp_cr_address, udp_cr_seen_at FROM devices WHERE id = $1",
            id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.udp_cr_address.zip(r.udp_cr_seen_at)))
    }

    /// Record a wake just now: method (`xmpp`, `http`, `udp` or `usp`; `None` = nothing sent)
    /// and outcome in API words. `true` = device exists.
    pub async fn record_wake(&self, id: Uuid, method: Option<&str>, outcome: &str) -> Result<bool> {
        let done = sqlx::query!(
            r#"
            UPDATE devices
            SET last_wake_at = now(), last_wake_method = $2, last_wake_outcome = $3
            WHERE id = $1
            "#,
            id,
            method,
            outcome
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Device has an XMPP session since `at` (microsecond precision). `true` = device exists.
    pub async fn set_xmpp_connected(&self, id: Uuid, at: OffsetDateTime) -> Result<bool> {
        let done = sqlx::query!(
            "UPDATE devices SET xmpp_connected_at = $2 WHERE id = $1",
            id,
            at
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// XMPP session started at `at` ended -> clear.
    /// Newer session (later `xmpp_connected_at`) -> no change. `true` = cleared.
    pub async fn clear_xmpp_connected(&self, id: Uuid, at: OffsetDateTime) -> Result<bool> {
        let done = sqlx::query!(
            "UPDATE devices SET xmpp_connected_at = NULL WHERE id = $1 AND xmpp_connected_at = $2",
            id,
            at
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Clear XMPP session time of all devices. XMPP server start -> no session exists,
    /// whatever a dead process left. Result = count cleared.
    pub async fn clear_all_xmpp_connected(&self) -> Result<u64> {
        let done = sqlx::query!(
            "UPDATE devices SET xmpp_connected_at = NULL WHERE xmpp_connected_at IS NOT NULL"
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// Serial number (CWMP) or EndpointID (USP) of devices, by ID.
    pub async fn device_labels(
        &self,
        ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, String>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, COALESCE(serial_number, endpoint_id, '') AS "label!"
            FROM devices WHERE id = ANY($1)
            "#,
            ids
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| (r.id, r.label)).collect())
    }

    pub async fn get_device(&self, id: Uuid) -> Result<Option<Device>> {
        Ok(sqlx::query_as!(
            Device,
            r#"
            SELECT id, tenant_id, protocol, oui, product_class, serial_number, endpoint_id,
                   manufacturer, model_name, software_version, hardware_version, data_model,
                   connection_request_url, cwmp_version, status, tags, first_seen_at,
                   last_contact_at, last_boot_at, host(last_remote_addr) AS last_remote_addr, attributes, usp_ws_url, xmpp_connected_at,
                   udp_cr_address, udp_cr_seen_at, last_wake_at, last_wake_method,
                   last_wake_outcome
            FROM devices WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn find_cwmp_device(
        &self,
        tenant_id: Uuid,
        identity: &CwmpIdentity,
    ) -> Result<Option<Uuid>> {
        Ok(sqlx::query_scalar!(
            r#"
            SELECT id FROM devices
            WHERE tenant_id = $1 AND protocol = 'cwmp'
              AND oui = $2 AND product_class = $3 AND serial_number = $4
            "#,
            tenant_id,
            identity.oui,
            identity.product_class,
            identity.serial_number
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Devices matching `search`, last heard first, and match count.
    pub async fn search_devices(
        &self,
        tenant_id: Uuid,
        search: &DeviceSearch,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Device>, i64)> {
        let mut count = QueryBuilder::new("SELECT count(*) FROM devices d");
        push_search(&mut count, tenant_id, search);
        let total: i64 = count.build_query_scalar().fetch_one(&self.pool).await?;
        let mut rows = QueryBuilder::new(DEVICE_SELECT);
        push_search(&mut rows, tenant_id, search);
        rows.push(" ORDER BY d.last_contact_at DESC NULLS LAST, d.id LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        let devices = rows
            .build_query_as::<Device>()
            .fetch_all(&self.pool)
            .await?;
        Ok((devices, total))
    }

    /// Distinct OUIs, product classes, model names of devices matching `search`, with counts.
    /// Each facet ignores its own filter -> selected value still shown.
    /// Each: [`MAX_FACET_VALUES`] most common values, sorted by value.
    pub async fn device_facets(
        &self,
        tenant_id: Uuid,
        search: &DeviceSearch,
    ) -> Result<DeviceFacets> {
        let oui = self
            .device_facet(
                tenant_id,
                &DeviceSearch {
                    oui: None,
                    ..search.clone()
                },
                "d.oui",
                true,
            )
            .await?;
        let product_class = self
            .device_facet(
                tenant_id,
                &DeviceSearch {
                    product_class: None,
                    ..search.clone()
                },
                "d.product_class",
                false,
            )
            .await?;
        let model_name = self
            .device_facet(
                tenant_id,
                &DeviceSearch {
                    model_name: None,
                    ..search.clone()
                },
                "d.model_name",
                false,
            )
            .await?;
        Ok(DeviceFacets {
            oui,
            product_class,
            model_name,
        })
    }

    /// One facet of [`Store::device_facets`]. `column` = fixed column name, never input.
    async fn device_facet(
        &self,
        tenant_id: Uuid,
        search: &DeviceSearch,
        column: &str,
        with_manufacturer: bool,
    ) -> Result<Vec<FacetValue>> {
        let manufacturer = if with_manufacturer {
            "mode() WITHIN GROUP (ORDER BY NULLIF(d.manufacturer, ''))"
        } else {
            "NULL::text"
        };
        let mut q = QueryBuilder::new(format!(
            "SELECT {column} AS value, count(*) AS count, {manufacturer} AS manufacturer \
             FROM devices d"
        ));
        push_search(&mut q, tenant_id, search);
        q.push(format!(
            " AND {column} IS NOT NULL AND {column} <> '' GROUP BY {column} \
             ORDER BY count(*) DESC, {column} LIMIT "
        ))
        .push_bind(MAX_FACET_VALUES);
        let mut values = q
            .build_query_as::<FacetValue>()
            .fetch_all(&self.pool)
            .await?;
        values.sort_by(|a, b| a.value.cmp(&b.value));
        Ok(values)
    }

    /// Set or clear WebSocket URL of a USP Agent with a WebSocket server (US-05).
    /// Controller connects to it. `true` = device exists.
    pub async fn set_usp_ws_url(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        url: Option<&str>,
    ) -> Result<bool> {
        let done = sqlx::query!(
            "UPDATE devices SET usp_ws_url = $3 WHERE id = $1 AND tenant_id = $2 AND protocol = 'usp'",
            id,
            tenant_id,
            url
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Active USP Agents the Controller connects to: `(EndpointID, URL)`.
    pub async fn usp_ws_clients(&self, tenant_id: Uuid) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query!(
            r#"
            SELECT endpoint_id AS "eid!", usp_ws_url AS "url!" FROM devices
            WHERE tenant_id = $1 AND protocol = 'usp' AND status = 'active'
              AND endpoint_id IS NOT NULL AND usp_ws_url IS NOT NULL
            "#,
            tenant_id
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| (r.eid, r.url)).collect())
    }

    /// Devices whose `column` (`id`, `serial_number` or `endpoint_id`) is in `values`
    /// -> `(value, device)` pairs. Serial number of N devices -> N pairs.
    pub async fn devices_by_key(
        &self,
        tenant_id: Uuid,
        column: &str,
        values: &[String],
    ) -> Result<Vec<(String, Uuid)>> {
        let rows = sqlx::query!(
            r#"
            SELECT k.v AS "key!", d.id
            FROM unnest($3::text[]) AS k(v)
            JOIN devices d ON d.tenant_id = $1 AND (
                ($2 = 'id' AND d.id::text = k.v)
                OR ($2 = 'serial_number' AND d.serial_number = k.v)
                OR ($2 = 'endpoint_id' AND d.endpoint_id = k.v))
            "#,
            tenant_id,
            column,
            values
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| (r.key, r.id)).collect())
    }

    /// Merge attribute changes into many devices at once (`null` removes a key).
    pub async fn merge_attributes(
        &self,
        tenant_id: Uuid,
        ids: &[Uuid],
        patches: &[serde_json::Value],
    ) -> Result<u64> {
        let done = sqlx::query!(
            r#"
            UPDATE devices d
            SET attributes = jsonb_strip_nulls(d.attributes || u.patch)
            FROM unnest($2::uuid[], $3::jsonb[]) AS u(id, patch)
            WHERE d.id = u.id AND d.tenant_id = $1
            "#,
            tenant_id,
            ids,
            patches
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// Replace tags and/or merge attribute changes (`null` removes a key).
    /// `true` = device in the tenant.
    pub async fn update_device(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        tags: Option<&[String]>,
        attributes: Option<&serde_json::Value>,
    ) -> Result<bool> {
        let done = sqlx::query!(
            r#"
            UPDATE devices SET
                tags = COALESCE($3, tags),
                attributes = CASE WHEN $4::jsonb IS NULL THEN attributes
                                  ELSE jsonb_strip_nulls(attributes || $4) END
            WHERE id = $1 AND tenant_id = $2
            "#,
            id,
            tenant_id,
            tags as Option<&[String]>,
            attributes
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Devices matching `search`, ID order, after `after`.
    /// Stable export pages, even while devices keep reporting.
    pub async fn export_devices(
        &self,
        tenant_id: Uuid,
        search: &DeviceSearch,
        after: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<Device>> {
        let mut q = QueryBuilder::new(DEVICE_SELECT);
        push_search(&mut q, tenant_id, search);
        if let Some(after) = after {
            q.push(" AND d.id > ").push_bind(after);
        }
        q.push(" ORDER BY d.id LIMIT ").push_bind(limit);
        Ok(q.build_query_as::<Device>().fetch_all(&self.pool).await?)
    }

    pub async fn list_devices(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Device>> {
        Ok(sqlx::query_as!(
            Device,
            r#"
            SELECT id, tenant_id, protocol, oui, product_class, serial_number, endpoint_id,
                   manufacturer, model_name, software_version, hardware_version, data_model,
                   connection_request_url, cwmp_version, status, tags, first_seen_at,
                   last_contact_at, last_boot_at, host(last_remote_addr) AS last_remote_addr, attributes, usp_ws_url, xmpp_connected_at,
                   udp_cr_address, udp_cr_seen_at, last_wake_at, last_wake_method,
                   last_wake_outcome
            FROM devices WHERE tenant_id = $1
            ORDER BY last_contact_at DESC NULLS LAST, id
            LIMIT $2 OFFSET $3
            "#,
            tenant_id,
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await?)
    }
}
