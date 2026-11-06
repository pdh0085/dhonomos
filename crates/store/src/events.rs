//! Device events (Inform, TransferComplete, value changes, ...).

use serde_json::Value as Json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Result, Store};

#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// Sequence number.
    pub id: i64,
    pub device_id: Option<Uuid>,
    /// e.g. `inform`.
    pub kind: String,
    pub detail: Json,
    pub occurred_at: OffsetDateTime,
}

impl Store {
    /// Insert event -> its sequence number.
    pub async fn record_event(
        &self,
        tenant_id: Uuid,
        device_id: Option<Uuid>,
        kind: &str,
        detail: &Json,
    ) -> Result<i64> {
        Ok(sqlx::query_scalar!(
            r#"
            INSERT INTO events (tenant_id, device_id, kind, detail)
            VALUES ($1, $2, $3, $4) RETURNING id
            "#,
            tenant_id,
            device_id,
            kind,
            detail
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// Events of a device at/after `since`, oldest first.
    pub async fn events_since(
        &self,
        device_id: Uuid,
        since: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<Event>> {
        Ok(sqlx::query_as!(
            Event,
            r#"
            SELECT id, device_id, kind, detail, occurred_at
            FROM events WHERE device_id = $1 AND occurred_at >= $2
            ORDER BY occurred_at, id
            LIMIT $3
            "#,
            device_id,
            since,
            limit
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Events of a device, newest first.
    pub async fn list_events(&self, device_id: Uuid, limit: i64) -> Result<Vec<Event>> {
        Ok(sqlx::query_as!(
            Event,
            r#"
            SELECT id, device_id, kind, detail, occurred_at
            FROM events WHERE device_id = $1
            ORDER BY occurred_at DESC, id DESC
            LIMIT $2
            "#,
            device_id,
            limit
        )
        .fetch_all(&self.pool)
        .await?)
    }
}
