//! Supported data model cache, key = firmware fingerprint (US-11).

use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Result, Store};

/// Cached supported data model.
#[derive(Debug, Clone, PartialEq)]
pub struct SupportedModel {
    pub id: Uuid,
    /// Firmware fingerprint or [`device_fingerprint`].
    pub fingerprint: String,
    /// `cwmp` or `usp`.
    pub protocol: String,
    /// Model doc: objects, parameters, commands, events.
    pub model: Value,
    /// Learn time, reset on replace.
    pub created_at: OffsetDateTime,
}

/// Fingerprint of a model for one device only.
/// Firmware not identifiable (no software version) -> model not shared.
/// Firmware fingerprints = SHA-256 hex -> never this form.
pub fn device_fingerprint(device_id: Uuid) -> String {
    format!("device:{device_id}")
}

impl Store {
    /// ID of the model cached for `fingerprint`, if any.
    pub async fn supported_model_id(&self, fingerprint: &str) -> Result<Option<Uuid>> {
        Ok(sqlx::query_scalar!(
            "SELECT id FROM supported_models WHERE fingerprint = $1",
            fingerprint
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Store model for `fingerprint` -> its ID. First stored wins.
    pub async fn put_supported_model(
        &self,
        fingerprint: &str,
        protocol: &str,
        model: &Value,
    ) -> Result<Uuid> {
        Ok(sqlx::query_scalar!(
            r#"
            WITH inserted AS (
                INSERT INTO supported_models (id, fingerprint, protocol, model)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (fingerprint) DO NOTHING
                RETURNING id
            )
            SELECT id AS "id!" FROM inserted
            UNION ALL
            SELECT id FROM supported_models
            WHERE fingerprint = $2 AND NOT EXISTS (SELECT 1 FROM inserted)
            "#,
            Uuid::now_v7(),
            fingerprint,
            protocol,
            model
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// Store model for `fingerprint`, replace old one -> ID.
    /// Row keeps its ID -> linked devices see new model.
    pub async fn replace_supported_model(
        &self,
        fingerprint: &str,
        protocol: &str,
        model: &Value,
    ) -> Result<Uuid> {
        Ok(sqlx::query_scalar!(
            r#"
            INSERT INTO supported_models (id, fingerprint, protocol, model)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (fingerprint) DO UPDATE
                SET protocol = EXCLUDED.protocol, model = EXCLUDED.model, created_at = now()
            RETURNING id AS "id!"
            "#,
            Uuid::now_v7(),
            fingerprint,
            protocol,
            model
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// Delete model cached for `fingerprint` -> linked devices without model.
    /// `true` = there was one.
    pub async fn delete_supported_model(&self, fingerprint: &str) -> Result<bool> {
        let done = sqlx::query!(
            "DELETE FROM supported_models WHERE fingerprint = $1",
            fingerprint
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Point device at cached model.
    pub async fn link_supported_model(&self, device_id: Uuid, model_id: Uuid) -> Result<()> {
        sqlx::query!(
            "UPDATE devices SET supported_model_id = $2 WHERE id = $1",
            device_id,
            model_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// `None` = no linked model.
    pub async fn device_supported_model(&self, device_id: Uuid) -> Result<Option<SupportedModel>> {
        Ok(sqlx::query_as!(
            SupportedModel,
            r#"
            SELECT m.id, m.fingerprint, m.protocol, m.model, m.created_at
            FROM devices d JOIN supported_models m ON m.id = d.supported_model_id
            WHERE d.id = $1
            "#,
            device_id
        )
        .fetch_optional(&self.pool)
        .await?)
    }
}
