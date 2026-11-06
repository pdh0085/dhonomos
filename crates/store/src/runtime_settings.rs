//! Runtime settings set from the web (runtime settings, stages 2-3).
//! One raw value per server option + history of every change.
//! Validation: caller; here only storage.
//! Every change -> bump [`RUNTIME_SETTINGS_REVISION`] counter, watched by every process.

use std::collections::BTreeMap;

use serde_json::Value as Json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::presets::bump;
use crate::{Result, Store};

/// `config_revisions` kind, bumped at every runtime setting change.
pub const RUNTIME_SETTINGS_REVISION: &str = "server_settings";

/// One change of a runtime setting.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeSettingChange {
    /// Before (`None` = no value).
    pub old: Option<Json>,
    /// After (`None` = reset to default).
    pub new: Option<Json>,
    pub actor: Option<String>,
    pub at: OffsetDateTime,
}

impl Store {
    /// Stored runtime settings of a tenant, by key.
    pub async fn runtime_settings(&self, tenant_id: Uuid) -> Result<BTreeMap<String, Json>> {
        Ok(sqlx::query!(
            "SELECT key, value FROM runtime_settings WHERE tenant_id = $1",
            tenant_id
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| (r.key, r.value))
        .collect())
    }

    /// Store `value` for `key` + record change + bump revision -> replaced value.
    pub async fn set_runtime_setting(
        &self,
        tenant_id: Uuid,
        key: &str,
        value: &Json,
        actor: Option<&str>,
    ) -> Result<Option<Json>> {
        let mut tx = self.pool.begin().await?;
        let old = sqlx::query_scalar!(
            "SELECT value FROM runtime_settings WHERE tenant_id = $1 AND key = $2 FOR UPDATE",
            tenant_id,
            key
        )
        .fetch_optional(&mut *tx)
        .await?;
        sqlx::query!(
            r#"
            INSERT INTO runtime_settings (tenant_id, key, value, updated_by)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (tenant_id, key) DO UPDATE
            SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()
            "#,
            tenant_id,
            key,
            value,
            actor
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            r#"
            INSERT INTO runtime_settings_history (tenant_id, key, old, new, actor)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            tenant_id,
            key,
            old.as_ref(),
            value,
            actor
        )
        .execute(&mut *tx)
        .await?;
        bump(&mut tx, tenant_id, RUNTIME_SETTINGS_REVISION).await?;
        tx.commit().await?;
        Ok(old)
    }

    /// Remove stored value of `key` + record change + bump revision -> removed value.
    /// No stored value -> no change, no record.
    pub async fn reset_runtime_setting(
        &self,
        tenant_id: Uuid,
        key: &str,
        actor: Option<&str>,
    ) -> Result<Option<Json>> {
        let mut tx = self.pool.begin().await?;
        let Some(old) = sqlx::query_scalar!(
            "DELETE FROM runtime_settings WHERE tenant_id = $1 AND key = $2 RETURNING value",
            tenant_id,
            key
        )
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(None);
        };
        sqlx::query!(
            r#"
            INSERT INTO runtime_settings_history (tenant_id, key, old, new, actor)
            VALUES ($1, $2, $3, NULL, $4)
            "#,
            tenant_id,
            key,
            old,
            actor
        )
        .execute(&mut *tx)
        .await?;
        bump(&mut tx, tenant_id, RUNTIME_SETTINGS_REVISION).await?;
        tx.commit().await?;
        Ok(Some(old))
    }

    /// Last `limit` changes of `key`, newest first.
    pub async fn runtime_setting_history(
        &self,
        tenant_id: Uuid,
        key: &str,
        limit: i64,
    ) -> Result<Vec<RuntimeSettingChange>> {
        Ok(sqlx::query_as!(
            RuntimeSettingChange,
            r#"
            SELECT old, new, actor, at FROM runtime_settings_history
            WHERE tenant_id = $1 AND key = $2 ORDER BY id DESC LIMIT $3
            "#,
            tenant_id,
            key,
            limit
        )
        .fetch_all(&self.pool)
        .await?)
    }
}
