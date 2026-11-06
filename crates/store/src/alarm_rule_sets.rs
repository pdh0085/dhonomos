//! Alarm rules edited from the web (runtime settings, stage 4): 1 YAML rule set per tenant.
//! Every version kept.
//! Validation = caller's job; store keeps the text only.
//! Each change -> bump of [`ALARM_RULES_REVISION`], watched by every process.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::presets::bump;
use crate::{Result, Store};

/// `config_revisions` kind, bumped on each change of the stored alarm rules.
pub const ALARM_RULES_REVISION: &str = "alarm_rules";

/// Stored alarm rules of a tenant.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredAlarmRules {
    pub yaml: String,
    pub updated_by: Option<String>,
    pub updated_at: OffsetDateTime,
}

/// 1 stored version of the alarm rules.
#[derive(Debug, Clone, PartialEq)]
pub struct AlarmRulesVersion {
    /// `None` -> rules removed.
    pub yaml: Option<String>,
    pub actor: Option<String>,
    pub at: OffsetDateTime,
}

impl Store {
    pub async fn alarm_rule_set(&self, tenant_id: Uuid) -> Result<Option<StoredAlarmRules>> {
        Ok(sqlx::query_as!(
            StoredAlarmRules,
            "SELECT yaml, updated_by, updated_at FROM alarm_rule_sets WHERE tenant_id = $1",
            tenant_id
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Store `yaml` as rules of the tenant + version row + revision bump, 1 transaction.
    /// -> replaced YAML.
    pub async fn set_alarm_rule_set(
        &self,
        tenant_id: Uuid,
        yaml: &str,
        actor: Option<&str>,
    ) -> Result<Option<String>> {
        let mut tx = self.pool.begin().await?;
        let old = sqlx::query_scalar!(
            "SELECT yaml FROM alarm_rule_sets WHERE tenant_id = $1 FOR UPDATE",
            tenant_id
        )
        .fetch_optional(&mut *tx)
        .await?;
        sqlx::query!(
            r#"
            INSERT INTO alarm_rule_sets (tenant_id, yaml, updated_by) VALUES ($1, $2, $3)
            ON CONFLICT (tenant_id) DO UPDATE
            SET yaml = EXCLUDED.yaml, updated_by = EXCLUDED.updated_by, updated_at = now()
            "#,
            tenant_id,
            yaml,
            actor
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            "INSERT INTO alarm_rule_set_history (tenant_id, yaml, actor) VALUES ($1, $2, $3)",
            tenant_id,
            yaml,
            actor
        )
        .execute(&mut *tx)
        .await?;
        bump(&mut tx, tenant_id, ALARM_RULES_REVISION).await?;
        tx.commit().await?;
        Ok(old)
    }

    /// Last `limit` versions, newest first.
    pub async fn alarm_rule_set_history(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<AlarmRulesVersion>> {
        Ok(sqlx::query_as!(
            AlarmRulesVersion,
            r#"
            SELECT yaml, actor, at FROM alarm_rule_set_history
            WHERE tenant_id = $1 ORDER BY id DESC LIMIT $2
            "#,
            tenant_id,
            limit
        )
        .fetch_all(&self.pool)
        .await?)
    }
}
