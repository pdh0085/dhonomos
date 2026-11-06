//! Audit trail of northbound changes (NB-05).

use serde_json::Value as Json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Result, Store};

/// Audit list filter. Unset field -> matches all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFilter {
    /// Exact actor.
    pub actor: Option<String>,
    /// Action prefix, e.g. `device.` or `preset.save`.
    pub action: Option<String>,
    /// Exact target ID.
    pub target_id: Option<String>,
    /// Only `id < before` -> next page.
    pub before: Option<i64>,
    /// Only `occurred_at >= since`.
    pub since: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuditEntry {
    /// Sequence number.
    pub id: i64,
    /// API identity.
    pub actor: String,
    /// Action, e.g. `task.create`.
    pub action: String,
    /// Object kind, e.g. `device`.
    pub target_type: String,
    pub target_id: Option<String>,
    pub detail: Json,
    pub occurred_at: OffsetDateTime,
}

impl Store {
    /// Append a record -> its sequence number.
    pub async fn record_audit(
        &self,
        tenant_id: Uuid,
        actor: &str,
        action: &str,
        target_type: &str,
        target_id: Option<&str>,
        detail: &Json,
    ) -> Result<i64> {
        Ok(sqlx::query_scalar!(
            r#"
            INSERT INTO audit_log (tenant_id, actor, action, target_type, target_id, detail)
            VALUES ($1, $2, $3, $4, $5, $6) RETURNING id
            "#,
            tenant_id,
            actor,
            action,
            target_type,
            target_id,
            detail
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// Tenant records matching `filter`, newest first, max `limit`.
    pub async fn list_audit(
        &self,
        tenant_id: Uuid,
        filter: &AuditFilter,
        limit: i64,
    ) -> Result<Vec<AuditEntry>> {
        // `%`, `_` in prefix = literal (escaped for LIKE).
        let action = filter.action.as_ref().map(|a| {
            format!(
                "{}%",
                a.replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_")
            )
        });
        Ok(sqlx::query_as!(
            AuditEntry,
            r#"
            SELECT id, actor, action, target_type, target_id, detail, occurred_at
            FROM audit_log
            WHERE tenant_id = $1
              AND ($3::text IS NULL OR actor = $3)
              AND ($4::text IS NULL OR action LIKE $4)
              AND ($5::text IS NULL OR target_id = $5)
              AND ($6::bigint IS NULL OR id < $6)
              AND ($7::timestamptz IS NULL OR occurred_at >= $7)
            ORDER BY id DESC
            LIMIT $2
            "#,
            tenant_id,
            limit,
            filter.actor,
            action,
            filter.target_id,
            filter.before,
            filter.since
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Records with `id > after_id`, oldest first -> shipping (ADR-083).
    pub async fn audit_after(
        &self,
        tenant_id: Uuid,
        after_id: i64,
        limit: i64,
    ) -> Result<Vec<AuditEntry>> {
        Ok(sqlx::query_as!(
            AuditEntry,
            r#"
            SELECT id, actor, action, target_type, target_id, detail, occurred_at
            FROM audit_log WHERE tenant_id = $1 AND id > $2
            ORDER BY id LIMIT $3
            "#,
            tenant_id,
            after_id,
            limit
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Newest sequence number (0 = no record).
    pub async fn latest_audit_id(&self, tenant_id: Uuid) -> Result<i64> {
        Ok(sqlx::query_scalar!(
            r#"SELECT COALESCE(max(id), 0) AS "id!" FROM audit_log WHERE tenant_id = $1"#,
            tenant_id
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// Last ID received by `sink` (0 = nothing yet).
    pub async fn audit_export_position(&self, tenant_id: Uuid, sink: &str) -> Result<i64> {
        Ok(sqlx::query_scalar!(
            "SELECT last_id FROM audit_export WHERE tenant_id = $1 AND sink = $2",
            tenant_id,
            sink
        )
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or(0))
    }

    /// Save: `sink` has all up to `last_id`. Position never moves back.
    pub async fn set_audit_export_position(
        &self,
        tenant_id: Uuid,
        sink: &str,
        last_id: i64,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO audit_export (tenant_id, sink, last_id) VALUES ($1, $2, $3)
            ON CONFLICT (tenant_id, sink)
            DO UPDATE SET last_id = GREATEST(audit_export.last_id, EXCLUDED.last_id), updated_at = now()
            "#,
            tenant_id,
            sink,
            last_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
