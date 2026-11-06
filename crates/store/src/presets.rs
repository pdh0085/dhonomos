//! Provisioning presets in DB + history (UI-03, ADR-077).
//! Validation: caller (`dhonomos_core::presets`); here only storage.
//!
//! Task secrets = ciphertext bound to row ID (`dhonomos_core::secrets::preset_context`).
//! History entries: document with secrets masked, never ciphertext.

use serde_json::Value as Json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Result, Store};

#[derive(Debug, Clone, PartialEq)]
pub struct StoredPreset {
    /// Row ID. Encrypted secrets of the definition are bound to it.
    pub id: Uuid,
    /// Unique per tenant.
    pub name: String,
    /// Disabled -> kept, never matches.
    pub enabled: bool,
    /// Preset document (as in the YAML file). Task secrets stored as `enc:v2:` ciphertext.
    pub definition: Json,
    /// +1 per save.
    pub revision: i32,
    pub updated_by: Option<String>,
    pub updated_at: OffsetDateTime,
}

/// One saved revision or deletion.
#[derive(Debug, Clone, PartialEq)]
pub struct PresetChange {
    /// After the change.
    pub revision: i32,
    /// After the change.
    pub enabled: bool,
    /// Document with secrets masked. `None` = deletion.
    pub definition: Option<Json>,
    pub changed_by: Option<String>,
    pub changed_at: OffsetDateTime,
}

/// Result of a conditional change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetWrite {
    /// Done -> new revision (0 after a deletion).
    Done(i32),
    /// Changed by someone else -> current revision (0 = does not exist).
    Conflict(i32),
}

impl Store {
    /// Presets of a tenant, by name.
    pub async fn list_presets(&self, tenant_id: Uuid) -> Result<Vec<StoredPreset>> {
        Ok(sqlx::query_as!(
            StoredPreset,
            r#"
            SELECT id, name, enabled, definition, revision, updated_by, updated_at
            FROM presets WHERE tenant_id = $1 ORDER BY name
            "#,
            tenant_id
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Create or replace a preset. `expected` -> only at this current revision
    /// (0 = must not exist yet).
    ///
    /// `id` = row ID the secrets in `definition` were sealed for. New row -> gets it.
    /// Existing row must have it, else preset deleted + created again meanwhile ->
    /// secrets would not open -> `Conflict`.
    /// `history` = document for the history entry: secrets masked, no ciphertext.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_preset(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        name: &str,
        enabled: bool,
        definition: &Json,
        history: &Json,
        expected: Option<i32>,
        by: Option<&str>,
    ) -> Result<PresetWrite> {
        let mut tx = self.pool.begin().await?;
        let (current_id, current) = sqlx::query!(
            "SELECT id, revision FROM presets WHERE tenant_id = $1 AND name = $2 FOR UPDATE",
            tenant_id,
            name
        )
        .fetch_optional(&mut *tx)
        .await?
        .map_or((None, 0), |r| (Some(r.id), r.revision));
        if expected.is_some_and(|e| e != current) || current_id.is_some_and(|c| c != id) {
            return Ok(PresetWrite::Conflict(current));
        }
        let revision = sqlx::query_scalar!(
            r#"
            INSERT INTO presets (id, tenant_id, name, enabled, definition, updated_by)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (tenant_id, name) DO UPDATE
            SET enabled = EXCLUDED.enabled, definition = EXCLUDED.definition,
                updated_by = EXCLUDED.updated_by, updated_at = now(),
                revision = presets.revision + 1
            RETURNING revision
            "#,
            id,
            tenant_id,
            name,
            enabled,
            definition,
            by
        )
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query!(
            r#"
            INSERT INTO preset_history (tenant_id, name, revision, enabled, definition, changed_by)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            tenant_id,
            name,
            revision,
            enabled,
            history,
            by
        )
        .execute(&mut *tx)
        .await?;
        bump(&mut tx, tenant_id, "presets").await?;
        tx.commit().await?;
        Ok(PresetWrite::Done(revision))
    }

    /// Delete a preset (`expected` -> only at this revision). Not found -> `Conflict(0)`.
    pub async fn delete_preset(
        &self,
        tenant_id: Uuid,
        name: &str,
        expected: Option<i32>,
        by: Option<&str>,
    ) -> Result<PresetWrite> {
        let mut tx = self.pool.begin().await?;
        let Some((revision, enabled)) = sqlx::query!(
            "SELECT revision, enabled FROM presets WHERE tenant_id = $1 AND name = $2 FOR UPDATE",
            tenant_id,
            name
        )
        .fetch_optional(&mut *tx)
        .await?
        .map(|r| (r.revision, r.enabled)) else {
            return Ok(PresetWrite::Conflict(0));
        };
        if expected.is_some_and(|e| e != revision) {
            return Ok(PresetWrite::Conflict(revision));
        }
        sqlx::query!(
            "DELETE FROM presets WHERE tenant_id = $1 AND name = $2",
            tenant_id,
            name
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            r#"
            INSERT INTO preset_history (tenant_id, name, revision, enabled, definition, changed_by)
            VALUES ($1, $2, $3, $4, NULL, $5)
            "#,
            tenant_id,
            name,
            revision + 1,
            enabled,
            by
        )
        .execute(&mut *tx)
        .await?;
        bump(&mut tx, tenant_id, "presets").await?;
        tx.commit().await?;
        Ok(PresetWrite::Done(0))
    }

    /// Saved revisions + deletions of a preset name, newest first.
    pub async fn preset_history(
        &self,
        tenant_id: Uuid,
        name: &str,
        limit: i64,
    ) -> Result<Vec<PresetChange>> {
        Ok(sqlx::query_as!(
            PresetChange,
            r#"
            SELECT revision, enabled, definition, changed_by, changed_at
            FROM preset_history WHERE tenant_id = $1 AND name = $2
            ORDER BY id DESC LIMIT $3
            "#,
            tenant_id,
            name,
            limit
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// All presets of all tenants as `(id, definition)` -> seal / reseal their secrets.
    pub async fn presets_for_rewrap(&self) -> Result<Vec<(Uuid, Json)>> {
        Ok(
            sqlx::query!("SELECT id, definition FROM presets ORDER BY id")
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .map(|r| (r.id, r.definition))
                .collect(),
        )
    }

    /// Replace definition unless changed since `old` was read.
    /// Revision kept: same content, only secrets sealed differently.
    pub async fn replace_preset_definition(
        &self,
        id: Uuid,
        old: &Json,
        new: &Json,
    ) -> Result<bool> {
        let done = sqlx::query!(
            "UPDATE presets SET definition = $3 WHERE id = $1 AND definition = $2",
            id,
            old,
            new
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// History entries maybe with a secret value (written before masking) -> `(id, definition)`.
    pub async fn preset_history_with_secrets(&self) -> Result<Vec<(i64, Json)>> {
        Ok(sqlx::query!(
            r#"
            SELECT id, definition AS "definition!" FROM preset_history
            WHERE definition::text LIKE '%password%' OR definition::text LIKE '%secret%'
            "#
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| (r.id, r.definition))
        .collect())
    }

    /// Replace a history entry's definition unless changed since `old` was read.
    pub async fn replace_history_definition(
        &self,
        id: i64,
        old: &Json,
        new: &Json,
    ) -> Result<bool> {
        let done = sqlx::query!(
            "UPDATE preset_history SET definition = $3 WHERE id = $1 AND definition = $2",
            id,
            old,
            new
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Revision counter of a config kind (0 before the first change).
    pub async fn config_revision(&self, tenant_id: Uuid, kind: &str) -> Result<i64> {
        Ok(sqlx::query_scalar!(
            "SELECT revision FROM config_revisions WHERE tenant_id = $1 AND kind = $2",
            tenant_id,
            kind
        )
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or(0))
    }
}

/// Bump revision counter of a config kind -> every process notices the change.
pub(crate) async fn bump(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    kind: &str,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO config_revisions (tenant_id, kind, revision) VALUES ($1, $2, 1)
        ON CONFLICT (tenant_id, kind) DO UPDATE SET revision = config_revisions.revision + 1
        "#,
        tenant_id,
        kind
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}
