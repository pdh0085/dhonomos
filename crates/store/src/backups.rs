//! Config backups (CO-08) + device deletion (CO-14).

use serde_json::Value as Json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Result, Store};

#[derive(Debug, Clone, PartialEq)]
pub struct ConfigBackup {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    /// Operator label.
    pub label: String,
    /// `[{path, value, type}]`.
    pub params: Json,
    pub created_by: Option<String>,
    pub created_at: OffsetDateTime,
}

/// What [`Store::delete_device`] removed + revoked.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DeletedDevice {
    /// IDs of deleted file records -> caller removes their content from storage.
    pub files: Vec<Uuid>,
    /// Agent certs revoked by the deletion (not counting already revoked ones).
    pub certificates_revoked: u64,
}

impl Store {
    /// Store a backup of `device_id` -> its ID.
    pub async fn create_backup(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        label: &str,
        params: &Json,
        created_by: Option<&str>,
    ) -> Result<Uuid> {
        let id = Uuid::now_v7();
        sqlx::query!(
            r#"
            INSERT INTO config_backups (id, tenant_id, device_id, label, params, created_by)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            id,
            tenant_id,
            device_id,
            label,
            params,
            created_by
        )
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn get_backup(&self, id: Uuid) -> Result<Option<ConfigBackup>> {
        Ok(sqlx::query_as!(
            ConfigBackup,
            r#"
            SELECT id, tenant_id, device_id, label, params, created_by, created_at
            FROM config_backups WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Backups of a device, newest first, max 100.
    pub async fn list_backups(&self, device_id: Uuid) -> Result<Vec<ConfigBackup>> {
        Ok(sqlx::query_as!(
            ConfigBackup,
            r#"
            SELECT id, tenant_id, device_id, label, params, created_by, created_at
            FROM config_backups WHERE device_id = $1 ORDER BY created_at DESC LIMIT 100
            "#,
            device_id
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Delete a backup -> `true` if it existed.
    pub async fn delete_backup(&self, id: Uuid) -> Result<bool> {
        let done = sqlx::query!("DELETE FROM config_backups WHERE id = $1", id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Delete a device + all its data: params, tasks, events, credentials, backups,
    /// uploaded files, job memberships, time series.
    ///
    /// Agent certs stay valid after deletion -> revoked first (`by`, reason "device deleted").
    /// Cert rows kept without device -> stay in the revoked set the MTPs enforce.
    /// `None` -> device not found. Else file record IDs (caller removes content from
    /// storage) and count of revoked certs.
    pub async fn delete_device(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        by: Option<&str>,
    ) -> Result<Option<DeletedDevice>> {
        let mut tx = self.pool.begin().await?;
        // Row lock -> no cert issued to the device during deletion (would stay unrevoked).
        sqlx::query!(
            "SELECT id FROM devices WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
            id,
            tenant_id
        )
        .fetch_optional(&mut *tx)
        .await?;
        let certificates_revoked = sqlx::query!(
            r#"
            UPDATE usp_certificates
            SET revoked_at = now(), revoked_by = $3, revoke_reason = 'device deleted'
            WHERE device_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
            "#,
            id,
            tenant_id,
            by
        )
        .execute(&mut *tx)
        .await?
        .rows_affected();
        // Partitioned samples table: no foreign key -> delete here.
        sqlx::query!("DELETE FROM metric_samples WHERE device_id = $1", id)
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM metric_rollups WHERE device_id = $1", id)
            .execute(&mut *tx)
            .await?;
        // Vendor config + log files hold device secrets.
        // Device link gone -> outside every device scope -> delete with the device.
        let files = sqlx::query_scalar!(
            r#"
            DELETE FROM files f USING devices d
            WHERE f.device_id = d.id AND d.id = $1 AND d.tenant_id = $2
            RETURNING f.id
            "#,
            id,
            tenant_id
        )
        .fetch_all(&mut *tx)
        .await?;
        let done = sqlx::query!(
            "DELETE FROM devices WHERE id = $1 AND tenant_id = $2",
            id,
            tenant_id
        )
        .execute(&mut *tx)
        .await?;
        // Own supported model of the device, if its firmware was not identified.
        sqlx::query!(
            "DELETE FROM supported_models WHERE fingerprint = $1",
            crate::models::device_fingerprint(id)
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok((done.rows_affected() == 1).then_some(DeletedDevice {
            files,
            certificates_revoked,
        }))
    }

    pub async fn remove_tags(&self, id: Uuid, tags: &[String]) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE devices SET tags = ARRAY(SELECT t FROM unnest(tags) AS t WHERE t <> ALL($2::text[]))
            WHERE id = $1
            "#,
            id,
            tags
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Add tags. Existing tags kept; result sorted, no duplicates.
    pub async fn add_tags(&self, id: Uuid, tags: &[String]) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE devices SET tags = ARRAY(SELECT DISTINCT unnest(tags || $2::text[]) ORDER BY 1)
            WHERE id = $1
            "#,
            id,
            tags
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
