//! Firmware + config files served to devices (CW-16).

use time::OffsetDateTime;
use uuid::Uuid;

use crate::scope::scope_param;
use crate::{DeviceScope, Result, Store};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFile {
    /// Also the file name on disk.
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// Display + download name.
    pub name: String,
    /// TR-069 file type, e.g. `1 Firmware Upgrade Image`.
    pub file_type: String,
    pub size_bytes: i64,
    pub sha256: Vec<u8>,
    /// Firmware version, if firmware.
    pub version: Option<String>,
    /// Upload time.
    pub created_at: OffsetDateTime,
    /// Uploading device (config backups).
    pub device_id: Option<Uuid>,
}

/// File to register. Content already in storage under `id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewFile {
    /// Chosen by caller = storage key.
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    /// TR-069 file type (e.g. `1 Firmware Upgrade Image`).
    pub file_type: String,
    pub size_bytes: i64,
    pub sha256: Vec<u8>,
    pub version: Option<String>,
    /// Uploading device (config backups).
    pub device_id: Option<Uuid>,
}

impl Store {
    /// Insert file record. Duplicate name in tenant -> error.
    pub async fn insert_file(&self, f: &NewFile) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO files (id, tenant_id, name, file_type, size_bytes, sha256, storage_key, version,
                               device_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            f.id,
            f.tenant_id,
            f.name,
            f.file_type,
            f.size_bytes,
            f.sha256,
            f.id.to_string(),
            f.version,
            f.device_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_file(&self, id: Uuid) -> Result<Option<StoredFile>> {
        Ok(sqlx::query_as!(
            StoredFile,
            r#"
            SELECT id, tenant_id, name, file_type, size_bytes, sha256, version, created_at, device_id
            FROM files WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Files of a tenant, newest first.
    ///
    /// With `scope`: file of a device -> listed only while device in scope.
    /// File without device -> always listed.
    pub async fn list_files(
        &self,
        tenant_id: Uuid,
        scope: Option<&DeviceScope>,
    ) -> Result<Vec<StoredFile>> {
        Ok(sqlx::query_as!(
            StoredFile,
            r#"
            SELECT f.id, f.tenant_id, f.name, f.file_type, f.size_bytes, f.sha256, f.version,
                   f.created_at, f.device_id
            FROM files f
            WHERE f.tenant_id = $1
              AND ($2::jsonb IS NULL OR f.device_id IS NULL OR EXISTS (
                  SELECT 1 FROM devices d
                  WHERE d.id = f.device_id AND d.tenant_id = $1 AND device_in_scope(d, $2)))
            ORDER BY f.created_at DESC, f.id DESC
            "#,
            tenant_id,
            scope_param(scope)
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Files a device uploaded, newest first, max 100.
    pub async fn list_device_files(&self, device_id: Uuid) -> Result<Vec<StoredFile>> {
        Ok(sqlx::query_as!(
            StoredFile,
            r#"
            SELECT id, tenant_id, name, file_type, size_bytes, sha256, version, created_at, device_id
            FROM files WHERE device_id = $1 ORDER BY created_at DESC, id DESC LIMIT 100
            "#,
            device_id
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Delete file record -> true if it existed.
    pub async fn delete_file(&self, tenant_id: Uuid, id: Uuid) -> Result<bool> {
        let done = sqlx::query!(
            "DELETE FROM files WHERE id = $1 AND tenant_id = $2",
            id,
            tenant_id
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }
}
