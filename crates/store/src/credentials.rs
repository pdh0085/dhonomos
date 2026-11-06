//! Per-device secrets, stored encrypted (CO-16).
//! Module moves ciphertext only.

use uuid::Uuid;

use crate::{Result, Store};

/// Per-device ACS credential + its relation to an Inform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcsBinding {
    pub device_id: Uuid,
    /// `acs_auth` or `acs_auth_pending`.
    pub kind: String,
    pub username: String,
    /// CPE has authenticated with it.
    pub confirmed: bool,
    /// Belongs to the device the Inform names.
    pub this_device: bool,
}

/// Encrypted credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedCredential {
    pub device_id: Uuid,
    /// `acs_auth` (CPE -> ACS), `connection_request` (ACS -> CPE),
    /// `xmpp` (XMPP login of the device, ADR-104), `mqtt` (USP broker account).
    /// `acs_auth_pending`, `connection_request_pending`, `xmpp_pending` = being provisioned.
    pub kind: String,
    /// Not secret.
    pub username: String,
    /// AES-GCM ciphertext + tag.
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    /// Key that sealed it.
    pub key_id: String,
}

impl Store {
    /// Insert or replace a device credential. Operator path (admin API).
    /// Provisioning from a CWMP session -> [`Store::put_pending_credential`], never replaces.
    pub async fn put_credential(&self, c: &SealedCredential) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO device_credentials (device_id, kind, username, secret_ciphertext, nonce, key_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (device_id, kind) DO UPDATE SET
                username = EXCLUDED.username, secret_ciphertext = EXCLUDED.secret_ciphertext,
                nonce = EXCLUDED.nonce, key_id = EXCLUDED.key_id, rotated_at = now()
            "#,
            c.device_id,
            c.kind,
            c.username,
            c.ciphertext,
            c.nonce,
            c.key_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Store a credential being provisioned (`acs_auth_pending`, `connection_request_pending`,
    /// `xmpp_pending`) unless the device has one of that kind. `true` = stored.
    /// `false` -> existing one kept -> a session that only claims the device identity
    /// cannot swap the credential under a provisioning in progress (M-4).
    pub async fn put_pending_credential(&self, c: &SealedCredential) -> Result<bool> {
        let done = sqlx::query!(
            r#"
            INSERT INTO device_credentials (device_id, kind, username, secret_ciphertext, nonce, key_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (device_id, kind) DO NOTHING
            "#,
            c.device_id,
            c.kind,
            c.username,
            c.ciphertext,
            c.nonce,
            c.key_id
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    pub async fn get_credential(
        &self,
        device_id: Uuid,
        kind: &str,
    ) -> Result<Option<SealedCredential>> {
        Ok(sqlx::query_as!(
            SealedCredential,
            r#"
            SELECT device_id, kind, username, secret_ciphertext AS ciphertext, nonce, key_id
            FROM device_credentials WHERE device_id = $1 AND kind = $2
            "#,
            device_id,
            kind
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    /// `acs_auth` + `acs_auth_pending` credentials with this username in a tenant, active first.
    /// CPE may use either: pending one = SPV that set it applied, but its answer lost.
    pub async fn find_acs_credentials(
        &self,
        tenant_id: Uuid,
        username: &str,
    ) -> Result<Vec<SealedCredential>> {
        Ok(sqlx::query_as!(
            SealedCredential,
            r#"
            SELECT c.device_id, c.kind, c.username, c.secret_ciphertext AS ciphertext, c.nonce, c.key_id
            FROM device_credentials c JOIN devices d ON d.id = c.device_id
            WHERE c.kind IN ('acs_auth', 'acs_auth_pending') AND c.username = $2 AND d.tenant_id = $1
            ORDER BY c.kind = 'acs_auth' DESC, c.device_id
            LIMIT 8
            "#,
            tenant_id,
            username
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// `xmpp` + `xmpp_pending` credentials of an active device of the tenant, active first.
    /// Device logs in with either: pending one after the SPV that set it applied
    /// (then it becomes the current one).
    pub async fn find_xmpp_credentials(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
    ) -> Result<Vec<SealedCredential>> {
        Ok(sqlx::query_as!(
            SealedCredential,
            r#"
            SELECT c.device_id, c.kind, c.username, c.secret_ciphertext AS ciphertext, c.nonce, c.key_id
            FROM device_credentials c JOIN devices d ON d.id = c.device_id
            WHERE c.kind IN ('xmpp', 'xmpp_pending') AND c.device_id = $2
              AND d.tenant_id = $1 AND d.status = 'active'
            ORDER BY c.kind = 'xmpp' DESC
            "#,
            tenant_id,
            device_id
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Kinds + usernames of the credentials of a device. No secrets.
    pub async fn list_credentials(&self, device_id: Uuid) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query!(
            "SELECT kind, username FROM device_credentials WHERE device_id = $1 ORDER BY kind",
            device_id
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| (r.kind, r.username)).collect())
    }

    /// Rename credential `from` -> `to` of a device, old `to` dropped.
    /// `false` = no `from` -> `to` unchanged.
    pub async fn promote_credential(&self, device_id: Uuid, from: &str, to: &str) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        sqlx::query!(
            "DELETE FROM device_credentials WHERE device_id = $1 AND kind = $2",
            device_id,
            to
        )
        .execute(&mut *tx)
        .await?;
        let done = sqlx::query!(
            r#"
            UPDATE device_credentials SET kind = $3, rotated_at = now()
            WHERE device_id = $1 AND kind = $2
            "#,
            device_id,
            from,
            to
        )
        .execute(&mut *tx)
        .await?;
        if done.rows_affected() == 1 {
            tx.commit().await?;
            Ok(true)
        } else {
            // No `from` -> rollback, current `to` kept.
            tx.rollback().await?;
            Ok(false)
        }
    }

    /// ACS credentials for an Inform: the one named `username` (any device)
    /// and the one of the device with `identity`, if any.
    pub async fn acs_auth_binding(
        &self,
        tenant_id: Uuid,
        identity: &crate::CwmpIdentity,
        username: &str,
    ) -> Result<Vec<AcsBinding>> {
        Ok(sqlx::query_as!(
            AcsBinding,
            r#"
            SELECT c.device_id AS "device_id!", c.kind AS "kind!", c.username AS "username!",
                   c.confirmed_at IS NOT NULL AS "confirmed!",
                   (d.oui = $2 AND d.product_class = $3 AND d.serial_number = $4) AS "this_device!"
            FROM device_credentials c JOIN devices d ON d.id = c.device_id
            WHERE d.tenant_id = $1 AND c.kind IN ('acs_auth', 'acs_auth_pending') AND c.username = $5
            UNION ALL
            SELECT c.device_id, c.kind, c.username, c.confirmed_at IS NOT NULL, true
            FROM devices d JOIN device_credentials c ON c.device_id = d.id
            WHERE d.tenant_id = $1 AND d.oui = $2 AND d.product_class = $3
              AND d.serial_number = $4 AND c.kind IN ('acs_auth', 'acs_auth_pending')
            "#,
            tenant_id,
            identity.oui,
            identity.product_class,
            identity.serial_number,
            username
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Mark `acs_auth` of a device as used by the CPE (first use only).
    pub async fn confirm_acs_auth(&self, device_id: Uuid) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE device_credentials SET confirmed_at = now()
            WHERE device_id = $1 AND kind = 'acs_auth' AND confirmed_at IS NULL
            "#,
            device_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete a credential and the one being provisioned to replace it:
    /// `acs_auth` -> also `acs_auth_pending`, `connection_request` -> also
    /// `connection_request_pending`, `xmpp` -> also `xmpp_pending`.
    /// Operator reset of provisioning: a session never replaces a pending credential.
    /// `true` = anything existed.
    pub async fn delete_credential(&self, device_id: Uuid, kind: &str) -> Result<bool> {
        let pending = match kind {
            "acs_auth" => "acs_auth_pending",
            "connection_request" => "connection_request_pending",
            "xmpp" => "xmpp_pending",
            other => other,
        };
        let done = sqlx::query!(
            "DELETE FROM device_credentials WHERE device_id = $1 AND kind IN ($2, $3)",
            device_id,
            kind,
            pending
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() >= 1)
    }

    /// Delete a device credential of exactly `kind`, if still the one of `nonce` (= credential id).
    /// Credential stored since -> left alone.
    /// Never another kind (!= [`Store::delete_credential`]). `true` = removed.
    pub async fn delete_credential_with_nonce(
        &self,
        device_id: Uuid,
        kind: &str,
        nonce: &[u8],
    ) -> Result<bool> {
        let done = sqlx::query!(
            "DELETE FROM device_credentials WHERE device_id = $1 AND kind = $2 AND nonce = $3",
            device_id,
            kind,
            nonce
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Credentials after `after`, `(device_id, kind)` order. For re-encryption (ADR-082).
    pub async fn credentials_page(
        &self,
        after: Option<(Uuid, String)>,
        limit: i64,
    ) -> Result<Vec<SealedCredential>> {
        let (dev, kind) = after.unzip();
        Ok(sqlx::query_as!(
            SealedCredential,
            r#"
            SELECT device_id, kind, username, secret_ciphertext AS ciphertext, nonce, key_id
            FROM device_credentials
            WHERE $1::uuid IS NULL OR (device_id, kind) > ($1, $2)
            ORDER BY device_id, kind LIMIT $3
            "#,
            dev,
            kind,
            limit
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Replace ciphertext with one sealed by another key, unless changed since `old` read.
    /// `true` = replaced.
    pub async fn rewrap_credential(
        &self,
        old: &SealedCredential,
        ciphertext: &[u8],
        nonce: &[u8],
        key_id: &str,
    ) -> Result<bool> {
        let done = sqlx::query!(
            r#"
            UPDATE device_credentials SET secret_ciphertext = $4, nonce = $5, key_id = $6
            WHERE device_id = $1 AND kind = $2 AND secret_ciphertext = $3
            "#,
            old.device_id,
            old.kind,
            old.ciphertext,
            ciphertext,
            nonce,
            key_id
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Unfinished tasks + jobs with an encrypted secret in payload: `(is_job, id, payload)`.
    /// Finished ones -> never decrypted again -> skipped.
    pub async fn payloads_with_secrets(&self) -> Result<Vec<(bool, Uuid, serde_json::Value)>> {
        let tasks = sqlx::query!(
            r#"
            SELECT id, payload FROM tasks
            WHERE state IN ('pending', 'running') AND payload::text LIKE '%enc:v_:%'
            "#
        )
        .fetch_all(&self.pool)
        .await?;
        let jobs = sqlx::query!(
            r#"
            SELECT id, task_payload FROM jobs
            WHERE state IN ('draft', 'running', 'paused') AND task_payload::text LIKE '%enc:v_:%'
            "#
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(tasks
            .into_iter()
            .map(|r| (false, r.id, r.payload))
            .chain(jobs.into_iter().map(|r| (true, r.id, r.task_payload)))
            .collect())
    }

    /// Replace payload of a task (or job) unless changed since `old` read. `true` = replaced.
    pub async fn replace_payload(
        &self,
        is_job: bool,
        id: Uuid,
        old: &serde_json::Value,
        new: &serde_json::Value,
    ) -> Result<bool> {
        let done = if is_job {
            sqlx::query!(
                "UPDATE jobs SET task_payload = $3 WHERE id = $1 AND task_payload = $2",
                id,
                old,
                new
            )
            .execute(&self.pool)
            .await?
        } else {
            sqlx::query!(
                "UPDATE tasks SET payload = $3 WHERE id = $1 AND payload = $2",
                id,
                old,
                new
            )
            .execute(&self.pool)
            .await?
        };
        Ok(done.rows_affected() == 1)
    }
}
