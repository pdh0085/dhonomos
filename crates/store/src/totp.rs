//! 2FA secrets + recovery codes (ADR-100).
//! Secrets stored encrypted (caller seals them); recovery codes only as hashes.

use uuid::Uuid;

use crate::{Result, Store};

/// TOTP secret as stored: sealed with the secrets key, bound to its account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedTotp {
    pub user_id: Uuid,
    /// true -> secret of an unconfirmed setup, not the one in use.
    pub pending: bool,
    /// AES-GCM ciphertext + tag.
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    /// Key that sealed it.
    pub key_id: String,
}

/// Secret in use + newest time step with an accepted code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveTotp {
    /// AES-GCM ciphertext + tag.
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    /// Newest accepted step. `None` -> no code accepted yet.
    pub last_step: Option<i64>,
}

/// Secret waiting for its first code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTotp {
    /// AES-GCM ciphertext + tag.
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl Store {
    /// Store secret waiting for its first code; replaces an older waiting one.
    /// Secret in use (if any) stays until [`Store::enable_totp`].
    pub async fn set_pending_totp(
        &self,
        user_id: Uuid,
        ciphertext: &[u8],
        nonce: &[u8],
        key_id: &str,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO user_totp (user_id, pending_ciphertext, pending_nonce, pending_key_id,
                                   pending_at)
            VALUES ($1, $2, $3, $4, now())
            ON CONFLICT (user_id) DO UPDATE SET
                pending_ciphertext = EXCLUDED.pending_ciphertext,
                pending_nonce = EXCLUDED.pending_nonce,
                pending_key_id = EXCLUDED.pending_key_id,
                pending_at = now()
            "#,
            user_id,
            ciphertext,
            nonce,
            key_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Secret waiting for its first code, only if set up within the last `max_age_secs`.
    pub async fn pending_totp(
        &self,
        user_id: Uuid,
        max_age_secs: i64,
    ) -> Result<Option<PendingTotp>> {
        Ok(sqlx::query!(
            r#"
            SELECT pending_ciphertext AS "ciphertext!", pending_nonce AS "nonce!"
            FROM user_totp
            WHERE user_id = $1 AND pending_ciphertext IS NOT NULL
              AND pending_at > now() - make_interval(secs => $2::double precision)
            "#,
            user_id,
            max_age_secs as f64
        )
        .fetch_optional(&self.pool)
        .await?
        .map(|r| PendingTotp {
            ciphertext: r.ciphertext,
            nonce: r.nonce,
        }))
    }

    /// Secret in use. `None` -> 2FA off.
    pub async fn active_totp(&self, user_id: Uuid) -> Result<Option<ActiveTotp>> {
        Ok(sqlx::query!(
            r#"
            SELECT ciphertext AS "ciphertext!", nonce AS "nonce!", last_step
            FROM user_totp
            WHERE user_id = $1 AND enabled_at IS NOT NULL
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await?
        .map(|r| ActiveTotp {
            ciphertext: r.ciphertext,
            nonce: r.nonce,
            last_step: r.last_step,
        }))
    }

    /// Record accepted code for `step` -> true if claimed.
    /// false: no secret in use, or code for this step or newer already accepted
    /// (replay, or 2 logins at the same instant -> only one wins).
    pub async fn claim_totp_step(&self, user_id: Uuid, step: i64) -> Result<bool> {
        let done = sqlx::query!(
            r#"
            UPDATE user_totp SET last_step = $2
            WHERE user_id = $1 AND enabled_at IS NOT NULL
              AND (last_step IS NULL OR last_step < $2)
            "#,
            user_id,
            step
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Waiting secret -> secret in use, after its code was accepted for `step`.
    /// Also: recovery codes of the account replaced by `recovery_hashes`.
    /// All sessions of the account ended except `keep_session` (token hash of the calling one).
    /// false -> waiting secret != `pending_ciphertext` (another setup replaced it meanwhile).
    pub async fn enable_totp(
        &self,
        user_id: Uuid,
        pending_ciphertext: &[u8],
        step: i64,
        recovery_hashes: &[Vec<u8>],
        keep_session: Option<&[u8]>,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let done = sqlx::query!(
            r#"
            UPDATE user_totp SET
                ciphertext = pending_ciphertext, nonce = pending_nonce, key_id = pending_key_id,
                enabled_at = now(), last_step = $3,
                pending_ciphertext = NULL, pending_nonce = NULL, pending_key_id = NULL,
                pending_at = NULL
            WHERE user_id = $1 AND pending_ciphertext = $2
            "#,
            user_id,
            pending_ciphertext,
            step
        )
        .execute(&mut *tx)
        .await?;
        if done.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(false);
        }
        replace_recovery(&mut tx, user_id, recovery_hashes).await?;
        sqlx::query!(
            "DELETE FROM sessions WHERE user_id = $1 AND ($2::bytea IS NULL OR token_hash <> $2)",
            user_id,
            keep_session
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Remove secrets + recovery codes of the account (2FA off, or setup abandoned).
    /// `end_sessions` -> also end all its sessions. Returns true if it had secrets.
    pub async fn remove_totp(&self, user_id: Uuid, end_sessions: bool) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let done = sqlx::query!("DELETE FROM user_totp WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query!(
            "DELETE FROM user_recovery_codes WHERE user_id = $1",
            user_id
        )
        .execute(&mut *tx)
        .await?;
        if end_sessions {
            sqlx::query!("DELETE FROM sessions WHERE user_id = $1", user_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(done.rows_affected() == 1)
    }

    /// Replace recovery codes of the account -> old ones stop working.
    pub async fn replace_recovery_codes(
        &self,
        user_id: Uuid,
        recovery_hashes: &[Vec<u8>],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        replace_recovery(&mut tx, user_id, recovery_hashes).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Use up a recovery code -> true if the account had it. A code works once.
    pub async fn use_recovery_code(&self, user_id: Uuid, code_hash: &[u8]) -> Result<bool> {
        let done = sqlx::query!(
            "DELETE FROM user_recovery_codes WHERE user_id = $1 AND code_hash = $2",
            user_id,
            code_hash
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    pub async fn recovery_codes_left(&self, user_id: Uuid) -> Result<i64> {
        Ok(sqlx::query_scalar!(
            r#"SELECT count(*) AS "n!" FROM user_recovery_codes WHERE user_id = $1"#,
            user_id
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// Secrets for re-encryption (ADR-082): accounts after `after` in order, max `limit`.
    /// Secret in use + waiting one -> separate entries.
    pub async fn totp_secrets_page(
        &self,
        after: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<SealedTotp>> {
        let rows = sqlx::query!(
            r#"
            SELECT user_id, ciphertext, nonce, key_id,
                   pending_ciphertext, pending_nonce, pending_key_id
            FROM user_totp
            WHERE $1::uuid IS NULL OR user_id > $1
            ORDER BY user_id LIMIT $2
            "#,
            after,
            limit
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::new();
        for r in rows {
            if let (Some(ciphertext), Some(nonce), Some(key_id)) = (r.ciphertext, r.nonce, r.key_id)
            {
                out.push(SealedTotp {
                    user_id: r.user_id,
                    pending: false,
                    ciphertext,
                    nonce,
                    key_id,
                });
            }
            if let (Some(ciphertext), Some(nonce), Some(key_id)) =
                (r.pending_ciphertext, r.pending_nonce, r.pending_key_id)
            {
                out.push(SealedTotp {
                    user_id: r.user_id,
                    pending: true,
                    ciphertext,
                    nonce,
                    key_id,
                });
            }
        }
        Ok(out)
    }

    /// Replace ciphertext of a secret with one sealed by another key -> true if replaced.
    /// Secret changed since `old` was read -> no change.
    pub async fn rewrap_totp(
        &self,
        old: &SealedTotp,
        ciphertext: &[u8],
        nonce: &[u8],
        key_id: &str,
    ) -> Result<bool> {
        let done = if old.pending {
            sqlx::query!(
                r#"
                UPDATE user_totp SET pending_ciphertext = $3, pending_nonce = $4, pending_key_id = $5
                WHERE user_id = $1 AND pending_ciphertext = $2
                "#,
                old.user_id,
                old.ciphertext,
                ciphertext,
                nonce,
                key_id
            )
            .execute(&self.pool)
            .await?
        } else {
            sqlx::query!(
                r#"
                UPDATE user_totp SET ciphertext = $3, nonce = $4, key_id = $5
                WHERE user_id = $1 AND ciphertext = $2
                "#,
                old.user_id,
                old.ciphertext,
                ciphertext,
                nonce,
                key_id
            )
            .execute(&self.pool)
            .await?
        };
        Ok(done.rows_affected() == 1)
    }
}

/// Delete recovery codes of the account + store `hashes` instead.
async fn replace_recovery(
    tx: &mut sqlx::PgConnection,
    user_id: Uuid,
    hashes: &[Vec<u8>],
) -> Result<()> {
    sqlx::query!(
        "DELETE FROM user_recovery_codes WHERE user_id = $1",
        user_id
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        r#"
        INSERT INTO user_recovery_codes (user_id, code_hash)
        SELECT $1, h.code_hash FROM unnest($2::bytea[]) AS h(code_hash)
        "#,
        user_id,
        hashes
    )
    .execute(&mut *tx)
    .await?;
    Ok(())
}
