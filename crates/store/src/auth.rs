//! Operators, sessions, API keys (NB-04). Only hashes stored.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::scope::scope_param;
use crate::wireguard::revoke_clients_of_user;
use crate::{DeviceScope, Result, RevokedClient, Store, StoreError};

/// Operator account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// Login name.
    pub username: String,
    /// Argon2id PHC string.
    pub password_hash: String,
    /// `admin`, `operator` or `viewer`.
    pub role: String,
    /// `true` -> no login.
    pub disabled: bool,
    pub created_at: OffsetDateTime,
    /// Last successful login.
    pub last_login_at: Option<OffsetDateTime>,
    /// Devices it may see + act on (`None` = all).
    pub scope: Option<DeviceScope>,
    /// TOTP 2FA on (ADR-100).
    pub totp_enabled: bool,
}

/// Account of a live session + how the session began.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionUser {
    pub user: User,
    /// Session from SSO -> identity provider handles the 2nd factor.
    pub sso: bool,
}

/// Result of an account change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserChanged {
    /// The account exists.
    pub found: bool,
    /// WireGuard client members revoked in the same transaction.
    /// Account disabled, deleted, role below operator or with device scope -> owns no
    /// clients (ADR-110 Q6).
    pub revoked_clients: Vec<RevokedClient>,
}

/// API key, without the key itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKey {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// Purpose.
    pub name: String,
    /// First chars -> recognise the key.
    pub prefix: String,
    /// `admin`, `operator` or `viewer`.
    pub role: String,
    /// Who created it.
    pub created_by: Option<String>,
    /// Creating operator account; key follows its state.
    /// `None` -> made with a token, or before keys were tied to accounts.
    pub created_by_user: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
    /// Devices it may see + act on (`None` = all).
    pub scope: Option<DeviceScope>,
}

/// Stored scope. Parse error -> query fails (never widens access).
fn parse_scope(v: Option<serde_json::Value>) -> Result<Option<DeviceScope>> {
    v.map(serde_json::from_value)
        .transpose()
        .map_err(|e| StoreError::Database(sqlx::Error::Decode(Box::new(e))))
}

struct UserRow {
    id: Uuid,
    tenant_id: Uuid,
    username: String,
    password_hash: String,
    role: String,
    disabled: bool,
    created_at: OffsetDateTime,
    last_login_at: Option<OffsetDateTime>,
    scope: Option<serde_json::Value>,
    totp_enabled: bool,
}

impl TryFrom<UserRow> for User {
    type Error = StoreError;

    fn try_from(r: UserRow) -> Result<Self> {
        Ok(Self {
            id: r.id,
            tenant_id: r.tenant_id,
            username: r.username,
            password_hash: r.password_hash,
            role: r.role,
            disabled: r.disabled,
            created_at: r.created_at,
            last_login_at: r.last_login_at,
            scope: parse_scope(r.scope)?,
            totp_enabled: r.totp_enabled,
        })
    }
}

/// [`UserRow`] + session columns.
struct SessionRow {
    id: Uuid,
    tenant_id: Uuid,
    username: String,
    password_hash: String,
    role: String,
    disabled: bool,
    created_at: OffsetDateTime,
    last_login_at: Option<OffsetDateTime>,
    scope: Option<serde_json::Value>,
    totp_enabled: bool,
    sso: bool,
    /// `last_seen_at` older than 1 min.
    stale: bool,
}

impl TryFrom<SessionRow> for SessionUser {
    type Error = StoreError;

    fn try_from(r: SessionRow) -> Result<Self> {
        Ok(Self {
            sso: r.sso,
            user: UserRow {
                id: r.id,
                tenant_id: r.tenant_id,
                username: r.username,
                password_hash: r.password_hash,
                role: r.role,
                disabled: r.disabled,
                created_at: r.created_at,
                last_login_at: r.last_login_at,
                scope: r.scope,
                totp_enabled: r.totp_enabled,
            }
            .try_into()?,
        })
    }
}

struct ApiKeyRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    prefix: String,
    role: String,
    created_by: Option<String>,
    created_by_user: Option<Uuid>,
    created_at: OffsetDateTime,
    last_used_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
    scope: Option<serde_json::Value>,
}

impl TryFrom<ApiKeyRow> for ApiKey {
    type Error = StoreError;

    fn try_from(r: ApiKeyRow) -> Result<Self> {
        Ok(Self {
            id: r.id,
            tenant_id: r.tenant_id,
            name: r.name,
            prefix: r.prefix,
            role: r.role,
            created_by: r.created_by,
            created_by_user: r.created_by_user,
            created_at: r.created_at,
            last_used_at: r.last_used_at,
            revoked_at: r.revoked_at,
            scope: parse_scope(r.scope)?,
        })
    }
}

impl Store {
    /// Any operator account in the DB (all tenants).
    pub async fn has_users(&self) -> Result<bool> {
        Ok(
            sqlx::query_scalar!(r#"SELECT EXISTS (SELECT 1 FROM users) AS "e!""#)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    /// Create an account -> ID. Fails if name taken.
    pub async fn create_user(
        &self,
        tenant_id: Uuid,
        username: &str,
        password_hash: &str,
        role: &str,
    ) -> Result<Uuid> {
        let id = Uuid::now_v7();
        sqlx::query!(
            r#"
            INSERT INTO users (id, tenant_id, username, password_hash, role)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            id,
            tenant_id,
            username,
            password_hash,
            role
        )
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn user_by_name(&self, tenant_id: Uuid, username: &str) -> Result<Option<User>> {
        sqlx::query_as!(
            UserRow,
            r#"
            SELECT id, tenant_id, username, password_hash, role, disabled, created_at, last_login_at, scope,
                   EXISTS (SELECT 1 FROM user_totp t WHERE t.user_id = users.id AND t.enabled_at IS NOT NULL) AS "totp_enabled!"
            FROM users WHERE tenant_id = $1 AND username = $2
            "#,
            tenant_id,
            username
        )
        .fetch_optional(&self.pool)
        .await?
        .map(TryInto::try_into)
        .transpose()
    }

    pub async fn get_user(&self, id: Uuid) -> Result<Option<User>> {
        sqlx::query_as!(
            UserRow,
            r#"
            SELECT id, tenant_id, username, password_hash, role, disabled, created_at, last_login_at, scope,
                   EXISTS (SELECT 1 FROM user_totp t WHERE t.user_id = users.id AND t.enabled_at IS NOT NULL) AS "totp_enabled!"
            FROM users WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?
        .map(TryInto::try_into)
        .transpose()
    }

    /// Tenant accounts, sorted by username.
    pub async fn list_users(&self, tenant_id: Uuid) -> Result<Vec<User>> {
        sqlx::query_as!(
            UserRow,
            r#"
            SELECT id, tenant_id, username, password_hash, role, disabled, created_at, last_login_at, scope,
                   EXISTS (SELECT 1 FROM user_totp t WHERE t.user_id = users.id AND t.enabled_at IS NOT NULL) AS "totp_enabled!"
            FROM users WHERE tenant_id = $1 ORDER BY username
            "#,
            tenant_id
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(TryInto::try_into)
        .collect()
    }

    /// Change role, disabled flag and/or password hash.
    ///
    /// Disable -> all sessions of the account end.
    /// New password -> all sessions end except `keep_session` (token hash of the session
    /// making the change, for own password change).
    /// Disable or role below `operator` -> its WireGuard clients revoked, same transaction.
    pub async fn update_user(
        &self,
        id: Uuid,
        role: Option<&str>,
        disabled: Option<bool>,
        password_hash: Option<&str>,
        keep_session: Option<&[u8]>,
    ) -> Result<UserChanged> {
        let mut tx = self.pool.begin().await?;
        let done = sqlx::query!(
            r#"
            UPDATE users SET role = COALESCE($2, role), disabled = COALESCE($3, disabled),
                password_hash = COALESCE($4, password_hash)
            WHERE id = $1
            "#,
            id,
            role,
            disabled,
            password_hash
        )
        .execute(&mut *tx)
        .await?;
        let found = done.rows_affected() == 1;
        let mut revoked_clients = Vec::new();
        if found && disabled == Some(true) {
            revoked_clients = revoke_clients_of_user(&mut tx, id, "user disabled").await?;
        } else if found && role.is_some_and(|r| !matches!(r, "admin" | "operator")) {
            revoked_clients = revoke_clients_of_user(&mut tx, id, "role changed").await?;
        }
        if disabled == Some(true) {
            sqlx::query!("DELETE FROM sessions WHERE user_id = $1", id)
                .execute(&mut *tx)
                .await?;
        } else if password_hash.is_some() {
            sqlx::query!(
                "DELETE FROM sessions WHERE user_id = $1 AND ($2::bytea IS NULL OR token_hash <> $2)",
                id,
                keep_session
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(UserChanged {
            found,
            revoked_clients,
        })
    }

    /// Account of an SSO identity: provider (`iss`) + user subject there (`sub`).
    /// `sub` never changes, unlike names and e-mail addresses.
    pub async fn user_by_oidc(
        &self,
        tenant_id: Uuid,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<User>> {
        sqlx::query_as!(
            UserRow,
            r#"
            SELECT id, tenant_id, username, password_hash, role, disabled, created_at, last_login_at, scope,
                   EXISTS (SELECT 1 FROM user_totp t WHERE t.user_id = users.id AND t.enabled_at IS NOT NULL) AS "totp_enabled!"
            FROM users WHERE tenant_id = $1 AND oidc_issuer = $2 AND oidc_subject = $3
            "#,
            tenant_id,
            issuer,
            subject
        )
        .fetch_optional(&self.pool)
        .await?
        .map(TryInto::try_into)
        .transpose()
    }

    /// SSO identity `(issuer, subject)` of an account, if any.
    pub async fn oidc_identity(&self, id: Uuid) -> Result<Option<(String, String)>> {
        Ok(sqlx::query!(
            "SELECT oidc_issuer, oidc_subject FROM users WHERE id = $1",
            id
        )
        .fetch_optional(&self.pool)
        .await?
        .and_then(|r| Some((r.oidc_issuer?, r.oidc_subject?))))
    }

    /// Attach an SSO identity to an account without one -> `true` if done.
    /// `false`: account has one already, or identity belongs to another account.
    pub async fn attach_oidc_identity(
        &self,
        id: Uuid,
        issuer: &str,
        subject: &str,
    ) -> Result<bool> {
        let done = sqlx::query!(
            r#"
            UPDATE users SET oidc_issuer = $2, oidc_subject = $3
            WHERE id = $1 AND oidc_subject IS NULL
            "#,
            id,
            issuer,
            subject
        )
        .execute(&self.pool)
        .await;
        match done {
            Ok(done) => Ok(done.rows_affected() == 1),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Create an account for an SSO identity -> ID. No password: `!sso` matches no hash.
    /// Fails if name or identity taken.
    pub async fn create_sso_user(
        &self,
        tenant_id: Uuid,
        username: &str,
        role: &str,
        issuer: &str,
        subject: &str,
    ) -> Result<Uuid> {
        let id = Uuid::now_v7();
        sqlx::query!(
            r#"
            INSERT INTO users (id, tenant_id, username, password_hash, role, oidc_issuer, oidc_subject)
            VALUES ($1, $2, $3, '!sso', $4, $5, $6)
            "#,
            id,
            tenant_id,
            username,
            role,
            issuer,
            subject
        )
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Set or clear (`None` = all devices) the device scope of an account.
    /// Scope set -> its WireGuard clients revoked, same transaction (scoped account owns
    /// no clients).
    pub async fn set_user_scope(
        &self,
        id: Uuid,
        scope: Option<&DeviceScope>,
    ) -> Result<UserChanged> {
        let mut tx = self.pool.begin().await?;
        let done = sqlx::query!(
            "UPDATE users SET scope = $2 WHERE id = $1",
            id,
            scope_param(scope)
        )
        .execute(&mut *tx)
        .await?;
        let found = done.rows_affected() == 1;
        let revoked_clients = if found && scope.is_some() {
            revoke_clients_of_user(&mut tx, id, "scope changed").await?
        } else {
            Vec::new()
        };
        tx.commit().await?;
        Ok(UserChanged {
            found,
            revoked_clients,
        })
    }

    /// Delete an account + its sessions.
    /// Its WireGuard clients revoked first; rows kept, without owner.
    pub async fn delete_user(&self, id: Uuid) -> Result<UserChanged> {
        let mut tx = self.pool.begin().await?;
        // `create_wg_member` holds a share lock on the client owner while adding a client.
        // Row lock first -> such a creation finishes before the revoke below (revoke sees
        // its member) or waits, then finds no owner (OwnerNotFound).
        // Without it -> client created in between survives as live server client, `user_id` NULL.
        sqlx::query!("SELECT id FROM users WHERE id = $1 FOR UPDATE", id)
            .fetch_optional(&mut *tx)
            .await?;
        let revoked_clients = revoke_clients_of_user(&mut tx, id, "user deleted").await?;
        let done = sqlx::query!("DELETE FROM users WHERE id = $1", id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(UserChanged {
            found: done.rows_affected() == 1,
            revoked_clients,
        })
    }

    /// Start a session. `sso` -> from SSO (see [`SessionUser`]).
    pub async fn create_session(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        expires_at: OffsetDateTime,
        sso: bool,
    ) -> Result<()> {
        sqlx::query!(
            "INSERT INTO sessions (token_hash, user_id, expires_at, sso) VALUES ($1, $2, $3, $4)",
            token_hash,
            user_id,
            expires_at,
            sso
        )
        .execute(&self.pool)
        .await?;
        sqlx::query!(
            "UPDATE users SET last_login_at = now() WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Enabled account of a live session.
    ///
    /// Unused for `idle_secs` s -> not live (`idle_secs <= 0` -> no idle limit).
    /// `last_seen_at` update max 1/min -> busy session != 1 row write per request.
    pub async fn session_user(
        &self,
        token_hash: &[u8],
        idle_secs: i64,
    ) -> Result<Option<SessionUser>> {
        let Some(found) = sqlx::query_as!(
            SessionRow,
            r#"
            SELECT u.id, u.tenant_id, u.username, u.password_hash, u.role, u.disabled,
                   u.created_at, u.last_login_at, u.scope, s.sso,
                   EXISTS (SELECT 1 FROM user_totp t WHERE t.user_id = u.id AND t.enabled_at IS NOT NULL) AS "totp_enabled!",
                   (s.last_seen_at < now() - interval '1 minute') AS "stale!"
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = $1 AND s.expires_at > now() AND NOT u.disabled
              AND ($2::float8 <= 0 OR s.last_seen_at > now() - make_interval(secs => $2::float8))
            "#,
            token_hash,
            idle_secs as f64
        )
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };
        if found.stale {
            sqlx::query!(
                "UPDATE sessions SET last_seen_at = now() WHERE token_hash = $1 AND last_seen_at < now() - interval '1 minute'",
                token_hash
            )
            .execute(&self.pool)
            .await?;
        }
        found.try_into().map(Some)
    }

    pub async fn delete_session(&self, token_hash: &[u8]) -> Result<()> {
        sqlx::query!("DELETE FROM sessions WHERE token_hash = $1", token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Remove expired sessions -> count.
    pub async fn delete_expired_sessions(&self) -> Result<u64> {
        Ok(
            sqlx::query!("DELETE FROM sessions WHERE expires_at < now()")
                .execute(&self.pool)
                .await?
                .rows_affected(),
        )
    }

    /// Store a new API key -> ID.
    ///
    /// `created_by_user` = creating operator account -> key works only while that account
    /// exists and is enabled. `None` -> made with a token or by a key, tied to no account.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_api_key(
        &self,
        tenant_id: Uuid,
        name: &str,
        key_hash: &[u8],
        prefix: &str,
        role: &str,
        scope: Option<&DeviceScope>,
        created_by: Option<&str>,
        created_by_user: Option<Uuid>,
    ) -> Result<Uuid> {
        let id = Uuid::now_v7();
        sqlx::query!(
            r#"
            INSERT INTO api_keys (id, tenant_id, name, key_hash, prefix, role, scope, created_by,
                                  created_by_user)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            id,
            tenant_id,
            name,
            key_hash,
            prefix,
            role,
            scope_param(scope),
            created_by,
            created_by_user
        )
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Live key with this hash -> its use recorded.
    /// Key of an operator account -> live only while that account is enabled.
    /// Account deleted -> its keys deleted.
    pub async fn use_api_key(&self, key_hash: &[u8]) -> Result<Option<ApiKey>> {
        sqlx::query_as!(
            ApiKeyRow,
            r#"
            UPDATE api_keys k SET last_used_at = now()
            WHERE k.key_hash = $1 AND k.revoked_at IS NULL
              AND (k.created_by_user IS NULL OR EXISTS (
                  SELECT 1 FROM users u WHERE u.id = k.created_by_user AND NOT u.disabled))
            RETURNING k.id, k.tenant_id, k.name, k.prefix, k.role, k.created_by, k.created_by_user,
                      k.created_at, k.last_used_at, k.revoked_at, k.scope
            "#,
            key_hash
        )
        .fetch_optional(&self.pool)
        .await?
        .map(TryInto::try_into)
        .transpose()
    }

    /// Tenant keys, newest first.
    pub async fn list_api_keys(&self, tenant_id: Uuid) -> Result<Vec<ApiKey>> {
        sqlx::query_as!(
            ApiKeyRow,
            r#"
            SELECT id, tenant_id, name, prefix, role, created_by, created_by_user, created_at,
                   last_used_at, revoked_at, scope
            FROM api_keys WHERE tenant_id = $1 ORDER BY created_at DESC
            "#,
            tenant_id
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(TryInto::try_into)
        .collect()
    }

    /// Revoke a key -> `true` if a live key was revoked.
    pub async fn revoke_api_key(&self, tenant_id: Uuid, id: Uuid) -> Result<bool> {
        let done = sqlx::query!(
            "UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL",
            id,
            tenant_id
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }
}
