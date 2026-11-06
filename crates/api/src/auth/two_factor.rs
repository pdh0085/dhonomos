//! Two-factor auth for local accounts (ADR-100): setup, off, recovery codes, admin reset,
//! login check.
//!
//! Secret made on the server -> shown once (text + QR code) -> stored encrypted with the
//! secrets key. Active only after the person sends a code (`enable`) -> app proven.
//! `enable` also gives the recovery codes (shown once, stored as hashes).
//! Each code good once: newest accepted time step stored with the secret.
//! Wrong codes at the account screens -> own table (`AppState::totp_attempts`,
//! key = account id, see `attempts`), per account + client address:
//! stolen session cannot guess codes without limit, cannot lock the owner out of login
//! (login has own table), and a name typed at login cannot lock the screens.
//! Try counted before the code check -> parallel requests cannot all pass the limit.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use dhonomos_store::User;
use zeroize::Zeroizing;

use super::*;
use crate::totp;

/// Max wait of a started setup for its first code.
const PENDING_SECS: i64 = 3600;
/// Max code length in bytes; longer -> not a code.
const MAX_CODE_BYTES: usize = 64;

/// Proof of the second factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Factor {
    /// Code of the authenticator app.
    Totp,
    /// Recovery code, used up.
    Recovery,
}

impl Factor {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Recovery => "recovery_code",
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn unavailable() -> ApiError {
    ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        "two-factor authentication is unavailable: the stored secret cannot be read (check --secrets-key)"
            .into(),
    )
}

fn rng_failure() -> ApiError {
    ApiError(
        StatusCode::INTERNAL_SERVER_ERROR,
        "random number generator failure".into(),
    )
}

fn wrong_code() -> ApiError {
    ApiError(StatusCode::FORBIDDEN, "wrong authentication code".into())
}

/// Count a try at `user`'s two-factor check by `client` before the check, or 429.
/// Settle: `success()` = right, `refund()` = nothing checked; drop = try counted (wrong).
fn reserve<'a>(
    s: &'a AppState,
    user: &User,
    client: &ClientInfo,
) -> Result<attempts::Slot<'a>, ApiError> {
    s.totp_attempts
        .reserve(&user.id.to_string(), &client.ip, true, Instant::now())
        .map_err(|_| {
            ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "too many wrong codes; try again later".into(),
            )
        })
}

fn log_failure(user: &User, client: &ClientInfo) {
    tracing::warn!(user = %user.username, client = %client.ip, "wrong two-factor code or password");
}

fn open_secret(
    s: &AppState,
    user: Uuid,
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    let secrets = s.config.secrets.as_deref().ok_or_else(unavailable)?;
    secrets
        .open_totp(user, ciphertext, nonce)
        .map(Zeroizing::new)
        .map_err(|e| {
            tracing::error!(error = %e, %user, "a two-factor secret could not be opened");
            unavailable()
        })
}

/// `input` = current code of the account secret + not used before?
async fn verify_totp(s: &AppState, user: Uuid, input: &str) -> Result<bool, ApiError> {
    let Some(active) = s.store.active_totp(user).await? else {
        return Ok(false);
    };
    let secret = open_secret(s, user, &active.ciphertext, &active.nonce)?;
    let Some(step) = totp::matching_step(&secret, input, now_unix(), active.last_step) else {
        return Ok(false);
    };
    let step = i64::try_from(step).unwrap_or(i64::MAX);
    // One statement -> of 2 requests with the same code, only 1 wins.
    Ok(s.store.claim_totp_step(user, step).await?)
}

/// Check `input` as second factor of `user`: app code, or (if `recovery`) a recovery code,
/// then used up. `None` -> neither, or not valid.
pub(super) async fn check_code(
    s: &AppState,
    user: &User,
    input: &str,
    recovery: bool,
) -> Result<Option<Factor>, ApiError> {
    if input.len() > MAX_CODE_BYTES {
        return Ok(None);
    }
    if totp::parse_code(input).is_some() {
        return Ok(verify_totp(s, user.id, input)
            .await?
            .then_some(Factor::Totp));
    }
    if recovery && let Some(code) = totp::normalize_recovery(input) {
        let used = s
            .store
            .use_recovery_code(user.id, &totp::recovery_hash(user.id, &code))
            .await?;
        return Ok(used.then_some(Factor::Recovery));
    }
    Ok(None)
}

/// Log + audit a login with a recovery code -> person should notice:
/// 1 code fewer, probably a lost or replaced phone.
pub(super) async fn note_recovery_login(s: &AppState, user: &User, client: &ClientInfo) {
    let left = s.store.recovery_codes_left(user.id).await.unwrap_or(0);
    tracing::warn!(user = %user.username, client = %client.ip, left, "logged in with a recovery code");
    ACTOR
        .scope(
            user.username.clone(),
            audit(
                s,
                "auth.recovery_code_used",
                "user",
                user.id,
                json!({ "codes_left": left, "client": client.ip }),
            ),
        )
        .await;
}

/// Account of the session making the request.
async fn own_account(s: &AppState, caller: &Principal) -> Result<User, ApiError> {
    match (caller.kind, caller.user_id) {
        ("session", Some(id)) => user_of(s, id).await,
        _ => Err(ApiError(
            StatusCode::FORBIDDEN,
            "two-factor authentication belongs to an account: log in with a username and password"
                .into(),
        )),
    }
}

/// SSO account: no password to add a factor to -> its provider does it.
fn local_only(user: &User) -> Result<(), ApiError> {
    if user.password_hash == SSO_HASH {
        return Err(unprocessable(
            "single sign-on accounts use the identity provider's own second factor",
        ));
    }
    Ok(())
}

/// Secrets stored encrypted -> no key, no setup.
fn needs_secrets_key(s: &AppState) -> Result<(), ApiError> {
    if s.config.secrets.is_none() {
        return Err(unprocessable(
            "two-factor authentication needs the server's --secrets-key to store its secrets",
        ));
    }
    Ok(())
}

/// New recovery codes + their stored hashes.
fn make_recovery_codes(user: Uuid) -> Result<(Vec<String>, Vec<Vec<u8>>), ApiError> {
    let codes = totp::new_recovery_codes().map_err(|_| rng_failure())?;
    let hashes = codes
        .iter()
        .filter_map(|c| totp::normalize_recovery(c))
        .map(|c| totp::recovery_hash(user, &c))
        .collect();
    Ok((codes, hashes))
}

/// Body of `POST /auth/totp/setup`.
#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TotpSetup {
    /// Current authentication code (or recovery code). Only when two-factor authentication
    /// is on already -> set up a new device.
    #[serde(default)]
    code: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/totp/setup",
    tag = "auth",
    operation_id = "totp_setup",
    summary = "Start setting up two-factor authentication",
    description = "Makes a new secret for the logged-in local account and returns it as text, as an `otpauth://` URI and as a QR code (SVG). It is not active until `POST /auth/totp/enable` confirms a code from it; another setup replaces it, and an unconfirmed one expires after an hour. If two-factor authentication is on already, a current code (or a recovery code) must be sent in `code`, and the old secret keeps working until the new one is confirmed. Works only in a login session of a local account, not with API keys or the API token, and only on a server with a `--secrets-key`. Also open to an admin who must enroll.",
    request_body = Option<TotpSetup>,
    responses(
        (status = 200, description = "The new secret", body = crate::schemas::TotpSetupResult),
        (status = 403, description = "Not a login session, or the code is wrong"),
        (status = 409, description = "Two-factor authentication is on already and no code was sent"),
        (status = 422, description = "Invalid body, a single sign-on account, or the server has no secrets key"),
        (status = 429, description = "Too many wrong codes; try again later"),
    ),
)]
pub(crate) async fn setup(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
    Extension(client): Extension<ClientInfo>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let req: TotpSetup = if body.is_empty() {
        TotpSetup::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| unprocessable(format!("invalid body: {e}")))?
    };
    let user = own_account(&s, &caller).await?;
    local_only(&user)?;
    needs_secrets_key(&s)?;
    if user.totp_enabled {
        // New device -> only by holder of the old one (or of a recovery code).
        let Some(code) = req.code.as_deref().filter(|c| !c.trim().is_empty()) else {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "two-factor authentication is on already: send a current authentication code (or a recovery code) as `code` to set up a new device"
                    .into(),
            ));
        };
        let slot = reserve(&s, &user, &client)?;
        match check_code(&s, &user, code, true).await {
            Ok(Some(factor)) => {
                slot.success();
                if factor == Factor::Recovery {
                    note_recovery_login(&s, &user, &client).await;
                }
            }
            Ok(None) => {
                log_failure(&user, &client);
                return Err(wrong_code());
            }
            Err(e) => {
                slot.refund();
                return Err(e);
            }
        }
    }
    let secret = Zeroizing::new(totp::new_secret().map_err(|_| rng_failure())?);
    let secrets = s.config.secrets.as_deref().ok_or_else(unavailable)?;
    let (ciphertext, nonce) = secrets.seal_totp(user.id, &secret[..]).map_err(|e| {
        tracing::error!(error = %e, "could not encrypt a two-factor secret");
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not encrypt the secret".into(),
        )
    })?;
    s.store
        .set_pending_totp(user.id, &ciphertext, &nonce, secrets.key_id())
        .await?;
    let secret_b32 = totp::secret_base32(&secret[..]);
    let uri = totp::otpauth_uri(s.config.totp.issuer(), &user.username, &secret_b32);
    let qr_svg = totp::qr_svg(&uri).map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not draw the QR code".into(),
        )
    })?;
    audit(
        &s,
        "totp.setup",
        "user",
        user.id,
        json!({ "replacing": user.totp_enabled }),
    )
    .await;
    Ok(Json(
        json!({ "secret": secret_b32, "otpauth_uri": uri, "qr_svg": qr_svg }),
    ))
}

/// Body of `POST /auth/totp/enable` and `POST /auth/totp/recovery-codes`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TotpCode {
    /// Six-digit code of the authenticator app.
    code: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/totp/enable",
    tag = "auth",
    operation_id = "totp_enable",
    summary = "Turn two-factor authentication on",
    description = "Checks a code against the secret `POST /auth/totp/setup` made, turns two-factor authentication on, and returns the recovery codes: ten single-use codes, shown only now. Ends the account's other sessions. Also open to an admin who must enroll.",
    request_body = TotpCode,
    responses(
        (status = 200, description = "Two-factor authentication is on", body = crate::schemas::RecoveryCodes),
        (status = 403, description = "Not a login session, or the code is wrong"),
        (status = 409, description = "No setup is in progress (or it timed out)"),
        (status = 422, description = "Invalid body, a single sign-on account, or the server has no secrets key"),
        (status = 429, description = "Too many wrong codes; try again later"),
    ),
)]
pub(crate) async fn enable(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
    Extension(client): Extension<ClientInfo>,
    headers: HeaderMap,
    body: Result<Json<TotpCode>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    let user = own_account(&s, &caller).await?;
    local_only(&user)?;
    needs_secrets_key(&s)?;
    let Some(pending) = s.store.pending_totp(user.id, PENDING_SECS).await? else {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "no setup is in progress, or it timed out: start with POST /auth/totp/setup".into(),
        ));
    };
    let secret = open_secret(&s, user.id, &pending.ciphertext, &pending.nonce)?;
    let slot = reserve(&s, &user, &client)?;
    let Some(step) = totp::matching_step(&secret, &req.code, now_unix(), None) else {
        log_failure(&user, &client);
        return Err(wrong_code());
    };
    slot.success();
    let (codes, hashes) = make_recovery_codes(user.id)?;
    // Only this session kept; other sessions of the account end.
    let keep = cookie_value(&headers, session_cookie_name(s.config.secure_cookies)).map(sha256);
    let step = i64::try_from(step).unwrap_or(i64::MAX);
    if !s
        .store
        .enable_totp(user.id, &pending.ciphertext, step, &hashes, keep.as_deref())
        .await?
    {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "the setup was replaced by another one; start again".into(),
        ));
    }
    audit(
        &s,
        "totp.enable",
        "user",
        user.id,
        json!({ "replaced_device": user.totp_enabled }),
    )
    .await;
    Ok(Json(json!({ "recovery_codes": codes })))
}

/// Body of `POST /auth/totp/disable`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TotpDisable {
    /// Account password.
    password: String,
    /// Current authentication code, or recovery code.
    code: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/totp/disable",
    tag = "auth",
    operation_id = "totp_disable",
    summary = "Turn two-factor authentication off",
    description = "Needs the account's password and a current code (or a recovery code). Refused for the roles `--require-totp-roles` names (admin by default): they can set up a new device instead, or an admin can reset it.",
    request_body = TotpDisable,
    responses(
        (status = 204, description = "Two-factor authentication is off"),
        (status = 403, description = "Not a login session, an admin who must keep it on, or the password or code is wrong"),
        (status = 409, description = "Two-factor authentication is not on"),
        (status = 422, description = "Invalid body, or a single sign-on account"),
        (status = 429, description = "Too many wrong codes; try again later"),
        (status = 503, description = "Too many logins are being checked at the moment; try again"),
    ),
)]
pub(crate) async fn disable(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
    Extension(client): Extension<ClientInfo>,
    body: Result<Json<TotpDisable>, axum::extract::rejection::JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    if req.password.len() > MAX_PASSWORD_BYTES {
        return Err(unprocessable("the password is too long"));
    }
    let user = own_account(&s, &caller).await?;
    local_only(&user)?;
    if !user.totp_enabled {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "two-factor authentication is not on".into(),
        ));
    }
    if s.config.totp.requires(&user.role) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "your role must keep two-factor authentication on (--require-totp-roles); set up a new device instead, or ask an admin to reset it"
                .into(),
        ));
    }
    // One message for both -> wrong answer says nothing about the other.
    let wrong = || {
        ApiError(
            StatusCode::FORBIDDEN,
            "wrong password or authentication code".into(),
        )
    };
    let slot = reserve(&s, &user, &client)?;
    match verify_async(&s, user.password_hash.clone(), req.password.clone()).await {
        Ok(true) => {}
        Ok(false) => {
            log_failure(&user, &client);
            return Err(wrong());
        }
        Err(e) => {
            slot.refund();
            return Err(e);
        }
    }
    match check_code(&s, &user, &req.code, true).await {
        Ok(Some(factor)) => {
            slot.success();
            if factor == Factor::Recovery {
                note_recovery_login(&s, &user, &client).await;
            }
        }
        Ok(None) => {
            log_failure(&user, &client);
            return Err(wrong());
        }
        Err(e) => {
            slot.refund();
            return Err(e);
        }
    }
    s.store.remove_totp(user.id, false).await?;
    audit(&s, "totp.disable", "user", user.id, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/totp/recovery-codes",
    tag = "auth",
    operation_id = "totp_recovery_codes",
    summary = "Make new recovery codes",
    description = "Needs a current code from the authenticator app (not a recovery code). The old recovery codes stop working. The new ones are shown only now.",
    request_body = TotpCode,
    responses(
        (status = 200, description = "The new recovery codes", body = crate::schemas::RecoveryCodes),
        (status = 403, description = "Not a login session, or the code is wrong"),
        (status = 409, description = "Two-factor authentication is not on"),
        (status = 422, description = "Invalid body, or a single sign-on account"),
        (status = 429, description = "Too many wrong codes; try again later"),
    ),
)]
pub(crate) async fn recovery_codes(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
    Extension(client): Extension<ClientInfo>,
    body: Result<Json<TotpCode>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    let user = own_account(&s, &caller).await?;
    local_only(&user)?;
    if !user.totp_enabled {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "two-factor authentication is not on".into(),
        ));
    }
    let slot = reserve(&s, &user, &client)?;
    match check_code(&s, &user, &req.code, false).await {
        Ok(Some(Factor::Totp)) => slot.success(),
        Ok(_) => {
            log_failure(&user, &client);
            return Err(wrong_code());
        }
        Err(e) => {
            slot.refund();
            return Err(e);
        }
    }
    let (codes, hashes) = make_recovery_codes(user.id)?;
    s.store.replace_recovery_codes(user.id, &hashes).await?;
    audit(&s, "totp.recovery_codes", "user", user.id, json!({})).await;
    Ok(Json(json!({ "recovery_codes": codes })))
}

#[utoipa::path(
    delete,
    path = "/api/v1/users/{id}/totp",
    tag = "users",
    operation_id = "reset_user_totp",
    summary = "Reset a user's two-factor authentication",
    description = "For a user who lost the phone and the recovery codes: removes their secret and recovery codes and ends all their sessions. They log in with the password alone (an account whose role must have it sets it up again at the next login). An admin cannot reset their own: they use `POST /auth/totp/disable` or set up a new device.",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 204, description = "Reset"),
        (status = 404, description = "Unknown user, or no two-factor authentication set up"),
        (status = 409, description = "The caller's own account"),
    ),
)]
pub(crate) async fn reset(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Extension(caller): Extension<Principal>,
) -> Result<StatusCode, ApiError> {
    let user = user_of(&s, id).await?;
    if caller.kind == "session" && caller.user_id == Some(id) {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "this is your own account: turn it off with POST /auth/totp/disable, or set up a new device".into(),
        ));
    }
    if !s.store.remove_totp(id, true).await? {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            "this user has no two-factor authentication set up".into(),
        ));
    }
    s.totp_attempts.forget(&user.id.to_string());
    audit(
        &s,
        "totp.reset",
        "user",
        id,
        json!({ "username": user.username }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}
