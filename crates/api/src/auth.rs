//! Authentication + authorization (NB-04): operator accounts with sessions (HttpOnly
//! cookie), API keys, static `--api-token`, 3 roles.
//!
//! | Role | May |
//! |---|---|
//! | `viewer` | read (GET) |
//! | `operator` | also change devices, tasks, jobs, files, backups, alarms, WireGuard members; read stored file contents, the BulkData URL and WireGuard data |
//! | `admin` | also manage users, API keys, credentials, certificates, broker accounts, WireGuard hubs and networks, deletions |
//!
//! Viewer or operator with a device scope (ADR-074) -> sees and acts on devices inside it
//! only (`device_of` + list queries apply it); fleet-wide operations refused.
//!
//! Local accounts: optional two-factor auth with a TOTP app (ADR-100, [`two_factor`]);
//! required for roles in `--require-totp-roles` (default: admin).
//! Not for API keys, static `--api-token`, single sign-on.
//!
//! Behind a reverse proxy (ADR-103): request with proxy headers -> never the anonymous admin
//! of open mode (no accounts, no token). Client address for limits + lockouts = the one the
//! trusted proxy forwards ([`crate::client`]). Guessing limits: [`attempts`].

pub(crate) mod attempts;
pub(crate) mod two_factor;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Extension, Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dhonomos_store::DeviceScope;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use self::attempts::Attempts;
use crate::client::{ClientInfo, info_of};
use crate::{ApiError, AppState, audit, not_found, ts};

/// Session cookie name. With `--secure-cookies` -> [`SESSION_COOKIE_HOST`].
pub(crate) const SESSION_COOKIE: &str = "dhonomos_session";
/// Session cookie name with `--secure-cookies`. `__Host-` prefix -> browser binds the
/// cookie to this exact host (no `Domain`, `Path=/`, `Secure`) -> sibling sub-domain cannot
/// plant or overwrite it. Old name not read then (older sessions end: one new login).
pub(crate) const SESSION_COOKIE_HOST: &str = "__Host-dhonomos_session";
/// Password hash of an SSO account: matches no password.
pub(crate) const SSO_HASH: &str = "!sso";
const MIN_PASSWORD: usize = 10;
/// Max wait of a login for a free hash slot, then refused.
const HASH_WAIT: Duration = Duration::from_secs(10);
/// Rate (1/s) + burst per client address on public routes that cost work: login, SSO.
const PUBLIC_RATE: u32 = 2;
const PUBLIC_BURST: u32 = 30;

/// What a caller may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Role {
    Viewer,
    Operator,
    Admin,
}

impl Role {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(Self::Viewer),
            "operator" => Some(Self::Operator),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }
}

/// Authenticated caller.
#[derive(Debug, Clone)]
pub(crate) struct Principal {
    name: String,
    role: Role,
    kind: &'static str,
    /// Devices it may see and act on (`None` = all).
    scope: Option<Arc<DeviceScope>>,
    /// Operator account behind it: session user, or API key creator.
    user_id: Option<Uuid>,
    /// Session account has two-factor auth on.
    totp_enabled: bool,
    /// Session account must have it (role in `--require-totp-roles` + password login)
    /// -> until then, session for enrollment only.
    totp_required: bool,
    /// Session account can have it: local account + server with a secrets key.
    totp_available: bool,
}

impl Principal {
    fn new(name: String, role: Role, kind: &'static str, scope: Option<DeviceScope>) -> Self {
        // Scope + admin role = no effect (admin can change own account) -> act as operator.
        let role = if scope.is_some() {
            role.min(Role::Operator)
        } else {
            role
        };
        Self {
            name,
            role,
            kind,
            scope: scope.map(Arc::new),
            user_id: None,
            totp_enabled: false,
            totp_required: false,
            totp_available: false,
        }
    }

    /// Session limited to two-factor enrollment.
    fn enrollment_only(&self) -> bool {
        self.totp_required && !self.totp_enabled
    }

    fn of_user(mut self, user_id: Option<Uuid>) -> Self {
        self.user_id = user_id;
        self
    }

    /// Caller with a device scope -> max operator.
    pub(crate) fn role(&self) -> Role {
        self.role
    }

    pub(crate) fn user_id(&self) -> Option<Uuid> {
        self.user_id
    }

    /// Devices the caller may see and act on (`None` = all).
    pub(crate) fn scope(&self) -> Option<&DeviceScope> {
        self.scope.as_deref()
    }
}

tokio::task_local! {
    /// Actor name of the current request (audit log).
    pub(crate) static ACTOR: String;
    /// Device scope of the current caller (`None` = every device).
    static SCOPE: Option<Arc<DeviceScope>>;
}

/// Device scope of the current caller (`None` = every device).
/// Outside a request -> error, not allow-all.
pub(crate) fn caller_scope() -> Result<Option<Arc<DeviceScope>>, ApiError> {
    SCOPE.try_with(Clone::clone).map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "no caller scope for this request".into(),
        )
    })
}

fn scoped_refusal() -> ApiError {
    ApiError(
        StatusCode::FORBIDDEN,
        "this needs an account without a device scope".into(),
    )
}

pub(crate) fn sha256(s: &str) -> Vec<u8> {
    Sha256::digest(s.as_bytes()).to_vec()
}

pub(crate) fn random_token() -> Result<String, ApiError> {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "random number generator failure".into(),
        )
    })?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

/// Argon2id hash (PHC string) of a password.
pub fn hash_password(password: &str) -> Result<String, String> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| e.to_string())?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| e.to_string())?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

fn verify_password(hash: &str, password: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| {
        Argon2::default()
            .verify_password(password.as_bytes(), &h)
            .is_ok()
    })
}

/// Max parallel password hashes: 1 per core -> login flood cannot take all cores
/// (each hash: 19 MiB + tens of ms of one core).
pub(crate) fn hash_slots() -> usize {
    std::thread::available_parallelism().map_or(2, usize::from)
}

/// Run `work` (Argon2 hash or check) on a blocking thread, max `hash_slots()` at a time.
/// Slot wait > [`HASH_WAIT`] -> 503, no ever longer queue.
async fn hashing<T: Send + 'static>(
    s: &AppState,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ApiError> {
    blocking_limited(&s.hashing, HASH_WAIT, work).await
}

/// [`hashing`] with given slots + wait.
async fn blocking_limited<T: Send + 'static>(
    slots: &Arc<tokio::sync::Semaphore>,
    wait: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ApiError> {
    let busy = || {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many logins in progress; try again".into(),
        )
    };
    let permit = tokio::time::timeout(wait, slots.clone().acquire_owned())
        .await
        .map_err(|_| busy())?
        .map_err(|_| busy())?;
    tokio::task::spawn_blocking(move || {
        let out = work();
        drop(permit);
        out
    })
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "password hashing crashed");
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "password hashing failed".into(),
        )
    })
}

async fn hash_async(s: &AppState, password: String) -> Result<String, ApiError> {
    hashing(s, move || hash_password(&password))
        .await?
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))
}

async fn verify_async(s: &AppState, hash: String, password: String) -> Result<bool, ApiError> {
    hashing(s, move || verify_password(&hash, &password)).await
}

pub(crate) fn constant_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |x, (p, q)| x | (p ^ q)) == 0
}

/// Role a request needs, from method + path (relative to `/api/v1`).
pub(crate) fn required_role(method: &Method, path: &str) -> Role {
    let path = path.strip_prefix("/api/v1").unwrap_or(path);
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    // Everyone sets up + manages own two-factor auth.
    if segments.starts_with(&["auth", "totp"]) {
        return Role::Viewer;
    }
    let admin = matches!(segments.first(), Some(&"users" | &"api-keys"))
        // Server config + runtime settings changed from the web.
        || segments.first() == Some(&"settings")
        || segments.contains(&"credentials")
        || segments.last() == Some(&"mqtt-credentials")
        || segments.last() == Some(&"certificate")
        || (segments.contains(&"certificates") && method != Method::GET)
        || (method == Method::DELETE && segments.len() == 2 && segments[0] == "devices")
        // Bulk device delete = role of single delete.
        || (method == Method::POST && segments == ["devices", "delete"])
        || wireguard_admin_write(method, &segments);
    // Reads that need operator: stored files (config backups may hold secrets),
    // BulkData URL (non-expiring link that accepts writes, L-8),
    // WireGuard hubs/networks/members (tunnel addresses, keys, LAN prefixes).
    let operator_read = (segments.first() == Some(&"files") && segments.last() == Some(&"content"))
        || segments.last() == Some(&"bulkdata-url")
        || segments.first() == Some(&"wireguard")
        || matches!(segments.as_slice(), ["devices", _, "wireguard"]);
    if admin {
        Role::Admin
    } else if (method == Method::GET || method == Method::HEAD) && !operator_read {
        Role::Viewer
    } else {
        Role::Operator
    }
}

/// WireGuard changes that need admin: hubs, networks (also rotating all device keys of one),
/// member delete. Other member changes -> operator (device member in the operator's device
/// scope, client member of the operator's own); handlers decide that.
fn wireguard_admin_write(method: &Method, segments: &[&str]) -> bool {
    if matches!(*method, Method::GET | Method::HEAD) {
        return false;
    }
    match segments {
        ["wireguard", "hubs", ..]
        | ["wireguard", "networks"]
        | ["wireguard", "networks", _]
        | ["wireguard", "networks", _, "rotate-keys"] => true,
        ["wireguard", "members", _] => method == Method::DELETE,
        _ => false,
    }
}

/// Fleet-wide or shared-resource operations, refused to scoped callers:
/// bulk device preregister + delete, attribute import, certificate bundle + revoke,
/// file changes, preset changes, Prometheus metrics.
pub(crate) fn fleet_wide(method: &Method, path: &str) -> bool {
    let path = path.strip_prefix("/api/v1").unwrap_or(path);
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match segments.as_slice() {
        ["metrics"] => true,
        ["devices"] | ["devices", "bulk" | "delete"] => method == Method::POST,
        ["devices", "attributes", "import"] => true,
        // Certificates for any devices the caller names -> keys of the whole fleet.
        ["certificates", "bundle" | "revoke"] => true,
        ["files", ..] => method != Method::GET && method != Method::HEAD,
        // Presets act on every device; dry run + validate change nothing.
        ["presets", "dry-run" | "validate"] => false,
        ["presets", ..] => method != Method::GET && method != Method::HEAD,
        _ => false,
    }
}

pub(crate) fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

async fn users_exist(s: &AppState) -> bool {
    // Cache only "yes" (deleting users never opens the API).
    // "No" -> ask again each time: accounts made by the OIDC callback or another API instance
    // must close open dev mode at once (audit M-1).
    // DB error -> "yes" (closed), not cached.
    if s.users_exist.load(Ordering::Relaxed) {
        return true;
    }
    match s.store.has_users().await {
        Ok(false) => false,
        Ok(true) => {
            s.users_exist.store(true, Ordering::Relaxed);
            true
        }
        Err(_) => true,
    }
}

/// Credentials of a request (owned -> no request borrow across awaits).
struct Credentials {
    bearer: Option<String>,
    session: Option<String>,
}

/// Session cookie name this server sets + reads (see [`SESSION_COOKIE_HOST`]).
pub(crate) fn session_cookie_name(secure_cookies: bool) -> &'static str {
    if secure_cookies {
        SESSION_COOKIE_HOST
    } else {
        SESSION_COOKIE
    }
}

/// Cookies with `Secure`? `--secure-cookies`, or a trusted proxy says HTTPS.
pub(crate) fn cookies_secure(s: &AppState, info: &ClientInfo) -> bool {
    s.config.secure_cookies || info.https()
}

fn credentials(req: &Request, cookie_name: &str) -> Credentials {
    Credentials {
        bearer: req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_owned),
        session: cookie_value(req.headers(), cookie_name).map(str::to_owned),
    }
}

async fn principal_of(s: &AppState, c: &Credentials) -> Result<Option<Principal>, ApiError> {
    if let Some(given) = c.bearer.as_deref() {
        if let Some(token) = &s.config.bearer_token
            && constant_eq(given, token)
        {
            return Ok(Some(Principal::new(
                "api-token".into(),
                Role::Admin,
                "token",
                None,
            )));
        }
        if given.starts_with("pk_")
            && let Some(key) = s.store.use_api_key(&sha256(given)).await?
            && key.tenant_id == s.config.tenant_id
        {
            // Account behind the key -> also owner of keys this key makes.
            return Ok(Some(
                Principal::new(
                    format!("key:{}", key.name),
                    Role::parse(&key.role).unwrap_or(Role::Viewer),
                    "api_key",
                    key.scope,
                )
                .of_user(key.created_by_user),
            ));
        }
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid bearer token or API key".into(),
        ));
    }
    if let Some(token) = c.session.as_deref()
        && let Some(found) = s
            .store
            .session_user(
                &sha256(token),
                (*s.config.session_idle_minutes.get())
                    .max(0)
                    .saturating_mul(60),
            )
            .await?
        && found.user.tenant_id == s.config.tenant_id
    {
        let user = found.user;
        // Two-factor = local accounts only; SSO session -> identity provider's own factor.
        let local = user.password_hash != SSO_HASH;
        let mut p = Principal::new(
            user.username,
            Role::parse(&user.role).unwrap_or(Role::Viewer),
            "session",
            user.scope,
        )
        .of_user(Some(user.id));
        p.totp_enabled = user.totp_enabled;
        p.totp_available = local && s.config.secrets.is_some();
        p.totp_required = s.config.totp.requires(p.role.as_str()) && local && !found.sso;
        return Ok(Some(p));
    }
    Ok(None)
}

/// Middleware: authenticate the caller + check the role the route needs.
/// No token + no user accounts -> API open to direct callers (development);
/// never for a request via a proxy (X-1).
pub(crate) async fn authenticate(
    State(s): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let required = required_role(req.method(), req.uri().path());
    let creds = credentials(&req, session_cookie_name(s.config.secure_cookies));
    let info = info_of(&req);
    let client = info.ip.as_str();
    let principal = match principal_of(&s, &creds).await {
        Ok(Some(p)) => p,
        Ok(None) if s.config.bearer_token.is_none() && !users_exist(&s).await => {
            if info.proxied {
                // Behind a proxy every visitor looks local -> anonymous admin for the whole
                // internet. Only an account closes this.
                if let Err(wait) = s.limiter.check(&format!("ip:{client}"), Instant::now()) {
                    return Ok(rate_limited(wait));
                }
                return Err(ApiError(
                    StatusCode::UNAUTHORIZED,
                    "no accounts exist; create an admin account on the server (--admin-password)"
                        .into(),
                ));
            }
            Principal::new("anonymous".into(), Role::Admin, "open", None)
        }
        found @ (Ok(None) | Err(ApiError(StatusCode::UNAUTHORIZED, _))) => {
            // Failed auth still costs a lookup -> limit per client address.
            if let Err(wait) = s.limiter.check(&format!("ip:{client}"), Instant::now()) {
                return Ok(rate_limited(wait));
            }
            return Err(found.err().unwrap_or_else(|| {
                ApiError(
                    StatusCode::UNAUTHORIZED,
                    "log in, or send a bearer token or API key".into(),
                )
            }));
        }
        Err(e) => return Err(e),
    };
    let key = if principal.kind == "open" {
        format!("ip:{client}")
    } else {
        format!("{}:{}", principal.kind, principal.name)
    };
    if let Err(wait) = s.limiter.check(&key, Instant::now()) {
        return Ok(rate_limited(wait));
    }
    if principal.enrollment_only() && !enrollment_route(req.method(), req.uri().path()) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "two-factor enrollment required".into(),
        ));
    }
    if principal.role < required {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            format!("this needs the {} role", required.as_str()),
        ));
    }
    if principal.scope.is_some() && fleet_wide(req.method(), req.uri().path()) {
        return Err(scoped_refusal());
    }
    // Cookie sessions: browser change request must come from this site (defence in depth
    // behind SameSite=Strict). Browsers never send tokens + API keys on their own.
    if principal.kind == "session"
        && !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS)
        && !same_origin(&req, &info, s.config.public_url.as_ref())
    {
        tracing::warn!(user = %principal.name, client = %info.ip, "cross-origin change request refused");
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "cross-origin request refused".into(),
        ));
    }
    let name = principal.name.clone();
    let scope = principal.scope.clone();
    req.extensions_mut().insert(principal);
    Ok(ACTOR.scope(name, SCOPE.scope(scope, next.run(req))).await)
}

/// Calls left to a session that must enroll in two-factor auth (logout needs no session):
/// who am I, set up + confirm the app.
fn enrollment_route(method: &Method, path: &str) -> bool {
    let path = path.strip_prefix("/api/v1").unwrap_or(path);
    matches!(
        (method, path.trim_end_matches('/')),
        (&Method::GET, "/auth/me") | (&Method::POST, "/auth/totp/setup" | "/auth/totp/enable")
    )
}

/// Request `Origin` (if any) = this site?
///
/// With `--public-url` -> exactly that address (scheme, host, port).
/// Without -> host = request `Host`, or `X-Forwarded-Host` of a trusted proxy
/// (others ignored: a forged one would vouch for the forger);
/// scheme = the one a trusted proxy reports, if any.
fn same_origin(
    req: &Request,
    info: &ClientInfo,
    public: Option<&crate::client::PublicOrigin>,
) -> bool {
    let Some(origin) = req.headers().get("origin") else {
        return true; // not a cross-site browser request
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    if let Some(public) = public {
        return public.matches(origin);
    }
    let Some((scheme, origin_host)) = origin.split_once("://") else {
        return false; // e.g. `null` from a sandboxed frame
    };
    if info
        .scheme
        .is_some_and(|s| !scheme.eq_ignore_ascii_case(s.as_str()))
    {
        return false;
    }
    let host = req.headers().get("host").and_then(|v| v.to_str().ok());
    [host, info.forwarded_host.as_deref()]
        .into_iter()
        .flatten()
        .any(|h| h.trim().eq_ignore_ascii_case(origin_host))
}

/// 429 + `Retry-After` (whole seconds, min 1).
fn rate_limited(wait: std::time::Duration) -> Response {
    metrics::counter!("dhonomos_api_rate_limited_total").increment(1);
    let secs = wait.as_secs_f64().ceil().max(1.0) as u64;
    let mut resp = ApiError(
        StatusCode::TOO_MANY_REQUESTS,
        "too many requests; slow down".into(),
    )
    .into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&secs.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
}

/// Limiter of the public routes (see [`public_limit`]).
pub(crate) fn public_limiter() -> crate::ratelimit::RateLimiter {
    crate::ratelimit::RateLimiter::new(PUBLIC_RATE, PUBLIC_BURST)
}

/// Limit public routes that cost work (login, SSO) to [`PUBLIC_RATE`]/s per client address
/// (the one a trusted proxy forwards, see [`crate::client`]).
/// Always on: not tied to `--api-rate-limit` (that one is for authenticated callers).
pub(crate) async fn public_limit(
    State(s): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let client = info_of(&req).ip;
    if let Err(wait) = s
        .public_limiter
        .check(&format!("ip:{client}"), Instant::now())
    {
        return rate_limited(wait);
    }
    next.run(req).await
}

pub(crate) fn public_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    let limited = Router::new()
        .route("/auth/login", post(login))
        .route("/auth/oidc/login", get(crate::oidc::login))
        .route("/auth/oidc/callback", get(crate::oidc::callback))
        .route_layer(axum::middleware::from_fn_with_state(state, public_limit));
    Router::new()
        .route("/auth/logout", post(logout))
        .route("/openapi.json", get(crate::openapi::serve))
        .route("/auth/config", get(crate::oidc::config))
        .merge(limited)
}

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/me", get(me))
        .route("/auth/totp/setup", post(two_factor::setup))
        .route("/auth/totp/enable", post(two_factor::enable))
        .route("/auth/totp/disable", post(two_factor::disable))
        .route(
            "/auth/totp/recovery-codes",
            post(two_factor::recovery_codes),
        )
        .route("/users", get(list_users).post(create_user))
        .route("/users/{id}", patch(update_user).delete(delete_user))
        .route("/users/{id}/totp", axum::routing::delete(two_factor::reset))
        .route("/api-keys", get(list_keys).post(create_key))
        .route("/api-keys/{id}", axum::routing::delete(revoke_key))
}

fn unprocessable(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg.into())
}

/// Body of `POST /auth/login`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct Login {
    username: String,
    password: String,
    /// Six-digit code of the authenticator app, or a recovery code.
    /// Needed when the account has two-factor authentication on;
    /// server asks with a 401 whose body has `"totp_required": true`.
    #[serde(default)]
    totp: Option<String>,
}

/// Max password length in bytes: Argon2 hash reads all of it.
const MAX_PASSWORD_BYTES: usize = 1024;

#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "auth",
    operation_id = "login",
    summary = "Log in",
    description = "A recovery code works in place of the app's code, once; using one is audited.",
    request_body = Login,
    responses(
        (status = 200, description = "Logged in; the session cookie is set", body = crate::schemas::LoginResult, headers(("set-cookie" = String, description = "`dhonomos_session=...; Path=/; HttpOnly; SameSite=Strict` (`__Host-dhonomos_session=...; Secure` with `--secure-cookies`)"))),
        (status = 401, description = "Wrong username, password or authentication code. When the username and password are right but the account has two-factor authentication on and no `totp` was sent, the body is `{\"error\": \"totp required\", \"totp_required\": true}` and no session is made: send the request again with the code. A wrong code counts as a failed login.", body = crate::schemas::LoginFailure),
        (status = 422, description = "Invalid body"),
        (status = 429, description = "Too many failed logins for this username from this client address (5 in 15 minutes) or from all addresses together (50), or too many requests from this address; try again later"),
        (status = 503, description = "Too many logins are being checked at the moment; try again"),
    ),
)]
async fn login(
    State(s): State<Arc<AppState>>,
    Extension(info): Extension<ClientInfo>,
    body: Result<Json<Login>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    if req.password.len() > MAX_PASSWORD_BYTES {
        return Err(unprocessable("the password is too long"));
    }
    let user = s
        .store
        .user_by_name(s.config.tenant_id, &req.username)
        .await?;
    // Count before the slow check -> parallel requests cannot all pass the limit
    // (see `attempts`). Same answer for a name that is an account and one that is not.
    let slot = s
        .login_attempts
        .reserve(&req.username, &info.ip, user.is_some(), Instant::now())
        .map_err(|_| {
            tracing::debug!(username = %Attempts::name_key(&req.username), client = %info.ip, "login refused: too many attempts");
            ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "too many failed logins; try again later".into(),
            )
        })?;
    // Hashing on blocking threads, a few at a time (see `hashing`).
    // Check not made (busy, storage) -> attempt given back.
    let checked = async {
        let ok = match &user {
            Some(u) => {
                !u.disabled
                    && verify_async(&s, u.password_hash.clone(), req.password.clone()).await?
            }
            None => {
                // Same work for unknown names.
                let _ = hash_async(&s, req.password.clone()).await?;
                false
            }
        };
        let Some(user) = user.filter(|_| ok) else {
            return Ok(Checked::Wrong);
        };
        if !user.totp_enabled {
            return Ok(Checked::Granted(Box::new(user), None));
        }
        // Second factor. Missing code != failure (password right -> client asks the person
        // for the code); wrong code = failure.
        let Some(code) = req.totp.as_deref().filter(|c| !c.trim().is_empty()) else {
            return Ok(Checked::NeedsCode);
        };
        Ok::<_, ApiError>(match two_factor::check_code(&s, &user, code, true).await? {
            Some(f) => Checked::Granted(Box::new(user), Some(f)),
            None => Checked::Wrong,
        })
    }
    .await;
    let (user, factor) = match checked {
        Err(e) => {
            slot.refund();
            return Err(e);
        }
        // Wrong name, password or code -> attempt stays counted.
        Ok(Checked::Wrong) => return Err(login_failed(&req, &info).await),
        Ok(Checked::NeedsCode) => {
            slot.refund();
            return Ok(totp_required());
        }
        Ok(Checked::Granted(user, factor)) => (user, factor),
    };
    slot.success();
    let mut detail = json!({ "client": info.ip });
    if let Some(f) = factor {
        detail["second_factor"] = json!(f.as_str());
    }
    let cookie = begin_session(&s, &user, detail, false, &info).await?;
    if factor == Some(two_factor::Factor::Recovery) {
        two_factor::note_recovery_login(&s, &user, &info).await;
    }
    let mut resp = Json(json!({ "username": user.username, "role": user.role })).into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(resp)
}

/// Result of a login check.
enum Checked {
    /// Name, password or code wrong.
    Wrong,
    /// Password right; account needs a code, none sent.
    NeedsCode,
    /// Let in, with the second factor that proved it (if the account has one).
    Granted(Box<dhonomos_store::User>, Option<two_factor::Factor>),
}

/// Answer to a failed login: wait + log.
/// Message does not say which of name, password, code was wrong.
async fn login_failed(req: &Login, info: &ClientInfo) -> ApiError {
    tokio::time::sleep(Duration::from_millis(300)).await;
    tracing::warn!(username = %Attempts::name_key(&req.username), client = %info.ip, "failed login");
    let with_code = req.totp.as_deref().is_some_and(|c| !c.trim().is_empty());
    ApiError(
        StatusCode::UNAUTHORIZED,
        if with_code {
            "wrong username, password or authentication code"
        } else {
            "wrong username or password"
        }
        .into(),
    )
}

/// 401 asking for the code: username + password right, no session made.
fn totp_required() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "totp required", "totp_required": true })),
    )
        .into_response()
}

/// Create a session for `user` (audit `auth.login` with `detail`) -> its `Set-Cookie` value.
/// `sso` = login via the identity provider.
pub(crate) async fn begin_session(
    s: &AppState,
    user: &dhonomos_store::User,
    detail: Value,
    sso: bool,
    info: &ClientInfo,
) -> Result<HeaderValue, ApiError> {
    let token = random_token()?;
    let hours = match *s.config.session_hours.get() {
        h if h > 0 => h,
        _ => 12,
    };
    s.store
        .create_session(
            user.id,
            &sha256(&token),
            OffsetDateTime::now_utc() + time::Duration::hours(hours),
            sso,
        )
        .await?;
    ACTOR
        .scope(
            user.username.clone(),
            audit(s, "auth.login", "user", user.id, detail),
        )
        .await;
    let cookie = format!(
        "{}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        session_cookie_name(s.config.secure_cookies),
        hours * 3600,
        if cookies_secure(s, info) {
            "; Secure"
        } else {
            ""
        }
    );
    HeaderValue::from_str(&cookie).map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not build the session cookie".into(),
        )
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "auth",
    operation_id = "logout",
    summary = "Log out",
    responses(
        (status = 204, description = "The session is ended and the cookie cleared"),
    ),
)]
async fn logout(State(s): State<Arc<AppState>>, req: Request) -> Result<Response, ApiError> {
    let token = credentials(&req, session_cookie_name(s.config.secure_cookies)).session;
    if let Some(token) = token {
        s.store.delete_session(&sha256(&token)).await?;
    }
    let secure = cookies_secure(&s, &info_of(&req));
    let mut resp = StatusCode::NO_CONTENT.into_response();
    // Clear the cookie this server sets + (with `--secure-cookies`) the old one from before
    // the `__Host-` prefix.
    let names: &[&str] = if s.config.secure_cookies {
        &[SESSION_COOKIE_HOST, SESSION_COOKIE]
    } else {
        &[SESSION_COOKIE]
    };
    for name in names {
        // `__Host-` cookie: always set and cleared with `Secure`.
        let secure = secure || *name == SESSION_COOKIE_HOST;
        if let Ok(v) = HeaderValue::from_str(&format!(
            "{name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
            if secure { "; Secure" } else { "" }
        )) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    Ok(resp)
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/me",
    tag = "auth",
    operation_id = "whoami",
    summary = "The current caller",
    responses(
        (status = 200, description = "The caller", body = crate::schemas::Caller),
    ),
)]
async fn me(req: Request) -> Json<Value> {
    let p = req.extensions().get::<Principal>().cloned();
    Json(match p {
        Some(p) => json!({ "name": p.name, "role": p.role.as_str(), "via": p.kind,
                           "scope": p.scope.as_deref(), "totp_enabled": p.totp_enabled,
                           "totp_required": p.totp_required, "totp_available": p.totp_available }),
        None => json!({ "name": null }),
    })
}

pub(crate) fn user_json(u: &dhonomos_store::User) -> Value {
    json!({
        "id": u.id,
        "username": u.username,
        "role": u.role,
        "disabled": u.disabled,
        "created_at": ts(u.created_at),
        "last_login_at": u.last_login_at.map(ts),
        "scope": u.scope,
        "totp_enabled": u.totp_enabled,
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/users",
    tag = "users",
    operation_id = "list_users",
    summary = "List operator accounts",
    responses(
        (status = 200, description = "The accounts", body = crate::schemas::UserList),
    ),
)]
async fn list_users(State(s): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let items: Vec<Value> = s
        .store
        .list_users(s.config.tenant_id)
        .await?
        .iter()
        .map(user_json)
        .collect();
    Ok(Json(json!({ "items": items })))
}

/// Body of `POST /users`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct NewUser {
    /// 1-64 characters, no spaces.
    username: String,
    /// Min 10 characters.
    password: String,
    /// `admin`, `operator` or `viewer`.
    role: String,
    /// Devices the user may see and act on (viewer and operator only); omitted or `null`: all.
    #[serde(default)]
    #[schema(value_type = Option<crate::schemas::DeviceScope>)]
    scope: Option<DeviceScope>,
}

/// Explicit `null` (`Some(None)`) != absent field (`None`).
pub(crate) fn present<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

/// Check a scope for an account or key with `role`.
fn check_scope(scope: &DeviceScope, role: &str) -> Result<(), ApiError> {
    if role == "admin" {
        return Err(unprocessable(
            "admins cannot have a device scope (they manage accounts); use viewer or operator",
        ));
    }
    if scope.is_empty() {
        return Err(unprocessable(
            "an empty scope would allow every device; use null for that",
        ));
    }
    if scope
        .tags
        .iter()
        .any(|t| t.trim().is_empty() || t.len() > 64)
    {
        return Err(unprocessable("scope tags are 1-64 characters"));
    }
    if let Some(k) = scope
        .attributes
        .keys()
        .find(|k| !crate::valid_attribute_key(k))
    {
        return Err(unprocessable(format!(
            "scope attribute key {k:?}: letters, digits, _ - . and at most 64 characters"
        )));
    }
    if let Some(p) = &scope.protocol
        && p != "cwmp"
        && p != "usp"
    {
        return Err(unprocessable("scope protocol must be cwmp or usp"));
    }
    Ok(())
}

fn check_password(p: &str) -> Result<(), ApiError> {
    if p.chars().count() < MIN_PASSWORD {
        return Err(unprocessable(format!(
            "passwords need at least {MIN_PASSWORD} characters"
        )));
    }
    if p.len() > MAX_PASSWORD_BYTES {
        return Err(unprocessable(format!(
            "passwords can have at most {MAX_PASSWORD_BYTES} bytes"
        )));
    }
    Ok(())
}

#[utoipa::path(
    post,
    path = "/api/v1/users",
    tag = "users",
    operation_id = "create_user",
    summary = "Create an operator account",
    request_body = NewUser,
    responses(
        (status = 201, description = "The user", body = crate::schemas::User),
        (status = 409, description = "The username exists"),
        (status = 422, description = "Invalid body, username, role, or a password under 10 characters"),
        (status = 500, description = "The password could not be hashed"),
    ),
)]
async fn create_user(
    State(s): State<Arc<AppState>>,
    body: Result<Json<NewUser>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    let name = req.username.trim();
    if name.is_empty() || name.len() > 64 || name.chars().any(char::is_whitespace) {
        return Err(unprocessable(
            "usernames are 1-64 characters without spaces",
        ));
    }
    Role::parse(&req.role)
        .ok_or_else(|| unprocessable("role must be admin, operator or viewer"))?;
    if let Some(scope) = &req.scope {
        check_scope(scope, &req.role)?;
    }
    check_password(&req.password)?;
    if s.store
        .user_by_name(s.config.tenant_id, name)
        .await?
        .is_some()
    {
        return Err(ApiError(
            StatusCode::CONFLICT,
            format!("user {name:?} exists"),
        ));
    }
    let hash = hash_async(&s, req.password.clone()).await?;
    let id = s
        .store
        .create_user(s.config.tenant_id, name, &hash, &req.role)
        .await?;
    if req.scope.is_some() {
        s.store.set_user_scope(id, req.scope.as_ref()).await?;
    }
    s.users_exist.store(true, Ordering::Relaxed);
    audit(
        &s,
        "user.create",
        "user",
        id,
        json!({ "username": name, "role": req.role, "scope": req.scope }),
    )
    .await;
    let u = s
        .store
        .get_user(id)
        .await?
        .ok_or_else(|| not_found("user"))?;
    Ok((StatusCode::CREATED, Json(user_json(&u))))
}

/// Body of `PATCH /users/{id}`: fields to change.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct UserChange {
    /// `admin`, `operator` or `viewer`.
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    disabled: Option<bool>,
    /// New password, min 10 characters.
    #[serde(default)]
    password: Option<String>,
    /// New device scope (viewer and operator only); `null` removes it.
    #[serde(default, deserialize_with = "present")]
    #[schema(value_type = Option<crate::schemas::DeviceScope>)]
    scope: Option<Option<DeviceScope>>,
}

/// 409 if `leaving` is the last enabled admin.
async fn last_admin_guard(s: &AppState, leaving: Uuid) -> Result<(), ApiError> {
    let others = s
        .store
        .list_users(s.config.tenant_id)
        .await?
        .iter()
        .filter(|u| u.id != leaving && u.role == "admin" && !u.disabled)
        .count();
    if others == 0 {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "this is the last enabled admin; make another admin first".into(),
        ));
    }
    Ok(())
}

async fn user_of(s: &AppState, id: Uuid) -> Result<dhonomos_store::User, ApiError> {
    s.store
        .get_user(id)
        .await?
        .filter(|u| u.tenant_id == s.config.tenant_id)
        .ok_or_else(|| not_found("user"))
}

#[utoipa::path(
    patch,
    path = "/api/v1/users/{id}",
    tag = "users",
    operation_id = "update_user",
    summary = "Change a user's role, state or password",
    description = "Disabling an account ends all its sessions and stops the API keys it made. A new password ends all the account's sessions except the one the change is made from when the account changes its own password.",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    request_body = UserChange,
    responses(
        (status = 200, description = "The user", body = crate::schemas::User),
        (status = 404, description = "Unknown user"),
        (status = 422, description = "Invalid body, role, or a password under 10 characters"),
        (status = 500, description = "The password could not be hashed"),
    ),
)]
async fn update_user(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Extension(caller): Extension<Principal>,
    headers: HeaderMap,
    body: Result<Json<UserChange>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    let current = user_of(&s, id).await?;
    if let Some(r) = &req.role {
        Role::parse(r).ok_or_else(|| unprocessable("role must be admin, operator or viewer"))?;
    }
    // Keep min 1 enabled admin, else nobody can manage accounts.
    let stays_admin = req.role.as_deref().unwrap_or(&current.role) == "admin"
        && !req.disabled.unwrap_or(current.disabled);
    if current.role == "admin" && !current.disabled && !stays_admin {
        last_admin_guard(&s, id).await?;
    }
    // Final role + scope must fit together.
    let role = req.role.as_deref().unwrap_or(&current.role);
    let scope = match &req.scope {
        Some(new) => new.as_ref(),
        None => current.scope.as_ref(),
    };
    if let Some(scope) = scope {
        check_scope(scope, role)?;
    }
    let hash = match &req.password {
        Some(p) => {
            check_password(p)?;
            Some(hash_async(&s, p.clone()).await?)
        }
        None => None,
    };
    // New password -> account sessions end, except the current one when the account changes
    // its own password (whoever knew the old password -> logged out).
    let own_session = (caller.kind == "session" && caller.user_id == Some(id))
        .then(|| cookie_value(&headers, session_cookie_name(s.config.secure_cookies)).map(sha256))
        .flatten();
    let mut revoked = s
        .store
        .update_user(
            id,
            req.role.as_deref(),
            req.disabled,
            hash.as_deref(),
            own_session.as_deref(),
        )
        .await?
        .revoked_clients;
    if let Some(scope) = &req.scope {
        revoked.extend(
            s.store
                .set_user_scope(id, scope.as_ref())
                .await?
                .revoked_clients,
        );
    }
    let mut detail =
        json!({ "role": req.role, "disabled": req.disabled, "password_changed": hash.is_some() });
    if let Some(scope) = &req.scope {
        detail["scope"] = json!(scope);
    }
    audit(&s, "user.update", "user", id, detail).await;
    crate::wireguard::audit_revoked_clients(&s, &revoked).await;
    Ok(Json(user_json(&user_of(&s, id).await?)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/users/{id}",
    tag = "users",
    operation_id = "delete_user",
    summary = "Delete a user",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Unknown user"),
    ),
)]
async fn delete_user(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let u = user_of(&s, id).await?;
    if u.role == "admin" && !u.disabled {
        last_admin_guard(&s, id).await?;
    }
    let revoked = s.store.delete_user(id).await?.revoked_clients;
    audit(
        &s,
        "user.delete",
        "user",
        id,
        json!({ "username": u.username }),
    )
    .await;
    crate::wireguard::audit_revoked_clients(&s, &revoked).await;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) fn key_json(k: &dhonomos_store::ApiKey) -> Value {
    json!({
        "id": k.id,
        "name": k.name,
        "prefix": k.prefix,
        "role": k.role,
        "created_by": k.created_by,
        "created_at": ts(k.created_at),
        "last_used_at": k.last_used_at.map(ts),
        "revoked_at": k.revoked_at.map(ts),
        "scope": k.scope,
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/api-keys",
    tag = "users",
    operation_id = "list_api_keys",
    summary = "List API keys",
    responses(
        (status = 200, description = "The keys (without secrets)", body = crate::schemas::ApiKeyList),
    ),
)]
async fn list_keys(State(s): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let items: Vec<Value> = s
        .store
        .list_api_keys(s.config.tenant_id)
        .await?
        .iter()
        .map(key_json)
        .collect();
    Ok(Json(json!({ "items": items })))
}

/// Body of `POST /api-keys`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct NewKey {
    name: String,
    /// `admin`, `operator` or `viewer`.
    role: String,
    /// Devices the key may see and act on (viewer and operator only); omitted or `null`: all.
    #[serde(default)]
    #[schema(value_type = Option<crate::schemas::DeviceScope>)]
    scope: Option<DeviceScope>,
}

#[utoipa::path(
    post,
    path = "/api/v1/api-keys",
    tag = "users",
    operation_id = "create_api_key",
    summary = "Create an API key",
    description = "A key made by an operator account works only while that account exists and is enabled: disabling the account stops its keys (enabling it again restores them), deleting the account deletes them. Keys made with the static `--api-token` are not tied to an account.",
    request_body = NewKey,
    responses(
        (status = 201, description = "The key, with its secret shown once", body = crate::schemas::NewApiKey),
        (status = 422, description = "Invalid body, empty name or unknown role"),
    ),
)]
async fn create_key(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
    body: Result<Json<NewKey>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    if req.name.trim().is_empty() {
        return Err(unprocessable("name is required"));
    }
    Role::parse(&req.role)
        .ok_or_else(|| unprocessable("role must be admin, operator or viewer"))?;
    if let Some(scope) = &req.scope {
        check_scope(scope, &req.role)?;
    }
    let key = format!("pk_{}", random_token()?);
    let prefix: String = key.chars().take(10).collect();
    let creator = ACTOR.try_with(Clone::clone).ok();
    let id = s
        .store
        .create_api_key(
            s.config.tenant_id,
            req.name.trim(),
            &sha256(&key),
            &prefix,
            &req.role,
            req.scope.as_ref(),
            creator.as_deref(),
            // Key works while its creator's account does.
            caller.user_id,
        )
        .await?;
    audit(
        &s,
        "api_key.create",
        "api_key",
        id,
        json!({ "name": req.name, "role": req.role, "prefix": prefix, "scope": req.scope }),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({ "id": id, "name": req.name.trim(), "role": req.role, "prefix": prefix,
                    "scope": req.scope, "key": key }),
        ),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/api-keys/{id}",
    tag = "users",
    operation_id = "revoke_api_key",
    summary = "Revoke an API key",
    params(
        ("id" = Uuid, Path, description = "API key ID"),
    ),
    responses(
        (status = 204, description = "Revoked"),
        (status = 404, description = "Unknown API key"),
    ),
)]
async fn revoke_key(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    if !s.store.revoke_api_key(s.config.tenant_id, id).await? {
        return Err(not_found("API key"));
    }
    audit(&s, "api_key.revoke", "api_key", id, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_per_route() {
        let r = |m: Method, p: &str| required_role(&m, p);
        assert_eq!(r(Method::GET, "/api/v1/devices"), Role::Viewer);
        assert_eq!(r(Method::GET, "/api/v1/devices/facets"), Role::Viewer);
        assert_eq!(r(Method::GET, "/api/v1/files"), Role::Viewer);
        assert_eq!(r(Method::GET, "/api/v1/files/x/content"), Role::Operator);
        assert_eq!(
            r(Method::GET, "/api/v1/devices/x/bulkdata-url"),
            Role::Operator
        );
        assert_eq!(r(Method::POST, "/api/v1/devices/x/tasks"), Role::Operator);
        assert_eq!(
            r(Method::POST, "/api/v1/devices/bulk"),
            Role::Operator,
            "pre-registering many devices is an operator's, like pre-registering one"
        );
        assert_eq!(
            r(Method::POST, "/api/v1/devices/x/data-model/refresh"),
            Role::Operator
        );
        assert_eq!(r(Method::DELETE, "/api/v1/devices/x"), Role::Admin);
        assert_eq!(
            r(Method::POST, "/api/v1/devices/delete"),
            Role::Admin,
            "deleting many devices is an admin's, like deleting one"
        );
        assert_eq!(r(Method::DELETE, "/api/v1/tasks/x"), Role::Operator);
        assert_eq!(r(Method::GET, "/api/v1/users"), Role::Admin);
        assert_eq!(r(Method::GET, "/api/v1/settings/server"), Role::Admin);
        assert_eq!(
            r(Method::PUT, "/api/v1/settings/server/session_hours"),
            Role::Admin
        );
        assert_eq!(
            r(Method::DELETE, "/api/v1/settings/server/session_hours"),
            Role::Admin
        );
        assert_eq!(
            r(Method::GET, "/api/v1/settings/server/session_hours/history"),
            Role::Admin
        );
        assert_eq!(r(Method::GET, "/api/v1/settings/alarm-rules"), Role::Admin);
        assert_eq!(r(Method::PUT, "/api/v1/settings/alarm-rules"), Role::Admin);
        assert_eq!(
            r(Method::GET, "/api/v1/settings/alarm-rules/history"),
            Role::Admin
        );
        assert_eq!(r(Method::GET, "/api/v1/alarm-rules"), Role::Viewer);
        assert_eq!(
            r(Method::PUT, "/api/v1/devices/x/credentials/acs_auth"),
            Role::Admin
        );
        assert_eq!(
            r(Method::POST, "/api/v1/devices/x/certificate"),
            Role::Admin
        );
        assert_eq!(
            r(Method::POST, "/api/v1/certificates/bundle"),
            Role::Admin,
            "keys for many devices at once"
        );
        assert_eq!(
            r(Method::POST, "/api/v1/certificates/revoke"),
            Role::Admin,
            "revoking by fingerprint"
        );
        assert_eq!(r(Method::POST, "/devices/x/mqtt-credentials"), Role::Admin);
        assert_eq!(
            r(Method::POST, "/api/v1/devices/x/certificates/y/revoke"),
            Role::Admin
        );
        assert_eq!(
            r(Method::GET, "/api/v1/devices/x/certificates"),
            Role::Viewer
        );
        assert_eq!(r(Method::GET, "/metrics"), Role::Viewer);
        // Every logged-in role manages own two-factor auth; reset of another user's -> admin.
        for endpoint in ["setup", "enable", "disable", "recovery-codes"] {
            assert_eq!(
                r(Method::POST, &format!("/api/v1/auth/totp/{endpoint}")),
                Role::Viewer,
                "{endpoint}"
            );
        }
        assert_eq!(r(Method::DELETE, "/api/v1/users/x/totp"), Role::Admin);
    }

    #[test]
    fn wireguard_roles_per_route() {
        let r = |m: Method, p: &str| required_role(&m, p);
        // Read -> operator+: tunnel addresses, keys, LAN prefixes.
        for path in [
            "/api/v1/wireguard/summary",
            "/api/v1/wireguard/hubs",
            "/api/v1/wireguard/hubs/x",
            "/api/v1/wireguard/networks",
            "/api/v1/wireguard/networks/x",
            "/api/v1/wireguard/networks/x/members",
            "/api/v1/wireguard/members/x",
            "/api/v1/wireguard/members/x/config",
            "/api/v1/devices/x/wireguard",
        ] {
            assert_eq!(r(Method::GET, path), Role::Operator, "GET {path}");
        }
        // Hubs, networks, member delete -> admin.
        for (m, path) in [
            (Method::POST, "/api/v1/wireguard/hubs"),
            (Method::PATCH, "/api/v1/wireguard/hubs/x"),
            (Method::DELETE, "/api/v1/wireguard/hubs/x"),
            (Method::POST, "/api/v1/wireguard/networks"),
            (Method::PATCH, "/api/v1/wireguard/networks/x"),
            (Method::DELETE, "/api/v1/wireguard/networks/x"),
            (Method::DELETE, "/api/v1/wireguard/members/x"),
            (Method::POST, "/api/v1/wireguard/hubs/x/token"),
            (Method::DELETE, "/api/v1/wireguard/hubs/x/token"),
            (Method::POST, "/api/v1/wireguard/networks/x/rotate-keys"),
        ] {
            assert_eq!(r(m.clone(), path), Role::Admin, "{m} {path}");
        }
        // Members -> operator (handlers check device scope + ownership).
        for (m, path) in [
            (Method::POST, "/api/v1/wireguard/networks/x/members"),
            (Method::PATCH, "/api/v1/wireguard/members/x"),
            (Method::POST, "/api/v1/wireguard/members/x/revoke"),
            (Method::POST, "/api/v1/wireguard/members/x/rekey"),
            (Method::POST, "/api/v1/wireguard/members/x/rotate-key"),
        ] {
            assert_eq!(r(m.clone(), path), Role::Operator, "{m} {path}");
        }
    }

    #[test]
    fn enrollment_only_sessions_reach_just_the_setup_routes() {
        let allowed = |m: Method, p: &str| enrollment_route(&m, p);
        assert!(allowed(Method::GET, "/api/v1/auth/me"));
        assert!(allowed(Method::GET, "/auth/me"));
        assert!(allowed(Method::POST, "/api/v1/auth/totp/setup"));
        assert!(allowed(Method::POST, "/api/v1/auth/totp/enable"));
        assert!(allowed(Method::POST, "/api/v1/auth/totp/enable/"));
        for (m, p) in [
            (Method::POST, "/api/v1/auth/totp/disable"),
            (Method::POST, "/api/v1/auth/totp/recovery-codes"),
            (Method::GET, "/api/v1/auth/totp/setup"),
            (Method::POST, "/api/v1/auth/me"),
            (Method::GET, "/api/v1/devices"),
            (Method::GET, "/api/v1/users"),
            (Method::POST, "/api/v1/api-keys"),
            (Method::PATCH, "/api/v1/users/x"),
            (Method::DELETE, "/api/v1/users/x/totp"),
            (Method::GET, "/api/v1/stream"),
            (Method::GET, "/metrics"),
        ] {
            assert!(!allowed(m.clone(), p), "{m} {p}");
        }
    }

    #[test]
    fn fleet_wide_routes() {
        let f = |m: Method, p: &str| fleet_wide(&m, p);
        assert!(f(Method::POST, "/api/v1/devices"));
        assert!(f(Method::POST, "/api/v1/devices/bulk"));
        assert!(!f(Method::GET, "/api/v1/devices/bulk"));
        assert!(f(Method::POST, "/api/v1/devices/delete"));
        assert!(!f(Method::GET, "/api/v1/devices/delete"));
        assert!(f(Method::POST, "/api/v1/certificates/bundle"));
        assert!(f(Method::POST, "/api/v1/certificates/revoke"));
        assert!(!f(Method::GET, "/api/v1/certificates/expiring"));
        assert!(!f(Method::GET, "/api/v1/devices"));
        assert!(f(Method::PUT, "/api/v1/presets/wifi"));
        assert!(f(Method::POST, "/api/v1/presets/import"));
        assert!(!f(Method::POST, "/api/v1/presets/dry-run"));
        assert!(!f(Method::POST, "/api/v1/presets/validate"));
        assert!(!f(Method::GET, "/api/v1/presets/export.yaml"));
        assert!(f(Method::DELETE, "/api/v1/files/x"));
        assert!(f(Method::GET, "/metrics"));
    }

    fn request(headers: &[(&str, &str)]) -> Request {
        let mut b = Request::builder().method(Method::POST).uri("/api/v1/x");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("{e}"))
    }

    fn resolved(peer: &str, trusted: &[&str], headers: &[(&str, &str)]) -> (Request, ClientInfo) {
        let req = request(headers);
        let trusted: Vec<dhonomos_core::Cidr> = trusted
            .iter()
            .map(|c| c.parse().unwrap_or_else(|e| panic!("{c}: {e}")))
            .collect();
        let info = crate::client::resolve(peer.parse().ok(), req.headers(), &trusted);
        (req, info)
    }

    #[test]
    fn the_origin_check_without_a_public_address() {
        let ok = |peer: &str, trusted: &[&str], headers: &[(&str, &str)]| {
            let (req, info) = resolved(peer, trusted, headers);
            same_origin(&req, &info, None)
        };
        // No Origin header -> not a cross-site browser request.
        assert!(ok("127.0.0.1", &[], &[("host", "rms.example.org")]));
        // Host it was sent to.
        assert!(ok(
            "127.0.0.1",
            &[],
            &[
                ("host", "rms.example.org"),
                ("origin", "https://rms.example.org")
            ]
        ));
        assert!(!ok(
            "127.0.0.1",
            &[],
            &[
                ("host", "rms.example.org"),
                ("origin", "https://evil.example")
            ]
        ));
        assert!(!ok(
            "127.0.0.1",
            &[],
            &[("host", "rms.example.org"), ("origin", "null")]
        ));
        // X-Forwarded-Host counts only from a trusted proxy.
        let via_proxy = [
            ("host", "127.0.0.1:8080"),
            ("x-forwarded-for", "203.0.113.7"),
            ("x-forwarded-host", "rms.example.org"),
            ("origin", "https://rms.example.org"),
        ];
        assert!(ok("127.0.0.1", &["127.0.0.1/32"], &via_proxy));
        assert!(
            !ok("127.0.0.1", &[], &via_proxy),
            "nobody vouched for the forwarded host"
        );
        assert!(
            !ok("198.51.100.9", &["127.0.0.1/32"], &via_proxy),
            "an untrusted peer's forwarded host is ignored"
        );
        // Trusted proxy reports the scheme -> Origin must use it.
        let https = [
            ("host", "rms.example.org"),
            ("x-forwarded-proto", "https"),
            ("origin", "http://rms.example.org"),
        ];
        assert!(!ok("127.0.0.1", &["127.0.0.1/32"], &https));
        assert!(ok(
            "127.0.0.1",
            &["127.0.0.1/32"],
            &[
                ("host", "rms.example.org"),
                ("x-forwarded-proto", "https"),
                ("origin", "https://rms.example.org")
            ]
        ));
    }

    #[test]
    fn the_origin_check_with_a_public_address_is_exact() {
        let public: crate::client::PublicOrigin = "https://rms.example.org"
            .parse()
            .unwrap_or_else(|e| panic!("{e}"));
        let ok = |headers: &[(&str, &str)]| {
            let (req, info) = resolved("127.0.0.1", &["127.0.0.1/32"], headers);
            same_origin(&req, &info, Some(&public))
        };
        assert!(ok(&[
            ("host", "127.0.0.1:8080"),
            ("origin", "https://rms.example.org")
        ]));
        assert!(ok(&[]), "no Origin header");
        // Neither Host nor X-Forwarded-Host makes another Origin pass.
        assert!(!ok(&[
            ("host", "evil.example"),
            ("x-forwarded-host", "evil.example"),
            ("origin", "https://evil.example")
        ]));
        assert!(!ok(&[("origin", "http://rms.example.org")]));
        assert!(!ok(&[("origin", "https://rms.example.org:8443")]));
        assert!(!ok(&[("origin", "https://rms.example.org.evil.example")]));
        assert!(!ok(&[("origin", "null")]));
    }

    #[test]
    fn the_session_cookie_has_the_host_prefix_with_secure_cookies() {
        assert_eq!(session_cookie_name(false), "dhonomos_session");
        assert_eq!(session_cookie_name(true), "__Host-dhonomos_session");
        let req = request(&[(
            "cookie",
            "dhonomos_session=old; __Host-dhonomos_session=new",
        )]);
        assert_eq!(
            credentials(&req, session_cookie_name(true))
                .session
                .as_deref(),
            Some("new")
        );
        assert_eq!(
            credentials(&req, session_cookie_name(false))
                .session
                .as_deref(),
            Some("old")
        );
        // With prefix -> old name is no session (sibling domain could have set it).
        let old_only = request(&[("cookie", "dhonomos_session=old")]);
        assert_eq!(
            credentials(&old_only, session_cookie_name(true)).session,
            None
        );
    }

    #[tokio::test]
    async fn hashing_runs_a_few_at_a_time_and_refuses_to_queue_for_long() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let slots = Arc::new(tokio::sync::Semaphore::new(2));
        let (running, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let job = |running: Arc<AtomicUsize>, peak: Arc<AtomicUsize>| {
            move || {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(150));
                running.fetch_sub(1, Ordering::SeqCst);
            }
        };
        // 6 at once, 2 slots, patient queue -> all run, max 2 together.
        let all = (0..6).map(|_| {
            blocking_limited(
                &slots,
                Duration::from_secs(10),
                job(running.clone(), peak.clone()),
            )
        });
        for r in futures_util::future::join_all(all).await {
            assert!(r.is_ok());
        }
        assert_eq!(peak.load(Ordering::SeqCst), 2);

        // Impatient one behind 2 long jobs -> 503.
        let long = |slots: Arc<tokio::sync::Semaphore>| async move {
            blocking_limited(&slots, Duration::from_secs(10), || {
                std::thread::sleep(Duration::from_millis(400));
            })
            .await
        };
        let (a, b) = (
            tokio::spawn(long(slots.clone())),
            tokio::spawn(long(slots.clone())),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        let refused = blocking_limited(&slots, Duration::from_millis(50), || ())
            .await
            .expect_err("no free slot");
        assert_eq!(refused.0, StatusCode::SERVICE_UNAVAILABLE);
        let _ = (a.await, b.await);
        // Free again after.
        assert!(
            blocking_limited(&slots, Duration::from_millis(50), || 7)
                .await
                .is_ok_and(|v| v == 7)
        );
    }

    #[test]
    fn passwords() {
        let h = hash_password("correct horse").unwrap_or_default();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password(&h, "correct horse"));
        assert!(!verify_password(&h, "wrong horse"));
        assert!(!verify_password("not a hash", "x"));
    }
}
