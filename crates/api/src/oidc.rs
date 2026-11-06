//! OIDC SSO (NB-04): authorization code flow + PKCE, state, nonce.
//! ID token verified with the provider JWKS (RS256/ES256). Role from a claim (e.g. `groups`).
//! User = `sso:<name>` -> never takes over a local account.
//! Same session cookie as a password login.
//!
//! Account key = provider + subject (`iss` + `sub`): both never change.
//! Not the name claim (`preferred_username`, e-mail): can change -> only labels a new account.
//! Older account without identity -> identity attached at its next login.
//! Account with another identity -> login refused.
//! E-mail names a user only if the provider says it is verified.
//!
//! Login `state` bound to its starting browser: start sets a short-lived cookie with its hash,
//! callback needs it -> callback URL planted in another browser (login CSRF) refused.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Extension;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::auth::cookies_secure;
use crate::client::ClientInfo;
use crate::jwt::{self, Jwks};
use crate::{ApiError, AppState};

/// Max time between redirect and callback.
const LOGIN_TTL: Duration = Duration::from_secs(600);
/// Max pending logins.
const MAX_PENDING: usize = 10_000;
/// Max pending logins per client address.
const MAX_PENDING_PER_CLIENT: usize = 20;
/// Cookie: login -> its starting browser.
const STATE_COOKIE: &str = "dhonomos_oidc";
/// Allowed clock skew for `exp`.
const SKEW_SECS: i64 = 60;

/// Provider settings.
#[derive(Debug, Clone, Default)]
pub struct OidcConfig {
    /// Issuer URL -> its `/.well-known/openid-configuration` is read.
    pub issuer: String,
    /// Client ID at the provider.
    pub client_id: String,
    /// Client secret (confidential client) -> sent with HTTP Basic.
    pub client_secret: Option<String>,
    /// Callback of this server, e.g. `https://dhonomos.example/api/v1/auth/oidc/callback`.
    pub redirect_url: String,
    /// Requested scopes (must include `openid`).
    pub scopes: String,
    /// User name claim (fallback: `email`, then `sub`).
    pub username_claim: String,
    /// Claim with groups or roles (string or string array).
    pub role_claim: String,
    /// Claim values -> role. `*` = every authenticated user.
    pub admin: Vec<String>,
    /// See `admin`.
    pub operator: Vec<String>,
    /// See `admin`.
    pub viewer: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Debug)]
struct Pending {
    nonce: String,
    verifier: String,
    return_to: String,
    created: Instant,
    /// Client address of the start.
    client: String,
}

/// ID token -> stable identity, label for a new account, role.
#[derive(Debug)]
struct Identity {
    /// Provider (`iss`).
    issuer: String,
    /// User at the provider (`sub`).
    subject: String,
    /// `sso:<name>`, for a new account.
    username: String,
    role: &'static str,
    return_to: String,
}

/// Cookie value: login `state` -> its browser.
fn state_hash(state: &str) -> String {
    B64URL.encode(Sha256::digest(state.as_bytes()))
}

fn state_cookie(value: &str, max_age: u64, secure: bool) -> Option<HeaderValue> {
    // Lax, not Strict: provider sends the browser back cross-site.
    HeaderValue::from_str(&format!(
        "{STATE_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    ))
    .ok()
}

/// Runtime state: provider metadata + keys (cached), pending logins.
#[derive(Debug)]
pub(crate) struct Oidc {
    config: OidcConfig,
    metadata: Mutex<Option<Metadata>>,
    jwks: Mutex<Option<(Jwks, Instant)>>,
    pending: Mutex<HashMap<String, Pending>>,
}

fn random(bytes: usize) -> Result<String, ApiError> {
    let mut raw = vec![0u8; bytes];
    getrandom::fill(&mut raw).map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "random number generator failure".into(),
        )
    })?;
    Ok(B64URL.encode(raw))
}

/// `application/x-www-form-urlencoded` value.
fn form(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Max `return_to`, bytes.
const MAX_RETURN_TO: usize = 2048;

/// `s` with `%XX` decoded (invalid UTF-8 -> U+FFFD).
/// `%` without 2 hex digits -> kept as is.
fn percent_decoded(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| char::from(c).to_digit(16);
        if b[i] == b'%'
            && let (Some(hi), Some(lo)) = (
                b.get(i + 1).and_then(|c| hex(*c)),
                b.get(i + 2).and_then(|c| hex(*c)),
            )
        {
            out.push(u8::try_from(hi * 16 + lo).unwrap_or(b'%'));
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Browser target after login: only a path on this site (`/...`), plain relative reference.
/// Refused (X-9): anything a browser could read as another site.
/// Second slash or backslash (`//evil`, `/\evil`).
/// Control chars + whitespace: browser drops tab/line break -> `/<TAB>/evil` = `//evil`.
/// No parse as a path without scheme + host.
/// `%XX` decoded -> checked again: control chars, backslash, 2nd leading slash
/// (`/%09/evil`, `/%2F/evil`), for any later decoder.
/// Else -> `/`.
fn safe_return(to: Option<&str>) -> String {
    let Some(p) = to else {
        return "/".into();
    };
    let decoded = percent_decoded(p);
    let ok = p.starts_with('/')
        && !p.starts_with("//")
        && p.len() <= MAX_RETURN_TO
        && !p
            .chars()
            .any(|c| c == '\\' || c.is_control() || c.is_whitespace())
        && decoded.starts_with('/')
        && !decoded.starts_with("//")
        && !decoded.chars().any(|c| c == '\\' || c.is_control())
        && p.parse::<axum::http::Uri>()
            .is_ok_and(|u| u.scheme().is_none() && u.authority().is_none());
    if ok { p.to_owned() } else { "/".into() }
}

async fn get_json(url: &str) -> Result<Value, String> {
    let (status, _, body) = dhonomos_core::webhook::exchange("GET", url, &[], Default::default())
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    if !(200..300).contains(&status) {
        return Err(format!("{url}: HTTP {status}"));
    }
    serde_json::from_slice(&body).map_err(|e| format!("{url}: {e}"))
}

/// Role granted by the claims, if any.
fn role_for(cfg: &OidcConfig, claims: &Value) -> Option<&'static str> {
    let values: Vec<&str> = match claims.get(&cfg.role_claim) {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    let grants = |list: &[String]| {
        list.iter()
            .any(|want| want == "*" || values.contains(&want.as_str()))
    };
    if grants(&cfg.admin) {
        Some("admin")
    } else if grants(&cfg.operator) {
        Some("operator")
    } else if grants(&cfg.viewer) {
        Some("viewer")
    } else {
        None
    }
}

/// Name of a new account: configured claim -> e-mail -> `sub`.
/// E-mail (configured or fallback) only if the provider verified it.
/// Else anyone who sets their address at the provider -> picks another account name.
fn username_of<'a>(cfg: &OidcConfig, claims: &'a Value) -> Option<&'a str> {
    let verified = match &claims["email_verified"] {
        Value::Bool(b) => *b,
        // Some providers: boolean as text.
        Value::String(s) => s == "true",
        _ => false,
    };
    [cfg.username_claim.as_str(), "email", "sub"]
        .into_iter()
        .find_map(|c| {
            let v = claims.get(c)?.as_str().filter(|v| !v.is_empty())?;
            (c != "email" || verified).then_some(v)
        })
}

impl Oidc {
    pub(crate) fn new(config: OidcConfig) -> Self {
        Self {
            config,
            metadata: Mutex::default(),
            jwks: Mutex::default(),
            pending: Mutex::default(),
        }
    }

    async fn metadata(&self) -> Result<Metadata, String> {
        if let Some(m) = self.metadata.lock().ok().and_then(|m| m.clone()) {
            return Ok(m);
        }
        let issuer = self.config.issuer.trim_end_matches('/');
        let doc = get_json(&format!("{issuer}/.well-known/openid-configuration")).await?;
        let m: Metadata =
            serde_json::from_value(doc).map_err(|e| format!("provider metadata: {e}"))?;
        if m.issuer.trim_end_matches('/') != issuer {
            return Err(format!(
                "the provider says its issuer is {:?}, not {issuer:?}",
                m.issuer
            ));
        }
        if let Ok(mut slot) = self.metadata.lock() {
            *slot = Some(m.clone());
        }
        Ok(m)
    }

    /// Key set, cached. `refresh` (unknown key) -> refetch if last fetch >= 1 min ago.
    async fn jwks(&self, meta: &Metadata, refresh: bool) -> Result<Jwks, String> {
        if let Some((keys, at)) = self.jwks.lock().ok().and_then(|j| j.clone())
            && (!refresh || at.elapsed() < Duration::from_secs(60))
        {
            return Ok(keys);
        }
        let keys: Jwks = serde_json::from_value(get_json(&meta.jwks_uri).await?)
            .map_err(|e| format!("provider keys: {e}"))?;
        if let Ok(mut slot) = self.jwks.lock() {
            *slot = Some((keys.clone(), Instant::now()));
        }
        Ok(keys)
    }

    /// Store a pending login. Refused: `client` has [`MAX_PENDING_PER_CLIENT`]
    /// or all clients have [`MAX_PENDING`] -> table cannot be filled up.
    /// Expired logins dropped first. No `login` -> check only.
    fn room_for(&self, client: &str, login: Option<(String, Pending)>) -> Result<(), ApiError> {
        let Ok(mut p) = self.pending.lock() else {
            return Ok(());
        };
        p.retain(|_, v| v.created.elapsed() < LOGIN_TTL);
        if p.values().filter(|v| v.client == client).count() >= MAX_PENDING_PER_CLIENT {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "too many logins started from this address; try again later".into(),
            ));
        }
        if p.len() >= MAX_PENDING {
            return Err(ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "too many logins in progress".into(),
            ));
        }
        if let Some((state, pending)) = login {
            p.insert(state, pending);
        }
        Ok(())
    }

    /// Redirect URL to the provider login page + its `state`.
    async fn begin(
        &self,
        return_to: Option<&str>,
        client: &str,
    ) -> Result<(String, String), ApiError> {
        // Check room before any provider fetch for the caller.
        self.room_for(client, None)?;
        let meta = self
            .metadata()
            .await
            .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, format!("single sign-on: {e}")))?;
        let (state, nonce, verifier) = (random(24)?, random(24)?, random(32)?);
        let challenge = B64URL.encode(Sha256::digest(verifier.as_bytes()));
        self.room_for(
            client,
            Some((
                state.clone(),
                Pending {
                    nonce: nonce.clone(),
                    verifier,
                    return_to: safe_return(return_to),
                    created: Instant::now(),
                    client: client.to_owned(),
                },
            )),
        )?;
        let sep = if meta.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        let url = format!(
            "{}{sep}response_type=code&client_id={}&redirect_uri={}&scope={}&state={state}&nonce={nonce}&code_challenge={challenge}&code_challenge_method=S256",
            meta.authorization_endpoint,
            form(&self.config.client_id),
            form(&self.config.redirect_url),
            form(&self.config.scopes),
        );
        Ok((url, state))
    }

    /// Exchange code + check ID token -> identity, role, next page.
    async fn finish(&self, code: &str, state: &str) -> Result<Identity, String> {
        let pending = self
            .pending
            .lock()
            .ok()
            .and_then(|mut p| p.remove(state))
            .filter(|p| p.created.elapsed() < LOGIN_TTL)
            .ok_or("the login expired or was already used; try again")?;
        let meta = self.metadata().await?;
        let body = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}&client_id={}",
            form(code),
            form(&self.config.redirect_url),
            form(&pending.verifier),
            form(&self.config.client_id)
        );
        let mut headers = vec![(
            "content-type".to_owned(),
            "application/x-www-form-urlencoded".to_owned(),
        )];
        if let Some(secret) = &self.config.client_secret {
            let basic = base64::engine::general_purpose::STANDARD.encode(format!(
                "{}:{}",
                form(&self.config.client_id),
                form(secret)
            ));
            headers.push(("authorization".to_owned(), format!("Basic {basic}")));
        }
        let (status, _, resp) = dhonomos_core::webhook::exchange(
            "POST",
            &meta.token_endpoint,
            &headers,
            body.into_bytes().into(),
        )
        .await
        .map_err(|e| format!("token endpoint: {e}"))?;
        let resp: Value =
            serde_json::from_slice(&resp).map_err(|_| format!("token endpoint: HTTP {status}"))?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "the provider refused the code: {}",
                resp["error_description"]
                    .as_str()
                    .or(resp["error"].as_str())
                    .unwrap_or("unknown error")
            ));
        }
        let token = resp["id_token"]
            .as_str()
            .ok_or("the provider returned no ID token")?;
        let claims = match jwt::verify(token, &self.jwks(&meta, false).await?) {
            Err(e) if e.contains("no matching") || e.contains("signature") => {
                // Keys may have rotated -> refetch.
                jwt::verify(token, &self.jwks(&meta, true).await?)?
            }
            other => other?,
        };
        self.check_claims(&meta, &claims, &pending.nonce)?;
        let role = role_for(&self.config, &claims)
            .ok_or("your account has no Dhonomos role (check the role claim and mapping)")?;
        let subject = claims["sub"]
            .as_str()
            .filter(|v| !v.is_empty())
            .ok_or("the ID token has no subject")?;
        let name = username_of(&self.config, &claims)
            .ok_or("the ID token names no user (an e-mail address counts only if the provider verified it)")?;
        Ok(Identity {
            issuer: meta.issuer.trim_end_matches('/').to_owned(),
            subject: subject.to_owned(),
            username: format!("sso:{name}"),
            role,
            return_to: pending.return_to,
        })
    }

    fn check_claims(&self, meta: &Metadata, c: &Value, nonce: &str) -> Result<(), String> {
        if c["iss"].as_str().map(|i| i.trim_end_matches('/'))
            != Some(meta.issuer.trim_end_matches('/'))
        {
            return Err("the ID token is from another issuer".into());
        }
        let aud_ok = match &c["aud"] {
            Value::String(a) => *a == self.config.client_id,
            Value::Array(a) => a.iter().any(|v| v.as_str() == Some(&self.config.client_id)),
            _ => false,
        };
        if !aud_ok {
            return Err("the ID token is for another client".into());
        }
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        if c["exp"].as_i64().is_none_or(|exp| exp + SKEW_SECS < now) {
            return Err("the ID token has expired".into());
        }
        if c["nonce"].as_str() != Some(nonce) {
            return Err("the ID token does not belong to this login".into());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct LoginQuery {
    /// Page after the login: path on this site (`/...`), no second slash,
    /// backslash, control character or whitespace. Else `/`.
    #[serde(default)]
    return_to: Option<String>,
}

fn redirect(to: &str) -> Response {
    let mut resp = StatusCode::FOUND.into_response();
    if let Ok(v) = HeaderValue::from_str(to) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

fn oidc_of(s: &AppState) -> Result<&Oidc, ApiError> {
    s.oidc.as_ref().ok_or_else(|| {
        ApiError(
            StatusCode::NOT_FOUND,
            "single sign-on is not configured".into(),
        )
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/oidc/login",
    tag = "auth",
    operation_id = "oidc_login",
    summary = "Start a single sign-on login (redirects to the identity provider)",
    params(LoginQuery),
    description = "Sets a short-lived cookie (`dhonomos_oidc`, HttpOnly, SameSite=Lax) that ties the login to this browser; the callback needs it. A client address may have 20 logins in progress.",
    responses(
        (status = 302, description = "Redirect to the provider's login page", headers(("set-cookie" = String, description = "`dhonomos_oidc=...; Path=/; HttpOnly; SameSite=Lax`"))),
        (status = 404, description = "Single sign-on is not configured"),
        (status = 429, description = "Too many requests, or too many logins in progress from this address"),
        (status = 502, description = "The provider's metadata could not be read"),
        (status = 503, description = "Too many logins in progress"),
    ),
)]
pub(crate) async fn login(
    State(s): State<Arc<AppState>>,
    Extension(info): Extension<ClientInfo>,
    Query(q): Query<LoginQuery>,
) -> Result<Response, ApiError> {
    let (url, state) = oidc_of(&s)?.begin(q.return_to.as_deref(), &info.ip).await?;
    let mut resp = redirect(&url);
    if let Some(c) = state_cookie(
        &state_hash(&state),
        LOGIN_TTL.as_secs(),
        cookies_secure(&s, &info),
    ) {
        resp.headers_mut().insert(header::SET_COOKIE, c);
    }
    Ok(resp)
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct CallbackQuery {
    /// Authorization code.
    #[serde(default)]
    code: Option<String>,
    /// State sent with the login.
    #[serde(default)]
    state: Option<String>,
    /// Error from the provider.
    #[serde(default)]
    error: Option<String>,
    /// Description of `error`.
    #[serde(default)]
    error_description: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/oidc/callback",
    tag = "auth",
    operation_id = "oidc_callback",
    summary = "Return from the identity provider",
    description = "Needs the `dhonomos_oidc` cookie the start set (the login must end in the browser that began it). Sets the session cookie and redirects to the page the login started from; on failure redirects to `/login?sso_error=...`. The account is the one with the same provider and subject; an account made by an earlier version gets them at its first login here.",
    params(CallbackQuery),
    responses(
        (status = 302, description = "Redirect into the UI (logged in) or back to the login page with `sso_error`"),
        (status = 404, description = "Single sign-on is not configured"),
        (status = 429, description = "Too many requests from this address"),
    ),
)]
pub(crate) async fn callback(
    State(s): State<Arc<AppState>>,
    Extension(info): Extension<ClientInfo>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    let oidc = oidc_of(&s)?;
    let mut resp = complete(&s, oidc, &headers, q, &info).await?;
    // Cookie done, any login result -> clear it.
    if let Some(c) = state_cookie("", 0, cookies_secure(&s, &info)) {
        resp.headers_mut().append(header::SET_COOKIE, c);
    }
    Ok(resp)
}

async fn complete(
    s: &AppState,
    oidc: &Oidc,
    headers: &HeaderMap,
    q: CallbackQuery,
    info: &ClientInfo,
) -> Result<Response, ApiError> {
    let fail = |why: String| {
        tracing::warn!(error = %why, "single sign-on failed");
        redirect(&format!("/login?sso_error={}", form(&why)))
    };
    if let Some(e) = q.error {
        return Ok(fail(q.error_description.unwrap_or(e)));
    }
    let (Some(code), Some(state)) = (q.code, q.state) else {
        return Ok(fail("the provider sent no authorization code".into()));
    };
    // Login must return to its starting browser.
    // Check before state is used up -> planted callback cannot burn the real login.
    let bound = crate::auth::cookie_value(headers, STATE_COOKIE)
        .is_some_and(|c| crate::auth::constant_eq(c, &state_hash(&state)));
    if !bound {
        return Ok(fail(
            "the login did not start in this browser; start it again".into(),
        ));
    }
    let id = match oidc.finish(&code, &state).await {
        Ok(v) => v,
        Err(e) => return Ok(fail(e)),
    };
    let tenant = s.config.tenant_id;
    let user = if let Some(u) = s
        .store
        .user_by_oidc(tenant, &id.issuer, &id.subject)
        .await?
    {
        u
    } else if let Some(u) = s.store.user_by_name(tenant, &id.username).await? {
        // Account from before identity keys -> this login claims it,
        // if SSO made it + no other identity has it.
        if u.password_hash != crate::auth::SSO_HASH {
            return Ok(fail(
                "an account with this name exists and is not a single sign-on account".into(),
            ));
        }
        if s.store.oidc_identity(u.id).await?.is_some() {
            return Ok(fail(
                "this account belongs to another identity at the provider".into(),
            ));
        }
        if u.disabled {
            return Ok(fail("this account is disabled".into()));
        }
        if !s
            .store
            .attach_oidc_identity(u.id, &id.issuer, &id.subject)
            .await?
        {
            return Ok(fail("this account is already linked; try again".into()));
        }
        u
    } else {
        // No password -> SSO users cannot log in with one.
        match s
            .store
            .create_sso_user(tenant, &id.username, id.role, &id.issuer, &id.subject)
            .await
        {
            Ok(new) => {
                // From now on: unauthenticated requests refused (see `users_exist`).
                s.users_exist
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                s.store.get_user(new).await?.ok_or_else(|| {
                    ApiError(StatusCode::INTERNAL_SERVER_ERROR, "user vanished".into())
                })?
            }
            Err(e) if e.to_string().contains("unique constraint") => {
                return Ok(fail("the account was just made; try again".into()));
            }
            Err(e) => return Err(e.into()),
        }
    };
    if user.disabled {
        return Ok(fail("this account is disabled".into()));
    }
    let user = if user.role == id.role {
        user
    } else {
        let changed = s
            .store
            .update_user(user.id, Some(id.role), None, None, None)
            .await?;
        crate::wireguard::audit_revoked_clients(s, &changed.revoked_clients).await;
        s.store.get_user(user.id).await?.unwrap_or(user)
    };
    let cookie = crate::auth::begin_session(
        s,
        &user,
        json!({ "method": "oidc", "client": info.ip }),
        true,
        info,
    )
    .await?;
    let mut resp = redirect(&id.return_to);
    resp.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(resp)
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/config",
    tag = "auth",
    operation_id = "auth_config",
    summary = "Which login methods the server offers",
    responses(
        (status = 200, description = "Login methods", body = crate::schemas::AuthConfig),
    ),
)]
pub(crate) async fn config(State(s): State<Arc<AppState>>) -> axum::Json<Value> {
    axum::Json(json!({ "password": true, "sso": s.oidc.is_some() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_from_claims() {
        let cfg = OidcConfig {
            role_claim: "groups".into(),
            admin: vec!["dhonomos-admins".into()],
            operator: vec!["noc".into()],
            viewer: vec!["*".into()],
            ..OidcConfig::default()
        };
        assert_eq!(
            role_for(&cfg, &json!({ "groups": ["noc", "dhonomos-admins"] })),
            Some("admin")
        );
        assert_eq!(
            role_for(&cfg, &json!({ "groups": "noc" })),
            Some("operator")
        );
        assert_eq!(
            role_for(&cfg, &json!({ "groups": ["sales"] })),
            Some("viewer")
        );
        let strict = OidcConfig {
            viewer: Vec::new(),
            ..cfg
        };
        assert_eq!(role_for(&strict, &json!({})), None);
    }

    #[test]
    fn names_come_from_verified_claims() {
        let cfg = OidcConfig {
            username_claim: "preferred_username".into(),
            ..OidcConfig::default()
        };
        let name = |c: Value| username_of(&cfg, &c).map(str::to_owned);
        assert_eq!(
            name(json!({ "preferred_username": "kim", "email": "a@b", "sub": "u1" })),
            Some("kim".into())
        );
        // E-mail names a user only if the provider verified it.
        assert_eq!(
            name(json!({ "email": "boss@example.org", "sub": "u1" })),
            Some("u1".into())
        );
        assert_eq!(
            name(json!({ "email": "boss@example.org", "email_verified": false, "sub": "u1" })),
            Some("u1".into())
        );
        assert_eq!(
            name(json!({ "email": "boss@example.org", "email_verified": true, "sub": "u1" })),
            Some("boss@example.org".into())
        );
        assert_eq!(
            name(json!({ "email": "boss@example.org", "email_verified": "true", "sub": "u1" })),
            Some("boss@example.org".into())
        );
        // Same with e-mail as the configured claim.
        let by_mail = OidcConfig {
            username_claim: "email".into(),
            ..OidcConfig::default()
        };
        assert_eq!(
            username_of(&by_mail, &json!({ "email": "x@y", "sub": "u1" })),
            Some("u1")
        );
        assert_eq!(username_of(&cfg, &json!({})), None);
    }

    #[test]
    fn the_state_cookie_binds_the_login_to_a_browser() {
        let c = state_cookie(&state_hash("abc"), 600, false).expect("cookie");
        let c = c.to_str().unwrap_or_default();
        assert!(c.starts_with("dhonomos_oidc="), "{c}");
        for want in ["HttpOnly", "SameSite=Lax", "Max-Age=600", "Path=/"] {
            assert!(c.contains(want), "{c}");
        }
        assert!(!c.contains("Secure"));
        assert!(
            state_cookie("x", 600, true)
                .and_then(|c| c.to_str().map(|s| s.contains("; Secure")).ok())
                .unwrap_or(false)
        );
        assert_ne!(state_hash("abc"), state_hash("abd"));
        assert!(!c.contains("abc"), "only a hash of the state");
    }

    #[test]
    fn pending_logins_are_limited_per_client_and_in_all() {
        let oidc = Oidc::new(OidcConfig::default());
        let pending = |client: &str| Pending {
            nonce: String::new(),
            verifier: String::new(),
            return_to: "/".into(),
            created: Instant::now(),
            client: client.into(),
        };
        for i in 0..MAX_PENDING_PER_CLIENT {
            assert!(
                oidc.room_for("a", Some((format!("s{i}"), pending("a"))))
                    .is_ok()
            );
        }
        let refused = oidc.room_for("a", None).expect_err("per-client limit");
        assert_eq!(refused.0, StatusCode::TOO_MANY_REQUESTS);
        let refused = oidc
            .room_for("a", Some(("x".into(), pending("a"))))
            .expect_err("per-client limit");
        assert_eq!(refused.0, StatusCode::TOO_MANY_REQUESTS);
        assert!(
            oidc.room_for("b", None).is_ok(),
            "other clients are not hurt"
        );
        // Table full of many clients' logins -> global cap holds.
        if let Ok(mut table) = oidc.pending.lock() {
            for i in 0..(MAX_PENDING - MAX_PENDING_PER_CLIENT) {
                let c = format!("c{i}");
                table.insert(format!("t{i}"), pending(&c));
            }
        }
        let refused = oidc.room_for("z", None).expect_err("global limit");
        assert_eq!(refused.0, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn return_paths_stay_on_site() {
        assert_eq!(safe_return(None), "/");
        assert_eq!(safe_return(Some("/devices/1")), "/devices/1");
        assert_eq!(safe_return(Some("/devices?q=a%20b")), "/devices?q=a%20b");
        assert_eq!(safe_return(Some("/jobs#top")), "/jobs#top");
        assert_eq!(safe_return(Some("/jobs/%E2%9C%93")), "/jobs/%E2%9C%93");
        assert_eq!(
            safe_return(Some("/%20/ok")),
            "/%20/ok",
            "an escaped space is just a space"
        );
        for bad in [
            "//evil.example",
            "https://evil.example",
            "/\\evil",
            "devices",
            "",
            // Browser drops tab/line break from a URL -> these = `//evil`.
            "/\t/evil",
            "/\n/evil",
            "/\r/evil",
            "/\u{b}/evil",
            "/ /evil",
            "/\u{a0}/evil",
            "/\u{2028}/evil",
            "/\u{7f}x",
            "/\0",
            // Same, still escaped: framework decodes a query value once,
            // a client may have escaped x2.
            "/%09/evil",
            "/%0a/evil",
            "/%0D/evil",
            "/%5Cevil",
            "/a%5C..",
            "/%2F/evil",
            "/%2f%2fevil",
            "/a b",
            "javascript:alert(1)",
        ] {
            assert_eq!(safe_return(Some(bad)), "/", "{bad:?}");
        }
        // After the 1st slash: all path on this site, even a host look-alike.
        assert_eq!(safe_return(Some("/@evil.example:80")), "/@evil.example:80");
        assert_eq!(
            safe_return(Some(&format!("/{}", "a".repeat(MAX_RETURN_TO)))),
            "/"
        );
        assert_eq!(percent_decoded("/a%09b%zz%4"), "/a\tb%zz%4");
        assert_eq!(form("a b&c=d/é"), "a%20b%26c%3Dd%2F%C3%A9");
    }
}
