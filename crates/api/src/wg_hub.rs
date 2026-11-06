//! Routes for the WireGuard hub process (ADR-110, stage 2): `dhonomos-wg-hub` on the hub host
//! -> gets its desired state, reports its public key + status of its peers.
//!
//! Auth: `Authorization: Bearer dwh_...` = hub token, issued by an admin via
//! `POST /api/v1/wireguard/hubs/{id}/token`. Only its SHA-256 stored.
//! Outside user auth: no session, API key or `--api-token` works here.
//! Hub token works nowhere else.
//! Each call: limit per client address (as other public routes) + record when/from where the
//! hub was seen (+ version from `User-Agent: dhonomos-wg-hub/<version>`).
//! Audit records it causes -> actor `hub:<name>`.
//!
//! Long-poll: `GET /wg-hub/state` -> state + `ETag: "r<revision>"`.
//! Hub sends the tag back in `If-None-Match` + `?wait=<seconds>` (max 60).
//! Revision unchanged -> server holds the request, checks 1/s, 304 after the wait.
//! Network, member or site prefix of the hub changes -> 200 + new state at once.
//! Server shutdown (`ApiConfig::shutdown`) -> 304 at once -> held request does not delay the
//! stop; hub polls again.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router};
use dhonomos_store::WgSealedPsk;
use dhonomos_wireguard::{
    HUB_TOKEN_PREFIX, HubState, KEY_LEN, MAX_STATUS_PEERS, MAX_WAIT_SECS, PublicKeyReport,
    StatusAccepted, StatusReport, key_text, validate_key,
};
use serde::Deserialize;
use serde_json::json;
use tokio::time::Instant;
use uuid::Uuid;
use zeroize::Zeroize as _;

use crate::auth::{self, sha256};
use crate::client::info_of;
use crate::wireguard::unprocessable;
use crate::{ApiError, AppState, audit};

/// Prefix before the version in a hub `User-Agent`.
const USER_AGENT_PREFIX: &str = "dhonomos-wg-hub/";
/// Max version length kept from `User-Agent`, in chars.
const MAX_VERSION: usize = 64;
/// Max status report body.
const MAX_STATUS_BODY: usize = 8 << 20;
/// Long-poll revision check interval.
const POLL_EVERY: Duration = Duration::from_secs(1);
/// Max handshake time, Unix seconds (end of year 9999).
const MAX_HANDSHAKE: i64 = 253_402_300_799;

/// Hub of the request (set by [`hub_auth`]).
#[derive(Debug, Clone)]
pub(crate) struct HubCaller {
    pub(crate) id: Uuid,
    pub(crate) name: String,
}

pub(crate) fn hub_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/wg-hub/state", get(hub_state))
        .route("/wg-hub/public-key", put(public_key))
        .route(
            "/wg-hub/status",
            post(status).layer(DefaultBodyLimit::max(MAX_STATUS_BODY)),
        )
        .route_layer(from_fn_with_state(state.clone(), hub_auth))
        .route_layer(from_fn_with_state(state, auth::public_limit))
}

fn unauthorized(msg: &str) -> ApiError {
    ApiError(StatusCode::UNAUTHORIZED, msg.into())
}

/// Version in a hub `User-Agent`; `None` if not a hub.
fn hub_version(headers: &HeaderMap) -> Option<String> {
    let agent = headers.get(header::USER_AGENT)?.to_str().ok()?;
    let (_, rest) = agent.split_once(USER_AGENT_PREFIX)?;
    let version: String = rest
        .split_whitespace()
        .next()?
        .chars()
        .take(MAX_VERSION)
        .collect();
    (!version.is_empty()).then_some(version)
}

/// Middleware: caller must carry a valid hub token of this server's tenant.
async fn hub_auth(
    State(s): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|t| t.starts_with(HUB_TOKEN_PREFIX))
        .ok_or_else(|| unauthorized("a hub token is required"))?;
    let hub = s
        .store
        .wg_hub_by_token(&sha256(token))
        .await?
        .filter(|h| h.tenant_id == s.config.tenant_id)
        .ok_or_else(|| unauthorized("invalid hub token"))?;
    let ip = info_of(&req).ip.parse::<IpAddr>().ok();
    let version = hub_version(req.headers());
    if let Err(e) = s.store.touch_wg_hub(hub.id, ip, version.as_deref()).await {
        tracing::warn!(error = %e, hub = %hub.name, "recording that the hub was seen failed");
    }
    let actor = format!("hub:{}", hub.name);
    req.extensions_mut().insert(HubCaller {
        id: hub.id,
        name: hub.name,
    });
    Ok(auth::ACTOR.scope(actor, next.run(req)).await)
}

/// Query of `GET /wg-hub/state`.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct StateQuery {
    /// With `If-None-Match` = current revision: hold the request up to this many seconds
    /// (0-60, default 0) until the state changes.
    #[serde(default)]
    wait: u64,
}

fn etag(revision: i64) -> String {
    format!("\"r{revision}\"")
}

/// 304 + the tag the hub has.
fn not_modified(revision: i64) -> Response {
    let mut resp = StatusCode::NOT_MODIFIED.into_response();
    if let Ok(v) = HeaderValue::from_str(&etag(revision)) {
        resp.headers_mut().insert(header::ETAG, v);
    }
    resp
}

#[utoipa::path(
    get,
    path = "/api/v1/wg-hub/state",
    tag = "wireguard-hub",
    operation_id = "get_wg_hub_state",
    summary = "The hub's desired state",
    description = "The hub's networks by listen port (interface `dwg<port>`, tunnel prefix, the hub's own address, MTU) and in each the members that are not revoked and have a public key, by address. A peer's `allowed_ips` are its `/32`, then the LAN prefixes behind it; a peer with a pre-shared key carries it in `preshared_key` (a secret, sent only here). When a stored pre-shared key cannot be opened (no `--secrets-key`, or another key), the server answers 500 instead of a state without it, and the hub keeps what it runs.\n\nLong-poll: send the `ETag` of the last answer in `If-None-Match` and `wait`; the server answers 200 as soon as the state changes, or 304 when `wait` seconds pass without a change (at once with `wait=0`). The server also answers 304 at once when it is shutting down.",
    params(
        StateQuery,
        ("If-None-Match" = Option<String>, Header, description = "The `ETag` of the state the hub has, e.g. `\"r42\"`"),
    ),
    security(("hub_token" = [])),
    responses(
        (status = 200, description = "The state", body = crate::schemas::WgHubState, headers(("etag" = String, description = "`\"r<revision>\"`"))),
        (status = 304, description = "Unchanged since the revision in `If-None-Match`", headers(("etag" = String, description = "`\"r<revision>\"`"))),
        (status = 422, description = "`wait` is over 60"),
        (status = 500, description = "A stored pre-shared key cannot be opened"),
    ),
)]
async fn hub_state(
    State(s): State<Arc<AppState>>,
    Extension(hub): Extension<HubCaller>,
    Query(q): Query<StateQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if q.wait > MAX_WAIT_SECS {
        return Err(unprocessable(format!(
            "wait must be between 0 and {MAX_WAIT_SECS} seconds"
        )));
    }
    let known = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_owned());
    let gone = || unauthorized("invalid hub token");
    let mut revision = s.store.wg_hub_revision(hub.id).await?.ok_or_else(gone)?;
    if known.as_deref() == Some(etag(revision).as_str()) {
        let deadline = Instant::now() + Duration::from_secs(q.wait);
        let seen = revision;
        while revision == seen {
            let now = Instant::now();
            if now >= deadline {
                return Ok(not_modified(revision));
            }
            tokio::select! {
                () = tokio::time::sleep(POLL_EVERY.min(deadline - now)) => {}
                () = crate::stopping(&s) => return Ok(not_modified(revision)),
            }
            revision = s.store.wg_hub_revision(hub.id).await?.ok_or_else(gone)?;
        }
    }
    let (mut state, sealed) = s
        .store
        .wg_hub_state_sealed(hub.id)
        .await?
        .ok_or_else(gone)?;
    // Never send a peer without its pre-shared key. Error answer -> hub keeps its kernel state.
    let opened = open_preshared_keys(&s, &mut state, &sealed);
    let tag = etag(state.revision);
    let resp = opened.map(|()| Json(&state).into_response());
    for p in state.networks.iter_mut().flat_map(|n| n.peers.iter_mut()) {
        if let Some(k) = p.preshared_key.as_mut() {
            k.zeroize();
        }
    }
    let mut resp = resp?;
    if let Ok(v) = HeaderValue::from_str(&tag) {
        resp.headers_mut().insert(header::ETAG, v);
    }
    Ok(resp)
}

/// Fill in the pre-shared key of each peer of `state` with one in `sealed`.
/// Opened with the server's secrets key.
/// Cannot open (no secrets key, other key, damaged row) -> 500 + warning naming the member.
fn open_preshared_keys(
    s: &AppState,
    state: &mut HubState,
    sealed: &HashMap<Uuid, WgSealedPsk>,
) -> Result<(), ApiError> {
    let cannot = |member: Uuid, why: &str| {
        tracing::warn!(member = %member, why, "a stored pre-shared key cannot be opened");
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "a stored pre-shared key cannot be opened".into(),
        )
    };
    for p in state.networks.iter_mut().flat_map(|n| n.peers.iter_mut()) {
        let Some((ct, nonce)) = sealed.get(&p.member_id) else {
            continue;
        };
        let Some(secrets) = s.config.secrets.as_deref() else {
            return Err(cannot(p.member_id, "no --secrets-key"));
        };
        let plain = secrets
            .open_wg_psk(p.member_id, ct, nonce)
            .map_err(|_| cannot(p.member_id, "it does not open"))?;
        let bytes: &[u8; KEY_LEN] = plain
            .as_slice()
            .try_into()
            .map_err(|_| cannot(p.member_id, "it is not 32 bytes"))?;
        p.preshared_key = Some(std::mem::take(&mut *key_text(bytes)));
    }
    Ok(())
}

#[utoipa::path(
    put,
    path = "/api/v1/wg-hub/public-key",
    tag = "wireguard-hub",
    operation_id = "put_wg_hub_public_key",
    summary = "Report the hub's public key",
    description = "The hub makes its key pair itself and keeps the private key; members get the public key from the hub's record. A change is audited, and devices are woken to take the new key: the CWMP devices of the hub's networks get a connection request (at most 100 per change; the others at their next periodic Inform), and USP Agents are reconciled while connected.",
    request_body = crate::schemas::WgHubPublicKey,
    security(("hub_token" = [])),
    responses(
        (status = 204, description = "Stored"),
        (status = 422, description = "Invalid body or key"),
    ),
)]
async fn public_key(
    State(s): State<Arc<AppState>>,
    Extension(hub): Extension<HubCaller>,
    body: Result<Json<PublicKeyReport>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    validate_key(&req.public_key).map_err(|e| unprocessable(format!("public_key: {e}")))?;
    let previous = s
        .store
        .set_wg_hub_public_key(hub.id, &req.public_key)
        .await?
        .ok_or_else(|| unauthorized("invalid hub token"))?;
    if previous.as_deref() != Some(req.public_key.as_str()) {
        // Public keys are not secret.
        audit(
            &s,
            "wireguard.hub.public_key",
            "wg_hub",
            hub.id,
            json!({ "old": previous, "new": req.public_key }),
        )
        .await;
        crate::wireguard::wake_hub(&s, hub.id, "hub public key changed").await;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/v1/wg-hub/status",
    tag = "wireguard-hub",
    operation_id = "post_wg_hub_status",
    summary = "Report the status of the hub's peers",
    description = "Each peer that is a member of one of the hub's networks (by network and public key) and is not revoked replaces that member's `hub_status`; the others are counted as ignored. At most 65,536 peers, 8 MiB.",
    request_body = crate::schemas::WgHubStatusReport,
    security(("hub_token" = [])),
    responses(
        (status = 200, description = "How many peers were stored and ignored", body = crate::schemas::WgHubStatusAccepted),
        (status = 413, description = "The body is over 8 MiB"),
        (status = 422, description = "Invalid body, too many peers, or an invalid key, endpoint or number"),
    ),
)]
async fn status(
    State(s): State<Arc<AppState>>,
    Extension(hub): Extension<HubCaller>,
    body: Result<Json<StatusReport>, JsonRejection>,
) -> Result<Json<StatusAccepted>, ApiError> {
    let Json(mut req) = body.map_err(|e| unprocessable(e.body_text()))?;
    if req.peers.len() > MAX_STATUS_PEERS {
        return Err(unprocessable(format!(
            "a status report has at most {MAX_STATUS_PEERS} peers"
        )));
    }
    for (i, p) in req.peers.iter_mut().enumerate() {
        validate_key(&p.public_key)
            .map_err(|e| unprocessable(format!("peers[{i}].public_key: {e}")))?;
        if let Some(endpoint) = &p.endpoint {
            // Stored as the server writes it -> bounded length.
            let addr: SocketAddr = endpoint
                .trim()
                .parse()
                .map_err(|_| unprocessable(format!("peers[{i}].endpoint: not an address:port")))?;
            p.endpoint = Some(addr.to_string());
        }
        if p.latest_handshake.is_some_and(|t| t > MAX_HANDSHAKE) {
            return Err(unprocessable(format!(
                "peers[{i}].latest_handshake: not a time in Unix seconds"
            )));
        }
        for (what, n) in [("rx_bytes", p.rx_bytes), ("tx_bytes", p.tx_bytes)] {
            if i64::try_from(n).is_err() {
                return Err(unprocessable(format!(
                    "peers[{i}].{what}: at most {}",
                    i64::MAX
                )));
            }
        }
    }
    let report = s.store.report_wg_peer_status(hub.id, &req.peers).await?;
    let (accepted, ignored) = (report.accepted, report.ignored);
    tracing::debug!(hub = %hub.name, accepted, ignored, "peer status reported");
    crate::wg_history::spawn_record(&s, report.peers);
    Ok(Json(StatusAccepted { accepted, ignored }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_version_comes_from_a_hubs_user_agent() {
        let of = |ua: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::USER_AGENT, HeaderValue::from_str(ua).unwrap());
            hub_version(&h)
        };
        assert_eq!(of("dhonomos-wg-hub/0.1.0").as_deref(), Some("0.1.0"));
        assert_eq!(
            of("dhonomos-wg-hub/0.2.0 (linux x86_64)").as_deref(),
            Some("0.2.0")
        );
        assert_eq!(of("curl/8.0"), None);
        assert_eq!(of("dhonomos-wg-hub/"), None);
        assert_eq!(
            of(&format!("dhonomos-wg-hub/{}", "1".repeat(100)))
                .unwrap()
                .len(),
            MAX_VERSION
        );
        assert_eq!(hub_version(&HeaderMap::new()), None);
    }

    #[test]
    fn tags_name_the_revision() {
        assert_eq!(etag(42), "\"r42\"");
        let resp = not_modified(7);
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(resp.headers()[header::ETAG], "\"r7\"");
    }
}
