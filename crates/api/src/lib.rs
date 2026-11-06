//! Northbound REST API (NB-01). All messages in English (ADR-025).
//!
//! | Method | Path | Purpose |
//! |---|---|---|
//! | GET | `/healthz` | Liveness |
//! | GET | `/api/v1/devices?q&protocol&status&product_class&oui&model_name&software_version&tag&limit&offset` | Search devices, + total |
//! | GET | `/api/v1/devices/facets?<filters>` | Distinct OUIs, product classes, model names (+ counts) of the matching devices; each list ignores its own filter (UI-01) |
//! | POST | `/api/v1/devices` | Pre-register a CWMP device, or a USP Agent with `endpoint_id` (CO-12) |
//! | POST | `/api/v1/devices/bulk` | Pre-register max 10,000 USP Agents (EndpointID, or OUI + serial number) or CWMP devices; dry run option |
//! | GET | `/api/v1/devices/{id}` | Device details |
//! | PATCH | `/api/v1/devices/{id}` | Change status (`active`, `quarantined`, `retired`) |
//! | DELETE | `/api/v1/devices/{id}` | Delete a retired device + all its data (CO-14) |
//! | POST | `/api/v1/devices/delete` | Delete max 1,000 devices + all their data; on request retire in-service ones first (CO-14) |
//! | GET/POST | `/api/v1/devices/{id}/config-backups` | List or take config backups (CO-08) |
//! | GET/DELETE | `/api/v1/config-backups/{id}`, `.../diff?device_id=`, POST `.../restore` | Backup values, drift, restore |
//! | GET/POST | `/api/v1/devices/{id}/config-files` | Vendor config files uploaded by the device / request one (CWMP Upload) |
//! | GET/POST | `/api/v1/devices/{id}/log-files` | Vendor log files uploaded by the device / request one (CWMP Upload, USP `VendorLogFile.{i}.Upload()`) |
//! | GET | `/api/v1/files/{id}/content` | Bytes of a stored file (operator; file of a device only inside the caller's scope) |
//! | POST | `/api/v1/devices/{id}/replace` | Replace a unit: backup, tags, restore onto the new one, retire (CO-14) |
//! | GET | `/api/v1/devices/{id}/parameters?prefix=` | Parameter snapshot |
//! | GET | `/api/v1/devices/{id}/credentials` | Credential kinds + usernames (no secrets) |
//! | PUT/DELETE | `/api/v1/devices/{id}/credentials/{kind}` | Set or remove `acs_auth` / `connection_request`; `xmpp` (XMPP login): remove only |
//! | POST/DELETE | `/api/v1/devices/{id}/mqtt-credentials` | Issue (rotate) or revoke the broker account of a USP Agent (US-17) |
//! | POST | `/api/v1/devices/{id}/certificate` | Issue a USP Agent cert (from a CSR, or with a new key) (US-08) |
//! | POST | `/api/v1/certificates/bundle` | Certs with new keys for many devices (by ID, EndpointID, OUI + serial number or filter) -> AES-256 encrypted zip (ADR-099) |
//! | POST | `/api/v1/certificates/revoke` | Revoke an Agent cert by SHA-256 fingerprint; for a cert no device leads to any more |
//! | GET | `/api/v1/devices/{id}/supported-model` | Supported data model of the device firmware (US-11) |
//! | POST | `/api/v1/devices/{id}/data-model/refresh` | Drop the cached supported data model of the USP Agent + read it again (US-11) |
//! | GET | `/api/v1/devices/{id}/metrics`, `.../metrics/series?path&from&to&step` | Time series (DG-04/05) |
//! | GET | `/api/v1/devices/{id}/bulkdata-url` | URL for the BulkData reports of the device (operator) |
//! | GET | `/api/v1/devices/{id}/wifi` | Radios, networks, stations + latest neighbour scan (DG-02) |
//! | GET | `/api/v1/devices/{id}/events?limit=` | Events |
//! | GET | `/api/v1/devices/{id}/tasks?limit=` | Tasks |
//! | POST | `/api/v1/devices/{id}/tasks` | Queue a task (+ wake the device) |
//! | POST | `/api/v1/devices/{id}/connection-request` | Wake the device |
//! | GET | `/api/v1/tasks/{id}` | Task details |
//! | DELETE | `/api/v1/tasks/{id}` | Cancel a pending task |
//! | PUT | `/api/v1/files?name=&file_type=&version=` | Upload a file (raw body) |
//! | GET | `/api/v1/files` | List files |
//! | DELETE | `/api/v1/files/{id}` | Delete a file |
//! | POST | `/api/v1/jobs/preview` | Devices a target filter selects |
//! | GET/POST | `/api/v1/jobs` | List or create bulk jobs (CO-15) |
//! | GET | `/api/v1/jobs/{id}`, `/api/v1/jobs/{id}/devices?state=` | Job progress, members |
//! | POST | `/api/v1/jobs/{id}/{start,pause,resume,approve,cancel}` | Control a job |
//! | GET | `/api/v1/presets` | Loaded provisioning presets |
//! | POST | `/api/v1/presets/dry-run` | Tasks presets would queue for a device on given events |
//! | GET | `/api/v1/alarms?state=&device_id=`, POST `/api/v1/alarms/{id}/ack`, GET `/api/v1/alarm-rules` | Alarms (CO-07) |
//! | GET/POST | `/api/v1/alarm-silences?all=`, DELETE `/api/v1/alarm-silences/{id}` (ends it) | Silences = maintenance windows (NB-07) |
//! | GET | `/api/v1/overview` | Fleet, sessions/min, task queue, jobs, firmware, alarms (UI-02) |
//! | GET | `/api/v1/devices/export.csv?<filters>`, `/api/v1/jobs/{id}/members.csv?state=`, `/api/v1/alarms/export.csv?state=` | CSV exports (NB-01) |
//! | POST | `/api/v1/devices/attributes/import?dry_run=` | Device attributes from CSV (CO-13) |
//! | GET | `/api/v1/stream?device_id=` | SSE: alarm changes + events of the device (NB-03) |
//! | GET | `/api/v1/audit?limit=` | Audit trail of changes |
//! | GET | `/api/v1/wireguard/summary` | WireGuard tunnel health: live members per state (connected, idle, stale, never, unknown), all + per network, + thresholds (operator) |
//! | GET/POST | `/api/v1/wireguard/hubs`, GET/PATCH/DELETE `.../hubs/{id}` | WireGuard hubs (ADR-110; read: operator, change: admin) |
//! | POST/DELETE | `/api/v1/wireguard/hubs/{id}/token` | Issue (shown once, replaces the old one) or revoke a hub token (admin) |
//! | GET/PUT/POST | `/api/v1/wg-hub/*`: GET `state?wait=`, PUT `public-key`, POST `status` | Called by `dhonomos-wg-hub` with its hub token: desired state of the hub (long-poll on the revision), its public key, status of its peers |
//! | GET/POST | `/api/v1/wireguard/networks`, GET/PATCH/DELETE `.../networks/{id}` | WireGuard overlay networks: tunnel prefix from the address pool, hub port, MTU |
//! | GET/POST | `/api/v1/wireguard/networks/{id}/members` | Members of a network (device + client peers); add client -> private key, config file + QR code, once |
//! | GET/PATCH/DELETE | `/api/v1/wireguard/members/{id}`, POST `.../revoke` | A member: rename, site prefixes, revoke, delete |
//! | GET | `/api/v1/wireguard/members/{id}/config` | wg-quick config file of a client member, without the private key |
//! | POST | `/api/v1/wireguard/members/{id}/rekey` | New key of a client member; key pair made here -> returned once with config file + QR code |
//! | GET | `/api/v1/devices/{id}/wireguard` | Live WireGuard device members of a device + its twin (other record of the same CPE): network names + what the device reported per tunnel (operator) |
//! | POST | `/api/v1/auth/totp/{setup,enable,disable,recovery-codes}` | TOTP two-factor auth of the logged-in local account (ADR-100) |
//! | DELETE | `/api/v1/users/{id}/totp` | Reset the TOTP two-factor auth of a user (admin) |
//! | GET | `/api/v1/settings/server` | Effective server config: value, source, category per option; secrets only set / not set; web-changeable or not (admin) |
//! | PUT | `/api/v1/settings/server/{key}` | Change a runtime option from the web -> applied on every process within seconds (admin) |
//! | DELETE | `/api/v1/settings/server/{key}` | Reset a runtime option to its default (admin) |
//! | GET | `/api/v1/settings/server/{key}/history` | Last 50 changes of a runtime option (admin) |
//! | GET | `/api/v1/settings/alarm-rules` | Alarm rules as YAML + as evaluated; source = `--alarms` file or web (admin) |
//! | PUT | `/api/v1/settings/alarm-rules` | Change the alarm rules (not with `--alarms`) -> applied on every process within seconds (admin) |
//! | GET | `/api/v1/settings/alarm-rules/history` | Last 20 versions of the alarm rules (admin) |
//! | GET | `/api/v1/openapi.json` | OpenAPI 3.1 document of this API (public) |
//! | GET | `/metrics` | Prometheus metrics |
//! | GET | `/*` | Operator web UI (single-page app) |

mod alarm_rules;
mod alarms;
mod auth;
mod bundle;
mod client;
mod enroll;
mod export;
mod files;
mod import;
mod jobs;
mod jwt;
mod lifecycle;
mod oidc;
mod openapi;
mod presets;
mod ratelimit;
mod schemas;
mod series;
mod settings;
mod stream;
mod tls_listener;
mod totp;
mod ui;
mod wg_history;
mod wg_hub;
mod wireguard;

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use dhonomos_core::usp::DataModelRefresh;
use dhonomos_core::{BrokerAccess, SecretBox, TaskKind, UspService, Waker};
use dhonomos_store::{
    AuditEntry, CwmpIdentity, Device, Event, NewTask, Store, StoredParam, Task, TaskState,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct ApiConfig {
    /// Required `Authorization: Bearer <token>`; `None` -> no check.
    pub bearer_token: Option<String>,
    /// Tenant the API acts for.
    pub tenant_id: Uuid,
    /// Sends CRs; `None` -> no waking.
    pub waker: Option<Waker>,
    /// Running USP service -> read data models of connected Agents again. `None` = USP off
    /// (cached models still dropped; Agents read at connect).
    pub usp: Option<UspService>,
    /// Prometheus metrics at `GET /metrics` (behind the bearer token).
    pub metrics: Option<metrics_exporter_prometheus::PrometheusHandle>,
    /// Device time series store: peer status reports of WireGuard hubs -> tunnel history of
    /// device members. `None` -> no history (tests, tools).
    pub metrics_ingest: Option<dhonomos_core::MetricsIngest>,
    /// File storage for firmware/config downloads; `None` -> no `/files`.
    pub files: Option<FilesConfig>,
    /// Encrypts stored secrets; `None` -> secrets cannot be stored (CO-16).
    pub secrets: Option<Arc<SecretBox>>,
    /// Issues broker accounts of USP Agents; `None` -> no `/mqtt-credentials` (US-17).
    pub broker: Option<BrokerAccess>,
    /// Issues certs of USP Agents; `None` -> no `/certificate` (US-08).
    pub ca: Option<Arc<dhonomos_pki::Ca>>,
    /// Loaded provisioning presets, for list + dry run (CO-04).
    pub presets: dhonomos_core::Shared<dhonomos_core::Presets>,
    /// Presets in DB, edited via API (UI-03). false -> from `--presets` file (read-only here).
    pub presets_in_db: bool,
    /// Loaded alarm rules (CO-07).
    pub alarm_rules: dhonomos_core::Shared<dhonomos_core::alarms::AlarmRules>,
    /// `--alarms` file of the rules (read-only here). `None` -> rules in DB, edited via API
    /// (runtime settings, stage 4).
    pub alarm_rules_file: Option<AlarmRulesFile>,
    /// Session cookie `Secure` + `__Host-` prefix (UI served over HTTPS, e.g. behind a proxy).
    pub secure_cookies: bool,
    /// Session lifetime in hours (0 = 12). Can change at runtime.
    pub session_hours: dhonomos_core::Shared<i64>,
    /// Session unused this many minutes -> ends; `<= 0` -> no idle limit (ADR-103).
    /// Can change at runtime.
    pub session_idle_minutes: dhonomos_core::Shared<i64>,
    /// Trusted reverse proxies (ADR-103). TCP peer inside one -> believe `X-Forwarded-For`,
    /// `Forwarded`, `X-Forwarded-Proto`, `X-Forwarded-Host` -> client address for limits and
    /// lockouts.
    pub trusted_proxies: Vec<dhonomos_core::Cidr>,
    /// Public URL of the UI (`https://rms.example.org`): browser change request accepted only
    /// with exactly this `Origin` (ADR-103).
    pub public_url: Option<PublicOrigin>,
    /// Requests/s per caller (burst x4); 0 = off. Can change at runtime.
    pub rate_limit: dhonomos_core::Shared<u32>,
    /// OpenID Connect SSO (NB-04).
    pub oidc: Option<OidcConfig>,
    /// TOTP two-factor auth of local accounts (ADR-100).
    pub totp: TotpConfig,
    /// Built-in XMPP server, if this process runs it -> device JID (`xmpp_jid`) from its live
    /// session table. `None` otherwise (`--role api` does not run it).
    pub xmpp: Option<dhonomos_xmpp::XmppServer>,
    /// WireGuard: address pool of the overlay networks + rest time of a revoked member's
    /// address (ADR-110). Can change at runtime.
    pub wireguard: dhonomos_core::Shared<WireguardConfig>,
    /// `true` = server stopping -> long-held requests (hub long-poll, event stream) end at once,
    /// no hold-up of graceful shutdown. `None` -> never (tests, tools).
    pub shutdown: Option<tokio::sync::watch::Receiver<bool>>,
    /// Options the server runs with, for `GET /settings/server` (secrets without values).
    /// Empty in tests and tools.
    pub server_settings: Arc<Vec<ServerSetting>>,
    /// Checks + applies runtime setting changes (`PUT /settings/server/{key}`).
    pub settings_hooks: SettingsHooks,
}

pub use alarm_rules::AlarmRulesFile;
pub use auth::hash_password;
pub use client::PublicOrigin;
pub use files::{DownloadLimits, FilesConfig, file_server};
pub use oidc::OidcConfig;
pub use settings::{
    ApplySettings, ServerSetting, SettingCategory, SettingKind, SettingSource, SettingsHooks,
    ValidateSettings,
};
pub use tls_listener::{PeerAddr, TlsListener};
pub use totp::TotpConfig;
pub use wireguard::WireguardConfig;

#[derive(Debug)]
pub(crate) struct AppState {
    store: Store,
    config: ApiConfig,
    /// Operator accounts known to exist (cached once true; "no" re-checked).
    users_exist: std::sync::atomic::AtomicBool,
    /// Login attempts per username + client address (bounded table).
    login_attempts: auth::attempts::Attempts,
    /// Same for the two-factor account screens, per account id.
    /// Own table -> the two cannot lock each other.
    totp_attempts: auth::attempts::Attempts,
    /// Rate limit for proxy set-up hints in the log.
    hints: client::Hints,
    /// Per-caller request limit.
    limiter: ratelimit::RateLimiter,
    /// Per-address limit on public routes that cost work (login, SSO). Always on.
    public_limiter: ratelimit::RateLimiter,
    /// Max concurrent password hashes (see `auth::hashing`).
    hashing: Arc<tokio::sync::Semaphore>,
    /// SSO, if configured.
    oidc: Option<oidc::Oidc>,
    /// Last sample of the tunnel of each WireGuard device member.
    wg_history: wg_history::TunnelHistory,
}

/// Resolves when the server stops ([`ApiConfig::shutdown`] is or turns `true`).
/// Never: no receiver, or sender gone without `true`.
pub(crate) async fn stopping(s: &AppState) {
    if let Some(rx) = &s.config.shutdown {
        let mut rx = rx.clone();
        if rx.wait_for(|stop| *stop).await.is_ok() {
            return;
        }
    }
    std::future::pending::<()>().await;
}

/// API error -> `{"error": "..."}`.
#[derive(Debug)]
pub struct ApiError(pub(crate) StatusCode, pub(crate) String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<dhonomos_store::StoreError> for ApiError {
    fn from(e: dhonomos_store::StoreError) -> Self {
        tracing::error!(error = %e, "storage error");
        Self(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage unavailable".into(),
        )
    }
}

fn not_found(what: &str) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, format!("{what} not found"))
}

pub(crate) fn ts(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

/// Full JID of the live XMPP session of the device.
/// `None`: XMPP server not in this process, or device not connected.
fn xmpp_jid(s: &AppState, d: &Device) -> Option<String> {
    s.config
        .xmpp
        .as_ref()?
        .jid(&dhonomos_core::account_of(d.id))
}

fn device_json(s: &AppState, d: &Device) -> Value {
    device_value(d, xmpp_jid(s, d))
}

/// Device as the API shows it; `xmpp_jid` = JID of its live XMPP session, if any.
fn device_value(d: &Device, xmpp_jid: Option<String>) -> Value {
    json!({
        "id": d.id,
        "protocol": d.protocol,
        "oui": d.oui,
        "product_class": d.product_class,
        "serial_number": d.serial_number,
        "endpoint_id": d.endpoint_id,
        "manufacturer": d.manufacturer,
        "model_name": d.model_name,
        "software_version": d.software_version,
        "hardware_version": d.hardware_version,
        "data_model": d.data_model,
        "connection_request_url": d.connection_request_url,
        "cwmp_version": d.cwmp_version,
        "status": d.status,
        "tags": d.tags,
        "first_seen_at": ts(d.first_seen_at),
        "last_contact_at": d.last_contact_at.map(ts),
        "last_boot_at": d.last_boot_at.map(ts),
        "last_remote_addr": d.last_remote_addr,
        "attributes": d.attributes,
        "usp_ws_url": d.usp_ws_url,
        "xmpp_connected_at": d.xmpp_connected_at.map(ts),
        "xmpp_jid": xmpp_jid,
        "udp_cr_address": d.udp_cr_address,
        "udp_cr_seen_at": d.udp_cr_seen_at.map(ts),
        "last_wake_at": d.last_wake_at.map(ts),
        "last_wake_method": d.last_wake_method,
        "last_wake_outcome": d.last_wake_outcome,
    })
}

/// Device list filters from query params (also for the CSV export).
fn device_search(q: DeviceQuery) -> Result<dhonomos_store::DeviceSearch, ApiError> {
    let blank = |v: Option<String>| v.filter(|s| !s.trim().is_empty());
    let attribute = match blank(q.attr) {
        None => None,
        Some(a) => {
            let (k, v) = a.split_once('=').ok_or_else(|| {
                ApiError(StatusCode::BAD_REQUEST, "attr must be key=value".into())
            })?;
            Some((k.trim().to_owned(), v.trim().to_owned()))
        }
    };
    Ok(dhonomos_store::DeviceSearch {
        q: blank(q.q),
        protocol: blank(q.protocol),
        status: blank(q.status),
        product_class: blank(q.product_class),
        oui: blank(q.oui),
        model_name: blank(q.model_name),
        software_version: blank(q.software_version),
        tag: blank(q.tag),
        attribute,
        scope: auth::caller_scope()?.map(|s| (*s).clone()),
        filter: blank(q.filter)
            .map(|f| dhonomos_store::FilterExpr::parse(&f))
            .transpose()
            .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?,
    })
}

/// Attribute key: letters, digits, `_`, `-`, `.`; max 64 chars.
pub(crate) fn valid_attribute_key(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 64
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

const MAX_ATTRIBUTES: usize = 50;
pub(crate) const MAX_ATTRIBUTE_VALUE: usize = 256;
const MAX_TAGS: usize = 50;

/// Tags as stored: trimmed, sorted, no duplicates. 422: too many, or one empty or too long.
pub(crate) fn clean_tags(tags: &[String]) -> Result<Vec<String>, ApiError> {
    let mut t: Vec<String> = tags.iter().map(|t| t.trim().to_owned()).collect();
    t.sort();
    t.dedup();
    if t.len() > MAX_TAGS || t.iter().any(|t| t.is_empty() || t.len() > 64) {
        return Err(ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("at most {MAX_TAGS} tags of 1-64 characters"),
        ));
    }
    Ok(t)
}

fn param_json(p: &StoredParam) -> Value {
    json!({
        "path": p.path,
        "value": p.value,
        "type": p.xsd_type,
        "writable": p.writable,
        "updated_at": ts(p.updated_at),
    })
}

/// Hides secrets (file server passwords, SPV entries marked `secret`) in API output and
/// audit records. Stored ciphertext never shown either.
pub(crate) fn redact(payload: &Value) -> Value {
    dhonomos_core::secrets::redact_secrets(payload)
}

/// [`redact`] for a task payload, also hides by `kind` what a viewer must not learn:
/// signed URLs -> holder can write a file or run a transfer on the file server
/// (device gets them via the protocol, not the API):
///
/// - Upload `url`;
/// - diagnostic `params.url` (signed test link, or link written by the operator);
/// - Operate `input` entries named `URL` (USP transfer commands).
///
/// Download URL kept: read-only, operators write it to be seen.
pub(crate) fn redact_task(kind: &str, payload: &Value) -> Value {
    let mut v = redact(payload);
    let hide = |slot: Option<&mut Value>| {
        if let Some(slot) = slot
            && let Some(url) = slot.as_str()
        {
            *slot = json!(redact_url(url));
        }
    };
    match kind {
        "upload" => hide(v.get_mut("url")),
        "diagnostic" => hide(v.pointer_mut("/params/url")),
        "operate" => {
            if let Some(input) = v.get_mut("input").and_then(Value::as_object_mut) {
                for (key, value) in input.iter_mut() {
                    if key.eq_ignore_ascii_case("url") {
                        hide(Some(value));
                    }
                }
            }
        }
        _ => {}
    }
    v
}

/// `url` minus credentials, query and fragment (signed links keep the signature there).
/// Enough to see where it points.
fn redact_url(url: &str) -> String {
    let (base, hidden) = match url.split_once(['?', '#']) {
        Some((base, _)) => (base, true),
        None => (url, false),
    };
    let base = match base.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            let host = authority.rsplit('@').next().unwrap_or(authority);
            format!("{scheme}://{host}{path}")
        }
        None => base.to_owned(),
    };
    if hidden {
        format!("{base}?{}", dhonomos_core::secrets::REDACTED)
    } else {
        base
    }
}

fn task_json(t: &Task) -> Value {
    json!({
        "id": t.id,
        "device_id": t.device_id,
        "kind": t.kind,
        "payload": redact_task(&t.kind, &t.payload),
        "state": t.state.as_str(),
        "attempts": t.attempts,
        "max_attempts": t.max_attempts,
        "result": t.result,
        "error": t.error,
        "created_at": ts(t.created_at),
        "priority": t.priority,
        "created_by": t.created_by,
        "job_id": t.job_id,
        "trace": t.trace,
    })
}

fn event_json(e: &Event) -> Value {
    json!({
        "id": e.id,
        "kind": e.kind,
        "detail": e.detail,
        "occurred_at": ts(e.occurred_at),
    })
}

#[derive(Debug, Deserialize)]
struct Page {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    100
}

impl Page {
    fn clamp(&self) -> (i64, i64) {
        (self.limit.clamp(1, 1000), self.offset.max(0))
    }
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct Prefix {
    /// Only parameters with this path prefix (default: all).
    #[serde(default)]
    prefix: String,
}

/// Body of `POST /devices/{id}/tasks`: task kind + queue options.
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct CreateTask {
    /// Task: `kind` + `payload`, next to the queue options.
    #[serde(flatten)]
    #[schema(value_type = openapi::TaskSpec)]
    pub task: TaskKind,
    /// Higher runs first.
    #[serde(default)]
    pub priority: i16,
    /// Attempts before giving up (default 3).
    #[serde(default)]
    pub max_attempts: Option<i32>,
    /// Expire if not sent within this many seconds.
    #[serde(default)]
    pub expires_in_seconds: Option<i64>,
    /// Deduplicates retries of the same request.
    #[serde(default)]
    pub idempotency_key: Option<String>,
    /// Wake the device -> task runs now (default true).
    #[serde(default = "yes")]
    pub connection_request: bool,
}

fn yes() -> bool {
    true
}

/// Actor for the audit log: the caller (`auth::ACTOR`), else `system`.
fn actor(_s: &AppState) -> String {
    auth::ACTOR
        .try_with(Clone::clone)
        .unwrap_or_else(|_| "system".into())
}

pub(crate) async fn audit(
    s: &AppState,
    action: &str,
    target_type: &str,
    target_id: impl std::fmt::Display,
    detail: Value,
) {
    if let Err(e) = s
        .store
        .record_audit(
            s.config.tenant_id,
            &actor(s),
            action,
            target_type,
            Some(&target_id.to_string()),
            &detail,
        )
        .await
    {
        tracing::error!(error = %e, action, "failed to write audit record");
    }
}

fn audit_json(a: &AuditEntry) -> Value {
    json!({
        "id": a.id,
        "actor": a.actor,
        "action": a.action,
        "target_type": a.target_type,
        "target_id": a.target_id,
        "detail": a.detail,
        "occurred_at": ts(a.occurred_at),
    })
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct AuditQuery {
    /// Exactly this actor (username, `key:<name>`, `api-token`).
    #[serde(default)]
    actor: Option<String>,
    /// Actions starting with this, e.g. `device.` or `preset.save`.
    #[serde(default)]
    action: Option<String>,
    /// Exactly this target ID (device, job, user, ...).
    #[serde(default)]
    target: Option<String>,
    /// Only records older than this `id` (next page).
    #[serde(default)]
    before: Option<i64>,
    /// Only records at or after this time (RFC 3339).
    #[serde(default)]
    since: Option<String>,
    /// Maximum items, 1-1000 (default 100).
    #[serde(default = "default_limit")]
    limit: i64,
}

#[utoipa::path(
    get,
    path = "/api/v1/audit",
    tag = "audit",
    operation_id = "list_audit",
    summary = "Audit trail of changes",
    params(AuditQuery),
    responses(
        (status = 200, description = "Audit records, newest first; for the next page pass the last `id` as `before`", body = schemas::AuditList),
        (status = 400, description = "`since` is not an RFC 3339 time"),
    ),
)]
async fn list_audit(
    State(s): State<Arc<AppState>>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Value>, ApiError> {
    let blank = |v: Option<String>| v.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
    let since = blank(q.since)
        .map(|t| OffsetDateTime::parse(&t, &Rfc3339))
        .transpose()
        .map_err(|_| {
            ApiError(
                StatusCode::BAD_REQUEST,
                "since must be an RFC 3339 time".into(),
            )
        })?;
    let mut filter = dhonomos_store::AuditFilter {
        actor: blank(q.actor),
        action: blank(q.action),
        target_id: blank(q.target),
        before: q.before,
        since,
    };
    // Scoped caller -> own actions only (other entries may be about devices outside the scope).
    if auth::caller_scope()?.is_some() {
        filter.actor = auth::ACTOR.try_with(Clone::clone).ok();
    }
    let items = s
        .store
        .list_audit(s.config.tenant_id, &filter, q.limit.clamp(1, 1000))
        .await?;
    Ok(Json(
        json!({ "items": items.iter().map(audit_json).collect::<Vec<_>>() }),
    ))
}

async fn wake(s: &AppState, device: Uuid) -> String {
    match &s.config.waker {
        Some(w) => w.wake(device).await.describe(),
        None => "skipped: disabled".into(),
    }
}

/// Device of the tenant inside the caller's scope; else 404 (out-of-scope device not
/// revealed). Every route on one device goes through here (ADR-074).
async fn device_of(state: &AppState, id: Uuid) -> Result<Device, ApiError> {
    let scope = auth::caller_scope()?;
    state
        .store
        .get_device(id)
        .await?
        .filter(|d| d.tenant_id == state.config.tenant_id)
        .filter(|d| scope.as_ref().is_none_or(|s| s.matches(d)))
        .ok_or_else(|| not_found("device"))
}

/// Stored file a Download task sends, if it names one.
/// Unknown file -> left for dispatch to report, as before.
pub(crate) async fn download_file(
    s: &AppState,
    task: &dhonomos_core::TaskKind,
) -> Result<Option<dhonomos_store::StoredFile>, ApiError> {
    let dhonomos_core::TaskKind::Download {
        file_id: Some(file_id),
        ..
    } = task
    else {
        return Ok(None);
    };
    Ok(s.store
        .get_file(*file_id)
        .await?
        .filter(|f| f.tenant_id == s.config.tenant_id))
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct DeviceQuery {
    /// Case-insensitive substring of serial number, endpoint ID, model, software version,
    /// product class, OUI or address.
    #[serde(default)]
    q: Option<String>,
    /// `cwmp` or `usp`.
    #[serde(default)]
    protocol: Option<String>,
    /// `active`, `quarantined` or `retired`.
    #[serde(default)]
    status: Option<String>,
    /// Exact product class.
    #[serde(default)]
    product_class: Option<String>,
    /// Exact OUI.
    #[serde(default)]
    oui: Option<String>,
    /// Exact model name.
    #[serde(default)]
    model_name: Option<String>,
    /// Exact software version.
    #[serde(default)]
    software_version: Option<String>,
    /// Devices with this tag.
    #[serde(default)]
    tag: Option<String>,
    /// Exact attribute value, `key=value` (e.g. `subscriber=12345`).
    #[serde(default)]
    attr: Option<String>,
    /// Filter expression, e.g. `product_class = HG8245 and (tag = east or attr.region = busan)
    /// and last_contact > 1d` (see the device filter guide).
    #[serde(default)]
    filter: Option<String>,
    /// Page size, 1-1000 (default 100).
    #[serde(default = "default_limit")]
    limit: i64,
    /// Items to skip.
    #[serde(default)]
    offset: i64,
}

/// `GET /devices?q=&protocol=&status=&product_class=&oui=&model_name=&software_version=&tag=&limit=&offset=`
#[utoipa::path(
    get,
    path = "/api/v1/devices",
    tag = "devices",
    operation_id = "list_devices",
    summary = "Search devices",
    params(
        DeviceQuery,
    ),
    responses(
        (status = 200, description = "Matching devices", body = schemas::DevicePage),
    ),
)]
async fn list_devices(
    State(s): State<Arc<AppState>>,
    Query(q): Query<DeviceQuery>,
) -> Result<Json<Value>, ApiError> {
    let (limit, offset) = Page {
        limit: q.limit,
        offset: q.offset,
    }
    .clamp();
    let search = device_search(q)?;
    let (devices, total) = s
        .store
        .search_devices(s.config.tenant_id, &search, limit, offset)
        .await?;
    Ok(Json(json!({
        "items": devices.iter().map(|d| device_json(&s, d)).collect::<Vec<_>>(),
        "total": total,
        "limit": limit,
        "offset": offset,
    })))
}

/// `GET /devices/facets?<filters>` -> values the device list can be narrowed to.
#[utoipa::path(
    get,
    path = "/api/v1/devices/facets",
    tag = "devices",
    operation_id = "list_device_facets",
    summary = "Device list filter values",
    description = "Distinct OUIs, product classes and model names of the devices matching the same filters as `GET /devices`; each list ignores its own filter. Up to 500 most common values each, sorted by value.",
    params(
        DeviceQuery,
    ),
    responses(
        (status = 200, body = schemas::DeviceFacets),
        (status = 400, description = "Bad filter expression"),
    ),
)]
async fn list_device_facets(
    State(s): State<Arc<AppState>>,
    Query(q): Query<DeviceQuery>,
) -> Result<Json<Value>, ApiError> {
    let search = device_search(q)?;
    let facets = s.store.device_facets(s.config.tenant_id, &search).await?;
    Ok(Json(facets_json(&facets)))
}

/// Filter values of the device list as JSON; `manufacturer` only on OUIs that have one.
fn facets_json(f: &dhonomos_store::DeviceFacets) -> Value {
    let values = |list: &[dhonomos_store::FacetValue]| {
        list.iter()
            .map(|v| {
                let mut item = json!({ "value": v.value, "count": v.count });
                if let Some(m) = &v.manufacturer {
                    item["manufacturer"] = json!(m);
                }
                item
            })
            .collect::<Vec<_>>()
    };
    json!({
        "oui": values(&f.oui),
        "product_class": values(&f.product_class),
        "model_name": values(&f.model_name),
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/devices/{id}",
    tag = "devices",
    operation_id = "get_device",
    summary = "Device details",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 200, description = "The device", body = schemas::Device),
        (status = 404, description = "Unknown device"),
    ),
)]
async fn get_device(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(device_json(&s, &device_of(&s, id).await?)))
}

/// Body of `POST /devices`: `endpoint_id` (USP), or `oui` + `serial_number` (CWMP).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct Preregister {
    /// USP Agent endpoint ID, `<authority-scheme>::<instance-id>`.
    #[serde(default)]
    endpoint_id: Option<String>,
    /// CWMP manufacturer OUI.
    #[serde(default)]
    oui: String,
    /// CWMP product class.
    #[serde(default)]
    product_class: String,
    /// CWMP serial number.
    #[serde(default)]
    serial_number: String,
    /// Tags for the device.
    #[serde(default)]
    tags: Vec<String>,
    /// USP Agent with a WebSocket server -> `ws://`/`wss://` URL the Controller connects to
    /// (US-05).
    #[serde(default)]
    usp_ws_url: Option<String>,
}

/// `ws://` or `wss://` URL with a host.
fn valid_ws_url(url: &str) -> bool {
    url.parse::<axum::http::Uri>().is_ok_and(|u| {
        matches!(u.scheme_str(), Some("ws" | "wss")) && u.host().is_some_and(|h| !h.is_empty())
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/devices",
    tag = "devices",
    operation_id = "preregister_device",
    summary = "Pre-register a CWMP device or a USP Agent",
    description = "With `endpoint_id` a USP Agent (CO-12), otherwise a CWMP device by OUI, product class and serial number.",
    request_body = Preregister,
    responses(
        (status = 200, description = "Already known: the device", body = schemas::Device),
        (status = 201, description = "Pre-registered: the device", body = schemas::Device),
        (status = 422, description = "Invalid body: neither `oui` + `serial_number` nor a valid `endpoint_id`"),
    ),
)]
async fn preregister(
    State(s): State<Arc<AppState>>,
    body: Result<Json<Preregister>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let Json(req) = body.map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, e.body_text()))?;
    if let Some(eid) = req.endpoint_id.as_deref().map(str::trim) {
        if !enroll::valid_endpoint_id(eid) {
            return Err(ApiError(
                StatusCode::UNPROCESSABLE_ENTITY,
                enroll::ENDPOINT_ID_RULE.into(),
            ));
        }
        if let Some(url) = &req.usp_ws_url
            && !valid_ws_url(url)
        {
            return Err(ApiError(
                StatusCode::UNPROCESSABLE_ENTITY,
                "usp_ws_url must be a ws:// or wss:// URL".into(),
            ));
        }
        let out = s
            .store
            .preregister_usp_device(s.config.tenant_id, eid, &req.tags)
            .await?;
        if let Some(url) = &req.usp_ws_url {
            s.store
                .set_usp_ws_url(s.config.tenant_id, out.id, Some(url))
                .await?;
        }
        if out.created {
            audit(
                &s,
                "device.preregister",
                "device",
                out.id,
                json!({ "endpoint_id": eid }),
            )
            .await;
        }
        let d = device_of(&s, out.id).await?;
        let status = if out.created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        };
        return Ok((status, Json(device_json(&s, &d))));
    }
    if req.oui.trim().is_empty() || req.serial_number.trim().is_empty() {
        return Err(ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "oui and serial_number (CWMP) or endpoint_id (USP) are required".into(),
        ));
    }
    let identity = CwmpIdentity {
        oui: req.oui.trim().to_owned(),
        product_class: req.product_class.trim().to_owned(),
        serial_number: req.serial_number.trim().to_owned(),
    };
    let out = s
        .store
        .preregister_cwmp_device(s.config.tenant_id, &identity, &req.tags)
        .await?;
    if out.created {
        audit(
            &s,
            "device.preregister",
            "device",
            out.id,
            json!({ "oui": identity.oui, "serial_number": identity.serial_number }),
        )
        .await;
    }
    let d = device_of(&s, out.id).await?;
    let status = if out.created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(device_json(&s, &d))))
}

/// Body of `PATCH /devices/{id}`; fields left out -> unchanged.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct PatchDevice {
    /// `active`, `quarantined` or `retired`.
    #[serde(default)]
    status: Option<String>,
    /// All tags (replaces the current ones).
    #[serde(default)]
    tags: Option<Vec<String>>,
    /// Attribute changes (CO-13): string -> set key, `null` -> remove key; other keys stay.
    #[serde(default)]
    #[schema(value_type = Object)]
    attributes: Option<std::collections::BTreeMap<String, Option<String>>>,
    /// WebSocket server of the USP Agent for the Controller (US-05); `""` -> removed.
    #[serde(default)]
    usp_ws_url: Option<String>,
}

#[utoipa::path(
    patch,
    path = "/api/v1/devices/{id}",
    tag = "devices",
    operation_id = "update_device",
    summary = "Change a device's status, tags or attributes",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    request_body = PatchDevice,
    responses(
        (status = 200, description = "The updated device", body = schemas::Device),
        (status = 404, description = "Unknown device"),
        (status = 422, description = "Invalid body, status, tag or attribute"),
        (status = 502, description = "Status saved, but the USP Agent's broker account could not be updated"),
    ),
)]
async fn patch_device(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    body: Result<Json<PatchDevice>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(req) = body.map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, e.body_text()))?;
    let invalid = |m: String| ApiError(StatusCode::UNPROCESSABLE_ENTITY, m);
    if let Some(status) = &req.status
        && !matches!(status.as_str(), "active" | "quarantined" | "retired")
    {
        return Err(invalid(
            "status must be active, quarantined or retired".into(),
        ));
    }
    if let Some(url) = req.usp_ws_url.as_deref().filter(|u| !u.is_empty())
        && !valid_ws_url(url)
    {
        return Err(invalid("usp_ws_url must be a ws:// or wss:// URL".into()));
    }
    let tags = req.tags.as_deref().map(clean_tags).transpose()?;
    let before = device_of(&s, id).await?;
    let attributes = match &req.attributes {
        Some(changes) => {
            if let Some(k) = changes.keys().find(|k| !valid_attribute_key(k)) {
                return Err(invalid(format!(
                    "attribute key {k:?}: letters, digits, _ - . and at most 64 characters"
                )));
            }
            if changes
                .values()
                .flatten()
                .any(|v| v.len() > MAX_ATTRIBUTE_VALUE)
            {
                return Err(invalid(format!(
                    "attribute values are at most {MAX_ATTRIBUTE_VALUE} characters"
                )));
            }
            let mut keys: std::collections::BTreeSet<&str> = before
                .attributes
                .as_object()
                .map(|o| o.keys().map(String::as_str).collect())
                .unwrap_or_default();
            for (k, v) in changes {
                if v.is_some() {
                    keys.insert(k);
                } else {
                    keys.remove(k.as_str());
                }
            }
            if keys.len() > MAX_ATTRIBUTES {
                return Err(invalid(format!(
                    "a device has at most {MAX_ATTRIBUTES} attributes"
                )));
            }
            Some(json!(changes))
        }
        None => None,
    };
    if req.usp_ws_url.is_some() && before.protocol != "usp" {
        return Err(invalid("usp_ws_url is for USP devices".into()));
    }
    // Device must stay inside the caller's scope: no moving it out.
    if let Some(scope) = auth::caller_scope()? {
        let mut after = before.clone();
        if let Some(t) = &tags {
            after.tags.clone_from(t);
        }
        if let (Some(changes), Some(obj)) = (&req.attributes, after.attributes.as_object_mut()) {
            for (k, v) in changes {
                match v {
                    Some(v) => obj.insert(k.clone(), json!(v)),
                    None => obj.remove(k),
                };
            }
        }
        if !scope.matches(&after) {
            return Err(invalid(
                "the change would move the device out of your scope".into(),
            ));
        }
    }
    if let Some(status) = &req.status {
        s.store
            .set_device_status(s.config.tenant_id, id, status)
            .await?;
    }
    if tags.is_some() || attributes.is_some() {
        s.store
            .update_device(s.config.tenant_id, id, tags.as_deref(), attributes.as_ref())
            .await?;
    }
    if let Some(url) = &req.usp_ws_url {
        s.store
            .set_usp_ws_url(
                s.config.tenant_id,
                id,
                Some(url.as_str()).filter(|u| !u.is_empty()),
            )
            .await?;
    }
    let status = req
        .status
        .as_ref()
        .map(|to| json!({ "from": before.status, "to": to }));
    // Status-only change -> own, more telling action.
    let (action, detail) = if tags.is_none() && attributes.is_none() && req.usp_ws_url.is_none() {
        ("device.status", status.unwrap_or_default())
    } else {
        (
            "device.update",
            json!({ "status": status, "tags": tags, "attributes": req.attributes,
                    "usp_ws_url": req.usp_ws_url }),
        )
    };
    audit(&s, action, "device", id, detail).await;
    let after = device_of(&s, id).await?;
    if req.status.is_some()
        && let Some(broker) = &s.config.broker
        && let Err(e) = broker.apply_status(&s.store, &after).await
    {
        tracing::error!(device = %id, error = %e, "updating the broker account failed");
        return Err(ApiError(
            StatusCode::BAD_GATEWAY,
            format!("status saved, but the broker account could not be updated: {e}"),
        ));
    }
    Ok(Json(device_json(&s, &after)))
}

fn broker_of(s: &AppState) -> Result<&BrokerAccess, ApiError> {
    s.config.broker.as_ref().ok_or_else(|| {
        ApiError(
            StatusCode::NOT_FOUND,
            "broker account management is not enabled (--usp-dynsec)".into(),
        )
    })
}

fn broker_error(e: dhonomos_core::BrokerError) -> ApiError {
    match e {
        dhonomos_core::BrokerError::NotUsp => {
            ApiError(StatusCode::UNPROCESSABLE_ENTITY, e.to_string())
        }
        dhonomos_core::BrokerError::Broker(_) => ApiError(StatusCode::BAD_GATEWAY, e.to_string()),
        _ => {
            tracing::error!(error = %e, "broker account operation failed");
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "broker account operation failed".into(),
            )
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/devices/{id}/mqtt-credentials",
    tag = "devices",
    operation_id = "issue_mqtt_credentials",
    summary = "Issue (rotate) a USP Agent's broker account",
    description = "US-17.",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 201, description = "The account; the password is shown once", body = schemas::MqttCredentials),
        (status = 404, description = "Unknown device, or broker account management is disabled (`--usp-dynsec`)"),
        (status = 422, description = "Not a USP device"),
        (status = 500, description = "The broker account could not be prepared"),
        (status = 502, description = "The broker rejected the change"),
    ),
)]
async fn issue_mqtt_credentials(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let broker = broker_of(&s)?;
    let device = device_of(&s, id).await?;
    let issued = broker
        .issue(&s.store, &device)
        .await
        .map_err(broker_error)?;
    audit(
        &s,
        "device.mqtt.issue",
        "device",
        id,
        json!({ "username": issued.username }),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "username": issued.username,
            "password": issued.password,
            "agent_topic": issued.agent_topic,
            "controller_topic": issued.controller_topic,
            "enabled": device.status == "active",
        })),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/devices/{id}/mqtt-credentials",
    tag = "devices",
    operation_id = "revoke_mqtt_credentials",
    summary = "Revoke a USP Agent's broker account",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 204, description = "Revoked"),
        (status = 404, description = "Unknown device, no broker account, or broker account management is disabled"),
        (status = 422, description = "Not a USP device"),
        (status = 500, description = "The broker account could not be removed"),
        (status = 502, description = "The broker rejected the change"),
    ),
)]
async fn revoke_mqtt_credentials(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let broker = broker_of(&s)?;
    let device = device_of(&s, id).await?;
    if !broker
        .revoke(&s.store, &device)
        .await
        .map_err(broker_error)?
    {
        return Err(not_found("broker account"));
    }
    audit(&s, "device.mqtt.revoke", "device", id, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Body of `PUT /devices/{id}/credentials/{kind}`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct PutCredential {
    username: String,
    /// Stored encrypted; never returned.
    password: String,
}

fn credential_kind(kind: &str) -> Result<&str, ApiError> {
    match kind {
        "acs_auth" | "connection_request" => Ok(kind),
        _ => Err(ApiError(
            StatusCode::NOT_FOUND,
            "credential kind must be acs_auth or connection_request".into(),
        )),
    }
}

/// [`credential_kind`] + `xmpp` (device login to the built-in XMPP server, ADR-104).
/// `xmpp`: remove only. Dhonomos makes the password, user name = device ID.
/// Removed -> zero-touch issues a new one at the next trigger.
fn removable_credential_kind(kind: &str) -> Result<&str, ApiError> {
    match kind {
        "xmpp" => Ok(kind),
        _ => credential_kind(kind).map_err(|_| {
            ApiError(
                StatusCode::NOT_FOUND,
                "credential kind must be acs_auth, connection_request or xmpp".into(),
            )
        }),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/devices/{id}/credentials",
    tag = "devices",
    operation_id = "list_credentials",
    summary = "Credential kinds and usernames (no secrets)",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 200, description = "The credentials", body = schemas::CredentialList),
        (status = 404, description = "Unknown device"),
    ),
)]
async fn list_credentials(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    device_of(&s, id).await?;
    let items: Vec<Value> = s
        .store
        .list_credentials(id)
        .await?
        .into_iter()
        .map(|(kind, username)| json!({ "kind": kind, "username": username }))
        .collect();
    Ok(Json(json!({ "items": items })))
}

#[utoipa::path(
    put,
    path = "/api/v1/devices/{id}/credentials/{kind}",
    tag = "devices",
    operation_id = "put_credential",
    summary = "Set a device credential",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
        ("kind" = String, Path, description = "`acs_auth` or `connection_request`"),
    ),
    request_body = PutCredential,
    responses(
        (status = 204, description = "Stored (password encrypted)"),
        (status = 404, description = "Unknown device or credential kind"),
        (status = 422, description = "Invalid body, empty username or password, or no `--secrets-key`"),
        (status = 500, description = "The password could not be encrypted"),
    ),
)]
async fn put_credential(
    State(s): State<Arc<AppState>>,
    Path((id, kind)): Path<(Uuid, String)>,
    body: Result<Json<PutCredential>, axum::extract::rejection::JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let kind = credential_kind(&kind)?;
    let Json(req) = body.map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, e.body_text()))?;
    device_of(&s, id).await?;
    let secrets = s.config.secrets.as_ref().ok_or_else(|| {
        ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "storing credentials requires the server to run with --secrets-key".into(),
        )
    })?;
    if req.username.is_empty() || req.password.is_empty() {
        return Err(ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "username and password are required".into(),
        ));
    }
    let (ciphertext, nonce) = secrets
        .seal_credential(id, req.password.as_bytes())
        .map_err(|e| {
            tracing::error!(error = %e, "sealing credential failed");
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not protect the password".into(),
            )
        })?;
    s.store
        .put_credential(&dhonomos_store::SealedCredential {
            device_id: id,
            kind: kind.to_owned(),
            username: req.username.clone(),
            ciphertext,
            nonce,
            key_id: secrets.key_id().to_owned(),
        })
        .await?;
    audit(
        &s,
        "device.credential.set",
        "device",
        id,
        json!({ "kind": kind, "username": req.username }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/api/v1/devices/{id}/credentials/{kind}",
    tag = "devices",
    operation_id = "delete_credential",
    summary = "Remove a device credential",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
        ("kind" = String, Path, description = "`acs_auth`, `connection_request` or `xmpp`"),
    ),
    responses(
        (status = 204, description = "Removed"),
        (status = 404, description = "Unknown device, credential kind, or no such credential"),
    ),
)]
async fn delete_credential(
    State(s): State<Arc<AppState>>,
    Path((id, kind)): Path<(Uuid, String)>,
) -> Result<StatusCode, ApiError> {
    let kind = removable_credential_kind(&kind)?;
    device_of(&s, id).await?;
    if !s.store.delete_credential(id, kind).await? {
        return Err(not_found("credential"));
    }
    audit(
        &s,
        "device.credential.delete",
        "device",
        id,
        json!({ "kind": kind }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/devices/{id}/parameters",
    tag = "devices",
    operation_id = "get_parameters",
    summary = "Parameter snapshot",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
        Prefix,
    ),
    responses(
        (status = 200, description = "The parameters", body = schemas::ParameterList),
        (status = 404, description = "Unknown device"),
    ),
)]
async fn get_parameters(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Query(q): Query<Prefix>,
) -> Result<Json<Value>, ApiError> {
    device_of(&s, id).await?;
    let params = s.store.get_params(id, &q.prefix).await?;
    Ok(Json(
        json!({ "items": params.iter().map(param_json).collect::<Vec<_>>() }),
    ))
}

/// Body of `POST /devices/{id}/certificate`.
#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
struct IssueCertificate {
    /// PEM CSR; none -> Dhonomos makes the key, returns it once.
    #[serde(default)]
    csr: Option<String>,
    /// Validity in days, 1-3650 (default 1095).
    #[serde(default)]
    days: Option<u32>,
}

#[utoipa::path(
    post,
    path = "/api/v1/devices/{id}/certificate",
    tag = "devices",
    operation_id = "issue_certificate",
    summary = "Issue a USP Agent certificate",
    description = "From the Agent's CSR, or with a key Dhonomos generates (US-08); then the response also holds `client_pem`, the certificate followed by the key (what `obuspa -a` reads). Valid for 1095 days unless `days` says otherwise. The body is optional.",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    request_body = Option<IssueCertificate>,
    responses(
        (status = 201, description = "The certificate", body = schemas::IssuedCertificate),
        (status = 404, description = "Unknown device, or certificate issuance is disabled (`--usp-ca-dir`)"),
        (status = 422, description = "Not a USP device, `days` out of range, or an unusable CSR"),
    ),
)]
async fn issue_certificate(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    body: Option<Json<IssueCertificate>>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let ca = s.config.ca.as_ref().ok_or_else(|| {
        ApiError(
            StatusCode::NOT_FOUND,
            "certificate issuance is not enabled (--usp-ca-dir)".into(),
        )
    })?;
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let device = device_of(&s, id).await?;
    let Some(eid) = device
        .endpoint_id
        .as_deref()
        .filter(|_| device.protocol == "usp")
    else {
        return Err(ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "certificates are only issued to USP devices".into(),
        ));
    };
    let days = bundle::check_days(req.days)?;
    let profile = dhonomos_pki::Profile {
        endpoint_id: eid.to_owned(),
        days,
        ..dhonomos_pki::Profile::default()
    };
    let issued = match &req.csr {
        Some(csr) => ca.issue_from_csr(csr, &profile),
        None => ca.issue(&profile),
    }
    .map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    s.store
        .record_certificate(
            s.config.tenant_id,
            id,
            &issued.serial,
            &issued.sha256,
            issued.not_after,
            req.csr.is_some(),
            Some(&actor(&s)),
        )
        .await?;
    metrics::counter!("dhonomos_usp_certificates_issued_total", "via" => "single").increment(1);
    audit(
        &s,
        "device.certificate.issue",
        "device",
        id,
        json!({ "serial": issued.serial, "sha256": issued.sha256, "csr": req.csr.is_some(),
                "not_after": ts(issued.not_after) }),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "certificate": issued.cert_pem,
            "private_key": issued.key_pem,
            "client_pem": issued.key_pem.as_deref()
                .map(|key| bundle::client_pem(&issued.cert_pem, key).as_str().to_owned()),
            "ca_certificate": ca.cert_pem(),
            "serial": issued.serial,
            "sha256": issued.sha256,
            "not_after": ts(issued.not_after),
        })),
    ))
}

pub(crate) fn certificate_json(c: &dhonomos_store::AgentCertificate) -> Value {
    let state = if c.revoked_at.is_some() {
        "revoked"
    } else if c.not_after <= OffsetDateTime::now_utc() {
        "expired"
    } else {
        "valid"
    };
    json!({
        "id": c.id,
        "device_id": c.device_id,
        "serial": c.serial,
        "sha256": c.fingerprint,
        "not_after": ts(c.not_after),
        "from_csr": c.from_csr,
        "issued_by": c.issued_by,
        "issued_at": ts(c.issued_at),
        "state": state,
        "revoked_at": c.revoked_at.map(ts),
        "revoked_by": c.revoked_by,
        "revoke_reason": c.revoke_reason,
        "device": null,
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/devices/{id}/certificates",
    tag = "devices",
    operation_id = "list_certificates",
    summary = "Certificates issued to a USP Agent",
    description = "US-08/US-18. Newest first; private keys are never stored.",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 200, description = "The certificates", body = schemas::CertificateList),
        (status = 404, description = "Unknown device"),
    ),
)]
async fn list_certificates(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    device_of(&s, id).await?;
    let items: Vec<Value> = s
        .store
        .device_certificates(id)
        .await?
        .iter()
        .map(certificate_json)
        .collect();
    Ok(Json(json!({ "items": items })))
}

/// Body of `POST /devices/{id}/certificates/{cert}/revoke`.
#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct Revoke {
    /// Why, for the record (e.g. "device stolen").
    #[serde(default)]
    reason: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/devices/{id}/certificates/{cert}/revoke",
    tag = "devices",
    operation_id = "revoke_certificate",
    summary = "Revoke an Agent certificate",
    description = "US-08/US-18. The WebSocket MTP refuses it from then on and closes connections made with it (within 10 seconds on every process).",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
        ("cert" = Uuid, Path, description = "Certificate ID"),
    ),
    request_body = Option<Revoke>,
    responses(
        (status = 200, description = "The revoked certificate", body = schemas::AgentCertificate),
        (status = 404, description = "Unknown device or certificate"),
    ),
)]
async fn revoke_certificate(
    State(s): State<Arc<AppState>>,
    Path((id, cert)): Path<(Uuid, Uuid)>,
    body: Option<Json<Revoke>>,
) -> Result<Json<Value>, ApiError> {
    device_of(&s, id).await?;
    let reason = body
        .and_then(|Json(b)| b.reason)
        .filter(|r| !r.trim().is_empty());
    let c = s
        .store
        .revoke_certificate(id, cert, Some(&actor(&s)), reason.as_deref())
        .await?
        .ok_or_else(|| not_found("certificate"))?;
    audit(
        &s,
        "device.certificate.revoke",
        "device",
        id,
        json!({ "serial": c.serial, "sha256": c.fingerprint, "reason": reason }),
    )
    .await;
    Ok(Json(certificate_json(&c)))
}

/// Body of `POST /certificates/revoke`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct RevokeFingerprint {
    /// SHA-256 fingerprint of the DER cert: 64 hex digits, any case (colons between bytes,
    /// as `openssl x509 -fingerprint` prints them, accepted).
    sha256: String,
    /// EndpointID the cert was issued for, kept with the record (max 256 bytes).
    #[serde(default)]
    endpoint_id: Option<String>,
    /// Why, for the record (e.g. "device deleted without revoking").
    #[serde(default)]
    reason: Option<String>,
}

/// Max reason size for a revocation by fingerprint.
const MAX_REASON_BYTES: usize = 1024;

/// Cert fingerprint as stored in DB: 64 lowercase hex digits.
fn normalize_fingerprint(text: &str) -> Option<String> {
    let hex: String = text
        .trim()
        .chars()
        .filter(|c| *c != ':')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then_some(hex)
}

#[utoipa::path(
    post,
    path = "/api/v1/certificates/revoke",
    tag = "devices",
    operation_id = "revoke_certificate_by_fingerprint",
    summary = "Revoke an Agent certificate by its fingerprint",
    description = "For a certificate no device record leads to any more: its device was deleted without revoking it, or its record was lost (the fingerprints of issued certificates are in the `certificate.bundle` and `device.certificate.issue` audit records). A certificate Dhonomos has a record of is revoked; otherwise a revoked record is made (without a device, serial number or expiry, which stays in the revoked set until it is removed), so the MTPs refuse that fingerprint from now on, within 10 seconds on every process. Revoking again keeps the first revocation. Needs an admin without a device scope.",
    request_body = RevokeFingerprint,
    responses(
        (status = 200, description = "The revoked certificate; `known` tells whether Dhonomos already had a record of it", body = schemas::CertificateRevocation),
        (status = 422, description = "`sha256` is not 64 hex digits, or `endpoint_id` or `reason` is unusable"),
    ),
)]
async fn revoke_certificate_by_fingerprint(
    State(s): State<Arc<AppState>>,
    body: Result<Json<RevokeFingerprint>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(req) = body.map_err(|e| ApiError(e.status(), e.body_text()))?;
    let unprocessable = |message: &str| ApiError(StatusCode::UNPROCESSABLE_ENTITY, message.into());
    let sha256 = normalize_fingerprint(&req.sha256)
        .ok_or_else(|| unprocessable("sha256 must be 64 hexadecimal digits"))?;
    let endpoint_id = req
        .endpoint_id
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty());
    if endpoint_id
        .is_some_and(|e| e.len() > bundle::MAX_EID_BYTES || e.chars().any(char::is_control))
    {
        return Err(unprocessable(
            "endpoint_id must be at most 256 bytes without control characters",
        ));
    }
    let reason = req
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty());
    if reason.is_some_and(|r| r.len() > MAX_REASON_BYTES) {
        return Err(unprocessable("reason must be at most 1024 bytes"));
    }
    let c = s
        .store
        .revoke_fingerprint(
            s.config.tenant_id,
            &sha256,
            endpoint_id,
            Some(&actor(&s)),
            reason,
        )
        .await?;
    audit(
        &s,
        "certificate.revoke",
        "certificate",
        c.id,
        json!({ "sha256": c.fingerprint, "endpoint_id": c.endpoint_id, "device_id": c.device_id,
                "serial": c.serial, "reason": reason, "known": c.known }),
    )
    .await;
    Ok(Json(revocation_json(&c)))
}

pub(crate) fn revocation_json(c: &dhonomos_store::FingerprintRevocation) -> Value {
    json!({
        "id": c.id,
        "sha256": c.fingerprint,
        "endpoint_id": c.endpoint_id,
        "device_id": c.device_id,
        "serial": c.serial,
        "not_after": c.not_after.map(ts),
        "revoked_at": ts(c.revoked_at),
        "revoked_by": c.revoked_by,
        "revoke_reason": c.revoke_reason,
        "known": c.known,
    })
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ExpiringQuery {
    /// Expiring within this many days (default 30, max 3650).
    #[serde(default = "thirty")]
    days: i32,
}

fn thirty() -> i32 {
    30
}

#[utoipa::path(
    get,
    path = "/api/v1/certificates/expiring",
    tag = "devices",
    operation_id = "expiring_certificates",
    summary = "Agent certificates about to expire",
    description = "US-18. Live certificates expiring soon, unless the device already has a newer one; soonest first (up to 1,000).",
    params(ExpiringQuery),
    responses(
        (status = 200, description = "The certificates with their device", body = schemas::CertificateList),
    ),
)]
async fn expiring_certificates(
    State(s): State<Arc<AppState>>,
    Query(q): Query<ExpiringQuery>,
) -> Result<Json<Value>, ApiError> {
    let scope = auth::caller_scope()?;
    let certs = s
        .store
        .expiring_certificates(
            s.config.tenant_id,
            q.days.clamp(1, 3650),
            scope.as_deref(),
            1000,
        )
        .await?;
    let ids: Vec<Uuid> = certs.iter().map(|c| c.device_id).collect();
    let labels = s.store.device_labels(&ids).await?;
    let items: Vec<Value> = certs
        .iter()
        .map(|c| {
            let mut v = certificate_json(c);
            v["device"] = json!(labels.get(&c.device_id));
            v
        })
        .collect();
    Ok(Json(json!({ "items": items })))
}

#[utoipa::path(
    get,
    path = "/api/v1/devices/{id}/supported-model",
    tag = "devices",
    operation_id = "get_supported_model",
    summary = "Supported data model of the device's firmware",
    description = "US-11.",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 200, description = "The supported data model of the device's firmware", body = schemas::SupportedModel),
        (status = 404, description = "Unknown device, or no supported model learned yet"),
    ),
)]
async fn get_supported_model(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    device_of(&s, id).await?;
    let m = s
        .store
        .device_supported_model(id)
        .await?
        .ok_or_else(|| not_found("supported model"))?;
    Ok(Json(supported_model_json(m)))
}

#[utoipa::path(
    post,
    path = "/api/v1/devices/{id}/data-model/refresh",
    tag = "devices",
    operation_id = "refresh_data_model",
    summary = "Read a USP Agent's supported data model again",
    description = "Discards the supported data model cached for the Agent's firmware (and the \
        Agent's own copy) and reads it again with GetSupportedDM (US-11). Use it when the \
        cached model is stale, e.g. after a firmware update that kept its software version. \
        If the Agent is connected the model is read now, in the background (`refreshing`). \
        Otherwise the cached model is deleted now and the Agent's next connection reads it \
        (`queued`); other devices of the same firmware are without a model until they \
        connect. Parameters already stored keep their writability until they are read again.",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 202, description = "Accepted: `refreshing` (Agent connected) or `queued` (Agent offline)", body = schemas::DataModelRefreshOutcome),
        (status = 404, description = "Unknown device"),
        (status = 422, description = "The device does not use USP"),
    ),
)]
async fn refresh_data_model(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let device = device_of(&s, id).await?;
    if device.protocol != "usp" {
        return Err(ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "only USP Agents have a supported data model to refresh".into(),
        ));
    }
    let outcome = match &s.config.usp {
        Some(usp) => usp.refresh_data_model(&device).await?,
        None => {
            dhonomos_core::usp::discard_supported_model(&s.store, &device).await?;
            DataModelRefresh::Queued
        }
    };
    let status = match outcome {
        DataModelRefresh::Refreshing => "refreshing",
        DataModelRefresh::Queued => "queued",
    };
    audit(
        &s,
        "device.data_model.refresh",
        "device",
        id,
        json!({ "status": status }),
    )
    .await;
    Ok((StatusCode::ACCEPTED, Json(json!({ "status": status }))))
}

/// Stored model document + fingerprint, protocol, learning time.
pub(crate) fn supported_model_json(m: dhonomos_store::SupportedModel) -> Value {
    let mut doc = m.model;
    if let Some(o) = doc.as_object_mut() {
        o.insert("fingerprint".into(), json!(m.fingerprint));
        o.insert("protocol".into(), json!(m.protocol));
        o.insert("learned_at".into(), json!(ts(m.created_at)));
    }
    doc
}

#[utoipa::path(
    get,
    path = "/api/v1/devices/{id}/events",
    tag = "devices",
    operation_id = "get_events",
    summary = "Device events",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
        ("limit" = Option<i64>, Query, description = "Maximum items, 1-1000 (default 100)"),
    ),
    responses(
        (status = 200, description = "The events, newest first", body = schemas::EventList),
        (status = 404, description = "Unknown device"),
    ),
)]
async fn get_events(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Query(page): Query<Page>,
) -> Result<Json<Value>, ApiError> {
    device_of(&s, id).await?;
    let events = s.store.list_events(id, page.clamp().0).await?;
    Ok(Json(
        json!({ "items": events.iter().map(event_json).collect::<Vec<_>>() }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/devices/{id}/tasks",
    tag = "tasks",
    operation_id = "list_device_tasks",
    summary = "A device's tasks",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
        ("limit" = Option<i64>, Query, description = "Maximum items, 1-1000 (default 100)"),
    ),
    responses(
        (status = 200, description = "Newest first", body = schemas::TaskList),
        (status = 404, description = "Unknown device"),
    ),
)]
async fn get_device_tasks(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Query(page): Query<Page>,
) -> Result<Json<Value>, ApiError> {
    device_of(&s, id).await?;
    let tasks = s.store.list_tasks(id, page.clamp().0).await?;
    Ok(Json(
        json!({ "items": tasks.iter().map(task_json).collect::<Vec<_>>() }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/devices/{id}/tasks",
    tag = "tasks",
    operation_id = "create_task",
    summary = "Queue a task (and wake the device)",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    request_body = CreateTask,
    responses(
        (status = 200, description = "A task with the same `idempotency_key` exists: that task", body = schemas::QueuedTask),
        (status = 201, description = "Queued", body = schemas::QueuedTask),
        (status = 404, description = "Unknown device"),
        (status = 422, description = "Invalid body or task, a task the device's protocol cannot run, a secret value starting with `enc:`, a download of a file another device uploaded, or a password without `--secrets-key`"),
        (status = 500, description = "The password could not be encrypted"),
    ),
)]
async fn create_task(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    body: Result<Json<CreateTask>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let Json(req) = body.map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, e.body_text()))?;
    let device = device_of(&s, id).await?;
    req.task
        .validate()
        .map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    if device.protocol == "cwmp"
        && let Err(e) = req
            .task
            .to_cwmp_in("", device.data_model.as_deref().unwrap_or("Device"))
    {
        return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, e));
    }
    if req.max_attempts.is_some_and(|m| m < 1) {
        return Err(ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "max_attempts must be at least 1".into(),
        ));
    }
    let (kind, mut payload) = req.task.to_row();
    dhonomos_core::secrets::reject_ciphertext_input(&payload)
        .map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    if let Some(file) = download_file(&s, &req.task).await?
        && file.device_id.is_some_and(|owner| owner != id)
    {
        return Err(ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            dhonomos_core::files::not_for_other_devices(file.id),
        ));
    }
    // Secrets bound to the task -> ID chosen before sealing.
    let task_id = Uuid::now_v7();
    if dhonomos_core::secrets::has_plain_secret(&payload) {
        let secrets = s.config.secrets.as_ref().ok_or_else(|| {
            ApiError(
                StatusCode::UNPROCESSABLE_ENTITY,
                "storing passwords requires the server to run with --secrets-key".into(),
            )
        })?;
        secrets
            .encrypt_fields(&mut payload, &dhonomos_core::secrets::task_context(task_id))
            .map_err(|e| {
                tracing::error!(error = %e, "encrypting task secrets failed");
                ApiError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not protect the password".into(),
                )
            })?;
    }
    let task = NewTask {
        priority: req.priority,
        max_attempts: req.max_attempts.unwrap_or(3),
        idempotency_key: req.idempotency_key,
        expires_at: req
            .expires_in_seconds
            .map(|s| OffsetDateTime::now_utc() + time::Duration::seconds(s)),
        created_by: Some("api".into()),
        ..NewTask::new(s.config.tenant_id, id, kind, payload)
    };
    let (task_id, created) = s.store.enqueue_task_with_id(task_id, &task).await?;
    let t = s
        .store
        .get_task(task_id)
        .await?
        .ok_or_else(|| not_found("task"))?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    if created {
        audit(
            &s,
            "task.create",
            "device",
            id,
            json!({ "task_id": t.id, "kind": t.kind, "payload": redact_task(&t.kind, &t.payload) }),
        )
        .await;
    }
    let mut body = task_json(&t);
    if req.connection_request {
        body["connection_request"] = json!(wake(&s, id).await);
    }
    Ok((status, Json(body)))
}

#[utoipa::path(
    post,
    path = "/api/v1/devices/{id}/connection-request",
    tag = "devices",
    operation_id = "connection_request",
    summary = "Wake the device",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 200, description = "The outcome", body = schemas::ConnectionRequestOutcome),
        (status = 404, description = "Unknown device"),
    ),
)]
async fn connection_request(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    device_of(&s, id).await?;
    let outcome = wake(&s, id).await;
    audit(
        &s,
        "device.connection_request",
        "device",
        id,
        json!({ "outcome": outcome }),
    )
    .await;
    Ok(Json(json!({ "connection_request": outcome })))
}

async fn metrics(State(s): State<Arc<AppState>>) -> Response {
    match &s.config.metrics {
        Some(h) => (
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            h.render(),
        )
            .into_response(),
        None => ApiError(StatusCode::NOT_FOUND, "metrics are disabled".into()).into_response(),
    }
}

async fn task_in_tenant(s: &AppState, id: Uuid) -> Result<Task, ApiError> {
    let t = s
        .store
        .get_task(id)
        .await?
        .ok_or_else(|| not_found("task"))?;
    device_of(s, t.device_id)
        .await
        .map_err(|_| not_found("task"))?;
    Ok(t)
}

#[utoipa::path(
    get,
    path = "/api/v1/tasks/{id}",
    tag = "tasks",
    operation_id = "get_task",
    summary = "Task details",
    params(
        ("id" = Uuid, Path, description = "Task ID"),
    ),
    responses(
        (status = 200, description = "The task", body = schemas::Task),
        (status = 404, description = "Unknown task"),
    ),
)]
async fn get_task(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(task_json(&task_in_tenant(&s, id).await?)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/tasks/{id}",
    tag = "tasks",
    operation_id = "cancel_task",
    summary = "Cancel a pending task",
    params(
        ("id" = Uuid, Path, description = "Task ID"),
    ),
    responses(
        (status = 204, description = "Cancelled"),
        (status = 404, description = "Unknown task"),
        (status = 409, description = "The task is no longer pending"),
    ),
)]
async fn cancel_task(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let t = task_in_tenant(&s, id).await?;
    if t.state != TaskState::Pending || !s.store.cancel_task(id).await? {
        return Err(ApiError(
            StatusCode::CONFLICT,
            format!(
                "only pending tasks can be cancelled (state: {})",
                t.state.as_str()
            ),
        ));
    }
    audit(
        &s,
        "task.cancel",
        "task",
        id,
        json!({ "device_id": t.device_id, "kind": t.kind }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// One span per API request, named by its route (OP-01).
async fn trace_request(req: axum::extract::Request, next: middleware::Next) -> Response {
    use tracing::Instrument as _;
    let route = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map_or_else(|| req.uri().path().to_owned(), |p| p.as_str().to_owned());
    let span = tracing::info_span!(
        "api.request",
        method = %req.method(),
        route = %route,
        status = tracing::field::Empty
    );
    async move {
        let resp = next.run(req).await;
        tracing::Span::current().record("status", resp.status().as_u16());
        resp
    }
    .instrument(span)
    .await
}

pub fn router(store: Store, config: ApiConfig) -> Router {
    let state = Arc::new(AppState {
        store,
        users_exist: std::sync::atomic::AtomicBool::new(false),
        login_attempts: auth::attempts::Attempts::new(auth::attempts::MAX_ENTRIES),
        totp_attempts: auth::attempts::Attempts::new(auth::attempts::MAX_ENTRIES),
        hints: client::Hints::default(),
        oidc: config.oidc.clone().map(oidc::Oidc::new),
        limiter: ratelimit::RateLimiter::live(config.rate_limit.clone(), 4),
        public_limiter: auth::public_limiter(),
        hashing: Arc::new(tokio::sync::Semaphore::new(auth::hash_slots())),
        wg_history: wg_history::TunnelHistory::default(),
        config,
    });
    let api = Router::new()
        .route("/devices", get(list_devices).post(preregister))
        .route("/devices/facets", get(list_device_facets))
        .route(
            "/devices/{id}",
            get(get_device)
                .patch(patch_device)
                .delete(lifecycle::delete_device),
        )
        .route("/devices/{id}/parameters", get(get_parameters))
        .route("/devices/{id}/credentials", get(list_credentials))
        .route(
            "/devices/{id}/credentials/{kind}",
            axum::routing::put(put_credential).delete(delete_credential),
        )
        .route(
            "/devices/{id}/mqtt-credentials",
            axum::routing::post(issue_mqtt_credentials).delete(revoke_mqtt_credentials),
        )
        .route("/devices/{id}/supported-model", get(get_supported_model))
        .route(
            "/devices/{id}/data-model/refresh",
            axum::routing::post(refresh_data_model),
        )
        .route(
            "/devices/{id}/certificate",
            axum::routing::post(issue_certificate),
        )
        .route("/devices/{id}/certificates", get(list_certificates))
        .route(
            "/devices/{id}/certificates/{cert}/revoke",
            axum::routing::post(revoke_certificate),
        )
        .route("/certificates/expiring", get(expiring_certificates))
        .route(
            "/certificates/revoke",
            axum::routing::post(revoke_certificate_by_fingerprint),
        )
        .route("/devices/{id}/events", get(get_events))
        .route(
            "/devices/{id}/tasks",
            get(get_device_tasks).post(create_task),
        )
        .route(
            "/devices/{id}/connection-request",
            axum::routing::post(connection_request),
        )
        .route("/tasks/{id}", get(get_task).delete(cancel_task))
        .route("/audit", get(list_audit))
        .route(
            "/files",
            get(files::list)
                .put(files::upload)
                .layer(files::upload_limit()),
        )
        .route("/files/{id}", axum::routing::delete(files::delete))
        .route("/files/{id}/content", get(files::content))
        .merge(bundle::routes())
        .merge(enroll::routes())
        .merge(jobs::routes())
        .merge(presets::routes())
        .merge(series::routes())
        .merge(lifecycle::routes())
        .merge(alarms::routes())
        .merge(export::routes())
        .merge(import::routes())
        .merge(stream::routes())
        .merge(wireguard::routes())
        .merge(auth::routes())
        .merge(settings::routes())
        .merge(alarm_rules::routes())
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::authenticate,
        ))
        .route_layer(middleware::from_fn(trace_request))
        .merge(auth::public_routes(state.clone()))
        .merge(wg_hub::hub_routes(state.clone()))
        .with_state(state.clone());
    let metrics_route = Router::new()
        .route("/metrics", get(metrics))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::authenticate,
        ))
        .with_state(state.clone());
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(metrics_route)
        .nest("/api/v1", api)
        .fallback(ui::serve)
        .layer(middleware::from_fn_with_state(state, client::client_info))
        .layer(middleware::map_response(security_headers))
}

/// Headers on every response: no framing (clickjacking), no MIME sniffing, no referrer.
/// Non-HTML -> deny-all policy. No own `Cache-Control` -> `no-store` (bodies may hold
/// secrets shown once, e.g. new API keys, or stored config backups).
/// UI page has its own script policy.
async fn security_headers(mut resp: Response) -> Response {
    use axum::http::HeaderValue;
    let html = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/html"));
    let h = resp.headers_mut();
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert(
        "content-security-policy",
        HeaderValue::from_static(if html {
            "frame-ancestors 'none'"
        } else {
            "default-src 'none'; frame-ancestors 'none'"
        }),
    );
    // No cache rule = data (JSON, CSV, stored file, cert bundle, metrics) -> no copy kept.
    // UI files set their own.
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_urls_lose_their_signature_and_credentials() {
        assert_eq!(
            redact_url("http://files.test:7548/uploads/d/u?e=1&s=abc"),
            "http://files.test:7548/uploads/d/u?********"
        );
        assert_eq!(
            redact_url("https://user:pw@backup.example/up/cfg#frag"),
            "https://backup.example/up/cfg?********"
        );
        assert_eq!(
            redact_url("https://user:pw@backup.example"),
            "https://backup.example"
        );
        assert_eq!(redact_url("ftp://[::1]:21/cfg"), "ftp://[::1]:21/cfg");
        assert_eq!(redact_url("not a url"), "not a url");
    }

    #[test]
    fn task_payloads_are_redacted_by_kind() {
        let upload = json!({ "url": "http://f/uploads/d/u?e=1&s=abc", "password": "pw" });
        assert_eq!(
            redact_task("upload", &upload),
            json!({ "url": "http://f/uploads/d/u?********", "password": "********" })
        );
        // Only an upload URL is a write link; other tasks keep theirs.
        let download = json!({ "url": "http://f/x.bin?token=1", "password": "pw" });
        assert_eq!(
            redact_task("download", &download),
            json!({ "url": "http://f/x.bin?token=1", "password": "********" })
        );
        // Diagnostic test links (signed, size up to 1 GB) hidden too.
        let down = json!({ "test": "download", "params": {
            "url": "http://f:7548/diag/d/1000?e=1&s=abc", "size": "1000" } });
        assert_eq!(
            redact_task("diagnostic", &down),
            json!({ "test": "download", "params": {
                "url": "http://f:7548/diag/d/1000?********", "size": "1000" } })
        );
        let up = json!({ "test": "upload", "params": {
            "url": "https://u:pw@f/diag/d?e=1&s=abc#x" } });
        assert_eq!(
            redact_task("diagnostic", &up)["params"]["url"],
            "https://f/diag/d?********"
        );
        let ping = json!({ "test": "ip_ping", "params": { "host": "example.org" } });
        assert_eq!(redact_task("diagnostic", &ping), ping);
        // USP transfer commands: link in the `URL` input.
        let op = json!({ "command": "Device.X.Upload()", "input": {
            "URL": "http://f/uploads/d/u?e=1&s=abc", "FileType": "1 Vendor Configuration File" } });
        let shown = redact_task("operate", &op);
        assert_eq!(shown["input"]["URL"], "http://f/uploads/d/u?********");
        assert_eq!(shown["input"]["FileType"], "1 Vendor Configuration File");
        let spv = json!({ "values": [
            { "name": "A", "value": "enc:v2:AAAA", "secret": true },
            { "name": "B", "value": "plain" },
        ] });
        let shown = redact_task("set_parameter_values", &spv);
        assert_eq!(shown["values"][0]["value"], "********");
        assert_eq!(shown["values"][1]["value"], "plain");
    }
}
