//! OpenAPI 3.1 document of the REST API (NB-01) -> `GET /api/v1/openapi.json`.
//!
//! Each handler under `/api/v1`: `#[utoipa::path]`; [`ApiDoc`] lists them.
//! Responses common to all operations (auth, roles, DB outage, malformed params,
//! `{"error": ...}` body) -> added by [`Common`], not per handler.
//! Tests: document = router.

use std::sync::OnceLock;

use axum::Json;
use axum::http::Method;
use utoipa::openapi::path::Operation;
use utoipa::openapi::schema::{ObjectBuilder, Schema, Type};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::{ContentBuilder, Ref, RefOr, ResponseBuilder};
use utoipa::{Modify, OpenApi, PartialSchema, ToSchema};

use crate::auth::{self, SESSION_COOKIE};

const DESCRIPTION: &str = "\
REST API of Dhonomos, a TR-069 (CWMP) ACS and TR-369 (USP) Controller.

Authentication: log in with `POST /api/v1/auth/login` to get the `dhonomos_session` cookie \
(HttpOnly, SameSite=Strict; named `__Host-dhonomos_session` and Secure when the server runs \
with `--secure-cookies`), or send `Authorization: Bearer <token>` with an API key \
(`pk_...`) or the server's static `--api-token`. Each operation states the role it needs \
(`viewer` < `operator` < `admin`). A server with neither an API token nor user accounts \
accepts every request that reaches it directly (development only); a request that carries \
proxy headers (`X-Forwarded-For`, `Forwarded`, `X-Real-IP`, ...) or comes from a trusted \
proxy is refused with 401 `no accounts exist`. A session unused for the server's idle limit \
(60 minutes by default) ends.

Local accounts can use two-factor authentication (TOTP): the login then also takes a `totp` \
code. While the server requires it for admins, an admin without it gets a session that may \
only call `GET /auth/me`, `POST /auth/logout` and `POST /auth/totp/{setup,enable}` (other \
calls answer 403 `two-factor enrollment required`). API keys, the API token and single \
sign-on are not affected.

Errors are JSON objects `{\"error\": \"...\"}`, except when the framework rejects a malformed \
path or query parameter (plain text). Times are RFC 3339 strings, IDs are UUIDs.";

/// The OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Dhonomos API",
        version = env!("CARGO_PKG_VERSION"),
        description = DESCRIPTION,
        license(name = "Apache-2.0", identifier = "Apache-2.0"),
    ),
    paths(
        crate::list_devices,
        crate::list_device_facets,
        crate::preregister,
        crate::enroll::bulk_preregister,
        crate::get_device,
        crate::patch_device,
        crate::lifecycle::delete_device,
        crate::lifecycle::delete_devices,
        crate::get_parameters,
        crate::list_credentials,
        crate::put_credential,
        crate::delete_credential,
        crate::issue_mqtt_credentials,
        crate::revoke_mqtt_credentials,
        crate::get_supported_model,
        crate::refresh_data_model,
        crate::issue_certificate,
        crate::bundle::issue_bundle,
        crate::list_certificates,
        crate::revoke_certificate,
        crate::revoke_certificate_by_fingerprint,
        crate::expiring_certificates,
        crate::get_events,
        crate::get_device_tasks,
        crate::create_task,
        crate::connection_request,
        crate::series::list,
        crate::series::series,
        crate::series::bulkdata_url,
        crate::series::wifi,
        crate::lifecycle::list_backups,
        crate::lifecycle::create_backup,
        crate::lifecycle::get_backup,
        crate::lifecycle::delete_backup,
        crate::lifecycle::backup_diff,
        crate::lifecycle::restore,
        crate::lifecycle::replace,
        crate::lifecycle::list_config_files,
        crate::lifecycle::request_log_file,
        crate::lifecycle::list_log_files,
        crate::lifecycle::request_config_file,
        crate::get_task,
        crate::cancel_task,
        crate::files::list,
        crate::files::upload,
        crate::files::delete,
        crate::files::content,
        crate::jobs::list,
        crate::jobs::create,
        crate::jobs::preview,
        crate::jobs::detail,
        crate::jobs::members,
        crate::jobs::control,
        crate::presets::list,
        crate::presets::dry_run,
        crate::presets::get_one,
        crate::presets::save,
        crate::presets::remove,
        crate::presets::history,
        crate::presets::validate,
        crate::presets::import,
        crate::presets::export,
        crate::alarms::list,
        crate::alarms::ack,
        crate::alarms::rules,
        crate::alarms::list_silences,
        crate::alarms::create_silence,
        crate::alarms::end_silence,
        crate::export::devices,
        crate::import::import,
        crate::export::job_members,
        crate::export::alarms,
        crate::series::overview,
        crate::stream::stream_handler,
        crate::list_audit,
        crate::auth::login,
        crate::oidc::config,
        crate::oidc::login,
        crate::oidc::callback,
        crate::auth::logout,
        crate::auth::me,
        crate::auth::two_factor::setup,
        crate::auth::two_factor::enable,
        crate::auth::two_factor::disable,
        crate::auth::two_factor::recovery_codes,
        crate::auth::two_factor::reset,
        crate::wireguard::summary,
        crate::wireguard::list_hubs,
        crate::wireguard::create_hub,
        crate::wireguard::get_hub,
        crate::wireguard::update_hub,
        crate::wireguard::delete_hub,
        crate::wireguard::issue_hub_token,
        crate::wireguard::revoke_hub_token,
        crate::wireguard::list_networks,
        crate::wireguard::create_network,
        crate::wireguard::get_network,
        crate::wireguard::update_network,
        crate::wireguard::delete_network,
        crate::wireguard::list_members,
        crate::wireguard::device_members,
        crate::wireguard::create_member,
        crate::wireguard::get_member,
        crate::wireguard::update_member,
        crate::wireguard::revoke_member,
        crate::wireguard::member_config,
        crate::wireguard::rekey_member,
        crate::wireguard::rotate_member_key,
        crate::wireguard::rotate_network_keys,
        crate::wireguard::delete_member,
        crate::wg_hub::hub_state,
        crate::wg_hub::public_key,
        crate::wg_hub::status,
        crate::auth::list_users,
        crate::auth::create_user,
        crate::auth::update_user,
        crate::auth::delete_user,
        crate::auth::list_keys,
        crate::auth::create_key,
        crate::auth::revoke_key,
        crate::settings::server,
        crate::settings::set,
        crate::settings::reset,
        crate::settings::history,
        crate::alarm_rules::show,
        crate::alarm_rules::set,
        crate::alarm_rules::history,
        serve,
    ),
    components(schemas(ErrorBody)),
    modifiers(&Common),
    security(("bearer" = []), ("session" = [])),
    tags(
        (name = "devices", description = "Device inventory, parameters, credentials, certificates"),
        (name = "tasks", description = "Queued operations on devices"),
        (name = "metrics", description = "Device time series and the Wi-Fi view"),
        (name = "backups", description = "Configuration backups, restore, replacement"),
        (name = "files", description = "Firmware and configuration files"),
        (name = "jobs", description = "Bulk jobs and firmware campaigns"),
        (name = "presets", description = "Provisioning presets"),
        (name = "alarms", description = "Alarms, alarm rules and silences"),
        (name = "overview", description = "Fleet overview"),
        (name = "stream", description = "Server-sent events"),
        (name = "audit", description = "Audit trail"),
        (name = "wireguard", description = "WireGuard hubs, overlay networks and their members"),
        (name = "wireguard-hub", description = "Called by dhonomos-wg-hub with a hub token"),
        (name = "auth", description = "Login, logout, the current caller"),
        (name = "users", description = "Operator accounts and API keys"),
        (name = "settings", description = "The server's configuration"),
        (name = "meta", description = "This document"),
    )
)]
pub(crate) struct ApiDoc;

/// Error response body.
#[derive(ToSchema)]
#[allow(dead_code)] // Docs only: errors built with `json!`.
pub(crate) struct ErrorBody {
    /// What went wrong, in English.
    error: String,
}

/// Task as the API takes it: `kind` + kind-specific `payload` (`dhonomos_core::TaskKind`).
#[derive(ToSchema)]
#[allow(dead_code)] // Docs only.
pub(crate) struct TaskSpec {
    /// `get_parameter_values`, `set_parameter_values`, `get_parameter_names`,
    /// `get_parameter_attributes`, `set_parameter_attributes`, `add_object`, `delete_object`,
    /// `reboot`, `factory_reset`, `download`, `upload`, `diagnostic` or `operate` (USP).
    kind: String,
    /// Kind arguments, e.g. `{"names": ["Device.DeviceInfo."]}`.
    /// Absent for kinds without arguments (`reboot`, `factory_reset`).
    #[schema(value_type = Option<Object>)]
    payload: Option<serde_json::Value>,
}

/// Raw bytes (non-JSON request body).
pub(crate) struct Binary;

impl PartialSchema for Binary {
    fn schema() -> RefOr<Schema> {
        ObjectBuilder::new()
            .schema_type(Type::String)
            .content_media_type("application/octet-stream")
            .into()
    }
}

impl ToSchema for Binary {}

/// Operations without credentials.
const PUBLIC: &[(&str, &str)] = &[
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/logout"),
    ("GET", "/api/v1/openapi.json"),
    ("GET", "/api/v1/auth/config"),
    ("GET", "/api/v1/auth/oidc/login"),
    ("GET", "/api/v1/auth/oidc/callback"),
];

/// Operations of the hub process, with its hub token (no user role).
fn hub_route(path: &str) -> bool {
    path.starts_with("/api/v1/wg-hub/")
}

/// Operations without DB access.
const NO_STORAGE: &[(&str, &str)] = &[
    ("GET", "/api/v1/openapi.json"),
    ("GET", "/api/v1/auth/me"),
    ("GET", "/api/v1/presets"),
    ("GET", "/api/v1/alarm-rules"),
];

/// Operations of a path item + their methods.
pub(crate) fn operations_mut(
    item: &mut utoipa::openapi::PathItem,
) -> impl Iterator<Item = (Method, &mut Operation)> {
    [
        (Method::GET, item.get.as_mut()),
        (Method::PUT, item.put.as_mut()),
        (Method::POST, item.post.as_mut()),
        (Method::DELETE, item.delete.as_mut()),
        (Method::PATCH, item.patch.as_mut()),
        (Method::HEAD, item.head.as_mut()),
        (Method::OPTIONS, item.options.as_mut()),
        (Method::TRACE, item.trace.as_mut()),
    ]
    .into_iter()
    .filter_map(|(m, op)| op.map(|op| (m, op)))
}

/// Adds security schemes + responses shared by all operations.
struct Common;

impl Modify for Common {
    fn modify(&self, api: &mut utoipa::openapi::OpenApi) {
        let components = api.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "An API key (`pk_...`, role chosen at creation) or the static \
                         `--api-token` (admin)",
                    ))
                    .build(),
            ),
        );
        components.add_security_scheme(
            "session",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                SESSION_COOKIE,
                "Session cookie set by `POST /api/v1/auth/login`",
            ))),
        );
        components.add_security_scheme(
            "hub_token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "A hub token (`dwh_...`) issued with `POST /api/v1/wireguard/hubs/{id}/token`; \
                         only the `wireguard-hub` operations accept it",
                    ))
                    .build(),
            ),
        );
        for (path, item) in api.paths.paths.iter_mut() {
            for (method, op) in operations_mut(item) {
                let key = (method.as_str(), path.as_str());
                let responses = &mut op.responses.responses;
                if PUBLIC.contains(&key) {
                    op.security = Some(Vec::new());
                } else if hub_route(path) {
                    responses
                        .entry("401".into())
                        .or_insert_with(|| error("No hub token, or an invalid one"));
                    responses.entry("429".into()).or_insert_with(|| {
                        error("Too many requests from this address; see `Retry-After`")
                    });
                } else {
                    let role = auth::required_role(&method, path).as_str();
                    let note = format!("Requires the `{role}` role.");
                    op.description = Some(match op.description.take() {
                        Some(d) => format!("{d}\n\n{note}"),
                        None => note,
                    });
                    responses
                        .entry("401".into())
                        .or_insert_with(|| error("Not logged in, or invalid credentials"));
                    responses
                        .entry("403".into())
                        .or_insert_with(|| error(&format!("The caller lacks the `{role}` role")));
                    responses.entry("429".into()).or_insert_with(|| {
                        error("Too many requests from this caller; see `Retry-After`")
                    });
                }
                if !NO_STORAGE.contains(&key) {
                    responses
                        .entry("503".into())
                        .or_insert_with(|| error("The database is unavailable"));
                }
                if op.parameters.as_ref().is_some_and(|p| !p.is_empty()) {
                    responses.entry("400".into()).or_insert_with(|| {
                        ResponseBuilder::new()
                            .description("A path or query parameter is malformed")
                            .content("text/plain", ContentBuilder::new().build())
                            .into()
                    });
                }
                // Handler errors = `{"error": ...}`.
                for (status, resp) in responses.iter_mut() {
                    if let RefOr::T(resp) = resp
                        && status.starts_with(['4', '5'])
                        && resp.content.is_empty()
                    {
                        resp.content
                            .insert("application/json".into(), error_content());
                    }
                }
            }
        }
    }
}

fn error_content() -> utoipa::openapi::Content {
    ContentBuilder::new()
        .schema(Some(Ref::from_schema_name("ErrorBody")))
        .build()
}

fn error(description: &str) -> RefOr<utoipa::openapi::Response> {
    ResponseBuilder::new()
        .description(description)
        .content("application/json", error_content())
        .into()
}

/// Built once.
pub(crate) fn document() -> &'static utoipa::openapi::OpenApi {
    static DOC: OnceLock<utoipa::openapi::OpenApi> = OnceLock::new();
    DOC.get_or_init(ApiDoc::openapi)
}

/// `GET /api/v1/openapi.json`.
#[utoipa::path(
    get,
    path = "/api/v1/openapi.json",
    tag = "meta",
    operation_id = "openapi",
    summary = "This OpenAPI 3.1 document",
    responses((status = 200, description = "The OpenAPI document", body = Object)),
)]
pub(crate) async fn serve() -> Json<&'static utoipa::openapi::OpenApi> {
    Json(document())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::BTreeSet;

    use super::*;

    /// Not operator API under `/api/v1`: root router liveness + Prometheus,
    /// device-facing file server.
    const NOT_API: &[&str] = &[
        "/healthz",
        "/metrics",
        "/files/{id}/{name}",
        "/uploads/{device}/{upload}",
        "/bulkdata/{device}/{signature}",
        "/diag/{device}/{bytes}",
        "/diag/{device}",
    ];

    const HTTP_METHODS: &[&str] = &[
        "get", "post", "put", "patch", "delete", "head", "options", "trace",
    ];

    /// Drop `//` comments (outside string literals) -> commented-out routes not counted.
    fn strip_comments(src: &str) -> String {
        src.lines()
            .map(|line| {
                let mut in_str = false;
                let mut prev = '\0';
                let mut cut = line.len();
                for (i, c) in line.char_indices() {
                    if c == '"' && prev != '\\' {
                        in_str = !in_str;
                    } else if c == '/' && prev == '/' && !in_str {
                        cut = i - 1;
                        break;
                    }
                    prev = c;
                }
                &line[..cut]
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// `(method, path)` of each `.route("path", <method router>)` call in `src`.
    /// Methods = calls at top level of the 2nd argument, e.g.
    /// `get(a).post(b)` or `axum::routing::put(c).delete(d).layer(e)`.
    fn routes_in(src: &str) -> Vec<(String, String)> {
        let src = strip_comments(src);
        let mut out = Vec::new();
        let mut rest = src.as_str();
        while let Some(at) = rest.find(".route(") {
            rest = &rest[at + ".route(".len()..];
            let args = rest.trim_start();
            let Some(args) = args.strip_prefix('"') else {
                continue;
            };
            let Some(end) = args.find('"') else { continue };
            let path = &args[..end];
            if !path.starts_with('/') {
                continue;
            }
            let Some(router) = args[end + 1..].trim_start().strip_prefix(',') else {
                continue;
            };
            // Walk 2nd argument up to the `)` closing `.route(`.
            let mut depth = 0usize;
            let mut in_str = false;
            let mut prev = '\0';
            let mut ident = String::new();
            for c in router.chars() {
                if in_str {
                    if c == '"' && prev != '\\' {
                        in_str = false;
                    }
                    prev = c;
                    continue;
                }
                match c {
                    '"' => in_str = true,
                    '(' | '[' | '{' => {
                        if depth == 0 && HTTP_METHODS.contains(&ident.as_str()) {
                            out.push((ident.to_uppercase(), path.to_owned()));
                        }
                        depth += 1;
                    }
                    ')' | ']' | '}' => {
                        if depth == 0 {
                            break;
                        }
                        depth -= 1;
                    }
                    _ => {}
                }
                if c.is_alphanumeric() || c == '_' {
                    if !(prev.is_alphanumeric() || prev == '_') {
                        ident.clear();
                    }
                    ident.push(c);
                } else if !c.is_whitespace() {
                    ident.clear();
                }
                prev = c;
            }
        }
        out
    }

    #[test]
    fn route_parser() {
        let src = r#"
            Router::new()
                .route("/a", get(x).post(y))
                // .route("/commented", get(x))
                .route(
                    "/b/{id}",
                    axum::routing::put(p).delete(files::delete).layer(lim()),
                )
                .route("/c", get(|| async { "ok" }))
                .route_layer(z)
        "#;
        assert_eq!(
            routes_in(src),
            [
                ("GET".to_owned(), "/a".to_owned()),
                ("POST".to_owned(), "/a".to_owned()),
                ("PUT".to_owned(), "/b/{id}".to_owned()),
                ("DELETE".to_owned(), "/b/{id}".to_owned()),
                ("GET".to_owned(), "/c".to_owned()),
            ]
        );
    }

    /// Each mounted route documented + each documented operation exists.
    #[test]
    fn document_matches_the_router() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut routed = BTreeSet::new();
        let mut excluded = BTreeSet::new();
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "rs"))
            .collect();
        entries.sort();
        for file in entries {
            let src = std::fs::read_to_string(&file).unwrap();
            // Test modules (like this one) build own routers.
            let src = src.split("#[cfg(test)]").next().unwrap_or_default();
            for (method, path) in routes_in(src) {
                if NOT_API.contains(&path.as_str()) {
                    excluded.insert(path);
                } else {
                    routed.insert((method, format!("/api/v1{path}")));
                }
            }
        }
        assert_eq!(
            excluded.len(),
            NOT_API.len(),
            "NOT_API lists routes that no longer exist: found only {excluded:?}"
        );
        assert!(routed.len() > 50, "the route parser found too little");

        let mut doc = ApiDoc::openapi();
        let mut documented = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for (path, item) in doc.paths.paths.iter_mut() {
            for (method, op) in operations_mut(item) {
                documented.insert((method.as_str().to_owned(), path.clone()));
                let id = op.operation_id.clone().unwrap_or_default();
                assert!(ids.insert(id.clone()), "duplicate operationId {id:?}");
                assert!(
                    op.tags.as_ref().is_some_and(|t| !t.is_empty()),
                    "{method} {path} has no tag"
                );
            }
        }
        let undocumented: Vec<_> = routed.difference(&documented).collect();
        let unrouted: Vec<_> = documented.difference(&routed).collect();
        assert!(
            undocumented.is_empty(),
            "routes without #[utoipa::path] (or missing from ApiDoc): {undocumented:?}"
        );
        assert!(
            unrouted.is_empty(),
            "documented operations that no route serves: {unrouted:?}"
        );
    }

    #[test]
    fn document_is_openapi_3_1() {
        let v = serde_json::to_value(document()).unwrap();
        assert!(v["openapi"].as_str().unwrap().starts_with("3.1"));
        assert_eq!(v["info"]["title"], "Dhonomos API");
        assert_eq!(v["info"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(v["info"]["license"]["identifier"], "Apache-2.0");
        assert_eq!(
            v["components"]["securitySchemes"]["session"]["name"],
            SESSION_COOKIE
        );
        let login = &v["paths"]["/api/v1/auth/login"]["post"];
        assert_eq!(login["security"], serde_json::json!([]));
        assert!(login["responses"]["401"].is_object());
        let users = &v["paths"]["/api/v1/users"]["get"];
        assert!(users["security"].is_null());
        assert!(
            users["description"]
                .as_str()
                .unwrap()
                .contains("`admin` role")
        );
        assert!(
            v["paths"]["/api/v1/devices/{id}"]["get"]["responses"]["404"]["content"]
                ["application/json"]
                .is_object()
        );
    }
}
