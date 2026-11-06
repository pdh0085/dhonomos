//! Server configuration (runtime settings) for the web.
//!
//! Each server option -> value, source, category. Runtime options -> admin edits from the web.
//! List built once at startup by the server binary -> [`crate::ApiConfig::server_settings`].
//! Secrets never in the list, only whether set.
//! Values stored from the web -> read from DB at each request.
//!
//! Change -> check by the server binary ([`SettingsHooks::validate`]: CLI parser of the option
//! and cross-option checks) -> store -> apply ([`SettingsHooks::apply_now`]).
//! Other processes follow within seconds.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use dhonomos_common::mask::{MASK, mask_url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{ApiError, AppState, audit, ts};

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/settings/server", get(server))
        .route(
            "/settings/server/{key}",
            axum::routing::put(set).delete(reset),
        )
        .route("/settings/server/{key}/history", get(history))
}

/// Source of the value of an option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SettingSource {
    Cli,
    Env,
    /// Built-in default.
    Default,
    /// Not set + no default.
    Unset,
    /// Changed from the web (stored in DB).
    Web,
}

/// Web edit form of an option value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SettingKind {
    Bool,
    /// Several values.
    List,
    /// One value.
    Text,
}

/// Option kind -> may the web change it or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SettingCategory {
    /// Read at server start: listeners, DB, identities, file paths.
    Bootstrap,
    /// Can change while the server runs -> web-editable unless set in server config.
    Runtime,
    /// Security-related -> server config only.
    Security,
    /// Secret -> value never shown, only whether set.
    Secret,
}

/// One server option, as in effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServerSetting {
    /// Option id (`acs_listen`).
    pub key: String,
    /// CLI flag (`--acs-listen`).
    pub flag: String,
    /// Env variable (`DHONOMOS_ACS_LISTEN`).
    pub env: String,
    /// UI group (`listeners_tls`).
    pub group: String,
    pub category: SettingCategory,
    /// 1st paragraph of the option help.
    pub help: String,
    pub source: SettingSource,
    /// Has a value (given or default).
    pub is_set: bool,
    /// Value as given, list joined with `,`. URL passwords -> `****`.
    /// Always `None` for secrets + when unset.
    pub value: Option<String>,
    pub kind: SettingKind,
    /// Web may change it = runtime option not set in server config.
    pub editable: bool,
    /// Why the web cannot change a runtime option.
    pub locked_reason: Option<String>,
    /// Value stored from the web: string, or array of strings for a list. Masked like `value`.
    /// Also shown when locked; server ignores it then.
    pub web_value: Option<Value>,
}

/// Check of stored runtime settings as after a change. `Err(reason)` -> server would refuse.
///
/// Change checked alone first, then with all stored values.
/// Stored value refused alone (server ignores it) -> must not block other changes.
pub type ValidateSettings =
    Arc<dyn Fn(&BTreeMap<String, Value>) -> Result<(), String> + Send + Sync>;

/// Apply stored runtime settings in this process now.
pub type ApplySettings = Arc<dyn Fn() + Send + Sync>;

/// Settings hooks from the server binary.
///
/// Binary knows option parsers + affected components; API does not.
#[derive(Clone)]
pub struct SettingsHooks {
    /// Check a change before store.
    pub validate: ValidateSettings,
    /// Apply stored settings after a change.
    pub apply_now: ApplySettings,
    /// Apply stored alarm rules after a change (`PUT /settings/alarm-rules`).
    pub apply_alarm_rules: ApplySettings,
}

impl Default for SettingsHooks {
    /// Accept all, apply nothing (tests, tools).
    fn default() -> Self {
        Self {
            validate: Arc::new(|_| Ok(())),
            apply_now: Arc::new(|| {}),
            apply_alarm_rules: Arc::new(|| {}),
        }
    }
}

impl std::fmt::Debug for SettingsHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SettingsHooks").finish_non_exhaustive()
    }
}

/// Max changes of a runtime option in the history view.
const HISTORY: i64 = 50;

/// `value` (string or array of strings) -> URL passwords + tokens masked, as the web shows it.
fn masked(value: &Value) -> Value {
    let one = |v: &str| Value::String(mask_url(v).unwrap_or_else(|| v.to_owned()));
    match value {
        Value::String(s) => one(s),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| v.as_str().map_or_else(|| v.clone(), one))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// `value` for the `value` field: list joined with `,`.
fn joined(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Array(items) => Some(
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(","),
        ),
        _ => None,
    }
}

/// `item` + its value from the web in `stored`. Editable -> web value = effective value.
fn with_web_value(item: &ServerSetting, stored: &BTreeMap<String, Value>) -> ServerSetting {
    let mut item = item.clone();
    if let Some(v) = stored.get(&item.key).map(masked) {
        if item.editable {
            item.value = joined(&v);
            item.is_set = true;
            item.source = SettingSource::Web;
        }
        item.web_value = Some(v);
    }
    item
}

#[utoipa::path(
    get,
    path = "/api/v1/settings/server",
    tag = "settings",
    operation_id = "server_settings",
    summary = "The server's configuration",
    description = "Every server option with its effective value, where it came from (`cli`, \
                   `env`, `default`, `unset`, or `web` when changed from the web) and its \
                   category. Secrets have no value, only `is_set`; passwords and tokens in URLs \
                   are replaced by `****`. `editable` runtime options can be changed with \
                   `PUT /settings/server/{key}`; `locked_reason` says why a runtime option \
                   cannot.",
    responses(
        (status = 200, description = "The options", body = crate::schemas::ServerSettingList),
    ),
)]
async fn server(State(s): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let stored = s.store.runtime_settings(s.config.tenant_id).await?;
    let items: Vec<ServerSetting> = s
        .config
        .server_settings
        .iter()
        .map(|i| with_web_value(i, &stored))
        .collect();
    Ok(Json(json!({ "items": items })))
}

/// Option `key` if the web may change it.
/// Else 404 unknown, 422 not a runtime option, 409 set in server config.
fn changeable<'a>(s: &'a AppState, key: &str) -> Result<&'a ServerSetting, ApiError> {
    let item = s
        .config
        .server_settings
        .iter()
        .find(|i| i.key == key)
        .ok_or_else(|| crate::not_found("setting"))?;
    if item.category != SettingCategory::Runtime {
        return Err(unprocessable(format!(
            "{key} cannot be changed from the web"
        )));
    }
    if let Some(reason) = &item.locked_reason {
        return Err(ApiError(StatusCode::CONFLICT, reason.clone()));
    }
    Ok(item)
}

fn unprocessable(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg.into())
}

/// Body of `PUT /settings/server/{key}`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct SetSetting {
    /// Value as the env variable or CLI would carry it.
    /// String, or array of strings for a `list` option.
    #[schema(value_type = serde_json::Value)]
    value: Value,
}

#[utoipa::path(
    put,
    path = "/api/v1/settings/server/{key}",
    tag = "settings",
    operation_id = "set_server_setting",
    summary = "Change a runtime option",
    description = "Checked like the command-line option (and with the options it depends on), \
                   stored, and applied on every server process within seconds. Only runtime \
                   options the server's configuration does not set; a value set there always \
                   wins. A value with the mask `****` in it is refused: send the full value.",
    params(("key" = String, Path, description = "The option's id, e.g. `session_hours`")),
    request_body = SetSetting,
    responses(
        (status = 200, description = "The option as it is now", body = crate::schemas::ServerSetting),
        (status = 404, description = "Unknown option"),
        (status = 409, description = "Set in the server's configuration, with the reason"),
        (status = 422, description = "Not a runtime option, or an invalid value, with the reason"),
    ),
)]
async fn set(
    State(s): State<Arc<AppState>>,
    Path(key): Path<String>,
    body: Result<Json<SetSetting>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let item = changeable(&s, &key)?;
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    let value = match (item.kind, req.value) {
        (SettingKind::List, Value::Array(items)) => {
            if !items.iter().all(Value::is_string) {
                return Err(unprocessable("value must be an array of strings"));
            }
            Value::Array(items)
        }
        (SettingKind::List, _) => return Err(unprocessable("value must be an array of strings")),
        (_, Value::String(v)) => Value::String(v),
        _ => return Err(unprocessable("value must be a string")),
    };
    let has_mask = match &value {
        Value::String(v) => v.contains(MASK),
        Value::Array(items) => items
            .iter()
            .any(|v| v.as_str().is_some_and(|v| v.contains(MASK))),
        _ => false,
    };
    if has_mask {
        return Err(unprocessable(
            "re-enter the full value; the shown value is masked",
        ));
    }
    // Value alone, then with the other stored values (cross-option checks).
    (s.config.settings_hooks.validate)(&BTreeMap::from([(key.clone(), value.clone())]))
        .map_err(unprocessable)?;
    let mut stored = s.store.runtime_settings(s.config.tenant_id).await?;
    stored.insert(key.clone(), value.clone());
    (s.config.settings_hooks.validate)(&stored).map_err(unprocessable)?;
    let actor = crate::actor(&s);
    let old = s
        .store
        .set_runtime_setting(s.config.tenant_id, &key, &value, Some(&actor))
        .await?;
    audit(
        &s,
        "settings.update",
        "setting",
        &key,
        json!({ "key": key, "old": old.as_ref().map(masked), "new": masked(&value) }),
    )
    .await;
    (s.config.settings_hooks.apply_now)();
    Ok(Json(json!(with_web_value(item, &stored))))
}

#[utoipa::path(
    delete,
    path = "/api/v1/settings/server/{key}",
    tag = "settings",
    operation_id = "reset_server_setting",
    summary = "Reset a runtime option",
    description = "Removes the value changed from the web: the option is back to its default \
                   on every server process within seconds.",
    params(("key" = String, Path, description = "The option's id, e.g. `session_hours`")),
    responses(
        (status = 204, description = "Reset (also when there was no value from the web)"),
        (status = 404, description = "Unknown option"),
        (status = 409, description = "Set in the server's configuration, with the reason"),
        (status = 422, description = "Not a runtime option, or the remaining values are refused, with the reason"),
    ),
)]
async fn reset(
    State(s): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<StatusCode, ApiError> {
    changeable(&s, &key)?;
    let mut stored = s.store.runtime_settings(s.config.tenant_id).await?;
    if stored.remove(&key).is_none() {
        return Ok(StatusCode::NO_CONTENT);
    }
    // Default may not fit the other web values (e.g. a timeout shorter than another).
    (s.config.settings_hooks.validate)(&stored).map_err(unprocessable)?;
    let actor = crate::actor(&s);
    if let Some(old) = s
        .store
        .reset_runtime_setting(s.config.tenant_id, &key, Some(&actor))
        .await?
    {
        audit(
            &s,
            "settings.reset",
            "setting",
            &key,
            json!({ "key": key, "old": masked(&old), "new": null }),
        )
        .await;
        (s.config.settings_hooks.apply_now)();
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/settings/server/{key}/history",
    tag = "settings",
    operation_id = "server_setting_history",
    summary = "Changes of a runtime option",
    description = "The last 50 changes from the web, newest first. `new` null is a reset to \
                   the default. Values are masked like in `GET /settings/server`.",
    params(("key" = String, Path, description = "The option's id, e.g. `session_hours`")),
    responses(
        (status = 200, description = "The changes", body = crate::schemas::ServerSettingHistory),
        (status = 404, description = "Unknown option"),
    ),
)]
async fn history(
    State(s): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if !s.config.server_settings.iter().any(|i| i.key == key) {
        return Err(crate::not_found("setting"));
    }
    let items: Vec<Value> = s
        .store
        .runtime_setting_history(s.config.tenant_id, &key, HISTORY)
        .await?
        .iter()
        .map(change_json)
        .collect();
    Ok(Json(json!({ "items": items })))
}

pub(crate) fn change_json(c: &dhonomos_store::RuntimeSettingChange) -> Value {
    json!({
        "old": c.old.as_ref().map(masked),
        "new": c.new.as_ref().map(masked),
        "actor": c.actor,
        "at": ts(c.at),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_values_are_masked() {
        assert_eq!(
            masked(&json!("https://h.example/x?token=abc")),
            json!("https://h.example/x?token=****")
        );
        assert_eq!(
            masked(&json!(["https://u:pw@a.example", "plain"])),
            json!(["https://u:****@a.example", "plain"])
        );
        assert_eq!(masked(&json!("30")), json!("30"));
        assert_eq!(joined(&json!(["a", "b"])).as_deref(), Some("a,b"));
    }
}
