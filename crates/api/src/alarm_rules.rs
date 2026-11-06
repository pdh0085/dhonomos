//! Alarm rules: admin view + edit (runtime settings, stage 4).
//! Server `--alarms` file -> read-only here ([`crate::ApiConfig::alarm_rules_file`]).
//! No file -> stored in DB: validated like the file, stored with history.
//! Change applied in this process at once ([`crate::SettingsHooks::apply_alarm_rules`]),
//! in every other process within seconds.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use dhonomos_core::alarms::AlarmRules;
use dhonomos_store::{AlarmRulesVersion, StoredAlarmRules};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{ApiError, AppState, audit, ts};

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/settings/alarm-rules", get(show).put(set))
        .route("/settings/alarm-rules/history", get(history))
}

/// Server `--alarms` file, when the rules come from it.
#[derive(Debug, Clone)]
pub struct AlarmRulesFile {
    /// Path as given.
    pub path: String,
    /// Text as last loaded (startup or SIGHUP).
    pub yaml: dhonomos_core::Shared<String>,
}

/// Max size of a rule set stored from the web.
const MAX_YAML_BYTES: usize = 256 * 1024;

/// Max versions shown in the history.
const HISTORY: i64 = 20;

fn unprocessable(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg.into())
}

/// Body of `GET /settings/alarm-rules`; `rules` = effective rules.
fn rules_json(s: &AppState, rules: &AlarmRules, stored: Option<&StoredAlarmRules>) -> Value {
    if let Some(file) = &s.config.alarm_rules_file {
        return json!({
            "source": "file",
            "path": file.path,
            "yaml": *file.yaml.get(),
            "editable": false,
            "rules": rules,
            "updated_by": null,
            "updated_at": null,
        });
    }
    json!({
        "source": if stored.is_some() { "web" } else { "none" },
        "path": null,
        "yaml": stored.map(|x| &x.yaml),
        "editable": true,
        "rules": rules,
        "updated_by": stored.and_then(|x| x.updated_by.as_ref()),
        "updated_at": stored.map(|x| ts(x.updated_at)),
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/settings/alarm-rules",
    tag = "settings",
    operation_id = "alarm_rule_settings",
    summary = "The alarm rules and where they come from",
    description = "`source` is `file` (the server's `--alarms` file: read-only, `path` names \
                   it), `web` (stored from the web) or `none` (no file and nothing stored: no \
                   rules). `yaml` is the text of the file or of the stored rules; `rules` the \
                   rules the server evaluates.",
    responses(
        (status = 200, description = "The alarm rules", body = crate::schemas::AlarmRuleSettings),
    ),
)]
async fn show(State(s): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let stored = match s.config.alarm_rules_file {
        Some(_) => None,
        None => s.store.alarm_rule_set(s.config.tenant_id).await?,
    };
    Ok(Json(rules_json(
        &s,
        &s.config.alarm_rules.get(),
        stored.as_ref(),
    )))
}

/// Body of `PUT /settings/alarm-rules`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct SetAlarmRules {
    /// Rules as YAML, same format as an `--alarms` file (max 256 KiB).
    yaml: String,
}

/// Rule names of `yaml`. Absent or invalid -> none.
fn names(yaml: Option<&str>) -> Vec<String> {
    yaml.and_then(|y| AlarmRules::from_yaml(y).ok())
        .map(|r| r.iter().map(|x| x.name.clone()).collect())
        .unwrap_or_default()
}

#[utoipa::path(
    put,
    path = "/api/v1/settings/alarm-rules",
    tag = "settings",
    operation_id = "set_alarm_rules",
    summary = "Change the alarm rules",
    description = "Validated like the `--alarms` file, stored, and applied on every server \
                   process within seconds. The active alarms of a rule the change removes are \
                   cleared at the next evaluation. Not when the server runs with an `--alarms` \
                   file.",
    request_body = SetAlarmRules,
    responses(
        (status = 200, description = "The alarm rules as they are now", body = crate::schemas::AlarmRuleSettings),
        (status = 409, description = "The rules come from the server's `--alarms` file"),
        (status = 422, description = "Invalid rules (with the reason), or larger than 256 KiB"),
    ),
)]
async fn set(
    State(s): State<Arc<AppState>>,
    body: Result<Json<SetAlarmRules>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    if s.config.alarm_rules_file.is_some() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "the alarm rules are set by the server's --alarms file".into(),
        ));
    }
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    if req.yaml.len() > MAX_YAML_BYTES {
        return Err(unprocessable("the alarm rules must be at most 256 KiB"));
    }
    let rules = AlarmRules::from_yaml(&req.yaml).map_err(unprocessable)?;
    let actor = crate::actor(&s);
    let old = s
        .store
        .set_alarm_rule_set(s.config.tenant_id, &req.yaml, Some(&actor))
        .await?;
    let before = names(old.as_deref());
    let after: Vec<String> = rules.iter().map(|r| r.name.clone()).collect();
    audit(
        &s,
        "settings.alarm_rules",
        "setting",
        "alarm_rules",
        json!({
            "rules_before": before.len(),
            "rules_after": after.len(),
            "names_added": after.iter().filter(|n| !before.contains(n)).collect::<Vec<_>>(),
            "names_removed": before.iter().filter(|n| !after.contains(n)).collect::<Vec<_>>(),
        }),
    )
    .await;
    (s.config.settings_hooks.apply_alarm_rules)();
    // Own watcher applies stored rules a moment later -> show just-stored rules as effective.
    let stored = s.store.alarm_rule_set(s.config.tenant_id).await?;
    Ok(Json(rules_json(&s, &rules, stored.as_ref())))
}

#[utoipa::path(
    get,
    path = "/api/v1/settings/alarm-rules/history",
    tag = "settings",
    operation_id = "alarm_rule_history",
    summary = "Versions of the alarm rules",
    description = "The last 20 versions stored from the web, newest first.",
    responses(
        (status = 200, description = "The versions", body = crate::schemas::AlarmRuleHistory),
    ),
)]
async fn history(State(s): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let items: Vec<Value> = s
        .store
        .alarm_rule_set_history(s.config.tenant_id, HISTORY)
        .await?
        .iter()
        .map(version_json)
        .collect();
    Ok(Json(json!({ "items": items })))
}

pub(crate) fn version_json(v: &AlarmRulesVersion) -> Value {
    json!({ "yaml": v.yaml, "actor": v.actor, "at": ts(v.at) })
}
