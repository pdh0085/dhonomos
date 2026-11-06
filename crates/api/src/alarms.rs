//! Alarms (CO-07): list, ack, rules, silences (maintenance windows).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use dhonomos_core::alarms::alarm_json;
use dhonomos_store::{DeviceFilter, Silence};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::{ApiError, AppState, audit, not_found};

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/alarms", get(list))
        .route("/alarms/{id}/ack", post(ack))
        .route("/alarm-rules", get(rules))
        .route("/alarm-silences", get(list_silences).post(create_silence))
        .route("/alarm-silences/{id}", delete(end_silence))
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct AlarmQuery {
    /// `active` or `cleared`.
    #[serde(default)]
    state: Option<String>,
    /// Only alarms of this device.
    #[serde(default)]
    device_id: Option<Uuid>,
    /// Max items, 1-1000 (default 100).
    #[serde(default = "crate::default_limit")]
    limit: i64,
}

#[utoipa::path(
    get,
    path = "/api/v1/alarms",
    tag = "alarms",
    operation_id = "list_alarms",
    summary = "List alarms",
    description = "CO-07.",
    params(
        AlarmQuery,
    ),
    responses(
        (status = 200, description = "Alarms with device labels, and active counts per severity", body = crate::schemas::AlarmList),
    ),
)]
async fn list(
    State(s): State<Arc<AppState>>,
    Query(q): Query<AlarmQuery>,
) -> Result<Json<Value>, ApiError> {
    let scope = crate::auth::caller_scope()?;
    let alarms = s
        .store
        .list_alarms(
            s.config.tenant_id,
            q.state.as_deref(),
            q.device_id,
            scope.as_deref(),
            q.limit.clamp(1, 1000),
        )
        .await?;
    let ids: Vec<Uuid> = alarms.iter().map(|a| a.device_id).collect();
    let labels = s.store.device_labels(&ids).await?;
    let items: Vec<Value> = alarms
        .iter()
        .map(|a| listed_alarm_json(a, labels.get(&a.device_id)))
        .collect();
    let active: serde_json::Map<String, Value> = s
        .store
        .active_alarm_counts(s.config.tenant_id, scope.as_deref())
        .await?
        .into_iter()
        .map(|(sev, n)| (sev, json!(n)))
        .collect();
    Ok(Json(json!({ "items": items, "active": active })))
}

/// Alarm + label of its device (serial number or endpoint ID).
pub(crate) fn listed_alarm_json(a: &dhonomos_store::Alarm, device: Option<&String>) -> Value {
    let mut v = alarm_json(a);
    v["device"] = json!(device);
    v
}

#[utoipa::path(
    post,
    path = "/api/v1/alarms/{id}/ack",
    tag = "alarms",
    operation_id = "ack_alarm",
    summary = "Acknowledge an alarm",
    params(
        ("id" = Uuid, Path, description = "Alarm ID"),
    ),
    responses(
        (status = 200, description = "The alarm", body = crate::schemas::Alarm),
        (status = 404, description = "Unknown alarm"),
    ),
)]
async fn ack(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = s
        .store
        .ack_alarm(
            s.config.tenant_id,
            id,
            &crate::actor(&s),
            crate::auth::caller_scope()?.as_deref(),
        )
        .await?
        .ok_or_else(|| not_found("alarm"))?;
    audit(
        &s,
        "alarm.ack",
        "device",
        a.device_id,
        json!({ "alarm": id, "rule": a.rule }),
    )
    .await;
    Ok(Json(alarm_json(&a)))
}

#[utoipa::path(
    get,
    path = "/api/v1/alarm-rules",
    tag = "alarms",
    operation_id = "list_alarm_rules",
    summary = "Loaded alarm rules",
    responses(
        (status = 200, description = "The rules the server evaluates: from the --alarms file, or stored from the web without it", body = crate::schemas::AlarmRuleList),
    ),
)]
async fn rules(State(s): State<Arc<AppState>>) -> Json<Value> {
    let items: Vec<Value> = s
        .config
        .alarm_rules
        .get()
        .iter()
        .map(|r| serde_json::to_value(r).unwrap_or_default())
        .collect();
    Json(json!({ "items": items }))
}

/// Max silence length -> maintenance cannot quietly become "never alarm".
const MAX_SILENCE_DAYS: i64 = 30;

pub(crate) fn silence_json(x: &Silence) -> Value {
    let ts = |t: OffsetDateTime| t.format(&Rfc3339).unwrap_or_default();
    let now = OffsetDateTime::now_utc();
    let state = if now < x.starts_at {
        "pending"
    } else if now < x.ends_at {
        "active"
    } else {
        "ended"
    };
    json!({
        "id": x.id,
        "rule": x.rule,
        "devices": x.devices,
        "starts_at": ts(x.starts_at),
        "ends_at": ts(x.ends_at),
        "state": state,
        "comment": x.comment,
        "created_by": x.created_by,
        "created_at": ts(x.created_at),
    })
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct SilenceQuery {
    /// Include ended silences.
    #[serde(default)]
    all: bool,
}

#[utoipa::path(
    get,
    path = "/api/v1/alarm-silences",
    tag = "alarms",
    operation_id = "list_silences",
    summary = "List silences",
    description = "Maintenance windows (NB-07).",
    params(
        SilenceQuery,
    ),
    responses(
        (status = 200, description = "The silences", body = crate::schemas::SilenceList),
    ),
)]
async fn list_silences(
    State(s): State<Arc<AppState>>,
    Query(q): Query<SilenceQuery>,
) -> Result<Json<Value>, ApiError> {
    let scope = crate::auth::caller_scope()?;
    let items: Vec<Value> = s
        .store
        .list_silences(s.config.tenant_id, q.all)
        .await?
        .iter()
        .filter(|x| scope.as_ref().is_none_or(|sc| sc.covers(&x.devices)))
        .map(silence_json)
        .collect();
    Ok(Json(json!({ "items": items })))
}

/// Body of `POST /alarm-silences`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct NewSilence {
    /// One rule; all rules when absent.
    #[serde(default)]
    rule: Option<String>,
    /// Covered devices, as a job target filter (default: all active devices).
    #[serde(default)]
    #[schema(value_type = Object)]
    devices: DeviceFilter,
    /// RFC 3339; default now.
    #[serde(default)]
    starts_at: Option<String>,
    /// RFC 3339; or use `duration_minutes`.
    #[serde(default)]
    ends_at: Option<String>,
    /// Length in minutes, instead of `ends_at`.
    #[serde(default)]
    duration_minutes: Option<i64>,
    #[serde(default)]
    comment: String,
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

fn parse_time(field: &str, v: &str) -> Result<OffsetDateTime, ApiError> {
    OffsetDateTime::parse(v, &Rfc3339).map_err(|_| bad(format!("{field} must be an RFC 3339 time")))
}

#[utoipa::path(
    post,
    path = "/api/v1/alarm-silences",
    tag = "alarms",
    operation_id = "create_silence",
    summary = "Create a silence",
    request_body = NewSilence,
    responses(
        (status = 201, description = "The silence", body = crate::schemas::Silence),
        (status = 400, description = "Unknown rule, bad times, longer than 30 days, or devices outside the caller's scope; or malformed JSON"),
        (status = 415, description = "The body is not `application/json`"),
        (status = 422, description = "The body does not match the schema"),
    ),
)]
async fn create_silence(
    State(s): State<Arc<AppState>>,
    Json(req): Json<NewSilence>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    if let Some(rule) = &req.rule
        && !s.config.alarm_rules.get().contains(rule)
    {
        return Err(bad(format!("unknown alarm rule {rule:?}")));
    }
    let now = OffsetDateTime::now_utc();
    let starts_at = match &req.starts_at {
        Some(t) => parse_time("starts_at", t)?,
        None => now,
    };
    let ends_at = match (&req.ends_at, req.duration_minutes) {
        (Some(t), None) => parse_time("ends_at", t)?,
        (None, Some(m)) if m > 0 => starts_at + time::Duration::minutes(m),
        _ => return Err(bad("give ends_at or a positive duration_minutes")),
    };
    if ends_at <= starts_at || ends_at <= now {
        return Err(bad(
            "the silence must end after it starts and in the future",
        ));
    }
    if ends_at - starts_at > time::Duration::days(MAX_SILENCE_DAYS) {
        return Err(bad(format!(
            "a silence can last at most {MAX_SILENCE_DAYS} days"
        )));
    }
    if req.devices.expression.is_some() {
        return Err(bad(
            "silences take the fixed device conditions; filter expressions are for searches and jobs",
        ));
    }
    // Scoped caller -> only devices inside its scope.
    let devices = match crate::auth::caller_scope()? {
        None => req.devices.clone(),
        Some(scope) => scope
            .restrict(&req.devices)
            .ok_or_else(|| bad("the devices are outside your device scope"))?,
    };
    let actor = crate::actor(&s);
    let x = s
        .store
        .create_silence(
            s.config.tenant_id,
            req.rule.as_deref(),
            &devices,
            starts_at,
            ends_at,
            req.comment.trim(),
            Some(&actor),
        )
        .await?;
    audit(
        &s,
        "alarm_silence.create",
        "alarm_silence",
        x.id,
        silence_json(&x),
    )
    .await;
    Ok((StatusCode::CREATED, Json(silence_json(&x))))
}

#[utoipa::path(
    delete,
    path = "/api/v1/alarm-silences/{id}",
    tag = "alarms",
    operation_id = "end_silence",
    summary = "End a silence",
    params(
        ("id" = Uuid, Path, description = "Silence ID"),
    ),
    responses(
        (status = 200, description = "The ended silence", body = crate::schemas::Silence),
        (status = 404, description = "Unknown silence"),
    ),
)]
async fn end_silence(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    if let Some(scope) = crate::auth::caller_scope()? {
        let visible = s
            .store
            .get_silence(s.config.tenant_id, id)
            .await?
            .is_some_and(|x| scope.covers(&x.devices));
        if !visible {
            return Err(not_found("silence"));
        }
    }
    let x = s
        .store
        .end_silence(s.config.tenant_id, id)
        .await?
        .ok_or_else(|| not_found("silence"))?;
    audit(&s, "alarm_silence.end", "alarm_silence", x.id, json!({})).await;
    Ok(Json(silence_json(&x)))
}
