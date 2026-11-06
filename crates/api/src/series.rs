//! Device time series (DG-04/05): reported metrics, aggregated series,
//! URL for the BulkData reports of the device.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::{ApiError, AppState, device_of, ts};

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/devices/{id}/metrics", get(list))
        .route("/devices/{id}/metrics/series", get(series))
        .route("/devices/{id}/bulkdata-url", get(bulkdata_url))
        .route("/devices/{id}/wifi", get(wifi))
        .route("/overview", get(overview))
}

#[utoipa::path(
    get,
    path = "/api/v1/devices/{id}/metrics",
    tag = "metrics",
    operation_id = "list_device_metrics",
    summary = "Metrics a device reports",
    description = "DG-04/05.",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 200, description = "The metrics with their latest values", body = crate::schemas::MetricList),
        (status = 404, description = "Unknown device"),
    ),
)]
async fn list(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    device_of(&s, id).await?;
    let items: Vec<Value> = s
        .store
        .device_metrics(id)
        .await?
        .iter()
        .map(|m| json!({ "path": m.path, "last_ts": ts(m.last_ts), "last_value": m.last_value }))
        .collect();
    Ok(Json(json!({ "items": items })))
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct SeriesQuery {
    /// Metric (parameter) path.
    path: String,
    /// RFC 3339. Default = 24 h before `to`.
    #[serde(default)]
    from: Option<String>,
    /// RFC 3339. Default = now.
    #[serde(default)]
    to: Option<String>,
    /// Bucket size in seconds. Default -> ~200 points over the range.
    #[serde(default)]
    step: Option<i64>,
}

fn time_arg(name: &str, v: Option<&str>) -> Result<Option<OffsetDateTime>, ApiError> {
    v.map(|t| {
        OffsetDateTime::parse(t, &Rfc3339).map_err(|_| {
            ApiError(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("{name} must be an RFC 3339 time"),
            )
        })
    })
    .transpose()
}

#[utoipa::path(
    get,
    path = "/api/v1/devices/{id}/metrics/series",
    tag = "metrics",
    operation_id = "get_metric_series",
    summary = "Aggregated time series of one metric",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
        SeriesQuery,
    ),
    responses(
        (status = 200, description = "The series", body = crate::schemas::MetricSeries),
        (status = 404, description = "Unknown device"),
        (status = 422, description = "Malformed time, or a range that is empty or longer than 400 days"),
    ),
)]
async fn series(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Query(q): Query<SeriesQuery>,
) -> Result<Json<Value>, ApiError> {
    device_of(&s, id).await?;
    let to = time_arg("to", q.to.as_deref())?.unwrap_or_else(OffsetDateTime::now_utc);
    let from = time_arg("from", q.from.as_deref())?.unwrap_or(to - time::Duration::days(1));
    let span = (to - from).whole_seconds();
    if span <= 0 || span > 400 * 86_400 {
        return Err(ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "from must be before to, at most 400 days apart".into(),
        ));
    }
    // Max 2000 buckets per request.
    let step = q.step.unwrap_or(span / 200).max(span / 2_000).max(1);
    let buckets = s.store.metric_series(id, &q.path, from, to, step).await?;
    Ok(Json(json!({
        "path": q.path,
        "from": ts(from),
        "to": ts(to),
        "step": step,
        "points": buckets.iter().map(|b| json!({
            "ts": ts(b.ts), "avg": b.avg, "min": b.min, "max": b.max, "count": b.count,
        })).collect::<Vec<_>>(),
    })))
}

/// Operations overview (UI-02).
#[utoipa::path(
    get,
    path = "/api/v1/overview",
    tag = "overview",
    operation_id = "get_overview",
    summary = "Fleet overview",
    description = "UI-02.",
    responses(
        (status = 200, description = "The overview", body = crate::schemas::Overview),
    ),
)]
async fn overview(State(s): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let scope = crate::auth::caller_scope()?;
    let o = s
        .store
        .overview(s.config.tenant_id, scope.as_deref())
        .await?;
    let alarms = s
        .store
        .active_alarm_counts(s.config.tenant_id, scope.as_deref())
        .await?;
    Ok(Json(overview_json(&o, &alarms)))
}

/// Overview JSON + active alarm counts per severity.
pub(crate) fn overview_json(o: &dhonomos_store::Overview, alarms: &[(String, i64)]) -> Value {
    let pairs = |v: &[(String, i64)]| {
        v.iter()
            .map(|(k, n)| (k.clone(), json!(n)))
            .collect::<serde_json::Map<_, _>>()
    };
    json!({
        "active": o.active,
        "online": { "m15": o.online.0, "h1": o.online.1, "d1": o.online.2 },
        "by_protocol": pairs(&o.by_protocol),
        "by_status": pairs(&o.by_status),
        "sessions_per_minute": o.sessions_per_minute.iter()
            .map(|(t, n)| json!({ "ts": ts(*t), "n": n })).collect::<Vec<_>>(),
        "tasks": pairs(&o.tasks),
        "jobs_running": o.jobs_running,
        "versions": o.versions.iter().map(|(v, n)| json!({ "version": v, "n": n })).collect::<Vec<_>>(),
        "alarms": pairs(alarms),
    })
}

/// Wi-Fi view (DG-02): radios, networks, stations (snapshot) + latest neighbour scan.
#[utoipa::path(
    get,
    path = "/api/v1/devices/{id}/wifi",
    tag = "metrics",
    operation_id = "get_wifi",
    summary = "Wi-Fi radios, networks, stations and the latest neighbour scan",
    description = "DG-02.",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 200, description = "Radios, networks with their stations, and the latest neighbour scan", body = crate::schemas::WifiView),
        (status = 404, description = "Unknown device"),
    ),
)]
async fn wifi(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    device_of(&s, id).await?;
    let mut params = s.store.get_params(id, "Device.WiFi.").await?;
    params.extend(
        s.store
            .get_params(id, "InternetGatewayDevice.LANDevice.")
            .await?,
    );
    let scan = s
        .store
        .latest_succeeded_task(id, "diagnostic", &json!({ "test": "wifi_neighbors" }))
        .await?;
    Ok(Json(wifi_json(&params, scan.as_ref())))
}

/// Wi-Fi view JSON + latest neighbour scan task.
pub(crate) fn wifi_json(
    params: &[dhonomos_store::StoredParam],
    scan: Option<&dhonomos_store::Task>,
) -> Value {
    let mut v = dhonomos_core::wifi::view(params);
    v["neighbor_scan"] = match scan {
        Some(t) => json!({
            "task_id": t.id,
            "at": ts(t.created_at),
            "neighbors": t.result.as_ref().map(|r| r["result"]["neighbors"].clone()),
        }),
        None => Value::Null,
    };
    v
}

#[utoipa::path(
    get,
    path = "/api/v1/devices/{id}/bulkdata-url",
    tag = "metrics",
    operation_id = "get_bulkdata_url",
    summary = "Where the device posts BulkData reports",
    description = "The URL carries a signature that does not expire and lets anyone holding it post reports as the device, so it needs the `operator` role.",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 200, description = "The URL", body = crate::schemas::BulkDataUrl),
        (status = 404, description = "Unknown device, or the device-facing file server is not configured"),
    ),
)]
async fn bulkdata_url(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    device_of(&s, id).await?;
    let files = s.config.files.as_ref().ok_or_else(|| {
        ApiError(
            StatusCode::NOT_FOUND,
            "the device-facing file server is not configured".into(),
        )
    })?;
    Ok(Json(json!({ "url": files.signer.bulkdata_url(id) })))
}
