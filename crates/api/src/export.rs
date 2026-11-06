//! CSV exports (NB-01): devices, job members, alarms -> spreadsheets, reports.
//!
//! Devices + job members: streamed page by page. Alarms: one body, max 100,000 rows.
//! Cell starts with `=`, `+`, `-`, `@`, tab or CR -> prefix `'` (no formula in a spreadsheet).

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{ApiError, AppState, DeviceQuery, audit, ts};

/// Rows per DB query.
const PAGE: i64 = 1_000;
/// Max rows per export.
const MAX_ROWS: i64 = 1_000_000;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/devices/export.csv", get(devices))
        .route("/jobs/{id}/members.csv", get(job_members))
        .route("/alarms/export.csv", get(alarms))
}

/// One CSV cell: formula-like value -> `'` prefix; quotes only when needed.
fn cell(v: &str) -> String {
    let v = if v.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{v}")
    } else {
        v.to_owned()
    };
    if v.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v
    }
}

/// One CSV line. CRLF: RFC 4180 + spreadsheets expect it.
pub(crate) fn line<S: AsRef<str>>(cells: &[S]) -> String {
    let mut out = cells
        .iter()
        .map(|c| cell(c.as_ref()))
        .collect::<Vec<_>>()
        .join(",");
    out.push_str("\r\n");
    out
}

fn opt(v: Option<&str>) -> &str {
    v.unwrap_or_default()
}

fn csv(filename: &str, body: Body) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        body,
    )
        .into_response()
}

/// Stream `header`, then pages. `page(cursor)` -> (lines, row count, next cursor).
/// Next cursor `None` -> last page. Stop after [`MAX_ROWS`] rows.
fn paged<C, F, Fut>(header: String, first: C, page: F) -> Body
where
    C: Send + 'static,
    F: Fn(C) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(String, usize, Option<C>), ApiError>> + Send,
{
    enum State<C> {
        Header(C),
        Next(C, i64),
        Done,
    }
    let page = Arc::new(page);
    let stream = futures_util::stream::unfold(State::Header(first), move |state| {
        let page = page.clone();
        let header = header.clone();
        async move {
            match state {
                State::Done => None,
                State::Header(c) => Some((Ok(Bytes::from(header)), State::Next(c, 0))),
                State::Next(_, rows) if rows >= MAX_ROWS => None,
                State::Next(c, rows) => match page(c).await {
                    Ok((text, n, next)) => {
                        let rows = rows + n as i64;
                        let state = next.map_or(State::Done, |c| State::Next(c, rows));
                        Some((Ok::<_, std::io::Error>(Bytes::from(text)), state))
                    }
                    Err(e) => {
                        tracing::warn!(error = %e.1, "CSV export stopped");
                        Some((Err(std::io::Error::other(e.1)), State::Done))
                    }
                },
            }
        }
    });
    Body::from_stream(stream)
}

#[utoipa::path(
    get,
    path = "/api/v1/devices/export.csv",
    tag = "devices",
    operation_id = "export_devices",
    summary = "Devices as CSV",
    description = "The same filters as `GET /devices`, without paging (up to 1,000,000 rows).",
    params(DeviceQuery),
    responses(
        (status = 200, description = "CSV: id, serial_number, endpoint_id, protocol, oui, product_class, manufacturer, model_name, software_version, hardware_version, status, tags (space-separated), first_seen_at, last_contact_at, last_boot_at, last_remote_addr, attributes (JSON)", content_type = "text/csv"),
    ),
)]
async fn devices(State(s): State<Arc<AppState>>, Query(q): Query<DeviceQuery>) -> Response {
    let search = match crate::device_search(q) {
        Ok(search) => search,
        Err(e) => return e.into_response(),
    };
    audit(
        &s,
        "export.devices",
        "tenant",
        s.config.tenant_id,
        json!({ "q": search.q, "protocol": search.protocol, "status": search.status,
                "product_class": search.product_class, "oui": search.oui,
                "model_name": search.model_name, "software_version": search.software_version,
                "tag": search.tag, "attr": search.attribute }),
    )
    .await;
    let header = line(&[
        "id",
        "serial_number",
        "endpoint_id",
        "protocol",
        "oui",
        "product_class",
        "manufacturer",
        "model_name",
        "software_version",
        "hardware_version",
        "status",
        "tags",
        "first_seen_at",
        "last_contact_at",
        "last_boot_at",
        "last_remote_addr",
        "attributes",
    ]);
    let body = paged(header, None, move |after: Option<Uuid>| {
        let (s, search) = (s.clone(), search.clone());
        async move {
            let rows = s
                .store
                .export_devices(s.config.tenant_id, &search, after, PAGE)
                .await?;
            let mut out = String::new();
            for d in &rows {
                out.push_str(&line(&[
                    d.id.to_string().as_str(),
                    opt(d.serial_number.as_deref()),
                    opt(d.endpoint_id.as_deref()),
                    &d.protocol,
                    opt(d.oui.as_deref()),
                    &d.product_class,
                    opt(d.manufacturer.as_deref()),
                    opt(d.model_name.as_deref()),
                    opt(d.software_version.as_deref()),
                    opt(d.hardware_version.as_deref()),
                    &d.status,
                    &d.tags.join(" "),
                    &ts(d.first_seen_at),
                    &d.last_contact_at.map(ts).unwrap_or_default(),
                    &d.last_boot_at.map(ts).unwrap_or_default(),
                    opt(d.last_remote_addr.as_deref()),
                    &d.attributes.to_string(),
                ]));
            }
            let next = (rows.len() as i64 == PAGE).then(|| rows.last().map(|d| d.id));
            Ok((out, rows.len(), next))
        }
    });
    csv("devices.csv", body)
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct StateFilter {
    /// Only rows in this state.
    #[serde(default)]
    state: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/jobs/{id}/members.csv",
    tag = "jobs",
    operation_id = "export_job_members",
    summary = "A job's devices and their outcome as CSV",
    params(
        ("id" = Uuid, Path, description = "Job ID"),
        StateFilter,
    ),
    responses(
        (status = 200, description = "CSV: device_id, device, rank, state, task_id, error, finished_at", content_type = "text/csv"),
        (status = 404, description = "Unknown job"),
    ),
)]
async fn job_members(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Query(q): Query<StateFilter>,
) -> Result<Response, ApiError> {
    crate::jobs::job_of(&s, id).await?;
    audit(
        &s,
        "export.job_members",
        "job",
        id,
        json!({ "state": q.state }),
    )
    .await;
    let header = line(&[
        "device_id",
        "device",
        "rank",
        "state",
        "task_id",
        "error",
        "finished_at",
    ]);
    let body = paged(header, 0i64, move |offset: i64| {
        let (s, state) = (s.clone(), q.state.clone());
        async move {
            let rows = s
                .store
                .list_job_members(id, state.as_deref(), PAGE, offset)
                .await?;
            let mut out = String::new();
            for m in &rows {
                out.push_str(&line(&[
                    m.device_id.to_string().as_str(),
                    opt(m.device_label.as_deref()),
                    &m.rank.to_string(),
                    &m.state,
                    &m.task_id.map(|t| t.to_string()).unwrap_or_default(),
                    opt(m.error.as_deref()),
                    &m.finished_at.map(ts).unwrap_or_default(),
                ]));
            }
            let next = (rows.len() as i64 == PAGE).then_some(offset + PAGE);
            Ok((out, rows.len(), next))
        }
    });
    Ok(csv(&format!("job-{id}.csv"), body))
}

#[utoipa::path(
    get,
    path = "/api/v1/alarms/export.csv",
    tag = "alarms",
    operation_id = "export_alarms",
    summary = "Alarms as CSV (newest first, up to 100,000)",
    params(StateFilter),
    responses(
        (status = 200, description = "CSV: id, raised_at, cleared_at, severity, rule, state, device_id, device, message, acked_at, acked_by, silenced", content_type = "text/csv"),
    ),
)]
async fn alarms(
    State(s): State<Arc<AppState>>,
    Query(q): Query<StateFilter>,
) -> Result<Response, ApiError> {
    let rows = s
        .store
        .list_alarms(
            s.config.tenant_id,
            q.state.as_deref(),
            None,
            crate::auth::caller_scope()?.as_deref(),
            100_000,
        )
        .await?;
    audit(
        &s,
        "export.alarms",
        "tenant",
        s.config.tenant_id,
        json!({ "state": q.state }),
    )
    .await;
    let ids: Vec<Uuid> = rows.iter().map(|a| a.device_id).collect();
    let labels = s.store.device_labels(&ids).await?;
    let mut out = line(&[
        "id",
        "raised_at",
        "cleared_at",
        "severity",
        "rule",
        "state",
        "device_id",
        "device",
        "message",
        "acked_at",
        "acked_by",
        "silenced",
    ]);
    for a in &rows {
        out.push_str(&line(&[
            a.id.to_string().as_str(),
            &ts(a.raised_at),
            &a.cleared_at.map(ts).unwrap_or_default(),
            &a.severity,
            &a.rule,
            &a.state,
            &a.device_id.to_string(),
            labels.get(&a.device_id).map_or("", String::as_str),
            &a.message,
            &a.acked_at.map(ts).unwrap_or_default(),
            opt(a.acked_by.as_deref()),
            if a.silenced_by.is_some() { "yes" } else { "" },
        ]));
    }
    Ok(csv("alarms.csv", Body::from(out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cells_are_quoted_and_formulas_neutralized() {
        assert_eq!(cell("plain"), "plain");
        assert_eq!(cell("a,b"), "\"a,b\"");
        assert_eq!(cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(cell("two\nlines"), "\"two\nlines\"");
        assert_eq!(cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(cell("+1"), "'+1");
        assert_eq!(cell("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(line(&["a", "b,c", ""]), "a,\"b,c\",\r\n");
    }
}
