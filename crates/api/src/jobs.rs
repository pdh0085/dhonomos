//! Bulk jobs + firmware campaigns (CO-15, FW-02/03). Design: docs/design/05-bulk-jobs.md.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use dhonomos_core::TaskKind;
use dhonomos_jobs::Policy;
use dhonomos_store::{DeviceFilter, Job, NewJob};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{ApiError, AppState, Page, audit, device_json, not_found, ts};

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/jobs", get(list).post(create))
        .route("/jobs/preview", post(preview))
        .route("/jobs/{id}", get(detail))
        .route("/jobs/{id}/devices", get(members))
        .route("/jobs/{id}/{action}", post(control))
}

fn unprocessable(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg.into())
}

/// Body of `POST /jobs/preview`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct Preview {
    /// Device filter: optional `protocol`, `oui`, `product_class`, `status` (default `active`),
    /// lists `software_version` (any of), `tags` (all of), `device_ids`, `attributes`,
    /// filter `expression` (resolved at job start).
    #[schema(value_type = Object)]
    target: DeviceFilter,
}

#[utoipa::path(
    post,
    path = "/api/v1/jobs/preview",
    tag = "jobs",
    operation_id = "preview_job_target",
    summary = "Devices a target filter selects",
    request_body = Preview,
    responses(
        (status = 200, description = "Matching devices", body = crate::schemas::JobPreview),
        (status = 422, description = "Invalid body, or a target outside the caller's device scope"),
    ),
)]
async fn preview(
    State(s): State<Arc<AppState>>,
    body: Result<Json<Preview>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    let target = scoped_target(&req.target)?;
    let (count, sample) = s
        .store
        .preview_devices(s.config.tenant_id, &target, 20)
        .await?;
    Ok(Json(json!({
        "count": count,
        "sample": sample.iter().map(|d| device_json(&s, d)).collect::<Vec<_>>(),
    })))
}

/// Body of `POST /jobs`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct CreateJob {
    name: String,
    /// Device filter, as in `POST /jobs/preview`.
    #[schema(value_type = Object)]
    target: DeviceFilter,
    /// Task for each member.
    #[schema(value_type = crate::openapi::TaskSpec)]
    task: TaskKind,
    /// Rollout policy (all optional): `stages` (cumulative %, last = 100), `max_in_flight`,
    /// `batch_size`, `window`, `abort_failure_rate`, `min_samples`, `gate_success_rate`,
    /// `auto_advance`, `task` options, `verify` (firmware version).
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    policy: Option<Value>,
    /// Start at once (default true); else job stays a draft.
    #[serde(default = "crate::yes")]
    start: bool,
}

pub(crate) fn job_json(j: &Job, counts: Option<&dhonomos_store::JobCounts>) -> Value {
    let mut v = json!({
        "id": j.id,
        "name": j.name,
        "target": j.target,
        "task": { "kind": j.task_kind, "payload": crate::redact_task(&j.task_kind, &j.task_payload) },
        "policy": j.policy,
        "state": j.state,
        "stage": j.stage,
        "reason": j.reason,
        "total": j.total,
        "created_by": j.created_by,
        "created_at": ts(j.created_at),
        "started_at": j.started_at.map(ts),
        "finished_at": j.finished_at.map(ts),
    });
    if let Some(c) = counts {
        let states = [
            "queued",
            "dispatched",
            "verifying",
            "succeeded",
            "failed",
            "cancelled",
        ];
        v["counts"] = states
            .iter()
            .map(|st| ((*st).to_owned(), json!(c.total(st))))
            .collect::<serde_json::Map<_, _>>()
            .into();
        v["stage_counts"] = states
            .iter()
            .map(|st| ((*st).to_owned(), json!(c.in_stage(st))))
            .collect::<serde_json::Map<_, _>>()
            .into();
    }
    v
}

fn policy_of(j: &Job) -> Policy {
    serde_json::from_value(j.policy.clone()).unwrap_or_default()
}

#[utoipa::path(
    post,
    path = "/api/v1/jobs",
    tag = "jobs",
    operation_id = "create_job",
    summary = "Create a bulk job",
    description = "CO-15, FW-02/03.",
    request_body = CreateJob,
    responses(
        (status = 201, description = "The job", body = crate::schemas::Job),
        (status = 422, description = "Invalid body, name, policy or task, a target outside the caller's device scope, a secret value starting with `enc:`, a download of a file a device uploaded to a target other than that device, or a password without `--secrets-key`"),
        (status = 500, description = "The password could not be encrypted"),
    ),
)]
async fn create(
    State(s): State<Arc<AppState>>,
    body: Result<Json<CreateJob>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    if req.name.trim().is_empty() {
        return Err(unprocessable("name is required"));
    }
    let policy: Policy = match req.policy {
        Some(p) => serde_json::from_value(p).map_err(|e| unprocessable(format!("policy: {e}")))?,
        None => Policy::default(),
    };
    policy.validate().map_err(unprocessable)?;
    req.task.validate().map_err(unprocessable)?;
    let target = scoped_target(&req.target)?;
    let (kind, mut payload) = req.task.to_row();
    dhonomos_core::secrets::reject_ciphertext_input(&payload).map_err(unprocessable)?;
    // File uploaded by a device -> back to that device only: job target must be just it.
    if let Some(file) = crate::download_file(&s, &req.task).await?
        && file
            .device_id
            .is_some_and(|owner| target.device_ids != [owner])
    {
        return Err(unprocessable(format!(
            "{} (a job can send it only with a target of just that device)",
            dhonomos_core::files::not_for_other_devices(file.id)
        )));
    }
    // Secrets bound to the job -> ID chosen before sealing.
    let id = Uuid::now_v7();
    if dhonomos_core::secrets::has_plain_secret(&payload) {
        let secrets = s.config.secrets.as_ref().ok_or_else(|| {
            unprocessable("storing passwords requires the server to run with --secrets-key")
        })?;
        secrets
            .encrypt_fields(&mut payload, &dhonomos_core::secrets::job_context(id))
            .map_err(|e| {
                tracing::error!(error = %e, "encrypting job secrets failed");
                ApiError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not protect the password".into(),
                )
            })?;
    }
    let id = s
        .store
        .create_job_with_id(
            id,
            &NewJob {
                tenant_id: s.config.tenant_id,
                name: req.name.trim().to_owned(),
                target: target.clone(),
                task_kind: kind.clone(),
                task_payload: payload,
                policy: serde_json::to_value(&policy).unwrap_or_default(),
                created_by: Some(
                    crate::auth::ACTOR
                        .try_with(Clone::clone)
                        .unwrap_or_else(|_| "api".into()),
                ),
            },
        )
        .await?;
    audit(
        &s,
        "job.create",
        "job",
        id,
        json!({ "name": req.name, "kind": kind, "target": target }),
    )
    .await;
    if req.start {
        s.store.start_job(id, &target).await?;
        audit(&s, "job.start", "job", id, json!({})).await;
    }
    let j = job_of(&s, id).await?;
    let counts = s.store.job_counts(id, j.total).await?;
    Ok((StatusCode::CREATED, Json(job_json(&j, Some(&counts)))))
}

/// Target narrowed to the caller's device scope (ADR-074); 422 if nothing can match.
fn scoped_target(target: &DeviceFilter) -> Result<DeviceFilter, ApiError> {
    if let Some(e) = &target.expression {
        dhonomos_store::FilterExpr::parse(e).map_err(|e| unprocessable(e.to_string()))?;
    }
    match crate::auth::caller_scope()? {
        None => Ok(target.clone()),
        Some(scope) => scope
            .restrict(target)
            .ok_or_else(|| unprocessable("the target is outside your device scope")),
    }
}

/// Job visible = whole job target inside the caller's scope.
fn visible(scope: Option<&dhonomos_store::DeviceScope>, j: &Job) -> bool {
    scope.is_none_or(|s| {
        serde_json::from_value::<DeviceFilter>(j.target.clone()).is_ok_and(|f| s.covers(&f))
    })
}

pub(crate) async fn job_of(s: &AppState, id: Uuid) -> Result<Job, ApiError> {
    let scope = crate::auth::caller_scope()?;
    s.store
        .get_job(id)
        .await?
        .filter(|j| j.tenant_id == s.config.tenant_id)
        .filter(|j| visible(scope.as_deref(), j))
        .ok_or_else(|| not_found("job"))
}

#[utoipa::path(
    get,
    path = "/api/v1/jobs",
    tag = "jobs",
    operation_id = "list_jobs",
    summary = "List bulk jobs",
    params(
        ("limit" = Option<i64>, Query, description = "Maximum items, 1-1000 (default 100)"),
    ),
    responses(
        (status = 200, description = "The jobs, newest first", body = crate::schemas::JobList),
    ),
)]
async fn list(
    State(s): State<Arc<AppState>>,
    Query(page): Query<Page>,
) -> Result<Json<Value>, ApiError> {
    let scope = crate::auth::caller_scope()?;
    let jobs = s
        .store
        .list_jobs(s.config.tenant_id, page.clamp().0)
        .await?;
    let mut items = Vec::with_capacity(jobs.len());
    for j in jobs.iter().filter(|j| visible(scope.as_deref(), j)) {
        let counts = s.store.job_counts(j.id, j.total).await?;
        items.push(job_json(j, Some(&counts)));
    }
    Ok(Json(json!({ "items": items })))
}

#[utoipa::path(
    get,
    path = "/api/v1/jobs/{id}",
    tag = "jobs",
    operation_id = "get_job",
    summary = "Job progress",
    params(
        ("id" = Uuid, Path, description = "Job ID"),
    ),
    responses(
        (status = 200, description = "The job with its stage details", body = crate::schemas::JobDetail),
        (status = 404, description = "Unknown job"),
    ),
)]
async fn detail(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let j = job_of(&s, id).await?;
    let policy = policy_of(&j);
    let limit = policy.stage_limit(usize::try_from(j.stage).unwrap_or(0), j.total);
    let counts = s.store.job_counts(id, limit).await?;
    Ok(Json(job_detail_json(&j, &counts, limit, &policy)))
}

/// Job + counts within the stage that ends at member rank `limit`.
pub(crate) fn job_detail_json(
    j: &Job,
    counts: &dhonomos_store::JobCounts,
    limit: i32,
    policy: &Policy,
) -> Value {
    let mut v = job_json(j, Some(counts));
    v["stage_limit"] = json!(limit);
    v["stages"] = json!(policy.stages);
    v
}

// Not `#[serde(flatten)] Page`: flatten breaks number parsing in query strings.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct MemberQuery {
    /// `queued`, `dispatched`, `verifying`, `succeeded`, `failed` or `cancelled`.
    #[serde(default)]
    state: Option<String>,
    /// Page size, 1-1000 (default 100).
    #[serde(default = "crate::default_limit")]
    limit: i64,
    /// Items to skip.
    #[serde(default)]
    offset: i64,
}

#[utoipa::path(
    get,
    path = "/api/v1/jobs/{id}/devices",
    tag = "jobs",
    operation_id = "list_job_members",
    summary = "Job members",
    params(
        ("id" = Uuid, Path, description = "Job ID"),
        MemberQuery,
    ),
    responses(
        (status = 200, description = "The members, in dispatch order", body = crate::schemas::JobMemberList),
        (status = 404, description = "Unknown job"),
    ),
)]
async fn members(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Query(q): Query<MemberQuery>,
) -> Result<Json<Value>, ApiError> {
    job_of(&s, id).await?;
    let (limit, offset) = Page {
        limit: q.limit,
        offset: q.offset,
    }
    .clamp();
    let rows = s
        .store
        .list_job_members(id, q.state.as_deref(), limit, offset)
        .await?;
    Ok(Json(json!({
        "items": rows.iter().map(member_json).collect::<Vec<_>>(),
    })))
}

pub(crate) fn member_json(m: &dhonomos_store::JobMember) -> Value {
    json!({
        "device_id": m.device_id,
        "device": m.device_label,
        "rank": m.rank,
        "state": m.state,
        "task_id": m.task_id,
        "error": m.error,
        "finished_at": m.finished_at.map(ts),
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/jobs/{id}/{action}",
    tag = "jobs",
    operation_id = "control_job",
    summary = "Start, pause, resume, approve or cancel a job",
    params(
        ("id" = Uuid, Path, description = "Job ID"),
        ("action" = String, Path, description = "`start`, `pause`, `resume`, `approve` (next stage) or `cancel`"),
    ),
    responses(
        (status = 200, description = "The job after the change", body = crate::schemas::JobDetail),
        (status = 404, description = "Unknown job or action"),
        (status = 409, description = "The action does not apply to the job's state or stage"),
    ),
)]
async fn control(
    State(s): State<Arc<AppState>>,
    Path((id, action)): Path<(Uuid, String)>,
) -> Result<Json<Value>, ApiError> {
    let j = job_of(&s, id).await?;
    let conflict = |msg: String| ApiError(StatusCode::CONFLICT, msg);
    let changed = match action.as_str() {
        "start" => {
            let target: DeviceFilter = serde_json::from_value(j.target.clone()).unwrap_or_default();
            s.store.start_job(id, &target).await?.is_some()
        }
        "pause" => {
            s.store
                .transition_job(id, &["running"], "paused", Some("paused by operator"), None)
                .await?
        }
        "resume" => {
            s.store
                .transition_job(id, &["paused"], "running", None, None)
                .await?
        }
        "approve" => {
            let stages = policy_of(&j).stages.len();
            let next = j.stage + 1;
            if usize::try_from(next).unwrap_or(usize::MAX) >= stages {
                return Err(conflict(
                    "the job is already in its last stage; use resume".into(),
                ));
            }
            s.store
                .transition_job(id, &["paused"], "running", None, Some(next))
                .await?
        }
        "cancel" => {
            let done = s
                .store
                .transition_job(
                    id,
                    &["draft", "running", "paused"],
                    "cancelled",
                    Some("cancelled by operator"),
                    None,
                )
                .await?;
            if done {
                s.store.cancel_job_members(id).await?;
            }
            done
        }
        _ => return Err(not_found("job action")),
    };
    if !changed {
        return Err(conflict(format!(
            "cannot {action} a job that is {}",
            j.state
        )));
    }
    audit(
        &s,
        &format!("job.{action}"),
        "job",
        id,
        json!({ "from": j.state }),
    )
    .await;
    detail(State(s), Path(id)).await
}
