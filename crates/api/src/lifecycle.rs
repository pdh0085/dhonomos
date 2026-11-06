//! Config backups + restore (CO-08), device replace + delete (CO-14).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use dhonomos_core::UploadKind;
use dhonomos_core::config::{BackupValue, diff, restore_tasks, snapshot};
use dhonomos_store::{CertificateTarget, ConfigBackup, Device, NewTask};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{ApiError, AppState, actor, audit, device_of, not_found, ts};

/// Values per SPV on restore.
const RESTORE_CHUNK: usize = 100;
/// Max devices per `POST /devices/delete`.
const MAX_DELETE: usize = 1000;
/// Max `POST /devices/delete` body: 1000 UUIDs + room for the rest.
const MAX_DELETE_BODY_BYTES: usize = 128 << 10;
/// Max devices named in a refusal.
const MAX_REPORTED: usize = 20;
/// Max devices named in the audit record of a bulk delete.
const AUDIT_SAMPLE: usize = 10;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/devices/{id}/config-backups",
            get(list_backups).post(create_backup),
        )
        .route(
            "/config-backups/{id}",
            get(get_backup).delete(delete_backup),
        )
        .route("/config-backups/{id}/diff", get(backup_diff))
        .route("/config-backups/{id}/restore", post(restore))
        .route("/devices/{id}/replace", post(replace))
        .route(
            "/devices/delete",
            post(delete_devices).layer(DefaultBodyLimit::max(MAX_DELETE_BODY_BYTES)),
        )
        .route(
            "/devices/{id}/config-files",
            get(list_config_files).post(request_config_file),
        )
        .route(
            "/devices/{id}/log-files",
            get(list_log_files).post(request_log_file),
        )
}

fn unprocessable(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg.into())
}

pub(crate) fn backup_json(b: &ConfigBackup, with_values: bool) -> Value {
    let mut v = json!({
        "id": b.id,
        "device_id": b.device_id,
        "label": b.label,
        "count": b.params.as_array().map_or(0, Vec::len),
        "created_by": b.created_by,
        "created_at": ts(b.created_at),
    });
    if with_values {
        v["values"] = b.params.clone();
    }
    v
}

/// Backup, if the caller sees its device (`device_of`).
/// Device deleted -> unscoped callers only.
async fn backup_of(s: &AppState, id: Uuid) -> Result<ConfigBackup, ApiError> {
    let b = s
        .store
        .get_backup(id)
        .await?
        .filter(|b| b.tenant_id == s.config.tenant_id)
        .ok_or_else(|| not_found("backup"))?;
    match device_of(s, b.device_id).await {
        Ok(_) => Ok(b),
        Err(_) if crate::auth::caller_scope()?.is_none() => Ok(b),
        Err(_) => Err(not_found("backup")),
    }
}

fn values_of(b: &ConfigBackup) -> Vec<BackupValue> {
    serde_json::from_value(b.params.clone()).unwrap_or_default()
}

/// Backup of `device` from its param snapshot.
async fn take_backup(
    s: &AppState,
    device: &Device,
    label: &str,
) -> Result<(ConfigBackup, Value), ApiError> {
    let params = s.store.get_params(device.id, "").await?;
    let model = s.store.device_supported_model(device.id).await?;
    let snap = snapshot(&params, model.as_ref().map(|m| &m.model));
    if snap.values.is_empty() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            format!(
                "no writable values known for this device ({} of unknown writability); \
                 read its parameter names first (task get_parameter_names)",
                snap.unknown_writability
            ),
        ));
    }
    let id = s
        .store
        .create_backup(
            s.config.tenant_id,
            device.id,
            label,
            &serde_json::to_value(&snap.values).unwrap_or_default(),
            Some("api"),
        )
        .await?;
    let b = backup_of(s, id).await?;
    let notes = json!({
        "skipped_secrets": snap.skipped_secrets,
        "unknown_writability": snap.unknown_writability,
    });
    Ok((b, notes))
}

/// Body of `POST /devices/{id}/config-backups`.
#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct CreateBackup {
    #[serde(default)]
    label: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/devices/{id}/config-backups",
    tag = "backups",
    operation_id = "create_backup",
    summary = "Take a configuration backup",
    description = "From the device's parameter snapshot (CO-08). The body is optional.",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    request_body = Option<CreateBackup>,
    responses(
        (status = 201, description = "The backup", body = crate::schemas::CreatedBackup),
        (status = 404, description = "Unknown device"),
        (status = 409, description = "No writable values are known for the device"),
    ),
)]
async fn create_backup(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    body: Option<Json<CreateBackup>>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let device = device_of(&s, id).await?;
    let (b, notes) = take_backup(&s, &device, req.label.trim()).await?;
    audit(
        &s,
        "device.backup",
        "device",
        id,
        json!({ "backup": b.id, "count": backup_json(&b, false)["count"] }),
    )
    .await;
    let mut v = backup_json(&b, false);
    v["notes"] = notes;
    Ok((StatusCode::CREATED, Json(v)))
}

#[utoipa::path(
    get,
    path = "/api/v1/devices/{id}/config-backups",
    tag = "backups",
    operation_id = "list_backups",
    summary = "A device's configuration backups",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 200, description = "The backups", body = crate::schemas::BackupList),
        (status = 404, description = "Unknown device"),
    ),
)]
async fn list_backups(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    device_of(&s, id).await?;
    let items: Vec<Value> = s
        .store
        .list_backups(id)
        .await?
        .iter()
        .map(|b| backup_json(b, false))
        .collect();
    Ok(Json(json!({ "items": items })))
}

#[utoipa::path(
    get,
    path = "/api/v1/config-backups/{id}",
    tag = "backups",
    operation_id = "get_backup",
    summary = "Backup with its values",
    params(
        ("id" = Uuid, Path, description = "Backup ID"),
    ),
    responses(
        (status = 200, description = "The backup with its values", body = crate::schemas::ConfigBackupValues),
        (status = 404, description = "Unknown backup"),
    ),
)]
async fn get_backup(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(backup_json(&backup_of(&s, id).await?, true)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/config-backups/{id}",
    tag = "backups",
    operation_id = "delete_backup",
    summary = "Delete a backup",
    params(
        ("id" = Uuid, Path, description = "Backup ID"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Unknown backup"),
    ),
)]
async fn delete_backup(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let b = backup_of(&s, id).await?;
    s.store.delete_backup(id).await?;
    audit(
        &s,
        "device.backup.delete",
        "device",
        b.device_id,
        json!({ "backup": id }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct DiffQuery {
    /// Compare with this device (default: device of the backup).
    #[serde(default)]
    device_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/config-backups/{id}/diff",
    tag = "backups",
    operation_id = "diff_backup",
    summary = "Drift between a backup and a device",
    params(
        ("id" = Uuid, Path, description = "Backup ID"),
        DiffQuery,
    ),
    responses(
        (status = 200, description = "The differences", body = crate::schemas::BackupDiff),
        (status = 404, description = "Unknown backup or device"),
    ),
)]
async fn backup_diff(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Query(q): Query<DiffQuery>,
) -> Result<Json<Value>, ApiError> {
    let b = backup_of(&s, id).await?;
    let device = device_of(&s, q.device_id.unwrap_or(b.device_id)).await?;
    let current = s.store.get_params(device.id, "").await?;
    let mut d = diff(&values_of(&b), &current);
    d["device_id"] = json!(device.id);
    Ok(Json(d))
}

/// Queue backup values on `target` -> task IDs.
async fn queue_restore(
    s: &AppState,
    b: &ConfigBackup,
    target: &Device,
    origin: &str,
) -> Result<Vec<Uuid>, ApiError> {
    let source = device_of(s, b.device_id).await.ok();
    if let Some(src) = &source
        && (src.protocol != target.protocol || src.data_model != target.data_model)
    {
        return Err(unprocessable(
            "the backup is from a device with another protocol or data model",
        ));
    }
    let mut ids = Vec::new();
    for (i, task) in restore_tasks(&values_of(b), RESTORE_CHUNK)
        .iter()
        .enumerate()
    {
        let (kind, payload) = task.to_row();
        let new = NewTask {
            priority: 10,
            idempotency_key: Some(format!(
                "restore:{}:{}:{i}:{}",
                b.id,
                target.id,
                Uuid::now_v7()
            )),
            created_by: Some(origin.to_owned()),
            ..NewTask::new(s.config.tenant_id, target.id, kind, payload)
        };
        ids.push(s.store.enqueue_task(&new).await?.0);
    }
    if let Some(w) = &s.config.waker {
        w.wake(target.id).await;
    }
    Ok(ids)
}

/// Body of `POST /config-backups/{id}/restore`.
#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct Restore {
    /// Restore onto this device (default: device of the backup).
    #[serde(default)]
    device_id: Option<Uuid>,
}

#[utoipa::path(
    post,
    path = "/api/v1/config-backups/{id}/restore",
    tag = "backups",
    operation_id = "restore_backup",
    summary = "Restore a backup onto a device",
    description = "The body is optional.",
    params(
        ("id" = Uuid, Path, description = "Backup ID"),
    ),
    request_body = Option<Restore>,
    responses(
        (status = 200, description = "The queued tasks", body = crate::schemas::RestoreResult),
        (status = 404, description = "Unknown backup or device"),
        (status = 422, description = "The backup is from a device with another protocol or data model"),
    ),
)]
async fn restore(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    body: Option<Json<Restore>>,
) -> Result<Json<Value>, ApiError> {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let b = backup_of(&s, id).await?;
    let target = device_of(&s, req.device_id.unwrap_or(b.device_id)).await?;
    let tasks = queue_restore(&s, &b, &target, &format!("restore:{}", b.id)).await?;
    audit(
        &s,
        "device.restore",
        "device",
        target.id,
        json!({ "backup": b.id, "tasks": tasks.len() }),
    )
    .await;
    Ok(Json(json!({ "device_id": target.id, "tasks": tasks })))
}

/// Body of `POST /devices/{id}/replace`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct Replace {
    /// New unit, takes over.
    new_device_id: Uuid,
}

/// Replace (CO-14): back up old unit -> tags to new -> restore onto new -> retire old.
#[utoipa::path(
    post,
    path = "/api/v1/devices/{id}/replace",
    tag = "backups",
    operation_id = "replace_device",
    summary = "Replace a unit",
    description = "Back up the old unit, carry its tags over, restore onto the new one, retire the old one (CO-14).",
    params(
        ("id" = Uuid, Path, description = "ID of the device being replaced"),
    ),
    request_body = Replace,
    responses(
        (status = 200, description = "The replacement", body = crate::schemas::Replacement),
        (status = 404, description = "Unknown old or new device"),
        (status = 409, description = "No writable values are known for the old device"),
        (status = 422, description = "Invalid body, the same device, or another protocol or data model"),
    ),
)]
async fn replace(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    body: Result<Json<Replace>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    if req.new_device_id == id {
        return Err(unprocessable("a device cannot replace itself"));
    }
    let old = device_of(&s, id).await?;
    let new = device_of(&s, req.new_device_id).await?;
    if old.protocol != new.protocol || old.data_model != new.data_model {
        return Err(unprocessable(
            "the new device must use the same protocol and data model",
        ));
    }
    let (backup, notes) = take_backup(&s, &old, "replacement").await?;
    s.store.add_tags(new.id, &old.tags).await?;
    let tasks = queue_restore(&s, &backup, &new, &format!("replace:{}", old.id)).await?;
    s.store
        .set_device_status(s.config.tenant_id, old.id, "retired")
        .await?;
    if let Some(broker) = &s.config.broker
        && let Ok(Some(d)) = s.store.get_device(old.id).await
        && let Err(e) = broker.apply_status(&s.store, &d).await
    {
        tracing::warn!(device = %old.id, error = %e, "disabling the old broker account failed");
    }
    let label = |d: &Device| d.serial_number.clone().or(d.endpoint_id.clone());
    s.store
        .record_event(
            s.config.tenant_id,
            Some(old.id),
            "replaced_by",
            &json!({ "device_id": new.id, "device": label(&new) }),
        )
        .await?;
    s.store
        .record_event(
            s.config.tenant_id,
            Some(new.id),
            "replaces",
            &json!({ "device_id": old.id, "device": label(&old), "backup": backup.id }),
        )
        .await?;
    audit(
        &s,
        "device.replace",
        "device",
        old.id,
        json!({ "new_device_id": new.id, "backup": backup.id, "tasks": tasks.len() }),
    )
    .await;
    Ok(Json(json!({
        "backup": backup_json(&backup, false),
        "notes": notes,
        "tags": old.tags,
        "tasks": tasks,
        "retired": old.id,
    })))
}

/// Ask device to upload its vendor config file (CO-08).
/// CWMP Upload or USP `VendorConfigFile.{i}.Backup()`.
/// -> file server, as `3 Vendor Configuration File` of the device.
#[utoipa::path(
    post,
    path = "/api/v1/devices/{id}/config-files",
    tag = "backups",
    operation_id = "request_config_file",
    summary = "Ask the device to upload its vendor configuration file",
    description = "CWMP Upload or USP `VendorConfigFile.{i}.Backup()` (CO-08).",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 202, description = "The upload is queued", body = crate::schemas::ConfigFileRequest),
        (status = 404, description = "Unknown device, or the file server is not configured"),
    ),
)]
async fn request_config_file(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    request_upload(&s, id, UploadKind::Config).await
}

/// Ask device to upload its vendor log file (CO-08).
/// CWMP Upload `2 Vendor Log File` or USP `VendorLogFile.{i}.Upload()`.
/// -> file server, as `2 Vendor Log File` of the device.
#[utoipa::path(
    post,
    path = "/api/v1/devices/{id}/log-files",
    tag = "backups",
    operation_id = "request_log_file",
    summary = "Ask the device to upload its vendor log file",
    description = "CWMP Upload or USP `VendorLogFile.{i}.Upload()` (CO-08).",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 202, description = "The upload is queued", body = crate::schemas::ConfigFileRequest),
        (status = 404, description = "Unknown device, or the file server is not configured"),
    ),
)]
async fn request_log_file(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    request_upload(&s, id, UploadKind::Log).await
}

/// Queue Upload of `kind` to a signed file server link + wake device.
async fn request_upload(
    s: &Arc<AppState>,
    id: Uuid,
    kind: UploadKind,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    device_of(s, id).await?;
    let files = s.config.files.as_ref().ok_or_else(|| {
        ApiError(
            StatusCode::NOT_FOUND,
            "the file server is not configured".into(),
        )
    })?;
    let upload = Uuid::now_v7();
    let task = dhonomos_core::TaskKind::Upload {
        file_type: kind.upload_file_type().into(),
        url: files.signer.upload_url(id, upload, kind),
        username: String::new(),
        password: String::new(),
        delay_seconds: 0,
    };
    let (task_kind, payload) = task.to_row();
    let (key, action) = match kind {
        UploadKind::Config => ("config-file", "device.config_file.request"),
        UploadKind::Log => ("log-file", "device.log_file.request"),
    };
    let new = NewTask {
        priority: 5,
        idempotency_key: Some(format!("{key}:{upload}")),
        created_by: Some("api".into()),
        ..NewTask::new(s.config.tenant_id, id, task_kind, payload)
    };
    let (task_id, _) = s.store.enqueue_task(&new).await?;
    let wake = match &s.config.waker {
        Some(w) => w.wake(id).await.describe(),
        None => "skipped".into(),
    };
    audit(
        s,
        action,
        "device",
        id,
        json!({ "upload": upload, "task": task_id }),
    )
    .await;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "task_id": task_id, "file_id": upload, "connection_request": wake })),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/devices/{id}/config-files",
    tag = "backups",
    operation_id = "list_config_files",
    summary = "Vendor configuration files the device uploaded",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 200, description = "The files", body = crate::schemas::FileList),
        (status = 404, description = "Unknown device"),
    ),
)]
async fn list_config_files(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    device_files(&s, id, UploadKind::Config).await
}

#[utoipa::path(
    get,
    path = "/api/v1/devices/{id}/log-files",
    tag = "backups",
    operation_id = "list_log_files",
    summary = "Vendor log files the device uploaded",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 200, description = "The files", body = crate::schemas::FileList),
        (status = 404, description = "Unknown device"),
    ),
)]
async fn list_log_files(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    device_files(&s, id, UploadKind::Log).await
}

/// Uploaded files of the device, one kind, newest first.
async fn device_files(s: &AppState, id: Uuid, kind: UploadKind) -> Result<Json<Value>, ApiError> {
    device_of(s, id).await?;
    let items: Vec<Value> = s
        .store
        .list_device_files(id)
        .await?
        .iter()
        .filter(|f| f.file_type == kind.stored_file_type())
        .map(crate::files::file_json)
        .collect();
    Ok(Json(json!({ "items": items })))
}

/// `DELETE /devices/{id}`: retired devices only -> all their data removed.
#[utoipa::path(
    delete,
    path = "/api/v1/devices/{id}",
    tag = "devices",
    operation_id = "delete_device",
    summary = "Delete a retired device and all its data",
    description = "CO-14. The device's Agent certificates stay valid after it is gone, so they are revoked first (reason `device deleted`) and their records are kept without a device: the MTPs keep refusing them. The `device.delete` audit record counts them in `certificates_revoked`.",
    params(
        ("id" = Uuid, Path, description = "Device ID"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Unknown device"),
        (status = 409, description = "The device is not retired"),
        (status = 502, description = "The USP Agent's broker account could not be removed"),
    ),
)]
pub(crate) async fn delete_device(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let d = device_of(&s, id).await?;
    if d.status != "retired" {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "retire the device before deleting it".into(),
        ));
    }
    if let Some(broker) = &s.config.broker
        && d.protocol == "usp"
        && let Err(e) = broker.revoke(&s.store, &d).await
    {
        return Err(ApiError(
            StatusCode::BAD_GATEWAY,
            format!("the broker account could not be removed: {e}"),
        ));
    }
    // Uploaded files (config backups, logs) go too, content included.
    // Agent certs stay valid -> revoked first, records kept.
    let by = actor(&s);
    let deleted = s
        .store
        .delete_device(s.config.tenant_id, id, Some(&by))
        .await?
        .unwrap_or_default();
    remove_stored_files(&s, &deleted.files).await;
    audit(
        &s,
        "device.delete",
        "device",
        id,
        json!({ "serial_number": d.serial_number, "endpoint_id": d.endpoint_id,
                "files": deleted.files.len(),
                "certificates_revoked": deleted.certificates_revoked }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Delete stored content of deleted file records. File already gone = no error.
async fn remove_stored_files(s: &AppState, files: &[Uuid]) {
    if let Some(cfg) = &s.config.files {
        for file in files {
            let _ = tokio::fs::remove_file(cfg.dir.join(file.to_string())).await;
        }
    }
}

/// Body of `POST /devices/delete`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct DeleteDevices {
    /// Devices of the tenant to delete: 1 to 1000, each once.
    #[schema(min_items = 1, max_items = 1000)]
    device_ids: Vec<Uuid>,
    /// Retire devices not retired yet, then delete them.
    /// Default false -> such a device is refused, as with `DELETE /devices/{id}`.
    #[serde(default)]
    retire: bool,
}

/// What `POST /devices/delete` removed.
#[derive(Debug, Serialize, utoipa::ToSchema)]
struct DeletedDevices {
    /// Devices deleted.
    deleted: usize,
    /// Agent certificates revoked with their devices (not counting earlier revocations).
    certificates_revoked: u64,
    /// Uploaded files (config backups, logs) deleted with the devices, content included.
    files: usize,
}

/// Device label for error message + audit record: ID + serial number or EndpointID (if known).
fn device_name(d: &CertificateTarget) -> String {
    match d.serial_number.as_deref().or(d.endpoint_id.as_deref()) {
        Some(label) => {
            let shown: String = label.chars().take(64).collect();
            format!("{} ({shown})", d.id)
        }
        None => d.id.to_string(),
    }
}

/// `names` for an error message: first [`MAX_REPORTED`] + `(and N more)`.
fn listed(names: &[String]) -> String {
    let shown = names
        .iter()
        .take(MAX_REPORTED)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    match names.len().saturating_sub(MAX_REPORTED) {
        0 => shown,
        more => format!("{shown} (and {more} more)"),
    }
}

/// Delete devices of `rows` one by one, in order + count them.
/// Stop at 1st failure -> deleted ones stay deleted; `done` = how many.
async fn delete_listed(
    s: &AppState,
    rows: &[&CertificateTarget],
    retire: bool,
    done: &mut BulkDeletion,
) -> Result<(), ApiError> {
    let tenant = s.config.tenant_id;
    let by = actor(s);
    for row in rows {
        let retired_first = retire && row.status != "retired";
        if retired_first && s.store.set_device_status(tenant, row.id, "retired").await? {
            done.retired += 1;
        }
        // Broker account of the Agent first, as in single delete.
        if let Some(broker) = &s.config.broker
            && row.protocol == "usp"
            && let Some(d) = s.store.get_device(row.id).await?
            && let Err(e) = broker.revoke(&s.store, &d).await
        {
            return Err(ApiError(
                StatusCode::BAD_GATEWAY,
                format!(
                    "the broker account of device {} could not be removed: {e}",
                    device_name(row)
                ),
            ));
        }
        // Deleted meanwhile by someone else -> not counted.
        let Some(deleted) = s.store.delete_device(tenant, row.id, Some(&by)).await? else {
            continue;
        };
        remove_stored_files(s, &deleted.files).await;
        done.deleted += 1;
        done.certificates_revoked += deleted.certificates_revoked;
        done.files += deleted.files.len();
        if done.sample.len() < AUDIT_SAMPLE {
            done.sample.push(device_name(row));
        }
        audit(
            s,
            "device.delete",
            "device",
            row.id,
            json!({ "serial_number": row.serial_number, "endpoint_id": row.endpoint_id,
                    "files": deleted.files.len(),
                    "certificates_revoked": deleted.certificates_revoked,
                    "bulk": true, "retired_first": retired_first }),
        )
        .await;
    }
    Ok(())
}

/// Bulk delete progress.
#[derive(Debug, Default)]
struct BulkDeletion {
    deleted: usize,
    /// Retired on request (`retire`).
    retired: usize,
    certificates_revoked: u64,
    files: usize,
    /// Names of the first deleted devices, for the audit record.
    sample: Vec<String>,
}

/// `POST /devices/delete`: many devices, each as by `DELETE /devices/{id}`.
#[utoipa::path(
    post,
    path = "/api/v1/devices/delete",
    tag = "devices",
    operation_id = "delete_devices",
    summary = "Delete many devices and all their data",
    description = "CO-14, for up to 1,000 devices at a time. Every device is checked first, and nothing is deleted unless all of them can be: the request is refused if a device is unknown, listed twice or, without `retire`, not retired yet. With `retire`, devices that are not retired are retired first, then deleted. Each device is then deleted as by `DELETE /devices/{id}`: its data and uploaded files are removed, and its Agent certificates are revoked (reason `device deleted`) with their records kept without a device, so the MTPs keep refusing them. A device still in service registers again at its next contact, as a new device. Audited as one `device.delete` record per device (with `bulk: true` and `retired_first`), and one `device.delete_bulk` summary. Devices are deleted one after the other: if one fails (502 when a USP Agent's broker account cannot be removed, or a storage error), those before it stay deleted and the error says how many. Not for accounts with a device scope.",
    request_body = DeleteDevices,
    responses(
        (status = 200, description = "What was deleted", body = DeletedDevices),
        (status = 413, description = "The request body is too large"),
        (status = 422, description = "No devices, more than 1,000, a device listed twice, unknown devices or (without `retire`) devices that are not retired: all listed in the error, nothing is deleted"),
        (status = 502, description = "A USP Agent's broker account could not be removed; the devices before it were deleted"),
    ),
)]
async fn delete_devices(
    State(s): State<Arc<AppState>>,
    body: Result<Json<DeleteDevices>, JsonRejection>,
) -> Result<Json<DeletedDevices>, ApiError> {
    let Json(req) = body.map_err(|e| ApiError(e.status(), e.body_text()))?;
    if req.device_ids.is_empty() {
        return Err(unprocessable("device_ids must not be empty"));
    }
    if req.device_ids.len() > MAX_DELETE {
        return Err(unprocessable(format!(
            "at most {MAX_DELETE} devices per request"
        )));
    }
    let mut seen = HashSet::new();
    let mut repeated = Vec::new();
    for id in &req.device_ids {
        if !seen.insert(*id) && !repeated.contains(&id.to_string()) {
            repeated.push(id.to_string());
        }
    }
    if !repeated.is_empty() {
        return Err(unprocessable(format!(
            "devices listed more than once: {}",
            listed(&repeated)
        )));
    }

    let found = s
        .store
        .certificate_targets(s.config.tenant_id, &req.device_ids, &[])
        .await?;
    let known: HashMap<Uuid, &CertificateTarget> = found.iter().map(|d| (d.id, d)).collect();
    let unknown: Vec<String> = req
        .device_ids
        .iter()
        .filter(|id| !known.contains_key(id))
        .map(ToString::to_string)
        .collect();
    if !unknown.is_empty() {
        return Err(unprocessable(format!(
            "unknown devices, nothing was deleted: {}",
            listed(&unknown)
        )));
    }
    // Request order.
    let rows: Vec<&CertificateTarget> = req.device_ids.iter().map(|id| known[id]).collect();
    if !req.retire {
        let active: Vec<String> = rows
            .iter()
            .filter(|d| d.status != "retired")
            .map(|d| device_name(d))
            .collect();
        if !active.is_empty() {
            return Err(unprocessable(format!(
                "devices that are not retired (retire them first, or set retire; nothing was deleted): {}",
                listed(&active)
            )));
        }
    }

    let mut done = BulkDeletion::default();
    let outcome = delete_listed(&s, &rows, req.retire, &mut done).await;
    if done.deleted > 0 || outcome.is_err() {
        audit(
            &s,
            "device.delete_bulk",
            "tenant",
            s.config.tenant_id,
            json!({ "requested": rows.len(), "deleted": done.deleted,
                    "retired": done.retired,
                    "certificates_revoked": done.certificates_revoked,
                    "files": done.files, "complete": outcome.is_ok(),
                    "sample": done.sample }),
        )
        .await;
    }
    if let Err(ApiError(status, message)) = outcome {
        let note = if done.deleted > 0 {
            format!(
                " ({} of {} devices were deleted before this)",
                done.deleted,
                rows.len()
            )
        } else {
            String::new()
        };
        return Err(ApiError(status, format!("{message}{note}")));
    }
    Ok(Json(DeletedDevices {
        deleted: done.deleted,
        certificates_revoked: done.certificates_revoked,
        files: done.files,
    }))
}
