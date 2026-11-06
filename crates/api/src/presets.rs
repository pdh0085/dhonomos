//! Provisioning presets (CO-04): list + dry run.
//! Presets in DB -> also edit with history (UI-03, ADR-077).
//! Dry run = same planning as real Informs ([`dhonomos_core::presets::plan`]) -> exact queue.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use dhonomos_core::secrets::redact_preset;
use dhonomos_core::{MatchContext, Preset, Presets, SecretError};
use dhonomos_cwmp_codec::EventCode;
use dhonomos_store::{PresetWrite, StoredPreset};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{ApiError, AppState, audit, device_of, ts};

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/presets", get(list))
        .route("/presets/dry-run", post(dry_run))
        .route("/presets/validate", post(validate))
        .route("/presets/import", post(import))
        .route("/presets/export.yaml", get(export))
        .route("/presets/{name}", get(get_one).put(save).delete(remove))
        .route("/presets/{name}/history", get(history))
}

fn unprocessable(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg.into())
}

/// 409 unless presets in DB.
fn editable(s: &AppState) -> Result<(), ApiError> {
    if s.config.presets_in_db {
        Ok(())
    } else {
        Err(ApiError(
            StatusCode::CONFLICT,
            "presets come from the --presets file; edit the file, or run without --presets to manage them here".into(),
        ))
    }
}

/// Secrets write-only -> every preset output has the mask in their place.
pub(crate) fn stored_json(p: &StoredPreset) -> Value {
    json!({
        "name": p.name,
        "enabled": p.enabled,
        "revision": p.revision,
        "updated_by": p.updated_by,
        "updated_at": ts(p.updated_at),
        "definition": redact_preset(&p.definition),
    })
}

fn secret_error(e: SecretError) -> ApiError {
    match e {
        SecretError::NoStored(_)
        | SecretError::Moved { .. }
        | SecretError::Reserved
        | SecretError::Decrypt => unprocessable(e.to_string()),
        e => {
            tracing::error!(error = %e, "sealing preset secrets failed");
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not protect the secrets".into(),
            )
        }
    }
}

/// Seal secrets of a definition before store as row `id` (replaces `stored`).
/// New secret -> encrypted. Mask -> stored value of the same place.
/// Any secret -> needs `--secrets-key`.
fn seal(
    s: &AppState,
    definition: &mut Value,
    id: Uuid,
    stored: Option<&Value>,
) -> Result<(), ApiError> {
    if !dhonomos_core::secrets::preset_has_secret(definition) {
        return Ok(());
    }
    let secrets = s.config.secrets.as_ref().ok_or_else(|| {
        unprocessable("storing passwords requires the server to run with --secrets-key")
    })?;
    secrets
        .seal_preset(definition, id, stored)
        .map_err(secret_error)
}

/// Reload presets of this process now. Other processes -> see the revision within seconds.
async fn reload(s: &AppState) -> Result<(), ApiError> {
    let (presets, errors) =
        dhonomos_core::presets::load_stored(&s.store, s.config.tenant_id, s.config.secrets.clone())
            .await?;
    for e in &errors {
        tracing::error!(error = %e, "stored preset left out");
    }
    s.config.presets.replace(presets);
    Ok(())
}

async fn stored(s: &AppState, name: &str) -> Result<StoredPreset, ApiError> {
    s.store
        .list_presets(s.config.tenant_id)
        .await?
        .into_iter()
        .find(|p| p.name == name)
        .ok_or_else(|| crate::not_found("preset"))
}

#[utoipa::path(
    get,
    path = "/api/v1/presets",
    tag = "presets",
    operation_id = "list_presets",
    summary = "Provisioning presets",
    description = "With `source: database` the presets are edited here; with `source: file` they come from the `--presets` file (no revision). Secrets of their tasks are shown as `********`.",
    responses(
        (status = 200, description = "The presets by name", body = crate::schemas::PresetList),
    ),
)]
async fn list(State(s): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let items: Vec<Value> = if s.config.presets_in_db {
        s.store
            .list_presets(s.config.tenant_id)
            .await?
            .iter()
            .map(stored_json)
            .collect()
    } else {
        s.config
            .presets
            .get()
            .iter()
            .map(|p| {
                json!({ "name": p.name, "enabled": p.enabled, "revision": null,
                        "updated_by": null, "updated_at": null,
                        "definition": redact_preset(&serde_json::to_value(p).unwrap_or_default()) })
            })
            .collect()
    };
    let source = if s.config.presets_in_db {
        "database"
    } else {
        "file"
    };
    Ok(Json(json!({ "source": source, "items": items })))
}

#[utoipa::path(
    get,
    path = "/api/v1/presets/{name}",
    tag = "presets",
    operation_id = "get_preset",
    summary = "A stored preset",
    params(("name" = String, Path, description = "Preset name")),
    responses(
        (status = 200, description = "The preset", body = crate::schemas::StoredPreset),
        (status = 404, description = "Unknown preset"),
        (status = 409, description = "Presets come from the --presets file"),
    ),
)]
async fn get_one(
    State(s): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    editable(&s)?;
    Ok(Json(stored_json(&stored(&s, &name).await?)))
}

/// Body of `PUT /presets/{name}`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct SavePreset {
    /// Preset as in the YAML file (`when`, `once`, `priority`, `run`, `script_source`,
    /// `args`, `enabled`). `name`, if given, must match the path.
    #[schema(value_type = Object)]
    definition: Value,
    /// Revision being replaced, from `GET`. 0 -> create. Omitted -> replace any current one.
    #[serde(default)]
    revision: Option<i32>,
}

/// `definition` as preset `name`, validated.
fn checked(name: &str, mut definition: Value) -> Result<Preset, ApiError> {
    let obj = definition
        .as_object_mut()
        .ok_or_else(|| unprocessable("definition must be an object"))?;
    match obj.get("name").and_then(Value::as_str) {
        Some(n) if n != name => {
            return Err(unprocessable(format!(
                "definition name {n:?} differs from the path; presets cannot be renamed"
            )));
        }
        _ => {
            obj.insert("name".into(), json!(name));
        }
    }
    let preset: Preset =
        serde_json::from_value(definition).map_err(|e| unprocessable(e.to_string()))?;
    Presets::check(&preset).map_err(|e| unprocessable(e.to_string()))?;
    Ok(preset)
}

fn conflict(current: i32) -> ApiError {
    ApiError(
        StatusCode::CONFLICT,
        if current == 0 {
            "the preset does not exist (any more)".into()
        } else {
            format!("the preset was changed meanwhile (now revision {current}); reload it")
        },
    )
}

#[utoipa::path(
    put,
    path = "/api/v1/presets/{name}",
    tag = "presets",
    operation_id = "save_preset",
    summary = "Create or replace a preset",
    description = "Validated (scripts compiled) before it is stored; every process uses it within seconds. Names cannot change: `once` presets remember devices by name. Secrets in the tasks of `run` (`password`, `values[]` entries with `secret: true`) are stored encrypted (they need `--secrets-key`) and never shown again: output has `********` in their place. Sending `********` keeps the stored secret of the same place (the same task index and field); with none stored it is refused. Values starting with `enc:` are refused.",
    params(("name" = String, Path, description = "Preset name")),
    request_body = SavePreset,
    responses(
        (status = 200, description = "The stored preset", body = crate::schemas::StoredPreset),
        (status = 409, description = "Changed meanwhile (stale `revision`), or presets come from the --presets file"),
        (status = 422, description = "Invalid preset, with the reason; a secret without `--secrets-key`; the mask `********` where no secret is stored"),
    ),
)]
async fn save(
    State(s): State<Arc<AppState>>,
    Path(name): Path<String>,
    body: Result<Json<SavePreset>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    editable(&s)?;
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    let preset = checked(&name, req.definition)?;
    let mut definition = serde_json::to_value(&preset).unwrap_or_default();
    let actor = crate::actor(&s);
    // Secrets bound to the row -> choose its ID before sealing.
    let current = s
        .store
        .list_presets(s.config.tenant_id)
        .await?
        .into_iter()
        .find(|p| p.name == name);
    let id = current.as_ref().map_or_else(Uuid::now_v7, |p| p.id);
    seal(
        &s,
        &mut definition,
        id,
        current.as_ref().map(|p| &p.definition),
    )?;
    // History: no secrets, not even sealed ones.
    let history = redact_preset(&definition);
    match s
        .store
        .put_preset(
            s.config.tenant_id,
            id,
            &name,
            preset.enabled,
            &definition,
            &history,
            req.revision,
            Some(&actor),
        )
        .await?
    {
        PresetWrite::Done(revision) => {
            audit(
                &s,
                "preset.save",
                "preset",
                &name,
                json!({ "revision": revision, "enabled": preset.enabled }),
            )
            .await;
        }
        PresetWrite::Conflict(current) => return Err(conflict(current)),
    }
    reload(&s).await?;
    Ok(Json(stored_json(&stored(&s, &name).await?)))
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct RevisionQuery {
    /// Delete only at this revision.
    #[serde(default)]
    revision: Option<i32>,
}

#[utoipa::path(
    delete,
    path = "/api/v1/presets/{name}",
    tag = "presets",
    operation_id = "delete_preset",
    summary = "Delete a preset",
    params(("name" = String, Path, description = "Preset name"), RevisionQuery),
    responses(
        (status = 204, description = "Deleted (kept in the history)"),
        (status = 404, description = "Unknown preset"),
        (status = 409, description = "Changed meanwhile, or presets come from the --presets file"),
    ),
)]
async fn remove(
    State(s): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(q): Query<RevisionQuery>,
) -> Result<StatusCode, ApiError> {
    editable(&s)?;
    let actor = crate::actor(&s);
    match s
        .store
        .delete_preset(s.config.tenant_id, &name, q.revision, Some(&actor))
        .await?
    {
        PresetWrite::Done(_) => {}
        PresetWrite::Conflict(0) => return Err(crate::not_found("preset")),
        PresetWrite::Conflict(current) => return Err(conflict(current)),
    }
    audit(&s, "preset.delete", "preset", &name, json!({})).await;
    reload(&s).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/presets/{name}/history",
    tag = "presets",
    operation_id = "preset_history",
    summary = "Saved revisions of a preset",
    params(("name" = String, Path, description = "Preset name")),
    responses(
        (status = 200, description = "Revisions and deletions, newest first (up to 100)", body = crate::schemas::PresetHistory),
        (status = 409, description = "Presets come from the --presets file"),
    ),
)]
async fn history(
    State(s): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    editable(&s)?;
    let items: Vec<Value> = s
        .store
        .preset_history(s.config.tenant_id, &name, 100)
        .await?
        .iter()
        .map(change_json)
        .collect();
    Ok(Json(json!({ "items": items })))
}

pub(crate) fn change_json(c: &dhonomos_store::PresetChange) -> Value {
    json!({
        "revision": c.revision,
        "enabled": c.enabled,
        "deleted": c.definition.is_none(),
        // Entries keep no secrets. Mask -> also covers entries from before that rule.
        "definition": c.definition.as_ref().map(redact_preset),
        "changed_by": c.changed_by,
        "changed_at": ts(c.changed_at),
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/presets/validate",
    tag = "presets",
    operation_id = "validate_preset",
    summary = "Check a preset without storing it",
    description = "Parses the preset and compiles its script, as saving would.",
    request_body(content = Object, description = "The preset (with `name`)"),
    responses(
        (status = 200, description = "Valid: `{\"ok\": true}`", body = Object),
        (status = 422, description = "Invalid, with the reason"),
    ),
)]
async fn validate(
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(definition) = body.map_err(|e| unprocessable(e.body_text()))?;
    let name = definition
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("draft")
        .to_owned();
    checked(&name, definition)?;
    Ok(Json(json!({ "ok": true })))
}

/// Body of `POST /presets/import`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct Import {
    /// Preset file (`presets: [...]`), scripts inline (`script_source`).
    yaml: String,
    /// Only report what would change.
    #[serde(default)]
    dry_run: bool,
}

#[utoipa::path(
    post,
    path = "/api/v1/presets/import",
    tag = "presets",
    operation_id = "import_presets",
    summary = "Import presets from YAML",
    description = "Creates or replaces the presets of the document (all are validated first; nothing is stored if one fails). Presets not in the document stay. Secrets are handled as when saving a preset: the mask `********` (what an export shows) keeps the stored secret of an existing preset and is refused for a new one.",
    request_body = Import,
    responses(
        (status = 200, description = "`created`, `updated`, `unchanged`: preset names", body = crate::schemas::PresetImport),
        (status = 409, description = "Presets come from the --presets file"),
        (status = 422, description = "Invalid document or preset, with the reason; a secret without `--secrets-key`; the mask `********` where no secret is stored"),
    ),
)]
async fn import(
    State(s): State<Arc<AppState>>,
    body: Result<Json<Import>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    editable(&s)?;
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    let list =
        dhonomos_core::presets::parse_list(&req.yaml).map_err(|e| unprocessable(e.to_string()))?;
    let mut names = HashSet::new();
    let mut checked_list = Vec::new();
    for p in list {
        if !names.insert(p.name.clone()) {
            return Err(unprocessable(format!("preset {:?} appears twice", p.name)));
        }
        Presets::check(&p).map_err(|e| unprocessable(e.to_string()))?;
        checked_list.push(p);
    }
    let current: std::collections::HashMap<String, StoredPreset> = s
        .store
        .list_presets(s.config.tenant_id)
        .await?
        .into_iter()
        .map(|p| (p.name.clone(), p))
        .collect();
    let (mut created, mut updated, mut unchanged) = (Vec::new(), Vec::new(), Vec::new());
    let actor = crate::actor(&s);
    // Seal all before storing any -> one bad secret stores nothing.
    let mut writes = Vec::new();
    for p in &checked_list {
        let mut definition = serde_json::to_value(p).unwrap_or_default();
        let existing = current.get(&p.name);
        // Secrets not comparable (each sealing differs) -> given secret = updated.
        // Else compare the documents without secrets.
        if let Some(e) = existing
            && !dhonomos_core::secrets::preset_has_new_secret(&definition)
            && redact_preset(&definition) == redact_preset(&e.definition)
        {
            unchanged.push(p.name.clone());
            continue;
        }
        let id = existing.map_or_else(Uuid::now_v7, |e| e.id);
        seal(&s, &mut definition, id, existing.map(|e| &e.definition))
            .map_err(|e| ApiError(e.0, format!("preset {:?}: {}", p.name, e.1)))?;
        if existing.is_some() {
            updated.push(p.name.clone());
        } else {
            created.push(p.name.clone());
        }
        writes.push((id, p, definition));
    }
    if !req.dry_run {
        for (id, p, definition) in &writes {
            s.store
                .put_preset(
                    s.config.tenant_id,
                    *id,
                    &p.name,
                    p.enabled,
                    definition,
                    &redact_preset(definition),
                    None,
                    Some(&actor),
                )
                .await?;
        }
    }
    if !req.dry_run && (!created.is_empty() || !updated.is_empty()) {
        audit(
            &s,
            "preset.import",
            "tenant",
            s.config.tenant_id,
            json!({ "created": created, "updated": updated }),
        )
        .await;
        reload(&s).await?;
    }
    Ok(Json(
        json!({ "created": created, "updated": updated, "unchanged": unchanged,
                    "dry_run": req.dry_run }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/presets/export.yaml",
    tag = "presets",
    operation_id = "export_presets",
    summary = "The presets as a YAML preset file",
    description = "Secrets are shown as `********`. Importing the file keeps the stored secret of a preset that exists and refuses the mask for a new one; as a `--presets` file it is refused until the secrets are written.",
    responses(
        (status = 200, description = "`presets: [...]`, loadable with `--presets` (after writing the secrets) or the import", content_type = "application/yaml", body = String),
    ),
)]
async fn export(State(s): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let presets: Vec<Value> = if s.config.presets_in_db {
        s.store
            .list_presets(s.config.tenant_id)
            .await?
            .into_iter()
            .map(|p| redact_preset(&p.definition))
            .collect()
    } else {
        s.config
            .presets
            .get()
            .iter()
            .map(|p| redact_preset(&serde_json::to_value(p).unwrap_or_default()))
            .collect()
    };
    let yaml = serde_saphyr::to_string(&json!({ "presets": presets })).map_err(|e| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("YAML output failed: {e}"),
        )
    })?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/yaml; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"presets.yaml\"",
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        yaml,
    )
        .into_response())
}

/// Body of `POST /presets/dry-run`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct DryRun {
    device_id: Uuid,
    /// Inform event codes (CWMP) or `USP CONNECT` / `1 BOOT` (USP).
    #[serde(default)]
    events: Vec<String>,
    /// Treat the device as seen for the first time.
    #[serde(default)]
    new_device: bool,
    /// Unsaved preset (as in `PUT /presets/{name}`, with `name`) instead of the loaded ones.
    /// Editor test run.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    draft: Option<Value>,
}

#[utoipa::path(
    post,
    path = "/api/v1/presets/dry-run",
    tag = "presets",
    operation_id = "dry_run_presets",
    summary = "Tasks presets would queue for a device on given events",
    request_body = DryRun,
    responses(
        (status = 200, description = "Planned tasks and script traces", body = crate::schemas::DryRunResult),
        (status = 404, description = "Unknown device"),
        (status = 422, description = "Invalid body or draft preset"),
    ),
)]
async fn dry_run(
    State(s): State<Arc<AppState>>,
    body: Result<Json<DryRun>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(req) =
        body.map_err(|e| ApiError(axum::http::StatusCode::UNPROCESSABLE_ENTITY, e.body_text()))?;
    let d = device_of(&s, req.device_id).await?;
    let events: Vec<EventCode> = req.events.iter().map(|e| EventCode::parse(e)).collect();
    let ctx = MatchContext {
        events: &events,
        oui: d.oui.as_deref().unwrap_or_default(),
        product_class: &d.product_class,
        software_version: d.software_version.as_deref(),
        tags: &d.tags,
        new_device: req.new_device,
        attributes: &d.attributes,
        serial: d
            .serial_number
            .as_deref()
            .or(d.endpoint_id.as_deref())
            .unwrap_or_default(),
        protocol: &d.protocol,
    };
    let presets = match req.draft {
        Some(draft) => {
            let name = draft
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("draft")
                .to_owned();
            let mut preset = checked(&name, draft)?;
            // Try it even when saved disabled.
            preset.enabled = true;
            Arc::new(Presets::single(preset).map_err(|e| unprocessable(e.to_string()))?)
        }
        None => s.config.presets.get(),
    };
    let mut planned = dhonomos_core::presets::plan(&presets, d.id, &ctx, "dry-run");
    let static_count = planned.len();
    // Scripts run for real on stored parameters, but nothing queued or tagged.
    let runs =
        dhonomos_core::presets::run_scripts(&s.store, &presets, d.id, &ctx, "dry-run").await?;
    for r in &runs {
        planned.extend(r.tasks.iter().cloned());
    }
    let keys: Vec<String> = planned
        .iter()
        .filter(|p| p.once)
        .map(|p| p.idempotency_key.clone())
        .collect();
    let existing: HashSet<String> = s
        .store
        .existing_idempotency_keys(s.config.tenant_id, &keys)
        .await?
        .into_iter()
        .collect();
    let items: Vec<Value> = planned
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let (kind, payload) = p.task.to_row();
            json!({
                "preset": p.preset,
                "index": p.index,
                "kind": kind,
                "payload": crate::redact_task(&kind, &payload),
                "priority": p.priority,
                "once": p.once,
                // `once` preset already run for this device -> queues nothing.
                "would_queue": !existing.contains(&p.idempotency_key),
                "script": i >= static_count,
            })
        })
        .collect();
    let scripts: Vec<Value> = runs.iter().map(|r| r.event_detail()).collect();
    Ok(Json(json!({ "items": items, "scripts": scripts })))
}
