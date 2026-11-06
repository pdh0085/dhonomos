//! File API + device-facing file server (CW-16).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension, Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use dhonomos_core::{FileSigner, UploadKind};
use dhonomos_store::{NewFile, Store, StoredFile};
use futures_util::StreamExt as _;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;
use tower::ServiceExt as _;
use tower_http::services::ServeFile;
use uuid::Uuid;

use crate::tls_listener::PeerAddr;
use crate::{ApiError, AppState, ts};

/// File storage settings. Limits change at run time ([`FilesConfig::set_max_bytes`],
/// [`FilesConfig::set_limits`]); clones share them -> API + file server follow.
#[derive(Debug, Clone)]
pub struct FilesConfig {
    /// Directory of file contents, one file per ID.
    pub dir: PathBuf,
    /// Signs + checks download URLs.
    pub signer: FileSigner,
    live: Arc<FilesLive>,
}

/// Limits of [`FilesConfig`], shared by its clones.
#[derive(Debug)]
struct FilesLive {
    /// Upload limit, bytes.
    max_bytes: AtomicU64,
    /// Per download, bytes/s; 0 = no limit.
    per_download_rate: AtomicU64,
    /// Shared by all downloads (`DownloadLimits::total_rate`); rate 0 = no limit.
    total_rate: Bucket,
    /// Download slots (`DownloadLimits::max_concurrent`) + their count.
    /// New count -> new semaphore; downloads with a slot of the old one keep it until the end.
    slots: dhonomos_core::Shared<Option<(usize, Arc<tokio::sync::Semaphore>)>>,
}

impl FilesConfig {
    /// Upload limit `max_bytes` + download `limits`.
    pub fn new(dir: PathBuf, signer: FileSigner, max_bytes: u64, limits: DownloadLimits) -> Self {
        let config = Self {
            dir,
            signer,
            live: Arc::new(FilesLive {
                max_bytes: AtomicU64::new(max_bytes),
                per_download_rate: AtomicU64::new(0),
                total_rate: Bucket::new(0),
                slots: dhonomos_core::Shared::new(None),
            }),
        };
        config.set_limits(&limits);
        config
    }

    /// Upload limit, bytes.
    pub fn max_bytes(&self) -> u64 {
        self.live.max_bytes.load(Ordering::Relaxed)
    }

    /// New upload limit -> for uploads that start after this.
    pub fn set_max_bytes(&self, max_bytes: u64) {
        self.live.max_bytes.store(max_bytes, Ordering::Relaxed);
    }

    pub fn limits(&self) -> DownloadLimits {
        let rate = |r: u64| (r > 0).then_some(r);
        DownloadLimits {
            total_rate: rate(self.live.total_rate.rate()),
            per_download_rate: rate(self.live.per_download_rate.load(Ordering::Relaxed)),
            max_concurrent: self.live.slots.get().as_ref().as_ref().map(|(n, _)| *n),
        }
    }

    /// New download limits. Total rate -> all downloads, running ones too.
    /// Per-download rate + max concurrent -> downloads that start after this.
    pub fn set_limits(&self, limits: &DownloadLimits) {
        self.live
            .total_rate
            .set_rate(limits.total_rate.unwrap_or(0));
        self.live
            .per_download_rate
            .store(limits.per_download_rate.unwrap_or(0), Ordering::Relaxed);
        let current = self.live.slots.get().as_ref().as_ref().map(|(n, _)| *n);
        if current != limits.max_concurrent {
            self.live.slots.replace(
                limits
                    .max_concurrent
                    .map(|n| (n, Arc::new(tokio::sync::Semaphore::new(n.max(1))))),
            );
        }
    }
}

/// Limits for device downloads (CW-16) -> a firmware campaign cannot fill the uplink.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DownloadLimits {
    /// All downloads together, bytes/s.
    pub total_rate: Option<u64>,
    /// Per download, bytes/s.
    pub per_download_rate: Option<u64>,
    /// Max downloads at once; more -> 503 + `Retry-After`.
    pub max_concurrent: Option<usize>,
}

/// Token bucket in bytes. Takers may overdraw, then wait off the debt ->
/// concurrent downloads share the rate. Rate changes at run time; 0 = no limit.
#[derive(Debug)]
struct Bucket {
    /// Bytes/s; 0 = no limit.
    rate: AtomicU64,
    state: std::sync::Mutex<(f64, std::time::Instant)>,
}

impl Bucket {
    fn new(rate: u64) -> Self {
        let bucket = Self {
            rate: AtomicU64::new(rate),
            state: std::sync::Mutex::new((0.0, std::time::Instant::now())),
        };
        bucket.set_rate(rate);
        bucket
    }

    fn rate(&self) -> u64 {
        self.rate.load(Ordering::Relaxed)
    }

    /// 1/4 s of traffic, min one 64 KiB read.
    fn burst(rate: f64) -> f64 {
        (rate / 4.0).max(65_536.0)
    }

    /// New rate; bucket starts full.
    fn set_rate(&self, rate: u64) {
        self.rate.store(rate, Ordering::Relaxed);
        if let Ok(mut st) = self.state.lock() {
            *st = (Self::burst(rate as f64), std::time::Instant::now());
        }
    }

    /// Take `n` bytes -> wait time before sending them.
    fn take(&self, n: usize) -> std::time::Duration {
        let rate = self.rate();
        if rate == 0 {
            return std::time::Duration::ZERO;
        }
        let rate = rate as f64;
        let Ok(mut st) = self.state.lock() else {
            return std::time::Duration::ZERO;
        };
        let now = std::time::Instant::now();
        let refill = now.duration_since(st.1).as_secs_f64() * rate;
        let tokens = (st.0 + refill).min(Self::burst(rate)) - n as f64;
        *st = (tokens, now);
        if tokens >= 0.0 {
            std::time::Duration::ZERO
        } else {
            std::time::Duration::from_secs_f64(-tokens / rate)
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn file_json(f: &StoredFile) -> Value {
    json!({
        "id": f.id,
        "name": f.name,
        "file_type": f.file_type,
        "size_bytes": f.size_bytes,
        "sha256": hex(&f.sha256),
        "version": f.version,
        "created_at": ts(f.created_at),
        "device_id": f.device_id,
    })
}

fn files_config(s: &AppState) -> Result<&FilesConfig, ApiError> {
    s.config
        .files
        .as_ref()
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "the file server is disabled".into()))
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct UploadQuery {
    /// File name: 1-255 bytes, no `/`, unique.
    name: String,
    /// TR-069 file type (default `1 Firmware Upgrade Image`).
    #[serde(default = "default_file_type")]
    file_type: String,
    /// Software version the file installs.
    #[serde(default)]
    version: Option<String>,
}

fn default_file_type() -> String {
    "1 Firmware Upgrade Image".into()
}

/// `PUT /api/v1/files?name=&file_type=&version=`, body = raw content.
#[utoipa::path(
    put,
    path = "/api/v1/files",
    tag = "files",
    operation_id = "upload_file",
    summary = "Upload a file",
    params(
        UploadQuery,
    ),
    request_body(content = inline(crate::openapi::Binary), content_type = "application/octet-stream", description = "The raw file content"),
    responses(
        (status = 201, description = "The stored file", body = crate::schemas::StoredFile),
        (status = 400, description = "The upload was interrupted, or a query parameter is missing or malformed"),
        (status = 404, description = "The file server is disabled"),
        (status = 409, description = "A file with this name exists"),
        (status = 413, description = "The file exceeds the size limit"),
        (status = 422, description = "Invalid name, or an empty file"),
        (status = 507, description = "The file could not be stored"),
    ),
)]
pub(crate) async fn upload(
    State(s): State<Arc<AppState>>,
    Query(q): Query<UploadQuery>,
    body: Body,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let cfg = files_config(&s)?;
    let name = q.name.trim();
    if name.is_empty() || name.contains('/') || name.len() > 255 {
        return Err(ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "name must be 1-255 characters without '/'".into(),
        ));
    }
    let id = Uuid::now_v7();
    let received = receive_file(cfg, id, body).await?;
    let size = received.size;
    let file = NewFile {
        id,
        tenant_id: s.config.tenant_id,
        name: name.to_owned(),
        file_type: q.file_type,
        size_bytes: i64::try_from(size).unwrap_or(i64::MAX),
        sha256: received.sha256.clone(),
        version: q.version,
        device_id: None,
    };
    if let Err(e) = register_and_place(&s.store, cfg, &file, &received).await {
        return Err(match e {
            PlaceError::Taken(msg) if msg.contains("files_tenant_id_name_key") => ApiError(
                StatusCode::CONFLICT,
                format!("a file named {name:?} already exists"),
            ),
            PlaceError::Taken(_) => {
                ApiError(StatusCode::CONFLICT, "the file ID is already used".into())
            }
            PlaceError::Store(e) => e.into(),
            PlaceError::Io => ApiError(
                StatusCode::INSUFFICIENT_STORAGE,
                "could not store the file".into(),
            ),
        });
    }
    crate::audit(
        &s,
        "file.upload",
        "file",
        id,
        json!({ "name": name, "size_bytes": size }),
    )
    .await;
    let stored = s
        .store
        .get_file(id)
        .await?
        .ok_or_else(|| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "file vanished".into()))?;
    Ok((StatusCode::CREATED, Json(file_json(&stored))))
}

/// File received into a private `.part` file, not yet under its ID.
struct Received {
    part: PathBuf,
    size: u64,
    sha256: Vec<u8>,
}

/// Why a received file was not put in place.
enum PlaceError {
    /// DB has a file with this ID or name; message says which.
    Taken(String),
    Store(dhonomos_store::StoreError),
    Io,
}

/// Insert `file` row (row decides who owns the ID), then move content to `<dir>/<id>`.
/// Losing request -> its own `.part` file removed here; never touches a file it did not create.
/// Move fails -> winner's row deleted again.
async fn register_and_place(
    store: &Store,
    cfg: &FilesConfig,
    file: &NewFile,
    received: &Received,
) -> Result<(), PlaceError> {
    if let Err(e) = store.insert_file(file).await {
        let _ = tokio::fs::remove_file(&received.part).await;
        let msg = e.to_string();
        return Err(
            if msg.contains("files_pkey") || msg.contains("files_tenant_id_name_key") {
                PlaceError::Taken(msg)
            } else {
                PlaceError::Store(e)
            },
        );
    }
    let final_path = cfg.dir.join(file.id.to_string());
    if let Err(e) = tokio::fs::rename(&received.part, &final_path).await {
        tracing::error!(error = %e, "file storage error");
        let _ = tokio::fs::remove_file(&received.part).await;
        if let Err(e) = store.delete_file(file.tenant_id, file.id).await {
            tracing::error!(error = %e, file = %file.id, "could not take back a file row");
        }
        return Err(PlaceError::Io);
    }
    Ok(())
}

/// Stream `body` to its own `.part` file, size limit enforced -> path, size, SHA-256.
/// [`register_and_place`] puts it under its ID. 2 requests for 1 ID (device retries an
/// upload link) never share a `.part` file.
async fn receive_file(cfg: &FilesConfig, id: Uuid, body: Body) -> Result<Received, ApiError> {
    let part_path = cfg.dir.join(format!("{id}.{}.part", Uuid::now_v7()));
    let io_err = |e: std::io::Error| {
        tracing::error!(error = %e, "file storage error");
        ApiError(
            StatusCode::INSUFFICIENT_STORAGE,
            "could not store the file".into(),
        )
    };
    let write = async {
        // Uploads can hold device secrets (config backups) -> owner-only.
        let mut out = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&part_path)
            .await
            .map_err(io_err)?;
        let mut hasher = Sha256::new();
        let mut size: u64 = 0;
        let mut stream = body.into_data_stream();
        let max_bytes = cfg.max_bytes();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                ApiError(StatusCode::BAD_REQUEST, format!("upload interrupted: {e}"))
            })?;
            size += chunk.len() as u64;
            if size > max_bytes {
                return Err(ApiError(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!("file exceeds the {max_bytes} byte limit"),
                ));
            }
            hasher.update(&chunk);
            out.write_all(&chunk).await.map_err(io_err)?;
        }
        out.sync_all().await.map_err(io_err)?;
        if size == 0 {
            return Err(ApiError(
                StatusCode::UNPROCESSABLE_ENTITY,
                "the file is empty".into(),
            ));
        }
        Ok((size, hasher.finalize().to_vec()))
    };
    match write.await {
        Ok((size, sha256)) => Ok(Received {
            part: part_path,
            size,
            sha256,
        }),
        Err(e) => {
            let _ = tokio::fs::remove_file(&part_path).await;
            Err(e)
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/files",
    tag = "files",
    operation_id = "list_files",
    summary = "List files",
    description = "Files a device uploaded are listed only while the device is inside the caller's device scope.",
    responses(
        (status = 200, description = "The files", body = crate::schemas::FileList),
        (status = 404, description = "The file server is disabled"),
    ),
)]
pub(crate) async fn list(State(s): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    files_config(&s)?;
    let scope = crate::auth::caller_scope()?;
    let files = s
        .store
        .list_files(s.config.tenant_id, scope.as_deref())
        .await?;
    Ok(Json(
        json!({ "items": files.iter().map(file_json).collect::<Vec<_>>() }),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/files/{id}",
    tag = "files",
    operation_id = "delete_file",
    summary = "Delete a file",
    params(
        ("id" = Uuid, Path, description = "File ID"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Unknown file, or the file server is disabled"),
    ),
)]
pub(crate) async fn delete(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let cfg = files_config(&s)?;
    if !s.store.delete_file(s.config.tenant_id, id).await? {
        return Err(ApiError(StatusCode::NOT_FOUND, "file not found".into()));
    }
    let _ = tokio::fs::remove_file(cfg.dir.join(id.to_string())).await;
    crate::audit(&s, "file.delete", "file", id, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /files/{id}/content`: stored bytes, e.g. config backup or device log.
/// Operators only (backups can hold secrets). Device file -> only while device in caller scope.
#[utoipa::path(
    get,
    path = "/api/v1/files/{id}/content",
    tag = "files",
    operation_id = "file_content",
    summary = "Download a stored file",
    description = "Requires the `operator` role. A file a device uploaded is served only while the device is in the caller's scope.",
    params(
        ("id" = Uuid, Path, description = "File ID"),
    ),
    responses(
        (status = 200, description = "The file", content_type = "application/octet-stream"),
        (status = 404, description = "Unknown file, a device outside the caller's scope, or the file server is disabled"),
    ),
)]
pub(crate) async fn content(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    req: Request,
) -> Result<Response, ApiError> {
    let cfg = files_config(&s)?;
    let file = s
        .store
        .get_file(id)
        .await?
        .filter(|f| f.tenant_id == s.config.tenant_id)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "file not found".into()))?;
    if let Some(device) = file.device_id {
        crate::device_of(&s, device).await?;
    }
    let mut resp = match ServeFile::new(cfg.dir.join(id.to_string()))
        .oneshot(req)
        .await
    {
        Ok(r) => r.map(Body::new),
        Err(e) => match e {},
    };
    if !resp.status().is_success() {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            "file content not found".into(),
        ));
    }
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/octet-stream"),
    );
    // Files can be config backups with secrets -> no copy in browser or proxy cache.
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    if let Ok(v) = header::HeaderValue::from_str(&format!(
        "attachment; filename=\"{}\"",
        file.name.replace(['"', '\\', '\r', '\n'], "_")
    )) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    crate::audit(&s, "file.read", "file", id, json!({ "name": file.name })).await;
    Ok(resp)
}

/// No body limit for uploads: handler enforces `max_bytes` itself.
pub(crate) fn upload_limit() -> DefaultBodyLimit {
    DefaultBodyLimit::disable()
}

#[derive(Debug, Deserialize)]
struct Signed {
    d: Uuid,
    e: u64,
    s: String,
}

#[derive(Debug)]
struct FileServerState {
    store: Store,
    files: FilesConfig,
    tenant_id: Uuid,
    metrics: Option<dhonomos_core::MetricsIngest>,
    /// Running diagnostic transfers.
    diag: DiagSlots,
}

/// Max diagnostic transfers at once per device.
const DIAG_PER_DEVICE: usize = 2;
/// Max diagnostic transfers at once per server.
const DIAG_TOTAL: usize = 64;
/// Max time of a diagnostic transfer -> then cut off.
const DIAG_MAX_TIME: std::time::Duration = std::time::Duration::from_secs(600);

/// Limits for diagnostic test links (DG-01). Size up to 1 GB, valid for
/// [`dhonomos_core::files::DIAG_LINK_TTL`] -> else a link holder can fill the uplink from
/// any number of connections.
#[derive(Debug)]
struct DiagSlots {
    total: Arc<tokio::sync::Semaphore>,
    per_device: Arc<std::sync::Mutex<std::collections::HashMap<Uuid, usize>>>,
    per_device_max: usize,
}

/// Running diagnostic transfer; drop -> frees its slots.
#[derive(Debug)]
struct DiagSlot {
    _total: tokio::sync::OwnedSemaphorePermit,
    device: Uuid,
    per_device: Arc<std::sync::Mutex<std::collections::HashMap<Uuid, usize>>>,
}

impl DiagSlots {
    fn new(per_device: usize, total: usize) -> Self {
        Self {
            total: Arc::new(tokio::sync::Semaphore::new(total.max(1))),
            per_device: Arc::default(),
            per_device_max: per_device.max(1),
        }
    }

    /// Slot for a transfer of `device`; `None` if device or server at limit.
    fn acquire(&self, device: Uuid) -> Option<DiagSlot> {
        let total = self.total.clone().try_acquire_owned().ok()?;
        let mut per_device = self.per_device.lock().ok()?;
        let n = per_device.entry(device).or_insert(0);
        if *n >= self.per_device_max {
            return None;
        }
        *n += 1;
        Some(DiagSlot {
            _total: total,
            device,
            per_device: self.per_device.clone(),
        })
    }
}

impl Drop for DiagSlot {
    fn drop(&mut self) {
        if let Ok(mut per_device) = self.per_device.lock()
            && let Some(n) = per_device.get_mut(&self.device)
        {
            *n = n.saturating_sub(1);
            if *n == 0 {
                per_device.remove(&self.device);
            }
        }
    }
}

/// 503 for a diagnostic transfer over the limits.
/// Device reports the test as failed -> task retried later.
fn diag_busy() -> Response {
    metrics::counter!("dhonomos_diag_busy_total").increment(1);
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "30")],
        "too many diagnostic transfers; try again later",
    )
        .into_response()
}

/// Bucket that throttles the chunks of a download.
enum Throttle {
    /// Shared by all downloads.
    Total(Arc<FilesLive>),
    /// Own bucket of this download.
    Own(Bucket),
}

impl Throttle {
    fn take(&self, n: usize) -> std::time::Duration {
        match self {
            Self::Total(live) => live.total_rate.take(n),
            Self::Own(b) => b.take(n),
        }
    }
}

/// One running download: throttles its chunks, records the end in device events
/// (`file_download`: bytes sent, seconds, complete).
struct Download {
    buckets: Vec<Throttle>,
    sent: u64,
    size: Option<u64>,
    started: std::time::Instant,
    /// Taken when the outcome is recorded -> recorded once.
    log: Option<(Store, Uuid, Uuid, Value)>,
    _slot: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl Download {
    fn outcome(&mut self, finished: bool) -> Option<(Store, Uuid, Uuid, Value)> {
        let (store, tenant, device, mut detail) = self.log.take()?;
        metrics::gauge!("dhonomos_file_downloads_active").decrement(1.0);
        let complete = finished && self.size.is_none_or(|n| n == self.sent);
        detail["bytes"] = json!(self.sent);
        detail["seconds"] = json!((self.started.elapsed().as_secs_f64() * 1000.0).round() / 1000.0);
        detail["complete"] = json!(complete);
        if !complete {
            metrics::counter!("dhonomos_file_downloads_total", "outcome" => "aborted").increment(1);
        }
        Some((store, tenant, device, detail))
    }

    async fn finish(&mut self, finished: bool) {
        if let Some((store, tenant, device, detail)) = self.outcome(finished) {
            record_download(&store, tenant, device, &detail).await;
        }
    }
}

impl Drop for Download {
    fn drop(&mut self) {
        // hyper drops the body after Content-Length bytes, without polling to the end
        // -> whole download. Fewer bytes -> device left mid-transfer. Record without blocking.
        let whole = self.size.is_some_and(|n| n == self.sent);
        if let Some((store, tenant, device, detail)) = self.outcome(whole)
            && let Ok(rt) = tokio::runtime::Handle::try_current()
        {
            rt.spawn(async move { record_download(&store, tenant, device, &detail).await });
        }
    }
}

async fn record_download(store: &Store, tenant: Uuid, device: Uuid, detail: &Value) {
    if let Err(e) = store
        .record_event(tenant, Some(device), "file_download", detail)
        .await
    {
        tracing::warn!(error = %e, "failed to record download");
    }
}

/// `body` throttled by the buckets of `dl`; records the outcome at the end.
fn throttled(body: Body, dl: Download) -> Body {
    let stream =
        futures_util::stream::unfold(Some((body.into_data_stream(), dl)), |state| async move {
            let (mut inner, mut dl) = state?;
            match inner.next().await {
                Some(Ok(chunk)) => {
                    for b in &dl.buckets {
                        let wait = b.take(chunk.len());
                        if !wait.is_zero() {
                            tokio::time::sleep(wait).await;
                        }
                    }
                    dl.sent += chunk.len() as u64;
                    metrics::counter!("dhonomos_file_download_bytes_total")
                        .increment(chunk.len() as u64);
                    Some((Ok(chunk), Some((inner, dl))))
                }
                Some(Err(e)) => {
                    dl.finish(false).await;
                    Some((Err(e), None))
                }
                None => {
                    dl.finish(true).await;
                    None
                }
            }
        });
    Body::from_stream(stream)
}

#[derive(Debug, Deserialize)]
struct UploadSigned {
    /// `log` -> vendor log file; absent -> config file.
    k: Option<String>,
    e: u64,
    s: String,
}

/// Peer of a file-server request. Set when the server has connection info
/// (the binary does).
type Peer = Option<Extension<ConnectInfo<PeerAddr>>>;

/// Log a file-server refusal + source (bad link or signature, or device not ours).
fn refused(peer: &Peer, reason: &'static str) {
    let remote = peer.as_ref().map(|Extension(ConnectInfo(PeerAddr(a)))| *a);
    dhonomos_common::request_refused!("files", reason, remote);
}

/// Upload target (CO-08): `PUT|POST /uploads/{device}/{upload}?[k=log&]e=&s=`.
/// Config file -> `3 Vendor Configuration File` of the device, ready for download back.
/// Log (`k=log`) -> `2 Vendor Log File`.
async fn device_upload(
    State(st): State<Arc<FileServerState>>,
    Path((device, upload)): Path<(Uuid, Uuid)>,
    Query(q): Query<UploadSigned>,
    peer: Peer,
    body: Body,
) -> Response {
    let kind = match q.k.as_deref() {
        None => UploadKind::Config,
        Some("log") => UploadKind::Log,
        Some(_) => return (StatusCode::BAD_REQUEST, "unknown upload kind").into_response(),
    };
    if !st
        .files
        .signer
        .verify_upload(device, upload, kind, q.e, &q.s)
    {
        refused(&peer, "bad_signature");
        return (StatusCode::FORBIDDEN, "invalid or expired upload link").into_response();
    }
    let d = match st.store.get_device(device).await {
        Ok(Some(d)) if d.tenant_id == st.tenant_id => d,
        Ok(_) => {
            refused(&peer, "unknown_device");
            return (StatusCode::FORBIDDEN, "unknown device").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "device lookup failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    // Cheap early answer; on a race the registration below decides.
    if matches!(st.store.get_file(upload).await, Ok(Some(_))) {
        return (StatusCode::CONFLICT, "already uploaded").into_response();
    }
    let received = match receive_file(&st.files, upload, body).await {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let (size, sha256) = (received.size, received.sha256.clone());
    let label = d
        .serial_number
        .or(d.endpoint_id)
        .unwrap_or_else(|| device.to_string())
        .replace(['/', ':'], "_");
    let date = time::OffsetDateTime::now_utc().date();
    let (what, ext, event) = match kind {
        UploadKind::Config => ("config", "cfg", "config_file_uploaded"),
        UploadKind::Log => ("log", "log", "log_file_uploaded"),
    };
    // Last digits: UUIDv7 starts with a timestamp, same for all uploads in ~1 min.
    // Name must be unique.
    let tag = upload.simple().to_string();
    let name = format!("{label}-{what}-{date}-{}.{ext}", &tag[24..]);
    let file = NewFile {
        id: upload,
        tenant_id: st.tenant_id,
        name: name.clone(),
        file_type: kind.stored_file_type().into(),
        size_bytes: i64::try_from(size).unwrap_or(i64::MAX),
        sha256,
        version: None,
        device_id: Some(device),
    };
    match register_and_place(&st.store, &st.files, &file, &received).await {
        Ok(()) => {}
        // Other request with this link was first -> its file untouched.
        Err(PlaceError::Taken(_)) => {
            return (StatusCode::CONFLICT, "already uploaded").into_response();
        }
        Err(PlaceError::Store(e)) => {
            tracing::error!(error = %e, "registering an uploaded file failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        Err(PlaceError::Io) => return StatusCode::INSUFFICIENT_STORAGE.into_response(),
    }
    let _ = st
        .store
        .record_event(
            st.tenant_id,
            Some(device),
            event,
            &json!({ "file_id": upload, "name": name, "size_bytes": size }),
        )
        .await;
    metrics::counter!("dhonomos_device_uploads_total").increment(1);
    StatusCode::CREATED.into_response()
}

#[derive(Debug, Deserialize)]
struct DiagSigned {
    e: u64,
    s: String,
}

/// Download diagnostic source (DG-01, TR-143): `GET /diag/{device}/{bytes}?e=&s=`.
/// Sends `bytes` zero bytes, unthrottled -> device measures its own path.
async fn diag_download(
    State(st): State<Arc<FileServerState>>,
    Path((device, bytes)): Path<(Uuid, u64)>,
    Query(q): Query<DiagSigned>,
    peer: Peer,
) -> Response {
    if !st
        .files
        .signer
        .verify_diag_download(device, bytes, q.e, &q.s)
    {
        refused(&peer, "bad_signature");
        return (StatusCode::FORBIDDEN, "invalid or expired diagnostic link").into_response();
    }
    if bytes > dhonomos_core::files::DIAG_MAX_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "too many bytes asked").into_response();
    }
    let Some(slot) = st.diag.acquire(device) else {
        return diag_busy();
    };
    const CHUNK: u64 = 64 * 1024;
    let zeros = axum::body::Bytes::from_static(&[0u8; CHUNK as usize]);
    let started = std::time::Instant::now();
    // Slot moves with the stream -> freed when the body is done or dropped.
    let stream = futures_util::stream::unfold((bytes, slot), move |(left, slot)| {
        let zeros = zeros.clone();
        async move {
            if left == 0 {
                return None;
            }
            if started.elapsed() > DIAG_MAX_TIME {
                let cut = std::io::Error::other("diagnostic transfer took too long");
                return Some((Err(cut), (0, slot)));
            }
            let n = left.min(CHUNK);
            metrics::counter!("dhonomos_diag_bytes_total", "direction" => "down").increment(n);
            Some((Ok(zeros.slice(..n as usize)), (left - n, slot)))
        }
    });
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (header::CONTENT_LENGTH, bytes.to_string()),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}

/// Upload diagnostic sink (DG-01, TR-143): `PUT|POST /diag/{device}?e=&s=`.
/// Reads + counts the body, keeps nothing.
async fn diag_upload(
    State(st): State<Arc<FileServerState>>,
    Path(device): Path<Uuid>,
    Query(q): Query<DiagSigned>,
    peer: Peer,
    body: Body,
) -> Response {
    if !st.files.signer.verify_diag_upload(device, q.e, &q.s) {
        refused(&peer, "bad_signature");
        return (StatusCode::FORBIDDEN, "invalid or expired diagnostic link").into_response();
    }
    let Some(_slot) = st.diag.acquire(device) else {
        return diag_busy();
    };
    let mut stream = body.into_data_stream();
    let mut total = 0u64;
    let read = async {
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(c) => {
                    total += c.len() as u64;
                    if total > dhonomos_core::files::DIAG_MAX_BYTES {
                        return Err((StatusCode::PAYLOAD_TOO_LARGE, "too much data"));
                    }
                }
                Err(_) => return Err((StatusCode::BAD_REQUEST, "upload interrupted")),
            }
        }
        Ok(())
    };
    match tokio::time::timeout(DIAG_MAX_TIME, read).await {
        Ok(Ok(())) => {}
        Ok(Err(refusal)) => return refusal.into_response(),
        Err(_) => return (StatusCode::REQUEST_TIMEOUT, "upload took too long").into_response(),
    }
    metrics::counter!("dhonomos_diag_bytes_total", "direction" => "up").increment(total);
    StatusCode::NO_CONTENT.into_response()
}

/// Max BulkData report size, after decompression.
const MAX_REPORT_BYTES: u64 = 8 * 1024 * 1024;

/// BulkData HTTP collector (DG-04): `POST /bulkdata/{device}/{signature}`, JSON report,
/// optional gzip or deflate.
async fn bulkdata(
    State(st): State<Arc<FileServerState>>,
    Path((device, sig)): Path<(Uuid, String)>,
    peer: Peer,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let reject = |status: StatusCode, msg: &'static str, outcome: &'static str| {
        metrics::counter!("dhonomos_bulkdata_reports_total", "outcome" => outcome).increment(1);
        (status, msg).into_response()
    };
    let Some(ingest) = &st.metrics else {
        return reject(
            StatusCode::NOT_FOUND,
            "BulkData collection is disabled",
            "disabled",
        );
    };
    if !st.files.signer.verify_bulkdata(device, &sig) {
        refused(&peer, "bad_signature");
        return reject(StatusCode::FORBIDDEN, "invalid BulkData URL", "denied");
    }
    match st.store.get_device(device).await {
        Ok(Some(d)) if d.tenant_id == st.tenant_id && d.status == "active" => {}
        Ok(_) => {
            refused(&peer, "device_not_accepted");
            return reject(StatusCode::FORBIDDEN, "device not accepted", "denied");
        }
        Err(e) => {
            tracing::error!(error = %e, "device lookup failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }
    let encoding = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("identity")
        .to_ascii_lowercase();
    let raw = match encoding.as_str() {
        "identity" => Ok(body.to_vec()),
        "gzip" | "x-gzip" => inflate(flate2::read::GzDecoder::new(&body[..])),
        "deflate" => inflate(flate2::read::ZlibDecoder::new(&body[..])),
        _ => {
            return reject(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported Content-Encoding",
                "invalid",
            );
        }
    };
    let Ok(raw) = raw else {
        return reject(
            StatusCode::BAD_REQUEST,
            "cannot decompress the report",
            "invalid",
        );
    };
    let samples = match dhonomos_core::parse_bulkdata_json(&raw, time::OffsetDateTime::now_utc()) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(%device, error = %e, "rejected BulkData report");
            return reject(
                StatusCode::BAD_REQUEST,
                "not a JSON BulkData report",
                "invalid",
            );
        }
    };
    match ingest.ingest(device, &samples).await {
        Ok(_) => {
            metrics::counter!("dhonomos_bulkdata_reports_total", "outcome" => "stored")
                .increment(1);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            tracing::error!(%device, error = %e, "storing BulkData samples failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

fn inflate(reader: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut out = Vec::new();
    reader.take(MAX_REPORT_BYTES + 1).read_to_end(&mut out)?;
    if out.len() as u64 > MAX_REPORT_BYTES {
        return Err(std::io::Error::other("report too large"));
    }
    Ok(out)
}

async fn serve(
    State(st): State<Arc<FileServerState>>,
    Path((id, name)): Path<(Uuid, String)>,
    Query(q): Query<Signed>,
    peer: Peer,
    req: Request,
) -> Response {
    if !st.files.signer.verify(id, q.d, q.e, &q.s) {
        metrics::counter!("dhonomos_file_downloads_total", "outcome" => "denied").increment(1);
        refused(&peer, "bad_signature");
        return (StatusCode::FORBIDDEN, "invalid or expired link").into_response();
    }
    let file = match st.store.get_file(id).await {
        Ok(Some(f)) if f.tenant_id == st.tenant_id && f.name == name => f,
        Ok(_) => return (StatusCode::NOT_FOUND, "file not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "file lookup failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let slots = st.files.live.slots.get();
    let slot = match slots.as_ref() {
        Some((_, slots)) => match slots.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                metrics::counter!("dhonomos_file_downloads_total", "outcome" => "busy")
                    .increment(1);
                // CPE reports the Download as failed -> task retried later.
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::RETRY_AFTER, "60")],
                    "too many downloads; try again later",
                )
                    .into_response();
            }
        },
        None => None,
    };
    let head = req.method() == axum::http::Method::HEAD;
    let range = req
        .headers()
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let resp = match ServeFile::new(st.files.dir.join(id.to_string()))
        .oneshot(req)
        .await
    {
        Ok(r) => r.map(Body::new),
        Err(e) => match e {},
    };
    let ok = resp.status().is_success();
    metrics::counter!("dhonomos_file_downloads_total", "outcome" => if ok { "served" } else { "failed" })
        .increment(1);
    if !ok || head {
        return resp;
    }
    let size = resp
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    let detail = json!({ "file_id": id, "name": file.name, "range": range,
                         "status": resp.status().as_u16(), "size": size });
    let mut buckets = vec![Throttle::Total(st.files.live.clone())];
    let rate = st.files.live.per_download_rate.load(Ordering::Relaxed);
    if rate > 0 {
        buckets.push(Throttle::Own(Bucket::new(rate)));
    }
    metrics::gauge!("dhonomos_file_downloads_active").increment(1.0);
    let dl = Download {
        buckets,
        sent: 0,
        size,
        started: std::time::Instant::now(),
        log: Some((st.store.clone(), st.tenant_id, q.d, detail)),
        _slot: slot,
    };
    resp.map(|body| throttled(body, dl))
}

/// Router of the device-facing listener: downloads, uploads, diagnostics, BulkData
/// HTTP collector (`metrics` = `None` -> 404).
pub fn file_server(
    store: Store,
    files: FilesConfig,
    tenant_id: Uuid,
    metrics: Option<dhonomos_core::MetricsIngest>,
) -> Router {
    let state = Arc::new(FileServerState {
        store,
        files,
        tenant_id,
        metrics,
        diag: DiagSlots::new(DIAG_PER_DEVICE, DIAG_TOTAL),
    });
    Router::new()
        .route("/files/{id}/{name}", get(serve))
        .route(
            "/uploads/{device}/{upload}",
            axum::routing::put(device_upload)
                .post(device_upload)
                .layer(DefaultBodyLimit::disable()),
        )
        .route("/diag/{device}/{bytes}", get(diag_download))
        .route(
            "/diag/{device}",
            axum::routing::put(diag_upload)
                .post(diag_upload)
                .layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/bulkdata/{device}/{signature}",
            axum::routing::post(bulkdata).layer(DefaultBodyLimit::max(MAX_REPORT_BYTES as usize)),
        )
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_slots_limit_each_device_and_the_server() {
        let slots = DiagSlots::new(2, 3);
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let a1 = slots.acquire(a).expect("first of a");
        let a2 = slots.acquire(a).expect("second of a");
        assert!(slots.acquire(a).is_none(), "a device has two at a time");
        // Other device not blocked by it, up to the server total.
        let b1 = slots.acquire(b).expect("first of b");
        assert!(slots.acquire(b).is_none(), "the server has three in all");
        drop(a1);
        let b2 = slots.acquire(b).expect("a slot is free again");
        assert!(slots.acquire(Uuid::from_u128(3)).is_none());
        drop((a2, b1, b2));
        // All slots back; a refused request took nothing.
        let held: Vec<_> = (0..2).filter_map(|_| slots.acquire(a)).collect();
        assert_eq!(held.len(), 2);
        assert_eq!(slots.total.available_permits(), 1);
        drop(held);
        assert_eq!(slots.total.available_permits(), 3);
        assert!(slots.per_device.lock().is_ok_and(|m| m.is_empty()));
    }
}
