//! REST API response bodies -> OpenAPI document (NB-01).
//!
//! Handlers build JSON with `serde_json::json!` (`device_json`, `task_json`, ...).
//! Types here only describe it.
//! Field names, types, nullability = builders: `Option` -> nullable,
//! key a builder always emits -> `required`.
//! Tests compare schemas with real builder output -> new builder key must be added here too.

// Docs only: nothing constructs these types.
// `Serialize` only so that `#[serde(flatten)]` (`allOf` in the document) is accepted.
#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// `{"items": [...]}` list bodies, no paging.
macro_rules! lists {
    ($($(#[doc = $doc:literal])* $name:ident => $item:ty;)*) => {$(
        $(#[doc = $doc])*
        #[derive(Serialize, ToSchema)]
        pub(crate) struct $name {
            items: Vec<$item>,
        }
    )*};
}

lists! {
    /// Parameters.
    ParameterList => Parameter;
    /// Tasks, newest first.
    TaskList => Task;
    /// Events, newest first.
    EventList => Event;
    /// Audit records, newest first.
    AuditList => AuditEntry;
    /// Credentials of a device, no secrets.
    CredentialList => Credential;
    /// Jobs, newest first.
    JobList => Job;
    /// Job members, dispatch order.
    JobMemberList => JobMember;
    /// Silences.
    SilenceList => Silence;
    /// Stored files.
    FileList => StoredFile;
    /// Configuration backups, newest first.
    BackupList => ConfigBackup;
    /// Metrics + latest values.
    MetricList => MetricInfo;
    /// Operator accounts.
    UserList => User;
    /// API keys, no secrets.
    ApiKeyList => ApiKey;
    /// Server options, registry order.
    ServerSettingList => ServerSetting;
    /// Changes of a runtime option, newest first.
    ServerSettingHistory => ServerSettingChange;
}

/// One page of devices.
#[derive(Serialize, ToSchema)]
pub(crate) struct DevicePage {
    /// This page.
    items: Vec<Device>,
    /// All matching devices.
    total: i64,
    /// Page size used.
    limit: i64,
    /// Devices skipped.
    offset: i64,
}

/// Filter values for the device list. Each list sorted by value.
#[derive(Serialize, ToSchema)]
pub(crate) struct DeviceFacets {
    /// OUIs + manufacturer most of their devices report.
    oui: Vec<FacetValue>,
    /// Product classes.
    product_class: Vec<FacetValue>,
    /// Model names.
    model_name: Vec<FacetValue>,
}

/// Distinct value of a device column + count of matching devices.
#[derive(Serialize, ToSchema)]
pub(crate) struct FacetValue {
    /// Value, never empty.
    value: String,
    /// Matching devices with this value.
    count: i64,
    /// OUIs only: manufacturer most of these devices report; absent if none.
    #[serde(skip_serializing_if = "Option::is_none")]
    manufacturer: Option<String>,
}

/// Registered device (CWMP CPE or USP Agent).
#[derive(Serialize, ToSchema)]
pub(crate) struct Device {
    id: Uuid,
    /// `cwmp` or `usp`.
    protocol: String,
    /// Manufacturer OUI (CWMP).
    #[schema(required)]
    oui: Option<String>,
    /// Product class; empty = unknown.
    product_class: String,
    /// Serial number.
    #[schema(required)]
    serial_number: Option<String>,
    /// USP endpoint ID.
    #[schema(required)]
    endpoint_id: Option<String>,
    #[schema(required)]
    manufacturer: Option<String>,
    #[schema(required)]
    model_name: Option<String>,
    /// Firmware version.
    #[schema(required)]
    software_version: Option<String>,
    #[schema(required)]
    hardware_version: Option<String>,
    /// Root data model, `Device` or `InternetGatewayDevice`.
    #[schema(required)]
    data_model: Option<String>,
    /// CWMP connection request URL.
    #[schema(required)]
    connection_request_url: Option<String>,
    /// Negotiated CWMP version.
    #[schema(required)]
    cwmp_version: Option<String>,
    /// `active`, `quarantined` or `retired`.
    status: String,
    tags: Vec<String>,
    #[schema(format = DateTime)]
    first_seen_at: String,
    #[schema(required, format = DateTime)]
    last_contact_at: Option<String>,
    /// Last boot reported by the device.
    #[schema(required, format = DateTime)]
    last_boot_at: Option<String>,
    /// Address of the last contact.
    #[schema(required)]
    last_remote_addr: Option<String>,
    /// Subscriber links + custom attributes (CO-13): key -> string value.
    attributes: BTreeMap<String, String>,
    /// WebSocket server of the USP Agent; Controller connects to it (US-05).
    #[schema(required)]
    usp_ws_url: Option<String>,
    /// Start of the current XMPP session (CR over XMPP, ADR-104); null = none.
    #[schema(required, format = DateTime)]
    xmpp_connected_at: Option<String>,
    /// Full JID (`<device ID>@<domain>/<resource>`) of the live XMPP session; null = none.
    /// Always null if the API process does not run the XMPP server (`--role api`).
    #[schema(required)]
    xmpp_jid: Option<String>,
    /// UDP CR address of the device (`host:port`, STUN, ADR-040); null = not known.
    #[schema(required)]
    udp_cr_address: Option<String>,
    /// Last confirmation of that address.
    #[schema(required, format = DateTime)]
    udp_cr_seen_at: Option<String>,
    /// Last wake (any outcome); null = never.
    #[schema(required, format = DateTime)]
    last_wake_at: Option<String>,
    /// Channel of that wake: `xmpp`, `http`, `udp` or `usp`.
    /// Null -> nothing sent (no URL, failure, offline Agent) or no wake.
    #[schema(required)]
    last_wake_method: Option<String>,
    /// Outcome of that wake in words, e.g. `sent over XMPP`, `sent`, `failed: ...`.
    #[schema(required)]
    last_wake_outcome: Option<String>,
}

/// Parameter value from the device snapshot.
#[derive(Serialize, ToSchema)]
pub(crate) struct Parameter {
    /// Full parameter path.
    path: String,
    /// Last known value.
    #[schema(required)]
    value: Option<String>,
    /// XML Schema type, e.g. `unsignedInt`.
    #[schema(required)]
    r#type: Option<String>,
    /// Writable, if known.
    #[schema(required)]
    writable: Option<bool>,
    #[schema(format = DateTime)]
    updated_at: String,
}

/// Queued operation on a device.
/// Secrets in `payload` (`password`, `values[]` entries marked `secret`) -> `********`.
/// URL of an `upload` task -> without query string (holds the signature).
#[derive(Serialize, ToSchema)]
pub(crate) struct Task {
    id: Uuid,
    device_id: Uuid,
    /// Task kind, e.g. `get_parameter_values`.
    kind: String,
    /// Arguments of the kind.
    #[schema(value_type = Object)]
    payload: Value,
    /// `pending`, `running`, `succeeded`, `failed`, `cancelled` or `expired`.
    state: String,
    /// Attempts so far.
    attempts: i32,
    max_attempts: i32,
    /// Result of a successful run (kind-specific).
    #[schema(required, value_type = Option<Object>)]
    result: Option<Value>,
    /// Last error.
    #[schema(required)]
    error: Option<String>,
    #[schema(format = DateTime)]
    created_at: String,
    /// Higher runs first.
    priority: i16,
    /// Origin: `api`, `preset:<name>`, `job:<id>`, ...
    #[schema(required)]
    created_by: Option<String>,
    /// Bulk job of the task.
    #[schema(required)]
    job_id: Option<Uuid>,
    /// Task history, oldest first.
    trace: Vec<TaskStep>,
}

/// One step of the task history.
#[derive(Serialize, ToSchema)]
pub(crate) struct TaskStep {
    #[schema(format = DateTime)]
    at: String,
    /// `queued`, `dispatched` (sent to device), `waiting` (for a completion report, e.g.
    /// TransferComplete), `retry`, `succeeded`, `failed`, `cancelled` or `expired`.
    step: String,
    /// Attempt number (0 = before the first).
    attempt: i32,
    /// Origin (`queued`) or error.
    detail: Option<String>,
}

/// Task from `POST /devices/{id}/tasks`.
#[derive(Serialize, ToSchema)]
pub(crate) struct QueuedTask {
    #[serde(flatten)]
    task: Task,
    /// Wake outcome, e.g. `sent` or `skipped: ...`.
    /// Absent if the request set `connection_request` = false.
    connection_request: Option<String>,
}

/// A device event.
#[derive(Serialize, ToSchema)]
pub(crate) struct Event {
    /// Sequence number.
    id: i64,
    /// Kind, e.g. `inform`, `boot`, `config_file_uploaded`.
    kind: String,
    /// Kind-specific details.
    #[schema(value_type = Object)]
    detail: Value,
    #[schema(format = DateTime)]
    occurred_at: String,
}

/// One audit record.
#[derive(Serialize, ToSchema)]
pub(crate) struct AuditEntry {
    /// Sequence number.
    id: i64,
    /// Who: username, `key:<name>` (API key), `api-token`, `anonymous` or `system`.
    actor: String,
    /// Action, e.g. `task.create`.
    action: String,
    /// Object kind, e.g. `device`.
    target_type: String,
    /// Object ID.
    #[schema(required)]
    target_id: Option<String>,
    /// Action-specific details (any JSON value).
    detail: Value,
    #[schema(format = DateTime)]
    occurred_at: String,
}

/// Device credential, no secret.
#[derive(Serialize, ToSchema)]
pub(crate) struct Credential {
    /// `acs_auth` or `connection_request`.
    kind: String,
    username: String,
}

/// Broker account of a USP Agent (US-17).
#[derive(Serialize, ToSchema)]
pub(crate) struct MqttCredentials {
    username: String,
    /// Shown only once.
    password: String,
    /// Topic the Agent subscribes to.
    agent_topic: String,
    /// Topic the Controller subscribes to.
    controller_topic: String,
    /// Account enabled (= device `active`).
    enabled: bool,
}

/// Certificate issued to a USP Agent (US-08). PEM texts.
#[derive(Serialize, ToSchema)]
pub(crate) struct IssuedCertificate {
    certificate: String,
    /// Generated key, shown only once; null if the request had a CSR.
    #[schema(required)]
    private_key: Option<String>,
    /// Certificate + generated key, ready for the Agent (`obuspa -a` format);
    /// null if the request had a CSR.
    #[schema(required)]
    client_pem: Option<String>,
    /// Issuing CA certificate.
    ca_certificate: String,
    /// Serial number (hex).
    serial: String,
    /// SHA-256 fingerprint of the certificate (hex).
    sha256: String,
    #[schema(format = DateTime)]
    not_after: String,
}

/// Outcome of a connection request.
#[derive(Serialize, ToSchema)]
pub(crate) struct ConnectionRequestOutcome {
    /// E.g. `sent` or `skipped: ...`.
    connection_request: String,
}

/// Outcome of a data model refresh.
#[derive(Serialize, ToSchema)]
pub(crate) struct DataModelRefreshOutcome {
    /// `refreshing`: Agent connected -> model read now.
    /// `queued`: Agent offline -> cached model dropped, next connection reads it.
    status: String,
}

/// Member counts by state.
#[derive(Serialize, ToSchema)]
pub(crate) struct MemberCounts {
    queued: i64,
    dispatched: i64,
    verifying: i64,
    succeeded: i64,
    failed: i64,
    cancelled: i64,
}

/// Task of each job member.
/// Secrets in `payload` (`password`, `values[]` entries marked `secret`) -> `********`.
#[derive(Serialize, ToSchema)]
pub(crate) struct JobTask {
    kind: String,
    #[schema(value_type = Object)]
    payload: Value,
}

/// Bulk job or firmware campaign (CO-15).
#[derive(Serialize, ToSchema)]
pub(crate) struct Job {
    id: Uuid,
    name: String,
    /// Target device filter.
    #[schema(value_type = Object)]
    target: Value,
    task: JobTask,
    /// Rollout policy (stages, limits, gates).
    #[schema(value_type = Object)]
    policy: Value,
    /// `draft`, `running`, `paused`, `completed` or `cancelled`.
    state: String,
    /// Current stage (index into `policy.stages`).
    stage: i32,
    /// Reason for pause or stop.
    #[schema(required)]
    reason: Option<String>,
    /// Member count.
    total: i32,
    #[schema(required)]
    created_by: Option<String>,
    #[schema(format = DateTime)]
    created_at: String,
    #[schema(required, format = DateTime)]
    started_at: Option<String>,
    #[schema(required, format = DateTime)]
    finished_at: Option<String>,
    /// Members by state.
    counts: MemberCounts,
    /// Members by state, current stage only.
    stage_counts: MemberCounts,
}

/// Job from `GET /jobs/{id}`.
#[derive(Serialize, ToSchema)]
pub(crate) struct JobDetail {
    #[serde(flatten)]
    job: Job,
    /// Highest member rank in the current stage.
    stage_limit: i32,
    /// Cumulative stage percentages, last = 100.
    stages: Vec<f64>,
}

/// A job member.
#[derive(Serialize, ToSchema)]
pub(crate) struct JobMember {
    device_id: Uuid,
    /// Serial number or endpoint ID.
    #[schema(required)]
    device: Option<String>,
    /// Dispatch order.
    rank: i32,
    /// `queued`, `dispatched`, `verifying`, `succeeded`, `failed` or `cancelled`.
    state: String,
    #[schema(required)]
    task_id: Option<Uuid>,
    /// Failure reason.
    #[schema(required)]
    error: Option<String>,
    #[schema(required, format = DateTime)]
    finished_at: Option<String>,
}

/// Devices selected by a target filter.
#[derive(Serialize, ToSchema)]
pub(crate) struct JobPreview {
    /// Matching devices.
    count: i64,
    /// Max 20 of them.
    sample: Vec<Device>,
}

/// Alarm (CO-07).
#[derive(Serialize, ToSchema)]
pub(crate) struct Alarm {
    id: Uuid,
    device_id: Uuid,
    /// Rule name.
    rule: String,
    /// `critical`, `major`, `minor` or `warning`.
    severity: String,
    /// `active` or `cleared`.
    state: String,
    /// Human-readable summary.
    message: String,
    /// Rule-specific values.
    #[schema(value_type = Object)]
    detail: Value,
    #[schema(format = DateTime)]
    raised_at: String,
    #[schema(required, format = DateTime)]
    cleared_at: Option<String>,
    #[schema(required, format = DateTime)]
    acked_at: Option<String>,
    /// Who acknowledged it.
    #[schema(required)]
    acked_by: Option<String>,
    /// Silence that suppressed its notification.
    #[schema(required)]
    silenced_by: Option<Uuid>,
}

/// Alarm in a list + device label.
#[derive(Serialize, ToSchema)]
pub(crate) struct ListedAlarm {
    #[serde(flatten)]
    alarm: Alarm,
    /// Serial number or endpoint ID of the device.
    #[schema(required)]
    device: Option<String>,
}

/// Alarms + active counts.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmList {
    items: Vec<ListedAlarm>,
    /// Active alarms per severity, whole tenant (not only the listed ones).
    active: BTreeMap<String, i64>,
}

/// Silence (maintenance window, NB-07).
#[derive(Serialize, ToSchema)]
pub(crate) struct Silence {
    id: Uuid,
    /// Silenced rule; null = every rule.
    #[schema(required)]
    rule: Option<String>,
    /// Covered devices, as a job target filter.
    #[schema(value_type = Object)]
    devices: Value,
    #[schema(format = DateTime)]
    starts_at: String,
    #[schema(format = DateTime)]
    ends_at: String,
    /// `pending`, `active` or `ended`.
    state: String,
    comment: String,
    #[schema(required)]
    created_by: Option<String>,
    #[schema(format = DateTime)]
    created_at: String,
}

/// Stored file (firmware or configuration).
#[derive(Serialize, ToSchema)]
pub(crate) struct StoredFile {
    id: Uuid,
    /// Display and download name.
    name: String,
    /// TR-069 file type, e.g. `1 Firmware Upgrade Image`.
    file_type: String,
    size_bytes: i64,
    /// SHA-256 of the content (hex).
    sha256: String,
    /// Software version the file installs.
    #[schema(required)]
    version: Option<String>,
    #[schema(format = DateTime)]
    created_at: String,
    /// Device that uploaded it (vendor configuration files).
    #[schema(required)]
    device_id: Option<Uuid>,
}

/// Configuration backup (CO-08), no values.
#[derive(Serialize, ToSchema)]
pub(crate) struct ConfigBackup {
    id: Uuid,
    /// Source device.
    device_id: Uuid,
    label: String,
    /// Number of values.
    count: u64,
    #[schema(required)]
    created_by: Option<String>,
    #[schema(format = DateTime)]
    created_at: String,
}

/// One value of a backup.
#[derive(Serialize, ToSchema)]
pub(crate) struct BackupValue {
    path: String,
    value: String,
    /// XML Schema type; absent = unknown.
    r#type: Option<String>,
}

/// Backup + its values.
#[derive(Serialize, ToSchema)]
pub(crate) struct ConfigBackupValues {
    #[serde(flatten)]
    backup: ConfigBackup,
    values: Vec<BackupValue>,
}

/// What a backup left out.
#[derive(Serialize, ToSchema)]
pub(crate) struct BackupNotes {
    /// Secret values (passwords, keys) not stored.
    skipped_secrets: u64,
    /// Values left out: writability unknown.
    unknown_writability: u64,
}

/// Backup just taken.
#[derive(Serialize, ToSchema)]
pub(crate) struct CreatedBackup {
    #[serde(flatten)]
    backup: ConfigBackup,
    notes: BackupNotes,
}

/// Value that differs between a backup and the device.
#[derive(Serialize, ToSchema)]
pub(crate) struct ChangedValue {
    path: String,
    /// Value in the backup.
    backup: String,
    /// Value on the device; null = device reported none.
    #[schema(required)]
    current: Option<String>,
}

/// Drift between a backup and a device.
#[derive(Serialize, ToSchema)]
pub(crate) struct BackupDiff {
    changed: Vec<ChangedValue>,
    /// Backup paths missing on the device.
    missing: Vec<String>,
    /// Number of equal values.
    unchanged: u64,
    /// Compared device.
    device_id: Uuid,
}

/// Tasks queued to restore a backup.
#[derive(Serialize, ToSchema)]
pub(crate) struct RestoreResult {
    /// Target device.
    device_id: Uuid,
    /// IDs of the queued tasks.
    tasks: Vec<Uuid>,
}

/// Outcome of a unit replacement (CO-14).
#[derive(Serialize, ToSchema)]
pub(crate) struct Replacement {
    /// Backup of the old unit.
    backup: ConfigBackup,
    notes: BackupNotes,
    /// Tags copied to the new unit.
    tags: Vec<String>,
    /// Restore task IDs, queued on the new unit.
    tasks: Vec<Uuid>,
    /// Old unit, now retired.
    retired: Uuid,
}

/// Requested upload of a vendor configuration file.
#[derive(Serialize, ToSchema)]
pub(crate) struct ConfigFileRequest {
    /// Queued upload task.
    task_id: Uuid,
    /// File ID after the device upload.
    file_id: Uuid,
    /// Wake outcome.
    connection_request: String,
}

/// Metric reported by the device.
#[derive(Serialize, ToSchema)]
pub(crate) struct MetricInfo {
    /// Metric (parameter) path.
    path: String,
    #[schema(format = DateTime)]
    last_ts: String,
    last_value: f64,
}

/// One bucket of a time series.
#[derive(Serialize, ToSchema)]
pub(crate) struct SeriesPoint {
    /// Bucket start.
    #[schema(format = DateTime)]
    ts: String,
    avg: f64,
    min: f64,
    max: f64,
    /// Samples in the bucket.
    count: i64,
}

/// Aggregated time series.
#[derive(Serialize, ToSchema)]
pub(crate) struct MetricSeries {
    path: String,
    #[schema(format = DateTime)]
    from: String,
    #[schema(format = DateTime)]
    to: String,
    /// Bucket size in seconds.
    step: i64,
    points: Vec<SeriesPoint>,
}

/// Where the device posts BulkData reports.
#[derive(Serialize, ToSchema)]
pub(crate) struct BulkDataUrl {
    url: String,
}

/// Active devices with contact in the last 15 min, 1 h, 1 day.
#[derive(Serialize, ToSchema)]
pub(crate) struct OnlineCounts {
    m15: i64,
    h1: i64,
    d1: i64,
}

/// Sessions in one minute.
#[derive(Serialize, ToSchema)]
pub(crate) struct MinuteCount {
    #[schema(format = DateTime)]
    ts: String,
    n: i64,
}

/// Devices running one software version.
#[derive(Serialize, ToSchema)]
pub(crate) struct VersionCount {
    version: String,
    n: i64,
}

/// Fleet overview (UI-02).
#[derive(Serialize, ToSchema)]
pub(crate) struct Overview {
    /// Active devices.
    active: i64,
    online: OnlineCounts,
    /// Devices per protocol (any status).
    by_protocol: BTreeMap<String, i64>,
    /// Devices per status.
    by_status: BTreeMap<String, i64>,
    /// Sessions (Informs, USP connects) per minute, last hour, oldest first.
    sessions_per_minute: Vec<MinuteCount>,
    /// Tasks per state: pending, running, finished within 1 day.
    tasks: BTreeMap<String, i64>,
    /// Running jobs.
    jobs_running: i64,
    /// Top 8 software versions of active devices.
    versions: Vec<VersionCount>,
    /// Active alarms per severity.
    alarms: BTreeMap<String, i64>,
}

/// Operator account.
#[derive(Serialize, ToSchema)]
pub(crate) struct User {
    id: Uuid,
    username: String,
    /// `admin`, `operator` or `viewer`.
    role: String,
    /// Cannot log in.
    disabled: bool,
    #[schema(format = DateTime)]
    created_at: String,
    #[schema(required, format = DateTime)]
    last_login_at: Option<String>,
    /// Devices the user may see and act on; null = all.
    #[schema(required)]
    scope: Option<DeviceScope>,
    /// Two-factor authentication (TOTP app) on for the account (ADR-100).
    totp_enabled: bool,
}

/// Device scope (ADR-074): caller sees + acts on devices that meet every condition.
#[derive(Serialize, ToSchema)]
pub(crate) struct DeviceScope {
    /// All of these tags.
    tags: Option<Vec<String>>,
    /// Attributes with these exact values, e.g. `{"region": "busan"}`.
    attributes: Option<BTreeMap<String, String>>,
    /// `cwmp` or `usp`.
    protocol: Option<String>,
    /// Manufacturer OUI.
    oui: Option<String>,
    /// Product class.
    product_class: Option<String>,
}

/// API key, without the key itself.
#[derive(Serialize, ToSchema)]
pub(crate) struct ApiKey {
    id: Uuid,
    /// Purpose.
    name: String,
    /// First chars of the key, to recognise it.
    prefix: String,
    /// `admin`, `operator` or `viewer`.
    role: String,
    #[schema(required)]
    created_by: Option<String>,
    #[schema(format = DateTime)]
    created_at: String,
    #[schema(required, format = DateTime)]
    last_used_at: Option<String>,
    #[schema(required, format = DateTime)]
    revoked_at: Option<String>,
    /// Devices the key may see and act on; null = all.
    #[schema(required)]
    scope: Option<DeviceScope>,
}

/// Server option, as the server runs with it (`dhonomos_api::ServerSetting`).
#[derive(Serialize, ToSchema)]
pub(crate) struct ServerSetting {
    /// Option id, e.g. `acs_listen`.
    key: String,
    /// Command-line flag, e.g. `--acs-listen`.
    flag: String,
    /// Environment variable, e.g. `DHONOMOS_ACS_LISTEN`.
    env: String,
    /// Display group, e.g. `listeners_tls`.
    group: String,
    /// `bootstrap`, `runtime`, `security` or `secret`.
    category: String,
    /// First paragraph of the option help.
    help: String,
    /// `cli`, `env`, `default`, `unset`, or `web` (changed from the web).
    source: String,
    /// Option has a value (given or default).
    is_set: bool,
    /// Value in use (several -> joined with `,`); passwords + tokens in URLs -> `****`.
    /// Null for secrets and when unset.
    #[schema(required)]
    value: Option<String>,
    /// Web editor kind: `bool`, `list` (array of strings) or `text`.
    kind: String,
    /// Editable from the web: runtime option not set by the server configuration.
    editable: bool,
    /// Why a runtime option is not editable from the web; null otherwise.
    #[schema(required)]
    locked_reason: Option<String>,
    /// Value stored from the web (string, or array of strings for a list), masked like `value`.
    /// Also present when locked (then ignored). Null = none.
    #[schema(required, value_type = Option<serde_json::Value>)]
    web_value: Option<Value>,
}

/// One change of a runtime option from the web.
#[derive(Serialize, ToSchema)]
pub(crate) struct ServerSettingChange {
    /// Value before (masked); null = none.
    #[schema(required, value_type = Option<serde_json::Value>)]
    old: Option<Value>,
    /// Value after (masked); null = reset to default.
    #[schema(required, value_type = Option<serde_json::Value>)]
    new: Option<Value>,
    /// Who.
    #[schema(required)]
    actor: Option<String>,
    #[schema(format = DateTime)]
    at: String,
}

/// New API key + its secret.
#[derive(Serialize, ToSchema)]
pub(crate) struct NewApiKey {
    id: Uuid,
    name: String,
    role: String,
    prefix: String,
    #[schema(required)]
    scope: Option<DeviceScope>,
    /// Key (`pk_...`), shown only once.
    key: String,
}

/// Successful login.
#[derive(Serialize, ToSchema)]
pub(crate) struct LoginResult {
    username: String,
    /// `admin`, `operator` or `viewer`.
    role: String,
}

/// Current caller.
#[derive(Serialize, ToSchema)]
pub(crate) struct Caller {
    /// Username, `key:<name>` (API key), `api-token`, or `anonymous` (server without
    /// credentials); null = no caller identity attached.
    #[schema(required)]
    name: Option<String>,
    /// `admin`, `operator` or `viewer`; absent if `name` is null.
    role: Option<String>,
    /// `session`, `api_key`, `token` or `open`; absent if `name` is null.
    via: Option<String>,
    /// Devices the caller may see and act on; null = all. Absent if `name` is null.
    scope: Option<DeviceScope>,
    /// Login session of an account with two-factor authentication on (ADR-100).
    /// False for API keys + tokens. Absent if `name` is null.
    totp_enabled: Option<bool>,
    /// Account must have two-factor authentication (admin while the server requires it),
    /// no way around. `totp_enabled` false -> session may only enroll
    /// (`POST /auth/totp/setup`, `.../enable`); other calls -> 403. Absent if `name` is null.
    totp_required: Option<bool>,
    /// Account can set up two-factor authentication: local account (not single sign-on)
    /// on a server with a secrets key. Absent if `name` is null.
    totp_available: Option<bool>,
}

/// Secret for an authenticator app; inactive until confirmed.
#[derive(Serialize, ToSchema)]
pub(crate) struct TotpSetupResult {
    /// Secret, base32 (to type into an app).
    secret: String,
    /// `otpauth://totp/...` URI of the secret (= QR code content).
    otpauth_uri: String,
    /// QR code as an SVG document.
    /// Show as an image (`<img src="data:image/svg+xml;base64,...">`), not as markup.
    qr_svg: String,
}

/// Recovery codes, shown once.
#[derive(Serialize, ToSchema)]
pub(crate) struct RecoveryCodes {
    /// 10 single-use codes, `XXXX-XXXX-XXXX-XXXX`; each replaces one app code, once.
    recovery_codes: Vec<String>,
}

/// Refused login.
#[derive(Serialize, ToSchema)]
pub(crate) struct LoginFailure {
    /// What went wrong.
    error: String,
    /// True if username + password were right but the account needs a `totp` code.
    totp_required: Option<bool>,
}

/// Login methods the server offers.
#[derive(Serialize, ToSchema)]
pub(crate) struct AuthConfig {
    /// Password login (always true).
    password: bool,
    /// Single sign-on configured.
    sso: bool,
}

/// Skipped CSV row.
#[derive(Serialize, ToSchema)]
pub(crate) struct InvalidRow {
    /// Line number in the CSV (header = line 1).
    line: u64,
    error: String,
}

/// Outcome of an attribute import (CO-13).
#[derive(Serialize, ToSchema)]
pub(crate) struct ImportReport {
    /// Dry run or not.
    dry_run: bool,
    /// Data rows read.
    rows: u64,
    /// Device keys matched to exactly one device.
    matched: u64,
    /// Devices changed (0 in a dry run).
    updated: u64,
    /// Keys without a device (max 100).
    unknown: Vec<String>,
    unknown_count: u64,
    /// Keys shared by several devices, skipped (max 100).
    ambiguous: Vec<String>,
    /// Skipped rows (max 100).
    invalid: Vec<InvalidRow>,
    invalid_count: u64,
}

/// Task a preset would queue.
#[derive(Serialize, ToSchema)]
pub(crate) struct PlannedTask {
    /// Preset name.
    preset: String,
    /// Task index in the preset.
    index: u64,
    kind: String,
    /// Arguments; secrets -> `********`.
    #[schema(value_type = Object)]
    payload: Value,
    priority: i16,
    /// Run only once per device.
    once: bool,
    /// False if a `once` task already ran for this device.
    would_queue: bool,
    /// Planned by a preset script.
    script: bool,
}

/// Outcome of a preset dry run.
#[derive(Serialize, ToSchema)]
pub(crate) struct DryRunResult {
    items: Vec<PlannedTask>,
    /// One trace per script run: `preset`, `script`, `error`, `duration_ms`, `tasks`,
    /// `tags_added`, `tags_removed`, `logs`, `reads`, `declared`.
    #[schema(value_type = Vec<Object>)]
    scripts: Vec<Value>,
}

/// Alarm rule as loaded (see the alarm rules file).
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmRule {
    name: String,
    /// `critical`, `major`, `minor` or `warning`.
    severity: String,
    /// Target devices: fixed conditions as in job targets.
    #[schema(value_type = Object)]
    devices: Value,
    /// One of `{offline_minutes}`, `{wg_handshake_minutes}`, `{metric, above?, below?}` or
    /// `{event, detail?, count, within_minutes}`.
    #[schema(value_type = Object)]
    when: Value,
}

lists! {
    /// Loaded alarm rules.
    AlarmRuleList => AlarmRule;
    /// Alarm rule versions stored from the web, newest first.
    AlarmRuleHistory => AlarmRuleVersion;
}

/// Alarm rule set, as in the rule file.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmRuleSet {
    alarms: Vec<AlarmRule>,
    /// More alarms of one rule than this in one evaluation -> notified as one storm.
    storm_threshold: u64,
}

/// Alarm rules + their source.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmRuleSettings {
    /// `file` (the `--alarms` file), `web` (stored from the web) or `none`.
    source: String,
    /// Path of the `--alarms` file; null otherwise.
    #[schema(required)]
    path: Option<String>,
    /// Rules as YAML (file text or stored text); null = none.
    #[schema(required)]
    yaml: Option<String>,
    /// Editable from the web (no `--alarms` file).
    editable: bool,
    /// Rules the server evaluates.
    rules: AlarmRuleSet,
    /// Who stored them (`web` only).
    #[schema(required)]
    updated_by: Option<String>,
    /// When (`web` only).
    #[schema(required, format = DateTime)]
    updated_at: Option<String>,
}

/// One version of the alarm rules stored from the web.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmRuleVersion {
    /// Rules as YAML; null = removed.
    #[schema(required)]
    yaml: Option<String>,
    /// Who.
    #[schema(required)]
    actor: Option<String>,
    #[schema(format = DateTime)]
    at: String,
}

/// Wi-Fi radio (TR-181).
#[derive(Serialize, ToSchema)]
pub(crate) struct WifiRadio {
    /// Object path, e.g. `Device.WiFi.Radio.1`.
    id: String,
    #[schema(required)]
    enabled: Option<bool>,
    #[schema(required)]
    status: Option<String>,
    /// e.g. `2.4GHz`.
    #[schema(required)]
    band: Option<String>,
    #[schema(required)]
    channel: Option<f64>,
    #[schema(required)]
    bandwidth: Option<String>,
    #[schema(required)]
    standards: Option<String>,
    #[schema(required)]
    tx_power_pct: Option<f64>,
    #[schema(required)]
    noise_dbm: Option<f64>,
}

/// Station associated with a network.
#[derive(Serialize, ToSchema)]
pub(crate) struct WifiStation {
    #[schema(required)]
    mac: Option<String>,
    #[schema(required)]
    signal_dbm: Option<f64>,
    #[schema(required)]
    down_kbps: Option<f64>,
    #[schema(required)]
    up_kbps: Option<f64>,
    #[schema(required)]
    active: Option<bool>,
}

/// Wi-Fi network (TR-181 access point or TR-098 WLAN configuration).
#[derive(Serialize, ToSchema)]
pub(crate) struct WifiNetwork {
    #[schema(required)]
    ssid: Option<String>,
    #[schema(required)]
    bssid: Option<String>,
    /// Radio path (TR-181 only).
    radio: Option<String>,
    /// Channel (TR-098 only; TR-181 has it on the radio).
    channel: Option<f64>,
    /// Standards (TR-098 only).
    standards: Option<String>,
    #[schema(required)]
    enabled: Option<bool>,
    /// Security mode (TR-181) or beacon type (TR-098).
    #[schema(required)]
    security: Option<String>,
    stations: Vec<WifiStation>,
}

/// Latest neighbour scan (`wifi_neighbors` diagnostic).
#[derive(Serialize, ToSchema)]
pub(crate) struct NeighborScan {
    task_id: Uuid,
    #[schema(format = DateTime)]
    at: String,
    /// Neighbour networks, as reported by the diagnostic.
    #[schema(required, value_type = Option<Vec<Object>>)]
    neighbors: Option<Value>,
}

/// Wi-Fi view of a device (DG-02).
#[derive(Serialize, ToSchema)]
pub(crate) struct WifiView {
    radios: Vec<WifiRadio>,
    networks: Vec<WifiNetwork>,
    #[schema(required)]
    neighbor_scan: Option<NeighborScan>,
}

/// Parameter of a supported object.
#[derive(Serialize, ToSchema)]
pub(crate) struct SupportedParam {
    name: String,
    /// `read_only`, `read_write` or `write_only`.
    access: String,
    /// Value type, e.g. `string`, `unsigned_int`, `boolean`.
    #[serde(rename = "type")]
    value_type: String,
    /// `allowed`, `wont_change` or `unknown`.
    value_change: String,
}

/// Command of a supported object.
#[derive(Serialize, ToSchema)]
pub(crate) struct SupportedCommandInfo {
    /// e.g. `Reboot()`.
    name: String,
    /// `sync` or `async`.
    #[serde(rename = "type")]
    command_type: String,
    inputs: Vec<String>,
    outputs: Vec<String>,
}

/// Event of a supported object.
#[derive(Serialize, ToSchema)]
pub(crate) struct SupportedEvent {
    name: String,
    args: Vec<String>,
}

/// Supported object of the data model.
#[derive(Serialize, ToSchema)]
pub(crate) struct SupportedObject {
    /// e.g. `Device.WiFi.SSID.{i}.`.
    path: String,
    /// `read_only`, `add_delete`, `add_only` or `delete_only`.
    access: String,
    multi_instance: bool,
    params: Vec<SupportedParam>,
    commands: Vec<SupportedCommandInfo>,
    events: Vec<SupportedEvent>,
    /// Unique key sets of a multi-instance object.
    unique_keys: Vec<Vec<String>>,
}

/// Supported data model learned for the device firmware (US-11).
#[derive(Serialize, ToSchema)]
pub(crate) struct SupportedModel {
    /// Firmware fingerprint of the model.
    fingerprint: String,
    /// `cwmp` or `usp`.
    protocol: String,
    #[schema(format = DateTime)]
    learned_at: String,
    objects: Vec<SupportedObject>,
    /// Request paths the Agent could not answer.
    errors: Vec<String>,
}

/// Certificate issued to a USP Agent (no private key).
#[derive(Serialize, ToSchema)]
pub(crate) struct AgentCertificate {
    id: Uuid,
    device_id: Uuid,
    /// Serial number, hex.
    serial: String,
    /// SHA-256 of the DER certificate, hex.
    sha256: String,
    #[schema(format = DateTime)]
    not_after: String,
    /// Issued for a CSR (the key never left the Agent).
    from_csr: bool,
    #[schema(required)]
    issued_by: Option<String>,
    #[schema(format = DateTime)]
    issued_at: String,
    /// `valid`, `expired` or `revoked`.
    state: String,
    #[schema(required, format = DateTime)]
    revoked_at: Option<String>,
    #[schema(required)]
    revoked_by: Option<String>,
    #[schema(required)]
    revoke_reason: Option<String>,
    /// Device label (serial number or EndpointID) in the expiring list; null elsewhere.
    #[schema(required)]
    device: Option<String>,
}

/// Certificate revoked by fingerprint.
#[derive(Serialize, ToSchema)]
pub(crate) struct CertificateRevocation {
    /// ID of the certificate record.
    id: Uuid,
    /// SHA-256 of the DER certificate, hex.
    sha256: String,
    /// EndpointID of the certificate, if known.
    #[schema(required)]
    endpoint_id: Option<String>,
    /// Device it was issued to; null after that device was deleted, or if Dhonomos had no
    /// record of the certificate.
    #[schema(required)]
    device_id: Option<Uuid>,
    /// Serial number, hex; null if only the fingerprint is known.
    #[schema(required)]
    serial: Option<String>,
    /// Expiry; null = unknown (fingerprint then stays in the revoked set).
    #[schema(required, format = DateTime)]
    not_after: Option<String>,
    /// Revocation time (first revocation stands).
    #[schema(format = DateTime)]
    revoked_at: String,
    #[schema(required)]
    revoked_by: Option<String>,
    #[schema(required)]
    revoke_reason: Option<String>,
    /// Dhonomos already had a record of this certificate (else one was made).
    known: bool,
}

lists! {
    /// Agent certificates.
    CertificateList => AgentCertificate;
}

/// Provisioning preset + storage details.
#[derive(Serialize, ToSchema)]
pub(crate) struct StoredPreset {
    name: String,
    enabled: bool,
    /// Grows with every save; null for presets from the `--presets` file.
    #[schema(required)]
    revision: Option<i32>,
    #[schema(required)]
    updated_by: Option<String>,
    #[schema(required, format = DateTime)]
    updated_at: Option<String>,
    /// Preset as in the YAML file: `name`, `when`, `once`, `priority`, `run`,
    /// `script_source`, `args`, `enabled`.
    /// Task secrets in `run` (`password`, `values[]` entries with `secret: true`) -> `********`.
    /// Keep one on save -> send `********` back.
    #[schema(value_type = Object)]
    definition: Value,
}

/// Presets + their source.
#[derive(Serialize, ToSchema)]
pub(crate) struct PresetList {
    /// `database` (edited through the API) or `file` (`--presets`).
    source: String,
    items: Vec<StoredPreset>,
}

/// Saved revision or deletion of a preset.
#[derive(Serialize, ToSchema)]
pub(crate) struct PresetRevision {
    revision: i32,
    enabled: bool,
    deleted: bool,
    /// Preset at this revision; null = deletion.
    #[schema(required, value_type = Option<Object>)]
    definition: Option<Value>,
    #[schema(required)]
    changed_by: Option<String>,
    #[schema(format = DateTime)]
    changed_at: String,
}

lists! {
    /// Revisions of a preset, newest first.
    PresetHistory => PresetRevision;
}

/// Outcome of a preset import.
#[derive(Serialize, ToSchema)]
pub(crate) struct PresetImport {
    created: Vec<String>,
    updated: Vec<String>,
    unchanged: Vec<String>,
    /// Nothing was stored.
    dry_run: bool,
}

/// WireGuard hub (ADR-110): endpoint managed by Dhonomos.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgHub {
    id: Uuid,
    /// Unique within the tenant.
    name: String,
    /// Host name or IP address members dial.
    endpoint_host: String,
    /// Hub public key; null until the hub process reports it.
    #[schema(required)]
    public_key: Option<String>,
    /// Networks on the hub.
    networks: i64,
    /// First 12 chars of the hub token (`dwh_...`); null = none issued.
    /// Token itself shown only at issue.
    #[schema(required)]
    token_prefix: Option<String>,
    /// Issue time of the hub token.
    #[schema(required, format = DateTime)]
    token_created_at: Option<String>,
    /// Last call of the hub process.
    #[schema(required, format = DateTime)]
    last_seen_at: Option<String>,
    /// Source address of that call.
    #[schema(required)]
    last_seen_ip: Option<String>,
    /// Hub process version (from its `User-Agent`).
    #[schema(required)]
    version: Option<String>,
    /// Grows on every change of a network, member or site prefix of the hub.
    /// Hub state `ETag` = `"r<state_revision>"`.
    state_revision: i64,
    #[schema(format = DateTime)]
    created_at: String,
    #[schema(format = DateTime)]
    updated_at: String,
}

/// Hub token just issued.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgHubToken {
    /// `dwh_...` -> give to the hub process (`Authorization: Bearer ...`).
    /// Shown only once: server keeps its SHA-256.
    token: String,
    /// First 12 chars, to recognise it.
    token_prefix: String,
    hub: WgHub,
}

lists! {
    /// WireGuard hubs by name.
    WgHubList => WgHub;
}

/// Hub of a network.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgNetworkHub {
    id: Uuid,
    name: String,
    endpoint_host: String,
    /// Null until the hub process reports it.
    #[schema(required)]
    public_key: Option<String>,
}

/// Member counts of a network; only members the caller may see.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgMemberCounts {
    /// Device members, not revoked.
    device: i64,
    /// Client members, not revoked.
    client: i64,
    /// Revoked members (their rows stay).
    revoked: i64,
}

/// WireGuard overlay network.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgNetwork {
    id: Uuid,
    hub: WgNetworkHub,
    /// Unique within the tenant.
    name: String,
    /// Tunnel prefix, e.g. `10.77.0.0/24`.
    ipv4_prefix: String,
    /// Hub address in the network = first host of the prefix.
    hub_address: String,
    /// Hub UDP port for this network.
    listen_port: i32,
    mtu: i32,
    /// Keepalive seconds members send (0 = none).
    persistent_keepalive: i32,
    members: WgMemberCounts,
    #[schema(format = DateTime)]
    created_at: String,
    #[schema(format = DateTime)]
    updated_at: String,
}

lists! {
    /// WireGuard networks by name.
    WgNetworkList => WgNetwork;
}

/// LAN prefix behind a device member.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgSitePrefix {
    /// E.g. `192.168.10.0/24`.
    prefix: String,
    description: String,
}

/// Member of a WireGuard network.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgMember {
    id: Uuid,
    network_id: Uuid,
    /// `device` (CPE configured over TR-181) or `client` (operator PC or server).
    kind: String,
    name: String,
    /// CPE of a device member.
    #[schema(required)]
    device_id: Option<Uuid>,
    /// Owner account of a client; null for a server client, a device member, or a client
    /// whose account was deleted (then revoked).
    #[schema(required)]
    user_id: Option<Uuid>,
    /// Public key; null for a device member whose key is not known yet.
    #[schema(required)]
    public_key: Option<String>,
    /// Device members: where the key pair is made, `device` or `server`.
    #[schema(required)]
    key_mode: Option<String>,
    preshared_key_enabled: bool,
    /// Tunnel address.
    address: String,
    /// LAN prefixes behind a device member, by prefix.
    site_prefixes: Vec<WgSitePrefix>,
    #[schema(required, format = DateTime)]
    revoked_at: Option<String>,
    /// Revoke reason: caller text, or `user disabled`, `user deleted`, `role changed` or
    /// `scope changed` after a change of the owner account.
    #[schema(required)]
    revoked_reason: Option<String>,
    /// Last hub report about the member; null = no report.
    #[schema(required)]
    hub_status: Option<WgPeerStatus>,
    /// CPE configuration state of a device member; null for a client.
    #[schema(required)]
    device_status: Option<WgDeviceStatus>,
    /// Device members: time of the key rotation request; null = none open (cleared once
    /// the device uses a new key). Always null for a client.
    #[schema(required, format = DateTime)]
    rotate_requested_at: Option<String>,
    #[schema(format = DateTime)]
    created_at: String,
    #[schema(format = DateTime)]
    updated_at: String,
}

/// Last hub report about a member.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgPeerStatus {
    /// `ip:port` last seen by the hub.
    #[schema(required)]
    endpoint: Option<String>,
    /// Last handshake; null = never.
    #[schema(required, format = DateTime)]
    latest_handshake: Option<String>,
    /// Bytes the hub received from it.
    rx_bytes: i64,
    /// Bytes the hub sent to it.
    tx_bytes: i64,
    /// Report time.
    #[schema(format = DateTime)]
    reported_at: String,
}

/// CPE configuration state of a device member.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgDeviceStatus {
    /// `pending`: not configured yet; `applied`: device matches;
    /// `blocked`: waiting (`detail` says for what); `unsupported`: no `Device.WireGuard.`;
    /// `error`: device refused (`detail` has the fault).
    #[schema(example = "applied")]
    state: String,
    /// What `blocked` waits for, or the fault of `error`; null otherwise.
    #[schema(required)]
    detail: Option<String>,
    /// Last state record by a run on the device; null = never.
    #[schema(required, format = DateTime)]
    checked_at: Option<String>,
}

/// Member just created or re-keyed.
/// Private key, configuration, QR code: only in this response (not stored, no other call
/// returns them).
#[derive(Serialize, ToSchema)]
pub(crate) struct WgMemberCreated {
    #[serde(flatten)]
    member: WgMember,
    /// Client private key, if the key pair was made for the request (no `public_key`
    /// given); null otherwise. Shown only once: not stored, no other call returns it.
    #[schema(required)]
    private_key: Option<String>,
    /// Client wg-quick configuration file with that private key; null if `private_key` is
    /// null. Shown only once.
    #[schema(required)]
    config: Option<String>,
    /// File name for `config` (wg-quick names the interface after it, e.g.
    /// `branches.conf`); null if `private_key` is null.
    #[schema(required)]
    config_filename: Option<String>,
    /// `config` as QR code in SVG, for the WireGuard mobile apps; null if `private_key` is
    /// null. Shown only once.
    #[schema(required)]
    qr_svg: Option<String>,
    /// Pre-shared key (32 bytes, base64) made for the request: creation with
    /// `preshared_key_enabled`, re-key of a client that has one, or a change that turns it
    /// on; null otherwise. Shown only once: stored sealed, no other call returns it.
    #[schema(required)]
    preshared_key: Option<String>,
}

/// Client configuration file without the private key (a comment line in its place).
#[derive(Serialize, ToSchema)]
pub(crate) struct WgClientConfig {
    /// wg-quick configuration.
    config: String,
    /// File name to save it as.
    config_filename: String,
}

/// Everything a hub should run (`GET /wg-hub/state`).
#[derive(Serialize, ToSchema)]
pub(crate) struct WgHubState {
    hub_id: Uuid,
    /// State revision (`ETag` = `"r<revision>"`).
    revision: i64,
    /// Hub networks, by listen port.
    networks: Vec<WgHubNetwork>,
}

/// One network = one interface on the hub.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgHubNetwork {
    id: Uuid,
    name: String,
    /// `dwg<listen_port>`.
    interface: String,
    listen_port: u16,
    /// Tunnel prefix, e.g. `10.77.0.0/24`.
    prefix: String,
    /// Own hub address = first host of the prefix.
    address: String,
    mtu: u16,
    /// Members not revoked + with a public key, by address.
    peers: Vec<WgHubPeer>,
}

/// Peer of a hub network.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgHubPeer {
    member_id: Uuid,
    /// `device` or `client`.
    kind: String,
    public_key: String,
    /// Member `/32`, then its LAN prefixes, ascending.
    allowed_ips: Vec<String>,
    /// Pre-shared key of the peer, 32 bytes, base64; absent if none.
    /// Secret: the hub never logs it.
    #[serde(skip_serializing_if = "Option::is_none")]
    preshared_key: Option<String>,
}

/// Body of `PUT /wg-hub/public-key`.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgHubPublicKey {
    /// Hub public key, 44 chars base64.
    public_key: String,
}

/// Body of `POST /wg-hub/status`.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgHubStatusReport {
    /// Max 65,536.
    peers: Vec<WgHubPeerStatus>,
}

/// One peer as the hub sees it.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgHubPeerStatus {
    /// Network (interface) of the peer.
    network_id: Uuid,
    public_key: String,
    /// `ip:port` last seen.
    endpoint: Option<String>,
    /// Last handshake, Unix seconds; null or `<= 0` = never.
    latest_handshake: Option<i64>,
    /// Bytes received from it (max 2^63 - 1).
    rx_bytes: u64,
    /// Bytes sent to it (max 2^63 - 1).
    tx_bytes: u64,
}

/// Answer of `POST /wg-hub/status`.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgHubStatusAccepted {
    /// Peers stored: live members of the hub networks.
    accepted: usize,
    /// Peers not stored: unknown keys, revoked members, other hubs' networks, repeats.
    ignored: usize,
}

/// Answer of a key rotation for a whole network.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgKeyRotations {
    /// Live device members asked for a new key.
    requested: i64,
}

/// Live device member of a device or its twin (other record of the same CPE, CWMP or USP),
/// as listed in the WireGuard view of the device.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgDeviceMember {
    #[serde(flatten)]
    member: WgMember,
    /// Network name of the member.
    network_name: String,
    /// Null = member of the device itself; else the twin record that owns it.
    #[schema(required)]
    via_twin: Option<WgViaTwin>,
    /// Last tunnel report of the owner record (device, or twin of `via_twin`), from its
    /// stored parameters; null if its snapshot has no `Device.WireGuard.Tunnel` with the
    /// network alias.
    #[schema(required)]
    device_side: Option<WgDeviceSide>,
}

/// Tunnel of a network as the device sees it: `Device.WireGuard.Tunnel.{t}` + `Peer.{p}`
/// rows with `Alias` = network alias (`dhonomos-wg-<network id, 32 hex>`).
/// Value missing in the snapshot -> null.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgDeviceSide {
    /// `Tunnel.{t}.Status`, e.g. `Enabled` or `Disabled`.
    #[schema(required, example = "Enabled")]
    tunnel_status: Option<String>,
    /// `Tunnel.{t}.Interface.1.Status`, e.g. `Up` or `Down`.
    #[schema(required, example = "Up")]
    interface_status: Option<String>,
    /// `Peer.{p}.LastHandshakeTime`: seconds since last handshake at read time (`read_at`);
    /// 0 = never.
    #[schema(required)]
    last_handshake_secs: Option<u64>,
    /// `Tunnel.{t}.Stats.BytesSent`.
    #[schema(required)]
    bytes_sent: Option<u64>,
    /// `Tunnel.{t}.Stats.BytesReceived`.
    #[schema(required)]
    bytes_received: Option<u64>,
    /// Store time of the newest of these values.
    #[schema(format = DateTime)]
    read_at: String,
}

/// The thresholds of the tunnel states, in seconds.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgThresholds {
    /// Handshake younger than this -> `connected`.
    #[schema(example = 180)]
    connected_secs: i64,
    /// Handshake older than this -> `stale` (`idle` in between).
    #[schema(example = 900)]
    stale_secs: i64,
    /// Hub silent for longer -> its members `unknown`.
    #[schema(example = 300)]
    hub_silent_secs: i64,
}

/// Live members per tunnel state.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgStateCounts {
    /// All of them.
    total: i64,
    connected: i64,
    idle: i64,
    stale: i64,
    never: i64,
    /// Hub of the member silent -> nothing known.
    unknown: i64,
}

/// Tunnel states of device and client members.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgSummaryTotals {
    device: WgStateCounts,
    client: WgStateCounts,
}

/// Tunnel states of the members of one network.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgSummaryNetwork {
    id: Uuid,
    name: String,
    hub_id: Uuid,
    hub_name: String,
    device: WgStateCounts,
    client: WgStateCounts,
}

/// WireGuard tunnel health: live members the caller may see, per tunnel state.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgSummary {
    thresholds: WgThresholds,
    /// All networks.
    totals: WgSummaryTotals,
    /// Each network, by name.
    networks: Vec<WgSummaryNetwork>,
}

/// Other record of the same CPE; owner of a member.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgViaTwin {
    /// Twin device.
    device_id: Uuid,
    /// Twin protocol, `cwmp` or `usp`.
    #[schema(example = "cwmp")]
    protocol: String,
}

lists! {
    /// Live device members of a device and its twins, by network name.
    WgDeviceMemberList => WgDeviceMember;
}

/// One page of network members.
#[derive(Serialize, ToSchema)]
pub(crate) struct WgMemberPage {
    /// This page, by address.
    items: Vec<WgMember>,
    /// All members the caller may see (paging filters applied).
    total: i64,
    /// Page size used.
    limit: i64,
    /// Members skipped.
    offset: i64,
}

#[cfg(test)]
mod tests {
    //! Drift guard: real builder output vs schemas of the generated document.
    #![allow(clippy::unwrap_used)]

    use std::collections::BTreeSet;

    use dhonomos_store as store;
    use serde_json::{Value, json};
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    use uuid::Uuid;

    fn doc() -> Value {
        serde_json::to_value(crate::openapi::document()).unwrap()
    }

    /// `$ref` -> named schema (recursive).
    fn resolve<'a>(doc: &'a Value, schema: &'a Value) -> &'a Value {
        match schema["$ref"].as_str() {
            Some(r) => {
                let name = r.strip_prefix("#/components/schemas/").unwrap();
                let target = &doc["components"]["schemas"][name];
                assert!(target.is_object(), "dangling reference {r}");
                resolve(doc, target)
            }
            None => schema,
        }
    }

    /// Declared + required properties; `allOf` parts merged (flattened types).
    fn object_shape(
        doc: &Value,
        schema: &Value,
    ) -> Option<(serde_json::Map<String, Value>, BTreeSet<String>)> {
        let schema = resolve(doc, schema);
        let mut props = serde_json::Map::new();
        let mut required = BTreeSet::new();
        let mut found = false;
        if let Some(parts) = schema["allOf"].as_array() {
            for part in parts {
                if let Some((p, r)) = object_shape(doc, part) {
                    props.extend(p);
                    required.extend(r);
                    found = true;
                }
            }
        }
        if let Some(p) = schema["properties"].as_object() {
            props.extend(p.clone());
            found = true;
        }
        for r in schema["required"].as_array().into_iter().flatten() {
            required.insert(r.as_str().unwrap().to_owned());
        }
        found.then_some((props, required))
    }

    fn json_type(v: &Value) -> &'static str {
        match v {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }

    /// `value` vs `schema`: object keys (all required present, none undeclared), JSON types,
    /// nullability, `uuid` / `date-time` formats. Nested objects, arrays, maps: recursive.
    fn check(doc: &Value, schema: &Value, value: &Value, at: &str) {
        let schema = resolve(doc, schema);
        if let Some((props, required)) = object_shape(doc, schema) {
            let obj = value
                .as_object()
                .unwrap_or_else(|| panic!("{at}: expected an object, got {value}"));
            let keys: BTreeSet<&String> = obj.keys().collect();
            let declared: BTreeSet<&String> = props.keys().collect();
            let undeclared: Vec<_> = keys.difference(&declared).collect();
            assert!(
                undeclared.is_empty(),
                "{at}: keys missing from the schema: {undeclared:?}"
            );
            let absent: Vec<_> = required.iter().filter(|r| !obj.contains_key(*r)).collect();
            assert!(
                absent.is_empty(),
                "{at}: required properties the builder does not emit: {absent:?}"
            );
            for (k, v) in obj {
                check(doc, &props[k], v, &format!("{at}.{k}"));
            }
            return;
        }
        let types: Vec<&str> = match &schema["type"] {
            Value::String(t) => vec![t.as_str()],
            Value::Array(ts) => ts.iter().filter_map(Value::as_str).collect(),
            // No type -> any JSON value.
            _ => return,
        };
        let actual = json_type(value);
        assert!(
            types.contains(&actual) || (actual == "integer" && types.contains(&"number")),
            "{at}: {actual} where the schema allows {types:?}"
        );
        match value {
            Value::String(s) => match schema["format"].as_str() {
                Some("uuid") => {
                    assert!(Uuid::parse_str(s).is_ok(), "{at}: {s:?} is not a UUID");
                }
                Some("date-time") => assert!(
                    OffsetDateTime::parse(s, &Rfc3339).is_ok(),
                    "{at}: {s:?} is not an RFC 3339 time"
                ),
                _ => {}
            },
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    check(doc, &schema["items"], item, &format!("{at}[{i}]"));
                }
            }
            Value::Object(map) if schema["additionalProperties"].is_object() => {
                for (k, v) in map {
                    check(
                        doc,
                        &schema["additionalProperties"],
                        v,
                        &format!("{at}.{k}"),
                    );
                }
            }
            _ => {}
        }
    }

    /// Each sample matches component schema `name`; top-level keys = schema properties.
    fn assert_matches(doc: &Value, name: &str, samples: &[Value]) {
        let schema = &doc["components"]["schemas"][name];
        assert!(schema.is_object(), "no component schema {name}");
        let (props, _) = object_shape(doc, schema).unwrap();
        let declared: BTreeSet<&String> = props.keys().collect();
        for (i, sample) in samples.iter().enumerate() {
            let keys: BTreeSet<&String> = sample.as_object().unwrap().keys().collect();
            assert_eq!(
                keys, declared,
                "{name} (sample {i}): builder keys and schema properties differ"
            );
            check(doc, schema, sample, &format!("{name}[{i}]"));
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    fn device(full: bool) -> store::Device {
        let some = |s: &str| full.then(|| s.to_owned());
        store::Device {
            id: Uuid::now_v7(),
            tenant_id: store::DEFAULT_TENANT,
            protocol: "cwmp".into(),
            oui: some("001122"),
            product_class: "Box".into(),
            serial_number: some("SN1"),
            endpoint_id: some("os::001122-SN1"),
            manufacturer: some("Acme"),
            model_name: some("X1"),
            software_version: some("1.0"),
            hardware_version: some("A"),
            data_model: some("Device"),
            connection_request_url: some("http://192.0.2.1:7547/"),
            cwmp_version: some("1.4"),
            status: "active".into(),
            tags: vec!["lab".into()],
            first_seen_at: now(),
            last_contact_at: full.then(now),
            last_boot_at: full.then(now),
            last_remote_addr: some("192.0.2.1"),
            attributes: if full {
                json!({ "subscriber": "12345" })
            } else {
                json!({})
            },
            usp_ws_url: some("ws://192.0.2.9:7650/usp"),
            xmpp_connected_at: full.then(now),
            udp_cr_address: some("198.51.100.7:50000"),
            udp_cr_seen_at: full.then(now),
            last_wake_at: full.then(now),
            last_wake_method: some("xmpp"),
            last_wake_outcome: some("sent over XMPP"),
        }
    }

    fn task(full: bool) -> store::Task {
        store::Task {
            id: Uuid::now_v7(),
            device_id: Uuid::now_v7(),
            kind: "download".into(),
            payload: json!({ "url": "http://example.com/fw.bin", "password": "secret" }),
            state: store::TaskState::Succeeded,
            attempts: 1,
            max_attempts: 3,
            result: full.then(|| json!({ "status": 0 })),
            error: full.then(|| "timeout".into()),
            created_at: now(),
            priority: 5,
            created_by: full.then(|| "api".into()),
            job_id: full.then(Uuid::now_v7),
            trace: if full {
                json!([
                    { "at": "2026-10-04T05:00:00.123456+00:00", "step": "queued", "attempt": 0, "detail": "api" },
                    { "at": "2026-10-04T05:00:01+00:00", "step": "retry", "attempt": 1, "detail": "timeout" },
                ])
            } else {
                json!([])
            },
        }
    }

    fn job(full: bool) -> store::Job {
        store::Job {
            id: Uuid::now_v7(),
            tenant_id: store::DEFAULT_TENANT,
            name: "fw 2.0".into(),
            target: json!({ "product_class": "Box" }),
            task_kind: "download".into(),
            task_payload: json!({ "url": "http://example.com/fw.bin" }),
            policy: json!({ "stages": [10.0, 100.0] }),
            state: "running".into(),
            stage: 0,
            reason: full.then(|| "paused by operator".into()),
            total: 20,
            created_by: full.then(|| "api".into()),
            created_at: now(),
            started_at: full.then(now),
            finished_at: full.then(now),
        }
    }

    fn alarm(full: bool) -> store::Alarm {
        store::Alarm {
            id: Uuid::now_v7(),
            tenant_id: store::DEFAULT_TENANT,
            device_id: Uuid::now_v7(),
            rule: "offline".into(),
            severity: "major".into(),
            state: "active".into(),
            message: "No contact for 30 minutes".into(),
            detail: json!({ "value": 30.0 }),
            raised_at: now(),
            cleared_at: full.then(now),
            acked_at: full.then(now),
            acked_by: full.then(|| "alice".into()),
            silenced_by: full.then(Uuid::now_v7),
        }
    }

    fn scope() -> store::DeviceScope {
        store::DeviceScope {
            tags: vec!["east".into()],
            attributes: [("region".to_owned(), "busan".to_owned())].into(),
            protocol: Some("cwmp".into()),
            oui: Some("00259E".into()),
            product_class: Some("HG8245".into()),
        }
    }

    fn backup() -> store::ConfigBackup {
        store::ConfigBackup {
            id: Uuid::now_v7(),
            tenant_id: store::DEFAULT_TENANT,
            device_id: Uuid::now_v7(),
            label: "before upgrade".into(),
            params: json!([
                { "path": "Device.WiFi.SSID.1.SSID", "value": "home", "type": "string" },
                { "path": "Device.X_Vendor.Mode", "value": "1" },
            ]),
            created_by: Some("api".into()),
            created_at: now(),
        }
    }

    #[test]
    fn builders_match_schemas() {
        let doc = doc();
        let both = |f: &dyn Fn(bool) -> Value| [f(true), f(false)];

        assert_matches(
            &doc,
            "Device",
            &both(&|full| {
                crate::device_value(
                    &device(full),
                    full.then(|| "id@xmpp.example/cwmp-0123456789ab".into()),
                )
            }),
        );
        assert_matches(
            &doc,
            "Parameter",
            &both(&|full| {
                crate::param_json(&store::StoredParam {
                    path: "Device.DeviceInfo.UpTime".into(),
                    value: full.then(|| "42".into()),
                    xsd_type: full.then(|| "unsignedInt".into()),
                    writable: full.then_some(false),
                    updated_at: now(),
                })
            }),
        );
        assert_matches(&doc, "Task", &both(&|full| crate::task_json(&task(full))));
        assert_matches(
            &doc,
            "DeviceFacets",
            &both(&|full| {
                let value = |v: &str, manufacturer: Option<&str>| store::FacetValue {
                    value: v.into(),
                    count: 3,
                    manufacturer: manufacturer.map(Into::into),
                };
                crate::facets_json(&store::DeviceFacets {
                    oui: vec![
                        value("B01408", full.then_some("LSI")),
                        value("00D09E", None),
                    ],
                    product_class: vec![value("LTE347", None)],
                    model_name: if full {
                        vec![value("LTE347", None)]
                    } else {
                        Vec::new()
                    },
                })
            }),
        );
        assert_matches(
            &doc,
            "ServerSetting",
            &both(&|full| {
                serde_json::to_value(crate::ServerSetting {
                    key: "acs_listen".into(),
                    flag: "--acs-listen".into(),
                    env: "DHONOMOS_ACS_LISTEN".into(),
                    group: "listeners_tls".into(),
                    category: crate::SettingCategory::Bootstrap,
                    help: "ACS listen address".into(),
                    source: if full {
                        crate::SettingSource::Default
                    } else {
                        crate::SettingSource::Unset
                    },
                    is_set: full,
                    value: full.then(|| "[::]:7547".into()),
                    kind: crate::SettingKind::Text,
                    editable: full,
                    locked_reason: (!full).then(|| "set in the server's configuration".into()),
                    web_value: full.then(|| json!("[::]:7547")),
                })
                .unwrap()
            }),
        );
        assert_matches(
            &doc,
            "ServerSettingChange",
            &[true, false].map(|full| {
                crate::settings::change_json(&store::RuntimeSettingChange {
                    old: full.then(|| json!("12")),
                    new: full.then(|| json!(["a", "b"])),
                    actor: full.then(|| "alice".into()),
                    at: now(),
                })
            }),
        );
        assert_matches(
            &doc,
            "AlarmRuleVersion",
            &[true, false].map(|full| {
                crate::alarm_rules::version_json(&store::AlarmRulesVersion {
                    yaml: full.then(|| "alarms: []".into()),
                    actor: full.then(|| "alice".into()),
                    at: now(),
                })
            }),
        );
        assert_matches(
            &doc,
            "Event",
            &[crate::event_json(&store::Event {
                id: 7,
                device_id: Some(Uuid::now_v7()),
                kind: "inform".into(),
                detail: json!({ "events": ["2 PERIODIC"] }),
                occurred_at: now(),
            })],
        );
        assert_matches(
            &doc,
            "AuditEntry",
            &both(&|full| {
                crate::audit_json(&store::AuditEntry {
                    id: 9,
                    actor: "alice".into(),
                    action: "device.status".into(),
                    target_type: "device".into(),
                    target_id: full.then(|| Uuid::now_v7().to_string()),
                    detail: if full {
                        json!({ "to": "retired" })
                    } else {
                        Value::Null
                    },
                    occurred_at: now(),
                })
            }),
        );

        let counts = store::JobCounts {
            by_state: vec![("queued".into(), 18, 1), ("succeeded".into(), 2, 1)],
        };
        assert_matches(
            &doc,
            "Job",
            &both(&|full| crate::jobs::job_json(&job(full), Some(&counts))),
        );
        assert_matches(
            &doc,
            "JobDetail",
            &both(&|full| {
                crate::jobs::job_detail_json(
                    &job(full),
                    &counts,
                    2,
                    &dhonomos_jobs::Policy::default(),
                )
            }),
        );
        assert_matches(
            &doc,
            "JobMember",
            &both(&|full| {
                crate::jobs::member_json(&store::JobMember {
                    device_id: Uuid::now_v7(),
                    device_label: full.then(|| "SN1".into()),
                    rank: 1,
                    state: "failed".into(),
                    task_id: full.then(Uuid::now_v7),
                    error: full.then(|| "fault 9010".into()),
                    finished_at: full.then(now),
                })
            }),
        );

        assert_matches(
            &doc,
            "Alarm",
            &both(&|full| dhonomos_core::alarms::alarm_json(&alarm(full))),
        );
        let label = "SN1".to_owned();
        assert_matches(
            &doc,
            "ListedAlarm",
            &both(&|full| crate::alarms::listed_alarm_json(&alarm(full), full.then_some(&label))),
        );
        assert_matches(
            &doc,
            "Silence",
            &both(&|full| {
                crate::alarms::silence_json(&store::Silence {
                    id: Uuid::now_v7(),
                    tenant_id: store::DEFAULT_TENANT,
                    rule: full.then(|| "offline".into()),
                    devices: store::DeviceFilter {
                        tags: vec!["lab".into()],
                        ..Default::default()
                    },
                    starts_at: now(),
                    ends_at: now() + time::Duration::hours(1),
                    comment: "maintenance".into(),
                    created_by: full.then(|| "alice".into()),
                    created_at: now(),
                })
            }),
        );

        assert_matches(
            &doc,
            "StoredFile",
            &both(&|full| {
                crate::files::file_json(&store::StoredFile {
                    id: Uuid::now_v7(),
                    tenant_id: store::DEFAULT_TENANT,
                    name: "fw.bin".into(),
                    file_type: "1 Firmware Upgrade Image".into(),
                    size_bytes: 1024,
                    sha256: vec![0xab; 32],
                    version: full.then(|| "2.0".into()),
                    created_at: now(),
                    device_id: full.then(Uuid::now_v7),
                })
            }),
        );
        assert_matches(
            &doc,
            "ConfigBackup",
            &[crate::lifecycle::backup_json(&backup(), false)],
        );
        assert_matches(
            &doc,
            "ConfigBackupValues",
            &[crate::lifecycle::backup_json(&backup(), true)],
        );

        assert_matches(
            &doc,
            "User",
            &both(&|full| {
                crate::auth::user_json(&store::User {
                    id: Uuid::now_v7(),
                    tenant_id: store::DEFAULT_TENANT,
                    username: "alice".into(),
                    password_hash: "$argon2id$...".into(),
                    role: "operator".into(),
                    disabled: false,
                    created_at: now(),
                    last_login_at: full.then(now),
                    scope: full.then(scope),
                    totp_enabled: full,
                })
            }),
        );
        assert_matches(
            &doc,
            "ApiKey",
            &both(&|full| {
                crate::auth::key_json(&store::ApiKey {
                    id: Uuid::now_v7(),
                    tenant_id: store::DEFAULT_TENANT,
                    name: "billing".into(),
                    prefix: "pk_abcdefg".into(),
                    role: "viewer".into(),
                    created_by: full.then(|| "alice".into()),
                    created_by_user: full.then(Uuid::now_v7),
                    created_at: now(),
                    last_used_at: full.then(now),
                    revoked_at: full.then(now),
                    scope: full.then(scope),
                })
            }),
        );

        let rules = dhonomos_core::alarms::AlarmRules::from_yaml(
            "alarms:\n  - { name: offline, severity: major, when: { offline_minutes: 30 } }\n  - { name: hot, severity: minor, devices: { tags: [lab] }, when: { metric: Device.X, above: 80 } }\n  - { name: reboots, severity: warning, when: { event: inform, count: 3, within_minutes: 60 } }\n",
        )
        .unwrap();
        assert_matches(
            &doc,
            "AlarmRule",
            &rules
                .iter()
                .map(|r| serde_json::to_value(r).unwrap())
                .collect::<Vec<_>>(),
        );
        let p = |path: &str, value: &str| store::StoredParam {
            path: path.into(),
            value: Some(value.into()),
            xsd_type: None,
            writable: None,
            updated_at: now(),
        };
        let params = [
            p("Device.WiFi.Radio.1.Channel", "6"),
            p("Device.WiFi.Radio.1.OperatingFrequencyBand", "2.4GHz"),
            p("Device.WiFi.SSID.1.SSID", "Home"),
            p(
                "Device.WiFi.AccessPoint.1.SSIDReference",
                "Device.WiFi.SSID.1",
            ),
            p(
                "Device.WiFi.AccessPoint.1.AssociatedDevice.1.MACAddress",
                "aa:bb:cc:dd:ee:ff",
            ),
            p(
                "Device.WiFi.AccessPoint.1.AssociatedDevice.1.SignalStrength",
                "-60",
            ),
            p(
                "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
                "Old",
            ),
            p(
                "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.Channel",
                "11",
            ),
        ];
        let scan = store::Task {
            result: Some(json!({ "result": { "neighbors": [{ "ssid": "x" }] } })),
            ..task(true)
        };
        let view = crate::series::wifi_json(&params, Some(&scan));
        assert_eq!(view["networks"].as_array().unwrap().len(), 2, "{view}");
        assert_matches(
            &doc,
            "WifiView",
            &[view, crate::series::wifi_json(&params, None)],
        );
        let model = store::SupportedModel {
            id: Uuid::now_v7(),
            fingerprint: "abc".into(),
            protocol: "usp".into(),
            model: json!({ "objects": [{
                "path": "Device.", "access": "read_only", "multi_instance": false,
                "params": [{ "name": "X", "access": "read_only", "type": "string", "value_change": "allowed" }],
                "commands": [{ "name": "Reboot()", "type": "sync", "inputs": [], "outputs": [] }],
                "events": [{ "name": "Boot!", "args": ["Cause"] }],
                "unique_keys": [["Alias"]],
            }], "errors": [] }),
            created_at: now(),
        };
        assert_matches(
            &doc,
            "SupportedModel",
            &[crate::supported_model_json(model)],
        );

        assert_matches(
            &doc,
            "AgentCertificate",
            &[true, false].map(|revoked| {
                crate::certificate_json(&store::AgentCertificate {
                    id: Uuid::now_v7(),
                    device_id: Uuid::now_v7(),
                    serial: "1a2b".into(),
                    fingerprint: "ab".repeat(32),
                    not_after: now(),
                    from_csr: true,
                    issued_by: Some("alice".into()),
                    issued_at: now(),
                    revoked_at: revoked.then(now),
                    revoked_by: revoked.then(|| "bob".into()),
                    revoke_reason: revoked.then(|| "stolen".into()),
                })
            }),
        );
        assert_matches(
            &doc,
            "CertificateRevocation",
            &[true, false].map(|known| {
                crate::revocation_json(&store::FingerprintRevocation {
                    id: Uuid::now_v7(),
                    fingerprint: "ab".repeat(32),
                    endpoint_id: known.then(|| "os::agent".into()),
                    device_id: known.then(Uuid::now_v7),
                    serial: known.then(|| "1a2b".into()),
                    not_after: known.then(now),
                    revoked_at: now(),
                    revoked_by: Some("bob".into()),
                    revoke_reason: known.then(|| "stolen".into()),
                    known,
                })
            }),
        );
        assert_matches(
            &doc,
            "StoredPreset",
            &[crate::presets::stored_json(&store::StoredPreset {
                id: uuid::Uuid::nil(),
                name: "wifi".into(),
                enabled: true,
                definition: json!({ "name": "wifi", "run": [] }),
                revision: 3,
                updated_by: Some("alice".into()),
                updated_at: now(),
            })],
        );
        assert_matches(
            &doc,
            "PresetRevision",
            &[true, false].map(|alive| {
                crate::presets::change_json(&store::PresetChange {
                    revision: 2,
                    enabled: true,
                    definition: alive.then(|| json!({ "name": "wifi" })),
                    changed_by: alive.then(|| "alice".into()),
                    changed_at: now(),
                })
            }),
        );

        let hub = store::WgHub {
            id: Uuid::now_v7(),
            name: "lab".into(),
            endpoint_host: "hub.example.org".into(),
            public_key: None,
            networks: 2,
            token_prefix: None,
            token_created_at: None,
            last_seen_at: None,
            last_seen_ip: None,
            hub_version: None,
            state_revision: 1,
            created_at: now(),
            updated_at: now(),
        };
        let seen_hub = store::WgHub {
            public_key: Some("A".repeat(43) + "="),
            token_prefix: Some("dwh_abcdefgh".into()),
            token_created_at: Some(now()),
            last_seen_at: Some(now()),
            last_seen_ip: Some("203.0.113.5".into()),
            hub_version: Some("0.1.0".into()),
            ..hub.clone()
        };
        assert_matches(
            &doc,
            "WgHub",
            &[
                crate::wireguard::hub_json(&hub),
                crate::wireguard::hub_json(&seen_hub),
            ],
        );
        assert_matches(
            &doc,
            "WgHubToken",
            &[json!({ "token": "dwh_x", "token_prefix": "dwh_x",
                      "hub": crate::wireguard::hub_json(&seen_hub) })],
        );
        let state = dhonomos_wireguard::HubState {
            hub_id: Uuid::now_v7(),
            revision: 3,
            networks: vec![dhonomos_wireguard::HubNetwork {
                id: Uuid::now_v7(),
                name: "branches".into(),
                interface: "dwg51820".into(),
                listen_port: 51820,
                prefix: "10.77.0.0/24".parse().unwrap(),
                address: "10.77.0.1".parse().unwrap(),
                mtu: 1420,
                peers: vec![dhonomos_wireguard::HubPeer {
                    member_id: Uuid::now_v7(),
                    kind: "device".into(),
                    public_key: "A".repeat(43) + "=",
                    allowed_ips: vec!["10.77.0.2/32".parse().unwrap()],
                    preshared_key: Some("B".repeat(43) + "="),
                }],
            }],
        };
        assert_matches(&doc, "WgHubState", &[serde_json::to_value(&state).unwrap()]);
        assert_matches(
            &doc,
            "WgHubStatusAccepted",
            &[serde_json::to_value(dhonomos_wireguard::StatusAccepted {
                accepted: 1,
                ignored: 2,
            })
            .unwrap()],
        );
        let network = store::WgNetwork {
            id: Uuid::now_v7(),
            hub_id: Uuid::now_v7(),
            hub_name: "lab".into(),
            hub_endpoint_host: "hub.example.org".into(),
            hub_public_key: None,
            name: "branches".into(),
            ipv4_prefix: "10.77.0.0/24".parse().unwrap(),
            listen_port: 51820,
            mtu: 1420,
            persistent_keepalive: 25,
            device_members: 3,
            client_members: 1,
            revoked_members: 2,
            created_at: now(),
            updated_at: now(),
        };
        assert_matches(
            &doc,
            "WgNetwork",
            &[
                crate::wireguard::network_json(&network),
                crate::wireguard::network_json(&store::WgNetwork {
                    hub_public_key: Some("A".repeat(43) + "="),
                    ..network
                }),
            ],
        );
        let wg_member = |client: bool, revoked: bool| store::WgMember {
            id: Uuid::now_v7(),
            network_id: Uuid::now_v7(),
            kind: if client { "client" } else { "device" }.into(),
            device_id: (!client).then(Uuid::now_v7),
            user_id: client.then(Uuid::now_v7),
            name: "member".into(),
            public_key: client.then(|| "A".repeat(43) + "="),
            key_mode: (!client).then(|| "device".into()),
            preshared_key_enabled: false,
            address: "10.77.0.2".parse().unwrap(),
            site_prefixes: if client {
                Vec::new()
            } else {
                vec![store::WgSitePrefix {
                    prefix: "192.168.10.0/24".parse().unwrap(),
                    description: "office".into(),
                }]
            },
            revoked_at: revoked.then(now),
            revoked_reason: revoked.then(|| "user disabled".into()),
            hub_status: client.then(|| store::WgPeerStatus {
                endpoint: (!revoked).then(|| "198.51.100.7:40000".into()),
                latest_handshake: (!revoked).then(now),
                rx_bytes: 10,
                tx_bytes: 20,
                reported_at: now(),
            }),
            device_state: (!client).then(|| "pending".into()),
            device_detail: None,
            device_checked_at: None,
            device_applied_hash: None,
            rotate_requested_at: None,
            created_at: now(),
            updated_at: now(),
        };
        let mut members: Vec<Value> = [(false, false), (true, false), (true, true)]
            .iter()
            .map(|&(client, revoked)| crate::wireguard::member_json(&wg_member(client, revoked)))
            .collect();
        members.push(crate::wireguard::member_json(&store::WgMember {
            device_state: Some("blocked".into()),
            device_detail: Some("the hub has not reported its public key yet".into()),
            device_checked_at: Some(now()),
            device_applied_hash: Some("a".repeat(64)),
            rotate_requested_at: Some(now()),
            ..wg_member(false, false)
        }));
        assert_matches(&doc, "WgMember", &members);
        assert_matches(
            &doc,
            "WgDeviceMember",
            &[
                crate::wireguard::device_member_json(&store::WgDeviceMember {
                    member: wg_member(false, false),
                    network_name: "branches".into(),
                    via_twin: None,
                    device_side: Some(store::WgDeviceSide {
                        tunnel_status: Some("Enabled".into()),
                        interface_status: Some("Up".into()),
                        last_handshake_secs: Some(12),
                        bytes_sent: Some(1000),
                        bytes_received: Some(2000),
                        read_at: now(),
                    }),
                }),
                crate::wireguard::device_member_json(&store::WgDeviceMember {
                    member: wg_member(false, false),
                    network_name: "branches".into(),
                    via_twin: Some((Uuid::now_v7(), "usp".into())),
                    device_side: Some(store::WgDeviceSide {
                        tunnel_status: None,
                        interface_status: None,
                        last_handshake_secs: None,
                        bytes_sent: None,
                        bytes_received: None,
                        read_at: now(),
                    }),
                }),
                crate::wireguard::device_member_json(&store::WgDeviceMember {
                    member: wg_member(false, false),
                    network_name: "branches".into(),
                    via_twin: None,
                    device_side: None,
                }),
            ],
        );
        assert_matches(&doc, "WgKeyRotations", &[json!({ "requested": 2 })]);
        let counts = store::WgStateCounts {
            connected: 3,
            idle: 1,
            stale: 0,
            never: 2,
            unknown: 0,
        };
        assert_matches(
            &doc,
            "WgSummary",
            &[
                crate::wireguard::summary_json(&store::WgHealthSummary::default()),
                crate::wireguard::summary_json(&store::WgHealthSummary {
                    device: counts,
                    client: store::WgStateCounts::default(),
                    networks: vec![store::WgNetworkHealth {
                        id: Uuid::now_v7(),
                        name: "branches".into(),
                        hub_id: Uuid::now_v7(),
                        hub_name: "lab".into(),
                        device: counts,
                        client: store::WgStateCounts::default(),
                    }],
                }),
            ],
        );
        assert_matches(
            &doc,
            "WgMemberCreated",
            &[
                crate::wireguard::member_created_json(
                    &wg_member(true, false),
                    Some(&crate::wireguard::MadeKey {
                        private_key: "key".to_owned().into(),
                        config: "[Interface]\n".to_owned().into(),
                        config_filename: "branches.conf".into(),
                        qr_svg: "<svg/>".to_owned().into(),
                    }),
                    Some("psk"),
                ),
                crate::wireguard::member_created_json(&wg_member(false, false), None, None),
            ],
        );
        assert_matches(
            &doc,
            "WgClientConfig",
            &[crate::wireguard::client_config_json(
                "[Interface]\n",
                "branches.conf",
            )],
        );

        assert_matches(
            &doc,
            "Overview",
            &[crate::series::overview_json(
                &store::Overview {
                    active: 10,
                    online: (5, 8, 10),
                    by_protocol: vec![("cwmp".into(), 7), ("usp".into(), 3)],
                    by_status: vec![("active".into(), 10)],
                    sessions_per_minute: vec![(now(), 4)],
                    tasks: vec![("pending".into(), 2)],
                    jobs_running: 1,
                    versions: vec![("1.0".into(), 6)],
                },
                &[("major".into(), 1)],
            )],
        );
    }

    /// Checker self-test: extra key, missing required key, wrong type, bad time, null -> caught.
    #[test]
    fn checker_catches_drift() {
        let doc = doc();
        let schema = &doc["components"]["schemas"]["User"];
        let good = crate::auth::user_json(&store::User {
            id: Uuid::now_v7(),
            tenant_id: store::DEFAULT_TENANT,
            username: "alice".into(),
            password_hash: String::new(),
            role: "admin".into(),
            disabled: false,
            created_at: now(),
            last_login_at: None,
            scope: None,
            totp_enabled: false,
        });
        check(&doc, schema, &good, "User");
        let mut bad = Vec::new();
        let mut v = good.clone();
        v["email"] = json!("a@example.com");
        bad.push(v);
        let mut v = good.clone();
        v.as_object_mut().unwrap().remove("role");
        bad.push(v);
        let mut v = good.clone();
        v["disabled"] = json!("no");
        bad.push(v);
        let mut v = good.clone();
        v["created_at"] = json!("yesterday");
        bad.push(v);
        let mut v = good;
        v["username"] = Value::Null;
        bad.push(v);
        for v in bad {
            let doc = doc.clone();
            let schema = schema.clone();
            let caught = std::panic::catch_unwind(move || check(&doc, &schema, &v, "User"));
            assert!(caught.is_err(), "drift not caught");
        }
    }

    /// Paged + plain lists wrap the item schemas.
    #[test]
    fn list_wrappers() {
        let doc = doc();
        let response = |path: &str, method: &str| {
            let r = &doc["paths"][path][method]["responses"]["200"]["content"]["application/json"]
                ["schema"];
            object_shape(&doc, r).unwrap()
        };
        let (props, required) = response("/api/v1/devices", "get");
        assert_eq!(
            props.keys().collect::<Vec<_>>(),
            ["items", "limit", "offset", "total"]
        );
        assert_eq!(required.len(), 4);
        assert_eq!(
            props["items"]["items"]["$ref"],
            "#/components/schemas/Device"
        );
        let (props, _) = response("/api/v1/devices/{id}/tasks", "get");
        assert_eq!(props["items"]["items"]["$ref"], "#/components/schemas/Task");
    }
}
