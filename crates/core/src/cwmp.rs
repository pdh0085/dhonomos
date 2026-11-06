//! CWMP backend: ACS listener -> registry + task queue.

use dhonomos_cwmp_codec::{EventCode, Fault, Rpc};
use dhonomos_cwmp_server::{Backend, InformContext, PasswordCandidate};
use dhonomos_cwmp_session::{Completed, Outcome};
use dhonomos_store::{
    CwmpIdentity, InformUpdate, NewTask, ParamUpdate, Store, StoredParam, TaskState,
};
use serde_json::json;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::files::FileSigner;
use crate::param_prune::{self, Mode, Reported};
use crate::param_store;
use crate::presets::{MatchContext, Presets};
use crate::secrets::SecretBox;
use crate::task::TaskKind;
use crate::wireguard::WgAnswer;

/// CPE auth to the ACS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpeCredentials {
    /// Every username/password refused (use with `AuthMode::None`).
    None,
    /// One username/password for all CPEs.
    Shared {
        /// Username.
        username: String,
        /// Password.
        password: String,
    },
}

/// Device the ACS has never seen -> what happens (CO-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnboardingMode {
    /// Register + activate.
    #[default]
    Auto,
    /// Register as quarantined: sessions work, no tasks until an operator activates it.
    Quarantine,
    /// Refuse unless pre-registered via the API.
    Preregistered,
}

/// Device admission policy (CO-12).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Onboarding {
    pub mode: OnboardingMode,
    /// Not empty -> only these OUIs admitted (hex, any case).
    pub allowed_ouis: Vec<String>,
}

/// Refuse an Inform of `identity` from `remote`: counted + logged with source address.
/// Serial number = device's own claim -> clipped + quoted.
fn denied(reason: &'static str, remote: SocketAddr, identity: &CwmpIdentity) -> Fault {
    metrics::counter!("dhonomos_cwmp_rejected_total", "reason" => reason).increment(1);
    dhonomos_common::request_refused!(
        "cwmp",
        reason,
        remote,
        oui = ?dhonomos_common::refusal::clip(&identity.oui),
        serial = ?dhonomos_common::refusal::clip(&identity.serial_number)
    );
    Fault::new(8001, "Request denied")
}

/// ACS config of a TR-181 device -> connects to the built-in XMPP server, takes CRs over it
/// (ADR-104).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmppProvisioning {
    /// XMPP domain (`--xmpp-domain`). Device login = `<device ID>@<domain>`.
    pub domain: String,
    /// `KeepAliveInterval` on the device, in s (`--xmpp-keepalive`).
    pub keepalive: u32,
}

/// Task from the queue for the current session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningTask {
    /// Task ID (= CommandKey / ParameterKey).
    pub id: Uuid,
    pub kind: TaskKind,
}

/// Runtime limits of a [`CwmpBackend`]: sessions per CPE per minute (ADR-084) and
/// parameters stored from a CPE (L-5).
#[derive(Debug)]
pub struct CwmpLimits {
    /// Sessions per CPE per minute (0 = off).
    pub sessions: crate::session_limit::SessionLimiter,
    max_params_per_message: AtomicUsize,
    max_params_per_device: AtomicUsize,
}

impl Default for CwmpLimits {
    fn default() -> Self {
        Self {
            sessions: crate::session_limit::SessionLimiter::new(0),
            max_params_per_message: AtomicUsize::new(DEFAULT_MAX_PARAMS_PER_MESSAGE),
            max_params_per_device: AtomicUsize::new(DEFAULT_MAX_PARAMS_PER_DEVICE),
        }
    }
}

impl CwmpLimits {
    /// Set max params stored per message + per device.
    pub fn set_param_limits(&self, per_message: usize, per_device: usize) {
        self.max_params_per_message
            .store(per_message, Ordering::Relaxed);
        self.max_params_per_device
            .store(per_device, Ordering::Relaxed);
    }

    pub fn max_params_per_message(&self) -> usize {
        self.max_params_per_message.load(Ordering::Relaxed)
    }

    pub fn max_params_per_device(&self) -> usize {
        self.max_params_per_device.load(Ordering::Relaxed)
    }
}

/// [`Backend`] on the PostgreSQL store.
#[derive(Debug, Clone)]
pub struct CwmpBackend {
    pub(crate) store: Store,
    pub(crate) tenant_id: Uuid,
    credentials: CpeCredentials,
    files: Option<FileSigner>,
    onboarding: Onboarding,
    presets: crate::Shared<Presets>,
    pub(crate) secrets: Option<std::sync::Arc<SecretBox>>,
    stun: Option<(String, u16, Vec<u8>)>,
    cr_per_device: bool,
    acs_per_device: bool,
    xmpp: Option<XmppProvisioning>,
    /// Session + param limits. Shared by clones, changeable at runtime ([`CwmpBackend::limits`]).
    limits: Arc<CwmpLimits>,
    /// Devices whose current session already logged a param limit warning.
    param_limit_warned: Arc<Mutex<HashSet<Uuid>>>,
    /// WireGuard runs in progress per device (ADR-110 stage 4). Shared by clones.
    pub(crate) wg: Arc<crate::wireguard::WgRunner>,
    /// Wake a device whose WireGuard run waits for its firmware, this long after session end
    /// ([`Self::with_wg_rewake`]).
    pub(crate) wg_rewake: Option<(crate::Waker, std::time::Duration)>,
}

/// Default max params from one CPE message (Inform, GPV or GPN response).
pub const DEFAULT_MAX_PARAMS_PER_MESSAGE: usize = 50_000;
/// Default max params per device. Full tree of a real CPE ~ some 1000s;
/// large gateways (many hosts, Wi-Fi clients) -> 10,000s.
pub const DEFAULT_MAX_PARAMS_PER_DEVICE: usize = 100_000;

/// Default delay: session end -> wake of a device whose WireGuard run waits for its firmware
/// ([`CwmpBackend::with_wg_rewake`]).
pub const DEFAULT_WG_REWAKE_DELAY: std::time::Duration = std::time::Duration::from_secs(10);

/// [`PasswordCandidate::tag`] of an ACS credential the CPE accepted.
const TAG_ACTIVE: u32 = 1;
/// [`PasswordCandidate::tag`] of an ACS credential still in provisioning.
const TAG_PENDING: u32 = 2;

/// Per-device credentials set on the CPE at zero-touch (SE-03, CO-16).
struct CredSpec {
    /// For logs.
    what: &'static str,
    /// Credential kind before the CPE accepts it.
    pending: &'static str,
    /// Credential kind after.
    active: &'static str,
    /// `ManagementServer.` parameters.
    user_param: &'static str,
    pass_param: &'static str,
    /// Username prefix (then the end of the device ID).
    prefix: &'static str,
    /// Username = whole device ID instead (XMPP: local part of its JID).
    username_is_device_id: bool,
    /// Idempotency key and task origin.
    key: &'static str,
    /// Idempotency key of an AddObject the credential needs (XMPP: its connection).
    /// Keyed by the credential like `key`.
    add_key: Option<&'static str>,
    metric: &'static str,
    /// Active credential -> new one on a later trigger?
    /// ([`CredentialTrigger::Rotate`]: first contact, new BOOTSTRAP)
    /// CR credentials: yes. Factory reset CPE forgets them; they only let the ACS call the CPE.
    /// Firmware change only ([`CredentialTrigger::FirmwareOnly`]) -> active one resent as is
    /// (ADR-112).
    /// ACS credentials: no. Shared credential proves nothing -> any session claiming the
    /// identity could take the device's credential over (M-4).
    /// Provision again -> operator deletes the old one.
    replace_active: bool,
}

/// What an Inform asks of the per-device credentials (ADR-112).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialTrigger {
    /// No trigger: only the operator-admitted path provisions.
    None,
    /// First contact or "0 BOOTSTRAP" -> credentials issued; CR credentials new even if
    /// active ones exist.
    Rotate,
    /// Firmware change only -> as [`Self::Rotate`], but an active CR credential with none
    /// pending is resent as is.
    FirmwareOnly,
}

const CR_SPEC: CredSpec = CredSpec {
    what: "connection request",
    pending: "connection_request_pending",
    active: "connection_request",
    user_param: "ConnectionRequestUsername",
    pass_param: "ConnectionRequestPassword",
    prefix: "dhonomos-",
    username_is_device_id: false,
    key: "cr-credentials",
    add_key: None,
    metric: "dhonomos_cr_credentials_provisioned_total",
    replace_active: true,
};

const ACS_SPEC: CredSpec = CredSpec {
    what: "ACS",
    pending: "acs_auth_pending",
    active: "acs_auth",
    user_param: "Username",
    pass_param: "Password",
    prefix: "acs-",
    username_is_device_id: false,
    key: "acs-credentials",
    add_key: None,
    metric: "dhonomos_acs_credentials_provisioned_total",
    replace_active: false,
};

/// XMPP login of the device (ADR-104). Not a `ManagementServer.` pair like the two above:
/// set with the rest of the connection in one SPV ([`CwmpBackend::enqueue_xmpp_setup`]).
/// Active at first login with it (`XmppAccounts::accepted`), not at SPV success.
const XMPP_SPEC: CredSpec = CredSpec {
    what: "XMPP",
    pending: crate::xmpp::KIND_PENDING,
    active: crate::xmpp::KIND_ACTIVE,
    user_param: "",
    pass_param: "",
    prefix: "",
    username_is_device_id: true,
    key: "xmpp-credentials",
    add_key: Some(XMPP_ADD_KEY),
    metric: "dhonomos_xmpp_credentials_provisioned_total",
    replace_active: false,
};

/// Task origin: XMPP login of a device.
const XMPP_TASK_ORIGIN: &str = "system:xmpp-credentials";
/// Idempotency key prefix: AddObject of a connection for the XMPP login.
const XMPP_ADD_KEY: &str = "xmpp-add";
/// Task origin: zero-touch read of the whole tree.
const BOOTSTRAP_TASK_ORIGIN: &str = "system:bootstrap";
/// Table of the device's XMPP connections.
const XMPP_CONNECTION_TABLE: &str = "Device.XMPP.Connection.";
/// Present -> TR-181 device has XMPP.
const XMPP_OBJECT: &str = "Device.XMPP.";
// Device back-off after a failed XMPP server connection (TR-181
// `Device.XMPP.Connection.{i}.ServerRetry*`; ranges 1..65535, 1000..65535, >=1).
// xmppc keeps its config across firmware upgrades -> upgraded device may still have 1/1000/1
// (retry every 1 s, forever) -> ACS sets a sane back-off.
// Values = xmppc's new defaults, agreed with the firmware side.
/// `ServerRetryInitialInterval`: s before the first retry.
const XMPP_RETRY_INITIAL_INTERVAL: u32 = 10;
/// `ServerRetryIntervalMultiplier`: in 1/1000 -> 2000 = interval x2 per retry.
const XMPP_RETRY_INTERVAL_MULTIPLIER: u32 = 2000;
/// `ServerRetryMaxInterval`: max interval, s.
const XMPP_RETRY_MAX_INTERVAL: u32 = 1800;
/// Operator-admitted path (`quarantine`, `preregistered`): wait after a CPE fault on a
/// credential SPV, before a new credential at an Inform.
/// Zero-touch triggers (new device, BOOTSTRAP, firmware change) do not wait.
/// Else a device that keeps refusing gets a new one at every Inform.
const REFUSED_CREDENTIAL_BACKOFF: time::Duration = time::Duration::hours(24);
/// Task origin: STUN setup of a device (ADR-040).
const STUN_TASK_ORIGIN: &str = "system:stun";
/// `ManagementServer.` params of the STUN setup.
/// Password last: not readable from a device -> never compared.
/// Password = task secret (encrypted if a key is set, empty in the snapshot).
const STUN_PARAMS: [&str; 5] = [
    "STUNEnable",
    "STUNServerAddress",
    "STUNServerPort",
    "STUNUsername",
    "STUNPassword",
];
/// Known device: wait after a failed STUN setup sent at an ordinary Inform, before next send.
/// Zero-touch triggers do not wait.
/// Else a device that cannot take it (no such param, read-only, invalid value) gets one at
/// every Inform.
const STUN_SETUP_BACKOFF: time::Duration = time::Duration::hours(24);
/// Max sends of one STUN config to a known device, 1 per [`STUN_SETUP_BACKOFF`]
/// -> then give up (until the config changes).
const STUN_SETUP_MAX_ROUNDS: usize = 30;

/// 24 random alphanumeric chars (~143 bits).
fn random_password() -> Result<String, ring::error::Unspecified> {
    use ring::rand::SecureRandom as _;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut raw = [0u8; 24];
    ring::rand::SystemRandom::new().fill(&mut raw)?;
    Ok(raw
        .iter()
        .map(|b| char::from(ALPHABET[usize::from(*b) % ALPHABET.len()]))
        .collect())
}

/// CPE fault -> task error: `9003 Invalid arguments | Device.X: 9007 Invalid value`.
/// Each param of an SPV fault named (UI shows them per value).
pub fn fault_text(f: &Fault) -> String {
    let mut s = format!("{} {}", f.code, f.string);
    for p in &f.set_parameter_values_faults {
        s.push_str(&format!(
            " | {}: {} {}",
            p.parameter_name, p.fault_code, p.fault_string
        ));
    }
    s
}

/// CPE fault code at the start of a failed task's error ([`fault_text`]).
/// `None` for any other end (session lost, no answer, unexpected response, expiry)
/// -> CPE may have applied the request. Fault -> nothing applied.
fn fault_code_of(error: &str) -> Option<u32> {
    let (code, rest) = error.split_at_checked(4)?;
    if !code.bytes().all(|b| b.is_ascii_digit()) || !(rest.is_empty() || rest.starts_with(' ')) {
        return None;
    }
    code.parse().ok().filter(|c| (9000..10000).contains(c))
}

/// Idempotency key of task `index` of a STUN setup (`occurrence` = which one).
fn stun_setup_key(device: Uuid, index: usize, occurrence: &str) -> String {
    format!("stun-setup:{device}:{index}:{occurrence}")
}

/// ID of the STUN setup for `host`, `port`, `username` (device ID) -> occurrence of its tasks
/// -> known device gets each config once.
fn stun_setup_id(host: &str, port: u16, username: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(format!("stun-setup|{host}|{port}|{username}"));
    crate::files::hex(&digest[..8])
}

/// STUN setup ([`stun_setup_id`]) of a queued SPV task.
fn stun_task_setup_id(task: &dhonomos_store::Task) -> Option<String> {
    let TaskKind::SetParameterValues { values } =
        TaskKind::from_row(&task.kind, &task.payload).ok()?
    else {
        return None;
    };
    let value_of = |name: &str| {
        values
            .iter()
            .find(|v| v.name.strip_prefix("Device.ManagementServer.") == Some(name))
            .map(|v| v.value.as_str())
    };
    Some(stun_setup_id(
        value_of("STUNServerAddress")?,
        value_of("STUNServerPort")?.parse().ok()?,
        value_of("STUNUsername")?,
    ))
}

/// Occurrence of the tasks of try `round` (0 = first) of STUN setup `id` for a known device
/// ([`stun_setup_id`]).
fn stun_sync_occurrence(id: &str, round: usize) -> String {
    match round {
        0 => format!("sync-{id}"),
        n => format!("sync-{id}-{n}"),
    }
}

/// Stored STUN params of a TR-181 device != setup for `host`, `port`, `username`:
/// `STUNEnable`, `STUNServerAddress`, `STUNServerPort` or `STUNUsername` missing, empty or
/// other value. Password not compared.
///
/// `false` if the device does not take the setup: no `STUNEnable` stored (no TR-111 STUN
/// client; missing param != difference then), or a STUN param known read-only
/// -> SPV would only be refused.
fn stun_setup_differs(params: &[StoredParam], host: &str, port: u16, username: &str) -> bool {
    let stored = |name: &str| {
        params
            .iter()
            .find(|p| p.path.strip_prefix("Device.ManagementServer.") == Some(name))
    };
    if stored("STUNEnable").is_none()
        || STUN_PARAMS
            .iter()
            .any(|n| stored(n).is_some_and(|p| p.writable == Some(false)))
    {
        return false;
    }
    let value_of = |name: &str| {
        stored(name)
            .and_then(|p| p.value.as_deref())
            .map(str::trim)
            .unwrap_or_default()
    };
    !(matches!(value_of("STUNEnable"), "true" | "1")
        && value_of("STUNServerAddress").eq_ignore_ascii_case(host)
        && value_of("STUNServerPort").parse::<u16>() == Ok(port)
        && value_of("STUNUsername").eq_ignore_ascii_case(username))
}

/// Idempotency key of a task with credential `credential_id` (nonce) -> 1 task per credential.
fn task_key(prefix: &str, device: Uuid, credential_id: &[u8]) -> String {
    format!("{prefix}:{device}:{}", crate::files::hex(credential_id))
}

/// Pending credential the CPE refused: its SPV (or AddObject) ended in a CPE fault
/// -> nothing of it applied.
struct Refusal {
    /// Credential nonce (= its id).
    credential_id: Vec<u8>,
    fault: u32,
    /// Task end time.
    at: time::OffsetDateTime,
}

fn retry() -> Fault {
    Fault::new(8005, "Retry request")
}

/// Retryable CPE faults: temporary conditions + transfer failures.
/// Others (9000 not supported, 9005 invalid name, 9007 invalid value, ...) -> fail at once.
pub fn is_retryable_fault(code: u32) -> bool {
    matches!(code, 9001 | 9002 | 9004 | 9010 | 9011 | 9014..=9017 | 9020)
}

impl CwmpBackend {
    /// Backend for one tenant.
    pub fn new(store: Store, tenant_id: Uuid, credentials: CpeCredentials) -> Self {
        let wg = crate::wireguard::WgRunner::new(
            store.clone(),
            tenant_id,
            None,
            crate::wireguard::WgProtocol::Cwmp,
            crate::wireguard::INCOMPLETE_RETRY,
            crate::wireguard::IpWait::default(),
        );
        Self {
            store,
            tenant_id,
            credentials,
            files: None,
            onboarding: Onboarding::default(),
            presets: crate::Shared::default(),
            secrets: None,
            stun: None,
            cr_per_device: false,
            acs_per_device: false,
            xmpp: None,
            limits: Arc::new(CwmpLimits::default()),
            param_limit_warned: Arc::default(),
            wg: Arc::new(wg),
            wg_rewake: None,
        }
    }

    /// Limit what a CPE can make Dhonomos store (L-5): max `per_message` params from one
    /// Inform or GPV/GPN response, max `per_device` in all.
    /// Params over a limit -> counted + dropped; CPE keeps working.
    pub fn with_param_limits(self, per_message: usize, per_device: usize) -> Self {
        self.limits.set_param_limits(per_message, per_device);
        self
    }

    /// Sessions over `per_minute` per device (and client address + username, see the check in
    /// `inform`) -> fault 8005 (CPE retries later), before the Inform is stored (ADR-084, L-3).
    pub fn with_session_limit(self, per_minute: u32) -> Self {
        self.limits.sessions.set_per_minute(per_minute);
        self
    }

    /// Session + param limits, changeable at runtime (reach every clone).
    pub fn limits(&self) -> Arc<CwmpLimits> {
        self.limits.clone()
    }

    /// Zero-touch -> also own ACS credentials per CPE (needs [`Self::with_secrets`] + CPE
    /// auth). Device used its own once -> shared ones stop working for it.
    pub fn with_per_device_acs_auth(mut self) -> Self {
        self.acs_per_device = true;
        self
    }

    /// Zero-touch -> own random CR credentials per CPE (needs [`Self::with_secrets`]).
    /// Used once the CPE accepted them.
    pub fn with_per_device_connection_requests(mut self) -> Self {
        self.cr_per_device = true;
        self
    }

    /// Zero-touch -> each TR-181 CPE with `Device.XMPP.` gets own login for the built-in XMPP
    /// server, its XMPP connection pointed at it (needs [`Self::with_secrets`]).
    /// CPE then takes CRs over that connection (ADR-104).
    pub fn with_xmpp_provisioning(mut self, xmpp: XmppProvisioning) -> Self {
        self.xmpp = Some(xmpp);
        self
    }

    /// Zero-touch -> CPEs pointed at built-in STUN server `host:port` (username = device ID,
    /// password from `secret`, see [`crate::nat::stun_password`]) + active notification of
    /// their UDP CR address (CW-08).
    pub fn with_stun_provisioning(
        mut self,
        host: impl Into<String>,
        port: u16,
        secret: impl Into<Vec<u8>>,
    ) -> Self {
        self.stun = Some((host.into(), port, secret.into()));
        self
    }

    /// WireGuard run waits for firmware to make the IP interface of a new tunnel
    /// -> wake the device with `waker`, `delay` after session end.
    /// Firmware makes it after commit of the session's requests (= session end)
    /// -> next session finds it. Without this -> next periodic Inform.
    pub fn with_wg_rewake(mut self, waker: crate::Waker, delay: std::time::Duration) -> Self {
        self.wg_rewake = Some((waker, delay));
        self
    }

    /// Per-device CPE credentials + encrypted task secrets (CO-16).
    pub fn with_secrets(mut self, secrets: std::sync::Arc<SecretBox>) -> Self {
        self.wg = Arc::new(crate::wireguard::WgRunner::new(
            self.store.clone(),
            self.tenant_id,
            Some(secrets.clone()),
            crate::wireguard::WgProtocol::Cwmp,
            crate::wireguard::INCOMPLETE_RETRY,
            crate::wireguard::IpWait::default(),
        ));
        self.secrets = Some(secrets);
        self
    }

    /// Provisioning presets, evaluated at every Inform (CO-04).
    /// [`crate::Shared`] -> reload at runtime.
    pub fn with_presets(mut self, presets: impl Into<crate::Shared<Presets>>) -> Self {
        self.presets = presets.into();
        self
    }

    /// Admission policy for unknown devices.
    pub fn with_onboarding(mut self, onboarding: Onboarding) -> Self {
        self.onboarding = onboarding;
        self
    }

    /// Downloads of files stored in Dhonomos (signed URLs).
    pub fn with_files(mut self, signer: FileSigner) -> Self {
        self.files = Some(signer);
        self
    }

    /// Queue the STUN setup of a device: SPV of the `STUN*` params + active notification of
    /// `UDPConnectionRequestAddress`. Both tasks keyed by `occurrence` -> each occurrence
    /// sent once, however often this runs.
    ///
    /// STUN password = task secret. With `--secrets-key`: encrypted in the queue, bound to
    /// the task like per-device credentials ([`Self::enqueue_credentials`]); encrypt fails
    /// -> not queued (`false`). No key -> queued as is (STUN provisioning does not need one).
    /// Both cases: API shows `********`, snapshot empty after the CPE took it, like every
    /// secret. Returns: setup queued?
    async fn enqueue_stun_setup(
        &self,
        device: Uuid,
        root: &str,
        host: &str,
        port: u16,
        password: &str,
        occurrence: &str,
    ) -> Result<bool, dhonomos_store::StoreError> {
        let ms = format!("{root}.ManagementServer.");
        let v = |name: &str, value: String, ty: &str, secret: bool| crate::task::SetValue {
            name: format!("{ms}{name}"),
            value,
            xsd_type: Some(ty.into()),
            secret,
        };
        let tasks = [
            TaskKind::SetParameterValues {
                values: vec![
                    v("STUNEnable", "true".into(), "boolean", false),
                    v("STUNServerAddress", host.into(), "string", false),
                    v("STUNServerPort", port.to_string(), "unsignedInt", false),
                    v("STUNUsername", device.to_string(), "string", false),
                    v("STUNPassword", password.to_owned(), "string", true),
                ],
            },
            TaskKind::SetParameterAttributes {
                changes: vec![crate::task::SetNotification {
                    name: format!("{ms}UDPConnectionRequestAddress"),
                    notification: 2,
                }],
            },
        ];
        for (i, kind) in tasks.iter().enumerate() {
            let (k, mut payload) = kind.to_row();
            // Secret bound to the task -> ID first. SPV = first task: password not sealed
            // -> nothing queued.
            let task_id = Uuid::now_v7();
            if let Some(secrets) = &self.secrets
                && secrets
                    .encrypt_fields(&mut payload, &crate::secrets::task_context(task_id))
                    .is_err()
            {
                warn!(%device, "encrypting the STUN password failed; not queueing the STUN setup");
                return Ok(false);
            }
            let task = NewTask {
                priority: -12,
                idempotency_key: Some(stun_setup_key(device, i, occurrence)),
                created_by: Some(STUN_TASK_ORIGIN.into()),
                ..NewTask::new(self.tenant_id, device, k, payload)
            };
            self.store.enqueue_task_with_id(task_id, &task).await?;
        }
        Ok(true)
    }

    /// Known device without the STUN setup -> give it.
    /// At an ordinary Inform (zero-touch triggers send it themselves): stored `STUN*` params vs
    /// `--stun-public-address` ([`stun_setup_differs`]); differ -> queue the setup
    /// ([`Self::enqueue_stun_setup`]).
    /// Why: devices onboarded before the STUN server never BOOTSTRAP again (icwmp: not even on
    /// an ACS URL change), rarely change firmware -> else never STUN. Password derived here
    /// -> cannot be set by hand.
    ///
    /// Unlike [`Self::provision_credentials`]: every onboarding mode, every active device.
    /// Setup gives no credential that needs operator approval or could lock the real device
    /// out. STUN password derived ([`crate::nat::stun_password`]), not issued; only lets the
    /// device authenticate the binding of its own UDP CR address.
    /// Not admitted (`quarantined`) -> waits, like for everything else.
    ///
    /// Only TR-181 devices (`Device.` root) that report the STUN params: snapshot has
    /// `Device.ManagementServer.STUNEnable`. Notification attributes not stored -> active
    /// notification on `UDPConnectionRequestAddress` not compared; sent with the setup
    /// (2nd task).
    ///
    /// Each config (host, port, device ID) sent once: tasks keyed by its hash.
    /// Failed setup (CPE fault or session lost) -> wait [`STUN_SETUP_BACKOFF`], then once more
    /// under a new key, max [`STUN_SETUP_MAX_ROUNDS`] tries.
    /// Changed config = new one -> sent at once.
    /// Success -> not repeated, even if the device later reports other values (operator
    /// change, device writes them back differently), unless the ACS sent another config since.
    async fn sync_stun_setup(
        &self,
        device: &dhonomos_store::UpsertOutcome,
        root: &str,
    ) -> Result<(), dhonomos_store::StoreError> {
        let Some((host, port, secret)) = &self.stun else {
            return Ok(());
        };
        if device.status != "active" || root != "Device" {
            return Ok(());
        }
        let username = device.id.to_string();
        let names: Vec<String> = STUN_PARAMS
            .iter()
            .map(|n| format!("Device.ManagementServer.{n}"))
            .collect();
        let params = self.store.get_params_exact(device.id, &names).await?;
        if !stun_setup_differs(&params, host, *port, &username) {
            return Ok(());
        }
        // Next try = first one of this config with no task yet.
        let id = stun_setup_id(host, *port, &username);
        let keys: Vec<String> = (0..STUN_SETUP_MAX_ROUNDS)
            .map(|round| stun_setup_key(device.id, 0, &stun_sync_occurrence(&id, round)))
            .collect();
        let existing = self
            .store
            .existing_idempotency_keys(self.tenant_id, &keys)
            .await?;
        let Some(round) = keys.iter().position(|k| !existing.contains(k)) else {
            debug!(device = %device.id, "STUN setup sent to the device as often as allowed; not sending it again");
            return Ok(());
        };
        let previous = round.checked_sub(1).map(|r| keys[r].as_str());
        if let Some(why) = self.stun_setup_held_back(device.id, &id, previous).await? {
            debug!(device = %device.id, why, "STUN parameters differ from the setup, but not sending it now");
            return Ok(());
        }
        let password = crate::nat::stun_password(secret, device.id);
        let queued = self
            .enqueue_stun_setup(
                device.id,
                root,
                host,
                *port,
                &password,
                &stun_sync_occurrence(&id, round),
            )
            .await?;
        if queued {
            tracing::info!(device = %device.id, round, "queued the STUN setup for a device that does not have it");
        }
        Ok(())
    }

    /// Why STUN setup `id` (see [`stun_setup_id`]) must not be queued now
    /// ([`Self::sync_stun_setup`]); `None` -> queue it.
    /// `previous` = key of the last try of this setup sent at an Inform. Held back if:
    ///
    /// - a STUN setup is queued or running;
    /// - device refused one with a CPE fault within [`STUN_SETUP_BACKOFF`] (zero-touch one
    ///   counts; time = task queued, ~ end for a refused task, it fails at once);
    /// - `previous` failed within [`STUN_SETUP_BACKOFF`], any reason;
    /// - `previous` sent + not failed, no setup of another config sent since. (Another config
    ///   since = STUN server address changed and back -> device must be moved back.)
    async fn stun_setup_held_back(
        &self,
        device: Uuid,
        id: &str,
        previous: Option<&str>,
    ) -> Result<Option<&'static str>, dhonomos_store::StoreError> {
        let now = time::OffsetDateTime::now_utc();
        let set_values = TaskKind::SetParameterValues { values: Vec::new() }.name();
        // Newest first.
        let setups: Vec<_> = self
            .store
            .list_tasks(device, 100)
            .await?
            .into_iter()
            .filter(|t| t.created_by.as_deref() == Some(STUN_TASK_ORIGIN) && t.kind == set_values)
            .collect();
        for task in &setups {
            match task.state {
                TaskState::Pending | TaskState::Running => {
                    return Ok(Some("a STUN setup is queued"));
                }
                TaskState::Failed
                    if now - task.created_at < STUN_SETUP_BACKOFF
                        && task.error.as_deref().and_then(fault_code_of).is_some() =>
                {
                    return Ok(Some(
                        "the device refused a STUN setup less than 24 hours ago",
                    ));
                }
                _ => {}
            }
        }
        let Some(key) = previous else {
            return Ok(None);
        };
        let failed = self
            .store
            .failed_tasks_by_key(self.tenant_id, &[key.to_owned()])
            .await?;
        match failed.first() {
            Some((_, at)) if now - *at < STUN_SETUP_BACKOFF => {
                Ok(Some("the last try failed less than 24 hours ago"))
            }
            Some(_) => Ok(None),
            None => {
                let last = setups.first().and_then(stun_task_setup_id);
                Ok(last
                    .is_none_or(|last| last == id)
                    .then_some("this configuration was sent"))
            }
        }
    }

    /// Credential in provisioning for the device: the stored one, else a fresh one.
    /// Existing pending one never replaced (M-4): this session may only claim the identity;
    /// swap during a provisioning -> real device locked out.
    /// (One the CPE refused with a fault -> discarded first, see [`Self::discard_refused`].)
    /// Returns username, password, stored nonce (= name of this credential).
    async fn pending_credential(
        &self,
        spec: &CredSpec,
        secrets: &SecretBox,
        device: Uuid,
    ) -> Result<Option<(String, String, Vec<u8>)>, dhonomos_store::StoreError> {
        // 2 tries: a session that stored its credential between our read + insert wins.
        for _ in 0..2 {
            if let Some(p) = self.store.get_credential(device, spec.pending).await? {
                let password = secrets
                    .open_credential(device, &p.ciphertext, &p.nonce)
                    .ok()
                    .and_then(|raw| String::from_utf8(raw).ok());
                let Some(password) = password else {
                    tracing::warn!(%device, what = spec.what, "cannot read the pending credential; delete it to provision again");
                    return Ok(None);
                };
                return Ok(Some((p.username, password, p.nonce)));
            }
            let Ok(password) = random_password() else {
                tracing::warn!(%device, what = spec.what, "no randomness for credentials");
                return Ok(None);
            };
            let username = if spec.username_is_device_id {
                device.hyphenated().to_string()
            } else {
                format!("{}{}", spec.prefix, &device.simple().to_string()[20..])
            };
            let Ok((ciphertext, nonce)) = secrets.seal_credential(device, password.as_bytes())
            else {
                tracing::warn!(%device, what = spec.what, "sealing credentials failed");
                return Ok(None);
            };
            let stored = self
                .store
                .put_pending_credential(&dhonomos_store::SealedCredential {
                    device_id: device,
                    kind: spec.pending.into(),
                    username: username.clone(),
                    ciphertext,
                    nonce: nonce.clone(),
                    key_id: secrets.key_id().to_owned(),
                })
                .await?;
            if stored {
                return Ok(Some((username, password, nonce)));
            }
        }
        Ok(None)
    }

    /// CPE refused the pending credential of `spec`? = its task ended in a CPE fault.
    /// Task found by the key from the credential nonce -> later credential has none,
    /// operator-deleted one leaves nothing.
    /// `None`: no pending credential, task not failed, or failed another way (session lost,
    /// no answer, expiry) -> CPE may have applied the values -> credential stays usable.
    async fn refused_pending(
        &self,
        spec: &CredSpec,
        device: Uuid,
    ) -> Result<Option<Refusal>, dhonomos_store::StoreError> {
        let Some(pending) = self.store.get_credential(device, spec.pending).await? else {
            return Ok(None);
        };
        let keys: Vec<String> = std::iter::once(spec.key)
            .chain(spec.add_key)
            .map(|prefix| task_key(prefix, device, &pending.nonce))
            .collect();
        let failed = self
            .store
            .failed_tasks_by_key(self.tenant_id, &keys)
            .await?;
        Ok(failed.into_iter().find_map(|(error, at)| {
            Some(Refusal {
                credential_id: pending.nonce.clone(),
                fault: fault_code_of(&error)?,
                at,
            })
        }))
    }

    /// Discard the pending credential of `spec` if the CPE refused it
    /// ([`Self::refused_pending`]) -> provisioning issues a new one (new password -> new task
    /// key). Refused SPV is atomic: nothing applied. Idempotency keys never reused -> a kept
    /// credential would never be sent again.
    ///
    /// `now` (zero-touch trigger) -> discard at once. Else (operator-admitted path, ordinary
    /// Inform) only after [`REFUSED_CREDENTIAL_BACKOFF`]. Returns: discarded?
    /// Operator-deleted credential -> not there, provisioning does not wait.
    async fn discard_refused(
        &self,
        spec: &CredSpec,
        device: Uuid,
        now: bool,
    ) -> Result<bool, dhonomos_store::StoreError> {
        let Some(refusal) = self.refused_pending(spec, device).await? else {
            return Ok(false);
        };
        if !now && time::OffsetDateTime::now_utc() - refusal.at < REFUSED_CREDENTIAL_BACKOFF {
            debug!(%device, what = spec.what, fault = refusal.fault,
                "the CPE refused the credentials recently; not provisioning again yet");
            return Ok(false);
        }
        let discarded = self
            .store
            .delete_credential_with_nonce(device, spec.pending, &refusal.credential_id)
            .await?;
        if discarded {
            tracing::info!(%device, what = spec.what, fault = refusal.fault,
                "discarded the per-device credentials the CPE refused; issuing new ones");
        }
        Ok(discarded)
    }

    /// Warn: CPE refused a credential task with fault `code` (from `completed`).
    /// No change here: refused credential stays until the next provisioning trigger replaces
    /// it ([`Self::discard_refused`]).
    async fn note_refused_credentials(&self, device: Uuid, task: &RunningTask, code: u32) {
        let carries_credentials = match &task.kind {
            TaskKind::SetParameterValues { .. } => true,
            TaskKind::AddObject { object, .. } => object == XMPP_CONNECTION_TABLE,
            _ => false,
        };
        if !carries_credentials || self.secrets.is_none() {
            return;
        }
        let Ok(Some(stored)) = self.store.get_task(task.id).await else {
            return;
        };
        let Some(created_by) = stored.created_by else {
            return;
        };
        if let Some(spec) = [&CR_SPEC, &ACS_SPEC, &XMPP_SPEC]
            .into_iter()
            .find(|s| created_by == format!("system:{}", s.key))
        {
            warn!(%device, what = spec.what, fault = code,
                "per-device credentials refused by the CPE; provisioning again on the next trigger");
        }
    }

    /// Queue SPV of the credentials in provisioning (fresh pending one, or the one already
    /// pending). Pending until the CPE accepts them ([`Self::promote_credentials`]).
    /// Task keyed by the pending credential -> each credential in one task, however often the
    /// CPE bootstraps; nothing CPE-reported (e.g. CurrentTime) picks the key.
    async fn enqueue_credentials(
        &self,
        spec: &CredSpec,
        secrets: &SecretBox,
        device: Uuid,
        root: &str,
    ) -> Result<(), dhonomos_store::StoreError> {
        let Some((username, password, credential_id)) =
            self.pending_credential(spec, secrets, device).await?
        else {
            return Ok(());
        };
        let key = task_key(spec.key, device, &credential_id);
        self.enqueue_credential_spv(spec, secrets, device, root, (username, password), key)
            .await
    }

    /// Queue SPV of the active credential of `spec` as is, after a firmware change only
    /// (ADR-112). Nothing new made; no pending credential -> success changes no credential
    /// ([`Self::promote_credentials`]).
    /// Keyed by Inform CurrentTime -> sent once per firmware change; firmware back to an
    /// earlier version -> sent again.
    async fn resend_active_credentials(
        &self,
        spec: &CredSpec,
        secrets: &SecretBox,
        device: Uuid,
        root: &str,
        current_time: &str,
    ) -> Result<(), dhonomos_store::StoreError> {
        let Some(c) = self.store.get_credential(device, spec.active).await? else {
            return Ok(());
        };
        let password = secrets
            .open_credential(device, &c.ciphertext, &c.nonce)
            .ok()
            .and_then(|raw| String::from_utf8(raw).ok());
        let Some(password) = password else {
            warn!(%device, what = spec.what, "cannot read the active credential; not sending it again");
            return Ok(());
        };
        let key = format!("{}-resend:{device}:{current_time}", spec.key);
        self.enqueue_credential_spv(spec, secrets, device, root, (c.username, password), key)
            .await
    }

    /// Queue SPV of username + password as the `spec` params, idempotency key `key`.
    /// Password encrypted in the task (bound to its ID).
    async fn enqueue_credential_spv(
        &self,
        spec: &CredSpec,
        secrets: &SecretBox,
        device: Uuid,
        root: &str,
        (username, password): (String, String),
        key: String,
    ) -> Result<(), dhonomos_store::StoreError> {
        let ms = format!("{root}.ManagementServer.");
        let (k, mut payload) = TaskKind::SetParameterValues {
            values: vec![
                crate::task::SetValue {
                    name: format!("{ms}{}", spec.user_param),
                    value: username,
                    xsd_type: Some("string".into()),
                    secret: false,
                },
                crate::task::SetValue {
                    name: format!("{ms}{}", spec.pass_param),
                    value: password,
                    xsd_type: Some("string".into()),
                    secret: true,
                },
            ],
        }
        .to_row();
        // Secret bound to the task -> ID first.
        let task_id = Uuid::now_v7();
        if secrets
            .encrypt_fields(&mut payload, &crate::secrets::task_context(task_id))
            .is_err()
        {
            tracing::warn!(%device, what = spec.what, "encrypting credentials failed");
            return Ok(());
        }
        let task = NewTask {
            priority: -12,
            idempotency_key: Some(key),
            created_by: Some(format!("system:{}", spec.key)),
            ..NewTask::new(self.tenant_id, device, k, payload)
        };
        self.store.enqueue_task_with_id(task_id, &task).await?;
        Ok(())
    }

    /// After a successful SPV: set credentials = pending ones (username + password)
    /// -> become the device's credentials.
    async fn promote_credentials(
        &self,
        device: Uuid,
        values: &[crate::task::SetValue],
    ) -> Result<(), dhonomos_store::StoreError> {
        let Some(secrets) = &self.secrets else {
            return Ok(());
        };
        let set = |name: &str| {
            values
                .iter()
                .find(|v| v.name.ends_with(&format!(".ManagementServer.{name}")))
                .map(|v| v.value.as_str())
        };
        for spec in [&CR_SPEC, &ACS_SPEC] {
            let (Some(user), Some(pass)) = (set(spec.user_param), set(spec.pass_param)) else {
                continue;
            };
            let Some(pending) = self.store.get_credential(device, spec.pending).await? else {
                continue;
            };
            let matches = pending.username == user
                && secrets
                    .open_credential(device, &pending.ciphertext, &pending.nonce)
                    .is_ok_and(|p| p == pass.as_bytes());
            if matches
                && self
                    .store
                    .promote_credential(device, spec.pending, spec.active)
                    .await?
            {
                tracing::info!(%device, what = spec.what, "per-device credentials active");
                metrics::counter!(spec.metric).increment(1);
            }
        }
        Ok(())
    }

    /// Per-device ACS credentials must be the device's own (CO-16).
    /// CPE with another device's credential -> refused. Device used its own once -> shared
    /// credential refused for it. Pending credential already in use (SPV answer lost)
    /// -> becomes active. `credential` = which password of the username the CPE proved
    /// ([`TAG_ACTIVE`], [`TAG_PENDING`]).
    async fn check_acs_binding(
        &self,
        identity: &CwmpIdentity,
        username: &str,
        credential: u32,
        remote: SocketAddr,
    ) -> Result<(), Fault> {
        let rows = self
            .store
            .acs_auth_binding(self.tenant_id, identity, username)
            .await
            .map_err(|_| retry())?;
        if rows
            .iter()
            .any(|r| r.username == username && !r.this_device)
        {
            warn!(serial = %identity.serial_number, %username, "CPE used another device's credential");
            return Err(denied("credential_mismatch", remote, identity));
        }
        let own = |kind: &str| {
            rows.iter()
                .find(|r| r.username == username && r.this_device && r.kind == kind)
        };
        let (active, pending) = (own(ACS_SPEC.active), own(ACS_SPEC.pending));
        match (active, pending) {
            (None, None) => {
                if rows
                    .iter()
                    .any(|r| r.this_device && r.kind == ACS_SPEC.active && r.confirmed)
                {
                    warn!(serial = %identity.serial_number, "shared credential used by a device with its own");
                    return Err(denied("shared_credential", remote, identity));
                }
                Ok(())
            }
            (active, pending) => {
                // Which one the CPE used: both stored (new one rolled out next to the current
                // one) -> tag says; one stored -> that one.
                let used_pending =
                    pending.is_some() && (active.is_none() || credential == TAG_PENDING);
                let used = if used_pending { pending } else { active };
                let Some(used) = used else {
                    return Ok(());
                };
                if used_pending {
                    let _ = self
                        .store
                        .promote_credential(used.device_id, ACS_SPEC.pending, ACS_SPEC.active)
                        .await;
                }
                if used_pending || !used.confirmed {
                    let _ = self.store.confirm_acs_auth(used.device_id).await;
                    tracing::info!(device = %used.device_id, "CPE uses its own ACS credential; shared credentials now refused for it");
                }
                Ok(())
            }
        }
    }

    /// Fill in what Dhonomos provides: signed links for stored files + for transfer
    /// diagnostics against the file server.
    async fn resolve_download(&self, device: Uuid, kind: TaskKind) -> Result<TaskKind, String> {
        let kind = crate::files::resolve_diagnostic(self.files.as_ref(), device, kind)?;
        crate::files::resolve_download(
            &self.store,
            self.files.as_ref(),
            self.tenant_id,
            device,
            kind,
        )
        .await
    }

    /// Own credentials for the device (CO-16), if the setup asks for them.
    ///
    /// Not before operator admission (M-4): `quarantine` mode -> device waits as
    /// `quarantined`, nothing issued; once active -> next Inform provisions it, like a known
    /// device without credentials yet (`quarantine` and `preregistered` only).
    /// `auto` mode -> issued at first contact, after BOOTSTRAP, after firmware change
    /// (`trigger`).
    ///
    /// CR credentials: new at first contact + after BOOTSTRAP. Firmware change only
    /// (ADR-112): active one, none pending -> active one resent
    /// ([`Self::resend_active_credentials`], keyed by `current_time` = Inform CurrentTime);
    /// pending one -> sent as on any trigger.
    ///
    /// Refused by the CPE with a fault ([`Self::discard_refused`]) -> new ones at those
    /// triggers; operator-admitted path (no trigger of its own) -> only after
    /// [`REFUSED_CREDENTIAL_BACKOFF`].
    ///
    /// XMPP login (ADR-104): same triggers, but needs `Device.XMPP.` known (not in the
    /// Inform). New device -> when its zero-touch tree read is stored
    /// ([`Self::xmpp_follow_up`], same session). Known device -> here, from the stored tree.
    async fn provision_credentials(
        &self,
        secrets: &SecretBox,
        device: &dhonomos_store::UpsertOutcome,
        root: &str,
        trigger: CredentialTrigger,
        current_time: &str,
    ) -> Result<(), dhonomos_store::StoreError> {
        let zero_touch = trigger != CredentialTrigger::None;
        if device.status != "active"
            || !(self.cr_per_device || self.acs_per_device || self.xmpp.is_some())
        {
            return Ok(());
        }
        let admitted_by_operator = self.onboarding.mode != OnboardingMode::Auto;
        if !zero_touch && !admitted_by_operator {
            return Ok(());
        }
        let kinds: Vec<String> = self
            .store
            .list_credentials(device.id)
            .await?
            .into_iter()
            .map(|(kind, _)| kind)
            .collect();
        let has = |kind: &str| kinds.iter().any(|k| k == kind);
        for (spec, wanted) in [
            (&CR_SPEC, self.cr_per_device),
            (&ACS_SPEC, self.acs_per_device),
        ] {
            if !wanted {
                continue;
            }
            let (active, mut pending) = (has(spec.active), has(spec.pending));
            if active && !spec.replace_active {
                continue;
            }
            // Trigger, or (operator-admitted setups) device with no credentials yet.
            if !(zero_touch || (admitted_by_operator && !active)) {
                continue;
            }
            // Refused credentials not sent again -> new one instead
            // (at once on a trigger, after the back-off on the operator-admitted path).
            if pending && self.discard_refused(spec, device.id, zero_touch).await? {
                pending = false;
            }
            // Active one here only if `replace_active`.
            if active && !pending && trigger == CredentialTrigger::FirmwareOnly {
                self.resend_active_credentials(spec, secrets, device.id, root, current_time)
                    .await?;
            } else if zero_touch || !pending {
                self.enqueue_credentials(spec, secrets, device.id, root)
                    .await?;
            }
        }
        // XMPP login: TR-181 only, once per device (like ACS credentials).
        if self.xmpp.is_some() && root == "Device" && !has(XMPP_SPEC.active) {
            let mut pending = has(XMPP_SPEC.pending);
            if pending
                && self
                    .discard_refused(&XMPP_SPEC, device.id, zero_touch)
                    .await?
            {
                pending = false;
            }
            if zero_touch {
                // Tree read on its way (or known from before): see `xmpp_follow_up`.
                self.provision_xmpp(secrets, device.id, false).await?;
            } else if admitted_by_operator && !pending {
                // No BOOTSTRAP -> no tree read on its way (pre-registered device, only ACS URL
                // changed) -> read `Device.XMPP.`.
                self.provision_xmpp(secrets, device.id, true).await?;
            }
        }
        Ok(())
    }

    /// Start the XMPP login of the device, if `Device.XMPP.` is in its stored params.
    /// Existing connection used (ours or not set up for something else, see
    /// [`xmpp_connection`]), else a new one added first ([`Self::xmpp_follow_up`] continues
    /// from its answer). Device without XMPP -> nothing stored.
    ///
    /// `probe` -> device with unknown `Device.XMPP.` gets one read of it
    /// ([`Self::xmpp_follow_up`] continues when it is stored).
    async fn provision_xmpp(
        &self,
        secrets: &SecretBox,
        device: Uuid,
        probe: bool,
    ) -> Result<(), dhonomos_store::StoreError> {
        let Some(xmpp) = &self.xmpp else {
            return Ok(());
        };
        let params = self.store.get_params(device, "Device.XMPP.").await?;
        if params.is_empty() {
            if probe {
                let (k, payload) = TaskKind::GetParameterValues {
                    names: vec![XMPP_OBJECT.into()],
                }
                .to_row();
                let task = NewTask {
                    priority: -12,
                    idempotency_key: Some(format!("xmpp-probe:{device}")),
                    created_by: Some(XMPP_TASK_ORIGIN.into()),
                    ..NewTask::new(self.tenant_id, device, k, payload)
                };
                self.store.enqueue_task(&task).await?;
            } else {
                debug!(%device, "no Device.XMPP. known for the device: no XMPP login provisioned");
            }
            return Ok(());
        }
        let Some((username, password, credential_id)) =
            self.pending_credential(&XMPP_SPEC, secrets, device).await?
        else {
            return Ok(());
        };
        match xmpp_connection(&params, &username, &xmpp.domain) {
            Some(instance) => {
                self.enqueue_xmpp_setup(
                    xmpp,
                    secrets,
                    device,
                    instance,
                    (&username, &password),
                    &credential_id,
                )
                .await
            }
            None => {
                let (k, payload) = TaskKind::AddObject {
                    object: XMPP_CONNECTION_TABLE.into(),
                    params: vec![],
                }
                .to_row();
                let task = NewTask {
                    priority: -12,
                    idempotency_key: Some(task_key(XMPP_ADD_KEY, device, &credential_id)),
                    created_by: Some(XMPP_TASK_ORIGIN.into()),
                    ..NewTask::new(self.tenant_id, device, k, payload)
                };
                self.store.enqueue_task(&task).await?;
                Ok(())
            }
        }
    }

    /// Queue the one SPV that sets connection `instance` up + points the CR at it.
    /// Keyed by the pending credential -> each credential sent once, however often this runs.
    /// Password bound to the task.
    ///
    /// Each value sent as the type the device reported for it (other type -> refused, 9006
    /// Invalid parameter type), else as the TR-181 type.
    async fn enqueue_xmpp_setup(
        &self,
        xmpp: &XmppProvisioning,
        secrets: &SecretBox,
        device: Uuid,
        instance: u32,
        (username, password): (&str, &str),
        credential_id: &[u8],
    ) -> Result<(), dhonomos_store::StoreError> {
        let conn = format!("Device.XMPP.Connection.{instance}.");
        let value = |name: String, value: String, ty: &str, secret: bool| crate::task::SetValue {
            name,
            value,
            xsd_type: Some(ty.into()),
            secret,
        };
        let mut values = vec![
            value(format!("{conn}Username"), username.into(), "string", false),
            value(format!("{conn}Password"), password.into(), "string", true),
            value(
                format!("{conn}Domain"),
                xmpp.domain.clone(),
                "string",
                false,
            ),
            value(format!("{conn}Resource"), String::new(), "string", false),
            // Explicit: TLS not asked for -> device may skip the certificate check, or never
            // connect.
            value(format!("{conn}UseTLS"), "true".into(), "boolean", false),
            value(
                format!("{conn}ServerConnectAlgorithm"),
                "DNS-SRV".into(),
                "string",
                false,
            ),
            value(
                format!("{conn}KeepAliveInterval"),
                xmpp.keepalive.to_string(),
                "long",
                false,
            ),
            value(
                format!("{conn}ServerRetryInitialInterval"),
                XMPP_RETRY_INITIAL_INTERVAL.to_string(),
                "unsignedInt",
                false,
            ),
            value(
                format!("{conn}ServerRetryIntervalMultiplier"),
                XMPP_RETRY_INTERVAL_MULTIPLIER.to_string(),
                "unsignedInt",
                false,
            ),
            value(
                format!("{conn}ServerRetryMaxInterval"),
                XMPP_RETRY_MAX_INTERVAL.to_string(),
                "unsignedInt",
                false,
            ),
            value(
                "Device.ManagementServer.ConnReqXMPPConnection".into(),
                format!("Device.XMPP.Connection.{instance}"),
                "string",
                false,
            ),
            value(
                "Device.ManagementServer.ConnReqAllowedJabberIDs".into(),
                format!("{}@{}", dhonomos_xmpp::ACS_LOCALPART, xmpp.domain),
                "string",
                false,
            ),
            // Last: connection starts with all of the above in place.
            value(format!("{conn}Enable"), "true".into(), "boolean", false),
        ];
        // Device-reported type wins over TR-181 (vendors differ; one wrong type -> whole SPV
        // refused). Not reported, or no type -> TR-181 type.
        let paths: Vec<String> = values.iter().map(|v| v.name.clone()).collect();
        for reported in self.store.get_params_exact(device, &paths).await? {
            let Some(ty) = reported.xsd_type.filter(|t| !t.is_empty()) else {
                continue;
            };
            if let Some(v) = values.iter_mut().find(|v| v.name == reported.path) {
                v.xsd_type = Some(ty);
            }
        }
        let (k, mut payload) = TaskKind::SetParameterValues { values }.to_row();
        // Secret bound to the task -> ID first.
        let task_id = Uuid::now_v7();
        if secrets
            .encrypt_fields(&mut payload, &crate::secrets::task_context(task_id))
            .is_err()
        {
            warn!(%device, what = XMPP_SPEC.what, "encrypting credentials failed");
            return Ok(());
        }
        let task = NewTask {
            priority: -12,
            idempotency_key: Some(task_key(XMPP_SPEC.key, device, credential_id)),
            created_by: Some(XMPP_TASK_ORIGIN.into()),
            ..NewTask::new(self.tenant_id, device, k, payload)
        };
        self.store.enqueue_task_with_id(task_id, &task).await?;
        Ok(())
    }

    /// Continue the XMPP login when a provisioning task has an answer, same session (task
    /// queue read again after every answer):
    ///
    /// - zero-touch tree read, or the `Device.XMPP.` read the ACS asked for
    ///   ([`Self::provision_xmpp`]), stored -> provision now that `Device.XMPP.` is known,
    ///   if no XMPP login yet;
    /// - connection added by the ACS exists -> queue its SPV with the instance number from
    ///   the answer.
    async fn xmpp_follow_up(&self, device: Uuid, task: &RunningTask, rpc: &Rpc) {
        let (Some(xmpp), Some(secrets)) = (&self.xmpp, &self.secrets) else {
            return;
        };
        let origin = match (&task.kind, rpc) {
            (TaskKind::AddObject { object, .. }, Rpc::AddObjectResponse(_))
                if object == XMPP_CONNECTION_TABLE =>
            {
                XMPP_TASK_ORIGIN
            }
            (TaskKind::GetParameterValues { names }, Rpc::GetParameterValuesResponse(_))
                if names.as_slice() == ["Device."] =>
            {
                BOOTSTRAP_TASK_ORIGIN
            }
            (TaskKind::GetParameterValues { names }, Rpc::GetParameterValuesResponse(_))
                if names.as_slice() == [XMPP_OBJECT] =>
            {
                XMPP_TASK_ORIGIN
            }
            _ => return,
        };
        let result = async {
            // Only tasks the ACS made itself: operator's own read or AddObject != trigger.
            let made_by = self
                .store
                .get_task(task.id)
                .await?
                .and_then(|t| t.created_by);
            if made_by.as_deref() != Some(origin) {
                return Ok(());
            }
            match rpc {
                Rpc::AddObjectResponse(r) => {
                    let Some((username, password, credential_id)) =
                        self.pending_credential(&XMPP_SPEC, secrets, device).await?
                    else {
                        return Ok(());
                    };
                    self.enqueue_xmpp_setup(
                        xmpp,
                        secrets,
                        device,
                        r.instance_number,
                        (&username, &password),
                        &credential_id,
                    )
                    .await
                }
                _ => {
                    if self
                        .store
                        .get_credential(device, XMPP_SPEC.active)
                        .await?
                        .is_some()
                    {
                        return Ok(());
                    }
                    self.provision_xmpp(secrets, device, false).await
                }
            }
        }
        .await;
        if let Err(e) = result {
            warn!(%device, error = %e, "provisioning the XMPP login failed");
        }
    }

    /// CPE report limits (L-5) on `reported`: names outside the data model roots + all past
    /// the per-message limit -> dropped, counted, logged (once per session).
    pub(crate) fn admit_reported(
        &self,
        device: Uuid,
        reported: Vec<ParamUpdate>,
    ) -> Vec<ParamUpdate> {
        let (params, rejected) = admit_params(reported, self.limits.max_params_per_message());
        self.report_rejected(device, "path", rejected.bad_path);
        self.report_rejected(device, "message_limit", rejected.over_message);
        params
    }

    /// Store params that passed [`Self::admit_reported`], up to the per-device limit.
    pub(crate) async fn store_admitted(
        &self,
        device: Uuid,
        params: &[ParamUpdate],
    ) -> Result<usize, dhonomos_store::StoreError> {
        let done = self
            .store
            .upsert_params_capped(device, params, self.limits.max_params_per_device())
            .await
            .inspect_err(|e| param_store::report_failure(device, "cwmp", e))?;
        self.report_rejected(device, "device_limit", done.dropped);
        param_store::report_rejected(device, "cwmp", &done.rejected);
        Ok(params
            .len()
            .saturating_sub(done.dropped + done.rejected.len()))
    }

    /// [`Self::admit_reported`] + [`Self::store_admitted`] for a message that is only stored.
    async fn store_reported(
        &self,
        device: Uuid,
        reported: Vec<ParamUpdate>,
    ) -> Result<usize, dhonomos_store::StoreError> {
        let params = self.admit_reported(device, reported);
        self.store_admitted(device, &params).await
    }

    fn report_rejected(&self, device: Uuid, reason: &'static str, count: usize) {
        if count == 0 {
            return;
        }
        metrics::counter!("dhonomos_cwmp_params_rejected_total", "reason" => reason)
            .increment(count as u64);
        let first = self
            .param_limit_warned
            .lock()
            .is_ok_and(|mut warned| warned.insert(device));
        if first {
            warn!(%device, reason, count,
                max_per_message = self.limits.max_params_per_message(),
                max_per_device = self.limits.max_params_per_device(),
                "dropping parameters the CPE reported beyond the limits (further drops in this session are counted only)");
        }
    }

    async fn apply_response(
        &self,
        device: Uuid,
        task: &RunningTask,
        rpc: &Rpc,
    ) -> serde_json::Value {
        let result = async {
            match rpc {
                Rpc::GetParameterValuesResponse(r) => {
                    let params = self.admit_reported(device, gpv_updates(r));
                    let stored = self.store_admitted(device, &params).await?;
                    // Inform has no ModelName; a DeviceInfo read does.
                    let model_name = r
                        .parameter_list
                        .iter()
                        .find(|p| {
                            p.name.ends_with(".DeviceInfo.ModelName")
                                && p.name.matches('.').count() == 2
                        })
                        .map(|p| p.value.trim().to_owned())
                        .filter(|v| !v.is_empty());
                    if model_name.is_some() {
                        let info = dhonomos_store::DeviceInfo {
                            model_name,
                            ..Default::default()
                        };
                        self.store.update_device_info(device, &info).await?;
                    }
                    // ADR-111: what the device sent, not what the limits let in.
                    let mut removed = 0;
                    if let TaskKind::GetParameterValues { names } = &task.kind {
                        let reported =
                            Reported::new(r.parameter_list.iter().map(|p| p.name.as_str()));
                        for name in names {
                            removed += param_prune::prune(
                                &self.store,
                                device,
                                name,
                                &reported,
                                Mode::Values,
                            )
                            .await;
                        }
                    }
                    Ok(json!({ "parameters": stored, "removed": removed }))
                }
                Rpc::GetParameterNamesResponse(r) => {
                    let params: Vec<ParamUpdate> = r
                        .parameter_list
                        .iter()
                        .map(|p| ParamUpdate {
                            path: p.name.clone(),
                            writable: Some(p.writable),
                            ..ParamUpdate::default()
                        })
                        .collect();
                    let stored = self.store_reported(device, params).await?;
                    // ADR-111; next-level read says nothing about deeper levels.
                    let mut removed = 0;
                    if let TaskKind::GetParameterNames {
                        path,
                        next_level: false,
                    } = &task.kind
                    {
                        let reported =
                            Reported::new(r.parameter_list.iter().map(|p| p.name.as_str()));
                        removed =
                            param_prune::prune(&self.store, device, path, &reported, Mode::Names)
                                .await;
                    }
                    Ok(json!({ "names": stored, "removed": removed }))
                }
                Rpc::SetParameterValuesResponse(r) => {
                    if let TaskKind::SetParameterValues { values } = &task.kind {
                        let params: Vec<ParamUpdate> = values
                            .iter()
                            .map(|v| ParamUpdate {
                                path: v.name.clone(),
                                // Secrets never in the snapshot (CPEs report them empty).
                                value: Some(if v.secret {
                                    String::new()
                                } else {
                                    v.value.clone()
                                }),
                                xsd_type: Some(
                                    v.xsd_type.clone().unwrap_or_else(|| "string".into()),
                                ),
                                writable: Some(true),
                            })
                            .collect();
                        let done = self
                            .store
                            .upsert_params(device, &params)
                            .await
                            .inspect_err(|e| param_store::report_failure(device, "cwmp", e))?;
                        param_store::report_rejected(device, "cwmp", &done.rejected);
                        self.promote_credentials(device, values).await?;
                    }
                    Ok(json!({ "status": r.status }))
                }
                Rpc::AddObjectResponse(r) => {
                    Ok(json!({ "instance_number": r.instance_number, "status": r.status }))
                }
                Rpc::DeleteObjectResponse(r) => {
                    if let TaskKind::DeleteObject { object } = &task.kind {
                        self.store.delete_params_under(device, object).await?;
                    }
                    Ok(json!({ "status": r.status }))
                }
                Rpc::GetParameterAttributesResponse(r) => Ok(json!({
                    "attributes": r.parameter_list.iter()
                        .map(|a| json!({ "name": a.name, "notification": a.notification }))
                        .collect::<Vec<_>>()
                })),
                Rpc::DownloadResponse(r) => Ok(json!({ "status": r.status })),
                Rpc::UploadResponse(r) => Ok(json!({ "status": r.status })),
                other => Ok(json!({ "response": other.name() })),
            }
        }
        .await;
        result.unwrap_or_else(|e: dhonomos_store::StoreError| {
            warn!(%device, error = %e, "failed to apply response to the snapshot");
            json!({ "warning": "snapshot not updated" })
        })
    }
}

/// What a GPV response stores in the snapshot.
pub(crate) fn gpv_updates(r: &dhonomos_cwmp_codec::GetParameterValuesResponse) -> Vec<ParamUpdate> {
    r.parameter_list
        .iter()
        .map(|p| ParamUpdate {
            path: p.name.clone(),
            value: Some(p.value.clone()),
            xsd_type: p.xsd_type.clone(),
            writable: None,
        })
        .collect()
}

/// Connection in the stored `Device.XMPP.Connection.` table to set up for Dhonomos login
/// `username` on `domain`: one already ours -> connection for something else left alone.
/// Order (lowest instance first within each group):
///
/// 1. row with `Username` = `username`;
/// 2. row with `Domain` = `domain`: set up by a Dhonomos server for this domain, any account
///    now (device deleted + registered again -> new ID, row keeps old account; firmware that
///    only uses connection 1 would never connect through a 2nd row);
/// 3. row with no `Username`.
///
/// Row with another domain + a user name: not ours (maybe the operator's own XMPP use)
/// -> never taken. `None`: no such instance -> add a new one.
fn xmpp_connection(params: &[StoredParam], username: &str, domain: &str) -> Option<u32> {
    #[derive(Default)]
    struct Row<'a> {
        user: Option<&'a str>,
        domain: Option<&'a str>,
    }
    let mut instances: std::collections::BTreeMap<u32, Row<'_>> = Default::default();
    for p in params {
        let Some(rest) = p.path.strip_prefix(XMPP_CONNECTION_TABLE) else {
            continue;
        };
        let Some((number, name)) = rest.split_once('.') else {
            continue;
        };
        let Ok(number) = number.parse::<u32>() else {
            continue;
        };
        let row = instances.entry(number).or_default();
        match name {
            "Username" => row.user = p.value.as_deref(),
            "Domain" => row.domain = p.value.as_deref(),
            _ => {}
        }
    }
    instances
        .into_iter()
        .filter_map(|(number, row)| {
            let group = if row.user == Some(username) {
                0
            } else if row.domain.is_some_and(|d| same_xmpp_domain(d, domain)) {
                1
            } else if row.user.is_none_or(str::is_empty) {
                2
            } else {
                return None;
            };
            Some((group, number))
        })
        .min()
        .map(|(_, number)| number)
}

/// Same XMPP domain name? DNS: any case, trailing dot (root) ignored.
/// Empty domain = no name.
fn same_xmpp_domain(a: &str, b: &str) -> bool {
    let a = a.strip_suffix('.').unwrap_or(a);
    let b = b.strip_suffix('.').unwrap_or(b);
    !a.is_empty() && a.eq_ignore_ascii_case(b)
}

/// CPE-reported name = data model path? TR-069 names start at the root object:
/// `Device.` (TR-181) or `InternetGatewayDevice.` (TR-098).
fn is_data_model_path(name: &str) -> bool {
    name.starts_with("Device.") || name.starts_with("InternetGatewayDevice.")
}

/// What [`admit_params`] left out.
#[derive(Debug, Default, PartialEq, Eq)]
struct Rejected {
    /// Names outside the data model roots.
    bad_path: usize,
    /// Params over the per-message limit.
    over_message: usize,
}

/// Params of one CPE message that may be stored (L-5): names under the data model roots,
/// max `per_message` (the first ones).
fn admit_params(reported: Vec<ParamUpdate>, per_message: usize) -> (Vec<ParamUpdate>, Rejected) {
    let total = reported.len();
    let mut kept: Vec<ParamUpdate> = reported
        .into_iter()
        .filter(|p| is_data_model_path(&p.path))
        .collect();
    let bad_path = total - kept.len();
    let over_message = kept.len().saturating_sub(per_message);
    kept.truncate(per_message);
    (
        kept,
        Rejected {
            bad_path,
            over_message,
        },
    )
}

/// Address for the session limit count: IPv6 by /64 (one subscriber prefix)
/// -> privacy addresses do not start a fresh count.
fn client_prefix(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

/// `Device` or `InternetGatewayDevice`, from the first parameter path.
fn root_of(names: impl Iterator<Item = String>) -> Option<String> {
    names
        .filter_map(|n| n.split_once('.').map(|(r, _)| r.to_owned()))
        .find(|r| r == "Device" || r == "InternetGatewayDevice")
}

impl Backend for CwmpBackend {
    type Device = Uuid;
    type Task = RunningTask;

    async fn password(&self, username: &str) -> Option<String> {
        self.candidates(username)
            .await
            .into_iter()
            .next()
            .map(|c| c.password)
    }

    async fn candidates(&self, username: &str) -> Vec<PasswordCandidate> {
        let mut out = Vec::new();
        // Per-device credentials first (CO-16), then shared ones. Credential in provisioning
        // next to the current one (CPE may have applied the new one, answer lost) -> either
        // works; pending one then becomes current (`check_acs_binding`).
        if let Some(secrets) = &self.secrets {
            match self
                .store
                .find_acs_credentials(self.tenant_id, username)
                .await
            {
                Ok(rows) => {
                    // Usernames per device; 2 devices with the same one -> only the 1st
                    // device's passwords count.
                    let owner = rows.first().map(|c| c.device_id);
                    for c in rows.iter().filter(|c| Some(c.device_id) == owner) {
                        match secrets.open_credential(c.device_id, &c.ciphertext, &c.nonce) {
                            Ok(p) => {
                                if let Ok(password) = String::from_utf8(p) {
                                    let tag = if c.kind == ACS_SPEC.pending {
                                        TAG_PENDING
                                    } else {
                                        TAG_ACTIVE
                                    };
                                    out.push(PasswordCandidate { password, tag });
                                }
                            }
                            Err(e) => {
                                warn!(device = %c.device_id, error = %e, "cannot decrypt CPE credential")
                            }
                        }
                    }
                }
                Err(e) => warn!(error = %e, "credential lookup failed"),
            }
        }
        if out.is_empty()
            && let CpeCredentials::Shared {
                username: u,
                password,
            } = &self.credentials
            && u == username
        {
            out.push(PasswordCandidate {
                password: password.clone(),
                tag: 0,
            });
        }
        out
    }

    async fn inform(&self, ctx: InformContext<'_>) -> Result<Uuid, Fault> {
        let inf = ctx.inform;
        let find = |suffix: &str| {
            inf.parameter_list
                .iter()
                .find(|p| is_data_model_path(&p.name) && p.name.ends_with(suffix))
                .map(|p| p.value.clone())
                .filter(|v| !v.is_empty())
        };
        let events: Vec<EventCode> = inf
            .events
            .iter()
            .map(|e| EventCode::parse(&e.event_code))
            .collect();
        let bootstrap = events.contains(&EventCode::Bootstrap);
        let identity = CwmpIdentity {
            oui: inf.device_id.oui.clone(),
            product_class: inf.device_id.product_class.clone(),
            serial_number: inf.device_id.serial_number.clone(),
        };
        let ouis = &self.onboarding.allowed_ouis;
        if !ouis.is_empty() && !ouis.iter().any(|o| o.eq_ignore_ascii_case(&identity.oui)) {
            warn!(oui = %identity.oui, serial = %identity.serial_number, "OUI not allowed");
            return Err(denied("oui", ctx.remote, &identity));
        }
        if self.onboarding.mode == OnboardingMode::Preregistered {
            let known = self
                .store
                .find_cwmp_device(self.tenant_id, &identity)
                .await
                .map_err(|_| retry())?;
            if known.is_none() {
                warn!(oui = %identity.oui, serial = %identity.serial_number, "device not pre-registered");
                return Err(denied("not_registered", ctx.remote, &identity));
            }
        }
        if let (Some(user), Some(_)) = (ctx.username, &self.secrets) {
            self.check_acs_binding(&identity, user, ctx.credential, ctx.remote)
                .await?;
        }
        // Only now: identity admitted + bound to the credential as far as the setup allows
        // (L-3). Key includes the asker too: shared credential -> anyone can claim any
        // identity -> must not use up the real device's sessions.
        let limiter = &self.limits.sessions;
        if limiter.per_minute() > 0 {
            let key = format!(
                "{}|{}|{}-{}-{}",
                ctx.username.unwrap_or_default(),
                client_prefix(ctx.remote.ip()),
                identity.oui,
                identity.product_class,
                identity.serial_number
            );
            if !limiter.allow(&key) {
                metrics::counter!("dhonomos_cwmp_sessions_limited_total").increment(1);
                debug!(device = %key, "too many sessions; asking the CPE to retry later");
                return Err(retry());
            }
        }
        let root = root_of(inf.parameter_list.iter().map(|p| p.name.clone()));
        let update = InformUpdate {
            manufacturer: Some(inf.device_id.manufacturer.clone()).filter(|m| !m.is_empty()),
            model_name: find(".DeviceInfo.ModelName"),
            software_version: find(".DeviceInfo.SoftwareVersion"),
            hardware_version: find(".DeviceInfo.HardwareVersion"),
            data_model: root.clone(),
            connection_request_url: find(".ManagementServer.ConnectionRequestURL"),
            cwmp_version: ctx.cwmp_version.map(str::to_owned),
            remote_addr: Some(ctx.remote.ip().to_canonical()),
            booted: bootstrap || events.contains(&EventCode::Boot),
            new_device_status: (self.onboarding.mode == OnboardingMode::Quarantine)
                .then(|| "quarantined".to_owned()),
        };
        let device = self
            .store
            .upsert_cwmp_device(self.tenant_id, &identity, &update)
            .await
            .map_err(|e| {
                warn!(error = %e, "device upsert failed");
                retry()
            })?;
        // NATed CPE reports where it gets UDP CRs (CW-08).
        if let Some(addr) = find(".ManagementServer.UDPConnectionRequestAddress")
            && addr.parse::<std::net::SocketAddr>().is_ok()
        {
            let _ = self
                .store
                .set_udp_cr_address(self.tenant_id, device.id, &addr)
                .await;
        }
        if device.status == "retired" {
            warn!(device = %device.id, "retired device contacted the ACS");
            return Err(denied("retired", ctx.remote, &identity));
        }
        // New session of the device -> param limit warning may be logged again.
        if let Ok(mut warned) = self.param_limit_warned.lock() {
            warned.remove(&device.id);
        }
        let params = self.admit_reported(
            device.id,
            inf.parameter_list
                .iter()
                .map(|p| ParamUpdate {
                    path: p.name.clone(),
                    value: Some(p.value.clone()),
                    xsd_type: p.xsd_type.clone(),
                    writable: None,
                })
                .collect(),
        );
        let stored = async {
            // CW-18 / CO-11: VALUE CHANGE Inform -> one normalized change event, only params
            // whose value differs from the snapshot.
            if events.contains(&EventCode::ValueChange) {
                let paths: Vec<String> = params.iter().map(|p| p.path.clone()).collect();
                let before = self.store.get_param_values(device.id, &paths).await?;
                let changes: Vec<serde_json::Value> = params
                    .iter()
                    .filter(|p| before.get(&p.path).is_none_or(|old| old != &p.value))
                    .map(|p| {
                        json!({
                            "path": p.path,
                            "old": before.get(&p.path).cloned().flatten(),
                            "new": p.value,
                        })
                    })
                    .collect();
                if !changes.is_empty() {
                    metrics::counter!("dhonomos_parameter_changes_total", "source" => "cwmp")
                        .increment(changes.len() as u64);
                    self.store
                        .record_event(
                            self.tenant_id,
                            Some(device.id),
                            "parameter_change",
                            &json!({ "source": "cwmp-value-change", "changes": changes }),
                        )
                        .await?;
                }
            }
            self.store_admitted(device.id, &params).await?;
            let detail = json!({
                "events": events.iter().map(EventCode::as_str).collect::<Vec<_>>(),
                "retry_count": inf.retry_count,
                "current_time": inf.current_time,
                "remote": ctx.remote.to_string(),
            });
            self.store
                .record_event(self.tenant_id, Some(device.id), "inform", &detail)
                .await?;
            if events.contains(&EventCode::DiagnosticsComplete)
                && let Some(diag) = self.store.waiting_task(device.id, "diagnostic").await?
                && let Ok(TaskKind::Diagnostic { test, .. }) =
                    TaskKind::from_row(&diag.kind, &diag.payload)
            {
                let root = root.clone().unwrap_or_else(|| "Device".into());
                match test.cwmp_object(&root) {
                    Some(object) => {
                        let (k, payload) = TaskKind::DiagnosticResult {
                            task: diag.id,
                            test,
                            object,
                        }
                        .to_row();
                        let task = NewTask {
                            priority: 100,
                            idempotency_key: Some(format!("diagnostic-result:{}", diag.id)),
                            created_by: Some("system:diagnostics".into()),
                            ..NewTask::new(self.tenant_id, device.id, k, payload)
                        };
                        self.store.enqueue_task(&task).await?;
                    }
                    None => {
                        self.store
                            .fail_task(diag.id, "no diagnostics object for this data model")
                            .await?;
                    }
                }
            }
            // Zero-touch (CW-07): read the whole tree of a new or factory-reset device, again
            // after a firmware change (data model may have grown).
            // Pre-registered device: record exists before its first Inform -> not created
            // then; no software version until the first Inform with one -> marks first
            // contact.
            let first_contact = device.created
                || (device.previous_software_version.is_none()
                    && update.software_version.is_some());
            let firmware_changed = matches!(
                (&device.previous_software_version, &update.software_version),
                (Some(before), Some(now)) if before != now
            );
            let zero_touch = first_contact || bootstrap || firmware_changed;
            if zero_touch && let Some(root) = &root {
                let kind = TaskKind::GetParameterValues {
                    names: vec![format!("{root}.")],
                };
                let (k, payload) = kind.to_row();
                let task = NewTask {
                    priority: -10,
                    idempotency_key: Some(format!("bootstrap:{}:{}", device.id, inf.current_time)),
                    created_by: Some("system:bootstrap".into()),
                    ..NewTask::new(self.tenant_id, device.id, k, payload)
                };
                self.store.enqueue_task(&task).await?;
                // Writability (GPV does not tell): needed for config backup + restore (CO-08).
                let (k, payload) = TaskKind::GetParameterNames {
                    path: format!("{root}."),
                    next_level: false,
                }
                .to_row();
                let names = NewTask {
                    priority: -11,
                    idempotency_key: Some(format!(
                        "bootstrap-names:{}:{}",
                        device.id, inf.current_time
                    )),
                    created_by: Some("system:bootstrap".into()),
                    ..NewTask::new(self.tenant_id, device.id, k, payload)
                };
                self.store.enqueue_task(&names).await?;
                if let Some((host, port, secret)) = &self.stun {
                    let password = crate::nat::stun_password(secret, device.id);
                    self.enqueue_stun_setup(
                        device.id,
                        root,
                        host,
                        *port,
                        &password,
                        &inf.current_time,
                    )
                    .await?;
                }
            }
            // Known device may lack the setup (onboarded before the STUN server was enabled).
            // Zero-touch trigger -> already queued above.
            if !zero_touch && let Some(root) = &root {
                self.sync_stun_setup(&device, root).await?;
            }
            // Boot not read whole (same firmware, no factory reset) may still be a fallback to
            // the other firmware image after a failed boot; only the image rows show it
            // -> read them again (ADR-108). Only TR-181 devices that have shown the object
            // -> others get no failed task at every boot.
            if !zero_touch
                && events.contains(&EventCode::Boot)
                && root.as_deref() == Some("Device")
                && self
                    .store
                    .has_param_prefix(device.id, crate::task::FIRMWARE_IMAGES)
                    .await?
            {
                let task =
                    crate::task::boot_firmware_read(self.tenant_id, device.id, &inf.current_time);
                self.store.enqueue_task(&task).await?;
            }
            if let (Some(secrets), Some(root)) = (&self.secrets, &root) {
                // New credentials for an active one: only first contact + BOOTSTRAP (ADR-112).
                let trigger = if first_contact || bootstrap {
                    CredentialTrigger::Rotate
                } else if firmware_changed {
                    CredentialTrigger::FirmwareOnly
                } else {
                    CredentialTrigger::None
                };
                self.provision_credentials(secrets, &device, root, trigger, &inf.current_time)
                    .await?;
            }
            // Every boot -> forced WireGuard run: boot may come with lost config (e.g. factory
            // reset + restore from backup); one `Device.WireGuard.` read per boot is cheap.
            let wg_forced = zero_touch || events.contains(&EventCode::Boot);
            self.wg_inform(&device, wg_forced, &inf.current_time).await;
            let presets = self.presets.get();
            if !presets.is_empty() {
                let (tags, attributes) = self
                    .store
                    .get_device(device.id)
                    .await?
                    .map(|d| (d.tags, d.attributes))
                    .unwrap_or_default();
                let ctx = MatchContext {
                    events: &events,
                    oui: &identity.oui,
                    product_class: &identity.product_class,
                    software_version: update.software_version.as_deref(),
                    tags: &tags,
                    new_device: first_contact,
                    attributes: &attributes,
                    serial: &identity.serial_number,
                    protocol: "cwmp",
                };
                crate::presets::enqueue_matching(
                    &self.store,
                    self.tenant_id,
                    &presets,
                    device.id,
                    &ctx,
                    &inf.current_time,
                )
                .await?;
            }
            Ok::<_, dhonomos_store::StoreError>(())
        }
        .await;
        stored.map_err(|e| {
            warn!(device = %device.id, error = %e, "storing Inform failed");
            retry()
        })?;
        Ok(device.id)
    }

    async fn cpe_request(&self, device: &Uuid, rpc: &Rpc) -> Result<(), Fault> {
        let r = async {
            match rpc {
                Rpc::TransferComplete(tc) => {
                    let ok = tc.fault.fault_code == 0;
                    let detail = json!({
                        "command_key": tc.command_key,
                        "fault_code": tc.fault.fault_code,
                        "fault_string": tc.fault.fault_string,
                        "start_time": tc.start_time,
                        "complete_time": tc.complete_time,
                    });
                    self.store
                        .record_event(self.tenant_id, Some(*device), "transfer_complete", &detail)
                        .await?;
                    if let Ok(task) = tc.command_key.parse::<Uuid>() {
                        let outcome = if ok {
                            Ok(detail)
                        } else {
                            Err(format!("{} {}", tc.fault.fault_code, tc.fault.fault_string))
                        };
                        // Reporting device completes only its own tasks (L-1).
                        self.store.complete_task(*device, task, outcome).await?;
                    }
                }
                other => {
                    let kind = match other {
                        Rpc::AutonomousTransferComplete(_) => "autonomous_transfer_complete",
                        Rpc::DUStateChangeComplete(_) => "du_state_change_complete",
                        Rpc::AutonomousDUStateChangeComplete(_) => {
                            "autonomous_du_state_change_complete"
                        }
                        Rpc::RequestDownload(_) => "request_download",
                        Rpc::Kicked(_) => "kicked",
                        _ => return Ok(()),
                    };
                    self.store
                        .record_event(self.tenant_id, Some(*device), kind, &json!({}))
                        .await?;
                }
            }
            Ok::<_, dhonomos_store::StoreError>(())
        }
        .await;
        r.map_err(|e| {
            warn!(%device, error = %e, "storing CPE request failed");
            retry()
        })
    }

    async fn next_request(&self, device: &Uuid) -> Option<(RunningTask, Rpc)> {
        match self.store.device_status(*device).await {
            Ok(Some(status)) if status == "active" => {}
            Ok(_) => return None, // quarantined/retired -> no tasks
            Err(e) => {
                warn!(%device, error = %e, "device status unavailable; ending session");
                return None;
            }
        }
        loop {
            let task = match self.store.next_task(*device).await {
                Ok(t) => t?,
                Err(e) => {
                    warn!(%device, error = %e, "task queue unavailable; ending session");
                    return None;
                }
            };
            let mut payload = task.payload.clone();
            if let Some(secrets) = &self.secrets
                && let Err(e) =
                    secrets.decrypt_fields(&mut payload, &crate::secrets::task_context(task.id))
            {
                warn!(task = %task.id, error = %e, "cannot decrypt task secrets");
                let _ = self.store.fail_task(task.id, &e.to_string()).await;
                continue;
            }
            let kind = match TaskKind::from_row(&task.kind, &payload) {
                Ok(k) => self
                    .resolve_download(*device, k)
                    .await
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let root = match &kind {
                Ok(TaskKind::Diagnostic { .. }) => self
                    .store
                    .get_device(*device)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|d| d.data_model)
                    .unwrap_or_else(|| "Device".into()),
                _ => "Device".into(),
            };
            // ParameterKey + CommandKey = string(32) in TR-069: task ID without hyphens
            // (32 hex digits) fits + parses back to the task (TransferComplete).
            let key = task.id.simple().to_string();
            let request = kind.and_then(|k| Ok((k.to_cwmp_in(&key, &root)?, k)));
            match request {
                Ok((rpc, kind)) => {
                    debug!(%device, task = %task.id, method = rpc.name(), "sending task");
                    return Some((RunningTask { id: task.id, kind }, rpc));
                }
                Err(e) => {
                    warn!(task = %task.id, error = %e, "task cannot be sent");
                    let _ = self
                        .store
                        .fail_task(task.id, &format!("invalid task: {e}"))
                        .await;
                }
            }
        }
    }

    async fn completed(&self, device: &Uuid, task: RunningTask, completed: Completed) {
        let label = match &completed.outcome {
            Outcome::Response(_) => "response",
            Outcome::Fault(_) => "fault",
            Outcome::Mismatch(_) => "mismatch",
            Outcome::NoResponse => "no_response",
        };
        metrics::counter!("dhonomos_tasks_completed_total", "kind" => task.kind.name(), "outcome" => label)
            .increment(1);
        if let (
            TaskKind::Diagnostic { .. },
            Outcome::Response(Rpc::SetParameterValuesResponse(_)),
        ) = (&task.kind, &completed.outcome)
        {
            // Requested; CPE reports 8 DIAGNOSTICS COMPLETE when done.
            let _ = self
                .store
                .mark_task_waiting(task.id, &json!({ "phase": "requested" }))
                .await;
            return;
        }
        if let (
            TaskKind::DiagnosticResult {
                task: diag,
                test,
                object,
            },
            Outcome::Response(rpc @ Rpc::GetParameterValuesResponse(r)),
        ) = (&task.kind, &completed.outcome)
        {
            let raw: std::collections::BTreeMap<String, String> = r
                .parameter_list
                .iter()
                .filter_map(|p| {
                    p.name
                        .strip_prefix(object.as_str())
                        .map(|rel| (rel.to_owned(), p.value.clone()))
                })
                .collect();
            let outcome = crate::diagnostics::outcome(*test, &raw);
            // Values into the param snapshot too.
            let _ = self.apply_response(*device, &task, rpc).await;
            if let Err(e) = self
                .store
                .complete_task(*device, *diag, outcome.clone())
                .await
            {
                warn!(task = %diag, error = %e, "failed to record diagnostic result");
            }
            let own = outcome.or_else(|e| Ok::<_, String>(json!({ "diagnostic_error": e })));
            if let Err(e) = self.store.complete_task(*device, task.id, own).await {
                warn!(task = %task.id, error = %e, "failed to record task result");
            }
            return;
        }
        let outcome = match &completed.outcome {
            Outcome::Response(rpc) => {
                let result = self.apply_response(*device, &task, rpc).await;
                self.xmpp_follow_up(*device, &task, rpc).await;
                self.wg_completed(*device, &task, WgAnswer::Response(rpc))
                    .await;
                let transfer_pending = matches!(
                    rpc,
                    Rpc::DownloadResponse(r) if r.status == 1
                ) || matches!(rpc, Rpc::UploadResponse(r) if r.status == 1);
                if transfer_pending {
                    // Completed later by TransferComplete, CommandKey = task ID.
                    let _ = self.store.mark_task_waiting(task.id, &result).await;
                    return;
                }
                Ok(result)
            }
            Outcome::Fault(f) if !is_retryable_fault(f.code) => {
                let msg = fault_text(f);
                match self.store.fail_task(task.id, &msg).await {
                    Ok(_) => self.note_refused_credentials(*device, &task, f.code).await,
                    Err(e) => warn!(task = %task.id, error = %e, "failed to record task result"),
                }
                self.wg_completed(*device, &task, WgAnswer::Fault(f)).await;
                return;
            }
            Outcome::Fault(f) => Err(fault_text(f)),
            Outcome::Mismatch(rpc) => Err(format!("unexpected response {}", rpc.name())),
            Outcome::NoResponse => Err("no response".to_owned()),
        };
        match self.store.complete_task(*device, task.id, outcome).await {
            // Fault, no retry attempts left -> final, like the ones above.
            Ok(TaskState::Failed) => {
                if let Outcome::Fault(f) = &completed.outcome {
                    self.note_refused_credentials(*device, &task, f.code).await;
                    self.wg_completed(*device, &task, WgAnswer::Fault(f)).await;
                } else {
                    self.wg_completed(*device, &task, WgAnswer::Lost).await;
                }
            }
            Ok(_) => {}
            Err(e) => warn!(task = %task.id, error = %e, "failed to record task result"),
        }
    }

    async fn session_ended(&self, device: &Uuid, task: Option<RunningTask>, aborted: bool) {
        if let Ok(mut warned) = self.param_limit_warned.lock() {
            warned.remove(device);
        }
        if aborted
            && task.is_some()
            && let Err(e) = self.store.requeue_running(*device).await
        {
            warn!(%device, error = %e, "failed to requeue tasks");
        }
        self.wg_session_ended(*device, task.as_ref(), aborted).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhonomos_cwmp_codec::SetParameterValuesFault;

    fn reported(paths: &[&str]) -> Vec<ParamUpdate> {
        paths
            .iter()
            .map(|p| ParamUpdate {
                path: (*p).into(),
                value: Some("v".into()),
                ..ParamUpdate::default()
            })
            .collect()
    }

    #[test]
    fn only_names_under_a_data_model_root_are_admitted() {
        let input = reported(&[
            "Device.DeviceInfo.UpTime",
            "InternetGatewayDevice.DeviceInfo.UpTime",
            "Device.",
            "Devices.X",
            "Device",
            "device.DeviceInfo.UpTime",
            "X_VENDOR.Device.A",
            "",
            "../Device.A",
        ]);
        let (kept, rejected) = admit_params(input, 100);
        let kept: Vec<&str> = kept.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(
            kept,
            [
                "Device.DeviceInfo.UpTime",
                "InternetGatewayDevice.DeviceInfo.UpTime",
                "Device."
            ]
        );
        assert_eq!(
            rejected,
            Rejected {
                bad_path: 6,
                over_message: 0
            }
        );
    }

    #[test]
    fn a_message_is_cut_at_the_per_message_limit_after_names_are_checked() {
        let input = reported(&["Bad.A", "Device.A", "Device.B", "Device.C", "Device.D"]);
        let (kept, rejected) = admit_params(input, 2);
        let kept: Vec<&str> = kept.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(kept, ["Device.A", "Device.B"], "rejected names use no room");
        assert_eq!(
            rejected,
            Rejected {
                bad_path: 1,
                over_message: 2
            }
        );
        assert_eq!(admit_params(Vec::new(), 0).0.len(), 0);
    }

    #[test]
    fn session_limits_count_ipv6_clients_by_prefix() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap_or_else(|_| panic!("{s}"));
        assert_eq!(client_prefix(ip("192.0.2.7")), ip("192.0.2.7"));
        assert_eq!(client_prefix(ip("::ffff:192.0.2.7")), ip("192.0.2.7"));
        assert_eq!(
            client_prefix(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd")),
            client_prefix(ip("2001:db8:1:2::1"))
        );
        assert_ne!(
            client_prefix(ip("2001:db8:1:2::1")),
            client_prefix(ip("2001:db8:1:3::1"))
        );
    }

    fn stored(path: &str, value: Option<&str>) -> StoredParam {
        StoredParam {
            path: path.into(),
            value: value.map(str::to_owned),
            xsd_type: None,
            writable: None,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn an_unused_xmpp_connection_is_taken_and_others_are_left_alone() {
        let ours = "0192b7a0-0000-7000-8000-000000000001";
        let domain = "acs.example.net";
        let pick = |params: &[StoredParam]| xmpp_connection(params, ours, domain);
        let none: Vec<StoredParam> = Vec::new();
        assert_eq!(pick(&none), None, "no connection: add one");
        // Support params only, no row.
        let support = [stored("Device.XMPP.ConnectionNumberOfEntries", Some("0"))];
        assert_eq!(pick(&support), None);
        // Row known by name only (GPN) or with no user name -> free.
        let free = [stored("Device.XMPP.Connection.1.", None)];
        assert_eq!(pick(&free), Some(1));
        let free = [stored("Device.XMPP.Connection.3.Username", Some(""))];
        assert_eq!(pick(&free), Some(3));
        // Row set up by somebody else -> untouched; next free one used, else a new one.
        let taken = [
            stored("Device.XMPP.Connection.1.Username", Some("someone")),
            stored("Device.XMPP.Connection.1.Enable", Some("true")),
            stored("Device.XMPP.Connection.2.Username", Some("")),
        ];
        assert_eq!(pick(&taken), Some(2));
        assert_eq!(pick(&taken[..2]), None);
        // Ours already -> used again, even behind a free one.
        let again = [
            stored("Device.XMPP.Connection.2.Username", Some(ours)),
            stored("Device.XMPP.Connection.5.Username", Some("")),
        ];
        assert_eq!(pick(&again), Some(2));
        // Sub-tables + look-alikes -> no instances.
        let other = [
            stored("Device.XMPP.Connection.1.Server.1.ServerAddress", Some("x")),
            stored("Device.XMPP.Connection.x.Username", Some("")),
            stored("Device.XMPP.ConnectionNumberOfEntries", Some("1")),
        ];
        assert_eq!(pick(&other), Some(1));
    }

    #[test]
    fn an_xmpp_connection_of_our_domain_is_taken_over_whatever_account_it_has() {
        let ours = "0192b7a0-0000-7000-8000-000000000001";
        let old = "0192b7a0-0000-7000-8000-0000000000ff";
        let domain = "acs.example.net";
        let pick = |params: &[StoredParam]| xmpp_connection(params, ours, domain);
        let row = |i: u32, user: &str, dom: &str| {
            [
                stored(&format!("Device.XMPP.Connection.{i}.Username"), Some(user)),
                stored(&format!("Device.XMPP.Connection.{i}.Domain"), Some(dom)),
            ]
        };
        let rows = |list: &[[StoredParam; 2]]| list.iter().flatten().cloned().collect::<Vec<_>>();

        // Device registered again: row 1 still has the old account on our domain.
        assert_eq!(pick(&row(1, old, domain)), Some(1));
        // Case + trailing dot do not matter.
        assert_eq!(pick(&row(1, old, "ACS.Example.NET.")), Some(1));
        assert_eq!(pick(&row(1, old, "acs.example.net.")), Some(1));
        // Other domain + an account = somebody else's use -> left alone.
        assert_eq!(pick(&row(1, old, "xmpp.other.example")), None);
        assert_eq!(pick(&row(1, old, "acs.example.net.evil")), None);
        assert_eq!(pick(&row(1, old, "")), None);

        // 1. Own account first, whatever comes before it.
        let list = rows(&[
            row(1, "", ""),
            row(2, old, domain),
            row(3, ours, "elsewhere.example"),
        ]);
        assert_eq!(pick(&list), Some(3));
        // 2. Then a row of our domain, even behind an unused one.
        let list = rows(&[row(1, "", ""), row(2, old, domain), row(4, "x", domain)]);
        assert_eq!(pick(&list), Some(2), "lowest instance within the group");
        // 3. Then an unused row; foreign row in front stays untouched.
        let list = rows(&[row(1, "operator", "xmpp.other.example"), row(2, "", "")]);
        assert_eq!(pick(&list), Some(2));
        let list = rows(&[row(1, "operator", "xmpp.other.example")]);
        assert_eq!(pick(&list), None, "only a foreign row: add one");
        // Row with a Domain, no user name -> ours by its domain too.
        let list = rows(&[row(1, "", "other.example"), row(2, "", domain)]);
        assert_eq!(pick(&list), Some(2));
        // No Username stored, only the Domain.
        let only_domain = [stored("Device.XMPP.Connection.1.Domain", Some(domain))];
        assert_eq!(pick(&only_domain), Some(1));
        // Empty configured domain -> matches no row.
        let empty = row(1, old, "");
        assert_eq!(xmpp_connection(&empty, ours, ""), None);
    }

    #[test]
    fn fault_text_names_each_parameter() {
        let mut f = Fault::new(9003, "Invalid arguments");
        f.set_parameter_values_faults = vec![
            SetParameterValuesFault {
                parameter_name: "Device.WiFi.SSID.1.SSID".into(),
                fault_code: 9007,
                fault_string: "Invalid parameter value".into(),
            },
            SetParameterValuesFault {
                parameter_name: "Device.X".into(),
                fault_code: 9008,
                fault_string: "Not writable".into(),
            },
        ];
        assert_eq!(
            fault_text(&f),
            "9003 Invalid arguments | Device.WiFi.SSID.1.SSID: 9007 Invalid parameter value | Device.X: 9008 Not writable"
        );
        assert_eq!(
            fault_text(&Fault::new(9002, "Internal error")),
            "9002 Internal error"
        );
    }

    #[test]
    fn only_a_cpe_fault_text_has_a_fault_code() {
        for f in [
            Fault::new(9003, "Invalid arguments"),
            Fault::new(9800, "Vendor fault"),
        ] {
            assert_eq!(fault_code_of(&fault_text(&f)), Some(f.code));
        }
        assert_eq!(fault_code_of("9001"), Some(9001));
        for other in [
            "",
            "session aborted before the device answered",
            "no response",
            "unexpected response GetParameterValuesResponse",
            "invalid task: bad payload",
            "8005 Retry request",
            "9003Invalid",
            "90031 Too long",
            "12345",
            "-903 Invalid",
        ] {
            assert_eq!(fault_code_of(other), None, "{other:?}");
        }
    }

    /// Stored STUN params of a device, `edit` applied to the wanted values.
    fn stun_params(edit: impl Fn(&str, &mut StoredParam)) -> Vec<StoredParam> {
        let mut params = vec![
            stored("Device.ManagementServer.STUNEnable", Some("true")),
            stored(
                "Device.ManagementServer.STUNServerAddress",
                Some("stun.example.net"),
            ),
            stored("Device.ManagementServer.STUNServerPort", Some("3478")),
            stored("Device.ManagementServer.STUNUsername", Some("device-1")),
            stored("Device.ManagementServer.STUNPassword", Some("")),
        ];
        for p in &mut params {
            let name = p.path.rsplit('.').next().unwrap_or_default().to_owned();
            edit(&name, p);
        }
        params
    }

    #[test]
    fn stun_setup_is_wanted_when_a_value_differs_or_is_missing() {
        let differs =
            |p: &[StoredParam]| stun_setup_differs(p, "stun.example.net", 3478, "device-1");
        assert!(!differs(&stun_params(|_, _| {})), "the setup is there");
        // Password never compared; booleans + numbers may be written another way.
        assert!(!differs(&stun_params(|n, p| {
            if n == "STUNPassword" {
                p.value = Some("anything".into());
            }
            if n == "STUNEnable" {
                p.value = Some("1".into());
            }
            if n == "STUNServerPort" {
                p.value = Some(" 3478 ".into());
            }
            if n == "STUNServerAddress" {
                p.value = Some("STUN.example.net".into());
            }
        })));
        for (name, other) in [
            ("STUNEnable", "false"),
            ("STUNEnable", ""),
            ("STUNServerAddress", "stun.other.example"),
            ("STUNServerAddress", ""),
            ("STUNServerPort", "3479"),
            ("STUNServerPort", "x"),
            ("STUNUsername", "device-2"),
            ("STUNUsername", ""),
        ] {
            assert!(
                differs(&stun_params(|n, p| {
                    if n == name {
                        p.value = Some(other.into());
                    }
                })),
                "{name}={other}"
            );
        }
        // Value not known, or row not reported (STUNEnable present).
        assert!(differs(&stun_params(|n, p| {
            if n == "STUNUsername" {
                p.value = None;
            }
        })));
        let mut params = stun_params(|_, _| {});
        params.retain(|p| !p.path.ends_with("STUNServerPort"));
        assert!(differs(&params));
    }

    #[test]
    fn a_device_that_does_not_take_the_stun_setup_is_left_alone() {
        let differs =
            |p: &[StoredParam]| stun_setup_differs(p, "stun.example.net", 3478, "device-1");
        // No STUN params at all, or only look-alikes.
        assert!(!differs(&[]));
        assert!(!differs(&[
            stored("Device.ManagementServer.STUNServerPort", Some("1")),
            stored(
                "InternetGatewayDevice.ManagementServer.STUNEnable",
                Some("false")
            ),
            stored("Device.XMPP.STUNEnable", Some("false")),
        ]));
        // Read-only -> device would only refuse the SPV.
        for name in STUN_PARAMS {
            assert!(
                !differs(&stun_params(|n, p| {
                    if n == "STUNEnable" {
                        p.value = Some("false".into());
                    }
                    if n == name {
                        p.writable = Some(false);
                    }
                })),
                "{name} read-only"
            );
        }
        // Writability unknown (GPN never ran) -> no stop.
        assert!(differs(&stun_params(|n, p| {
            if n == "STUNEnable" {
                p.value = Some("false".into());
            }
            p.writable = None;
        })));
    }

    #[test]
    fn each_stun_configuration_has_its_own_tasks() {
        let id = stun_setup_id("stun.example.net", 3478, "device-1");
        assert_eq!(id.len(), 16);
        assert_eq!(id, stun_setup_id("stun.example.net", 3478, "device-1"));
        for other in [
            stun_setup_id("stun2.example.net", 3478, "device-1"),
            stun_setup_id("stun.example.net", 3479, "device-1"),
            stun_setup_id("stun.example.net", 3478, "device-2"),
            stun_setup_id("stun.example.net:3478", 0, "device-1"),
        ] {
            assert_ne!(id, other);
        }
        let device = Uuid::nil();
        let keys: HashSet<String> = (0..STUN_SETUP_MAX_ROUNDS)
            .flat_map(|round| {
                (0..2).map(move |i| stun_setup_key(device, i, &stun_sync_occurrence("abc", round)))
            })
            .collect();
        assert_eq!(
            keys.len(),
            STUN_SETUP_MAX_ROUNDS * 2,
            "no two tries share a key"
        );
        assert!(
            !keys.contains(&stun_setup_key(device, 0, "2026-10-14T00:00:00Z")),
            "none is a zero-touch key"
        );
    }
}
