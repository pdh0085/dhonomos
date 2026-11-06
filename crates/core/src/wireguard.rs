//! WireGuard on devices (ADR-110 stage 4).
//! Caller of the device planner (`dhonomos_wireguard::device`) -> system tasks configure the
//! CPE's TR-181 `Device.WireGuard.` + result recorded per member.
//! [`WgRunner`] = same for CWMP devices and USP Agents; only step -> tasks differs
//! ([`WgProtocol`]).
//!
//! Run start: a membership needs one (see [`needs_run`]), or snapshot still has rows of ours
//! for a network the device left.
//! CWMP -> at end of an Inform. USP -> Agent connect, boot event, periodic sweep of connected
//! Agents.
//! Zero-touch trigger (incl. every boot) -> every membership needs a run: boot may come with
//! lost config (e.g. factory reset, then restore from backup).
//! Run = plan 1 step -> queue as task (`created_by` [`WG_TASK_ORIGIN`]) -> device answers ->
//! plan again, until planner done. CWMP session + USP drain read the queue again after each
//! answer.
//! Run in memory only: lost with server, session or connection -> starts again later.
//!
//! Server key mode -> server makes the device's key pair.
//! Private key only in the task that sets it (sealed with `--secrets-key`, bound to the task)
//! and in memory while sent. Task finished -> `********` in the task. Snapshot keeps it empty
//! like every secret.
//! Public key stored as the member's before the task is sent; forgotten if the device does not
//! take it. After the key -> tunnel read again.
//!
//! Key rotation (member's `rotate_requested_at`) = direct swap. Run gives the device a new key
//! once. Server key mode -> new key pair. Device key mode -> `PrivateKey` = "" -> firmware
//! makes a new pair, then tunnel read again.
//! New public key -> member's -> hub replaces the peer.
//! Request cleared when run ends with member applied and key really changed.
//! Device keeps its key -> member blocked, request open.
//!
//! Pre-shared key (sealed in DB with `--secrets-key`, bound to the member) -> sent in the run's
//! values as `Peer.PresharedKey`. Secret: sealed in the task like a private key, redacted after
//! the task finished.
//! Key reads as "" on the device -> run cannot compare it.
//! Sent (key, or "" for none) until a set of it succeeded in the run, if any of:
//! network's Peer row added in the run (new member, or device lost its config);
//! member not applied (earlier run ended before the values, e.g. CWMP firmware wait, but
//! stored the hash);
//! desired state (incl. key digest) changed since last run.
//! Key rotation -> new pre-shared key too: stored before the rotation step (hub takes it),
//! sent with the values after it.
//! Stored key cannot be opened (no or other `--secrets-key`) -> member `error`, nothing sent
//! for it.
//!
//! Some firmware makes the IP interface of a new tunnel only some s after the add is
//! committed (planner's `Step::WaitForFirmware`).
//! CWMP: commit at session end -> run records member pending + ends. Device woken shortly
//! after its session ([`CwmpBackend::with_wg_rewake`]) -> next run finds the row.
//! 1 wait per session, max [`IpWait::cwmp_sessions`].
//! USP: each message commits on its own -> run reads `Device.IP.Interface.` again every
//! [`IpWait::usp_poll_every`], max [`IpWait::usp_polls`] times.
//! After that many waits -> run adds the IP interface itself.
//! Count per member, kept in memory until the member is applied.
//! Firmware never makes the row -> no new wait by that member; new member (re-added) waits
//! again.
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex};

use dhonomos_cwmp_codec::{Fault, Rpc};
use dhonomos_store::{
    NewTask, ParamUpdate, Store, StoreError, StoredParam, UpsertOutcome, WgDeviceMembership,
    WgRefusal,
};
use dhonomos_wireguard::{
    DesiredTunnel, KEY_LEN, KeyMode, Outcome, Param, PlanInput, Step, Tree, desired_hash,
    generate_keypair, generate_preshared_key, key_text, network_of_alias, plan,
};
use time::{Duration, OffsetDateTime};
use tracing::{debug, info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cwmp::{CwmpBackend, RunningTask, gpv_updates};
use crate::secrets::SecretBox;
use crate::task::{SetValue, TaskKind};
use crate::usp_map::Applied;

/// Origin of a run's tasks.
pub(crate) const WG_TASK_ORIGIN: &str = "system:wireguard";
/// Queue priority of these tasks (credentials: -12).
const WG_PRIORITY: i16 = -10;
/// Applied config trusted this long -> then a run reads the device again.
const DRIFT_CHECK: Duration = Duration::hours(6);
/// Wait of a blocked, error or unsupported membership for another run, unless its desired
/// state changes.
const RETRY_AFTER: Duration = Duration::hours(24);
/// Sweep wait before another run on a device whose last run ended without outcome
/// (answer lost, add without its instance, task not queued, run cancelled). Default, configurable.
pub(crate) const INCOMPLETE_RETRY: Duration = Duration::minutes(5);
/// Max steps per run.
const MAX_STEPS: usize = 32;

const WG_ROOT: &str = "Device.WireGuard.";
const PEER_TABLE: &str = "Device.WireGuard.Peer.";
const TUNNEL_TABLE: &str = "Device.WireGuard.Tunnel.";
const IP_TABLE: &str = "Device.IP.Interface.";

/// Wait of a run for firmware to make the IP interface of a new tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IpWait {
    /// CWMP: sessions (1 wait each) before the run adds the IP interface itself.
    pub cwmp_sessions: u32,
    /// USP: reads of `Device.IP.Interface.` before the run adds it itself.
    pub usp_polls: u32,
    /// USP: wait before each of those reads.
    pub usp_poll_every: Duration,
}

impl Default for IpWait {
    fn default() -> Self {
        Self {
            cwmp_sessions: 2,
            usp_polls: 30,
            usp_poll_every: Duration::seconds(1),
        }
    }
}

/// State detail: member's pre-shared key cannot be opened.
const PSK_UNOPENED: &str = "the stored pre-shared key cannot be opened";

/// State detail: run waits for firmware over CWMP.
const IP_WAIT_DETAIL: &str = "waiting for the device to make the IP interface of the tunnel";

/// Protocol: step -> tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WgProtocol {
    /// AddObject -> SetParameterValues of the new instance's Alias -> its read.
    Cwmp,
    /// Add with the Alias (writeOnceReadOnly in USP) -> read of the new instance.
    Usp,
}

/// Needs of a run from its protocol driver.
pub(crate) trait WgHost {
    /// Store a run's read result. Snapshot under the read paths already emptied.
    fn wg_store_read(
        &self,
        device: Uuid,
        params: Vec<ParamUpdate>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// WireGuard runs of one protocol driver, by device. 1 runner per driver.
#[derive(Debug)]
pub(crate) struct WgRunner {
    store: Store,
    tenant_id: Uuid,
    secrets: Option<Arc<SecretBox>>,
    protocol: WgProtocol,
    /// Runs in progress, by device.
    runs: Mutex<HashMap<Uuid, WgRun>>,
    /// 1 at a time per device. USP: run start + answer to a run task can come at once
    /// (connect or sweep while the drain runs).
    gates: Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>,
    /// Last end of a non-converged run on a device with only stale rows (no live membership)
    /// -> sweep leaves the device alone for [`RETRY_AFTER`] after it.
    stale_failed: Mutex<HashMap<Uuid, OffsetDateTime>>,
    /// No sweep run until then on a device whose last run ended without outcome
    /// (see [`INCOMPLETE_RETRY`]).
    incomplete: Mutex<HashMap<Uuid, OffsetDateTime>>,
    /// Length of that hold-off.
    incomplete_retry: Duration,
    /// Wait limits for firmware-made IP interfaces.
    ip_wait: IpWait,
    /// Firmware IP interface waits so far, by (device, member). Kept across runs until the
    /// member is applied or no longer live.
    ip_waits: Mutex<HashMap<(Uuid, Uuid), u32>>,
    /// CWMP devices to wake after session end: their run waits for firmware.
    rewake: Mutex<HashSet<Uuid>>,
}

/// Holds a device's gate. Drop -> gate released + forgotten when unused.
struct Gate<'a> {
    runner: &'a WgRunner,
    device: Uuid,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for Gate<'_> {
    fn drop(&mut self) {
        self.guard.take();
        if let Ok(mut gates) = self.runner.gates.lock()
            && gates
                .get(&self.device)
                .is_some_and(|g| Arc::strong_count(g) == 1)
        {
            gates.remove(&self.device);
        }
    }
}

/// One run on a device.
#[derive(Debug)]
pub(crate) struct WgRun {
    /// Run name in its task keys = Inform's CurrentTime + random nonce
    /// (devices without a clock send the same CurrentTime every time).
    occurrence: String,
    /// Object paths read in this run.
    read: BTreeSet<String>,
    steps: usize,
    /// Fingerprints of steps taken.
    issued: HashSet<String>,
    /// Networks whose Tunnel row this run added + no server-made key yet.
    fresh_tunnels: BTreeSet<Uuid>,
    /// Networks whose Peer row this run added -> device gets the pre-shared key.
    fresh_peers: BTreeSet<Uuid>,
    /// Networks whose `PresharedKey` this run set (key, or "" for none).
    psk_sent: BTreeSet<Uuid>,
    /// Members whose pre-shared key cannot be opened -> recorded as `error` in this run.
    psk_failed: BTreeSet<Uuid>,
    /// Networks whose key rotation step this run issued.
    rotated: BTreeSet<Uuid>,
    /// Device key mode: member's key before this run's rotation step, by network.
    old_keys: BTreeMap<Uuid, Option<String>>,
    /// Queued tasks of the run, by task ID.
    pending: HashMap<Uuid, Pending>,
    /// Device had no live membership at run start, only rows of ours.
    stale_only: bool,
    /// Planner said done.
    converged: bool,
    /// A member state was recorded (error, blocked, unsupported, no progress).
    recorded: bool,
}

impl WgRun {
    /// No read answered yet + only reads queued -> result will show the device as it is now.
    fn has_read_nothing(&self) -> bool {
        self.read.is_empty()
            && !self.pending.is_empty()
            && self
                .pending
                .values()
                .all(|p| matches!(p, Pending::Read { .. }))
    }
}

/// Kind of a queued run task.
#[derive(Debug, Clone)]
enum Pending {
    /// `Step::Read`.
    Read { paths: Vec<String> },
    /// AddObject (CWMP) or Add (USP) of `Step::Add`.
    Add {
        table: String,
        alias: String,
        network_id: Uuid,
        then_read: Vec<String>,
    },
    /// SetParameterValues of the new instance's Alias (CWMP).
    AddAlias { network_id: Uuid },
    /// Read of the new instance + the `then_read` paths.
    AddRead {
        paths: Vec<String>,
        network_id: Uuid,
    },
    /// `Step::Set`. `secret`: a value is a secret (task redacted after it finished).
    /// `preshared_key`: sets `PresharedKey`.
    Set {
        network_id: Uuid,
        secret: bool,
        preshared_key: bool,
    },
    /// SetParameterValues of a server-made private key.
    Key { network_id: Uuid, member_id: Uuid },
    /// SetParameterValues of an empty private key (device key mode rotation).
    Regenerate { network_id: Uuid },
    /// Read of the tunnel after `Key` or `Regenerate`.
    KeyRead {
        paths: Vec<String>,
        network_id: Uuid,
    },
    /// Read of `Step::WaitForFirmware` (USP).
    WaitRead {
        paths: Vec<String>,
        network_id: Uuid,
    },
    /// `Step::Delete`.
    Delete { object: String },
}

impl Pending {
    /// Network of the task, if any.
    fn network(&self) -> Option<Uuid> {
        match self {
            Self::Add { network_id, .. }
            | Self::AddAlias { network_id }
            | Self::AddRead { network_id, .. }
            | Self::Set { network_id, .. }
            | Self::Key { network_id, .. }
            | Self::Regenerate { network_id }
            | Self::KeyRead { network_id, .. }
            | Self::WaitRead { network_id, .. } => Some(*network_id),
            Self::Read { .. } | Self::Delete { .. } => None,
        }
    }
}

/// End of a run task, as the driver saw it.
pub(crate) enum WgAnswer<'a> {
    /// Device answered (CWMP).
    Response(&'a Rpc),
    /// Device refused with a CPE fault (CWMP).
    Fault(&'a Fault),
    /// Agent answered (USP): meaning of the response.
    Applied(&'a Applied),
    /// Agent refused (USP): Error message, or a response that reports a failure.
    /// Value = text the task failed with.
    Refused(&'a str),
    /// No answer (session or connection lost, no response, unexpected response).
    Lost,
}

impl WgAnswer<'_> {
    /// Values of a read answer, else `None`.
    fn values(&self) -> Option<Vec<ParamUpdate>> {
        match self {
            Self::Response(Rpc::GetParameterValuesResponse(r)) => Some(gpv_updates(r)),
            Self::Applied(a) => Some(a.params.clone()),
            _ => None,
        }
    }

    /// Instance (ends with '.') an add in `table` made, if the answer says.
    fn instance(&self, table: &str) -> Option<String> {
        match self {
            Self::Response(Rpc::AddObjectResponse(r)) => {
                Some(format!("{table}{}.", r.instance_number))
            }
            Self::Applied(a) => {
                let path = a.result["instantiated_paths"].get(0)?.as_str()?;
                let path = format!("{}.", path.trim_end_matches('.'));
                (path.len() > table.len() && path.starts_with(table)).then_some(path)
            }
            _ => None,
        }
    }
}

/// Whether `m` needs a run. Yes if any of:
/// zero-touch trigger (incl. every boot of the device);
/// never run, or desired state != last run's (`psk`: its pre-shared key as
/// [`WgRunner::psk_of`] opened it; cannot be opened -> left to the state);
/// key rotation asked + member pending or applied (blocked, failed, unsupported -> wait below);
/// applied config last checked more than [`DRIFT_CHECK`] ago;
/// blocked, failed or unsupported, last tried more than [`RETRY_AFTER`] ago.
fn needs_run(
    m: &WgDeviceMembership,
    psk: Result<Option<Zeroizing<String>>, ()>,
    zero_touch: bool,
    now: OffsetDateTime,
) -> bool {
    let older_than = |age: Duration| m.device_checked_at.is_none_or(|at| now - at > age);
    let changed = psk.is_ok_and(|psk| {
        m.device_applied_hash.as_deref()
            != Some(desired_hash(&desired_of(m, psk, false, false)).as_str())
    });
    zero_touch
        || m.device_state == "pending"
        || (m.rotate_requested_at.is_some() && m.device_state == "applied")
        || changed
        || match m.device_state.as_str() {
            "applied" => older_than(DRIFT_CHECK),
            _ => older_than(RETRY_AFTER),
        }
}

/// Planner view of a membership, with `preshared_key` (opened), not sent (caller decides).
/// `fresh_tunnel`: this run added the network's Tunnel row + key mode server -> row has no
/// key, whatever the member's key.
/// `rotated`: this run already issued the network's key rotation step (`rotate_key` wanted
/// only while the member's request is open and it was not).
fn desired_of(
    m: &WgDeviceMembership,
    preshared_key: Option<Zeroizing<String>>,
    fresh_tunnel: bool,
    rotated: bool,
) -> DesiredTunnel {
    let key_mode = if m.key_mode == "server" {
        KeyMode::Server
    } else {
        KeyMode::Device
    };
    let mut allowed_ips = vec![m.prefix];
    allowed_ips.extend(m.other_site_prefixes.iter().copied());
    DesiredTunnel {
        network_id: m.network_id,
        hub_public_key: m.hub_public_key.clone(),
        endpoint_host: m.hub_endpoint_host.clone(),
        endpoint_port: m.listen_port,
        persistent_keepalive: m.persistent_keepalive,
        allowed_ips,
        address: m.address,
        prefix: m.prefix,
        mtu: m.mtu,
        key_mode,
        member_public_key: if fresh_tunnel && key_mode == KeyMode::Server {
            None
        } else {
            m.public_key.clone()
        },
        rotate_key: m.rotate_requested_at.is_some() && !rotated,
        preshared_key,
        send_preshared_key: false,
    }
}

/// Snapshot as the planner reads it.
fn tree_of(params: impl IntoIterator<Item = StoredParam>) -> Tree {
    params
        .into_iter()
        .map(|p| {
            (
                p.path,
                Param {
                    value: p.value.unwrap_or_default(),
                    writable: p.writable,
                    xsd_type: p.xsd_type,
                },
            )
        })
        .collect()
}

/// Step for logs and state details: paths, never values.
fn describe(step: &Step) -> String {
    match step {
        Step::Read { paths } => format!("read {}", paths.join(", ")),
        Step::Add { table, .. } => format!("add a row to {table}"),
        Step::Set { values, .. } => format!(
            "set {}",
            values
                .iter()
                .map(|v| v.path.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Step::SetPrivateKey { tunnel, .. } => format!("set the private key of {tunnel}"),
        Step::RegenerateKey { tunnel, .. } => format!("make {tunnel} make a new key"),
        Step::Delete { object } => format!("delete {object}"),
        Step::WaitForFirmware { table, .. } => {
            format!("wait for the device to make a row in {table}")
        }
        Step::Done { .. } => "done".to_owned(),
    }
}

/// 8 random lowercase hex digits.
fn nonce() -> Option<String> {
    use ring::rand::SecureRandom as _;
    let mut raw = [0u8; 4];
    ring::rand::SystemRandom::new().fill(&mut raw).ok()?;
    Some(crate::files::hex(&raw))
}

/// Whether a SetParameterValues task carries a secret value.
fn carries_secret(kind: &TaskKind) -> bool {
    matches!(kind, TaskKind::SetParameterValues { values } if values.iter().any(|v| v.secret))
}

/// Run occurrence time for drivers without the device's time: now, RFC 3339.
pub(crate) fn now_text() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

impl CwmpBackend {
    /// End of an Inform -> start a run on the device if needed. `at` = Inform's CurrentTime.
    /// Failures logged; the Inform goes on without the run.
    pub(crate) async fn wg_inform(&self, device: &UpsertOutcome, zero_touch: bool, at: &str) {
        self.wg
            .start(device.id, &device.status, zero_touch, at)
            .await;
    }

    /// Task of a run ended -> its run goes on.
    pub(crate) async fn wg_completed(
        &self,
        device: Uuid,
        task: &RunningTask,
        answer: WgAnswer<'_>,
    ) {
        self.wg
            .completed(self, device, task.id, &task.kind, answer)
            .await;
    }

    /// Device session ended (see [`WgRunner::session_ended`]).
    /// Run waits for firmware -> device woken after the rewake delay
    /// ([`CwmpBackend::with_wg_rewake`]); else it goes on at its next periodic Inform.
    pub(crate) async fn wg_session_ended(
        &self,
        device: Uuid,
        task: Option<&RunningTask>,
        aborted: bool,
    ) {
        let rewake = self
            .wg
            .session_ended(device, task.map(|t| t.id), aborted)
            .await;
        if !rewake {
            return;
        }
        match self.wg_rewake.clone() {
            Some((waker, delay)) => {
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let outcome = waker.wake(device).await;
                    info!(%device, outcome = %outcome.describe(), "WireGuard: waking the device to finish its tunnel");
                });
            }
            None => {
                debug!(%device, "WireGuard: the device goes on with its tunnel at its next periodic Inform");
            }
        }
    }
}

impl WgHost for CwmpBackend {
    async fn wg_store_read(
        &self,
        device: Uuid,
        params: Vec<ParamUpdate>,
    ) -> Result<(), StoreError> {
        let params = self.admit_reported(device, params);
        self.store_admitted(device, &params).await?;
        Ok(())
    }
}

impl WgRunner {
    /// Runner of one protocol driver. `secrets` seals server-made private keys.
    /// `incomplete_retry`: see [`INCOMPLETE_RETRY`]; `ip_wait`: see [`IpWait`].
    pub(crate) fn new(
        store: Store,
        tenant_id: Uuid,
        secrets: Option<Arc<SecretBox>>,
        protocol: WgProtocol,
        incomplete_retry: Duration,
        ip_wait: IpWait,
    ) -> Self {
        Self {
            store,
            tenant_id,
            secrets,
            protocol,
            runs: Mutex::default(),
            gates: Mutex::default(),
            stale_failed: Mutex::default(),
            incomplete: Mutex::default(),
            incomplete_retry,
            ip_wait,
            ip_waits: Mutex::default(),
            rewake: Mutex::default(),
        }
    }

    /// Periodic sweep (USP): does any membership of the device need a run now?
    /// Same as [`needs_run`] without a zero-touch trigger.
    pub(crate) fn sweep_due(
        &self,
        memberships: &[WgDeviceMembership],
        now: OffsetDateTime,
    ) -> bool {
        memberships
            .iter()
            .any(|m| needs_run(m, self.psk_of(m), false, now))
    }

    /// Member's pre-shared key as text, opened with the secrets key.
    /// `Ok(None)`: none. `Err`: cannot be opened (no `--secrets-key`, other key, damaged row).
    fn psk_of(&self, m: &WgDeviceMembership) -> Result<Option<Zeroizing<String>>, ()> {
        let Some((ciphertext, nonce)) = &m.psk else {
            return Ok(None);
        };
        let secrets = self.secrets.as_deref().ok_or(())?;
        let plain = secrets
            .open_wg_psk(m.member_id, ciphertext, nonce)
            .map_err(drop)?;
        let bytes: &[u8; KEY_LEN] = plain.as_slice().try_into().map_err(drop)?;
        Ok(Some(key_text(bytes)))
    }

    /// Key rotation of `m`: has a pre-shared key -> new one made, sealed, stored (hub takes it;
    /// run sends it with the values).
    /// Returns whether the rotation may go on: false if the new key could not be stored.
    async fn wg_new_psk(&self, device: Uuid, m: &WgDeviceMembership) -> bool {
        if m.psk.is_none() {
            return true;
        }
        let Some(secrets) = self.secrets.as_deref() else {
            return false;
        };
        let Ok(psk) = generate_preshared_key() else {
            warn!(%device, "WireGuard: no randomness for a pre-shared key");
            return false;
        };
        let Ok((ciphertext, nonce)) = secrets.seal_wg_psk(m.member_id, &psk[..]) else {
            warn!(%device, member = %m.member_id, "WireGuard: sealing a pre-shared key failed");
            return false;
        };
        match self
            .store
            .replace_wg_member_psk(m.member_id, &ciphertext, &nonce)
            .await
        {
            Ok(_) => true,
            Err(e) => {
                warn!(%device, member = %m.member_id, error = %e, "WireGuard: storing a new pre-shared key failed; the rotation waits");
                false
            }
        }
    }

    /// Wait for the device's gate.
    async fn gate(&self, device: Uuid) -> Gate<'_> {
        let gate = self
            .gates
            .lock()
            .ok()
            .map(|mut gates| gates.entry(device).or_default().clone());
        let guard = match gate {
            Some(g) => Some(g.lock_owned().await),
            None => None,
        };
        Gate {
            runner: self,
            device,
            guard,
        }
    }

    fn running(&self, device: Uuid) -> bool {
        self.runs
            .lock()
            .is_ok_and(|runs| runs.contains_key(&device))
    }

    /// Start a run on the device if needed; replaces one in progress (its queued tasks
    /// cancelled). USP: a run of the same kind still waiting for its 1st read is kept instead
    /// (reads the device as it is now).
    /// `status` = device's. `at` names the occurrence (Inform's CurrentTime, time of USP
    /// connect or boot).
    /// Failures logged. Returns whether a run is now in progress.
    pub(crate) async fn start(
        &self,
        device: Uuid,
        status: &str,
        zero_touch: bool,
        at: &str,
    ) -> bool {
        // Tasks of non-active devices do not run -> a run would only fill the queue.
        if status != "active" {
            return false;
        }
        let _gate = self.gate(device).await;
        let needed = async {
            let memberships = self
                .store
                .wg_device_memberships(self.tenant_id, device)
                .await?;
            if memberships.is_empty() {
                // Our rows for networks the device left, unless its other record
                // (CWMP or USP) manages them.
                let kept = self.store.wg_twin_networks(self.tenant_id, device).await?;
                let stale = self
                    .store
                    .get_params(device, WG_ROOT)
                    .await?
                    .iter()
                    .any(|p| {
                        p.path.ends_with(".Alias")
                            && p.value
                                .as_deref()
                                .and_then(network_of_alias)
                                .is_some_and(|n| !kept.contains(&n))
                    });
                return Ok::<_, StoreError>((stale, true));
            }
            let now = OffsetDateTime::now_utc();
            Ok((
                memberships
                    .iter()
                    .any(|m| needs_run(m, self.psk_of(m), zero_touch, now)),
                false,
            ))
        }
        .await;
        let stale_only = match needed {
            Ok((true, stale_only)) => stale_only,
            Ok((false, _)) => return false,
            Err(e) => {
                warn!(%device, error = %e, "WireGuard: reading the memberships failed");
                return false;
            }
        };
        self.begin(device, at, true, stale_only).await
    }

    /// Start a run the periodic sweep found due (see [`sweep_due`]; `stale_only`: device has
    /// no live membership, only rows of ours).
    /// Not if: one in progress; last one ended without outcome within the incomplete retry;
    /// `stale_only` + a like run failed within [`RETRY_AFTER`].
    /// Returns whether a run is now in progress.
    pub(crate) async fn start_due(&self, device: Uuid, stale_only: bool, at: &str) -> bool {
        let _gate = self.gate(device).await;
        if self.running(device) {
            return false;
        }
        let now = OffsetDateTime::now_utc();
        let waiting = self
            .incomplete
            .lock()
            .ok()
            .and_then(|i| i.get(&device).copied())
            .is_some_and(|until| now < until);
        if waiting {
            return false;
        }
        if stale_only {
            let backing_off = self
                .stale_failed
                .lock()
                .ok()
                .and_then(|f| f.get(&device).copied())
                .is_some_and(|at| now - at < RETRY_AFTER);
            if backing_off {
                return false;
            }
        }
        self.begin(device, at, false, stale_only).await
    }

    /// Make a run + take its 1st step. `replace` -> run in progress ends first (USP: unless
    /// same kind + nothing read yet -> it goes on); else it stays and none starts.
    /// Called with the device's gate held.
    async fn begin(&self, device: Uuid, at: &str, replace: bool, stale_only: bool) -> bool {
        // CWMP run tied to its session; its task may be stuck in an aborted one.
        if replace && self.protocol == WgProtocol::Usp {
            let fresh = self.runs.lock().is_ok_and(|runs| {
                runs.get(&device)
                    .is_some_and(|run| run.stale_only == stale_only && run.has_read_nothing())
            });
            if fresh {
                debug!(%device, "WireGuard: a run that has read nothing yet goes on");
                return true;
            }
        }
        let Some(nonce) = nonce() else {
            warn!(%device, "WireGuard: no randomness for the run");
            return false;
        };
        let run = WgRun {
            occurrence: format!("{at}~{nonce}"),
            read: BTreeSet::new(),
            steps: 0,
            issued: HashSet::new(),
            fresh_tunnels: BTreeSet::new(),
            fresh_peers: BTreeSet::new(),
            psk_sent: BTreeSet::new(),
            psk_failed: BTreeSet::new(),
            rotated: BTreeSet::new(),
            old_keys: BTreeMap::new(),
            pending: HashMap::new(),
            stale_only,
            converged: false,
            recorded: false,
        };
        if replace {
            debug!(%device, "WireGuard: starting a run");
            // Run left from an earlier session (or connection) ends here.
            let earlier = self.runs.lock().ok().and_then(|mut m| m.remove(&device));
            if let Some(earlier) = earlier {
                self.wg_end(device, earlier).await;
            }
        } else if self.running(device) {
            return false;
        } else {
            debug!(%device, "WireGuard: starting a run");
        }
        self.wg_advance(device, run).await
    }

    /// Task of a run ended -> its run goes on.
    pub(crate) async fn completed(
        &self,
        host: &impl WgHost,
        device: Uuid,
        task_id: Uuid,
        kind: &TaskKind,
        answer: WgAnswer<'_>,
    ) {
        let _gate = self.gate(device).await;
        let taken = self.runs.lock().ok().and_then(|mut runs| {
            let run = runs.get_mut(&device)?;
            let pending = run.pending.remove(&task_id)?;
            Some((runs.remove(&device)?, pending))
        });
        let Some((mut run, pending)) = taken else {
            // Not a task of a run in progress -> its secret still goes.
            if carries_secret(kind)
                && let Ok(Some(t)) = self.store.get_task(task_id).await
                && t.created_by.as_deref() == Some(WG_TASK_ORIGIN)
            {
                self.wg_redact(task_id).await;
            }
            return;
        };
        if matches!(
            pending,
            Pending::Key { .. } | Pending::Set { secret: true, .. }
        ) {
            self.wg_redact(task_id).await;
        }
        let result = match answer {
            WgAnswer::Response(_) | WgAnswer::Applied(_) => {
                self.wg_answered(host, device, &mut run, pending, &answer)
                    .await
            }
            WgAnswer::Fault(_) | WgAnswer::Refused(_) => {
                self.wg_refused(device, &pending, &answer).await;
                run.recorded = true;
                Ok(Next::End)
            }
            WgAnswer::Lost => {
                debug!(%device, task = %task_id, "WireGuard: the device did not answer; ending the run");
                if let Pending::Key { member_id, .. } = pending {
                    self.wg_forget_key(member_id).await;
                }
                Ok(Next::End)
            }
        };
        match result {
            Ok(Next::Plan) => {
                self.wg_advance(device, run).await;
            }
            Ok(Next::Wait) => {
                self.wg_keep(device, run).await;
            }
            Ok(Next::End) => self.wg_end(device, run).await,
            Err(e) => {
                warn!(%device, error = %e, "WireGuard: the run failed");
                self.wg_end(device, run).await;
            }
        }
    }

    /// CWMP session of the device ended -> its run ends too, if the session ended normally or
    /// a run task was out (a later Inform starts a new one).
    /// Aborted session with no run task out = older session replaced by the device's new one,
    /// after the new one's Inform started its run.
    ///
    /// Returns whether to wake the device: a run of the session waited for firmware
    /// (device forgotten for that either way).
    pub(crate) async fn session_ended(
        &self,
        device: Uuid,
        task: Option<Uuid>,
        aborted: bool,
    ) -> bool {
        let rewake = self
            .rewake
            .lock()
            .is_ok_and(|mut rewake| rewake.remove(&device));
        let _gate = self.gate(device).await;
        let run = self.runs.lock().ok().and_then(|mut runs| {
            let ours = runs
                .get(&device)
                .is_some_and(|run| !aborted || task.is_some_and(|t| run.pending.contains_key(&t)));
            if ours { runs.remove(&device) } else { None }
        });
        if let Some(run) = run {
            self.wg_end(device, run).await;
        }
        rewake
    }

    /// Next action after a device answer to a run task.
    async fn wg_answered(
        &self,
        host: &impl WgHost,
        device: Uuid,
        run: &mut WgRun,
        pending: Pending,
        answer: &WgAnswer<'_>,
    ) -> Result<Next, StoreError> {
        match pending {
            Pending::Read { paths } => {
                self.wg_replace(host, device, &paths, answer.values())
                    .await?;
                run.read.extend(paths);
                Ok(Next::Plan)
            }
            Pending::AddRead { paths, .. }
            | Pending::KeyRead { paths, .. }
            | Pending::WaitRead { paths, .. } => {
                self.wg_replace(host, device, &paths, answer.values())
                    .await?;
                Ok(Next::Plan)
            }
            Pending::Add {
                table,
                alias,
                network_id,
                then_read,
            } => {
                let Some(instance) = answer.instance(&table) else {
                    return Ok(Next::End);
                };
                if table == TUNNEL_TABLE {
                    run.fresh_tunnels.insert(network_id);
                }
                if table == PEER_TABLE {
                    run.fresh_peers.insert(network_id);
                }
                let step = run.steps;
                let alias_task = TaskKind::SetParameterValues {
                    values: vec![SetValue {
                        name: format!("{instance}Alias"),
                        value: alias,
                        xsd_type: Some("string".into()),
                        secret: false,
                    }],
                };
                let mut paths = vec![instance];
                paths.extend(then_read);
                let read_task = TaskKind::GetParameterValues {
                    names: paths.clone(),
                };
                let mut tasks = Vec::new();
                // USP sent the Alias with the Add.
                if self.protocol == WgProtocol::Cwmp {
                    tasks.push(("alias", alias_task, Pending::AddAlias { network_id }));
                }
                tasks.push(("read", read_task, Pending::AddRead { paths, network_id }));
                for (suffix, kind, what) in tasks {
                    match self
                        .wg_enqueue(device, run, &format!("{step}:{suffix}"), kind, None, None)
                        .await?
                    {
                        Some(id) => {
                            run.pending.insert(id, what);
                        }
                        None => return Ok(Next::End),
                    }
                }
                Ok(Next::Wait)
            }
            // Next read does the planning.
            Pending::AddAlias { .. } | Pending::Key { .. } | Pending::Regenerate { .. } => {
                Ok(Next::Wait)
            }
            Pending::Set {
                network_id,
                preshared_key,
                ..
            } => {
                if preshared_key {
                    run.psk_sent.insert(network_id);
                }
                Ok(Next::Plan)
            }
            Pending::Delete { object } => {
                self.store.delete_params_under(device, &object).await?;
                Ok(Next::Plan)
            }
        }
    }

    /// Record the meaning of a refusal (CPE fault, Agent error) of a run task.
    async fn wg_refused(&self, device: Uuid, pending: &Pending, answer: &WgAnswer<'_>) {
        if let Pending::Key { member_id, .. } = pending {
            self.wg_forget_key(*member_id).await;
        }
        let memberships = match self
            .store
            .wg_device_memberships(self.tenant_id, device)
            .await
        {
            Ok(m) => m,
            Err(e) => {
                warn!(%device, error = %e, "WireGuard: reading the memberships failed");
                return;
            }
        };
        let reads_root =
            matches!(pending, Pending::Read { paths } if paths.iter().any(|p| p == WG_ROOT));
        // CWMP: 9005 Invalid parameter name; USP: any refusal of that read.
        let (unsupported, detail) = match answer {
            WgAnswer::Fault(f) => (
                f.code == 9005 && reads_root,
                format!("{} {}", f.code, f.string),
            ),
            WgAnswer::Refused(text) => (reads_root, (*text).to_owned()),
            _ => return,
        };
        let network = pending.network();
        for m in memberships
            .iter()
            .filter(|m| network.is_none_or(|n| n == m.network_id))
        {
            // Key cannot be opened -> stored hash stays.
            let hash = self
                .psk_of(m)
                .ok()
                .map(|psk| desired_hash(&desired_of(m, psk, false, false)));
            let (state, detail) = if unsupported {
                (
                    "unsupported",
                    "the device has no Device.WireGuard.".to_owned(),
                )
            } else {
                ("error", detail.clone())
            };
            self.wg_state(m.member_id, state, Some(&detail), hash.as_deref())
                .await;
        }
        if unsupported {
            info!(%device, "WireGuard: the device has no Device.WireGuard.");
        } else {
            warn!(%device, error = %detail, "WireGuard: the device refused a request; ending the run");
        }
    }

    /// Replace the snapshot under each of `paths` with the read result.
    /// `None`: answer was not a read's -> no change.
    async fn wg_replace(
        &self,
        host: &impl WgHost,
        device: Uuid,
        paths: &[String],
        reported: Option<Vec<ParamUpdate>>,
    ) -> Result<(), StoreError> {
        let Some(reported) = reported else {
            return Ok(());
        };
        // Read reports no writability (maybe no type) -> keep known values of a path still
        // there -> read-only flags from GetParameterNames (or supported data model) survive.
        let mut known: HashMap<String, (Option<bool>, Option<String>)> = HashMap::new();
        for path in paths {
            for p in self.store.get_params(device, path).await? {
                known.insert(p.path, (p.writable, p.xsd_type));
            }
            self.store.delete_params_under(device, path).await?;
        }
        let under: Vec<_> = reported
            .into_iter()
            .filter(|p| paths.iter().any(|path| p.path.starts_with(path.as_str())))
            .map(|mut p| {
                if let Some((writable, xsd_type)) = known.get(&p.path) {
                    p.writable = p.writable.or(*writable);
                    if p.xsd_type.is_none() {
                        p.xsd_type.clone_from(xsd_type);
                    }
                }
                p
            })
            .collect();
        host.wg_store_read(device, under).await
    }

    /// Plan the run's next step + take it. Returns whether the run goes on (task queued).
    async fn wg_advance(&self, device: Uuid, mut run: WgRun) -> bool {
        match self.wg_step(device, &mut run).await {
            Ok(Next::Wait) => self.wg_keep(device, run).await,
            Ok(_) => {
                self.wg_end(device, run).await;
                false
            }
            Err(e) => {
                warn!(%device, error = %e, "WireGuard: the run failed");
                self.wg_end(device, run).await;
                false
            }
        }
    }

    /// One run step: [`Next::Wait`] if a task was queued, else run over.
    async fn wg_step(&self, device: Uuid, run: &mut WgRun) -> Result<Next, StoreError> {
        let memberships = self
            .store
            .wg_device_memberships(self.tenant_id, device)
            .await?;
        let mut desired: Vec<DesiredTunnel> = Vec::with_capacity(memberships.len());
        // Networks of members whose pre-shared key cannot be opened -> out of the plan, rows
        // kept as they are.
        let mut unopened = BTreeSet::new();
        for m in &memberships {
            let Ok(psk) = self.psk_of(m) else {
                unopened.insert(m.network_id);
                if run.psk_failed.insert(m.member_id) {
                    warn!(%device, member = %m.member_id, "WireGuard: {PSK_UNOPENED}");
                    self.wg_state(m.member_id, "error", Some(PSK_UNOPENED), None)
                        .await;
                    run.recorded = true;
                }
                continue;
            };
            let mut d = desired_of(
                m,
                psk,
                run.fresh_tunnels.contains(&m.network_id),
                run.rotated.contains(&m.network_id),
            );
            let hash = desired_hash(&d);
            d.send_preshared_key = !run.psk_sent.contains(&m.network_id)
                && (run.fresh_peers.contains(&m.network_id)
                    || m.device_state != "applied"
                    || m.device_applied_hash.as_deref() != Some(hash.as_str()));
            desired.push(d);
        }
        let mut params = self.store.get_params(device, WG_ROOT).await?;
        params.extend(self.store.get_params(device, IP_TABLE).await?);
        let tree = tree_of(params);
        let limit = match self.protocol {
            WgProtocol::Cwmp => self.ip_wait.cwmp_sessions,
            WgProtocol::Usp => self.ip_wait.usp_polls,
        };
        let ip_wait_over: BTreeSet<Uuid> = self
            .ip_waits
            .lock()
            .map(|mut waits| {
                // Members no longer live (revoked, deleted, moved away) -> waits forgotten.
                waits.retain(|(d, member), _| {
                    *d != device || memberships.iter().any(|m| m.member_id == *member)
                });
                memberships
                    .iter()
                    .filter(|m| {
                        waits
                            .get(&(device, m.member_id))
                            .is_some_and(|c| *c >= limit)
                    })
                    .map(|m| m.network_id)
                    .collect()
            })
            .unwrap_or_default();
        // Networks whose rows the device's other record (CWMP or USP) manages + those left
        // out above.
        let mut kept = self.store.wg_twin_networks(self.tenant_id, device).await?;
        kept.extend(unopened);
        let step = plan(&PlanInput {
            desired: &desired,
            tree: &tree,
            read: &run.read,
            ip_wait_over: &ip_wait_over,
            kept: &kept,
        });
        let member_of = |network: Uuid| memberships.iter().find(|m| m.network_id == network);
        let hash_of = |network: Uuid| {
            desired
                .iter()
                .find(|d| d.network_id == network)
                .map(desired_hash)
        };
        if let Step::Done { outcomes } = &step {
            for o in outcomes {
                self.wg_outcome(device, o, &memberships, &desired, run)
                    .await?;
            }
            debug!(%device, "WireGuard: run done");
            run.converged = true;
            return Ok(Next::End);
        }

        // Wait repeats the same step on purpose; wait limit bounds it.
        if let Step::WaitForFirmware { table, network_id } = &step {
            return self
                .wg_wait(device, run, table, *network_id, &memberships, hash_of)
                .await;
        }

        // No progress: same step again, or too many.
        let fingerprint = format!("{step:?}");
        if run.steps >= MAX_STEPS || !run.issued.insert(fingerprint) {
            let what = describe(&step);
            warn!(%device, step = %what, "WireGuard: no progress; ending the run");
            let network = match &step {
                Step::Add { network_id, .. }
                | Step::Set { network_id, .. }
                | Step::SetPrivateKey { network_id, .. }
                | Step::RegenerateKey { network_id, .. } => Some(*network_id),
                _ => None,
            };
            let detail = format!("no progress: {what}");
            for m in memberships
                .iter()
                .filter(|m| network.is_none_or(|n| n == m.network_id))
            {
                let hash = hash_of(m.network_id);
                self.wg_state(m.member_id, "error", Some(&detail), hash.as_deref())
                    .await;
            }
            run.recorded = true;
            return Ok(Next::End);
        }
        run.steps += 1;
        let key = run.steps.to_string();
        let rotating = |network: Uuid| {
            desired
                .iter()
                .any(|d| d.network_id == network && d.rotate_key)
        };

        // `reread`: tunnel read after the task, with the network. `secret`: seal the task with
        // this key; also the member for a server-made private key.
        let mut reread: Option<(String, Uuid)> = None;
        let (kind, what, secret): (_, _, Option<(Arc<SecretBox>, Option<Uuid>)>) = match step {
            Step::Read { paths } => (
                TaskKind::GetParameterValues {
                    names: paths.clone(),
                },
                Pending::Read { paths },
                None,
            ),
            Step::Add {
                table,
                alias,
                network_id,
                then_read,
            } => (
                TaskKind::AddObject {
                    object: table.clone(),
                    params: match self.protocol {
                        WgProtocol::Cwmp => vec![],
                        // USP row Alias = writeOnceReadOnly -> comes with the Add.
                        WgProtocol::Usp => vec![SetValue {
                            name: "Alias".into(),
                            value: alias.clone(),
                            xsd_type: Some("string".into()),
                            secret: false,
                        }],
                    },
                },
                Pending::Add {
                    table,
                    alias,
                    network_id,
                    then_read,
                },
                None,
            ),
            Step::Set { values, network_id } => {
                let has_secret = values.iter().any(|v| v.secret);
                let preshared_key = values.iter().any(|v| v.path.ends_with(".PresharedKey"));
                let sealer = match (has_secret, self.secrets.clone()) {
                    (false, _) => None,
                    (true, Some(s)) => Some((s, None)),
                    // Secret opened only with the key -> cannot happen. Never queued in
                    // clear text.
                    (true, None) => return Ok(Next::End),
                };
                (
                    TaskKind::SetParameterValues {
                        values: values
                            .into_iter()
                            .map(|v| SetValue {
                                name: v.path,
                                value: v.value,
                                xsd_type: Some(v.xsd_type),
                                secret: v.secret,
                            })
                            .collect(),
                    },
                    Pending::Set {
                        network_id,
                        secret: has_secret,
                        preshared_key,
                    },
                    sealer,
                )
            }
            Step::Delete { object } => (
                TaskKind::DeleteObject {
                    object: object.clone(),
                },
                Pending::Delete { object },
                None,
            ),
            Step::SetPrivateKey { tunnel, network_id } => {
                let Some(m) = member_of(network_id) else {
                    return Ok(Next::End);
                };
                let hash = hash_of(network_id);
                let Some(secrets) = self.secrets.clone() else {
                    self.wg_state(
                        m.member_id,
                        "blocked",
                        Some("server key mode needs --secrets-key"),
                        hash.as_deref(),
                    )
                    .await;
                    run.recorded = true;
                    return Ok(Next::End);
                };
                let Ok(pair) = generate_keypair() else {
                    warn!(%device, "WireGuard: no randomness for a key pair");
                    return Ok(Next::End);
                };
                if rotating(network_id) && !self.wg_new_psk(device, m).await {
                    return Ok(Next::End);
                }
                match self
                    .store
                    .set_wg_device_member_key(m.member_id, &pair.public)
                    .await?
                {
                    Ok(()) => {}
                    Err(WgRefusal::KeyInUse) => {
                        self.wg_state(m.member_id, "error", Some("key collision"), hash.as_deref())
                            .await;
                        run.recorded = true;
                        return Ok(Next::End);
                    }
                    Err(_) => return Ok(Next::End),
                }
                run.fresh_tunnels.remove(&network_id);
                if rotating(network_id) {
                    run.rotated.insert(network_id);
                    run.psk_sent.remove(&network_id);
                }
                reread = Some((tunnel.clone(), network_id));
                (
                    TaskKind::SetParameterValues {
                        values: vec![SetValue {
                            name: format!("{tunnel}PrivateKey"),
                            value: pair.private.to_string(),
                            xsd_type: Some("string".into()),
                            secret: true,
                        }],
                    },
                    Pending::Key {
                        network_id,
                        member_id: m.member_id,
                    },
                    Some((secrets, Some(m.member_id))),
                )
            }
            Step::RegenerateKey { tunnel, network_id } => {
                if let Some(m) = member_of(network_id)
                    && !self.wg_new_psk(device, m).await
                {
                    return Ok(Next::End);
                }
                run.rotated.insert(network_id);
                run.psk_sent.remove(&network_id);
                run.old_keys.insert(
                    network_id,
                    member_of(network_id).and_then(|m| m.public_key.clone()),
                );
                reread = Some((tunnel.clone(), network_id));
                (
                    TaskKind::SetParameterValues {
                        values: vec![SetValue {
                            name: format!("{tunnel}PrivateKey"),
                            value: String::new(),
                            xsd_type: Some("string".into()),
                            secret: false,
                        }],
                    },
                    Pending::Regenerate { network_id },
                    None,
                )
            }
            Step::Done { .. } | Step::WaitForFirmware { .. } => return Ok(Next::End),
        };
        let sealed = secret.as_ref().map(|(s, _)| s.as_ref());
        match self.wg_enqueue(device, run, &key, kind, sealed, None).await {
            Ok(Some(id)) => {
                run.pending.insert(id, what);
                if let Some((tunnel, network_id)) = reread {
                    let paths = vec![tunnel];
                    let read = TaskKind::GetParameterValues {
                        names: paths.clone(),
                    };
                    // Not queued -> run ends; its end cancels the 1st task (+ forgets a key
                    // on its way).
                    let Some(id) = self
                        .wg_enqueue(device, run, &format!("{key}:read"), read, None, None)
                        .await?
                    else {
                        return Ok(Next::End);
                    };
                    run.pending
                        .insert(id, Pending::KeyRead { paths, network_id });
                }
                Ok(Next::Wait)
            }
            other => {
                // Key not sent -> member must not keep it.
                if let Some((_, Some(member))) = secret {
                    self.wg_forget_key(member).await;
                }
                other.map(|_| Next::End)
            }
        }
    }

    /// `Step::WaitForFirmware` for `network`: count the wait.
    /// USP: queue the read of `table` after [`IpWait::usp_poll_every`].
    /// CWMP: record member pending + end the run; device woken after its session (session end
    /// commits).
    async fn wg_wait(
        &self,
        device: Uuid,
        run: &mut WgRun,
        table: &str,
        network: Uuid,
        memberships: &[WgDeviceMembership],
        hash_of: impl Fn(Uuid) -> Option<String>,
    ) -> Result<Next, StoreError> {
        // Desired tunnels come from the memberships -> always found.
        let Some(member_id) = memberships
            .iter()
            .find(|m| m.network_id == network)
            .map(|m| m.member_id)
        else {
            return Ok(Next::End);
        };
        let count = self
            .ip_waits
            .lock()
            .map(|mut waits| {
                let c = waits.entry((device, member_id)).or_default();
                *c = c.saturating_add(1);
                *c
            })
            .unwrap_or(u32::MAX);
        debug!(%device, %network, member = %member_id, %table, wait = count, "WireGuard: waiting for the firmware to make a row");
        match self.protocol {
            WgProtocol::Usp => {
                let paths = vec![table.to_owned()];
                let read = TaskKind::GetParameterValues {
                    names: paths.clone(),
                };
                let due = OffsetDateTime::now_utc() + self.ip_wait.usp_poll_every;
                let key = format!("{}:wait:{count}", run.steps);
                match self
                    .wg_enqueue(device, run, &key, read, None, Some(due))
                    .await?
                {
                    Some(id) => {
                        run.pending.insert(
                            id,
                            Pending::WaitRead {
                                paths,
                                network_id: network,
                            },
                        );
                        Ok(Next::Wait)
                    }
                    None => Ok(Next::End),
                }
            }
            WgProtocol::Cwmp => {
                if let Some(m) = memberships.iter().find(|m| m.network_id == network) {
                    let hash = hash_of(network);
                    self.wg_state(
                        m.member_id,
                        "pending",
                        Some(IP_WAIT_DETAIL),
                        hash.as_deref(),
                    )
                    .await;
                }
                if let Ok(mut rewake) = self.rewake.lock() {
                    rewake.insert(device);
                }
                run.recorded = true;
                Ok(Next::End)
            }
        }
    }

    /// Record one planner outcome.
    /// Applied + key rotation step issued in this run: key changed -> member's request cleared
    /// (device key mode: key read from device != key before the step; server key mode:
    /// always); else member blocked, request kept.
    /// Applied -> member's IP interface waits on the device forgotten.
    async fn wg_outcome(
        &self,
        device: Uuid,
        o: &Outcome,
        memberships: &[WgDeviceMembership],
        desired: &[DesiredTunnel],
        run: &WgRun,
    ) -> Result<(), StoreError> {
        let member_of = |network: Uuid| memberships.iter().find(|m| m.network_id == network);
        let hash_of = |network: Uuid| {
            desired
                .iter()
                .find(|d| d.network_id == network)
                .map(desired_hash)
        };
        match o {
            Outcome::Applied {
                network_id,
                desired_hash,
                device_public_key,
            } => {
                let Some(m) = member_of(*network_id) else {
                    return Ok(());
                };
                if let Ok(mut waits) = self.ip_waits.lock() {
                    waits.remove(&(device, m.member_id));
                }
                let rotated = run.rotated.contains(network_id);
                if rotated && m.key_mode == "device" {
                    let new = device_public_key.as_ref().or(m.public_key.as_ref());
                    let old = run.old_keys.get(network_id).cloned().flatten();
                    if new == old.as_ref() {
                        self.wg_state(
                            m.member_id,
                            "blocked",
                            Some("the device did not make a new key"),
                            Some(desired_hash),
                        )
                        .await;
                        return Ok(());
                    }
                }
                if let Some(key) = device_public_key
                    && let Err(WgRefusal::KeyInUse) = self
                        .store
                        .set_wg_device_member_key(m.member_id, key)
                        .await?
                {
                    self.wg_state(
                        m.member_id,
                        "error",
                        Some("the device's key is used by another member"),
                        Some(desired_hash),
                    )
                    .await;
                    return Ok(());
                }
                self.wg_state(m.member_id, "applied", None, Some(desired_hash))
                    .await;
                if rotated && let Err(e) = self.store.clear_wg_key_rotation(m.member_id).await {
                    warn!(member = %m.member_id, error = %e, "WireGuard: clearing a key rotation failed");
                }
            }
            Outcome::Blocked { network_id, reason } => {
                if let Some(m) = member_of(*network_id) {
                    let hash = hash_of(*network_id);
                    self.wg_state(m.member_id, "blocked", Some(reason), hash.as_deref())
                        .await;
                }
            }
            Outcome::Unsupported { network_id } => {
                if let Some(m) = member_of(*network_id) {
                    let hash = hash_of(*network_id);
                    self.wg_state(
                        m.member_id,
                        "unsupported",
                        Some("the device has no Device.WireGuard."),
                        hash.as_deref(),
                    )
                    .await;
                }
            }
        }
        Ok(())
    }

    /// Queue one run task, key `wg:{device}:{occurrence}:{key}`.
    /// `secrets` -> secret values sealed + bound to the task. `not_before` -> not sent before.
    /// `None`: not queued (task with that key exists, or sealing failed) -> run ends.
    async fn wg_enqueue(
        &self,
        device: Uuid,
        run: &WgRun,
        key: &str,
        kind: TaskKind,
        secrets: Option<&SecretBox>,
        not_before: Option<OffsetDateTime>,
    ) -> Result<Option<Uuid>, StoreError> {
        let (k, mut payload) = kind.to_row();
        let task_id = Uuid::now_v7();
        if let Some(secrets) = secrets
            && secrets
                .encrypt_fields(&mut payload, &crate::secrets::task_context(task_id))
                .is_err()
        {
            warn!(%device, "WireGuard: encrypting the private key failed; ending the run");
            return Ok(None);
        }
        let task = NewTask {
            priority: WG_PRIORITY,
            // Retry would repeat a step the run has passed (AddObject -> 2nd row) -> next run
            // plans anew instead.
            max_attempts: 1,
            idempotency_key: Some(format!("wg:{device}:{}:{key}", run.occurrence)),
            created_by: Some(WG_TASK_ORIGIN.into()),
            not_before,
            ..NewTask::new(self.tenant_id, device, k, payload)
        };
        let (id, created) = self.store.enqueue_task_with_id(task_id, &task).await?;
        if !created {
            warn!(%device, "WireGuard: a task of this run exists already; ending the run");
            return Ok(None);
        }
        Ok(Some(id))
    }

    /// Put the run back, unless a newer one took its place meanwhile. Returns whether it was.
    async fn wg_keep(&self, device: Uuid, run: WgRun) -> bool {
        let left = match self.runs.lock() {
            Ok(mut runs) => match runs.entry(device) {
                std::collections::hash_map::Entry::Occupied(_) => Some(run),
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(run);
                    None
                }
            },
            Err(_) => Some(run),
        };
        match left {
            Some(run) => {
                self.wg_end(device, run).await;
                false
            }
            None => true,
        }
    }

    /// End a run: queued tasks cancelled. Server-made key still on its way -> forgotten
    /// (device may never get it) + its task redacted.
    /// Not converged on a device with only stale rows -> sweep holds off the device.
    /// Ended without outcome -> same, shorter.
    async fn wg_end(&self, device: Uuid, run: WgRun) {
        if let Ok(mut incomplete) = self.incomplete.lock() {
            if run.converged {
                incomplete.remove(&device);
            } else if !run.recorded {
                incomplete.insert(device, OffsetDateTime::now_utc() + self.incomplete_retry);
            }
        }
        if run.stale_only
            && let Ok(mut failed) = self.stale_failed.lock()
        {
            if run.converged {
                failed.remove(&device);
            } else {
                failed.insert(device, OffsetDateTime::now_utc());
            }
        }
        for (id, pending) in run.pending {
            if let Err(e) = self.store.cancel_task(id).await {
                warn!(task = %id, error = %e, "WireGuard: cancelling a task failed");
            }
            match pending {
                Pending::Key { member_id, .. } => {
                    self.wg_forget_key(member_id).await;
                    self.wg_redact(id).await;
                }
                Pending::Set { secret: true, .. } => self.wg_redact(id).await,
                _ => {}
            }
        }
    }

    /// Forget the member's server-made key: device did not take it.
    async fn wg_forget_key(&self, member_id: Uuid) {
        if let Err(e) = self.store.clear_wg_device_member_key(member_id).await {
            warn!(member = %member_id, error = %e, "WireGuard: forgetting a key failed");
        }
    }

    /// Replace secret values (private or pre-shared key) in a finished task by `********`.
    async fn wg_redact(&self, task_id: Uuid) {
        if let Err(e) = self.store.redact_task_secret_values(task_id).await {
            warn!(task = %task_id, error = %e, "WireGuard: redacting a task failed");
        }
    }

    /// Record a member's state; failure logged.
    async fn wg_state(
        &self,
        member_id: Uuid,
        state: &str,
        detail: Option<&str>,
        hash: Option<&str>,
    ) {
        if let Err(e) = self
            .store
            .set_wg_member_device_state(member_id, state, detail, hash)
            .await
        {
            warn!(member = %member_id, error = %e, "WireGuard: recording the device state failed");
        }
    }
}

/// Run action after a task ended.
enum Next {
    /// Plan the next step.
    Plan,
    /// Wait for another queued run task.
    Wait,
    /// Run over.
    End,
}
