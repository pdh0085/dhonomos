//! USP driver (Phase 3): USP Controller <-> registry + task queue.
//!
//! USP tasks run as soon as the Agent is connected (CO-02).
//! Triggers: connect + API wake after a queued task.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dhonomos_store::{DeviceInfo, NewTask, ParamUpdate, Store};
use dhonomos_usp_controller::{Controller, Handler, UspError};
use dhonomos_usp_mtp::{MqttConfig, MqttMtp, MultiMtp, WsMtp};
use dhonomos_usp_proto::UspVersion;
use dhonomos_usp_proto::msg::{self, notify::Notification, request::ReqType};
use serde_json::json;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::param_prune::{self, Mode, Reported};
use crate::param_store;
use crate::task::TaskKind;
use crate::usp_map;
use crate::wireguard::{WgAnswer, WgHost};

/// USP settings.
#[derive(Debug, Clone)]
pub struct UspConfig {
    /// MQTT broker + Controller topic, if Agents use MQTT.
    pub mqtt: Option<MqttConfig>,
    /// Agents may connect over WebSocket -> serve router of [`UspService::ws_mtp`].
    pub websocket: bool,
    /// Embedded STOMP broker, if Agents may use STOMP -> serve [`UspService::stomp_mtp`].
    pub stomp: Option<dhonomos_usp_mtp::StompConfig>,
    /// Embedded MQTT 5 broker, if Agents may connect to Dhonomos with MQTT
    /// -> serve [`UspService::mqtt_broker_mtp`].
    /// Independent of `mqtt` (client of an external broker); both can be on.
    pub mqtt_broker: Option<dhonomos_usp_mtp::MqttBrokerConfig>,
    /// Admission of new Agents, same as CWMP devices (CO-12).
    pub onboarding: crate::Onboarding,
    /// Controller EndpointID (ADR-020).
    pub endpoint_id: String,
    /// Wait per response.
    pub request_timeout: Duration,
    /// Wait for a whole-model response (Get of `Device.`, GetSupportedDM).
    /// Busy Agent (e.g. right after boot) -> up to ~1 min.
    /// Min `request_timeout`; shorter value -> `request_timeout`.
    pub full_read_timeout: Duration,
    /// Tenant of registered Agents.
    pub tenant_id: Uuid,
    /// Provisioning presets. USP Agents match `USP CONNECT` on connect, `1 BOOT` on Boot!.
    pub presets: crate::Shared<crate::presets::Presets>,
    /// Store for BulkData reports (`Device.BulkData.Profile.{i}.Push!` events).
    pub metrics: Option<crate::metrics::MetricsIngest>,
    /// Signed links to stored files for firmware downloads (FW-05).
    pub files: Option<crate::files::FileSigner>,
    /// Decrypt secrets in task payloads (CO-16).
    pub secrets: Option<Arc<crate::secrets::SecretBox>>,
    /// TLS to Agents with a WebSocket server (`wss://`, US-05).
    pub ws_client_tls: Option<Arc<rustls::ClientConfig>>,
    /// Controller adds own subscriptions (Boot!, OperationComplete, BulkData Push!) to each
    /// connecting Agent (US-10).
    /// Off -> these notifications only with subscriptions set some other way.
    pub auto_subscribe: bool,
    /// Check interval for connected Agents with WireGuard memberships (ADR-110 stage 4).
    /// Due a run (drift check, desired state change, retry) -> run.
    /// Agents stay connected for days -> no Inform to start runs.
    pub wg_sweep_interval: Duration,
    /// Sweep pause for an Agent after a WireGuard run without outcome
    /// (answer lost, add without its instance, run cancelled).
    /// Connect or boot -> run anyway.
    pub wg_incomplete_retry: Duration,
    /// WireGuard run: wait between reads while Agent firmware makes the new tunnel's
    /// IP interface. Max [`USP_DRAIN_HOLD`] (longer value -> that).
    pub wg_ip_poll_interval: Duration,
    /// Max such reads before the WireGuard run adds the IP interface itself.
    pub wg_ip_poll_limit: u32,
}

/// [`UspConfig::wg_sweep_interval`] unless configured otherwise.
pub const DEFAULT_WG_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// [`UspConfig::wg_incomplete_retry`] unless configured otherwise.
pub const DEFAULT_WG_INCOMPLETE_RETRY: Duration = Duration::from_secs(5 * 60);

/// [`UspConfig::wg_ip_poll_interval`] unless configured otherwise.
pub const DEFAULT_WG_IP_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// [`UspConfig::wg_ip_poll_limit`] unless configured otherwise.
pub const DEFAULT_WG_IP_POLL_LIMIT: u32 = 30;

/// Max drain wait for a device task due soon, instead of ending (see [`UspService::drain`]).
/// Task due later -> next drain.
const USP_DRAIN_HOLD: Duration = Duration::from_secs(5);

#[derive(Debug)]
enum UspEvent {
    Connected(String),
    Disconnected(String),
    /// Notify from the Agent: (EndpointID, Notify `msg_id`, Notify).
    Notify(String, String, msg::Notify),
}

struct Sink(mpsc::UnboundedSender<UspEvent>);

impl Handler for Sink {
    async fn agent_connected(&self, eid: &str, _version: UspVersion) {
        let _ = self.0.send(UspEvent::Connected(eid.to_owned()));
    }
    async fn agent_disconnected(&self, eid: &str) {
        let _ = self.0.send(UspEvent::Disconnected(eid.to_owned()));
    }
    async fn notify(&self, eid: &str, msg_id: &str, n: msg::Notify) {
        let _ = self
            .0
            .send(UspEvent::Notify(eid.to_owned(), msg_id.to_owned(), n));
    }
}

/// `d` in whole milliseconds, saturated.
fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

struct Inner {
    store: Store,
    tenant_id: Uuid,
    presets: crate::Shared<crate::presets::Presets>,
    metrics: Option<crate::metrics::MetricsIngest>,
    files: Option<crate::files::FileSigner>,
    secrets: Option<Arc<crate::secrets::SecretBox>>,
    ctrl: Controller<MultiMtp, Sink>,
    /// Wait of whole-model requests (see [`reads_whole_model`]), ms ([`UspService::set_timeouts`]).
    full_read_timeout_ms: AtomicU64,
    onboarding: crate::Onboarding,
    /// [`UspService::set_auto_subscribe`].
    auto_subscribe: AtomicBool,
    draining: Mutex<HashSet<Uuid>>,
    again: Mutex<HashSet<Uuid>>,
    /// One GetSupportedDM per firmware at a time.
    /// Other Agents of that firmware wait, not all ask (e.g. after a firmware rollout).
    learning: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// WireGuard runs on Agents (ADR-110 stage 4).
    wg: crate::wireguard::WgRunner,
}

/// `req` asks for the whole data model = Get or GetSupportedDM incl. root object (`Device.`).
/// Large model or slow Agent -> much slower answer than an ordinary request + big answer.
fn reads_whole_model(req: &ReqType) -> bool {
    let root = |path: &String| path.trim_end_matches('.') == "Device";
    match req {
        ReqType::Get(g) => g.param_paths.iter().any(root),
        ReqType::GetSupportedDm(g) => g.obj_paths.iter().any(root),
        _ => false,
    }
}

/// Keep a connection to every Agent with a WebSocket URL.
/// List re-read every 30 s (devices added, changed, retired, removed).
async fn supervise_ws_clients(
    ws: WsMtp,
    store: Store,
    tenant_id: Uuid,
    controller_eid: String,
    tls: Option<Arc<rustls::ClientConfig>>,
) {
    let mut running: HashMap<String, (String, dhonomos_usp_mtp::ClientHandle)> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tick.tick().await;
        let wanted: HashMap<String, String> = match store.usp_ws_clients(tenant_id).await {
            Ok(w) => w.into_iter().collect(),
            Err(e) => {
                warn!(error = %e, "reading USP WebSocket clients failed");
                continue;
            }
        };
        // Drop handle -> connection closed.
        running.retain(|eid, (url, _)| wanted.get(eid) == Some(url));
        for (eid, url) in wanted {
            if running.contains_key(&eid) {
                continue;
            }
            if url.starts_with("wss://") && tls.is_none() {
                warn!(agent = %eid, "wss:// Agent skipped: no TLS configuration");
                continue;
            }
            let handle = ws.connect_to(
                eid.clone(),
                url.clone(),
                controller_eid.clone(),
                tls.clone(),
            );
            running.insert(eid, (url, handle));
        }
        metrics::gauge!("dhonomos_usp_ws_clients").set(running.len() as f64);
    }
}

/// OUI in an EndpointID, authority scheme `os::` (`os::<OUI>-<serial>`) or `oui:`
/// (`oui:<OUI>:...`) (TR-369).
pub fn endpoint_oui(eid: &str) -> Option<&str> {
    let oui = if let Some(rest) = eid.strip_prefix("os::") {
        rest.split('-').next()
    } else if let Some(rest) = eid.strip_prefix("oui:") {
        rest.split(':').next()
    } else {
        None
    }?;
    (oui.len() == 6 && oui.bytes().all(|b| b.is_ascii_hexdigit())).then_some(oui)
}

/// Firmware ID: same fingerprint -> shared supported model.
/// `None` if software version unknown (missing or blank) -> builds not distinguishable,
/// model of one must not be used for another.
pub fn firmware_fingerprint(d: &dhonomos_store::Device) -> Option<String> {
    use sha2::{Digest, Sha256};
    let version = d
        .software_version
        .as_deref()
        .filter(|v| !v.trim().is_empty())?;
    let mut h = Sha256::new();
    for part in [
        d.protocol.as_str(),
        d.manufacturer.as_deref().unwrap_or_default(),
        d.oui.as_deref().unwrap_or_default(),
        d.product_class.as_str(),
        d.model_name.as_deref().unwrap_or_default(),
        version,
    ] {
        h.update(part.as_bytes());
        h.update([0]);
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Drop cached supported model of the device firmware + own copy of the device.
/// Linked devices -> no model until their Agents are asked again.
pub async fn discard_supported_model(
    store: &Store,
    device: &dhonomos_store::Device,
) -> Result<(), dhonomos_store::StoreError> {
    if let Some(fingerprint) = firmware_fingerprint(device) {
        store.delete_supported_model(&fingerprint).await?;
    }
    store
        .delete_supported_model(&dhonomos_store::device_fingerprint(device.id))
        .await?;
    Ok(())
}

/// Result of [`UspService::refresh_data_model`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataModelRefresh {
    /// Agent connected -> model read now.
    Refreshing,
    /// Agent offline -> cached model dropped, next connection reads it.
    Queued,
}

fn log_learned(eid: &str, model: &serde_json::Value) {
    metrics::counter!("dhonomos_supported_models_learned_total").increment(1);
    info!(agent = %eid, objects = model["objects"].as_array().map_or(0, Vec::len),
        "supported data model learned");
}

/// Update interval for last contact of connected Agents.
pub const TOUCH_INTERVAL: Duration = Duration::from_secs(60);

/// Running USP service; cheap to clone.
#[derive(Clone)]
pub struct UspService {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for UspService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UspService").finish_non_exhaustive()
    }
}

/// Last Agent certificate state sent to the MTPs.
#[derive(Default)]
struct CertificateState {
    revoked: Option<HashSet<String>>,
    bound: Option<HashSet<String>>,
}

impl CertificateState {
    /// Read from DB: revoked certificates + EndpointIDs with an issued one.
    /// Tell the MTPs the changes since last time.
    async fn sync(&mut self, store: &Store, tenant_id: Uuid, usp: &UspService) {
        match store.revoked_fingerprints(tenant_id).await {
            Ok(list) => {
                let set: HashSet<String> = list.into_iter().collect();
                if self.revoked.as_ref() != Some(&set) {
                    let closed = usp.set_revoked_certificates(set.clone());
                    info!(
                        revoked = set.len(),
                        closed, "revoked Agent certificates loaded"
                    );
                    self.revoked = Some(set);
                }
            }
            Err(e) => warn!(error = %e, "loading revoked certificates failed"),
        }
        match store.certificate_bound_endpoints(tenant_id).await {
            Ok(list) => {
                let set: HashSet<String> = list.into_iter().collect();
                if self.bound.as_ref() != Some(&set) {
                    usp.set_certificate_bound(set.clone());
                    info!(
                        endpoints = set.len(),
                        "EndpointIDs bound to an Agent certificate loaded"
                    );
                    self.bound = Some(set);
                }
            }
            Err(e) => warn!(error = %e, "loading the EndpointIDs bound to certificates failed"),
        }
    }
}

/// Tell the MTPs the Agent certificates once, now. Call before the listeners take Agents
/// -> EndpointID with an issued certificate refused without it from the 1st connection.
/// Later updates: [`watch_certificates`].
pub async fn load_certificates(store: &Store, tenant_id: Uuid, usp: &UspService) {
    CertificateState::default()
        .sync(store, tenant_id, usp)
        .await;
}

/// Keep MTPs in step with DB on Agent client certificates (US-08), check every `every`.
/// Revoked -> refused; connections with a newly revoked one closed (WebSocket, STOMP,
/// embedded MQTT broker).
/// EndpointID with an issued certificate -> connection without it refused on all (H-3, M-5).
pub async fn watch_certificates(store: Store, tenant_id: Uuid, usp: UspService, every: Duration) {
    let mut state = CertificateState::default();
    loop {
        state.sync(&store, tenant_id, &usp).await;
        tokio::time::sleep(every).await;
    }
}

impl UspService {
    /// Start the configured MTPs + handle Agents.
    pub fn start(store: Store, config: UspConfig) -> Self {
        Self::start_with_touch_interval(store, config, TOUCH_INTERVAL)
    }

    /// [`UspService::start`] + last contact update every `touch_every`
    /// (default [`TOUCH_INTERVAL`]).
    pub fn start_with_touch_interval(
        store: Store,
        config: UspConfig,
        touch_every: Duration,
    ) -> Self {
        let (in_tx, inbound) = mpsc::channel(4096);
        let mut mtp = MultiMtp::default();
        if let Some(mqtt) = config.mqtt {
            let (client, mut rx) = MqttMtp::start(mqtt);
            let tx = in_tx.clone();
            tokio::spawn(async move {
                while let Some(i) = rx.recv().await {
                    if tx.send(i).await.is_err() {
                        break;
                    }
                }
            });
            mtp.mqtt = Some(client);
        }
        if let Some(stomp) = config.stomp {
            mtp.stomp = Some(dhonomos_usp_mtp::StompMtp::new(in_tx.clone(), stomp));
        }
        if let Some(broker) = config.mqtt_broker {
            mtp.mqtt_broker = Some(dhonomos_usp_mtp::MqttBrokerMtp::new(in_tx.clone(), broker));
        }
        if config.websocket {
            mtp.ws = Some(WsMtp::new(in_tx));
        }
        // Agents with a WebSocket server -> Controller connects to them (US-05).
        if let Some(ws) = &mtp.ws {
            tokio::spawn(supervise_ws_clients(
                ws.clone(),
                store.clone(),
                config.tenant_id,
                config.endpoint_id.clone(),
                config.ws_client_tls.clone(),
            ));
        }
        if !config.auto_subscribe {
            info!(
                "automatic Controller subscriptions are off (--usp-auto-subscribe=false): \
                 Boot! events (last boot time, `1 BOOT` presets), OperationComplete \
                 notifications (asynchronous commands such as Download() stay waiting until the \
                 24 hour limit; nothing polls for them) and BulkData Push! reports reach the \
                 Controller only through subscriptions set up on the Agent by other means"
            );
        }
        let (tx, mut events) = mpsc::unbounded_channel();
        let wg = crate::wireguard::WgRunner::new(
            store.clone(),
            config.tenant_id,
            config.secrets.clone(),
            crate::wireguard::WgProtocol::Usp,
            time::Duration::try_from(config.wg_incomplete_retry)
                .unwrap_or(crate::wireguard::INCOMPLETE_RETRY),
            crate::wireguard::IpWait {
                usp_polls: config.wg_ip_poll_limit,
                usp_poll_every: time::Duration::try_from(
                    config.wg_ip_poll_interval.min(USP_DRAIN_HOLD),
                )
                .unwrap_or(time::Duration::seconds(1)),
                ..crate::wireguard::IpWait::default()
            },
        );
        let inner = Arc::new(Inner {
            store,
            tenant_id: config.tenant_id,
            presets: config.presets,
            metrics: config.metrics,
            files: config.files,
            secrets: config.secrets,
            ctrl: Controller::new(config.endpoint_id, mtp, Sink(tx), config.request_timeout),
            full_read_timeout_ms: AtomicU64::new(millis(
                config.full_read_timeout.max(config.request_timeout),
            )),
            onboarding: config.onboarding,
            auto_subscribe: AtomicBool::new(config.auto_subscribe),
            draining: Mutex::new(HashSet::new()),
            again: Mutex::new(HashSet::new()),
            learning: Mutex::new(HashMap::new()),
            wg,
        });
        let runner = inner.clone();
        tokio::spawn(async move { runner.ctrl.run(inbound).await });
        // Last contact = last heard from, not last looked at.
        // Idle connection -> no Records, only keep-alives -> MTPs track the last thing each
        // connection got (frame, heart-beat, on Linux a TCP ACK). Written only when it moved.
        let toucher = inner.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(touch_every);
            let mut written: HashMap<String, OffsetDateTime> = HashMap::new();
            loop {
                every.tick().await;
                let agents = toucher.ctrl.connected_agent_addresses();
                let heard = toucher.ctrl.transport().heard_from();
                let now = OffsetDateTime::now_utc();
                let mut due = Vec::new();
                for (eid, addresses) in &agents {
                    let at = match heard.get(eid) {
                        Some(t) => OffsetDateTime::from(*t),
                        // Via an external MQTT broker: no own connection to ask
                        // -> heard from while the Controller sees it connected.
                        None if addresses
                            .iter()
                            .any(|a| !MultiMtp::is_connection_address(a)) =>
                        {
                            now
                        }
                        // Connection just closed, Controller not told yet
                        // (final time written then).
                        None => continue,
                    };
                    if written.get(eid).is_none_or(|w| *w < at) {
                        due.push((eid.clone(), at));
                    }
                }
                let live: HashSet<&str> = agents.iter().map(|(eid, _)| eid.as_str()).collect();
                written.retain(|eid, _| live.contains(eid.as_str()));
                match toucher
                    .store
                    .touch_usp_devices(toucher.tenant_id, &due)
                    .await
                {
                    Ok(_) => written.extend(due),
                    Err(e) => warn!(error = %e, "refreshing USP last contact failed"),
                }
            }
        });
        // Due WireGuard runs on connected Agents. Ends when the service is gone.
        let sweeper = Arc::downgrade(&inner);
        let sweep_every = config.wg_sweep_interval;
        tokio::spawn(async move {
            let mut every = tokio::time::interval(sweep_every);
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                every.tick().await;
                let Some(inner) = sweeper.upgrade() else {
                    break;
                };
                Self { inner }.wg_sweep().await;
            }
        });
        let svc = Self { inner };
        let worker = svc.clone();
        tokio::spawn(async move {
            while let Some(ev) = events.recv().await {
                let w = worker.clone();
                // Events may send requests -> never block the event stream on them.
                tokio::spawn(async move { w.on_event(ev).await });
            }
        });
        svc
    }

    /// Set response waits: `request` for ordinary requests, `full_read` (min `request`)
    /// for whole-model requests. Applies to requests sent from now on.
    pub fn set_timeouts(&self, request: Duration, full_read: Duration) {
        self.inner.ctrl.set_timeout(request);
        self.inner
            .full_read_timeout_ms
            .store(millis(full_read.max(request)), Ordering::Relaxed);
    }

    /// (ordinary, whole-model) request waits.
    pub fn timeouts(&self) -> (Duration, Duration) {
        (self.inner.ctrl.timeout(), self.full_read_timeout())
    }

    fn full_read_timeout(&self) -> Duration {
        Duration::from_millis(self.inner.full_read_timeout_ms.load(Ordering::Relaxed))
    }

    /// Controller adds own subscriptions to Agents connecting from now on
    /// (`UspConfig::auto_subscribe`).
    pub fn set_auto_subscribe(&self, on: bool) {
        self.inner.auto_subscribe.store(on, Ordering::Relaxed);
    }

    /// Embedded STOMP broker, if enabled -> serve where Agents connect.
    pub fn stomp_mtp(&self) -> Option<&dhonomos_usp_mtp::StompMtp> {
        self.inner.ctrl.transport().stomp.as_ref()
    }

    /// Embedded MQTT broker, if enabled -> serve where Agents connect.
    pub fn mqtt_broker_mtp(&self) -> Option<&dhonomos_usp_mtp::MqttBrokerMtp> {
        self.inner.ctrl.transport().mqtt_broker.as_ref()
    }

    /// WebSocket MTP, if enabled -> serve its router where Agents connect.
    pub fn ws_mtp(&self) -> Option<&WsMtp> {
        self.inner.ctrl.transport().ws.as_ref()
    }

    /// Tell all MTPs the revoked Agent client certificates (SHA-256 fingerprints, hex).
    /// -> refused + their connections closed. Returns the closed count.
    pub fn set_revoked_certificates(&self, fingerprints: HashSet<String>) -> usize {
        self.inner.ctrl.transport().set_revoked(fingerprints)
    }

    /// Tell all MTPs the EndpointIDs with an issued client certificate.
    /// Connection for one without a certificate naming it -> refused.
    pub fn set_certificate_bound(&self, eids: HashSet<String>) {
        self.inner.ctrl.transport().set_certificate_bound(eids);
    }

    /// Send a request + wait for the answer.
    /// Wait = request timeout, or full-read timeout for a whole-model request.
    async fn request(&self, eid: &str, req: ReqType) -> Result<msg::Response, UspError> {
        if reads_whole_model(&req) {
            self.inner
                .ctrl
                .request_with_timeout(eid, req, self.full_read_timeout())
                .await
        } else {
            self.inner.ctrl.request(eid, req).await
        }
    }

    pub fn is_connected(&self, endpoint_id: &str) -> bool {
        self.inner.ctrl.is_connected(endpoint_id)
    }

    /// Run queued tasks of the device now if its Agent is connected.
    /// `false` -> Agent offline, tasks wait for the next connect.
    pub async fn wake(&self, device: Uuid, endpoint_id: &str) -> bool {
        if !self.is_connected(endpoint_id) {
            return false;
        }
        self.spawn_drain(device, endpoint_id.to_owned());
        true
    }

    async fn on_event(&self, ev: UspEvent) {
        let store = &self.inner.store;
        match ev {
            UspEvent::Connected(eid) => {
                let new_status = match self.admit(&eid).await {
                    Ok(status) => status,
                    Err(reason) => {
                        metrics::counter!("dhonomos_usp_rejected_total", "reason" => reason)
                            .increment(1);
                        dhonomos_common::request_refused!(
                            "usp",
                            reason,
                            self.inner.ctrl.transport().peer_addr(&eid),
                            agent = ?dhonomos_common::refusal::clip(&eid)
                        );
                        self.inner.ctrl.transport().disconnect(&eid);
                        return;
                    }
                };
                let device = match store
                    .upsert_usp_device(self.inner.tenant_id, &eid, new_status)
                    .await
                {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(agent = %eid, error = %e, "registering USP agent failed");
                        return;
                    }
                };
                let _ = store
                    .record_event(
                        self.inner.tenant_id,
                        Some(device.id),
                        "usp_connect",
                        &json!({ "endpoint_id": eid }),
                    )
                    .await;
                // WebSocket, STOMP, embedded-MQTT Agents connect to us -> keep source address.
                if let Some(addr) = self.inner.ctrl.transport().peer_addr(&eid) {
                    let _ = store.set_usp_remote_addr(device.id, addr).await;
                }
                let version = async || {
                    store
                        .get_device(device.id)
                        .await
                        .ok()
                        .flatten()
                        .and_then(|d| d.software_version)
                };
                let before = version().await;
                self.refresh_info(device.id, &eid).await;
                let after = version().await;
                self.refresh_supported_model(device.id, &eid).await;
                // Known Agent lost the Controller subscriptions? (ADR-107)
                let boot_subscription_missing = self.inner.auto_subscribe.load(Ordering::Relaxed)
                    && self.ensure_subscriptions(&eid).await;
                // = CWMP zero-touch: new Agent or other firmware -> read whole.
                // Same for lost state (factory reset, DB wiped): our `dhonomos-boot`
                // subscription is gone (ADR-107).
                // Pre-registered Agent: record exists before 1st connect, no software version
                // until 1st DeviceInfo read -> that marks first contact.
                let first_contact = device.created || (before.is_none() && after.is_some());
                let firmware_changed = before.is_some() && after.is_some() && before != after;
                if first_contact || firmware_changed {
                    self.enqueue_full_read(device.id, after.as_deref().unwrap_or_default())
                        .await;
                } else if boot_subscription_missing {
                    info!(
                        agent = %eid,
                        device = %device.id,
                        "the Agent lacks the Controller's subscriptions (factory reset or lost state); reading it whole"
                    );
                    self.queue_state_lost_read(
                        device.id,
                        json!({ "reason": "subscriptions_missing" }),
                    )
                    .await;
                }
                self.apply_presets(device.id, "USP CONNECT", first_contact)
                    .await;
                // Queued before the drain -> same drain runs it.
                self.inner
                    .wg
                    .start(
                        device.id,
                        &device.status,
                        first_contact || firmware_changed || boot_subscription_missing,
                        &crate::wireguard::now_text(),
                    )
                    .await;
                self.spawn_drain(device.id, eid);
            }
            UspEvent::Disconnected(eid) => {
                // Last contact = last receive on the closed connection, not the previous
                // touch (device without power is found out much later).
                if let Some(at) = self.inner.ctrl.transport().take_final_heard(&eid)
                    && let Err(e) = store
                        .touch_usp_devices(
                            self.inner.tenant_id,
                            &[(eid.clone(), OffsetDateTime::from(at))],
                        )
                        .await
                {
                    warn!(agent = %eid, error = %e, "recording the last contact of a closed connection failed");
                }
                if let Ok(Some(id)) = store.find_usp_device(self.inner.tenant_id, &eid).await {
                    let _ = store
                        .record_event(self.inner.tenant_id, Some(id), "usp_disconnect", &json!({}))
                        .await;
                    self.requeue_unless_draining(id, eid).await;
                }
            }
            UspEvent::Notify(eid, msg_id, n) => self.on_notify(&eid, &msg_id, n).await,
        }
    }

    /// Admission (CO-12). Retired Agent -> refused.
    /// Unknown Agent -> refused if only pre-registered Agents or other OUIs admitted,
    /// quarantined if so configured. Returns the status of a new Agent.
    async fn admit(&self, eid: &str) -> Result<Option<&'static str>, &'static str> {
        let store = &self.inner.store;
        let known = store
            .find_usp_device(self.inner.tenant_id, eid)
            .await
            .map_err(|_| "store")?;
        if let Some(id) = known {
            return match store.device_status(id).await {
                Ok(Some(s)) if s == "retired" => Err("retired"),
                _ => Ok(None),
            };
        }
        let policy = &self.inner.onboarding;
        if !policy.allowed_ouis.is_empty() {
            let allowed = endpoint_oui(eid).is_some_and(|o| {
                policy
                    .allowed_ouis
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(o))
            });
            if !allowed {
                return Err("oui");
            }
        }
        match policy.mode {
            crate::OnboardingMode::Preregistered => Err("not_registered"),
            crate::OnboardingMode::Quarantine => Ok(Some("quarantined")),
            crate::OnboardingMode::Auto => Ok(None),
        }
    }

    /// Queue a Get of the whole `Device.` tree (low priority, once per `occasion`).
    /// `occasion` = firmware version of the Agent, or `state-lost:<UTC date>` for lost state
    /// (ADR-107, see `queue_state_lost_read`).
    async fn enqueue_full_read(&self, device: Uuid, occasion: &str) {
        let (kind, payload) = TaskKind::GetParameterValues {
            names: vec!["Device.".into()],
        }
        .to_row();
        let task = NewTask {
            priority: -10,
            idempotency_key: Some(format!("usp-full-read:{device}:{occasion}")),
            created_by: Some("system:bootstrap".into()),
            ..NewTask::new(self.inner.tenant_id, device, kind, payload)
        };
        if let Err(e) = self.inner.store.enqueue_task(&task).await {
            warn!(%device, error = %e, "queueing the full read failed");
        }
    }

    /// Agent with lost state (factory reset, DB wiped) -> read whole like a new one (ADR-107).
    /// Queue the full read + record a `usp_state_lost` event, detail = how it was found.
    /// Read keyed by UTC date -> max 1/day per device. Else an Agent that cannot keep its
    /// subscriptions -> full read at every connection.
    async fn queue_state_lost_read(&self, device: Uuid, detail: serde_json::Value) {
        let day = OffsetDateTime::now_utc().date();
        self.enqueue_full_read(device, &format!("state-lost:{day}"))
            .await;
        if let Err(e) = self
            .inner
            .store
            .record_event(
                self.inner.tenant_id,
                Some(device),
                "usp_state_lost",
                &detail,
            )
            .await
        {
            warn!(%device, error = %e, "recording the lost state of a USP agent failed");
        }
    }

    /// Boot! -> read the Agent firmware images again (ADR-108).
    /// Bootloader fell back to the other image after a failed boot -> old version runs,
    /// no `FirmwareUpdated`, no `SoftwareVersion` change -> nothing else reads the
    /// `FirmwareImage` rows the failed boot left.
    ///
    /// Only if stored parameters already have that object (an earlier full read saw it)
    /// -> else a failed task at every boot.
    /// Not if a full read is waiting or running (new Agent, new firmware, lost state,
    /// operator refresh) -> same values.
    /// Boot! often comes while connect still decides on a full read -> both run, cost: one
    /// more small Get.
    ///
    /// Task key = Notify `msg_id`; Agent repeats it on resend of an unanswered Notify
    /// -> resent Boot! adds no 2nd read. No usable `msg_id` (empty or over 128 bytes) -> no key,
    /// each Boot! queues its own.
    async fn queue_boot_firmware_read(&self, device: Uuid, msg_id: &str) {
        let store = &self.inner.store;
        match store
            .has_param_prefix(device, crate::task::FIRMWARE_IMAGES)
            .await
        {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                warn!(%device, error = %e, "checking for firmware images failed");
                return;
            }
        }
        match store.has_open_read_of(device, "Device.").await {
            Ok(true) => return,
            Ok(false) => {}
            // Read twice > no read.
            Err(e) => warn!(%device, error = %e, "checking for a waiting full read failed"),
        }
        let boot = if msg_id.is_empty() || msg_id.len() > 128 {
            Uuid::now_v7().to_string()
        } else {
            msg_id.to_owned()
        };
        let task = crate::task::boot_firmware_read(self.inner.tenant_id, device, &boot);
        if let Err(e) = store.enqueue_task(&task).await {
            warn!(%device, error = %e, "queueing the firmware image read failed");
        }
    }

    /// Queue tasks of matching presets for a USP device.
    async fn apply_presets(&self, device: Uuid, event: &str, new_device: bool) {
        let presets = self.inner.presets.get();
        if presets.is_empty() {
            return;
        }
        let store = &self.inner.store;
        let Ok(Some(d)) = store.get_device(device).await else {
            return;
        };
        let events = [dhonomos_cwmp_codec::EventCode::parse(event)];
        let ctx = crate::presets::MatchContext {
            events: &events,
            oui: d.oui.as_deref().unwrap_or_default(),
            product_class: &d.product_class,
            software_version: d.software_version.as_deref(),
            tags: &d.tags,
            new_device,
            attributes: &d.attributes,
            serial: d.endpoint_id.as_deref().unwrap_or_default(),
            protocol: "usp",
        };
        let occurrence = Uuid::now_v7().to_string();
        if let Err(e) = crate::presets::enqueue_matching(
            store,
            self.inner.tenant_id,
            &presets,
            device,
            &ctx,
            &occurrence,
        )
        .await
        {
            warn!(%device, error = %e, "applying presets failed");
        }
    }

    /// Create the Controller's own subscriptions (US-10): Boot! events, completion of async
    /// commands, BulkData Push!. Runs on every connect.
    /// Subscription ID = unique key -> existing one reported as 7025, left alone.
    ///
    /// Returns: Boot! subscription `dhonomos-boot` missing = table read, ID not in it.
    /// -> sign of lost state (factory reset wipes even persistent subscriptions); no Boot!
    /// reaches us without it (ADR-107). Unreadable table != missing.
    /// Result independent of the following Add.
    async fn ensure_subscriptions(&self, eid: &str) -> bool {
        use msg::add_resp::created_object_result::operation_status::OperStatus;
        let sub = |id: &str, ty: &str, reference: &str| msg::add::CreateObject {
            obj_path: "Device.LocalAgent.Subscription.".into(),
            param_settings: [
                ("ID", id),
                ("NotifType", ty),
                ("ReferenceList", reference),
                ("Persistent", "true"),
                ("Enable", "true"),
            ]
            .into_iter()
            .map(|(p, v)| msg::add::CreateParamSetting {
                param: p.into(),
                value: v.into(),
                required: true,
            })
            .collect(),
        };
        let wanted = [
            ("dhonomos-boot", "Event", "Device.Boot!"),
            (
                "dhonomos-operation-complete",
                "OperationComplete",
                "Device.",
            ),
            (
                "dhonomos-bulkdata",
                "Event",
                "Device.BulkData.Profile.*.Push!",
            ),
        ];
        // Subscriptions persist on the Agent -> add only missing ones -> reconnect changes
        // nothing (+ no refusals in the Agent log).
        // Table not readable -> add all; existing IDs refused harmlessly (7025).
        let read = self.subscription_ids(eid).await;
        let boot_missing = read
            .as_ref()
            .is_some_and(|ids| !ids.iter().any(|i| i == "dhonomos-boot"));
        let existing = read.unwrap_or_default();
        let create_objs: Vec<_> = wanted
            .iter()
            .filter(|(id, _, _)| !existing.iter().any(|e| e == id))
            .map(|(id, ty, reference)| sub(id, ty, reference))
            .collect();
        if create_objs.is_empty() {
            return boot_missing;
        }
        let req = ReqType::Add(msg::Add {
            allow_partial: true,
            create_objs,
        });
        let resp = match self.request(eid, req).await {
            Ok(r) => r,
            Err(e) => {
                warn!(agent = %eid, error = %e, "creating subscriptions failed");
                return boot_missing;
            }
        };
        let Some(msg::response::RespType::AddResp(a)) = resp.resp_type else {
            return boot_missing;
        };
        for r in a.created_obj_results {
            match r.oper_status.and_then(|o| o.oper_status) {
                Some(OperStatus::OperSuccess(ok)) => {
                    info!(agent = %eid, path = %ok.instantiated_path, "subscription created");
                }
                Some(OperStatus::OperFailure(f)) if f.err_code == 7025 => {}
                Some(OperStatus::OperFailure(f)) => {
                    warn!(agent = %eid, code = f.err_code, error = %f.err_msg, "subscription not created");
                }
                None => {}
            }
        }
        boot_missing
    }

    /// Subscription IDs of the Agent. `None` -> not readable.
    async fn subscription_ids(&self, eid: &str) -> Option<Vec<String>> {
        let req = ReqType::Get(msg::Get {
            param_paths: vec!["Device.LocalAgent.Subscription.".into()],
            max_depth: 0,
        });
        let resp = self.request(eid, req).await.ok()?;
        let read = usp_map::apply(&TaskKind::GetParameterValues { names: vec![] }, &resp).ok()?;
        Some(
            read.params
                .into_iter()
                .filter(|p| {
                    p.path.starts_with("Device.LocalAgent.Subscription.") && p.path.ends_with(".ID")
                })
                .filter_map(|p| p.value)
                .collect(),
        )
    }

    /// Whole supported data model of the Agent (GetSupportedDM of `Device.`).
    async fn fetch_supported_model(&self, eid: &str) -> Result<serde_json::Value, String> {
        let req = ReqType::GetSupportedDm(msg::GetSupportedDm {
            obj_paths: vec!["Device.".into()],
            first_level_only: false,
            return_commands: true,
            return_events: true,
            return_params: true,
            return_unique_key_sets: true,
        });
        match self.request(eid, req).await {
            Ok(msg::Response {
                resp_type: Some(msg::response::RespType::GetSupportedDmResp(r)),
            }) => usp_map::supported_model(&r),
            Ok(other) => Err(format!("unexpected response {other:?}")),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Link the device to the supported data model of its firmware (US-11).
    /// Ask the Agent (GetSupportedDM of `Device.`) only for new firmware.
    /// Software version unknown -> no firmware to share by -> ask every time, model kept
    /// for this device only.
    async fn refresh_supported_model(&self, device: Uuid, eid: &str) {
        let store = &self.inner.store;
        let Ok(Some(d)) = store.get_device(device).await else {
            return;
        };
        let Some(fingerprint) = firmware_fingerprint(&d) else {
            info!(agent = %eid,
                "supported data model cache skipped: the software version is unknown");
            self.learn_private_model(device, eid).await;
            return;
        };
        let gate = self
            .inner
            .learning
            .lock()
            .map(|mut l| l.entry(fingerprint.clone()).or_default().clone())
            .ok();
        let _turn = match &gate {
            Some(g) => Some(g.lock().await),
            None => None,
        };
        let cached = match store.supported_model_id(&fingerprint).await {
            Ok(c) => c,
            Err(e) => {
                warn!(%device, error = %e, "looking up the supported model failed");
                return;
            }
        };
        let id = match cached {
            Some(id) => id,
            None => {
                let model = match self.fetch_supported_model(eid).await {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(agent = %eid, error = %e, "reading the supported data model failed");
                        return;
                    }
                };
                log_learned(eid, &model);
                match store.put_supported_model(&fingerprint, "usp", &model).await {
                    Ok(id) => id,
                    Err(e) => {
                        warn!(%device, error = %e, "storing the supported model failed");
                        return;
                    }
                }
            }
        };
        if let Err(e) = store.link_supported_model(device, id).await {
            warn!(%device, error = %e, "linking the supported model failed");
        }
        // Model for this device only (from before its version was known) -> obsolete.
        let _ = store
            .delete_supported_model(&dhonomos_store::device_fingerprint(device))
            .await;
        drop(_turn);
        // Last Agent through the gate removes it.
        if let (Some(g), Ok(mut l)) = (gate, self.inner.learning.lock())
            && Arc::strong_count(&g) <= 2
        {
            l.remove(&fingerprint);
        }
    }

    /// Firmware not identifiable -> fetch the model, keep it for this device only
    /// (replaces the one from its last connection).
    async fn learn_private_model(&self, device: Uuid, eid: &str) {
        let store = &self.inner.store;
        let model = match self.fetch_supported_model(eid).await {
            Ok(m) => m,
            Err(e) => {
                warn!(agent = %eid, error = %e, "reading the supported data model failed");
                return;
            }
        };
        log_learned(eid, &model);
        let fingerprint = dhonomos_store::device_fingerprint(device);
        match store
            .replace_supported_model(&fingerprint, "usp", &model)
            .await
        {
            Ok(id) => {
                if let Err(e) = store.link_supported_model(device, id).await {
                    warn!(%device, error = %e, "linking the supported model failed");
                }
            }
            Err(e) => warn!(%device, error = %e, "storing the supported model failed"),
        }
    }

    /// Operator refresh of the supported data model: firmware model (+ own copy of the
    /// device) dropped and read again.
    ///
    /// Agent connected -> fetch in background, replace old model on arrival (devices of the
    /// same firmware get it too). Else -> cached model deleted now, next connection reads it.
    pub async fn refresh_data_model(
        &self,
        device: &dhonomos_store::Device,
    ) -> Result<DataModelRefresh, dhonomos_store::StoreError> {
        let connected = device
            .endpoint_id
            .as_deref()
            .filter(|eid| self.is_connected(eid));
        let Some(eid) = connected else {
            discard_supported_model(&self.inner.store, device).await?;
            return Ok(DataModelRefresh::Queued);
        };
        let svc = self.clone();
        let (device, eid) = (device.clone(), eid.to_owned());
        tokio::spawn(async move { svc.relearn_supported_model(&device, &eid).await });
        Ok(DataModelRefresh::Refreshing)
    }

    /// Read the supported data model of the connected Agent again.
    /// OK -> replace cached model in place. Fail -> drop cache -> next connection reads it,
    /// no model kept that the operator found wrong.
    async fn relearn_supported_model(&self, device: &dhonomos_store::Device, eid: &str) {
        let store = &self.inner.store;
        let model = match self.fetch_supported_model(eid).await {
            Ok(m) => m,
            Err(e) => {
                warn!(agent = %eid, error = %e, "refreshing the supported data model failed");
                if let Err(e) = discard_supported_model(store, device).await {
                    warn!(device = %device.id, error = %e, "discarding the supported model failed");
                }
                return;
            }
        };
        log_learned(eid, &model);
        let fingerprint = firmware_fingerprint(device)
            .unwrap_or_else(|| dhonomos_store::device_fingerprint(device.id));
        match store
            .replace_supported_model(&fingerprint, "usp", &model)
            .await
        {
            Ok(id) => {
                if let Err(e) = store.link_supported_model(device.id, id).await {
                    warn!(device = %device.id, error = %e, "linking the supported model failed");
                }
            }
            Err(e) => warn!(device = %device.id, error = %e, "storing the supported model failed"),
        }
    }

    /// Read identity parameters of `Device.DeviceInfo.` ([`IDENTITY_PARAMS`]) -> registry entry.
    /// Full paths, not the object: object can be very big, read on every connection, links
    /// paid per byte. LS500X: `ProcessStatus.Process.{i}` = 1,710 parameters, `DeviceLog` =
    /// one value ~32 KiB, direct parameter of `DeviceInfo` -> sent even with `max_depth`.
    /// Whole object -> full read (first contact, new firmware).
    /// Missing parameter -> error for that path; the others still count.
    async fn refresh_info(&self, device: Uuid, eid: &str) {
        let req = ReqType::Get(msg::Get {
            param_paths: identity_paths(),
            // Full parameter paths -> nothing below.
            max_depth: 0,
        });
        let resp = match self.request(eid, req).await {
            Ok(r) => r,
            Err(e) => {
                warn!(agent = %eid, error = %e, "reading DeviceInfo failed");
                return;
            }
        };
        let applied = match usp_map::apply(&TaskKind::GetParameterValues { names: vec![] }, &resp) {
            Ok(a) => a,
            Err(e) => {
                // All paths failed (only case where `apply` fails).
                warn!(agent = %eid, error = %e, "the Agent has none of the DeviceInfo identity parameters");
                return;
            }
        };
        for failure in applied.result["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| e.as_str())
        {
            debug!(agent = %eid, error = %failure, "reading a DeviceInfo identity parameter failed");
        }
        let info = device_info(|name| {
            applied
                .params
                .iter()
                .find(|p| {
                    p.path
                        .strip_prefix(DEVICE_INFO)
                        .is_some_and(|param| param == name)
                })
                .and_then(|p| p.value.clone())
                .filter(|v| !v.is_empty())
        });
        let store = &self.inner.store;
        if let Err(e) = store.update_device_info(device, &info).await {
            warn!(%device, error = %e, "updating device info failed");
        }
        let mut params = applied.params;
        self.writability(device).await.fill(&mut params);
        param_store::upsert_reporting(store, device, "usp", &params).await;
    }

    /// Writability from the device supported data model (empty if not learned yet).
    async fn writability(&self, device: Uuid) -> usp_map::Writability {
        match self.inner.store.device_supported_model(device).await {
            Ok(Some(m)) => usp_map::Writability::from_model(&m.model),
            _ => usp_map::Writability::default(),
        }
    }

    async fn on_notify(&self, eid: &str, msg_id: &str, n: msg::Notify) {
        let store = &self.inner.store;
        let tenant = self.inner.tenant_id;
        let Ok(Some(device)) = store.find_usp_device(tenant, eid).await else {
            debug!(agent = %eid, "notify from an unregistered agent");
            return;
        };
        let (kind, detail) = match n.notification {
            Some(Notification::ValueChange(vc)) => {
                // CO-11: same normalized event as CWMP VALUE CHANGE.
                let old = store
                    .get_param_values(device, std::slice::from_ref(&vc.param_path))
                    .await
                    .ok()
                    .and_then(|m| m.get(&vc.param_path).cloned().flatten());
                param_store::upsert_reporting(
                    store,
                    device,
                    "usp",
                    &[ParamUpdate {
                        path: vc.param_path.clone(),
                        value: Some(vc.param_value.clone()),
                        ..ParamUpdate::default()
                    }],
                )
                .await;
                metrics::counter!("dhonomos_parameter_changes_total", "source" => "usp")
                    .increment(1);
                (
                    "parameter_change",
                    json!({ "source": "usp-value-change", "subscription": n.subscription_id,
                            "changes": [{ "path": vc.param_path, "old": old, "new": vc.param_value }] }),
                )
            }
            Some(Notification::Event(e))
                if e.event_name == "Push!"
                    && e.obj_path.starts_with("Device.BulkData.Profile.") =>
            {
                // BulkData over USP (DG-04): report = `Data` argument.
                if let (Some(ingest), Some(data)) = (&self.inner.metrics, e.params.get("Data")) {
                    match crate::metrics::parse_bulkdata_json(
                        data.as_bytes(),
                        time::OffsetDateTime::now_utc(),
                    ) {
                        Ok(samples) => {
                            if let Err(err) = ingest.ingest(device, &samples).await {
                                warn!(%device, error = %err, "storing BulkData samples failed");
                            }
                        }
                        Err(err) => debug!(%device, error = %err, "ignored BulkData push"),
                    }
                }
                return;
            }
            Some(Notification::Event(e)) => {
                if e.event_name == "Boot!" {
                    let _ = store.mark_booted(device).await;
                    self.apply_presets(device, "1 BOOT", false).await;
                    // Factory reset -> read whole like a new Agent (ADR-107).
                    // Queued before the drain -> same drain runs it.
                    let factory_reset = e.params.get("Cause").filter(|c| {
                        matches!(c.as_str(), "LocalFactoryReset" | "RemoteFactoryReset")
                    });
                    if let Some(cause) = factory_reset {
                        self.queue_state_lost_read(
                            device,
                            json!({ "reason": "boot_cause", "cause": cause }),
                        )
                        .await;
                    }
                    self.queue_boot_firmware_read(device, msg_id).await;
                    // New run replaces one in progress -> device may have lost what the old
                    // one did. Run still waiting for its 1st read kept -> reads current state.
                    // Every boot forces the run, not only factory reset: boot may come with
                    // lost config (e.g. factory reset + restore from backup).
                    // One read of `Device.WireGuard.` per boot = cheap.
                    match store.device_status(device).await {
                        Ok(Some(status)) => {
                            self.inner
                                .wg
                                .start(device, &status, true, &crate::wireguard::now_text())
                                .await;
                        }
                        Ok(None) => {}
                        Err(e) => warn!(%device, error = %e, "reading the device status failed"),
                    }
                    self.spawn_drain(device, eid.to_owned());
                }
                (
                    "usp_event",
                    json!({ "subscription": n.subscription_id, "path": format!("{}{}", e.obj_path, e.event_name), "params": e.params }),
                )
            }
            Some(Notification::ObjCreation(c)) => (
                "usp_object_created",
                json!({ "path": c.obj_path, "unique_keys": c.unique_keys }),
            ),
            Some(Notification::ObjDeletion(d)) => {
                ("usp_object_deleted", json!({ "path": d.obj_path }))
            }
            Some(Notification::OperComplete(oc)) => {
                use msg::notify::operation_complete::OperationResp;
                let outcome = match &oc.operation_resp {
                    Some(OperationResp::CmdFailure(f)) => {
                        Err(format!("{} {}", f.err_code, f.err_msg))
                    }
                    Some(OperationResp::ReqOutputArgs(a)) => Ok(json!({ "output": a.output_args })),
                    None => Ok(json!({})),
                };
                if let Ok(task) = oc.command_key.parse::<Uuid>() {
                    // Diagnostics -> normalized result (DG-01).
                    // Command key = task ID -> only for own tasks of this device (L-1).
                    let diagnostic = match (&oc.operation_resp, store.get_task(task).await) {
                        (Some(OperationResp::ReqOutputArgs(a)), Ok(Some(t)))
                            if t.device_id == device =>
                        {
                            match TaskKind::from_row(&t.kind, &t.payload) {
                                Ok(TaskKind::Diagnostic { test, .. }) => {
                                    let raw = a
                                        .output_args
                                        .iter()
                                        .map(|(k, v)| (k.clone(), v.clone()))
                                        .collect();
                                    Some(crate::diagnostics::outcome(test, &raw))
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    };
                    let _ = store
                        .complete_task(device, task, diagnostic.unwrap_or_else(|| outcome.clone()))
                        .await;
                }
                (
                    "usp_operation_complete",
                    json!({ "command": format!("{}{}", oc.obj_path, oc.command_name), "command_key": oc.command_key,
                            "error": outcome.err() }),
                )
            }
            Some(Notification::OnBoardReq(o)) => (
                "usp_onboard_request",
                json!({ "oui": o.oui, "product_class": o.product_class, "serial_number": o.serial_number }),
            ),
            None => return,
        };
        if let Err(e) = store
            .record_event(tenant, Some(device), kind, &detail)
            .await
        {
            warn!(%device, error = %e, "recording USP notification failed");
        }
    }

    fn spawn_drain(&self, device: Uuid, eid: String) {
        {
            let Ok(mut draining) = self.inner.draining.lock() else {
                return;
            };
            if !draining.insert(device) {
                // Drain running -> it looks again when done.
                if let Ok(mut again) = self.inner.again.lock() {
                    again.insert(device);
                }
                return;
            }
        }
        let svc = self.clone();
        tokio::spawn(async move {
            loop {
                svc.drain(device, &eid).await;
                let more = svc.inner.again.lock().is_ok_and(|mut a| a.remove(&device));
                if !more {
                    break;
                }
            }
            if let Ok(mut d) = svc.inner.draining.lock() {
                d.remove(&device);
            }
        });
    }

    /// After disconnect: tasks left `running` -> back to queue, only if no drain owns the device.
    /// Running drain requeues its own task on request failure. Response already there
    /// -> requeue here would drop it + resend (close right after SetResp, or AddResp:
    /// object added twice).
    /// Drain slot taken for the requeue -> no drain starts in between.
    async fn requeue_unless_draining(&self, device: Uuid, eid: String) {
        let free = self
            .inner
            .draining
            .lock()
            .is_ok_and(|mut d| d.insert(device));
        if !free {
            return;
        }
        let _ = self.inner.store.requeue_running(device).await;
        if let Ok(mut d) = self.inner.draining.lock() {
            d.remove(&device);
        }
        // Wake that came while this held the slot.
        let again = self.inner.again.lock().is_ok_and(|mut a| a.remove(&device));
        if again {
            self.spawn_drain(device, eid);
        }
    }

    /// FW-05: resolve the file, pick the inactive firmware slot, build `Download()`.
    async fn firmware_request(
        &self,
        device: Uuid,
        eid: &str,
        kind: TaskKind,
        key: &str,
    ) -> Result<ReqType, String> {
        let kind = crate::files::resolve_download(
            &self.inner.store,
            self.inner.files.as_ref(),
            self.inner.tenant_id,
            device,
            kind,
        )
        .await?;
        let get = ReqType::Get(msg::Get {
            param_paths: vec![
                "Device.DeviceInfo.FirmwareImage.".into(),
                "Device.DeviceInfo.ActiveFirmwareImage".into(),
            ],
            max_depth: 0,
        });
        let resp = self
            .request(eid, get)
            .await
            .map_err(|e| format!("reading firmware images: {e}"))?;
        let images = usp_map::apply(&TaskKind::GetParameterValues { names: vec![] }, &resp)?;
        let bank = usp_map::firmware_bank(&images.params)?;
        usp_map::firmware_download(&bank, &kind, key)
    }

    /// Vendor config backup/restore, vendor log upload (CO-08).
    /// Command of the first VendorConfigFile (or VendorLogFile) instance of the device.
    async fn file_transfer_request(
        &self,
        device: Uuid,
        eid: &str,
        table: &str,
        kind: TaskKind,
        key: &str,
    ) -> Result<ReqType, String> {
        let kind = match kind {
            TaskKind::Download { .. } => {
                crate::files::resolve_download(
                    &self.inner.store,
                    self.inner.files.as_ref(),
                    self.inner.tenant_id,
                    device,
                    kind,
                )
                .await?
            }
            other => other,
        };
        let get = ReqType::Get(msg::Get {
            param_paths: vec![table.to_owned()],
            max_depth: 0,
        });
        let resp = self
            .request(eid, get)
            .await
            .map_err(|e| format!("reading {table}: {e}"))?;
        let found = usp_map::apply(&TaskKind::GetParameterValues { names: vec![] }, &resp)?;
        let entry = usp_map::first_instance(&found.params, table)?;
        usp_map::file_transfer(&entry, &kind, key)
    }

    /// Send runnable tasks of the device one by one until none left.
    /// Task due within [`USP_DRAIN_HOLD`] (WireGuard poll, any task scheduled that soon)
    /// -> wait + send on time, not at next connect.
    async fn drain(&self, device: Uuid, eid: &str) {
        let store = &self.inner.store;
        match store.device_status(device).await {
            Ok(Some(s)) if s == "active" => {}
            _ => return,
        }
        loop {
            let task = match store.next_task(device).await {
                Ok(Some(t)) => t,
                Ok(None) => match store.next_due_in(device).await {
                    Ok(Some(due)) if due <= USP_DRAIN_HOLD => {
                        tokio::time::sleep(due.max(Duration::from_millis(20))).await;
                        continue;
                    }
                    Ok(_) => return,
                    Err(e) => {
                        warn!(%device, error = %e, "task queue unavailable");
                        return;
                    }
                },
                Err(e) => {
                    warn!(%device, error = %e, "task queue unavailable");
                    return;
                }
            };
            let mut payload = task.payload.clone();
            if let Some(secrets) = &self.inner.secrets
                && let Err(e) =
                    secrets.decrypt_fields(&mut payload, &crate::secrets::task_context(task.id))
            {
                let _ = store.fail_task(task.id, &e.to_string()).await;
                continue;
            }
            let kind = match TaskKind::from_row(&task.kind, &payload) {
                Ok(k) => k,
                Err(e) => {
                    let _ = store
                        .fail_task(task.id, &format!("invalid task: {e}"))
                        .await;
                    continue;
                }
            };
            // Transfer diagnostic without URL -> test link of the file server.
            let kind =
                match crate::files::resolve_diagnostic(self.inner.files.as_ref(), device, kind) {
                    Ok(k) => k,
                    Err(e) => {
                        let _ = store.fail_task(task.id, &e).await;
                        continue;
                    }
                };
            let key = task.id.to_string();
            let req = if let Some(table) = usp_map::transfer_table(&kind) {
                self.file_transfer_request(device, eid, table, kind.clone(), &key)
                    .await
            } else if matches!(kind, TaskKind::Download { .. }) {
                self.firmware_request(device, eid, kind.clone(), &key).await
            } else {
                usp_map::to_request(&kind, &key)
            };
            let req = match req {
                Ok(r) => r,
                Err(e) => {
                    let _ = store.fail_task(task.id, &e).await;
                    continue;
                }
            };
            info!(%device, agent = %eid, task = %task.id, kind = %task.kind, "sending USP task");
            // Task outcome recorded -> its WireGuard run (if any) goes on
            // (may queue its next step -> this loop takes it).
            let wg = &self.inner.wg;
            match self.request(eid, req).await {
                Ok(resp) => {
                    metrics::counter!("dhonomos_tasks_completed_total", "kind" => kind.name(), "outcome" => "response").increment(1);
                    match usp_map::apply(&kind, &resp) {
                        Ok(mut applied) => {
                            if !applied.params.is_empty() {
                                self.writability(device).await.fill(&mut applied.params);
                            }
                            param_store::upsert_reporting(store, device, "usp", &applied.params)
                                .await;
                            for prefix in &applied.deleted {
                                let _ = store.delete_params_under(device, prefix).await;
                            }
                            if matches!(kind, TaskKind::GetParameterValues { .. }) {
                                let mut removed = 0;
                                for (prefix, paths) in &applied.reads {
                                    let reported = Reported::new(paths.iter().map(String::as_str));
                                    removed += param_prune::prune(
                                        store,
                                        device,
                                        prefix,
                                        &reported,
                                        Mode::Values,
                                    )
                                    .await;
                                }
                                if let Some(result) = applied.result.as_object_mut() {
                                    result.insert("removed".into(), removed.into());
                                }
                            }
                            if applied.pending {
                                let _ = store.mark_task_waiting(task.id, &applied.result).await;
                            } else {
                                let _ = store
                                    .complete_task(device, task.id, Ok(applied.result.clone()))
                                    .await;
                            }
                            wg.completed(self, device, task.id, &kind, WgAnswer::Applied(&applied))
                                .await;
                        }
                        Err(e) => {
                            let _ = store.fail_task(task.id, &e).await;
                            wg.completed(self, device, task.id, &kind, WgAnswer::Refused(&e))
                                .await;
                        }
                    }
                }
                Err(UspError::Agent { code, message }) => {
                    metrics::counter!("dhonomos_tasks_completed_total", "kind" => kind.name(), "outcome" => "fault").increment(1);
                    let text = format!("{} {message}", code.0);
                    let _ = store.fail_task(task.id, &text).await;
                    wg.completed(self, device, task.id, &kind, WgAnswer::Refused(&text))
                        .await;
                }
                Err(e @ UspError::ConnectionReplaced) => {
                    // Agent reconnected; request went over the replaced connection, which the
                    // Agent dropped with it (ADR-109). Still connected -> unlike below, no wait
                    // for next connect: attempt used (task back to `pending`, or failed if
                    // last), drain goes on, resends over the new connection.
                    // Terminates: each `next_task` pass takes an attempt -> max `max_attempts`
                    // sends per task.
                    warn!(%device, task = %task.id, error = %e, "USP task interrupted");
                    let _ = store
                        .complete_task(device, task.id, Err(e.to_string()))
                        .await;
                    wg.completed(self, device, task.id, &kind, WgAnswer::Lost)
                        .await;
                    continue;
                }
                Err(e) => {
                    // Not connected, disconnected, timeout, transport -> retry on next connect.
                    // WireGuard run ends here (its tasks have no attempt left); next connect
                    // starts a new one.
                    warn!(%device, task = %task.id, error = %e, "USP task interrupted");
                    let _ = store.requeue_running(device).await;
                    wg.completed(self, device, task.id, &kind, WgAnswer::Lost)
                        .await;
                    return;
                }
            }
        }
    }
}

impl UspService {
    /// One WireGuard sweep pass. Connected, active Agent -> run, unless one in progress, if:
    /// memberships due a run (see [`crate::wireguard::WgRunner::sweep_due`]), or no live
    /// membership but still rows of ours.
    async fn wg_sweep(&self) {
        let store = &self.inner.store;
        let tenant = self.inner.tenant_id;
        let eids = self.inner.ctrl.connected_agents();
        if eids.is_empty() {
            return;
        }
        let swept = async {
            let known = store.find_usp_devices(tenant, &eids).await?;
            let active: Vec<(Uuid, String)> = known
                .into_iter()
                .filter(|(_, d)| d.status == "active")
                .map(|(eid, d)| (d.id, eid))
                .collect();
            let ids: Vec<Uuid> = active.iter().map(|(id, _)| *id).collect();
            let memberships = store.wg_device_memberships_for(tenant, &ids).await?;
            let without: Vec<Uuid> = ids
                .iter()
                .filter(|id| !memberships.contains_key(id))
                .copied()
                .collect();
            let stale: HashSet<Uuid> = if without.is_empty() {
                HashSet::new()
            } else {
                store
                    .wg_stale_devices(&without)
                    .await?
                    .into_iter()
                    .collect()
            };
            Ok::<_, dhonomos_store::StoreError>((active, memberships, stale))
        }
        .await;
        let (active, memberships, stale) = match swept {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "WireGuard: the sweep could not read the memberships");
                return;
            }
        };
        let now = OffsetDateTime::now_utc();
        for (device, eid) in active {
            let stale_only = match memberships.get(&device) {
                Some(m) if self.inner.wg.sweep_due(m, now) => false,
                Some(_) => continue,
                None if stale.contains(&device) => true,
                None => continue,
            };
            if self
                .inner
                .wg
                .start_due(device, stale_only, &crate::wireguard::now_text())
                .await
            {
                self.spawn_drain(device, eid);
            }
        }
    }
}

impl WgHost for UspService {
    async fn wg_store_read(
        &self,
        device: Uuid,
        params: Vec<ParamUpdate>,
    ) -> Result<(), dhonomos_store::StoreError> {
        let written = self
            .inner
            .store
            .upsert_params(device, &params)
            .await
            .inspect_err(|e| param_store::report_failure(device, "usp", e))?;
        param_store::report_rejected(device, "usp", &written.rejected);
        Ok(())
    }
}

/// Object with the identity parameters of an Agent.
const DEVICE_INFO: &str = "Device.DeviceInfo.";

/// Parameters of [`DEVICE_INFO`] read at every connection, by name.
/// [`device_info`] maps them to the registry entry (a test keeps both in step).
const IDENTITY_PARAMS: [&str; 7] = [
    "Manufacturer",
    "ManufacturerOUI",
    "ProductClass",
    "SerialNumber",
    "ModelName",
    "SoftwareVersion",
    "HardwareVersion",
];

/// Full paths of [`IDENTITY_PARAMS`].
fn identity_paths() -> Vec<String> {
    IDENTITY_PARAMS
        .iter()
        .map(|name| format!("{DEVICE_INFO}{name}"))
        .collect()
}

/// Registry entry of an Agent. `get` = identity parameter by name (see [`IDENTITY_PARAMS`]).
fn device_info(get: impl Fn(&str) -> Option<String>) -> DeviceInfo {
    DeviceInfo {
        manufacturer: get("Manufacturer"),
        oui: get("ManufacturerOUI"),
        product_class: get("ProductClass"),
        serial_number: get("SerialNumber"),
        model_name: get("ModelName"),
        software_version: get("SoftwareVersion"),
        hardware_version: get("HardwareVersion"),
        data_model: Some("Device".into()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use dhonomos_usp_proto::msg::{self, request::ReqType};

    use super::{
        DEVICE_INFO, IDENTITY_PARAMS, device_info, endpoint_oui, firmware_fingerprint,
        identity_paths, reads_whole_model,
    };

    fn device(version: Option<&str>) -> dhonomos_store::Device {
        dhonomos_store::Device {
            id: uuid::Uuid::now_v7(),
            tenant_id: dhonomos_store::DEFAULT_TENANT,
            protocol: "usp".into(),
            oui: Some("00AA00".into()),
            product_class: "Box".into(),
            serial_number: Some("U1".into()),
            endpoint_id: Some("os::00AA00-U1".into()),
            manufacturer: Some("Acme".into()),
            model_name: Some("B1".into()),
            software_version: version.map(Into::into),
            hardware_version: None,
            data_model: Some("Device".into()),
            connection_request_url: None,
            cwmp_version: None,
            status: "active".into(),
            tags: Vec::new(),
            first_seen_at: time::OffsetDateTime::now_utc(),
            last_contact_at: None,
            last_boot_at: None,
            last_remote_addr: None,
            attributes: serde_json::json!({}),
            usp_ws_url: None,
            xmpp_connected_at: None,
            udp_cr_address: None,
            udp_cr_seen_at: None,
            last_wake_at: None,
            last_wake_method: None,
            last_wake_outcome: None,
        }
    }

    #[test]
    fn fingerprint_needs_a_software_version() {
        // Unknown firmware shares nothing: no fingerprint -> no cache entry to collide on.
        for unknown in [None, Some(""), Some("  ")] {
            assert_eq!(firmware_fingerprint(&device(unknown)), None, "{unknown:?}");
        }
        let a = firmware_fingerprint(&device(Some("1.0"))).unwrap();
        let b = firmware_fingerprint(&device(Some("1.1"))).unwrap();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b, "builds are told apart by their version");
        // Same firmware, other unit -> same fingerprint (= what is shared).
        assert_eq!(firmware_fingerprint(&device(Some("1.0"))).unwrap(), a);
    }

    #[test]
    fn the_connect_read_names_the_identity_parameters_and_nothing_else() {
        let paths = identity_paths();
        assert_eq!(
            paths,
            [
                "Device.DeviceInfo.Manufacturer",
                "Device.DeviceInfo.ManufacturerOUI",
                "Device.DeviceInfo.ProductClass",
                "Device.DeviceInfo.SerialNumber",
                "Device.DeviceInfo.ModelName",
                "Device.DeviceInfo.SoftwareVersion",
                "Device.DeviceInfo.HardwareVersion",
            ]
        );
        // Parameters, not an object -> no DeviceLog or ProcessStatus along.
        for p in &paths {
            assert!(p.starts_with(DEVICE_INFO) && !p.ends_with('.'), "{p}");
            assert_ne!(p, DEVICE_INFO);
        }
        let get = ReqType::Get(msg::Get {
            param_paths: paths,
            max_depth: 0,
        });
        assert!(!reads_whole_model(&get));
    }

    #[test]
    fn every_identity_parameter_is_looked_up_once_and_fills_its_own_field() {
        // Read list + registry mapping cannot drift apart.
        let asked = std::cell::RefCell::new(Vec::new());
        let info = device_info(|name| {
            asked.borrow_mut().push(name.to_owned());
            Some(format!("<{name}>"))
        });
        assert_eq!(asked.into_inner(), IDENTITY_PARAMS);
        let field = |v: Option<String>| v.unwrap();
        assert_eq!(field(info.manufacturer), "<Manufacturer>");
        assert_eq!(field(info.oui), "<ManufacturerOUI>");
        assert_eq!(field(info.product_class), "<ProductClass>");
        assert_eq!(field(info.serial_number), "<SerialNumber>");
        assert_eq!(field(info.model_name), "<ModelName>");
        assert_eq!(field(info.software_version), "<SoftwareVersion>");
        assert_eq!(field(info.hardware_version), "<HardwareVersion>");
        assert_eq!(info.data_model.as_deref(), Some("Device"));
    }

    #[test]
    fn oui_from_endpoint_ids() {
        assert_eq!(endpoint_oui("os::B01408-B01408123456"), Some("B01408"));
        assert_eq!(
            endpoint_oui("oui:00256D:my-unique-bbf-id-42"),
            Some("00256D")
        );
        assert_eq!(endpoint_oui("proto::agent-1"), None);
        assert_eq!(endpoint_oui("os::012345-000000000000"), Some("012345"));
        assert_eq!(endpoint_oui("os::XYZ-1"), None);
    }

    #[test]
    fn only_requests_for_the_whole_model_are_full_reads() {
        let get = |paths: &[&str]| {
            ReqType::Get(msg::Get {
                param_paths: paths.iter().map(|p| (*p).to_owned()).collect(),
                max_depth: 0,
            })
        };
        let gsdm = |paths: &[&str]| {
            ReqType::GetSupportedDm(msg::GetSupportedDm {
                obj_paths: paths.iter().map(|p| (*p).to_owned()).collect(),
                ..Default::default()
            })
        };
        // Root object, alone or among others.
        assert!(reads_whole_model(&get(&["Device."])));
        assert!(reads_whole_model(&get(&["Device"])));
        assert!(reads_whole_model(&get(&["Device.DeviceInfo.", "Device."])));
        assert!(reads_whole_model(&gsdm(&["Device."])));
        // Anything below it -> ordinary request.
        assert!(!reads_whole_model(&get(&["Device.DeviceInfo."])));
        assert!(!reads_whole_model(&get(&[
            "Device.DeviceInfo.SoftwareVersion"
        ])));
        assert!(!reads_whole_model(&get(&[
            "Device.LocalAgent.Subscription."
        ])));
        assert!(!reads_whole_model(&get(&["Devices."])));
        assert!(!reads_whole_model(&get(&[])));
        assert!(!reads_whole_model(&gsdm(&["Device.WiFi."])));
        // Other requests -> never full reads.
        assert!(!reads_whole_model(&ReqType::Set(msg::Set::default())));
        assert!(!reads_whole_model(&ReqType::GetInstances(
            msg::GetInstances::default()
        )));
    }
}
