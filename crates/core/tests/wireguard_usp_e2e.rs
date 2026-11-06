//! E2E: WireGuard on USP Agents (ADR-110 stage 4).
//! USP service on its embedded STOMP broker + PostgreSQL + scripted Agent.
//! Agent WireGuard + IP layer = fake CPE of `dhonomos_wireguard`.
//! Device planner configures `Device.WireGuard.` on connect, at boot + from periodic sweep
//! -> each member records the result.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dhonomos_core::{Presets, SecretBox, UspConfig, UspService};
use dhonomos_store::{
    DEFAULT_TENANT, NewWgMember, NewWgMemberKind, NewWgNetwork, Store, Task, WgMember,
    WgPrefixChoice, WgSitePrefix, WgVisibility,
};
use dhonomos_usp_mtp::stomp::{Frame, Parsed, USP_CONTENT_TYPE};
use dhonomos_usp_proto::msg::{self, body::MsgBody, request::ReqType, response::RespType};
use dhonomos_usp_proto::record::{self, record::RecordType};
use dhonomos_usp_proto::{ErrorCode, UspVersion, builder};
use dhonomos_wireguard::fake::{FakeDevice, FakeError, FakeOptions};
use dhonomos_wireguard::{
    DesiredTunnel, Ipv4Prefix, KeyMode, alias_of, desired_hash, generate_keypair,
    public_from_private,
};
use prost::Message as _;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use uuid::Uuid;

const CTRL: &str = "self::dhonomos-wg-test";
const ORIGIN: &str = "system:wireguard";
const HUB_HOST: &str = "hub.example.net";
const EID_A: &str = "os::00AA00-WGA";
const EID_B: &str = "os::00AA00-WGB";
/// Sweep interval in these tests.
const SWEEP: Duration = Duration::from_secs(1);
const ALL: WgVisibility<'static> = WgVisibility {
    all_clients: true,
    user_id: None,
    scope: None,
};

fn secrets() -> Arc<SecretBox> {
    Arc::new(SecretBox::from_base64("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "k1").unwrap())
}

fn p(s: &str) -> Ipv4Prefix {
    s.parse().unwrap()
}

/// (b): firmware makes tunnel interface + IP interface; device makes its key.
fn firmware_b() -> FakeOptions {
    FakeOptions {
        tunnel_interface_made: true,
        firmware_ip_interface: true,
        makes_key: true,
        supported: true,
        regenerates_key: false,
        ip_interface_later: false,
        ip_lower_layers_empty: false,
    }
}

/// (a): firmware makes no interface.
fn firmware_a() -> FakeOptions {
    FakeOptions {
        tunnel_interface_made: false,
        firmware_ip_interface: false,
        makes_key: true,
        supported: true,
        regenerates_key: false,
        ip_interface_later: false,
        ip_lower_layers_empty: false,
    }
}

/// LS500X: like (b), but IP interface of a new tunnel only some time after Add commit
/// ([`AgentState::derive_after`]).
fn ls500x() -> FakeOptions {
    FakeOptions {
        ip_interface_later: true,
        ..firmware_b()
    }
}

/// USP service + DB + hub + network 10.77.0.0/24 + 2 member Agents.
/// A: 192.168.10.0/24 behind it. B: 192.168.20.0/24. Only A connects.
struct World {
    _container: ContainerAsync<Postgres>,
    store: Store,
    svc: UspService,
    broker: std::net::SocketAddr,
    hub: Uuid,
    network: Uuid,
    a: Uuid,
    ma: Uuid,
    mb: Uuid,
}

async fn world(with_secrets: bool, key_mode: &str) -> World {
    world_with(
        with_secrets,
        key_mode,
        dhonomos_core::DEFAULT_WG_INCOMPLETE_RETRY,
        Duration::from_secs(5),
    )
    .await
}

/// [`world`] + sweep wait after a run without outcome + request timeout.
async fn world_with(
    with_secrets: bool,
    key_mode: &str,
    incomplete_retry: Duration,
    request_timeout: Duration,
) -> World {
    let container = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let store = Store::connect(
        &format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres"),
        4,
    )
    .await
    .unwrap();
    store.migrate().await.unwrap();
    let svc = UspService::start(
        store.clone(),
        UspConfig {
            mqtt: None,
            websocket: false,
            onboarding: dhonomos_core::Onboarding::default(),
            stomp: Some(dhonomos_usp_mtp::StompConfig::default()),
            mqtt_broker: None,
            metrics: None,
            files: None,
            secrets: with_secrets.then(secrets),
            ws_client_tls: None,
            auto_subscribe: false,
            wg_sweep_interval: SWEEP,
            wg_incomplete_retry: incomplete_retry,
            wg_ip_poll_interval: Duration::from_millis(100),
            wg_ip_poll_limit: 5,
            endpoint_id: CTRL.into(),
            request_timeout,
            full_read_timeout: Duration::from_secs(5),
            tenant_id: DEFAULT_TENANT,
            presets: Presets::default().into(),
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker = listener.local_addr().unwrap();
    let mtp = svc.stomp_mtp().unwrap().clone();
    tokio::spawn(async move {
        mtp.serve(listener, None, std::future::pending())
            .await
            .unwrap()
    });

    let hub_key = generate_keypair().unwrap().public;
    let hub = store
        .create_wg_hub(DEFAULT_TENANT, "lab", HUB_HOST)
        .await
        .unwrap()
        .unwrap()
        .id;
    store.set_wg_hub_public_key(hub, &hub_key).await.unwrap();
    let network = store
        .create_wg_network(
            DEFAULT_TENANT,
            &NewWgNetwork {
                hub_id: hub,
                name: "sites".into(),
                prefix: WgPrefixChoice::Explicit(p("10.77.0.0/24")),
                listen_port: Some(51820),
                mtu: 1420,
                persistent_keepalive: 25,
            },
        )
        .await
        .unwrap()
        .unwrap()
        .id;
    let mut ids = Vec::new();
    for (eid, site) in [(EID_A, "192.168.10.0/24"), (EID_B, "192.168.20.0/24")] {
        let device = store
            .upsert_usp_device(DEFAULT_TENANT, eid, None)
            .await
            .unwrap()
            .id;
        let member = store
            .create_wg_member(
                DEFAULT_TENANT,
                network,
                &NewWgMember {
                    id: Uuid::now_v7(),
                    psk: None,
                    name: format!("cpe-{eid}"),
                    kind: NewWgMemberKind::Device {
                        device_id: device,
                        key_mode: key_mode.into(),
                    },
                    site_prefixes: vec![WgSitePrefix {
                        prefix: p(site),
                        description: String::new(),
                    }],
                },
                time::Duration::hours(24),
            )
            .await
            .unwrap()
            .unwrap()
            .id;
        ids.push((device, member));
    }
    World {
        _container: container,
        store,
        svc,
        broker,
        hub,
        network,
        a: ids[0].0,
        ma: ids[0].1,
        mb: ids[1].1,
    }
}

/// State of the scripted Agent + what it saw.
struct AgentState {
    fake: FakeDevice,
    /// Controller requests: `get <paths>`, `set <path>=<value>,...`,
    /// `add <table> <param>=<value>,...`, `delete <object>`.
    /// Secret values (private keys, non-empty pre-shared keys) -> `<secret>`.
    log: Vec<String>,
    /// Refuse every Delete.
    refuse_delete: bool,
    /// Drop next Get of `Device.WireGuard.`, never answer it.
    drop_next_wg_get: bool,
    /// Arrival time of each Get of `Device.WireGuard.`.
    wg_gets: Vec<tokio::time::Instant>,
    /// Hold every Get of `Device.WireGuard.` unanswered (logged with ` (held)`)
    /// until [`Agent::release`].
    hold_wg_gets: bool,
    /// Held requests (message ID, request), oldest first.
    held: Vec<(String, ReqType)>,
    /// Firmware makes the IP interface of a new tunnel ([`FakeDevice::derive`]) before
    /// the answer to Get N of `Device.IP.Interface.` after a Tunnel Add.
    /// 0 = right after the Add response; None = never.
    derive_after: Option<usize>,
    /// Arrival time of each Get of `Device.IP.Interface.` after the last Tunnel Add.
    /// None before any Tunnel Add.
    ip_gets: Option<Vec<tokio::time::Instant>>,
}

/// USP Agent on the embedded STOMP broker. WireGuard + IP layer = [`FakeDevice`].
struct Agent {
    state: Arc<Mutex<AgentState>>,
    outbox: tokio::sync::mpsc::UnboundedSender<msg::Msg>,
}

impl Agent {
    fn spawn(broker: std::net::SocketAddr, eid: &str, opts: FakeOptions) -> Self {
        Self::start(broker, eid, opts, false, None)
    }

    /// [`Agent::spawn`] with [`AgentState::derive_after`].
    fn spawn_deriving(
        broker: std::net::SocketAddr,
        eid: &str,
        opts: FakeOptions,
        derive_after: Option<usize>,
    ) -> Self {
        Self::start(broker, eid, opts, false, derive_after)
    }

    /// [`Agent::spawn`]; Agent drops its first Get of `Device.WireGuard.`.
    fn spawn_dropping_first_wg_get(
        broker: std::net::SocketAddr,
        eid: &str,
        opts: FakeOptions,
    ) -> Self {
        Self::start(broker, eid, opts, true, None)
    }

    /// [`Agent::spawn`]; WireGuard + IP layer = `fake`.
    fn spawn_with(broker: std::net::SocketAddr, eid: &str, fake: FakeDevice) -> Self {
        Self::start_with(broker, eid, fake, false, None)
    }

    fn start(
        broker: std::net::SocketAddr,
        eid: &str,
        opts: FakeOptions,
        drop_next_wg_get: bool,
        derive_after: Option<usize>,
    ) -> Self {
        Self::start_with(
            broker,
            eid,
            FakeDevice::new(opts),
            drop_next_wg_get,
            derive_after,
        )
    }

    fn start_with(
        broker: std::net::SocketAddr,
        eid: &str,
        fake: FakeDevice,
        drop_next_wg_get: bool,
        derive_after: Option<usize>,
    ) -> Self {
        let state = Arc::new(Mutex::new(AgentState {
            fake,
            log: Vec::new(),
            refuse_delete: false,
            drop_next_wg_get,
            wg_gets: Vec::new(),
            hold_wg_gets: false,
            held: Vec::new(),
            derive_after,
            ip_gets: None,
        }));
        let (outbox, outgoing) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(run_agent(broker, eid.to_owned(), state.clone(), outgoing));
        Self { state, outbox }
    }

    fn with<T>(&self, f: impl FnOnce(&mut AgentState) -> T) -> T {
        f(&mut self.state.lock().unwrap())
    }

    /// WireGuard requests seen (about `Device.WireGuard.` or `Device.IP.Interface.`).
    fn wg_log(&self) -> Vec<String> {
        self.with(|s| {
            s.log
                .iter()
                .filter(|l| l.contains("Device.WireGuard.") || l.contains("Device.IP.Interface."))
                .cloned()
                .collect()
        })
    }

    /// Instance of `table` with our Alias for `network` on the device.
    fn instance(&self, table: &str, network: Uuid) -> Option<String> {
        let alias = alias_of(network);
        let tree = self.with(|s| s.fake.read(table)).ok()?;
        tree.iter()
            .find(|(k, p)| {
                k.ends_with(".Alias")
                    && p.value == alias
                    && k[table.len()..].matches('.').count() == 1
            })
            .map(|(k, _)| k.trim_end_matches("Alias").to_owned())
    }

    fn value(&self, path: &str) -> String {
        self.with(|s| s.fake.value(path).map(str::to_owned))
            .unwrap_or_else(|| panic!("no {path}"))
    }

    /// Any row with one of our aliases left on the device.
    fn has_our_rows(&self) -> bool {
        self.with(|s| {
            ["Device.WireGuard.", "Device.IP.Interface."]
                .iter()
                .filter_map(|t| s.fake.read(t).ok())
                .flatten()
                .any(|(k, p)| k.ends_with(".Alias") && p.value.starts_with("dhonomos-wg-"))
        })
    }

    /// Hold every Get of `Device.WireGuard.` from now on, until [`Agent::release`].
    fn hold_wg_gets(&self) {
        self.with(|s| s.hold_wg_gets = true);
    }

    /// Stop holding -> Agent answers the held Gets, in order.
    fn release(&self) {
        self.with(|s| s.hold_wg_gets = false);
    }

    /// Count of held Gets of `Device.WireGuard.`.
    fn held(&self) -> usize {
        self.with(|s| s.held.len())
    }

    /// Send a Boot! notification with this `Cause`.
    fn boot(&self, cause: &str) {
        let notify = builder::request(
            format!("boot-{cause}"),
            ReqType::Notify(msg::Notify {
                subscription_id: "dhonomos-boot".into(),
                send_resp: false,
                notification: Some(msg::notify::Notification::Event(msg::notify::Event {
                    obj_path: "Device.".into(),
                    event_name: "Boot!".into(),
                    params: [
                        ("Cause", cause),
                        ("CommandKey", ""),
                        ("FirmwareUpdated", "false"),
                    ]
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
                })),
            }),
        );
        self.outbox.send(notify).unwrap();
    }
}

/// Minimal STOMP 1.2 client.
struct StompClient {
    tcp: tokio::net::TcpStream,
    buf: Vec<u8>,
}

impl StompClient {
    async fn send(&mut self, f: &Frame) {
        self.tcp.write_all(&f.encode()).await.unwrap();
    }

    /// Next frame within `wait`. `Err` = none came; `None` = broker closed.
    async fn next_within(
        &mut self,
        wait: Duration,
    ) -> Result<Option<Frame>, tokio::time::error::Elapsed> {
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            match Frame::parse(&self.buf, 16 << 20).unwrap() {
                Parsed::Heartbeat(n) => {
                    self.buf.drain(..n);
                    continue;
                }
                Parsed::Frame(f, n) => {
                    self.buf.drain(..n);
                    return Ok(Some(f));
                }
                Parsed::Incomplete => {}
            }
            let n = tokio::time::timeout(wait, self.tcp.read(&mut chunk))
                .await?
                .unwrap();
            if n == 0 {
                return Ok(None);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

const VERSION: UspVersion = UspVersion { major: 1, minor: 3 };

fn record_frame(r: record::Record) -> Frame {
    let mut f = Frame::new(
        "SEND",
        &[
            ("destination", "/queue/usp.controller"),
            ("content-type", USP_CONTENT_TYPE),
        ],
    );
    f.body = r.encode_to_vec().into();
    f
}

async fn run_agent(
    broker: std::net::SocketAddr,
    eid: String,
    state: Arc<Mutex<AgentState>>,
    mut outgoing: tokio::sync::mpsc::UnboundedReceiver<msg::Msg>,
) {
    let mut agent = StompClient {
        tcp: tokio::net::TcpStream::connect(broker).await.unwrap(),
        buf: Vec::new(),
    };
    agent
        .send(&Frame::new(
            "STOMP",
            &[("accept-version", "1.2"), ("endpoint-id", &eid)],
        ))
        .await;
    let connected = agent
        .next_within(Duration::from_secs(10))
        .await
        .unwrap()
        .unwrap();
    let dest = connected.header("subscribe-dest").unwrap().to_owned();
    agent
        .send(&Frame::new(
            "SUBSCRIBE",
            &[("id", "0"), ("destination", &dest)],
        ))
        .await;
    agent
        .send(&record_frame(builder::stomp_connect_record(
            VERSION, &eid, CTRL, &dest,
        )))
        .await;
    loop {
        while let Ok(n) = outgoing.try_recv() {
            agent
                .send(&record_frame(builder::no_session_record(
                    VERSION, &eid, CTRL, &n,
                )))
                .await;
        }
        // Released -> held requests answered, in order.
        // Logged on arrival -> still one log line each.
        let released: Vec<msg::Msg> = {
            let mut s = state.lock().unwrap();
            if s.hold_wg_gets {
                Vec::new()
            } else {
                std::mem::take(&mut s.held)
                    .into_iter()
                    .map(|(id, req)| {
                        let n = s.log.len();
                        let reply = answer_from_fake(&mut s, &id, req);
                        s.log.truncate(n);
                        reply
                    })
                    .collect()
            }
        };
        for reply in released {
            agent
                .send(&record_frame(builder::no_session_record(
                    VERSION, &eid, CTRL, &reply,
                )))
                .await;
        }
        let Ok(next) = agent.next_within(Duration::from_millis(50)).await else {
            continue;
        };
        let Some(frame) = next else { return };
        let rec = record::Record::decode(frame.body).unwrap();
        let Some(RecordType::NoSessionContext(ns)) = rec.record_type else {
            continue;
        };
        let m = msg::Msg::decode(ns.payload.as_slice()).unwrap();
        let id = m.header.as_ref().unwrap().msg_id.clone();
        let Some(MsgBody::Request(req)) = m.body.and_then(|b| b.msg_body) else {
            continue;
        };
        let Some(reply) = answer(&mut state.lock().unwrap(), &id, req.req_type.unwrap()) else {
            continue;
        };
        agent
            .send(&record_frame(builder::no_session_record(
                VERSION, &eid, CTRL, &reply,
            )))
            .await;
    }
}

/// Identity parameters of the Agent.
fn identity(param: &str) -> Option<&'static str> {
    Some(match param {
        "Manufacturer" => "Acme",
        "ManufacturerOUI" => "00AA00",
        "ProductClass" => "WgBox",
        "SerialNumber" => "WG1",
        "ModelName" => "Model-W",
        "SoftwareVersion" => "1.0",
        "HardwareVersion" => "HW-1",
        _ => return None,
    })
}

/// Requested path the Agent does not have.
fn invalid_path(path: &str) -> msg::get_resp::RequestedPathResult {
    msg::get_resp::RequestedPathResult {
        requested_path: path.to_owned(),
        err_code: 7026,
        err_msg: "Invalid path".into(),
        resolved_path_results: Vec::new(),
    }
}

fn agent_error(id: &str, e: &FakeError) -> msg::Msg {
    let code = match e {
        FakeError::NotWritable(_) => ErrorCode::PARAMETER_READ_ONLY,
        FakeError::NotFound(_) | FakeError::Unsupported => ErrorCode(7026),
    };
    builder::error(id, code, e.to_string())
}

/// Answer one request from the fake device. `None` = request dropped unanswered.
fn answer(s: &mut AgentState, id: &str, req: ReqType) -> Option<msg::Msg> {
    if let ReqType::Get(g) = &req
        && g.param_paths.iter().any(|p| p == "Device.WireGuard.")
    {
        s.wg_gets.push(tokio::time::Instant::now());
        if std::mem::take(&mut s.drop_next_wg_get) {
            s.log
                .push(format!("get {} (dropped)", g.param_paths.join(",")));
            return None;
        }
    }
    if s.hold_wg_gets
        && let ReqType::Get(g) = &req
        && g.param_paths.iter().any(|p| p == "Device.WireGuard.")
    {
        s.log
            .push(format!("get {} (held)", g.param_paths.join(",")));
        s.held.push((id.to_owned(), req));
        return None;
    }
    if let ReqType::Get(g) = &req
        && g.param_paths.iter().any(|p| p == "Device.IP.Interface.")
        && let Some(gets) = &mut s.ip_gets
    {
        gets.push(tokio::time::Instant::now());
        if s.derive_after == Some(gets.len()) {
            s.fake.derive();
        }
    }
    let adds_tunnel = matches!(&req, ReqType::Add(a)
        if a.create_objs.iter().any(|o| o.obj_path == "Device.WireGuard.Tunnel."));
    let reply = answer_from_fake(s, id, req);
    if adds_tunnel {
        s.ip_gets = Some(Vec::new());
        if s.derive_after == Some(0) {
            s.fake.derive();
        }
    }
    Some(reply)
}

fn answer_from_fake(s: &mut AgentState, id: &str, req: ReqType) -> msg::Msg {
    match req {
        ReqType::Get(g) => {
            s.log.push(format!("get {}", g.param_paths.join(",")));
            let results = g
                .param_paths
                .iter()
                .map(|path| {
                    if path == "Device." {
                        return msg::get_resp::RequestedPathResult {
                            requested_path: path.clone(),
                            err_code: 0,
                            err_msg: String::new(),
                            resolved_path_results: vec![msg::get_resp::ResolvedPathResult {
                                resolved_path: "Device.DeviceInfo.".into(),
                                result_params: [("UpTime".to_owned(), "12".to_owned())].into(),
                            }],
                        };
                    }
                    if let Some(param) = path.strip_prefix("Device.DeviceInfo.") {
                        return match identity(param) {
                            Some(v) => msg::get_resp::RequestedPathResult {
                                requested_path: path.clone(),
                                err_code: 0,
                                err_msg: String::new(),
                                resolved_path_results: vec![msg::get_resp::ResolvedPathResult {
                                    resolved_path: "Device.DeviceInfo.".into(),
                                    result_params: [(param.to_owned(), v.to_owned())].into(),
                                }],
                            },
                            None => invalid_path(path),
                        };
                    }
                    let Ok(tree) = s.fake.read(path) else {
                        return invalid_path(path);
                    };
                    // One resolved path per object; its parameters by name.
                    let mut objects: BTreeMap<String, HashMap<String, String>> = BTreeMap::new();
                    for (full, param) in tree {
                        let (object, name) = full.split_at(full.rfind('.').unwrap() + 1);
                        objects
                            .entry(object.to_owned())
                            .or_default()
                            .insert(name.to_owned(), param.value);
                    }
                    msg::get_resp::RequestedPathResult {
                        requested_path: path.clone(),
                        err_code: 0,
                        err_msg: String::new(),
                        resolved_path_results: objects
                            .into_iter()
                            .map(|(resolved_path, result_params)| {
                                msg::get_resp::ResolvedPathResult {
                                    resolved_path,
                                    result_params,
                                }
                            })
                            .collect(),
                    }
                })
                .collect();
            builder::response(
                id,
                RespType::GetResp(msg::GetResp {
                    req_path_results: results,
                }),
            )
        }
        ReqType::Set(set) => {
            let pairs: Vec<(String, String)> = set
                .update_objs
                .iter()
                .flat_map(|o| {
                    o.param_settings
                        .iter()
                        .map(|p| (format!("{}{}", o.obj_path, p.param), p.value.clone()))
                })
                .collect();
            s.log.push(format!(
                "set {}",
                pairs
                    .iter()
                    .map(|(k, v)| {
                        if k.ends_with("PrivateKey")
                            || (k.ends_with("PresharedKey") && !v.is_empty())
                        {
                            format!("{k}=<secret>")
                        } else {
                            format!("{k}={v}")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            ));
            match s.fake.set(&pairs) {
                Ok(()) => builder::response(id, RespType::SetResp(msg::SetResp::default())),
                Err(e) => agent_error(id, &e),
            }
        }
        ReqType::Add(add) => {
            use msg::add_resp::created_object_result::{OperationStatus, operation_status};
            let mut results = Vec::new();
            for o in &add.create_objs {
                s.log.push(format!(
                    "add {} {}",
                    o.obj_path,
                    o.param_settings
                        .iter()
                        .map(|p| format!("{}={}", p.param, p.value))
                        .collect::<Vec<_>>()
                        .join(",")
                ));
                let alias = o
                    .param_settings
                    .iter()
                    .find(|p| p.param == "Alias")
                    .map(|p| p.value.clone())
                    .unwrap_or_default();
                match s.fake.add(&o.obj_path, &alias) {
                    Ok(instance) => results.push(msg::add_resp::CreatedObjectResult {
                        requested_path: o.obj_path.clone(),
                        oper_status: Some(OperationStatus {
                            oper_status: Some(operation_status::OperStatus::OperSuccess(
                                operation_status::OperationSuccess {
                                    instantiated_path: instance,
                                    param_errs: vec![],
                                    unique_keys: [("Alias".to_owned(), alias)].into(),
                                },
                            )),
                        }),
                    }),
                    Err(FakeError::NotWritable(_)) => {
                        return builder::error(
                            id,
                            ErrorCode::OBJECT_NOT_CREATED,
                            "Object could not be created",
                        );
                    }
                    Err(e) => return agent_error(id, &e),
                }
            }
            builder::response(
                id,
                RespType::AddResp(msg::AddResp {
                    created_obj_results: results,
                }),
            )
        }
        ReqType::Delete(d) => {
            use msg::delete_resp::deleted_object_result::{OperationStatus, operation_status};
            let mut results = Vec::new();
            for object in &d.obj_paths {
                s.log.push(format!("delete {object}"));
                if s.refuse_delete {
                    return builder::error(id, ErrorCode::REQUEST_DENIED, "Request denied");
                }
                if let Err(e) = s.fake.delete(object) {
                    return agent_error(id, &e);
                }
                results.push(msg::delete_resp::DeletedObjectResult {
                    requested_path: object.clone(),
                    oper_status: Some(OperationStatus {
                        oper_status: Some(operation_status::OperStatus::OperSuccess(
                            operation_status::OperationSuccess {
                                affected_paths: vec![object.clone()],
                                unaffected_path_errs: vec![],
                            },
                        )),
                    }),
                });
            }
            builder::response(
                id,
                RespType::DeleteResp(msg::DeleteResp {
                    deleted_obj_results: results,
                }),
            )
        }
        _ => builder::error(id, ErrorCode::MESSAGE_NOT_SUPPORTED, "not supported"),
    }
}

/// Poll `cond` for max 20 s.
async fn until<F: AsyncFn() -> bool>(what: &str, cond: F) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !cond().await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// WireGuard tasks of the device, oldest first.
async fn wg_tasks(store: &Store, device: Uuid) -> Vec<Task> {
    let mut tasks: Vec<Task> = store
        .list_tasks(device, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|t| t.created_by.as_deref() == Some(ORIGIN))
        .collect();
    tasks.reverse();
    tasks
}

/// No WireGuard task of the device waiting or running?
async fn wg_idle(store: &Store, device: Uuid) -> bool {
    wg_tasks(store, device).await.iter().all(|t| {
        !matches!(
            t.state,
            dhonomos_store::TaskState::Pending | dhonomos_store::TaskState::Running
        )
    })
}

async fn member(store: &Store, id: Uuid) -> WgMember {
    store
        .get_wg_member(DEFAULT_TENANT, id, &ALL)
        .await
        .unwrap()
        .unwrap()
}

/// Wait until the member run recorded `state` + device has no WireGuard task left.
async fn settled(w: &World, member_id: Uuid, state: &str) -> WgMember {
    until(&format!("the member to be {state}"), async || {
        member(&w.store, member_id).await.device_state.as_deref() == Some(state)
            && wg_idle(&w.store, w.a).await
    })
    .await;
    member(&w.store, member_id).await
}

/// Desired state of device A.
async fn desired_a(w: &World, key_mode: KeyMode, others: &[&str]) -> DesiredTunnel {
    let hub_public_key = w
        .store
        .get_wg_hub(DEFAULT_TENANT, w.hub)
        .await
        .unwrap()
        .unwrap()
        .public_key;
    let mut allowed_ips = vec![p("10.77.0.0/24")];
    allowed_ips.extend(others.iter().map(|s| p(s)));
    DesiredTunnel {
        network_id: w.network,
        hub_public_key,
        endpoint_host: HUB_HOST.into(),
        endpoint_port: 51820,
        persistent_keepalive: 25,
        allowed_ips,
        address: member(&w.store, w.ma).await.address,
        prefix: p("10.77.0.0/24"),
        mtu: 1420,
        key_mode,
        member_public_key: None,
        rotate_key: false,
        preshared_key: None,
        send_preshared_key: false,
    }
}

/// Move last check of the member back by `hours`.
async fn age_check(store: &Store, member: Uuid, hours: i32) {
    sqlx::query(
        "UPDATE wg_members SET device_checked_at = now() - make_interval(hours => $2) WHERE id = $1",
    )
    .bind(member)
    .bind(hours)
    .execute(store.pool())
    .await
    .unwrap();
}

/// `needle` anywhere in tasks, events, audit log or snapshot?
async fn stored_anywhere(store: &Store, needle: &str) -> bool {
    let mut found = false;
    for sql in [
        "SELECT count(*) FROM tasks WHERE payload::text LIKE '%' || $1 || '%' OR coalesce(result::text, '') LIKE '%' || $1 || '%' OR coalesce(error, '') LIKE '%' || $1 || '%' OR trace::text LIKE '%' || $1 || '%'",
        "SELECT count(*) FROM events WHERE detail::text LIKE '%' || $1 || '%'",
        "SELECT count(*) FROM audit_log WHERE row_to_json(audit_log)::text LIKE '%' || $1 || '%'",
        "SELECT count(*) FROM device_params WHERE coalesce(value, '') LIKE '%' || $1 || '%'",
    ] {
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(needle)
            .fetch_one(store.pool())
            .await
            .unwrap();
        found |= n > 0;
    }
    found
}

/// Peers the hub runs for the network: (public key, allowed IPs).
async fn hub_peers(w: &World) -> Vec<(String, Vec<Ipv4Prefix>)> {
    let state = w.store.wg_hub_state(w.hub).await.unwrap().unwrap();
    state
        .networks
        .into_iter()
        .flat_map(|n| n.peers)
        .map(|p| (p.public_key, p.allowed_ips))
        .collect()
}

/// WireGuard requests the Agent saw after the first `from`.
fn since(agent: &Agent, from: usize) -> Vec<String> {
    agent.wg_log()[from..].to_vec()
}

#[tokio::test]
async fn device_key_mode_converges_on_connect_and_the_sweep_repairs_follows_and_cleans_up() {
    let w = world(false, "device").await;
    let agent = Agent::spawn(w.broker, EID_A, firmware_b());

    // 1. Connect -> converged.
    let ma = settled(&w, w.ma, "applied").await;
    let peer = agent.instance("Device.WireGuard.Peer.", w.network).unwrap();
    let tunnel = agent
        .instance("Device.WireGuard.Tunnel.", w.network)
        .unwrap();
    assert_eq!(agent.value(&format!("{peer}EndpointAddress")), HUB_HOST);
    assert_eq!(agent.value(&format!("{peer}EndpointPort")), "51820");
    assert_eq!(
        agent.value(&format!("{peer}AllowedIPs")),
        "10.77.0.0/24,192.168.20.0/24"
    );
    assert_eq!(agent.value(&format!("{peer}Enable")), "true");
    assert_eq!(agent.value(&format!("{tunnel}Enable")), "true");
    assert_eq!(
        agent.value("Device.IP.Interface.2.IPv4Address.1.IPAddress"),
        ma.address.to_string()
    );
    assert_eq!(agent.value("Device.IP.Interface.1.Alias"), "cpe-lan");
    let device_key = agent.value(&format!("{tunnel}PublicKey"));
    assert!(!device_key.is_empty());
    assert_eq!(ma.device_detail, None);
    let want = desired_a(&w, KeyMode::Device, &["192.168.20.0/24"]).await;
    assert_eq!(ma.device_applied_hash, Some(desired_hash(&want)));
    assert_eq!(ma.public_key.as_deref(), Some(device_key.as_str()));
    let a32 = Ipv4Prefix::new(ma.address, 32).unwrap();
    assert_eq!(
        hub_peers(&w).await,
        [(device_key.clone(), vec![a32, p("192.168.10.0/24")])]
    );
    // Adds carried the Alias -> no Set of an Alias after them.
    let alias = alias_of(w.network);
    let adds: Vec<String> = agent
        .wg_log()
        .into_iter()
        .filter(|l| l.starts_with("add "))
        .collect();
    assert_eq!(
        adds,
        [
            format!("add Device.WireGuard.Peer. Alias={alias}"),
            format!("add Device.WireGuard.Tunnel. Alias={alias}"),
        ]
    );
    assert!(!agent.wg_log().iter().any(|l| l.contains(".Alias=")));
    let tasks = wg_tasks(&w.store, w.a).await;
    assert!(
        tasks
            .iter()
            .filter(|t| t.state != dhonomos_store::TaskState::Cancelled)
            .all(|t| t.state == dhonomos_store::TaskState::Succeeded && t.max_attempts == 1),
        "{tasks:?}"
    );

    // 3. Drift: unnoticed until the check is due -> then 1 read + 1 set.
    let port = format!("{peer}EndpointPort");
    agent.with(|s| s.fake.set(&[(port.clone(), "1".to_owned())]).unwrap());
    let mark = agent.wg_log().len();
    tokio::time::sleep(SWEEP * 3).await;
    assert_eq!(since(&agent, mark), Vec::<String>::new());
    age_check(&w.store, w.ma, 7).await;
    until("the drift to be repaired", async || {
        agent.value(&port) == "51820" && wg_idle(&w.store, w.a).await
    })
    .await;
    assert_eq!(
        since(&agent, mark),
        [
            "get Device.WireGuard.,Device.IP.Interface.".to_owned(),
            format!("set {port}=51820"),
        ]
    );
    let ma = settled(&w, w.ma, "applied").await;
    assert_eq!(ma.device_applied_hash, Some(desired_hash(&want)));

    // 4. Desired state change while connected (B: new site prefix).
    let mark = agent.wg_log().len();
    w.store
        .update_wg_member(
            DEFAULT_TENANT,
            w.mb,
            None,
            Some(&[
                WgSitePrefix {
                    prefix: p("192.168.20.0/24"),
                    description: String::new(),
                },
                WgSitePrefix {
                    prefix: p("192.168.21.0/24"),
                    description: String::new(),
                },
            ]),
            None,
        )
        .await
        .unwrap()
        .unwrap();
    let want = desired_a(&w, KeyMode::Device, &["192.168.20.0/24", "192.168.21.0/24"]).await;
    until("the change to be applied", async || {
        member(&w.store, w.ma).await.device_applied_hash == Some(desired_hash(&want))
            && wg_idle(&w.store, w.a).await
    })
    .await;
    let sets: Vec<String> = since(&agent, mark)
        .into_iter()
        .filter(|l| l.starts_with("set "))
        .collect();
    assert_eq!(
        sets,
        [format!(
            "set {peer}AllowedIPs=10.77.0.0/24,192.168.20.0/24,192.168.21.0/24,{peer}PresharedKey="
        )],
        "the desired state changed: the pre-shared key (\"\" for none) goes with it"
    );
    assert_eq!(
        member(&w.store, w.ma).await.device_state.as_deref(),
        Some("applied")
    );

    // 5. A revoked -> sweep deletes its rows.
    let mark = agent.wg_log().len();
    w.store
        .revoke_wg_member(DEFAULT_TENANT, w.ma, None)
        .await
        .unwrap()
        .unwrap();
    until("our rows to go", async || {
        !agent.has_our_rows() && wg_idle(&w.store, w.a).await
    })
    .await;
    let deleted: Vec<String> = since(&agent, mark)
        .into_iter()
        .filter(|l| l.starts_with("delete "))
        .collect();
    assert_eq!(
        deleted,
        [format!("delete {tunnel}"), format!("delete {peer}")],
        "the IP interface was the firmware's"
    );
    assert_eq!(agent.value("Device.IP.Interface.1.Alias"), "cpe-lan");
    // Nothing of ours left -> nothing more happens.
    let mark = agent.wg_log().len();
    tokio::time::sleep(SWEEP * 3).await;
    assert_eq!(since(&agent, mark), Vec::<String>::new());
    assert!(w.svc.is_connected(EID_A));
}

#[tokio::test]
async fn device_key_rotation_swaps_the_key_at_the_next_sweep() {
    let w = world(false, "device").await;
    let agent = Agent::spawn(
        w.broker,
        EID_A,
        FakeOptions {
            regenerates_key: true,
            ..firmware_b()
        },
    );
    let old = settled(&w, w.ma, "applied").await.public_key.unwrap();
    let tunnel = agent
        .instance("Device.WireGuard.Tunnel.", w.network)
        .unwrap();
    let peer = agent.instance("Device.WireGuard.Peer.", w.network).unwrap();
    assert_eq!(agent.value(&format!("{tunnel}PublicKey")), old);

    let mark = agent.wg_log().len();
    let asked = w
        .store
        .request_wg_key_rotation(DEFAULT_TENANT, w.ma)
        .await
        .unwrap()
        .unwrap();
    assert!(asked.rotate_requested_at.is_some());
    until("the key to be swapped", async || {
        let m = member(&w.store, w.ma).await;
        m.rotate_requested_at.is_none()
            && m.device_state.as_deref() == Some("applied")
            && wg_idle(&w.store, w.a).await
    })
    .await;
    assert_eq!(
        since(&agent, mark),
        [
            "get Device.WireGuard.,Device.IP.Interface.".to_owned(),
            format!("set {tunnel}PrivateKey=<secret>"),
            format!("get {tunnel}"),
            // Pending again -> pre-shared key ("" = none) sent once more.
            format!("set {peer}PresharedKey="),
        ]
    );
    let new = agent.value(&format!("{tunnel}PublicKey"));
    assert_ne!(new, old);
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.public_key.as_deref(), Some(new.as_str()));
    let keys: Vec<String> = hub_peers(&w).await.into_iter().map(|(k, _)| k).collect();
    assert_eq!(keys, [new]);
    // Done -> sweep leaves it alone.
    let mark = agent.wg_log().len();
    tokio::time::sleep(SWEEP * 3).await;
    assert_eq!(since(&agent, mark), Vec::<String>::new());
}

#[tokio::test]
async fn server_key_mode_sends_a_key_kept_nowhere_and_again_after_a_factory_reset() {
    let w = world(true, "server").await;
    let agent = Agent::spawn(w.broker, EID_A, firmware_a());

    // 2. Converges with a key made by the server.
    let ma = settled(&w, w.ma, "applied").await;
    let tunnel = agent
        .instance("Device.WireGuard.Tunnel.", w.network)
        .unwrap();
    let private = agent.value(&format!("{tunnel}PrivateKey"));
    let key = ma.public_key.clone().expect("the member has the key");
    assert_eq!(public_from_private(&private).unwrap(), key);
    let want = desired_a(&w, KeyMode::Server, &["192.168.20.0/24"]).await;
    assert_eq!(ma.device_applied_hash, Some(desired_hash(&want)));
    // (a): IP interface made by Dhonomos, with our Alias.
    let ip = agent.instance("Device.IP.Interface.", w.network).unwrap();
    assert_eq!(
        agent.value(&format!("{ip}LowerLayers")),
        format!("{tunnel}Interface.1")
    );
    let snapshot = w
        .store
        .get_params_exact(w.a, &[format!("{tunnel}PrivateKey")])
        .await
        .unwrap();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].value.as_deref(), Some(""));
    let key_tasks: Vec<Task> = wg_tasks(&w.store, w.a)
        .await
        .into_iter()
        .filter(|t| t.payload.to_string().contains("PrivateKey"))
        .collect();
    assert_eq!(key_tasks.len(), 1);
    assert_eq!(
        key_tasks[0].payload["values"][0]["value"],
        serde_json::json!("********")
    );
    assert!(!key_tasks[0].payload.to_string().contains("enc:"));
    assert!(!stored_anywhere(&w.store, &private).await);
    assert_eq!(hub_peers(&w).await.len(), 1);

    // 7. Factory reset (Boot! with RemoteFactoryReset), rows gone -> added again, new key.
    agent.with(|s| s.fake = FakeDevice::new(firmware_a()));
    assert!(!agent.has_our_rows());
    agent.boot("RemoteFactoryReset");
    until("the rows to be back with a new key", async || {
        let m = member(&w.store, w.ma).await;
        agent.has_our_rows()
            && m.public_key.as_ref().is_some_and(|k| *k != key)
            && m.device_state.as_deref() == Some("applied")
            && wg_idle(&w.store, w.a).await
    })
    .await;
    let tunnel = agent
        .instance("Device.WireGuard.Tunnel.", w.network)
        .unwrap();
    let private = agent.value(&format!("{tunnel}PrivateKey"));
    let ma = member(&w.store, w.ma).await;
    let new_key = ma.public_key.clone().unwrap();
    assert_eq!(public_from_private(&private).unwrap(), new_key);
    let peers = hub_peers(&w).await;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].0, new_key, "the old key is gone from the hub");
    assert!(!stored_anywhere(&w.store, &private).await);
}

/// Factory reset + restore from a backup without WireGuard rows.
/// Boot! Cause != factory reset -> that boot still reruns + puts tunnel back.
#[tokio::test]
async fn a_boot_that_is_no_factory_reset_puts_lost_rows_back() {
    let w = world(false, "device").await;
    let agent = Agent::spawn(w.broker, EID_A, firmware_b());
    let checked = settled(&w, w.ma, "applied").await.device_checked_at;

    // Reset + restore -> no row of ours left.
    let peer = agent.instance("Device.WireGuard.Peer.", w.network).unwrap();
    let tunnel = agent
        .instance("Device.WireGuard.Tunnel.", w.network)
        .unwrap();
    agent.with(|s| {
        s.fake.delete(&tunnel).unwrap();
        s.fake.delete(&peer).unwrap();
    });
    assert!(!agent.has_our_rows());
    let mark = agent.wg_log().len();
    agent.boot("LocalReboot");
    // Run ended = outcome recorded.
    until("the rows to be back", async || {
        let m = member(&w.store, w.ma).await;
        agent.has_our_rows()
            && m.device_checked_at > checked
            && m.device_state.as_deref() == Some("applied")
            && wg_idle(&w.store, w.a).await
    })
    .await;
    let log = since(&agent, mark);
    assert!(
        log.iter()
            .any(|l| l.starts_with("add Device.WireGuard.Peer.")),
        "{log:#?}"
    );
    assert!(
        log.iter()
            .any(|l| l.starts_with("add Device.WireGuard.Tunnel.")),
        "{log:#?}"
    );
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_detail, None);
    let want = desired_a(&w, KeyMode::Device, &["192.168.20.0/24"]).await;
    assert_eq!(ma.device_applied_hash, Some(desired_hash(&want)));
    let tunnel = agent
        .instance("Device.WireGuard.Tunnel.", w.network)
        .unwrap();
    assert!(
        agent
            .instance("Device.WireGuard.Peer.", w.network)
            .is_some()
    );
    assert_eq!(agent.value(&format!("{tunnel}Enable")), "true");
    assert_eq!(
        ma.public_key.as_deref(),
        Some(agent.value(&format!("{tunnel}PublicKey")).as_str())
    );
}

#[tokio::test]
async fn an_agent_without_wireguard_is_unsupported_and_left_alone() {
    let w = world(false, "device").await;
    let agent = Agent::spawn(
        w.broker,
        EID_A,
        FakeOptions {
            supported: false,
            ..firmware_b()
        },
    );
    // 6.
    let ma = settled(&w, w.ma, "unsupported").await;
    assert_eq!(
        ma.device_detail.as_deref(),
        Some("the device has no Device.WireGuard.")
    );
    assert_eq!(
        agent.wg_log(),
        ["get Device.WireGuard.,Device.IP.Interface."]
    );
    let before = wg_tasks(&w.store, w.a).await.len();
    tokio::time::sleep(SWEEP * 3).await;
    assert_eq!(wg_tasks(&w.store, w.a).await.len(), before);
    assert_eq!(agent.wg_log().len(), 1);
    // B untouched by the runs of A.
    assert_eq!(
        member(&w.store, w.mb).await.device_state.as_deref(),
        Some("pending")
    );
}

#[tokio::test]
async fn stale_rows_the_agent_will_not_delete_are_tried_once_by_the_sweep() {
    let w = world(false, "device").await;
    let agent = Agent::spawn(w.broker, EID_A, firmware_b());
    settled(&w, w.ma, "applied").await;
    agent.with(|s| s.refuse_delete = true);
    let mark = agent.wg_log().len();
    w.store
        .revoke_wg_member(DEFAULT_TENANT, w.ma, None)
        .await
        .unwrap()
        .unwrap();
    until("the delete to be refused", async || {
        agent.wg_log()[mark..]
            .iter()
            .any(|l| l.starts_with("delete "))
            && wg_idle(&w.store, w.a).await
    })
    .await;
    let tasks = wg_tasks(&w.store, w.a).await.len();
    let log = agent.wg_log().len();
    tokio::time::sleep(SWEEP * 4).await;
    assert_eq!(wg_tasks(&w.store, w.a).await.len(), tasks);
    assert_eq!(agent.wg_log().len(), log);
    let deletes = since(&agent, mark)
        .iter()
        .filter(|l| l.starts_with("delete "))
        .count();
    assert_eq!(deletes, 1);
    assert!(agent.has_our_rows());
    let _ = EID_B;
}

#[tokio::test]
async fn after_a_run_without_an_outcome_the_sweep_waits_before_the_next() {
    const RETRY: Duration = Duration::from_secs(4);
    const TIMEOUT: Duration = Duration::from_secs(2);
    let w = world_with(false, "device", RETRY, TIMEOUT).await;
    let agent = Agent::spawn_dropping_first_wg_get(w.broker, EID_A, firmware_b());
    // Connect run loses its read -> run started by sweep converges, but only after the wait
    // (sweep every 1 s, member stays due meanwhile).
    let ma = settled(&w, w.ma, "applied").await;
    assert!(ma.public_key.is_some());
    let gets = agent.with(|s| s.wg_gets.clone());
    assert!(gets.len() >= 2, "{gets:?}");
    let waited = gets[1] - gets[0];
    assert!(
        waited >= TIMEOUT + RETRY - Duration::from_millis(300),
        "the next run came after {waited:?}"
    );
    assert!(agent.wg_log()[0].ends_with("(dropped)"));
}

#[tokio::test]
async fn ls500x_makes_the_ip_interface_while_the_run_polls() {
    let w = world(false, "device").await;
    let agent = Agent::spawn_deriving(w.broker, EID_A, ls500x(), Some(3));
    let ma = settled(&w, w.ma, "applied").await;
    assert_eq!(ma.device_detail, None);
    let want = desired_a(&w, KeyMode::Device, &["192.168.20.0/24"]).await;
    assert_eq!(ma.device_applied_hash, Some(desired_hash(&want)));
    let log = agent.wg_log();
    assert!(
        !log.iter()
            .any(|l| l.starts_with("add Device.IP.Interface.")),
        "{log:#?}"
    );
    assert!(!log.iter().any(|l| l.contains("LowerLayers")), "{log:#?}");
    // Values went to the row the firmware made.
    assert_eq!(agent.value("Device.IP.Interface.2.Name"), "wg1");
    assert_eq!(agent.value("Device.IP.Interface.2.MaxMTUSize"), "1420");
    assert_eq!(
        agent.value("Device.IP.Interface.2.IPv4Address.1.IPAddress"),
        ma.address.to_string()
    );
    assert_eq!(agent.value("Device.IP.Interface.2.Enable"), "true");
    // Read after the Add + 2 polls, spaced by the poll interval.
    let gets = agent.with(|s| s.ip_gets.clone()).unwrap();
    assert!(gets.len() >= 3, "{gets:?}");
    let took = gets[2] - gets[0];
    assert!(
        took >= Duration::from_millis(200),
        "the polls took {took:?}"
    );
    // Done -> sweep leaves it alone.
    let mark = agent.wg_log().len();
    tokio::time::sleep(SWEEP * 3).await;
    assert_eq!(since(&agent, mark), Vec::<String>::new());
}

#[tokio::test]
async fn an_agent_that_never_makes_the_ip_interface_is_polled_then_fails_once() {
    let w = world(false, "device").await;
    let agent = Agent::spawn_deriving(w.broker, EID_A, ls500x(), None);
    let ma = settled(&w, w.ma, "error").await;
    assert!(ma.device_detail.is_some());
    // Within the retry period -> sweep neither polls nor adds again.
    tokio::time::sleep(SWEEP * 3).await;
    assert_eq!(
        member(&w.store, w.ma).await.device_state.as_deref(),
        Some("error")
    );
    let log = agent.wg_log();
    let tunnel_add = log
        .iter()
        .position(|l| l.starts_with("add Device.WireGuard.Tunnel."))
        .unwrap();
    let alias = alias_of(w.network);
    let ip_add = format!("add Device.IP.Interface. Alias={alias}");
    let first_ip_add = log.iter().position(|l| *l == ip_add).unwrap();
    assert_eq!(
        log[tunnel_add + 1..=first_ip_add],
        [
            "get Device.WireGuard.Tunnel.1.,Device.IP.Interface.",
            "get Device.IP.Interface.",
            "get Device.IP.Interface.",
            "get Device.IP.Interface.",
            "get Device.IP.Interface.",
            "get Device.IP.Interface.",
            ip_add.as_str(),
        ]
    );
    // Later run (of the connect, if the sweep run came first) adds at once -> waits used up.
    assert!(
        !log[first_ip_add..]
            .iter()
            .any(|l| l == "get Device.IP.Interface."),
        "{log:#?}"
    );

    // Revoked -> rows go. Device added again = new member -> polled again.
    w.store
        .revoke_wg_member(DEFAULT_TENANT, w.ma, None)
        .await
        .unwrap()
        .unwrap();
    until("our rows to go", async || {
        !agent.has_our_rows() && wg_idle(&w.store, w.a).await
    })
    .await;
    let mark = agent.wg_log().len();
    let again = w
        .store
        .create_wg_member(
            DEFAULT_TENANT,
            w.network,
            &NewWgMember {
                id: Uuid::now_v7(),
                psk: None,
                name: "cpe-A-again".into(),
                kind: NewWgMemberKind::Device {
                    device_id: w.a,
                    key_mode: "device".into(),
                },
                site_prefixes: Vec::new(),
            },
            time::Duration::hours(24),
        )
        .await
        .unwrap()
        .unwrap()
        .id;
    settled(&w, again, "error").await;
    let log = since(&agent, mark);
    let again_ip_add = log.iter().position(|l| *l == ip_add).unwrap();
    let polls = log[..again_ip_add]
        .iter()
        .filter(|l| *l == "get Device.IP.Interface.")
        .count();
    assert_eq!(polls, 5, "{log:#?}");
}

/// 2nd Boot! while the run of the 1st still waits for its read -> run kept.
/// Its read not cancelled, not sent again.
#[tokio::test]
async fn a_boot_while_the_run_waits_for_its_first_read_keeps_that_run() {
    let w = world(false, "device").await;
    let agent = Agent::spawn(w.broker, EID_A, firmware_b());
    let checked = settled(&w, w.ma, "applied").await.device_checked_at;
    let before = wg_tasks(&w.store, w.a).await.len();
    let wg_reads = |log: &[String]| {
        log.iter()
            .filter(|l| l.starts_with("get Device.WireGuard."))
            .count()
    };
    let cancelled = async || {
        wg_tasks(&w.store, w.a).await[before..]
            .iter()
            .filter(|t| t.state == dhonomos_store::TaskState::Cancelled)
            .count()
    };

    agent.hold_wg_gets();
    let mark = agent.wg_log().len();
    agent.boot("LocalReboot");
    until("the run's read to be held", async || agent.held() == 1).await;
    agent.boot("RemoteReboot");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let log = since(&agent, mark);
    assert_eq!(agent.held(), 1, "{log:#?}");
    assert_eq!(wg_reads(&log), 1, "{log:#?}");
    assert_eq!(cancelled().await, 0);

    agent.release();
    until("the kept run to end", async || {
        let m = member(&w.store, w.ma).await;
        m.device_checked_at > checked
            && m.device_state.as_deref() == Some("applied")
            && wg_idle(&w.store, w.a).await
    })
    .await;
    let log = since(&agent, mark);
    assert_eq!(wg_reads(&log), 1, "{log:#?}");
    assert_eq!(cancelled().await, 0);
}

/// Boot! during a run that already read the device -> replaces it; new run reads again.
#[tokio::test]
async fn a_boot_after_the_run_read_the_device_starts_a_new_run() {
    let w = world(false, "device").await;
    // Firmware never makes the IP interface -> after Tunnel Add the run polls
    // `Device.IP.Interface.` (x5, every 100 ms).
    let agent = Agent::spawn_deriving(w.broker, EID_A, ls500x(), None);
    until("the Tunnel Add", async || {
        agent
            .wg_log()
            .iter()
            .any(|l| l.starts_with("add Device.WireGuard.Tunnel."))
    })
    .await;
    let mark = agent.wg_log().len();
    agent.boot("LocalReboot");
    let new_read = || {
        since(&agent, mark)
            .iter()
            .position(|l| l.starts_with("get Device.WireGuard.,"))
    };
    until("the device to be read again", async || new_read().is_some()).await;
    // Run still in progress at the boot: no own IP interface Add (after its 5 polls)
    // before the read of the new run.
    // Its queued task = no reliable sign: a task already sent is not cancelled.
    let log = since(&agent, mark);
    let alias = alias_of(w.network);
    let ip_add = format!("add Device.IP.Interface. Alias={alias}");
    assert!(!log[..new_read().unwrap()].contains(&ip_add), "{log:#?}");
}

/// One CPE with CWMP + USP = 2 devices.
/// Rows of a network of its CWMP record -> not stale for its USP record (connect or sweep).
#[tokio::test]
async fn rows_the_cwmp_record_of_the_device_manages_are_left_alone() {
    let w = world(false, "device").await;
    // Network of A passes to the CWMP record of the same CPE (OUI + serial of the Agent)
    // before A ever connects.
    w.store
        .update_device_info(
            w.a,
            &dhonomos_store::DeviceInfo {
                oui: Some("00AA00".into()),
                serial_number: Some("WG1".into()),
                ..dhonomos_store::DeviceInfo::default()
            },
        )
        .await
        .unwrap();
    w.store
        .revoke_wg_member(DEFAULT_TENANT, w.ma, None)
        .await
        .unwrap()
        .unwrap();
    let twin = w
        .store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &dhonomos_store::CwmpIdentity {
                oui: "00AA00".into(),
                product_class: "WgBox".into(),
                serial_number: "WG1".into(),
            },
            &dhonomos_store::InformUpdate::default(),
        )
        .await
        .unwrap()
        .id;
    w.store
        .create_wg_member(
            DEFAULT_TENANT,
            w.network,
            &NewWgMember {
                id: Uuid::now_v7(),
                psk: None,
                name: "cpe-cwmp".into(),
                kind: NewWgMemberKind::Device {
                    device_id: twin,
                    key_mode: "device".into(),
                },
                site_prefixes: Vec::new(),
            },
            time::Duration::hours(24),
        )
        .await
        .unwrap()
        .unwrap();
    // CPE has the network rows; stored snapshot of A shows them.
    let mut fake = FakeDevice::new(firmware_b());
    let alias = alias_of(w.network);
    fake.add("Device.WireGuard.Peer.", &alias).unwrap();
    fake.add("Device.WireGuard.Tunnel.", &alias).unwrap();
    let rows = fake.read("Device.WireGuard.").unwrap();
    let snapshot: Vec<dhonomos_store::ParamUpdate> = rows
        .iter()
        .map(|(path, param)| dhonomos_store::ParamUpdate {
            path: path.clone(),
            value: Some(param.value.clone()),
            xsd_type: param.xsd_type.clone(),
            writable: param.writable,
        })
        .collect();
    w.store.upsert_params(w.a, &snapshot).await.unwrap();

    let agent = Agent::spawn_with(w.broker, EID_A, fake);
    until("the Agent to connect", async || w.svc.is_connected(EID_A)).await;
    tokio::time::sleep(SWEEP * 3).await;
    let log = agent.wg_log();
    assert!(
        !log.iter()
            .any(|l| l.starts_with("get ") && l.contains("Device.WireGuard."))
            && !log.iter().any(|l| l.starts_with("delete ")),
        "{log:?}"
    );
    assert!(wg_tasks(&w.store, w.a).await.is_empty());
    assert_eq!(
        agent.with(|s| s.fake.read("Device.WireGuard.")).unwrap(),
        rows
    );
}

#[tokio::test]
async fn a_preshared_key_reaches_the_agent_once_and_is_redacted() {
    let w = world(true, "device").await;
    let bytes = dhonomos_wireguard::generate_preshared_key().unwrap();
    let (ct, nonce) = secrets().seal_wg_psk(w.ma, &bytes[..]).unwrap();
    w.store
        .update_wg_member(DEFAULT_TENANT, w.ma, None, None, Some(Some((&ct, &nonce))))
        .await
        .unwrap()
        .unwrap();
    let psk = dhonomos_wireguard::key_text(&bytes).to_string();
    let agent = Agent::spawn(w.broker, EID_A, firmware_b());
    let ma = settled(&w, w.ma, "applied").await;
    let peer = agent.instance("Device.WireGuard.Peer.", w.network).unwrap();
    assert_eq!(agent.value(&format!("{peer}PresharedKey")), psk);
    let mut want = desired_a(&w, KeyMode::Device, &["192.168.20.0/24"]).await;
    want.preshared_key = Some(psk.clone().into());
    assert_eq!(ma.device_applied_hash, Some(desired_hash(&want)));
    let psk_sets: Vec<String> = agent
        .wg_log()
        .into_iter()
        .filter(|l| l.starts_with("set ") && l.contains("PresharedKey"))
        .collect();
    assert_eq!(psk_sets.len(), 1, "{psk_sets:?}");
    assert!(
        psk_sets[0].contains(&format!("{peer}PresharedKey=<secret>")),
        "{psk_sets:?}"
    );
    assert!(!stored_anywhere(&w.store, &psk).await);
    let tasks = w.store.list_tasks(w.a, 1000).await.unwrap();
    let with_psk: Vec<_> = tasks
        .iter()
        .filter(|t| t.payload.to_string().contains("PresharedKey"))
        .collect();
    assert_eq!(with_psk.len(), 1);
    assert!(with_psk[0].payload.to_string().contains("********"));
    assert!(!with_psk[0].payload.to_string().contains("enc:"));
}
