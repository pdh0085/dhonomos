//! E2E: WireGuard on CWMP devices (ADR-110 stage 4).
//! Real ACS listener + PostgreSQL + scripted CPEs (answers from fake CPE of `dhonomos_wireguard`).
//! Device planner configures `Device.WireGuard.` -> each member records the result.
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use bytes::Bytes;
use dhonomos_core::{AddressPolicy, CpeCredentials, CwmpBackend, SecretBox, Waker};
use dhonomos_cwmp_codec::{
    AddObjectResponse, Body, CwmpNamespace, DeleteObjectResponse, Envelope, Fault,
    GetParameterNamesResponse, GetParameterValuesResponse, ParameterValue, Rpc,
    SetParameterValuesResponse,
};
use dhonomos_cwmp_server::{AcsServer, AuthMode, Config, bind};
use dhonomos_store::{
    CwmpIdentity, DEFAULT_TENANT, InformUpdate, NewWgMember, NewWgMemberKind, NewWgNetwork, Store,
    Task, WgMember, WgPrefixChoice, WgSitePrefix, WgVisibility,
};
use dhonomos_wireguard::fake::{FakeDevice, FakeError, FakeOptions};
use dhonomos_wireguard::{
    DesiredTunnel, Ipv4Prefix, KeyMode, alias_of, desired_hash, generate_keypair,
    public_from_private,
};
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const INFORM: &[u8] = include_bytes!("../../cwmp-codec/tests/corpus/genieacs-sim/01-Inform.xml");
const ORIGIN: &str = "system:wireguard";
const HUB_HOST: &str = "hub.example.net";
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

fn identity(serial: &str) -> CwmpIdentity {
    CwmpIdentity {
        oui: "202BC1".into(),
        product_class: "BM632w".into(),
        serial_number: serial.into(),
    }
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

/// LS500X: like (b), but IP interface of a new tunnel only after commit (CWMP session end).
fn ls500x() -> FakeOptions {
    FakeOptions {
        ip_interface_later: true,
        ..firmware_b()
    }
}

/// Member state detail while its run waits for the firmware.
const WAITING: &str = "waiting for the device to make the IP interface of the tunnel";

/// ACS + DB + hub + network 10.77.0.0/24 + 2 member devices.
/// A: 192.168.10.0/24 behind it. B: 192.168.20.0/24.
struct World {
    _container: ContainerAsync<Postgres>,
    store: Store,
    addr: SocketAddr,
    hub: Uuid,
    network: Uuid,
    a: Uuid,
    b: Uuid,
    ma: Uuid,
    mb: Uuid,
}

async fn world(with_secrets: bool, key_mode: &str, hub_key: Option<&str>) -> World {
    world_with(with_secrets, key_mode, hub_key, None).await
}

/// = [`world`] + `rewake`.
/// `rewake` -> backend wakes a device waiting for firmware this long after its session.
async fn world_with(
    with_secrets: bool,
    key_mode: &str,
    hub_key: Option<&str>,
    rewake: Option<Duration>,
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
    let mut backend = CwmpBackend::new(store.clone(), DEFAULT_TENANT, CpeCredentials::None);
    if with_secrets {
        backend = backend.with_secrets(secrets());
    }
    if let Some(delay) = rewake {
        let waker = Waker::new(store.clone(), None, Duration::from_secs(1))
            .with_address_policy(AddressPolicy::permit_all());
        backend = backend.with_wg_rewake(waker, delay);
    }
    let config = Config {
        auth: AuthMode::None,
        session_timeout: Duration::from_secs(10),
        ..Config::default()
    };
    let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(AcsServer::new(config, backend).serve(listener, std::future::pending()));

    let hub = store
        .create_wg_hub(DEFAULT_TENANT, "lab", HUB_HOST)
        .await
        .unwrap()
        .unwrap()
        .id;
    if let Some(key) = hub_key {
        store.set_wg_hub_public_key(hub, key).await.unwrap();
    }
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
    for (serial, site) in [("A", "192.168.10.0/24"), ("B", "192.168.20.0/24")] {
        let device = store
            .upsert_cwmp_device(DEFAULT_TENANT, &identity(serial), &InformUpdate::default())
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
                    name: format!("cpe-{serial}"),
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
        addr,
        hub,
        network,
        a: ids[0].0,
        b: ids[1].0,
        ma: ids[0].1,
        mb: ids[1].1,
    }
}

/// Own CurrentTime per Inform.
static CLOCK: AtomicU32 = AtomicU32::new(0);

/// Captured Inform as TR-181 device `serial` sends it, with `events`.
fn inform(serial: &str, events: &[&str]) -> Vec<u8> {
    inform_with(serial, events, None)
}

/// = [`inform`]; `cr_url` -> its ConnectionRequestURL.
fn inform_with(serial: &str, events: &[&str], cr_url: Option<&str>) -> Vec<u8> {
    let mut env = Envelope::decode(INFORM).unwrap().unwrap();
    let Body::Rpc(Rpc::Inform(inf)) = &mut env.body else {
        panic!()
    };
    let t = CLOCK.fetch_add(1, Ordering::SeqCst);
    inf.current_time = format!(
        "2026-10-03T{:02}:{:02}:{:02}Z",
        t / 3600,
        (t / 60) % 60,
        t % 60
    );
    inf.device_id.oui = "202BC1".into();
    inf.device_id.product_class = "BM632w".into();
    inf.device_id.serial_number = serial.into();
    for p in &mut inf.parameter_list {
        p.name = p.name.replacen("InternetGatewayDevice.", "Device.", 1);
        if let Some(url) = cr_url
            && p.name == "Device.ManagementServer.ConnectionRequestURL"
        {
            p.value = url.into();
        }
    }
    inf.events.clear();
    for e in events {
        inf.events.push(dhonomos_cwmp_codec::EventStruct {
            event_code: (*e).into(),
            command_key: String::new(),
        });
    }
    env.encode().into_bytes()
}

/// Scripted CPE. WireGuard + IP layer = [`FakeDevice`].
struct Cpe {
    fake: FakeDevice,
    /// Refuse next SPV of a PrivateKey (fault 9008).
    refuse_key_once: bool,
    /// Session end commits its requests ([`FakeDevice::derive`]).
    /// false -> firmware never makes the IP interface of a new tunnel.
    commits: bool,
}

fn fault(code: u32, string: &str) -> Result<Rpc, Fault> {
    Err(Fault::new(code, string))
}

impl Cpe {
    fn new(opts: FakeOptions) -> Self {
        Self {
            fake: FakeDevice::new(opts),
            refuse_key_once: false,
            commits: true,
        }
    }

    fn answer(&mut self, rpc: &Rpc) -> Result<Rpc, Fault> {
        match rpc {
            // Zero-touch read of the whole tree.
            Rpc::GetParameterValues(g) if g.parameter_names.as_slice() == ["Device."] => {
                Ok(GetParameterValuesResponse {
                    parameter_list: vec![ParameterValue::new(
                        "Device.DeviceInfo.UpTime",
                        "12",
                        "unsignedInt",
                    )],
                }
                .into())
            }
            Rpc::GetParameterValues(g) => {
                let mut list = Vec::new();
                for name in &g.parameter_names {
                    let Ok(tree) = self.fake.read(name) else {
                        return fault(9005, "Invalid parameter name");
                    };
                    for (path, param) in tree {
                        list.push(ParameterValue::new(
                            path,
                            param.value,
                            param.xsd_type.as_deref().unwrap_or("string"),
                        ));
                    }
                }
                Ok(GetParameterValuesResponse {
                    parameter_list: list,
                }
                .into())
            }
            Rpc::GetParameterNames(_) => Ok(GetParameterNamesResponse::default().into()),
            Rpc::SetParameterValues(s) => {
                if self.refuse_key_once
                    && s.parameter_list
                        .iter()
                        .any(|v| v.name.ends_with(".PrivateKey"))
                {
                    self.refuse_key_once = false;
                    return fault(9008, "Attempt to set a non-writable parameter");
                }
                let pairs: Vec<(String, String)> = s
                    .parameter_list
                    .iter()
                    .map(|v| (v.name.clone(), v.value.clone()))
                    .collect();
                match self.fake.set(&pairs) {
                    Ok(()) => Ok(SetParameterValuesResponse { status: 0 }.into()),
                    Err(FakeError::NotWritable(_)) => {
                        fault(9008, "Attempt to set a non-writable parameter")
                    }
                    Err(_) => fault(9005, "Invalid parameter name"),
                }
            }
            Rpc::AddObject(a) => match self.fake.add(&a.object_name, "") {
                Ok(instance) => {
                    let number = instance
                        .trim_end_matches('.')
                        .rsplit('.')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    Ok(AddObjectResponse {
                        instance_number: number,
                        status: 0,
                    }
                    .into())
                }
                Err(_) => fault(9005, "Invalid parameter name"),
            },
            Rpc::DeleteObject(d) => match self.fake.delete(&d.object_name) {
                Ok(()) => Ok(DeleteObjectResponse { status: 0 }.into()),
                Err(_) => fault(9005, "Invalid parameter name"),
            },
            other => panic!("unexpected {}", other.name()),
        }
    }

    /// Instance of `table` with our Alias for `network` on the device.
    fn instance(&self, table: &str, network: Uuid) -> Option<String> {
        let alias = alias_of(network);
        let tree = self.fake.read(table).ok()?;
        tree.iter()
            .find(|(k, p)| {
                k.ends_with(".Alias")
                    && p.value == alias
                    && k[table.len()..].matches('.').count() == 1
            })
            .map(|(k, _)| k.trim_end_matches("Alias").to_owned())
    }

    fn value(&self, path: &str) -> String {
        self.fake
            .value(path)
            .unwrap_or_else(|| panic!("no {path}"))
            .to_owned()
    }

    /// Any row with one of our aliases left on the device.
    fn has_our_rows(&self) -> bool {
        ["Device.WireGuard.", "Device.IP.Interface."]
            .iter()
            .filter_map(|t| self.fake.read(t).ok())
            .flatten()
            .any(|(k, p)| k.ends_with(".Alias") && p.value.starts_with("dhonomos-wg-"))
    }
}

/// One CPE session: send `inform` -> answer every ACS request -> end commits ([`Cpe::commits`]).
/// Returns the ACS requests, in order.
async fn session(addr: SocketAddr, inform: Vec<u8>, cpe: &mut Cpe) -> Vec<Rpc> {
    let io = TokioIo::new(TcpStream::connect(addr).await.unwrap());
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);
    let mut post = async |body: Vec<u8>| {
        let resp = sender
            .send_request(
                Request::post("/")
                    .body(Full::new(Bytes::from(body)))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, Envelope::decode(&bytes).unwrap())
    };
    let (status, first) = post(inform).await;
    assert_eq!(status, StatusCode::OK);
    assert!(matches!(
        first.unwrap().body,
        Body::Rpc(Rpc::InformResponse(_))
    ));
    let mut seen = Vec::new();
    let (mut status, mut req) = post(Vec::new()).await;
    while status == StatusCode::OK {
        let env = req.unwrap();
        let Body::Rpc(rpc) = &env.body else {
            panic!("fault from the ACS: {env:?}")
        };
        seen.push(rpc.clone());
        let id = env.header.id.clone().unwrap();
        let reply = match cpe.answer(rpc) {
            Ok(rpc) => Envelope::rpc(CwmpNamespace::V1_0, id, rpc),
            Err(fault) => Envelope {
                header: dhonomos_cwmp_codec::Header {
                    id: Some(id),
                    ..Default::default()
                },
                body: Body::Fault(fault),
                namespace: CwmpNamespace::V1_0,
            },
        };
        (status, req) = post(reply.encode().into_bytes()).await;
    }
    if cpe.commits {
        cpe.fake.derive();
    }
    seen
}

/// (a) firmware: first session + 2 more. Firmware makes no IP interface
/// -> runs of sessions 1, 2 wait for it; session 3 adds it. Returns requests of all 3.
async fn sessions_until_ip_added(addr: SocketAddr, cpe: &mut Cpe) -> Vec<Rpc> {
    let mut all = session(addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), cpe).await;
    for _ in 0..2 {
        all.extend(session(addr, inform("A", &["6 CONNECTION REQUEST"]), cpe).await);
    }
    all
}

/// Tables of the AddObject requests in `requests`.
fn added(requests: &[Rpc]) -> Vec<String> {
    requests
        .iter()
        .filter_map(|r| match r {
            Rpc::AddObject(a) => Some(a.object_name.clone()),
            _ => None,
        })
        .collect()
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

async fn member(store: &Store, id: Uuid) -> WgMember {
    store
        .get_wg_member(DEFAULT_TENANT, id, &ALL)
        .await
        .unwrap()
        .unwrap()
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

/// SPV requests in `requests`, as (name, value) lists.
fn sets(requests: &[Rpc]) -> Vec<Vec<(String, String)>> {
    requests
        .iter()
        .filter_map(|r| match r {
            Rpc::SetParameterValues(s) => Some(
                s.parameter_list
                    .iter()
                    .map(|v| (v.name.clone(), v.value.clone()))
                    .collect(),
            ),
            _ => None,
        })
        .collect()
}

/// `needle` anywhere in tasks, events or audit log?
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

#[tokio::test]
async fn device_key_mode_converges_then_stays_repairs_drift_follows_changes_and_cleans_up() {
    let hub_key = generate_keypair().unwrap().public;
    let w = world(false, "device", Some(&hub_key)).await;
    let mut cpe = Cpe::new(firmware_b());

    // 1. One Inform session -> converged.
    session(w.addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    let peer = cpe.instance("Device.WireGuard.Peer.", w.network).unwrap();
    let tunnel = cpe.instance("Device.WireGuard.Tunnel.", w.network).unwrap();
    assert_eq!(cpe.value(&format!("{peer}PublicKey")), hub_key);
    assert_eq!(cpe.value(&format!("{peer}EndpointAddress")), HUB_HOST);
    assert_eq!(cpe.value(&format!("{peer}EndpointPort")), "51820");
    assert_eq!(cpe.value(&format!("{peer}PersistentKeepalive")), "25");
    assert_eq!(
        cpe.value(&format!("{peer}AllowedIPs")),
        "10.77.0.0/24,192.168.20.0/24"
    );
    assert_eq!(cpe.value(&format!("{peer}Enable")), "true");
    assert_eq!(cpe.value(&format!("{tunnel}Enable")), "true");
    assert_eq!(cpe.value(&format!("{tunnel}ListenPort")), "0");
    assert_eq!(
        cpe.value(&format!("{tunnel}PeerReferences")),
        peer.trim_end_matches('.')
    );
    let ma = member(&w.store, w.ma).await;
    // Firmware made Device.IP.Interface.2 above the tunnel.
    assert_eq!(
        cpe.value("Device.IP.Interface.2.IPv4Address.1.IPAddress"),
        ma.address.to_string()
    );
    assert_eq!(
        cpe.value("Device.IP.Interface.2.IPv4Address.1.SubnetMask"),
        "255.255.255.0"
    );
    assert_eq!(cpe.value("Device.IP.Interface.2.MaxMTUSize"), "1420");
    assert_eq!(cpe.value("Device.IP.Interface.1.Alias"), "cpe-lan");
    let device_key = cpe.value(&format!("{tunnel}PublicKey"));
    assert!(!device_key.is_empty());
    assert_eq!(ma.device_state.as_deref(), Some("applied"));
    assert_eq!(ma.device_detail, None);
    let want = desired_a(&w, KeyMode::Device, &["192.168.20.0/24"]).await;
    assert_eq!(ma.device_applied_hash, Some(desired_hash(&want)));
    assert_eq!(ma.public_key.as_deref(), Some(device_key.as_str()));
    let peers = hub_peers(&w).await;
    let a32 = Ipv4Prefix::new(ma.address, 32).unwrap();
    assert_eq!(
        peers,
        [(device_key.clone(), vec![a32, p("192.168.10.0/24")])]
    );
    // Each task of the run ran once; none left.
    let tasks = wg_tasks(&w.store, w.a).await;
    assert!(
        tasks
            .iter()
            .all(|t| t.state == dhonomos_store::TaskState::Succeeded && t.max_attempts == 1),
        "{tasks:?}"
    );

    // 3. Periodic Inform right after -> nothing to do, not even a read.
    let before = wg_tasks(&w.store, w.a).await.len();
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert!(requests.is_empty(), "{requests:?}");
    assert_eq!(wg_tasks(&w.store, w.a).await.len(), before);

    // 4. Drift, found at next check -> 1 read + 1 set of exactly that value.
    cpe.fake
        .set(&[(format!("{peer}EndpointPort"), "1".to_owned())])
        .unwrap();
    age_check(&w.store, w.ma, 7).await;
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    let names: Vec<&str> = requests.iter().map(Rpc::name).collect();
    assert_eq!(names, ["GetParameterValues", "SetParameterValues"]);
    assert_eq!(
        sets(&requests),
        [[(format!("{peer}EndpointPort"), "51820".to_owned())]]
    );
    assert_eq!(cpe.value(&format!("{peer}EndpointPort")), "51820");
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("applied"));
    assert_eq!(ma.device_applied_hash, Some(desired_hash(&want)));

    // 5. Desired state change (B: new site prefix) -> 1 set of AllowedIPs.
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
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert_eq!(
        sets(&requests),
        [[
            (
                format!("{peer}AllowedIPs"),
                "10.77.0.0/24,192.168.20.0/24,192.168.21.0/24".to_owned()
            ),
            // Desired state changed -> pre-shared key ("" = none) sent with it.
            (format!("{peer}PresharedKey"), String::new()),
        ]]
    );
    let want = desired_a(&w, KeyMode::Device, &["192.168.20.0/24", "192.168.21.0/24"]).await;
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("applied"));
    assert_eq!(ma.device_applied_hash, Some(desired_hash(&want)));

    // Read-only flag from earlier GPN survives a read that replaces the subtree
    // -> value that must change there -> blocked, not set.
    let port_path = format!("{peer}EndpointPort");
    sqlx::query("UPDATE device_params SET writable = false WHERE device_id = $1 AND path = $2")
        .bind(w.a)
        .bind(&port_path)
        .execute(w.store.pool())
        .await
        .unwrap();
    cpe.fake
        .set(&[(port_path.clone(), "1".to_owned())])
        .unwrap();
    age_check(&w.store, w.ma, 7).await;
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert!(sets(&requests).is_empty(), "{requests:?}");
    let stored = w
        .store
        .get_params_exact(w.a, std::slice::from_ref(&port_path))
        .await
        .unwrap();
    assert_eq!(stored[0].writable, Some(false), "kept across the read");
    assert_eq!(
        stored[0].value.as_deref(),
        Some("1"),
        "the value is the new one"
    );
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("blocked"));
    assert_eq!(
        ma.device_detail,
        Some(format!("{port_path} is not writable on this device"))
    );

    // 6. A revoked -> its rows go at next Inform; B untouched.
    let mb_before = member(&w.store, w.mb).await;
    w.store
        .revoke_wg_member(DEFAULT_TENANT, w.ma, None)
        .await
        .unwrap()
        .unwrap();
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    let deleted: Vec<String> = requests
        .iter()
        .filter_map(|r| match r {
            Rpc::DeleteObject(d) => Some(d.object_name.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        deleted,
        [tunnel.clone(), peer.clone()],
        "the IP interface was the firmware's"
    );
    assert!(!cpe.has_our_rows());
    assert_eq!(cpe.value("Device.IP.Interface.1.Alias"), "cpe-lan");
    assert!(
        cpe.fake.read("Device.IP.Interface.2.").is_err(),
        "went with the tunnel"
    );
    assert_eq!(member(&w.store, w.mb).await, mb_before);
    // Nothing of ours left -> nothing more happens.
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert!(requests.is_empty(), "{requests:?}");
}

#[tokio::test]
async fn server_key_mode_sends_a_key_that_is_kept_nowhere_and_again_after_a_reset() {
    let hub_key = generate_keypair().unwrap().public;
    let w = world(true, "server", Some(&hub_key)).await;
    let mut cpe = Cpe::new(firmware_a());

    // 2. Converges after the run stops waiting for firmware to make the IP interface.
    session(w.addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("pending"));
    assert_eq!(ma.device_detail.as_deref(), Some(WAITING));
    for _ in 0..2 {
        session(w.addr, inform("A", &["6 CONNECTION REQUEST"]), &mut cpe).await;
    }
    let tunnel = cpe.instance("Device.WireGuard.Tunnel.", w.network).unwrap();
    let private = cpe.value(&format!("{tunnel}PrivateKey"));
    let ma = member(&w.store, w.ma).await;
    let key = ma.public_key.clone().expect("the member has the key");
    assert_eq!(public_from_private(&private).unwrap(), key);
    assert_eq!(ma.device_state.as_deref(), Some("applied"));
    let want = desired_a(&w, KeyMode::Server, &["192.168.20.0/24"]).await;
    assert_eq!(ma.device_applied_hash, Some(desired_hash(&want)));
    // (a): IP interface made by Dhonomos, with our Alias.
    let ip = cpe.instance("Device.IP.Interface.", w.network).unwrap();
    assert_eq!(
        cpe.value(&format!("{ip}LowerLayers")),
        format!("{tunnel}Interface.1")
    );
    // Snapshot keeps it empty, finished task holds `********`, nowhere else.
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

    // 10. Factory reset -> tunnel added again + new key.
    cpe = Cpe::new(firmware_a());
    let requests = sessions_until_ip_added(w.addr, &mut cpe).await;
    assert!(added(&requests).contains(&"Device.IP.Interface.".to_owned()));
    let tunnel = cpe.instance("Device.WireGuard.Tunnel.", w.network).unwrap();
    let private = cpe.value(&format!("{tunnel}PrivateKey"));
    let ma = member(&w.store, w.ma).await;
    let new_key = ma.public_key.clone().unwrap();
    assert_ne!(new_key, key);
    assert_eq!(public_from_private(&private).unwrap(), new_key);
    assert_eq!(ma.device_state.as_deref(), Some("applied"));
    let peers = hub_peers(&w).await;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].0, new_key, "the old key is gone from the hub");
    assert!(!stored_anywhere(&w.store, &private).await);
}

#[tokio::test]
async fn a_refused_private_key_is_forgotten_and_sent_again_later() {
    let hub_key = generate_keypair().unwrap().public;
    let w = world(true, "server", Some(&hub_key)).await;
    let mut cpe = Cpe::new(firmware_a());
    cpe.refuse_key_once = true;
    // Key before IP layer -> first session ends with the key refused.
    session(w.addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.public_key, None, "the device does not have it");
    assert_eq!(ma.device_state.as_deref(), Some("error"));
    assert_eq!(
        ma.device_detail.as_deref(),
        Some("9008 Attempt to set a non-writable parameter")
    );
    assert!(hub_peers(&w).await.is_empty());
    // Refused task holds no key either.
    for t in wg_tasks(&w.store, w.a).await {
        if t.payload.to_string().contains("PrivateKey") {
            assert_eq!(
                t.payload["values"][0]["value"],
                serde_json::json!("********")
            );
        }
    }
    // Within 1 day -> no retry.
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert!(requests.is_empty(), "{requests:?}");
    // After it -> new key sent; run stops waiting for the firmware IP interface -> converges.
    age_check(&w.store, w.ma, 25).await;
    session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("pending"));
    assert!(ma.public_key.is_some(), "sent before the wait");
    for _ in 0..2 {
        session(w.addr, inform("A", &["6 CONNECTION REQUEST"]), &mut cpe).await;
    }
    let tunnel = cpe.instance("Device.WireGuard.Tunnel.", w.network).unwrap();
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("applied"));
    assert_eq!(
        public_from_private(&cpe.value(&format!("{tunnel}PrivateKey"))).unwrap(),
        ma.public_key.unwrap()
    );
}

#[tokio::test]
async fn a_device_without_wireguard_is_unsupported_and_left_alone() {
    let hub_key = generate_keypair().unwrap().public;
    let w = world(false, "device", Some(&hub_key)).await;
    let mut cpe = Cpe::new(FakeOptions {
        supported: false,
        ..firmware_b()
    });
    // 7.
    let requests = session(w.addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    let reads: Vec<&Vec<String>> = requests
        .iter()
        .filter_map(|r| match r {
            Rpc::GetParameterValues(g) => Some(&g.parameter_names),
            _ => None,
        })
        .collect();
    assert_eq!(
        reads,
        [
            &vec!["Device.".to_owned()],
            &vec![
                "Device.WireGuard.".to_owned(),
                "Device.IP.Interface.".to_owned()
            ]
        ]
    );
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("unsupported"));
    assert_eq!(
        ma.device_detail.as_deref(),
        Some("the device has no Device.WireGuard.")
    );
    let before = wg_tasks(&w.store, w.a).await.len();
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert!(requests.is_empty(), "{requests:?}");
    assert_eq!(wg_tasks(&w.store, w.a).await.len(), before);
    // B is not touched by A's runs.
    assert_eq!(
        member(&w.store, w.mb).await.device_state.as_deref(),
        Some("pending")
    );
}

#[tokio::test]
async fn a_hub_without_a_key_blocks_until_it_has_one() {
    let w = world(false, "device", None).await;
    let mut cpe = Cpe::new(firmware_b());
    // 8.
    let requests = session(w.addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    assert!(
        !requests.iter().any(|r| matches!(
            r,
            Rpc::AddObject(_) | Rpc::SetParameterValues(_) | Rpc::DeleteObject(_)
        )),
        "{requests:?}"
    );
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("blocked"));
    assert_eq!(
        ma.device_detail.as_deref(),
        Some("the hub has not reported its public key yet")
    );
    let hub_key = generate_keypair().unwrap().public;
    w.store
        .set_wg_hub_public_key(w.hub, &hub_key)
        .await
        .unwrap();
    session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("applied"));
    let peer = cpe.instance("Device.WireGuard.Peer.", w.network).unwrap();
    assert_eq!(cpe.value(&format!("{peer}PublicKey")), hub_key);
}

#[tokio::test]
async fn server_key_mode_needs_a_secrets_key() {
    let hub_key = generate_keypair().unwrap().public;
    let w = world(false, "server", Some(&hub_key)).await;
    let mut cpe = Cpe::new(firmware_a());
    // 9.
    let requests = session(w.addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    assert!(
        !sets(&requests)
            .iter()
            .flatten()
            .any(|(name, _)| name.ends_with(".PrivateKey"))
    );
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("blocked"));
    assert_eq!(
        ma.device_detail.as_deref(),
        Some("server key mode needs --secrets-key")
    );
    assert_eq!(ma.public_key, None);
    let _ = w.b;
}

/// GPV requests in `requests`, as name lists.
fn reads(requests: &[Rpc]) -> Vec<Vec<String>> {
    requests
        .iter()
        .filter_map(|r| match r {
            Rpc::GetParameterValues(g) => Some(g.parameter_names.clone()),
            _ => None,
        })
        .collect()
}

async fn request_rotation(store: &Store, member: Uuid) {
    let m = store
        .request_wg_key_rotation(DEFAULT_TENANT, member)
        .await
        .unwrap()
        .unwrap();
    assert!(m.rotate_requested_at.is_some());
    assert_eq!(m.device_state.as_deref(), Some("pending"));
}

#[tokio::test]
async fn device_key_rotation_swaps_the_key_at_the_next_inform() {
    let hub_key = generate_keypair().unwrap().public;
    let w = world(false, "device", Some(&hub_key)).await;
    let mut cpe = Cpe::new(FakeOptions {
        regenerates_key: true,
        ..firmware_b()
    });
    session(w.addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    let tunnel = cpe.instance("Device.WireGuard.Tunnel.", w.network).unwrap();
    let old = member(&w.store, w.ma).await.public_key.unwrap();
    assert_eq!(cpe.value(&format!("{tunnel}PublicKey")), old);

    request_rotation(&w.store, w.ma).await;
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    let peer = cpe.instance("Device.WireGuard.Peer.", w.network).unwrap();
    // Member pending again -> pre-shared key ("" = none) sent once more.
    assert_eq!(
        sets(&requests),
        [
            vec![(format!("{tunnel}PrivateKey"), String::new())],
            vec![(format!("{peer}PresharedKey"), String::new())],
        ]
    );
    assert_eq!(
        reads(&requests),
        [
            vec![
                "Device.WireGuard.".to_owned(),
                "Device.IP.Interface.".to_owned()
            ],
            vec![tunnel.clone()],
        ]
    );
    let new = cpe.value(&format!("{tunnel}PublicKey"));
    assert_ne!(new, old);
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.public_key.as_deref(), Some(new.as_str()));
    assert_eq!(ma.rotate_requested_at, None);
    assert_eq!(ma.device_state.as_deref(), Some("applied"));
    let keys: Vec<String> = hub_peers(&w).await.into_iter().map(|(k, _)| k).collect();
    assert_eq!(keys, [new]);

    // Done -> next Inform has nothing to do.
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert!(requests.is_empty(), "{requests:?}");
}

#[tokio::test]
async fn server_key_rotation_sends_a_new_key_and_the_hub_drops_the_old() {
    let hub_key = generate_keypair().unwrap().public;
    let w = world(true, "server", Some(&hub_key)).await;
    let mut cpe = Cpe::new(firmware_a());
    sessions_until_ip_added(w.addr, &mut cpe).await;
    let tunnel = cpe.instance("Device.WireGuard.Tunnel.", w.network).unwrap();
    let old = member(&w.store, w.ma).await.public_key.unwrap();
    assert_eq!(cpe.value(&format!("{tunnel}PublicKey")), old);

    request_rotation(&w.store, w.ma).await;
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    let key_sets: Vec<_> = sets(&requests)
        .into_iter()
        .filter(|s| s.iter().any(|(n, _)| n.ends_with(".PrivateKey")))
        .collect();
    assert_eq!(key_sets.len(), 1, "{requests:?}");
    // Tunnel read after the key.
    assert_eq!(reads(&requests).last(), Some(&vec![tunnel.clone()]));
    let private = cpe.value(&format!("{tunnel}PrivateKey"));
    let ma = member(&w.store, w.ma).await;
    let new = ma.public_key.clone().unwrap();
    assert_ne!(new, old);
    assert_eq!(public_from_private(&private).unwrap(), new);
    assert_eq!(cpe.value(&format!("{tunnel}PublicKey")), new);
    assert_eq!(ma.rotate_requested_at, None);
    assert_eq!(ma.device_state.as_deref(), Some("applied"));
    let keys: Vec<String> = hub_peers(&w).await.into_iter().map(|(k, _)| k).collect();
    assert_eq!(keys, [new], "the old key is gone from the hub");
    for t in wg_tasks(&w.store, w.a).await {
        if t.payload.to_string().contains("PrivateKey") {
            assert_eq!(
                t.payload["values"][0]["value"],
                serde_json::json!("********")
            );
        }
    }
    assert!(!stored_anywhere(&w.store, &private).await);
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert!(requests.is_empty(), "{requests:?}");
}

#[tokio::test]
async fn a_device_that_keeps_its_key_is_blocked_and_the_request_stays() {
    let hub_key = generate_keypair().unwrap().public;
    let w = world(false, "device", Some(&hub_key)).await;
    let mut cpe = Cpe::new(firmware_b());
    session(w.addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    let tunnel = cpe.instance("Device.WireGuard.Tunnel.", w.network).unwrap();
    let old = member(&w.store, w.ma).await.public_key.unwrap();

    request_rotation(&w.store, w.ma).await;
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    let peer = cpe.instance("Device.WireGuard.Peer.", w.network).unwrap();
    // Member pending again -> pre-shared key ("" = none) sent once more.
    assert_eq!(
        sets(&requests),
        [
            vec![(format!("{tunnel}PrivateKey"), String::new())],
            vec![(format!("{peer}PresharedKey"), String::new())],
        ]
    );
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.public_key.as_deref(), Some(old.as_str()));
    assert_eq!(ma.device_state.as_deref(), Some("blocked"));
    assert_eq!(
        ma.device_detail.as_deref(),
        Some("the device did not make a new key")
    );
    assert!(ma.rotate_requested_at.is_some(), "the request stays");
    let keys: Vec<String> = hub_peers(&w).await.into_iter().map(|(k, _)| k).collect();
    assert_eq!(keys, std::slice::from_ref(&old));

    // Within 1 day -> no retry.
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert!(requests.is_empty(), "{requests:?}");
    // New request -> pending -> next Inform retries.
    request_rotation(&w.store, w.ma).await;
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    let peer = cpe.instance("Device.WireGuard.Peer.", w.network).unwrap();
    // Member pending again -> pre-shared key ("" = none) sent once more.
    assert_eq!(
        sets(&requests),
        [
            vec![(format!("{tunnel}PrivateKey"), String::new())],
            vec![(format!("{peer}PresharedKey"), String::new())],
        ]
    );
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("blocked"));
    assert!(ma.rotate_requested_at.is_some());
}

/// LS500X, device key mode: session 1 adds Peer + Tunnel, then waits.
/// Firmware makes the IP interface at session end -> next session converges.
async fn ls500x_converges_in_the_session_after(opts: FakeOptions) {
    let hub_key = generate_keypair().unwrap().public;
    let w = world(false, "device", Some(&hub_key)).await;
    let mut cpe = Cpe::new(opts);

    let first = session(w.addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    assert_eq!(
        added(&first),
        ["Device.WireGuard.Peer.", "Device.WireGuard.Tunnel."]
    );
    assert!(
        sets(&first)
            .iter()
            .flatten()
            .all(|(n, _)| n.ends_with(".Alias"))
    );
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("pending"));
    assert_eq!(ma.device_detail.as_deref(), Some(WAITING));
    // Nothing of the run left queued.
    assert!(
        wg_tasks(&w.store, w.a)
            .await
            .iter()
            .all(|t| t.state == dhonomos_store::TaskState::Succeeded),
    );

    let second = session(w.addr, inform("A", &["6 CONNECTION REQUEST"]), &mut cpe).await;
    assert!(added(&second).is_empty(), "{second:?}");
    assert!(
        !sets(&second)
            .iter()
            .flatten()
            .any(|(n, _)| n.ends_with("LowerLayers")),
        "{second:?}"
    );
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("applied"));
    assert_eq!(ma.device_detail, None);
    let want = desired_a(&w, KeyMode::Device, &["192.168.20.0/24"]).await;
    assert_eq!(ma.device_applied_hash, Some(desired_hash(&want)));
    // Values went to the row the firmware made.
    assert_eq!(cpe.value("Device.IP.Interface.2.Name"), "wg1");
    assert_eq!(cpe.value("Device.IP.Interface.2.MaxMTUSize"), "1420");
    assert_eq!(cpe.value("Device.IP.Interface.2.Enable"), "true");
    assert_eq!(
        cpe.value("Device.IP.Interface.2.IPv4Address.1.IPAddress"),
        ma.address.to_string()
    );
    assert_eq!(
        cpe.value("Device.IP.Interface.2.IPv4Address.1.Enable"),
        "true"
    );
    let tunnel = cpe.instance("Device.WireGuard.Tunnel.", w.network).unwrap();
    assert_eq!(cpe.value(&format!("{tunnel}Enable")), "true");
    assert_eq!(
        ma.public_key.as_deref(),
        Some(cpe.value(&format!("{tunnel}PublicKey")).as_str())
    );

    // Done -> next Inform has nothing to do.
    let third = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert!(third.is_empty(), "{third:?}");
}

#[tokio::test]
async fn ls500x_makes_the_ip_interface_after_the_session() {
    ls500x_converges_in_the_session_after(ls500x()).await;
}

#[tokio::test]
async fn ls500x_with_empty_lower_layers_is_found_by_name() {
    ls500x_converges_in_the_session_after(FakeOptions {
        ip_lower_layers_empty: true,
        ..ls500x()
    })
    .await;
}

/// Factory reset + restore from a backup without WireGuard rows.
/// CPE back with `1 BOOT` only, no `0 BOOTSTRAP` -> that boot alone reruns + puts tunnel back.
#[tokio::test]
async fn a_boot_without_bootstrap_puts_lost_rows_back() {
    let hub_key = generate_keypair().unwrap().public;
    let w = world(false, "device", Some(&hub_key)).await;
    let mut cpe = Cpe::new(ls500x());
    session(w.addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    session(w.addr, inform("A", &["6 CONNECTION REQUEST"]), &mut cpe).await;
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("applied"));

    // Periodic Inform right after -> no run, no task.
    let before = wg_tasks(&w.store, w.a).await.len();
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert!(requests.is_empty(), "{requests:?}");
    assert_eq!(wg_tasks(&w.store, w.a).await.len(), before);

    // Reset + restore -> no row of ours left.
    let peer = cpe.instance("Device.WireGuard.Peer.", w.network).unwrap();
    let tunnel = cpe.instance("Device.WireGuard.Tunnel.", w.network).unwrap();
    cpe.fake.delete(&tunnel).unwrap();
    cpe.fake.delete(&peer).unwrap();
    assert!(!cpe.has_our_rows());

    let first = session(w.addr, inform("A", &["1 BOOT"]), &mut cpe).await;
    assert_eq!(
        added(&first),
        ["Device.WireGuard.Peer.", "Device.WireGuard.Tunnel."]
    );
    assert!(wg_tasks(&w.store, w.a).await.len() > before);
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("pending"));
    assert_eq!(ma.device_detail.as_deref(), Some(WAITING));

    session(w.addr, inform("A", &["6 CONNECTION REQUEST"]), &mut cpe).await;
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("applied"));
    assert_eq!(ma.device_detail, None);
    let want = desired_a(&w, KeyMode::Device, &["192.168.20.0/24"]).await;
    assert_eq!(ma.device_applied_hash, Some(desired_hash(&want)));
    let tunnel = cpe.instance("Device.WireGuard.Tunnel.", w.network).unwrap();
    assert!(cpe.instance("Device.WireGuard.Peer.", w.network).is_some());
    assert_eq!(cpe.value(&format!("{tunnel}Enable")), "true");
    assert_eq!(
        ma.public_key.as_deref(),
        Some(cpe.value(&format!("{tunnel}PublicKey")).as_str())
    );
    assert_eq!(
        cpe.value("Device.IP.Interface.2.IPv4Address.1.IPAddress"),
        ma.address.to_string()
    );
}

#[tokio::test]
async fn firmware_that_never_makes_the_ip_interface_ends_in_an_error() {
    let hub_key = generate_keypair().unwrap().public;
    let w = world(false, "device", Some(&hub_key)).await;
    let mut cpe = Cpe::new(ls500x());
    cpe.commits = false;

    let first = session(w.addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    assert!(!added(&first).contains(&"Device.IP.Interface.".to_owned()));
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("pending"));
    assert_eq!(ma.device_detail.as_deref(), Some(WAITING));
    let second = session(w.addr, inform("A", &["6 CONNECTION REQUEST"]), &mut cpe).await;
    assert!(added(&second).is_empty(), "{second:?}");
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("pending"));
    assert_eq!(ma.device_detail.as_deref(), Some(WAITING));

    // Run stopped waiting -> adds the IP interface itself -> firmware refuses.
    let third = session(w.addr, inform("A", &["6 CONNECTION REQUEST"]), &mut cpe).await;
    assert_eq!(added(&third), ["Device.IP.Interface."]);
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("error"));
    assert_eq!(
        ma.device_detail.as_deref(),
        Some("9005 Invalid parameter name")
    );
    // Within 1 day -> no retry.
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert!(requests.is_empty(), "{requests:?}");

    // Revoked -> rows go. Device added again = new member -> waits again.
    w.store
        .revoke_wg_member(DEFAULT_TENANT, w.ma, None)
        .await
        .unwrap()
        .unwrap();
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert!(!deleted(&requests).is_empty(), "{requests:?}");
    assert!(!cpe.has_our_rows());
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
    let fourth = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert!(
        !added(&fourth).contains(&"Device.IP.Interface.".to_owned()),
        "{fourth:?}"
    );
    let m = member(&w.store, again).await;
    assert_eq!(m.device_state.as_deref(), Some("pending"));
    assert_eq!(m.device_detail.as_deref(), Some(WAITING));
}

/// Answer every connection request at `listener` with 200 + report each.
fn connection_requests(listener: TcpListener) -> tokio::sync::mpsc::UnboundedReceiver<()> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
            let _ = tx.send(());
        }
    });
    rx
}

#[tokio::test]
async fn a_device_whose_run_waits_for_its_firmware_is_woken_after_the_session() {
    let hub_key = generate_keypair().unwrap().public;
    let w = world_with(
        false,
        "device",
        Some(&hub_key),
        Some(Duration::from_millis(100)),
    )
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let mut woken = connection_requests(listener);
    let mut cpe = Cpe::new(ls500x());

    let inform_a = |events: &[&str]| inform_with("A", events, Some(&url));
    session(w.addr, inform_a(&["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    assert_eq!(
        member(&w.store, w.ma).await.device_state.as_deref(),
        Some("pending")
    );
    tokio::time::timeout(Duration::from_secs(5), woken.recv())
        .await
        .expect("a connection request after the session")
        .unwrap();

    // Session it opens converges; nobody wakes the device after it.
    session(w.addr, inform_a(&["6 CONNECTION REQUEST"]), &mut cpe).await;
    assert_eq!(
        member(&w.store, w.ma).await.device_state.as_deref(),
        Some("applied")
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(1), woken.recv())
            .await
            .is_err(),
        "no connection request after a session that converged"
    );
}

#[tokio::test]
async fn ls500x_in_server_key_mode_gets_its_key_before_the_wait() {
    let hub_key = generate_keypair().unwrap().public;
    let w = world(true, "server", Some(&hub_key)).await;
    let mut cpe = Cpe::new(FakeOptions {
        makes_key: false,
        ..ls500x()
    });

    // Session 1: add Peer + Tunnel, set tunnel key, then wait.
    let first = session(w.addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    assert_eq!(
        added(&first),
        ["Device.WireGuard.Peer.", "Device.WireGuard.Tunnel."]
    );
    let tunnel = cpe.instance("Device.WireGuard.Tunnel.", w.network).unwrap();
    let key_sets = |requests: &[Rpc]| {
        sets(requests)
            .into_iter()
            .flatten()
            .filter(|(n, _)| n.ends_with(".PrivateKey"))
            .count()
    };
    assert_eq!(key_sets(&first), 1, "{first:?}");
    let private = cpe.value(&format!("{tunnel}PrivateKey"));
    let sent = public_from_private(&private).unwrap();
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("pending"));
    assert_eq!(ma.device_detail.as_deref(), Some(WAITING));
    assert_eq!(ma.public_key.as_deref(), Some(sent.as_str()));

    // Session 2 converges with that key; no other key sent.
    let second = session(w.addr, inform("A", &["6 CONNECTION REQUEST"]), &mut cpe).await;
    assert!(added(&second).is_empty(), "{second:?}");
    assert_eq!(key_sets(&second), 0, "{second:?}");
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("applied"));
    assert_eq!(ma.public_key.as_deref(), Some(sent.as_str()));
    assert_eq!(cpe.value(&format!("{tunnel}PrivateKey")), private);
    assert_eq!(cpe.value(&format!("{tunnel}PublicKey")), sent);
    let want = desired_a(&w, KeyMode::Server, &["192.168.20.0/24"]).await;
    assert_eq!(ma.device_applied_hash, Some(desired_hash(&want)));
    assert_eq!(cpe.value("Device.IP.Interface.2.MaxMTUSize"), "1420");
    assert!(!stored_anywhere(&w.store, &private).await);
    let keys: Vec<String> = hub_peers(&w).await.into_iter().map(|(k, _)| k).collect();
    assert_eq!(keys, [sent]);
}

/// DeleteObject requests in `requests`.
fn deleted(requests: &[Rpc]) -> Vec<String> {
    requests
        .iter()
        .filter_map(|r| match r {
            Rpc::DeleteObject(d) => Some(d.object_name.clone()),
            _ => None,
        })
        .collect()
}

/// One CPE with CWMP + USP = 2 devices.
/// Rows of a network of its USP record -> not stale for its CWMP record (with or without a run).
#[tokio::test]
async fn rows_the_usp_record_of_the_device_manages_are_left_alone() {
    let hub_key = generate_keypair().unwrap().public;
    let w = world(false, "device", Some(&hub_key)).await;
    let mut cpe = Cpe::new(firmware_b());
    session(w.addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    let peer = cpe.instance("Device.WireGuard.Peer.", w.network).unwrap();
    let tunnel = cpe.instance("Device.WireGuard.Tunnel.", w.network).unwrap();
    let rows = cpe.fake.read("Device.WireGuard.").unwrap();

    // Network rows pass to the USP record of the same CPE.
    let twin = w
        .store
        .upsert_usp_device(DEFAULT_TENANT, "os::202BC1-A", None)
        .await
        .unwrap()
        .id;
    w.store
        .update_device_info(
            twin,
            &dhonomos_store::DeviceInfo {
                oui: Some("202BC1".into()),
                serial_number: Some("A".into()),
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
    w.store
        .create_wg_member(
            DEFAULT_TENANT,
            w.network,
            &NewWgMember {
                id: Uuid::now_v7(),
                psk: None,
                name: "cpe-A-usp".into(),
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

    // No own membership -> CWMP record starts no run.
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert!(deleted(&requests).is_empty(), "{requests:?}");
    assert_eq!(cpe.fake.read("Device.WireGuard.").unwrap(), rows);

    // Run for its own network -> leaves them alone too.
    let other = w
        .store
        .create_wg_network(
            DEFAULT_TENANT,
            &NewWgNetwork {
                hub_id: w.hub,
                name: "more".into(),
                prefix: WgPrefixChoice::Explicit(p("10.78.0.0/24")),
                listen_port: Some(51821),
                mtu: 1420,
                persistent_keepalive: 25,
            },
        )
        .await
        .unwrap()
        .unwrap()
        .id;
    let mine = w
        .store
        .create_wg_member(
            DEFAULT_TENANT,
            other,
            &NewWgMember {
                id: Uuid::now_v7(),
                psk: None,
                name: "cpe-A".into(),
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
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert!(deleted(&requests).is_empty(), "{requests:?}");
    assert!(!added(&requests).is_empty(), "{requests:?}");
    assert_eq!(
        member(&w.store, mine).await.device_state.as_deref(),
        Some("applied")
    );
    assert_eq!(
        cpe.instance("Device.WireGuard.Peer.", w.network).as_deref(),
        Some(peer.as_str())
    );
    assert_eq!(
        cpe.instance("Device.WireGuard.Tunnel.", w.network)
            .as_deref(),
        Some(tunnel.as_str())
    );
    let now = cpe.fake.read(&peer).unwrap();
    assert_eq!(now, cpe_rows_under(&rows, &peer));
}

fn cpe_rows_under(rows: &dhonomos_wireguard::Tree, prefix: &str) -> dhonomos_wireguard::Tree {
    rows.iter()
        .filter(|(k, _)| k.starts_with(prefix))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// New pre-shared key for the member, sealed with [`secrets`] like the API. Returns it as text.
async fn give_psk(store: &Store, member: Uuid) -> String {
    let bytes = dhonomos_wireguard::generate_preshared_key().unwrap();
    let (ct, nonce) = secrets().seal_wg_psk(member, &bytes[..]).unwrap();
    let m = store
        .update_wg_member(
            DEFAULT_TENANT,
            member,
            None,
            None,
            Some(Some((&ct, &nonce))),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(m.preshared_key_enabled);
    dhonomos_wireguard::key_text(&bytes).to_string()
}

/// Pre-shared key given to the hub for the member, opened.
async fn hub_psk(w: &World, member: Uuid) -> Option<String> {
    let (_, sealed) = w.store.wg_hub_state_sealed(w.hub).await.unwrap().unwrap();
    let (ct, nonce) = sealed.get(&member)?;
    let plain = secrets().open_wg_psk(member, ct, nonce).unwrap();
    let bytes: [u8; 32] = plain.as_slice().try_into().unwrap();
    Some(dhonomos_wireguard::key_text(&bytes).to_string())
}

/// `PresharedKey` values of the SPV requests in `requests`.
fn psk_sets(requests: &[Rpc]) -> Vec<String> {
    sets(requests)
        .into_iter()
        .flatten()
        .filter(|(n, _)| n.ends_with(".PresharedKey"))
        .map(|(_, v)| v)
        .collect()
}

#[tokio::test]
async fn a_preshared_key_reaches_the_device_once_and_follows_resets_rotations_and_removal() {
    let hub_key = generate_keypair().unwrap().public;
    let w = world(true, "device", Some(&hub_key)).await;
    let alias = alias_of(w.network);
    let psk = give_psk(&w.store, w.ma).await;
    let mut cpe = Cpe::new(FakeOptions {
        regenerates_key: true,
        ..firmware_b()
    });

    // First run converges + gives the device the key, once.
    let requests = session(w.addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    assert_eq!(psk_sets(&requests), std::slice::from_ref(&psk));
    assert_eq!(cpe.fake.preshared_key(&alias), Some(psk.as_str()));
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("applied"));
    let mut want = desired_a(&w, KeyMode::Device, &["192.168.20.0/24"]).await;
    want.preshared_key = Some(psk.clone().into());
    assert_eq!(ma.device_applied_hash, Some(desired_hash(&want)));
    assert_eq!(hub_psk(&w, w.ma).await.as_deref(), Some(psk.as_str()));
    // Finished task holds `********`; key stored nowhere in clear text.
    let psk_tasks: Vec<Task> = wg_tasks(&w.store, w.a)
        .await
        .into_iter()
        .filter(|t| t.payload.to_string().contains("PresharedKey"))
        .collect();
    assert_eq!(psk_tasks.len(), 1);
    let value = psk_tasks[0].payload["values"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"].as_str().unwrap().ends_with(".PresharedKey"))
        .unwrap()
        .clone();
    assert_eq!(value["value"], serde_json::json!("********"));
    assert_eq!(value["secret"], serde_json::json!(true));
    assert!(!psk_tasks[0].payload.to_string().contains("enc:"));
    assert!(!stored_anywhere(&w.store, &psk).await);

    // Later run, same desired state -> key not sent again.
    age_check(&w.store, w.ma, 7).await;
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert!(!requests.is_empty(), "the drift check ran");
    assert_eq!(psk_sets(&requests), Vec::<String>::new());
    assert_eq!(
        member(&w.store, w.ma).await.device_state.as_deref(),
        Some("applied")
    );

    // Factory reset: rows gone -> boot puts them back with the key.
    let peer = cpe.instance("Device.WireGuard.Peer.", w.network).unwrap();
    let tunnel = cpe.instance("Device.WireGuard.Tunnel.", w.network).unwrap();
    cpe.fake.delete(&tunnel).unwrap();
    cpe.fake.delete(&peer).unwrap();
    let requests = session(w.addr, inform("A", &["1 BOOT"]), &mut cpe).await;
    assert_eq!(psk_sets(&requests), std::slice::from_ref(&psk));
    assert_eq!(cpe.fake.preshared_key(&alias), Some(psk.as_str()));
    assert_eq!(
        member(&w.store, w.ma).await.device_state.as_deref(),
        Some("applied")
    );

    // Key rotation -> new pre-shared key for device + hub.
    let old_key = member(&w.store, w.ma).await.public_key.unwrap();
    request_rotation(&w.store, w.ma).await;
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    let sent = psk_sets(&requests);
    assert_eq!(sent.len(), 1, "{requests:?}");
    assert_ne!(sent[0], psk);
    assert_eq!(cpe.fake.preshared_key(&alias), Some(sent[0].as_str()));
    assert_eq!(hub_psk(&w, w.ma).await.as_deref(), Some(sent[0].as_str()));
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("applied"));
    assert_eq!(ma.rotate_requested_at, None);
    assert_ne!(ma.public_key.unwrap(), old_key);
    assert!(!stored_anywhere(&w.store, &sent[0]).await);

    // Turned off -> device gets "".
    w.store
        .update_wg_member(DEFAULT_TENANT, w.ma, None, None, Some(None))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(hub_psk(&w, w.ma).await, None);
    let requests = session(w.addr, inform("A", &["2 PERIODIC"]), &mut cpe).await;
    assert_eq!(psk_sets(&requests), [String::new()]);
    assert_eq!(cpe.fake.preshared_key(&alias), Some(""));
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("applied"));
    let want = desired_a(&w, KeyMode::Device, &["192.168.20.0/24"]).await;
    assert_eq!(ma.device_applied_hash, Some(desired_hash(&want)));
}

/// LS500X: session 1 adds rows + waits for firmware before any set; desired state stored already.
/// Pre-shared key still reaches the device in session 2.
#[tokio::test]
async fn an_ls500x_gets_its_preshared_key_after_the_wait() {
    let hub_key = generate_keypair().unwrap().public;
    let w = world(true, "device", Some(&hub_key)).await;
    let alias = alias_of(w.network);
    let psk = give_psk(&w.store, w.ma).await;
    let mut cpe = Cpe::new(ls500x());

    let first = session(w.addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    assert_eq!(psk_sets(&first), Vec::<String>::new());
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("pending"));
    assert_eq!(ma.device_detail.as_deref(), Some(WAITING));
    let mut want = desired_a(&w, KeyMode::Device, &["192.168.20.0/24"]).await;
    want.preshared_key = Some(psk.clone().into());
    assert_eq!(ma.device_applied_hash, Some(desired_hash(&want)));
    assert_eq!(cpe.fake.preshared_key(&alias), Some(""));

    let second = session(w.addr, inform("A", &["6 CONNECTION REQUEST"]), &mut cpe).await;
    assert!(added(&second).is_empty(), "{second:?}");
    assert_eq!(psk_sets(&second), std::slice::from_ref(&psk));
    assert_eq!(cpe.fake.preshared_key(&alias), Some(psk.as_str()));
    assert_eq!(
        member(&w.store, w.ma).await.device_state.as_deref(),
        Some("applied")
    );
}

/// Stored pre-shared key the server cannot open (no `--secrets-key` here)
/// -> member in error, nothing set.
#[tokio::test]
async fn a_preshared_key_that_cannot_be_opened_is_an_error() {
    let hub_key = generate_keypair().unwrap().public;
    let w = world(false, "device", Some(&hub_key)).await;
    give_psk(&w.store, w.ma).await;
    let mut cpe = Cpe::new(firmware_b());
    let requests = session(w.addr, inform("A", &["0 BOOTSTRAP", "1 BOOT"]), &mut cpe).await;
    assert_eq!(psk_sets(&requests), Vec::<String>::new());
    assert!(cpe.instance("Device.WireGuard.Peer.", w.network).is_none());
    let ma = member(&w.store, w.ma).await;
    assert_eq!(ma.device_state.as_deref(), Some("error"));
    assert_eq!(
        ma.device_detail.as_deref(),
        Some("the stored pre-shared key cannot be opened")
    );
}
