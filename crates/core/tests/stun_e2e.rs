//! E2E: STUN setup of known devices (ADR-040).
//! Real ACS listener + PostgreSQL + scripted TR-181 CPE.
//! Onboarded before STUN server on -> setup at next Inform, once per configuration.
//! Setup refused -> left alone 24 h. No STUN parameters -> nothing.
//! Waker -> device behind CGNAT over UDP from the STUN socket, under the address policy.
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::Bytes;
use dhonomos_core::{
    Cidr, CpeCredentials, CwmpBackend, Onboarding, OnboardingMode, SecretBox, WakeOutcome, Waker,
};
use dhonomos_cwmp_codec::{
    Body, CwmpNamespace, Envelope, Fault, GetParameterNamesResponse, GetParameterValuesResponse,
    ParameterValue, Rpc, SetParameterAttributesResponse, SetParameterValuesResponse,
};
use dhonomos_cwmp_server::{AcsServer, AddressPolicy, AuthMode, Config, ConnReqCredentials, bind};
use dhonomos_store::{CwmpIdentity, DEFAULT_TENANT, ParamUpdate, Store, Task};
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use tokio::net::{TcpStream, UdpSocket};
use uuid::Uuid;

const INFORM: &[u8] = include_bytes!("../../cwmp-codec/tests/corpus/genieacs-sim/01-Inform.xml");
/// Server secret -> STUN passwords derive from it.
const SECRET: &[u8] = b"stun-secret";
const HOST: &str = "stun.example.net";
const MS: &str = "Device.ManagementServer.";

fn identity() -> CwmpIdentity {
    CwmpIdentity {
        oui: "202BC1".into(),
        product_class: "BM632w".into(),
        serial_number: "000000".into(),
    }
}

async fn database() -> (ContainerAsync<Postgres>, Store) {
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
    (container, store)
}

/// ACS on `store`, no CPE auth, configures STUN at `stun` (`--stun-public-address`) if given.
/// 2nd ACS on the same store = same server, other options.
async fn serve(store: &Store, stun: Option<(&str, u16)>, onboarding: Onboarding) -> SocketAddr {
    serve_with(store, stun, onboarding, None).await
}

/// [`serve`] + `--secrets-key` if `secrets` given.
async fn serve_with(
    store: &Store,
    stun: Option<(&str, u16)>,
    onboarding: Onboarding,
    secrets: Option<Arc<SecretBox>>,
) -> SocketAddr {
    let mut backend = CwmpBackend::new(store.clone(), DEFAULT_TENANT, CpeCredentials::None)
        .with_onboarding(onboarding);
    if let Some((host, port)) = stun {
        backend = backend.with_stun_provisioning(host, port, SECRET);
    }
    if let Some(secrets) = secrets {
        backend = backend.with_secrets(secrets);
    }
    let config = Config {
        auth: AuthMode::None,
        session_timeout: Duration::from_secs(10),
        ..Config::default()
    };
    let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(AcsServer::new(config, backend).serve(listener, std::future::pending()));
    addr
}

/// Captured Inform as a TR-181 device sends it, + extra events and parameters.
/// `at` = device clock. Bootstrap tasks keyed by it -> later bootstrap needs later `at`.
fn inform_181(events: &[&str], at: u32, extra: &[(&str, &str)]) -> Vec<u8> {
    let mut env = Envelope::decode(INFORM).unwrap().unwrap();
    let Body::Rpc(Rpc::Inform(inf)) = &mut env.body else {
        panic!()
    };
    inf.current_time = format!("2026-10-03T11:{at:02}:00Z");
    for p in &mut inf.parameter_list {
        p.name = p.name.replacen("InternetGatewayDevice.", "Device.", 1);
    }
    for (name, value) in extra {
        match inf.parameter_list.iter_mut().find(|p| p.name == *name) {
            Some(p) => p.value = (*value).into(),
            None => inf
                .parameter_list
                .push(ParameterValue::new(*name, *value, "string")),
        }
    }
    for e in events {
        inf.events.push(dhonomos_cwmp_codec::EventStruct {
            event_code: (*e).into(),
            command_key: String::new(),
        });
    }
    env.encode().into_bytes()
}

/// Captured Inform unchanged, TR-098 device `serial`.
fn inform_098(serial: &str, at: u32) -> Vec<u8> {
    let mut env = Envelope::decode(INFORM).unwrap().unwrap();
    let Body::Rpc(Rpc::Inform(inf)) = &mut env.body else {
        panic!()
    };
    inf.device_id.serial_number = serial.into();
    inf.current_time = format!("2026-10-03T11:{at:02}:00Z");
    env.encode().into_bytes()
}

/// Scripted CPE reply to an ACS request.
enum Reply {
    Answer(Rpc),
    /// SOAP Fault answer.
    Fault(Fault),
    /// Connection lost before the CPE answers.
    Vanish,
}

/// One CPE session: send `inform`, then answer each ACS request with `answer`.
/// Returns ACS requests, in order.
async fn session(
    addr: SocketAddr,
    inform: Vec<u8>,
    mut answer: impl FnMut(&Rpc) -> Reply,
) -> Vec<Rpc> {
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
        let reply = match answer(rpc) {
            Reply::Answer(rpc) => Envelope::rpc(CwmpNamespace::V1_0, id, rpc),
            Reply::Fault(fault) => Envelope {
                header: dhonomos_cwmp_codec::Header {
                    id: Some(id),
                    ..Default::default()
                },
                body: Body::Fault(fault),
                namespace: CwmpNamespace::V1_0,
            },
            Reply::Vanish => return seen,
        };
        (status, req) = post(reply.encode().into_bytes()).await;
    }
    seen
}

/// Healthy TR-181 device: GPV -> `tree`, takes what is set.
/// `on_spv` -> its reply to SPV.
fn device(tree: Vec<ParameterValue>, on_spv: impl Fn() -> Reply) -> impl FnMut(&Rpc) -> Reply {
    move |rpc| match rpc {
        Rpc::GetParameterValues(_) => Reply::Answer(
            GetParameterValuesResponse {
                parameter_list: tree.clone(),
            }
            .into(),
        ),
        Rpc::GetParameterNames(_) => Reply::Answer(GetParameterNamesResponse::default().into()),
        Rpc::SetParameterValues(_) => on_spv(),
        Rpc::SetParameterAttributes(_) => Reply::Answer(SetParameterAttributesResponse {}.into()),
        other => panic!("unexpected {}", other.name()),
    }
}

fn applied() -> Reply {
    Reply::Answer(SetParameterValuesResponse { status: 0 }.into())
}

fn refused() -> Reply {
    Reply::Fault(Fault::new(9007, "Invalid parameter value"))
}

/// Report of a device with STUN client, not set up yet.
fn unset_tree() -> Vec<ParameterValue> {
    [
        ("STUNEnable", "false", "boolean"),
        ("STUNServerAddress", "", "string"),
        ("STUNServerPort", "3478", "unsignedInt"),
        ("STUNUsername", "", "string"),
        ("STUNPassword", "", "string"),
    ]
    .into_iter()
    .map(|(name, value, ty)| ParameterValue::new(format!("{MS}{name}"), value, ty))
    .chain([ParameterValue::new(
        "Device.DeviceInfo.UpTime",
        "12",
        "unsignedInt",
    )])
    .collect()
}

/// Device without STUN client.
fn plain_tree() -> Vec<ParameterValue> {
    vec![ParameterValue::new(
        "Device.DeviceInfo.UpTime",
        "12",
        "unsignedInt",
    )]
}

fn names(requests: &[Rpc]) -> Vec<&str> {
    requests.iter().map(Rpc::name).collect()
}

/// Register the device on an ACS without STUN (as the real ones were).
/// Zero-touch read answered with `tree`.
async fn onboard(store: &Store, tree: Vec<ParameterValue>) -> Uuid {
    let before = serve(store, None, Onboarding::default()).await;
    let requests = session(
        before,
        inform_181(&["0 BOOTSTRAP"], 1, &[]),
        device(tree, applied),
    )
    .await;
    assert_eq!(
        names(&requests),
        ["GetParameterValues", "GetParameterNames"]
    );
    the_device(store).await
}

async fn the_device(store: &Store) -> Uuid {
    store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap()
}

/// STUN setup tasks of the ACS for the device, newest first.
async fn stun_tasks(store: &Store, device: Uuid) -> Vec<Task> {
    store
        .list_tasks(device, 100)
        .await
        .unwrap()
        .into_iter()
        .filter(|t| t.created_by.as_deref() == Some("system:stun"))
        .collect()
}

fn the_spv(requests: &[Rpc]) -> &dhonomos_cwmp_codec::SetParameterValues {
    let spvs: Vec<_> = requests
        .iter()
        .filter_map(|r| match r {
            Rpc::SetParameterValues(spv) => Some(spv),
            _ => None,
        })
        .collect();
    assert_eq!(
        spvs.len(),
        1,
        "one SetParameterValues: {:?}",
        names(requests)
    );
    spvs[0]
}

fn value_of(spv: &dhonomos_cwmp_codec::SetParameterValues, name: &str) -> (String, String) {
    let p = spv
        .parameter_list
        .iter()
        .find(|p| p.name == format!("{MS}{name}"))
        .unwrap_or_else(|| panic!("no {name} in {:?}", spv.parameter_list));
    (p.value.clone(), p.xsd_type.clone().unwrap_or_default())
}

fn secret_box() -> Arc<SecretBox> {
    let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    Arc::new(SecretBox::from_base64(&key, "k1").unwrap())
}

/// Check STUN password of `device`, setup sent in `requests` (one session).
/// CPE got the password the STUN server verifies.
/// Queued task -> secret: `enc:` ciphertext if `sealed`, plain value without key.
/// No plain text anywhere else. Snapshot keeps it empty.
async fn assert_password_is_a_secret(store: &Store, device: Uuid, requests: &[Rpc], sealed: bool) {
    let (password, _) = value_of(the_spv(requests), "STUNPassword");
    assert_eq!(
        dhonomos_core::nat::stun_passwords(SECRET.to_vec())(&device.to_string()),
        Some(password.clone().into_bytes()),
        "the STUN server verifies bindings with the password the device was given"
    );
    let tasks = stun_tasks(store, device).await;
    let spvs: Vec<_> = tasks
        .iter()
        .filter(|t| t.kind == "set_parameter_values")
        .collect();
    assert_eq!(spvs.len(), 1, "one SetParameterValues");
    let values = spvs[0].payload["values"].as_array().unwrap();
    let entry = |name: &str| {
        values
            .iter()
            .find(|v| v["name"] == format!("{MS}{name}"))
            .unwrap_or_else(|| panic!("no {name} in {values:?}"))
    };
    let queued = &entry("STUNPassword");
    assert_eq!(queued["secret"], true, "marked as a secret: {queued}");
    let stored = queued["value"].as_str().unwrap();
    if sealed {
        assert!(
            stored.starts_with("enc:v2:"),
            "sealed in the queue: {stored}"
        );
        assert!(
            !spvs[0].payload.to_string().contains(&password),
            "the queue holds no plain password: {}",
            spvs[0].payload
        );
    } else {
        assert_eq!(stored, password);
    }
    // Only the password is a secret.
    for name in [
        "STUNEnable",
        "STUNServerAddress",
        "STUNServerPort",
        "STUNUsername",
    ] {
        assert!(
            entry(name).get("secret").is_none(),
            "{name} is not a secret"
        );
    }
    assert_eq!(entry("STUNServerAddress")["value"], HOST);
    assert_eq!(entry("STUNUsername")["value"], device.to_string());
    // Snapshot never keeps it, as for every secret (CPE reported it empty).
    let snapshot = store
        .get_params_exact(device, &[format!("{MS}STUNPassword")])
        .await
        .unwrap();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].value.as_deref(), Some(""));
}

/// Backdate queueing + end of every failed task by `hours` h.
async fn age_failures(store: &Store, hours: i32) {
    sqlx::query(
        "UPDATE tasks SET created_at = created_at - make_interval(hours => $1), \
         finished_at = finished_at - make_interval(hours => $1) WHERE state = 'failed'",
    )
    .bind(hours)
    .execute(store.pool())
    .await
    .unwrap();
}

/// Periodic Inform of a device that takes what is set.
async fn periodic(addr: SocketAddr, at: u32) -> Vec<Rpc> {
    session(addr, inform_181(&[], at, &[]), device(Vec::new(), applied)).await
}

// Setup of a known device

#[tokio::test]
async fn a_known_device_gets_the_stun_setup_at_its_next_inform_and_only_once() {
    let (_c, store) = database().await;
    let id = onboard(&store, unset_tree()).await;
    assert!(stun_tasks(&store, id).await.is_empty(), "no STUN yet");
    let acs = serve(&store, Some((HOST, 3478)), Onboarding::default()).await;

    // Next Inform -> setup + active notification of the UDP address.
    // Inform also reports the UDP CR address -> stored.
    let requests = session(
        acs,
        inform_181(
            &[],
            2,
            &[(
                "Device.ManagementServer.UDPConnectionRequestAddress",
                "198.51.100.7:50000",
            )],
        ),
        device(Vec::new(), applied),
    )
    .await;
    assert_eq!(
        names(&requests),
        ["SetParameterValues", "SetParameterAttributes"]
    );
    let spv = the_spv(&requests);
    assert_eq!(
        value_of(spv, "STUNEnable"),
        ("true".into(), "boolean".into())
    );
    assert_eq!(
        value_of(spv, "STUNServerAddress"),
        (HOST.into(), "string".into())
    );
    assert_eq!(
        value_of(spv, "STUNServerPort"),
        ("3478".into(), "unsignedInt".into())
    );
    assert_eq!(
        value_of(spv, "STUNUsername"),
        (id.to_string(), "string".into())
    );
    let (password, _) = value_of(spv, "STUNPassword");
    assert_eq!(
        dhonomos_core::nat::stun_passwords(SECRET.to_vec())(&id.to_string()),
        Some(password.into_bytes()),
        "the STUN server verifies bindings with the password the device was given"
    );
    let Rpc::SetParameterAttributes(spa) = &requests[1] else {
        panic!()
    };
    assert_eq!(spa.parameter_list.len(), 1);
    assert_eq!(
        spa.parameter_list[0].name,
        format!("{MS}UDPConnectionRequestAddress")
    );
    assert!(spa.parameter_list[0].notification_change);
    assert_eq!(spa.parameter_list[0].notification, 2);
    assert_eq!(
        store.udp_cr_address(id).await.unwrap().unwrap().0,
        "198.51.100.7:50000",
        "the address in the Inform is still learned"
    );

    // Device took it -> snapshot shows setup, later Informs leave it alone.
    let stored: Vec<_> = store
        .get_params_exact(
            id,
            &[
                "STUNEnable",
                "STUNServerAddress",
                "STUNServerPort",
                "STUNUsername",
            ]
            .map(|n| format!("{MS}{n}")),
        )
        .await
        .unwrap();
    let stored: Vec<_> = stored.iter().map(|p| p.value.as_deref().unwrap()).collect();
    assert_eq!(stored.len(), 4);
    assert!(stored.contains(&"true") && stored.contains(&HOST));
    for at in [3, 4] {
        let requests = periodic(acs, at).await;
        assert!(requests.is_empty(), "Inform {at}: {:?}", names(&requests));
    }
    assert_eq!(stun_tasks(&store, id).await.len(), 2, "one SPV, one SPA");
}

#[tokio::test]
async fn the_stun_password_is_sealed_in_the_queue_and_never_stored_in_the_snapshot() {
    let (_c, store) = database().await;
    let id = onboard(&store, unset_tree()).await;
    let acs = serve_with(
        &store,
        Some((HOST, 3478)),
        Onboarding::default(),
        Some(secret_box()),
    )
    .await;
    let requests = periodic(acs, 2).await;
    assert_eq!(
        names(&requests),
        ["SetParameterValues", "SetParameterAttributes"]
    );
    assert_password_is_a_secret(&store, id, &requests, true).await;
    // Once per configuration -> nothing more queued, task keeps its ciphertext.
    assert!(periodic(acs, 3).await.is_empty());
    assert_eq!(stun_tasks(&store, id).await.len(), 2);
}

#[tokio::test]
async fn without_a_secrets_key_the_stun_password_is_still_a_secret_of_the_task() {
    let (_c, store) = database().await;
    let id = onboard(&store, unset_tree()).await;
    let acs = serve(&store, Some((HOST, 3478)), Onboarding::default()).await;
    let requests = periodic(acs, 2).await;
    assert_eq!(
        names(&requests),
        ["SetParameterValues", "SetParameterAttributes"]
    );
    assert_password_is_a_secret(&store, id, &requests, false).await;
}

#[tokio::test]
async fn zero_touch_seals_the_stun_password_and_a_repeated_bootstrap_queues_nothing_more() {
    let (_c, store) = database().await;
    let acs = serve_with(
        &store,
        Some((HOST, 3478)),
        Onboarding::default(),
        Some(secret_box()),
    )
    .await;
    let bootstrap = || inform_181(&["0 BOOTSTRAP"], 1, &[]);
    let requests = session(acs, bootstrap(), device(unset_tree(), applied)).await;
    assert_eq!(
        names(&requests),
        [
            "GetParameterValues",
            "GetParameterNames",
            "SetParameterValues",
            "SetParameterAttributes"
        ]
    );
    let id = the_device(&store).await;
    assert_password_is_a_secret(&store, id, &requests, true).await;
    let sealed = stun_tasks(&store, id).await;

    // Same BOOTSTRAP again (same device clock -> same keys) -> duplicate = no-op.
    let again = session(acs, bootstrap(), device(unset_tree(), applied)).await;
    assert!(again.is_empty(), "{:?}", names(&again));
    let tasks = stun_tasks(&store, id).await;
    assert_eq!(tasks.len(), 2);
    assert_eq!(
        tasks.iter().map(|t| (t.id, &t.payload)).collect::<Vec<_>>(),
        sealed
            .iter()
            .map(|t| (t.id, &t.payload))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn a_setup_that_is_still_queued_is_not_queued_again() {
    let (_c, store) = database().await;
    let id = onboard(&store, unset_tree()).await;
    let acs = serve(&store, Some((HOST, 3478)), Onboarding::default()).await;

    // Session lost before the device answers.
    let lost = session(
        acs,
        inform_181(&[], 2, &[]),
        device(Vec::new(), || Reply::Vanish),
    )
    .await;
    assert_eq!(names(&lost), ["SetParameterValues"]);
    // Next Inform -> same task again, not a new one.
    let requests = periodic(acs, 3).await;
    assert_eq!(
        names(&requests),
        ["SetParameterValues", "SetParameterAttributes"]
    );
    assert_eq!(stun_tasks(&store, id).await.len(), 2);
    assert!(periodic(acs, 4).await.is_empty());
}

#[tokio::test]
async fn a_changed_public_address_sends_the_setup_again() {
    let (_c, store) = database().await;
    let id = onboard(&store, unset_tree()).await;
    let a = serve(&store, Some((HOST, 3478)), Onboarding::default()).await;
    let b = serve(
        &store,
        Some(("stun2.example.net", 3478)),
        Onboarding::default(),
    )
    .await;
    let c = serve(
        &store,
        Some(("stun2.example.net", 3479)),
        Onboarding::default(),
    )
    .await;

    let setup = |requests: &[Rpc], host: &str, port: &str| {
        assert_eq!(
            names(requests),
            ["SetParameterValues", "SetParameterAttributes"]
        );
        let spv = the_spv(requests);
        assert_eq!(value_of(spv, "STUNServerAddress").0, host);
        assert_eq!(value_of(spv, "STUNServerPort").0, port);
    };
    setup(&periodic(a, 2).await, HOST, "3478");
    assert!(periodic(a, 3).await.is_empty());
    // New address, then new port.
    setup(&periodic(b, 4).await, "stun2.example.net", "3478");
    assert!(periodic(b, 5).await.is_empty());
    setup(&periodic(c, 6).await, "stun2.example.net", "3479");
    assert!(periodic(c, 7).await.is_empty());
    // Back to an earlier address -> device moved back too.
    setup(&periodic(a, 8).await, HOST, "3478");
    assert!(periodic(a, 9).await.is_empty());
    setup(&periodic(b, 10).await, "stun2.example.net", "3478");
    assert_eq!(stun_tasks(&store, id).await.len(), 2 * 5);
}

#[tokio::test]
async fn a_refused_setup_is_not_sent_again_within_24_hours() {
    let (_c, store) = database().await;
    let id = onboard(&store, unset_tree()).await;
    let acs = serve(&store, Some((HOST, 3478)), Onboarding::default()).await;

    // Device refuses with a fault (9007 here, 9005 for a missing parameter) -> sent once.
    let refusing = |at| async move {
        session(acs, inform_181(&[], at, &[]), device(Vec::new(), refused)).await
    };
    let requests = refusing(2).await;
    assert_eq!(
        names(&requests),
        ["SetParameterValues", "SetParameterAttributes"]
    );
    let tasks = stun_tasks(&store, id).await;
    let failed = tasks
        .iter()
        .find(|t| t.kind == "set_parameter_values")
        .unwrap();
    assert!(
        failed.error.as_deref().unwrap().starts_with("9007 "),
        "{:?}",
        failed.error
    );
    for at in [3, 4] {
        let requests = periodic(acs, at).await;
        assert!(requests.is_empty(), "Inform {at}: {:?}", names(&requests));
    }

    // After 24 h -> 1 more try (new task), refused again.
    age_failures(&store, 25).await;
    let requests = refusing(5).await;
    assert_eq!(
        names(&requests),
        ["SetParameterValues", "SetParameterAttributes"]
    );
    assert!(periodic(acs, 6).await.is_empty(), "and left alone again");
    assert_eq!(stun_tasks(&store, id).await.len(), 4);

    // Zero-touch trigger does not wait: BOOTSTRAP -> setup once, with the tree read.
    // This time the device takes it.
    let requests = session(
        acs,
        inform_181(&["0 BOOTSTRAP"], 7, &[]),
        device(unset_tree(), applied),
    )
    .await;
    assert_eq!(
        names(&requests),
        [
            "GetParameterValues",
            "GetParameterNames",
            "SetParameterValues",
            "SetParameterAttributes"
        ]
    );
    the_spv(&requests);
    assert!(periodic(acs, 8).await.is_empty());
}

#[tokio::test]
async fn a_device_that_does_not_take_the_setup_gets_nothing() {
    let (_c, store) = database().await;
    let id = onboard(&store, plain_tree()).await;
    let stun_acs = serve(&store, Some((HOST, 3478)), Onboarding::default()).await;

    // No STUN parameters -> nothing, however often it informs.
    for at in [2, 3] {
        let requests = periodic(stun_acs, at).await;
        assert!(requests.is_empty(), "Inform {at}: {:?}", names(&requests));
    }
    assert!(stun_tasks(&store, id).await.is_empty());

    // STUN parameters known read-only -> not written either.
    let param = |name: &str, value: &str| ParamUpdate {
        path: format!("{MS}{name}"),
        value: Some(value.into()),
        xsd_type: Some("string".into()),
        writable: Some(false),
    };
    store
        .upsert_params(
            id,
            &[
                param("STUNEnable", "false"),
                param("STUNServerAddress", ""),
                param("STUNServerPort", "3478"),
                param("STUNUsername", ""),
            ],
        )
        .await
        .unwrap();
    assert!(periodic(stun_acs, 4).await.is_empty());
    assert!(stun_tasks(&store, id).await.is_empty());

    // TR-098 device: STUN parameters elsewhere -> not touched.
    let before = serve(&store, None, Onboarding::default()).await;
    session(before, inform_098("098", 1), device(Vec::new(), applied)).await;
    let igd = store
        .find_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                serial_number: "098".into(),
                ..identity()
            },
        )
        .await
        .unwrap()
        .unwrap();
    store
        .upsert_params(
            igd,
            &[ParamUpdate {
                path: "InternetGatewayDevice.ManagementServer.STUNEnable".into(),
                value: Some("false".into()),
                xsd_type: Some("boolean".into()),
                writable: Some(true),
            }],
        )
        .await
        .unwrap();
    let requests = session(stun_acs, inform_098("098", 2), device(Vec::new(), applied)).await;
    assert!(
        names(&requests)
            .iter()
            .all(|n| !n.starts_with("SetParameter")),
        "{:?}",
        names(&requests)
    );
    assert!(stun_tasks(&store, igd).await.is_empty());
}

#[tokio::test]
async fn operator_admitted_devices_get_the_setup_once_they_are_active() {
    // `preregistered`: device exists before it informs.
    // First contact -> full read like a new device (here: ACS without STUN).
    // Then setup reaches it as a known device.
    let (_c, store) = database().await;
    let id = store
        .preregister_cwmp_device(DEFAULT_TENANT, &identity(), &[])
        .await
        .unwrap()
        .id;
    let seed = |name: &str, value: &str| ParamUpdate {
        path: format!("{MS}{name}"),
        value: Some(value.into()),
        xsd_type: Some("string".into()),
        writable: Some(true),
    };
    store
        .upsert_params(
            id,
            &[seed("STUNEnable", "false"), seed("STUNServerAddress", "")],
        )
        .await
        .unwrap();
    let preregistered_mode = Onboarding {
        mode: OnboardingMode::Preregistered,
        ..Onboarding::default()
    };
    let first_contact = serve(&store, None, preregistered_mode.clone()).await;
    // Full read returns the seeded params (a read drops what it does not return).
    let requests = session(
        first_contact,
        inform_181(&[], 1, &[]),
        device(unset_tree(), applied),
    )
    .await;
    assert_eq!(
        names(&requests),
        ["GetParameterValues", "GetParameterNames"]
    );
    assert!(stun_tasks(&store, id).await.is_empty());
    let preregistered = serve(&store, Some((HOST, 3478)), preregistered_mode).await;
    let requests = periodic(preregistered, 2).await;
    assert_eq!(
        names(&requests),
        ["SetParameterValues", "SetParameterAttributes"]
    );
    assert_eq!(value_of(the_spv(&requests), "STUNServerAddress").0, HOST);
    assert!(periodic(preregistered, 3).await.is_empty());

    // `quarantine`: not admitted by an operator yet -> nothing queued.
    let (_c2, store) = database().await;
    let quarantine = Onboarding {
        mode: OnboardingMode::Quarantine,
        ..Onboarding::default()
    };
    let before = serve(&store, None, quarantine.clone()).await;
    session(
        before,
        inform_181(&[], 1, &[]),
        device(unset_tree(), applied),
    )
    .await;
    let id = the_device(&store).await;
    assert_eq!(
        store.device_status(id).await.unwrap().as_deref(),
        Some("quarantined")
    );
    store
        .upsert_params(
            id,
            &[seed("STUNEnable", "false"), seed("STUNServerAddress", "")],
        )
        .await
        .unwrap();
    let acs = serve(&store, Some((HOST, 3478)), quarantine).await;
    periodic(acs, 2).await;
    assert!(stun_tasks(&store, id).await.is_empty(), "quarantined");
    assert!(
        store
            .set_device_status(DEFAULT_TENANT, id, "active")
            .await
            .unwrap()
    );
    // Tree read queued at first contact still waiting -> setup comes with it.
    let requests = periodic(acs, 3).await;
    assert_eq!(
        names(&requests),
        [
            "GetParameterValues",
            "GetParameterNames",
            "SetParameterValues",
            "SetParameterAttributes"
        ]
    );
}

// Waking a device behind CGNAT

fn cidr(s: &str) -> Cidr {
    s.parse().unwrap()
}

/// True if nothing arrives at `socket` within 300 ms.
async fn silent(socket: &UdpSocket) -> bool {
    let mut buf = [0u8; 1500];
    tokio::time::timeout(Duration::from_millis(300), socket.recv_from(&mut buf))
        .await
        .is_err()
}

/// Device with CR URL = CGNAT address + reported UDP CR address
/// -> woken over UDP from the STUN socket, no XMPP session,
/// only where the address policy (`--cr-allow`, `--cr-deny`) lets the request go.
#[tokio::test]
async fn a_device_behind_cgnat_is_woken_over_udp_from_the_stun_socket_under_the_address_policy() {
    let (_c, store) = database().await;
    let acs = serve(&store, Some((HOST, 3478)), Onboarding::default()).await;
    let cpe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let cpe_addr = cpe.local_addr().unwrap();
    // Inform carries both: private URL + UDP address.
    session(
        acs,
        inform_181(
            &["0 BOOTSTRAP"],
            1,
            &[
                (
                    "Device.ManagementServer.ConnectionRequestURL",
                    "http://100.70.1.1:30005/cr",
                ),
                (
                    "Device.ManagementServer.UDPConnectionRequestAddress",
                    &cpe_addr.to_string(),
                ),
            ],
        ),
        device(plain_tree(), applied),
    )
    .await;
    let id = the_device(&store).await;
    assert_eq!(
        store.udp_cr_address(id).await.unwrap().unwrap().0,
        cpe_addr.to_string(),
        "learned from the Inform"
    );

    let stun = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let stun_addr = stun.local_addr().unwrap();
    let waker = |policy: AddressPolicy| {
        Waker::new(
            store.clone(),
            Some(ConnReqCredentials {
                username: "cr-user".into(),
                password: "cr-pass".into(),
            }),
            // HTTP request to the CGNAT address would wait this long.
            Duration::from_secs(30),
        )
        .with_address_policy(policy)
        .with_udp(stun.clone())
    };
    // Refused by policy: deny list holds the address, allow list does not,
    // built-in deny list (loopback; lab address stands for a public one).
    for (policy, what) in [
        (
            AddressPolicy::new(Vec::new(), vec![cidr("127.0.0.0/8")]),
            "deny",
        ),
        (
            AddressPolicy::new(vec![cidr("10.0.0.0/8")], Vec::new()),
            "allow",
        ),
        (AddressPolicy::default(), "built-in"),
    ] {
        let outcome = waker(policy).wake(id).await;
        assert!(
            matches!(&outcome, WakeOutcome::Failed(e) if e.contains("address not permitted")),
            "{what}: {}",
            outcome.describe()
        );
        assert!(silent(&cpe).await, "{what}: nothing was sent");
    }

    // Permitted: UDP at once (no HTTP try at the CGNAT URL), from the STUN socket.
    let started = Instant::now();
    let outcome = waker(AddressPolicy::new(vec![cidr("127.0.0.0/8")], Vec::new()))
        .wake(id)
        .await;
    assert_eq!(outcome, WakeOutcome::SentUdp, "{}", outcome.describe());
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "{:?}",
        started.elapsed()
    );
    let mut buf = [0u8; 1500];
    let (n, from) = tokio::time::timeout(Duration::from_secs(2), cpe.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, stun_addr);
    let msg = std::str::from_utf8(&buf[..n]).unwrap();
    assert!(msg.starts_with("GET http://127.0.0.1:"), "{msg}");
    assert!(msg.contains("un=cr-user"), "{msg}");
    let woken = store.get_device(id).await.unwrap().unwrap();
    assert_eq!(woken.last_wake_method.as_deref(), Some("udp"));
}
