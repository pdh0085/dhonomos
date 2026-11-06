//! E2E, built-in XMPP server (ADR-104): real ACS listener + PostgreSQL + scripted CPE.
//! Provisioning: XMPP login via SPV (AddObject first when device has no connection to use).
//! Wake: Waker -> XMPP connection first, HTTP fallback when no answer.
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use dhonomos_core::{
    CpeCredentials, CwmpBackend, Onboarding, OnboardingMode, SecretBox, TaskKind, WakeOutcome,
    Waker, XmppAccounts, XmppProvisioning, account_of,
};
use dhonomos_cwmp_codec::{
    AddObjectResponse, Body, CwmpNamespace, Envelope, Fault, GetParameterNamesResponse,
    GetParameterValuesResponse, ParameterValue, Rpc, SetParameterValuesFault,
    SetParameterValuesResponse,
};
use dhonomos_cwmp_server::{AcsServer, AuthMode, Config, ConnReqCredentials, bind};
use dhonomos_pki::tls::CertResolver;
use dhonomos_store::{CwmpIdentity, DEFAULT_TENANT, NewTask, ParamUpdate, Store, TaskState};
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls_pki_types::{CertificateDer, ServerName};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const INFORM: &[u8] = include_bytes!("../../cwmp-codec/tests/corpus/genieacs-sim/01-Inform.xml");
const DOMAIN: &str = "xmpp.test";

fn secrets() -> Arc<SecretBox> {
    Arc::new(SecretBox::from_base64("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "k1").unwrap())
}

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

/// ACS without CPE auth, provisions XMPP logins for `xmpp.test`.
async fn acs(onboarding: Onboarding) -> (ContainerAsync<Postgres>, Store, SocketAddr) {
    let (container, store) = database().await;
    let backend = CwmpBackend::new(store.clone(), DEFAULT_TENANT, CpeCredentials::None)
        .with_secrets(secrets())
        .with_onboarding(onboarding)
        .with_xmpp_provisioning(XmppProvisioning {
            domain: DOMAIN.into(),
            keepalive: 30,
        });
    let config = Config {
        auth: AuthMode::None,
        session_timeout: Duration::from_secs(10),
        ..Config::default()
    };
    let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(AcsServer::new(config, backend).serve(listener, std::future::pending()));
    (container, store, addr)
}

/// Captured Inform as a TR-181 device sends it, + extra events.
/// `at` = device clock. Bootstrap tasks keyed by it -> later bootstrap needs later `at`.
fn inform_181(events: &[&str], at: u32) -> Vec<u8> {
    inform_181_on(events, at, FIRMWARE)
}

/// Firmware in the captured Inform.
const FIRMWARE: &str = "V100R001IRQC56B017";

/// [`inform_181`] for a device on `firmware`.
fn inform_181_on(events: &[&str], at: u32, firmware: &str) -> Vec<u8> {
    let mut env = Envelope::decode(INFORM).unwrap().unwrap();
    let Body::Rpc(Rpc::Inform(inf)) = &mut env.body else {
        panic!()
    };
    inf.current_time = format!("2026-10-03T11:{at:02}:00Z");
    for p in &mut inf.parameter_list {
        p.name = p.name.replacen("InternetGatewayDevice.", "Device.", 1);
        if p.name.ends_with(".DeviceInfo.SoftwareVersion") {
            p.value = firmware.into();
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

/// Scripted CPE reply to an ACS request.
enum Reply {
    Answer(Rpc),
    /// SOAP Fault.
    Fault(Fault),
    /// Connection lost before CPE answers.
    Vanish,
}

/// One CPE session: send `inform`, answer each ACS request with `answer`.
/// Returns ACS requests, in order.
async fn session(
    addr: SocketAddr,
    inform: Vec<u8>,
    mut answer: impl FnMut(&Rpc) -> Rpc,
) -> Vec<Rpc> {
    session_with(addr, inform, |rpc| Reply::Answer(answer(rpc))).await
}

/// [`session`]; `answer` = `None` -> fault 9005.
async fn session_or_fault(
    addr: SocketAddr,
    inform: Vec<u8>,
    mut answer: impl FnMut(&Rpc) -> Option<Rpc>,
) -> Vec<Rpc> {
    session_with(addr, inform, |rpc| match answer(rpc) {
        Some(rpc) => Reply::Answer(rpc),
        None => Reply::Fault(Fault::new(9005, "Invalid parameter name")),
    })
    .await
}

/// [`session`] + choice: fault or leave.
async fn session_with(
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

fn names(requests: &[Rpc]) -> Vec<&str> {
    requests.iter().map(Rpc::name).collect()
}

/// Whole tree of a TR-181 device with XMPP.
fn tree_with_xmpp(connection: Option<&[(&str, &str)]>) -> GetParameterValuesResponse {
    let mut list = vec![
        ParameterValue::new("Device.DeviceInfo.UpTime", "12", "unsignedInt"),
        ParameterValue::new(
            "Device.XMPP.SupportedServerConnectAlgorithms",
            "DNS-SRV,ServerTable",
            "string",
        ),
    ];
    match connection {
        None => list.push(ParameterValue::new(
            "Device.XMPP.ConnectionNumberOfEntries",
            "0",
            "unsignedInt",
        )),
        Some(params) => {
            list.push(ParameterValue::new(
                "Device.XMPP.ConnectionNumberOfEntries",
                "1",
                "unsignedInt",
            ));
            for (name, value) in params {
                list.push(ParameterValue::new(
                    format!("Device.XMPP.Connection.1.{name}"),
                    *value,
                    "string",
                ));
            }
        }
    }
    GetParameterValuesResponse {
        parameter_list: list,
    }
}

/// GPN answer (whole subtree) of a device with `tree`: objects + params under `path`.
/// Names read drops rows of instances not returned (ADR-111) -> must match reported values.
fn names_of(tree: &GetParameterValuesResponse, path: &str) -> GetParameterNamesResponse {
    let mut names = std::collections::BTreeSet::new();
    for p in tree
        .parameter_list
        .iter()
        .filter(|p| p.name.starts_with(path))
    {
        for (i, _) in p.name.match_indices('.') {
            if i + 1 >= path.len() {
                names.insert(p.name[..=i].to_owned());
            }
        }
        names.insert(p.name.clone());
    }
    GetParameterNamesResponse {
        parameter_list: names
            .into_iter()
            .map(|name| dhonomos_cwmp_codec::ParameterInfo {
                name,
                writable: true,
            })
            .collect(),
    }
}

/// Answers like a TR-181 device with `tree`. Created connection = number 3.
fn device_answering(tree: GetParameterValuesResponse) -> impl FnMut(&Rpc) -> Rpc {
    move |rpc| match rpc {
        Rpc::GetParameterValues(_) => tree.clone().into(),
        Rpc::GetParameterNames(r) => names_of(&tree, &r.parameter_path).into(),
        Rpc::AddObject(_) => AddObjectResponse {
            instance_number: 3,
            status: 0,
        }
        .into(),
        Rpc::SetParameterValues(_) => SetParameterValuesResponse { status: 0 }.into(),
        other => panic!("unexpected {}", other.name()),
    }
}

fn value_of(spv: &dhonomos_cwmp_codec::SetParameterValues, name: &str) -> String {
    spv.parameter_list
        .iter()
        .find(|p| p.name == name)
        .unwrap_or_else(|| panic!("no {name} in {:?}", spv.parameter_list))
        .value
        .clone()
}

/// Value of `name` in the SPV + its `xsi:type`.
fn typed_value_of(spv: &dhonomos_cwmp_codec::SetParameterValues, name: &str) -> (String, String) {
    let p = spv
        .parameter_list
        .iter()
        .find(|p| p.name == name)
        .unwrap_or_else(|| panic!("no {name} in {:?}", spv.parameter_list));
    (p.value.clone(), p.xsd_type.clone().unwrap_or_default())
}

/// `Enable=true` of connection `instance` = last value.
/// -> connection starts with all else in place.
fn assert_enable_is_last(spv: &dhonomos_cwmp_codec::SetParameterValues, instance: u32) {
    let last = spv.parameter_list.last().expect("a non-empty SPV");
    assert_eq!(
        last.name,
        format!("Device.XMPP.Connection.{instance}.Enable"),
        "Enable is last"
    );
    assert_eq!(last.value, "true");
}

async fn the_device(store: &Store) -> uuid::Uuid {
    store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap()
}

fn the_spv(requests: &[Rpc]) -> &dhonomos_cwmp_codec::SetParameterValues {
    requests
        .iter()
        .find_map(|r| match r {
            Rpc::SetParameterValues(spv) => Some(spv),
            _ => None,
        })
        .expect("a SetParameterValues")
}

// Provisioning

#[tokio::test]
async fn zero_touch_adds_a_connection_and_sets_the_xmpp_login_in_one_session() {
    let (_c, store, addr) = acs(Onboarding::default()).await;
    let requests = session(
        addr,
        inform_181(&["0 BOOTSTRAP"], 1),
        device_answering(tree_with_xmpp(None)),
    )
    .await;
    // No connection on device -> one added, set up with the number it answered.
    assert_eq!(
        names(&requests),
        [
            "GetParameterValues",
            "GetParameterNames",
            "AddObject",
            "SetParameterValues"
        ]
    );
    let Rpc::AddObject(add) = &requests[2] else {
        panic!()
    };
    assert_eq!(add.object_name, "Device.XMPP.Connection.");

    let device = the_device(&store).await;
    let spv = the_spv(&requests);
    let conn = |p: &str| value_of(spv, &format!("Device.XMPP.Connection.3.{p}"));
    assert_eq!(
        conn("Username"),
        device.to_string(),
        "the JID local part is the device ID"
    );
    let password = conn("Password");
    assert_eq!(password.len(), 24);
    assert_eq!(conn("Domain"), DOMAIN);
    assert_eq!(conn("Resource"), "");
    assert_eq!(conn("UseTLS"), "true", "explicit");
    assert_eq!(conn("ServerConnectAlgorithm"), "DNS-SRV");
    assert_eq!(conn("KeepAliveInterval"), "30");
    // New connection not reported by device yet -> TR-181 types.
    // KeepAliveInterval = `long` (`int` refused with 9006).
    assert_eq!(
        typed_value_of(spv, "Device.XMPP.Connection.3.KeepAliveInterval").1,
        "long"
    );
    // Retry back-off for a failing server connection: always set, as unsignedInt.
    // -> device may carry 1/1000/1 from an older image.
    let typed = |p: &str| typed_value_of(spv, &format!("Device.XMPP.Connection.3.{p}"));
    for (name, value) in [
        ("ServerRetryInitialInterval", "10"),
        ("ServerRetryIntervalMultiplier", "2000"),
        ("ServerRetryMaxInterval", "1800"),
    ] {
        assert_eq!(typed(name), (value.to_string(), "unsignedInt".to_string()));
    }
    assert_eq!(conn("Enable"), "true");
    assert_enable_is_last(spv, 3);
    assert_eq!(
        value_of(spv, "Device.ManagementServer.ConnReqXMPPConnection"),
        "Device.XMPP.Connection.3"
    );
    assert_eq!(
        value_of(spv, "Device.ManagementServer.ConnReqAllowedJabberIDs"),
        "acs@xmpp.test"
    );
    assert_eq!(spv.parameter_list.len(), 13);

    // Password = pending until device logs in with it.
    // Encrypted at rest + in queue; never in snapshot.
    let queue: String = store
        .list_tasks(device, 100)
        .await
        .unwrap()
        .iter()
        .map(|t| t.payload.to_string())
        .collect();
    assert!(
        !queue.contains(&password),
        "no plaintext password in the queue"
    );
    assert!(
        store
            .get_credential(device, "xmpp")
            .await
            .unwrap()
            .is_none()
    );
    let pending = store
        .get_credential(device, "xmpp_pending")
        .await
        .unwrap()
        .expect("a pending XMPP credential");
    assert_eq!(pending.username, device.to_string());
    assert_eq!(
        secrets()
            .open_credential(device, &pending.ciphertext, &pending.nonce)
            .unwrap(),
        password.as_bytes()
    );
    let snapshot = store
        .get_params(device, "Device.XMPP.Connection.3.")
        .await
        .unwrap();
    assert!(
        snapshot
            .iter()
            .all(|p| p.value.as_deref() != Some(password.as_str()))
    );
    let tasks = store.list_tasks(device, 100).await.unwrap();
    assert!(
        tasks
            .iter()
            .all(|t| t.state == dhonomos_store::TaskState::Succeeded)
    );

    // 1st login with pending password -> it becomes the device password.
    use dhonomos_xmpp::Accounts as _;
    let accounts = XmppAccounts::new(store.clone(), DEFAULT_TENANT, secrets());
    let account = account_of(device);
    let creds = accounts.credentials(&account).await.unwrap();
    assert_eq!(creds.len(), 1);
    assert!(creds[0].pending && creds[0].password == password.as_bytes());
    accounts.accepted(&account, &creds[0]).await;
    assert!(
        store
            .get_credential(device, "xmpp")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .get_credential(device, "xmpp_pending")
            .await
            .unwrap()
            .is_none()
    );
    let creds = accounts.credentials(&account).await.unwrap();
    assert!(!creds[0].pending);

    // Issued once per device -> another bootstrap changes nothing.
    let requests = session(
        addr,
        inform_181(&["0 BOOTSTRAP"], 2),
        device_answering(tree_with_xmpp(Some(&[("Username", &device.to_string())]))),
    )
    .await;
    assert_eq!(
        names(&requests),
        ["GetParameterValues", "GetParameterNames"]
    );
    // Until operator removes it -> next trigger issues a new one.
    store.delete_credential(device, "xmpp").await.unwrap();
    let requests = session(
        addr,
        inform_181(&["0 BOOTSTRAP"], 3),
        device_answering(tree_with_xmpp(Some(&[("Username", &device.to_string())]))),
    )
    .await;
    assert_eq!(
        names(&requests),
        [
            "GetParameterValues",
            "GetParameterNames",
            "SetParameterValues"
        ],
        "the connection the device already has for this login is set up again"
    );
    let spv = the_spv(&requests);
    assert_ne!(value_of(spv, "Device.XMPP.Connection.1.Password"), password);
    assert!(
        store
            .get_credential(device, "xmpp_pending")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn an_unused_connection_the_device_has_is_set_up_instead_of_adding_one() {
    let (_c, store, addr) = acs(Onboarding::default()).await;
    let requests = session(
        addr,
        inform_181(&[], 4),
        device_answering(tree_with_xmpp(Some(&[
            ("Username", ""),
            ("Enable", "false"),
        ]))),
    )
    .await;
    assert_eq!(
        names(&requests),
        [
            "GetParameterValues",
            "GetParameterNames",
            "SetParameterValues"
        ]
    );
    let spv = the_spv(&requests);
    assert_eq!(
        value_of(spv, "Device.XMPP.Connection.1.Username"),
        the_device(&store).await.to_string()
    );
    assert_enable_is_last(spv, 1);
    assert_eq!(
        value_of(
            spv,
            "Device.XMPP.Connection.1.ServerRetryIntervalMultiplier"
        ),
        "2000"
    );
    assert_eq!(
        value_of(spv, "Device.ManagementServer.ConnReqXMPPConnection"),
        "Device.XMPP.Connection.1"
    );
}

#[tokio::test]
async fn a_connection_set_up_for_something_else_is_left_alone() {
    let (_c, _store, addr) = acs(Onboarding::default()).await;
    let requests = session(
        addr,
        inform_181(&[], 5),
        device_answering(tree_with_xmpp(Some(&[
            ("Username", "someone-else"),
            ("Enable", "true"),
        ]))),
    )
    .await;
    assert_eq!(
        names(&requests),
        [
            "GetParameterValues",
            "GetParameterNames",
            "AddObject",
            "SetParameterValues"
        ],
        "a new connection is added instead"
    );
    let spv = the_spv(&requests);
    assert!(
        spv.parameter_list
            .iter()
            .all(|p| p.name.starts_with("Device.XMPP.Connection.3.")
                || p.name.starts_with("Device.ManagementServer.")),
        "nothing of connection 1 is touched"
    );
}

#[tokio::test]
async fn a_connection_of_our_domain_with_another_account_is_taken_over() {
    // Device deleted + registered again -> new ID, connection still has old account on our domain.
    // Firmware using only connection 1 never connects via a 2nd row -> old one set up again.
    let (_c, store, addr) = acs(Onboarding::default()).await;
    let old_account = uuid::Uuid::now_v7().to_string();
    let requests = session(
        addr,
        inform_181(&[], 6),
        device_answering(tree_with_xmpp(Some(&[
            ("Username", old_account.as_str()),
            ("Domain", DOMAIN),
            ("Enable", "true"),
        ]))),
    )
    .await;
    assert_eq!(
        names(&requests),
        [
            "GetParameterValues",
            "GetParameterNames",
            "SetParameterValues"
        ],
        "no AddObject: connection 1 is reused"
    );
    let spv = the_spv(&requests);
    let device = the_device(&store).await.to_string();
    assert_ne!(device, old_account);
    assert_eq!(
        value_of(spv, "Device.XMPP.Connection.1.Username"),
        device,
        "the account is replaced by this device's"
    );
    assert_eq!(value_of(spv, "Device.XMPP.Connection.1.Domain"), DOMAIN);
    assert_enable_is_last(spv, 1);
    assert_eq!(
        value_of(spv, "Device.ManagementServer.ConnReqXMPPConnection"),
        "Device.XMPP.Connection.1"
    );
    assert!(
        spv.parameter_list
            .iter()
            .all(|p| p.name.starts_with("Device.XMPP.Connection.1.")
                || p.name.starts_with("Device.ManagementServer.")),
        "only connection 1 is set"
    );
}

#[tokio::test]
async fn devices_without_xmpp_or_with_the_other_data_model_get_no_login() {
    let (_c, store, addr) = acs(Onboarding::default()).await;
    // TR-181 without Device.XMPP.
    let plain = GetParameterValuesResponse {
        parameter_list: vec![ParameterValue::new(
            "Device.DeviceInfo.UpTime",
            "1",
            "unsignedInt",
        )],
    };
    let requests = session(addr, inform_181(&[], 6), device_answering(plain)).await;
    assert_eq!(
        names(&requests),
        ["GetParameterValues", "GetParameterNames"]
    );
    let device = the_device(&store).await;
    assert!(store.list_credentials(device).await.unwrap().is_empty());

    // TR-098, tree happens to hold the names.
    let (_c, store, addr) = acs(Onboarding::default()).await;
    let requests = session(addr, INFORM.to_vec(), |rpc| match rpc {
        Rpc::GetParameterValues(_) => GetParameterValuesResponse {
            parameter_list: vec![ParameterValue::new(
                "InternetGatewayDevice.XMPP.ConnectionNumberOfEntries",
                "0",
                "unsignedInt",
            )],
        }
        .into(),
        _ => GetParameterNamesResponse::default().into(),
    })
    .await;
    assert_eq!(
        names(&requests),
        ["GetParameterValues", "GetParameterNames"]
    );
    let device = the_device(&store).await;
    assert!(store.list_credentials(device).await.unwrap().is_empty());
}

/// Pre-registered + informed before -> firmware known, Inform != first contact.
/// (1st Inform of a pre-registered device = first contact -> read whole, as at zero-touch.)
async fn preregistered_and_known(store: &Store) -> uuid::Uuid {
    let device = store
        .preregister_cwmp_device(DEFAULT_TENANT, &identity(), &[])
        .await
        .unwrap()
        .id;
    store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &identity(),
            &dhonomos_store::InformUpdate {
                software_version: Some(FIRMWARE.into()),
                ..dhonomos_store::InformUpdate::default()
            },
        )
        .await
        .unwrap();
    device
}

/// 1st Inform of a pre-registered device = first contact, though no device created.
/// -> tree read whole, XMPP login from it, as for a new device.
#[tokio::test]
async fn a_preregistered_device_is_provisioned_at_its_first_inform() {
    let (_c, store, addr) = acs(Onboarding {
        mode: OnboardingMode::Preregistered,
        allowed_ouis: vec![],
    })
    .await;
    let device = store
        .preregister_cwmp_device(DEFAULT_TENANT, &identity(), &[])
        .await
        .unwrap()
        .id;
    let requests = session(
        addr,
        inform_181(&[], 1),
        device_answering(tree_with_xmpp(None)),
    )
    .await;
    assert_eq!(
        names(&requests),
        [
            "GetParameterValues",
            "GetParameterNames",
            "AddObject",
            "SetParameterValues"
        ]
    );
    assert!(
        store
            .get_credential(device, "xmpp_pending")
            .await
            .unwrap()
            .is_some()
    );
    let requests = session(
        addr,
        inform_181(&[], 2),
        device_answering(tree_with_xmpp(None)),
    )
    .await;
    assert!(requests.is_empty(), "{:?}", names(&requests));
}

#[tokio::test]
async fn a_preregistered_device_that_never_bootstrapped_is_asked_for_its_xmpp_and_provisioned() {
    let (_c, store, addr) = acs(Onboarding {
        mode: OnboardingMode::Preregistered,
        allowed_ouis: vec![],
    })
    .await;
    let device = preregistered_and_known(&store).await;
    // Informed before without BOOTSTRAP, this Inform no BOOTSTRAP either (only ACS URL changed).
    // -> no tree read, XMPP unknown -> ACS asks for `Device.XMPP.`, goes on from the answer.
    let requests = session(
        addr,
        inform_181(&[], 1),
        device_answering(tree_with_xmpp(None)),
    )
    .await;
    assert_eq!(
        names(&requests),
        ["GetParameterValues", "AddObject", "SetParameterValues"]
    );
    let Rpc::GetParameterValues(gpv) = &requests[0] else {
        panic!()
    };
    assert_eq!(gpv.parameter_names, ["Device.XMPP."]);
    assert!(
        store
            .get_credential(device, "xmpp_pending")
            .await
            .unwrap()
            .is_some()
    );
    // Only once.
    let requests = session(
        addr,
        inform_181(&[], 2),
        device_answering(tree_with_xmpp(None)),
    )
    .await;
    assert!(requests.is_empty(), "{:?}", names(&requests));
}

#[tokio::test]
async fn a_device_without_xmpp_is_asked_once() {
    let (_c, store, addr) = acs(Onboarding {
        mode: OnboardingMode::Preregistered,
        allowed_ouis: vec![],
    })
    .await;
    let device = preregistered_and_known(&store).await;
    // No such object on device -> fault; not asked again at every Inform.
    for at in [1, 2, 3] {
        let requests = session_or_fault(addr, inform_181(&[], at), |_| None).await;
        let expected: &[&str] = if at == 1 {
            &["GetParameterValues"]
        } else {
            &[]
        };
        assert_eq!(names(&requests), expected, "Inform {at}");
    }
    assert!(store.list_credentials(device).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_read_the_operator_asked_for_is_no_trigger() {
    let (_c, store, addr) = acs(Onboarding::default()).await;
    // New device, no XMPP in its tree.
    let plain = GetParameterValuesResponse {
        parameter_list: vec![ParameterValue::new(
            "Device.DeviceInfo.UpTime",
            "1",
            "unsignedInt",
        )],
    };
    session(addr, inform_181(&[], 1), device_answering(plain)).await;
    let device = the_device(&store).await;
    assert!(store.list_credentials(device).await.unwrap().is_empty());

    // Operator reads tree, now shows XMPP (new image) -> no trigger.
    // -> nothing happens, then or at next ordinary Inform.
    let (k, payload) = TaskKind::GetParameterValues {
        names: vec!["Device.".into()],
    }
    .to_row();
    store
        .enqueue_task(&NewTask::new(DEFAULT_TENANT, device, k, payload))
        .await
        .unwrap();
    let requests = session(
        addr,
        inform_181(&[], 2),
        device_answering(tree_with_xmpp(None)),
    )
    .await;
    assert_eq!(names(&requests), ["GetParameterValues"]);
    let requests = session(
        addr,
        inform_181(&[], 3),
        device_answering(tree_with_xmpp(None)),
    )
    .await;
    assert!(requests.is_empty(), "{:?}", names(&requests));
    assert!(store.list_credentials(device).await.unwrap().is_empty());

    // Next BOOTSTRAP = trigger.
    let requests = session(
        addr,
        inform_181(&["0 BOOTSTRAP"], 4),
        device_answering(tree_with_xmpp(None)),
    )
    .await;
    assert_eq!(
        names(&requests),
        [
            "GetParameterValues",
            "GetParameterNames",
            "AddObject",
            "SetParameterValues"
        ]
    );
}

// Types + device refusing what it gets

/// Tree as a device reports it: `(name, value, type)`.
fn typed_tree(params: &[(&str, &str, &str)]) -> GetParameterValuesResponse {
    GetParameterValuesResponse {
        parameter_list: params
            .iter()
            .map(|(name, value, ty)| ParameterValue::new(*name, *value, ty))
            .collect(),
    }
}

/// [`device_answering`], except SPV -> `on_spv`.
fn device_replying(
    tree: GetParameterValuesResponse,
    mut on_spv: impl FnMut() -> Reply,
) -> impl FnMut(&Rpc) -> Reply {
    let mut others = device_answering(tree);
    move |rpc| match rpc {
        Rpc::SetParameterValues(_) => on_spv(),
        other => Reply::Answer(others(other)),
    }
}

/// Real device fault to the SPV: 9003, names KeepAliveInterval of wrong type.
/// SPV atomic -> nothing applied.
fn refuse() -> Reply {
    let mut fault = Fault::new(9003, "Invalid arguments");
    fault.set_parameter_values_faults = vec![SetParameterValuesFault {
        parameter_name: "Device.XMPP.Connection.3.KeepAliveInterval".into(),
        fault_code: 9006,
        fault_string: "Invalid parameter type".into(),
    }];
    Reply::Fault(fault)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Key of the SPV task with pending credential `nonce`.
fn setup_key(device: uuid::Uuid, nonce: &[u8]) -> String {
    format!("xmpp-credentials:{device}:{}", hex(nonce))
}

/// Pending XMPP credential of the device: nonce (= its id) + password.
async fn pending_xmpp(store: &Store, device: uuid::Uuid) -> Option<(Vec<u8>, String)> {
    let c = store
        .get_credential(device, "xmpp_pending")
        .await
        .unwrap()?;
    let password = secrets()
        .open_credential(device, &c.ciphertext, &c.nonce)
        .unwrap();
    Some((c.nonce, String::from_utf8(password).unwrap()))
}

/// Tasks of `kind` the ACS made for the XMPP login, oldest first.
async fn xmpp_tasks(store: &Store, device: uuid::Uuid, kind: &str) -> Vec<dhonomos_store::Task> {
    let mut tasks: Vec<_> = store
        .list_tasks(device, 100)
        .await
        .unwrap()
        .into_iter()
        .filter(|t| t.created_by.as_deref() == Some("system:xmpp-credentials") && t.kind == kind)
        .collect();
    tasks.reverse();
    tasks
}

async fn has_key(store: &Store, key: String) -> bool {
    !store
        .existing_idempotency_keys(DEFAULT_TENANT, &[key])
        .await
        .unwrap()
        .is_empty()
}

/// Backdate end of every failed task by `hours`.
async fn age_failures(store: &Store, hours: i32) {
    sqlx::query(
        "UPDATE tasks SET finished_at = finished_at - make_interval(hours => $1) \
         WHERE state = 'failed'",
    )
    .bind(hours)
    .execute(store.pool())
    .await
    .unwrap();
}

#[tokio::test]
async fn the_xmpp_setup_carries_the_types_the_device_reported() {
    let (_c, _store, addr) = acs(Onboarding::default()).await;
    let requests = session(
        addr,
        inform_181(&[], 7),
        device_answering(typed_tree(&[
            ("Device.XMPP.ConnectionNumberOfEntries", "1", "unsignedInt"),
            ("Device.XMPP.Connection.1.Username", "", "string"),
            ("Device.XMPP.Connection.1.Enable", "false", "boolean"),
            // Real device reports this type + refuses any other.
            ("Device.XMPP.Connection.1.KeepAliveInterval", "60", "long"),
            // Not TR-181 type -> device's own type is the accepted one.
            (
                "Device.XMPP.Connection.1.ServerRetryInitialInterval",
                "1",
                "int",
            ),
            // No type reported -> TR-181 type.
            ("Device.XMPP.Connection.1.Domain", "", ""),
            (
                "Device.ManagementServer.ConnReqXMPPConnection",
                "",
                "anyURI",
            ),
        ])),
    )
    .await;
    assert_eq!(
        names(&requests),
        [
            "GetParameterValues",
            "GetParameterNames",
            "SetParameterValues"
        ]
    );
    let spv = the_spv(&requests);
    let ty = |name: &str| typed_value_of(spv, name).1;
    for (name, expected) in [
        ("KeepAliveInterval", "long"),
        ("ServerRetryInitialInterval", "int"),
        ("Domain", "string"),
        ("Enable", "boolean"),
        // Not reported -> TR-181 type.
        ("Username", "string"),
        ("Password", "string"),
        ("Resource", "string"),
        ("UseTLS", "boolean"),
        ("ServerConnectAlgorithm", "string"),
        ("ServerRetryIntervalMultiplier", "unsignedInt"),
        ("ServerRetryMaxInterval", "unsignedInt"),
    ] {
        assert_eq!(
            ty(&format!("Device.XMPP.Connection.1.{name}")),
            expected,
            "{name}"
        );
    }
    assert_eq!(
        ty("Device.ManagementServer.ConnReqXMPPConnection"),
        "anyURI"
    );
    assert_eq!(
        ty("Device.ManagementServer.ConnReqAllowedJabberIDs"),
        "string"
    );
    assert_eq!(
        typed_value_of(spv, "Device.XMPP.Connection.1.KeepAliveInterval").0,
        "30"
    );
    assert_enable_is_last(spv, 1);
}

#[tokio::test]
async fn a_refused_xmpp_setup_is_issued_again_at_the_next_trigger_with_a_new_password() {
    let (_c, store, addr) = acs(Onboarding::default()).await;
    // Device refuses SPV (9003).
    let requests = session_with(
        addr,
        inform_181(&["0 BOOTSTRAP"], 1),
        device_replying(tree_with_xmpp(None), refuse),
    )
    .await;
    assert_eq!(
        names(&requests),
        [
            "GetParameterValues",
            "GetParameterNames",
            "AddObject",
            "SetParameterValues"
        ]
    );
    let device = the_device(&store).await;
    let first_password = value_of(the_spv(&requests), "Device.XMPP.Connection.3.Password");
    let setups = xmpp_tasks(&store, device, "set_parameter_values").await;
    assert_eq!(setups.len(), 1);
    assert_eq!(setups[0].state, TaskState::Failed);
    let error = setups[0].error.clone().unwrap();
    assert!(error.starts_with("9003 Invalid arguments"), "{error}");
    assert!(
        error.contains("KeepAliveInterval: 9006 Invalid parameter type"),
        "{error}"
    );
    assert!(!error.contains(&first_password), "never the secret");
    let (first_nonce, pending_password) = pending_xmpp(&store, device)
        .await
        .expect("kept until the next trigger");
    assert_eq!(pending_password, first_password);

    // Ordinary Inform -> not sent again, however often.
    for at in [2, 3] {
        let requests = session(
            addr,
            inform_181(&[], at),
            device_answering(tree_with_xmpp(None)),
        )
        .await;
        assert!(requests.is_empty(), "Inform {at}: {:?}", names(&requests));
    }
    assert_eq!(pending_xmpp(&store, device).await.unwrap().0, first_nonce);

    // Next BOOTSTRAP -> new login: new password + new task.
    let requests = session(
        addr,
        inform_181(&["0 BOOTSTRAP"], 4),
        device_answering(tree_with_xmpp(None)),
    )
    .await;
    assert_eq!(
        names(&requests),
        [
            "GetParameterValues",
            "GetParameterNames",
            "AddObject",
            "SetParameterValues"
        ]
    );
    let second_password = value_of(the_spv(&requests), "Device.XMPP.Connection.3.Password");
    assert_ne!(second_password, first_password);
    let (second_nonce, pending_password) = pending_xmpp(&store, device).await.unwrap();
    assert_eq!(pending_password, second_password);
    assert_ne!(second_nonce, first_nonce);
    assert!(has_key(&store, setup_key(device, &first_nonce)).await);
    assert!(has_key(&store, setup_key(device, &second_nonce)).await);
    let setups = xmpp_tasks(&store, device, "set_parameter_values").await;
    assert_eq!(
        setups.iter().map(|t| t.state).collect::<Vec<_>>(),
        [TaskState::Failed, TaskState::Succeeded]
    );
}

#[tokio::test]
async fn a_refused_connection_add_does_not_block_the_next_trigger() {
    let (_c, store, addr) = acs(Onboarding::default()).await;
    let mut device_says = device_answering(tree_with_xmpp(None));
    let requests = session_with(addr, inform_181(&["0 BOOTSTRAP"], 1), |rpc| match rpc {
        Rpc::AddObject(_) => Reply::Fault(Fault::new(9000, "Method not supported")),
        other => Reply::Answer(device_says(other)),
    })
    .await;
    assert_eq!(
        names(&requests),
        ["GetParameterValues", "GetParameterNames", "AddObject"]
    );
    let device = the_device(&store).await;
    let adds = xmpp_tasks(&store, device, "add_object").await;
    assert_eq!(adds.len(), 1);
    assert_eq!(adds[0].state, TaskState::Failed);
    assert!(adds[0].error.as_deref().unwrap().starts_with("9000 "));
    let (first_nonce, _) = pending_xmpp(&store, device).await.unwrap();

    let requests = session(
        addr,
        inform_181(&[], 2),
        device_answering(tree_with_xmpp(None)),
    )
    .await;
    assert!(requests.is_empty(), "{:?}", names(&requests));

    let requests = session(
        addr,
        inform_181(&["0 BOOTSTRAP"], 3),
        device_answering(tree_with_xmpp(None)),
    )
    .await;
    assert_eq!(
        names(&requests),
        [
            "GetParameterValues",
            "GetParameterNames",
            "AddObject",
            "SetParameterValues"
        ]
    );
    let (second_nonce, password) = pending_xmpp(&store, device).await.unwrap();
    assert_ne!(second_nonce, first_nonce);
    assert_eq!(
        value_of(the_spv(&requests), "Device.XMPP.Connection.3.Password"),
        password
    );
    assert!(has_key(&store, format!("xmpp-add:{device}:{}", hex(&first_nonce))).await);
    assert!(has_key(&store, format!("xmpp-add:{device}:{}", hex(&second_nonce))).await);
}

/// Device stuck by an earlier version: pending credential, its SPV refused long ago,
/// empty queue.
#[tokio::test]
async fn a_credential_refused_before_the_fault_was_handled_is_replaced_by_a_firmware_change() {
    let (_c, store, addr) = acs(Onboarding::default()).await;
    let device = store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &identity(),
            &dhonomos_store::InformUpdate {
                software_version: Some(FIRMWARE.into()),
                ..dhonomos_store::InformUpdate::default()
            },
        )
        .await
        .unwrap()
        .id;
    // Stored by the earlier tree read: our connection, ready for setup.
    let param = |path: &str, value: &str| ParamUpdate {
        path: path.into(),
        value: Some(value.into()),
        xsd_type: Some("string".into()),
        writable: None,
    };
    store
        .upsert_params(
            device,
            &[
                param("Device.XMPP.ConnectionNumberOfEntries", "1"),
                param("Device.XMPP.Connection.1.Username", &device.to_string()),
            ],
        )
        .await
        .unwrap();
    let (ciphertext, nonce) = secrets()
        .seal_credential(device, b"stuck-password")
        .unwrap();
    store
        .put_pending_credential(&dhonomos_store::SealedCredential {
            device_id: device,
            kind: "xmpp_pending".into(),
            username: device.to_string(),
            ciphertext,
            nonce: nonce.clone(),
            key_id: "k1".into(),
        })
        .await
        .unwrap();
    let (k, payload) = TaskKind::SetParameterValues { values: vec![] }.to_row();
    store
        .enqueue_task(&NewTask {
            idempotency_key: Some(setup_key(device, &nonce)),
            created_by: Some("system:xmpp-credentials".into()),
            ..NewTask::new(DEFAULT_TENANT, device, k, payload)
        })
        .await
        .unwrap();
    let task = store.next_task(device).await.unwrap().unwrap();
    assert!(
        store
            .fail_task(
                task.id,
                "9003 Invalid arguments | Device.XMPP.Connection.1.KeepAliveInterval: \
                 9006 Invalid parameter type",
            )
            .await
            .unwrap()
    );

    // Ordinary Inform -> nothing ...
    let requests = session(
        addr,
        inform_181(&[], 1),
        device_answering(tree_with_xmpp(None)),
    )
    .await;
    assert!(requests.is_empty(), "{:?}", names(&requests));
    // ... new firmware -> provisioned again, new login.
    let requests = session(
        addr,
        inform_181_on(&[], 2, "V100R001IRQC56B018"),
        device_answering(tree_with_xmpp(Some(&[("Username", &device.to_string())]))),
    )
    .await;
    assert_eq!(
        names(&requests),
        [
            "GetParameterValues",
            "GetParameterNames",
            "SetParameterValues"
        ]
    );
    let password = value_of(the_spv(&requests), "Device.XMPP.Connection.1.Password");
    assert_ne!(password, "stuck-password");
    let (new_nonce, pending_password) = pending_xmpp(&store, device).await.unwrap();
    assert_eq!(pending_password, password);
    assert_ne!(new_nonce, nonce);
    assert!(has_key(&store, setup_key(device, &new_nonce)).await);
}

/// Operator-admitted path (`preregistered`, `quarantine`): no trigger of its own.
/// Without a pause -> new login at every Inform to a device that keeps refusing.
#[tokio::test]
async fn the_admitted_path_leaves_a_device_that_refused_alone_for_a_day() {
    let (_c, store, addr) = acs(Onboarding {
        mode: OnboardingMode::Preregistered,
        allowed_ouis: vec![],
    })
    .await;
    let device = preregistered_and_known(&store).await;
    let requests = session_with(
        addr,
        inform_181(&[], 1),
        device_replying(tree_with_xmpp(None), refuse),
    )
    .await;
    assert_eq!(
        names(&requests),
        ["GetParameterValues", "AddObject", "SetParameterValues"]
    );
    let (first_nonce, first_password) = pending_xmpp(&store, device).await.unwrap();

    // Refused just now -> not again at next Inform, nor the one after.
    for at in [2, 3] {
        let requests = session(
            addr,
            inform_181(&[], at),
            device_answering(tree_with_xmpp(None)),
        )
        .await;
        assert!(requests.is_empty(), "Inform {at}: {:?}", names(&requests));
    }
    assert_eq!(pending_xmpp(&store, device).await.unwrap().0, first_nonce);

    // 1 day later -> retry with new login (refused again).
    age_failures(&store, 25).await;
    let requests = session_with(
        addr,
        inform_181(&[], 4),
        device_replying(tree_with_xmpp(None), refuse),
    )
    .await;
    assert_eq!(names(&requests), ["AddObject", "SetParameterValues"]);
    let (second_nonce, second_password) = pending_xmpp(&store, device).await.unwrap();
    assert_ne!(second_nonce, first_nonce);
    assert_ne!(second_password, first_password);
    assert_eq!(
        value_of(the_spv(&requests), "Device.XMPP.Connection.3.Password"),
        second_password
    );
    let requests = session(
        addr,
        inform_181(&[], 5),
        device_answering(tree_with_xmpp(None)),
    )
    .await;
    assert!(requests.is_empty(), "{:?}", names(&requests));

    // Operator removes login -> no wait.
    assert!(store.delete_credential(device, "xmpp").await.unwrap());
    let requests = session(
        addr,
        inform_181(&[], 6),
        device_answering(tree_with_xmpp(None)),
    )
    .await;
    assert_eq!(names(&requests), ["AddObject", "SetParameterValues"]);
    let (_, third_password) = pending_xmpp(&store, device).await.unwrap();
    assert_ne!(third_password, second_password);
}

/// Task end without fault (here: 3 sessions lost before device answer) -> maybe applied.
/// -> credential kept.
#[tokio::test]
async fn a_failure_that_is_no_cpe_fault_keeps_the_pending_credential() {
    let (_c, store, addr) = acs(Onboarding::default()).await;
    let lost = |tree: GetParameterValuesResponse| device_replying(tree, || Reply::Vanish);
    let requests = session_with(
        addr,
        inform_181(&["0 BOOTSTRAP"], 1),
        lost(tree_with_xmpp(None)),
    )
    .await;
    assert_eq!(
        names(&requests),
        [
            "GetParameterValues",
            "GetParameterNames",
            "AddObject",
            "SetParameterValues"
        ]
    );
    let device = the_device(&store).await;
    // Lost session noticed only when next session replaces it.
    // -> 3rd loss counted at 4th session.
    for at in [2, 3] {
        let requests = session_with(addr, inform_181(&[], at), lost(tree_with_xmpp(None))).await;
        assert_eq!(names(&requests), ["SetParameterValues"], "Inform {at}");
    }
    let (nonce, password) = pending_xmpp(&store, device).await.unwrap();

    // Next trigger keeps the credential: device may have applied it + log in with it.
    let requests = session(
        addr,
        inform_181(&["0 BOOTSTRAP"], 4),
        device_answering(tree_with_xmpp(None)),
    )
    .await;
    assert_eq!(
        names(&requests),
        ["GetParameterValues", "GetParameterNames"]
    );
    let setups = xmpp_tasks(&store, device, "set_parameter_values").await;
    assert_eq!(setups.len(), 1);
    assert_eq!(setups[0].state, TaskState::Failed);
    assert!(
        setups[0]
            .error
            .as_deref()
            .unwrap()
            .starts_with("session aborted"),
        "{:?}",
        setups[0].error
    );
    assert_eq!(
        pending_xmpp(&store, device).await.unwrap(),
        (nonce, password)
    );
}

// Wake over XMPP

/// TLS client of the XMPP server, raw XML (as xmppc).
struct Xmpp {
    io: tokio_rustls::client::TlsStream<TcpStream>,
    seen: String,
}

impl Xmpp {
    async fn until(&mut self, needle: &str) -> String {
        loop {
            if let Some(i) = self.seen.find(needle) {
                return self.seen.drain(..i + needle.len()).collect();
            }
            let mut buf = [0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(5), self.io.read(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for {needle:?}; got {:?}", self.seen))
                .unwrap_or(0);
            assert!(
                n > 0,
                "closed while waiting for {needle:?}; got {:?}",
                self.seen
            );
            self.seen.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    }

    async fn send(&mut self, s: &str) {
        self.io.write_all(s.as_bytes()).await.unwrap();
        self.io.flush().await.unwrap();
    }
}

async fn xmpp_login(
    addr: SocketAddr,
    root: &CertificateDer<'static>,
    user: &str,
    pass: &str,
) -> Xmpp {
    use base64::Engine as _;
    let open = format!(
        "<?xml version='1.0'?><stream:stream to='{DOMAIN}' xmlns='jabber:client' \
         xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
    );
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(open.as_bytes()).await.unwrap();
    let mut seen = Vec::new();
    while !String::from_utf8_lossy(&seen).contains("</stream:features>") {
        let mut buf = [0u8; 1024];
        let n = tcp.read(&mut buf).await.unwrap();
        seen.extend_from_slice(&buf[..n]);
    }
    tcp.write_all(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        .await
        .unwrap();
    seen.clear();
    while !String::from_utf8_lossy(&seen).contains("<proceed") {
        let mut buf = [0u8; 1024];
        let n = tcp.read(&mut buf).await.unwrap();
        seen.extend_from_slice(&buf[..n]);
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let io = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(DOMAIN).unwrap(), tcp)
        .await
        .unwrap();
    let mut x = Xmpp {
        io,
        seen: String::new(),
    };
    x.send(&open).await;
    x.until("</stream:features>").await;
    let plain = base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"));
    x.send(&format!(
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{plain}</auth>"
    ))
    .await;
    x.until("<success").await;
    x.send(&open).await;
    x.until("</stream:features>").await;
    x.send("<iq type='set' id='b1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq>")
        .await;
    x.until("</jid>").await;
    x.until("</iq>").await;
    x
}

/// `id` of the Connection Request iq in `xml`.
fn request_id(xml: &str) -> String {
    xml.split("id=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned()
}

/// Last wake in the device row: (method, outcome).
async fn last_wake(store: &Store, device: uuid::Uuid) -> (Option<String>, Option<String>) {
    let d = store.get_device(device).await.unwrap().unwrap();
    assert!(d.last_wake_at.is_some(), "every wake is recorded");
    (d.last_wake_method, d.last_wake_outcome)
}

#[tokio::test]
async fn waking_uses_xmpp_first_and_falls_back_to_http() {
    let (_c, store) = database().await;
    // Device: registered, CR URL answers 204 + counts hits.
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/cr", http.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    {
        let hits = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = http.accept().await else {
                    return;
                };
                let hits = hits.clone();
                tokio::spawn(async move {
                    let svc =
                        hyper::service::service_fn(move |_req: Request<hyper::body::Incoming>| {
                            hits.fetch_add(1, Ordering::SeqCst);
                            async {
                                let mut resp = hyper::Response::new(Full::new(Bytes::new()));
                                *resp.status_mut() = StatusCode::NO_CONTENT;
                                Ok::<_, std::convert::Infallible>(resp)
                            }
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
    }
    let device = store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &identity(),
            &dhonomos_store::InformUpdate {
                connection_request_url: Some(url),
                ..dhonomos_store::InformUpdate::default()
            },
        )
        .await
        .unwrap()
        .id;
    // XMPP login, as zero-touch stores it (active).
    let (ciphertext, nonce) = secrets().seal_credential(device, b"xmpp-secret").unwrap();
    store
        .put_credential(&dhonomos_store::SealedCredential {
            device_id: device,
            kind: "xmpp".into(),
            username: device.to_string(),
            ciphertext,
            nonce,
            key_id: "k1".into(),
        })
        .await
        .unwrap();

    // XMPP server, cert for xmpp.test.
    let ck = rcgen::generate_simple_self_signed(vec![DOMAIN.to_owned()]).unwrap();
    let resolver = CertResolver::from_pem(&ck.cert.pem(), &ck.signing_key.serialize_pem()).unwrap();
    assert!(resolver.covers(DOMAIN));
    let root = CertificateDer::from(ck.cert.der().to_vec());
    let server = dhonomos_xmpp::XmppServer::new(
        dhonomos_xmpp::XmppConfig::new(DOMAIN),
        Arc::new(XmppAccounts::new(store.clone(), DEFAULT_TENANT, secrets())),
        dhonomos_xmpp::tls_acceptor(resolver).unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let xmpp_addr = listener.local_addr().unwrap();
    {
        let server = server.clone();
        tokio::spawn(async move { server.serve(listener, std::future::pending()).await });
    }

    let waker = Waker::new(
        store.clone(),
        Some(ConnReqCredentials {
            username: "cr-user".into(),
            password: "cr-pass".into(),
        }),
        Duration::from_secs(2),
    )
    .with_address_policy(dhonomos_cwmp_server::AddressPolicy::permit_all())
    .with_xmpp(server.clone())
    .with_xmpp_timeout(Duration::from_millis(600));

    // No XMPP connection -> HTTP.
    assert_eq!(
        store
            .get_device(device)
            .await
            .unwrap()
            .unwrap()
            .last_wake_at,
        None,
        "never woken"
    );
    assert_eq!(waker.wake(device).await, WakeOutcome::Sent);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        last_wake(&store, device).await,
        (Some("http".into()), Some("sent".into()))
    );

    // Connected + device answers -> XMPP only, shared CR credentials (no per-device ones).
    let mut cpe = xmpp_login(xmpp_addr, &root, &device.to_string(), "xmpp-secret").await;
    assert!(server.is_connected(&device.to_string()));
    assert!(
        store
            .get_device(device)
            .await
            .unwrap()
            .unwrap()
            .xmpp_connected_at
            .is_some(),
        "recorded when the session bound"
    );
    let wake = tokio::spawn({
        let waker = waker.clone();
        async move { waker.wake(device).await }
    });
    let request = cpe.until("</iq>").await;
    assert!(
        request.contains("<username>cr-user</username><password>cr-pass</password>"),
        "{request}"
    );
    cpe.send(&format!(
        "<iq type='result' id='{}'/>",
        request_id(&request)
    ))
    .await;
    let outcome = wake.await.unwrap();
    assert_eq!(outcome, WakeOutcome::SentXmpp, "{}", outcome.describe());
    assert_eq!(outcome.describe(), "sent over XMPP");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "HTTP was not used");
    assert_eq!(
        last_wake(&store, device).await,
        (Some("xmpp".into()), Some("sent over XMPP".into()))
    );

    // Connected but silent -> HTTP after XMPP timeout.
    let wake = tokio::spawn({
        let waker = waker.clone();
        async move { waker.wake(device).await }
    });
    cpe.until("</iq>").await;
    assert_eq!(wake.await.unwrap(), WakeOutcome::Sent);
    assert_eq!(hits.load(Ordering::SeqCst), 2, "fell back to HTTP");
    assert_eq!(
        last_wake(&store, device).await,
        (Some("http".into()), Some("sent".into())),
        "the way it went out, not the way it was tried first"
    );

    // Connected, device refuses credentials -> final answer, no fallback.
    let wake = tokio::spawn({
        let waker = waker.clone();
        async move { waker.wake(device).await }
    });
    let request = cpe.until("</iq>").await;
    cpe.send(&format!(
        "<iq type='error' id='{}'><error type='auth'><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
        request_id(&request)
    ))
    .await;
    let outcome = wake.await.unwrap();
    assert_eq!(
        outcome,
        WakeOutcome::Failed("XMPP connection request refused: not-authorized".into())
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "no fallback after a refusal"
    );
    assert_eq!(
        last_wake(&store, device).await,
        (
            None,
            Some("failed: XMPP connection request refused: not-authorized".into())
        ),
        "a failure sent nothing"
    );

    // Disconnect -> session end recorded.
    cpe.send("</stream:stream>").await;
    cpe.until("</stream:stream>").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!server.is_connected(&device.to_string()));
    assert!(
        store
            .get_device(device)
            .await
            .unwrap()
            .unwrap()
            .xmpp_connected_at
            .is_none()
    );
    assert_eq!(waker.wake(device).await, WakeOutcome::Sent);
    assert_eq!(hits.load(Ordering::SeqCst), 3);

    // Later session of same device -> old one cannot clear what newer one set.
    let mut first = xmpp_login(xmpp_addr, &root, &device.to_string(), "xmpp-secret").await;
    let mut second = xmpp_login(xmpp_addr, &root, &device.to_string(), "xmpp-secret").await;
    first.until("<conflict").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        store
            .get_device(device)
            .await
            .unwrap()
            .unwrap()
            .xmpp_connected_at
            .is_some()
    );
    second.send("</stream:stream>").await;
    second.until("</stream:stream>").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        store
            .get_device(device)
            .await
            .unwrap()
            .unwrap()
            .xmpp_connected_at
            .is_none()
    );

    // Server start -> clears what a dead process left.
    store
        .set_xmpp_connected(device, time::OffsetDateTime::now_utc())
        .await
        .unwrap();
    assert_eq!(store.clear_all_xmpp_connected().await.unwrap(), 1);
    assert!(
        store
            .get_device(device)
            .await
            .unwrap()
            .unwrap()
            .xmpp_connected_at
            .is_none()
    );
}

#[tokio::test]
async fn a_pending_xmpp_password_logs_in_and_becomes_the_devices_password() {
    let (_c, store) = database().await;
    let device = store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &identity(),
            &dhonomos_store::InformUpdate::default(),
        )
        .await
        .unwrap()
        .id;
    let (ciphertext, nonce) = secrets().seal_credential(device, b"pending-pw").unwrap();
    store
        .put_pending_credential(&dhonomos_store::SealedCredential {
            device_id: device,
            kind: "xmpp_pending".into(),
            username: device.to_string(),
            ciphertext,
            nonce,
            key_id: "k1".into(),
        })
        .await
        .unwrap();
    let ck = rcgen::generate_simple_self_signed(vec![DOMAIN.to_owned()]).unwrap();
    let resolver = CertResolver::from_pem(&ck.cert.pem(), &ck.signing_key.serialize_pem()).unwrap();
    let root = CertificateDer::from(ck.cert.der().to_vec());
    let server = dhonomos_xmpp::XmppServer::new(
        dhonomos_xmpp::XmppConfig::new(DOMAIN),
        Arc::new(XmppAccounts::new(store.clone(), DEFAULT_TENANT, secrets())),
        dhonomos_xmpp::tls_acceptor(resolver).unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { server.serve(listener, std::future::pending()).await });

    let _cpe = xmpp_login(addr, &root, &device.to_string(), "pending-pw").await;
    let active = store
        .get_credential(device, "xmpp")
        .await
        .unwrap()
        .expect("promoted");
    assert_eq!(
        secrets()
            .open_credential(device, &active.ciphertext, &active.nonce)
            .unwrap(),
        b"pending-pw"
    );
    assert!(
        store
            .get_credential(device, "xmpp_pending")
            .await
            .unwrap()
            .is_none()
    );

    // Retired device -> no login.
    store
        .set_device_status(DEFAULT_TENANT, device, "retired")
        .await
        .unwrap();
    use dhonomos_xmpp::Accounts as _;
    let accounts = XmppAccounts::new(store.clone(), DEFAULT_TENANT, secrets());
    assert!(
        accounts
            .credentials(&device.to_string())
            .await
            .unwrap()
            .is_empty()
    );
}
