//! E2E: real listener + CWMP backend + PostgreSQL container, over HTTP.
//! Message captured from genieacs-sim.
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use dhonomos_core::{CpeCredentials, CwmpBackend, TaskKind};
use dhonomos_cwmp_codec::{
    Body, CwmpNamespace, DownloadResponse, Envelope, GetParameterValuesResponse, ParameterValue,
    RebootResponse, Rpc, TransferComplete, TransferFault,
};
use dhonomos_cwmp_server::{AcsServer, AuthMode, Config, bind};
use dhonomos_store::{CwmpIdentity, DEFAULT_TENANT, NewTask, Store, TaskState};
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use tokio::net::TcpStream;

const INFORM: &[u8] = include_bytes!("../../cwmp-codec/tests/corpus/genieacs-sim/01-Inform.xml");

async fn setup(timeout: Duration) -> (ContainerAsync<Postgres>, Store, SocketAddr) {
    setup_with(timeout, None).await
}

async fn setup_with(
    timeout: Duration,
    signer: Option<dhonomos_core::FileSigner>,
) -> (ContainerAsync<Postgres>, Store, SocketAddr) {
    setup_full(timeout, signer, dhonomos_core::Onboarding::default()).await
}

async fn setup_full(
    timeout: Duration,
    signer: Option<dhonomos_core::FileSigner>,
    onboarding: dhonomos_core::Onboarding,
) -> (ContainerAsync<Postgres>, Store, SocketAddr) {
    setup_custom(timeout, |b| {
        let b = b.with_onboarding(onboarding);
        match signer {
            Some(s) => b.with_files(s),
            None => b,
        }
    })
    .await
}

async fn setup_custom(
    timeout: Duration,
    customize: impl FnOnce(CwmpBackend) -> CwmpBackend,
) -> (ContainerAsync<Postgres>, Store, SocketAddr) {
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
    let backend = customize(CwmpBackend::new(
        store.clone(),
        DEFAULT_TENANT,
        CpeCredentials::None,
    ));
    let config = Config {
        auth: AuthMode::None,
        session_timeout: timeout,
        ..Config::default()
    };
    let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(AcsServer::new(config, backend).serve(listener, std::future::pending()));
    (container, store, addr)
}

struct Cpe {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
}

impl Cpe {
    async fn connect(addr: SocketAddr) -> Self {
        let io = TokioIo::new(TcpStream::connect(addr).await.unwrap());
        let (sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        Self { sender }
    }

    /// Post on the same connection -> no cookie needed.
    async fn post(&mut self, body: Vec<u8>) -> (StatusCode, Option<Envelope>) {
        let resp = self
            .sender
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
    }

    async fn reply(
        &mut self,
        to: &Envelope,
        rpc: impl Into<Rpc>,
    ) -> (StatusCode, Option<Envelope>) {
        let env = Envelope::rpc(CwmpNamespace::V1_0, to.header.id.clone().unwrap(), rpc);
        self.post(env.encode().into_bytes()).await
    }
}

fn rpc(e: &Option<Envelope>) -> &Rpc {
    match &e.as_ref().unwrap().body {
        Body::Rpc(r) => r,
        Body::Fault(f) => panic!("fault {f:?}"),
    }
}

fn identity() -> CwmpIdentity {
    CwmpIdentity {
        oui: "202BC1".into(),
        product_class: "BM632w".into(),
        serial_number: "000000".into(),
    }
}

#[tokio::test]
async fn new_device_is_registered_and_fully_read() {
    let (_c, store, addr) = setup(Duration::from_secs(30)).await;
    let mut cpe = Cpe::connect(addr).await;

    let (status, resp) = cpe.post(INFORM.to_vec()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(matches!(rpc(&resp), Rpc::InformResponse(_)));

    // Zero-touch: new device -> full read of its tree.
    let (_, req) = cpe.post(Vec::new()).await;
    let Rpc::GetParameterValues(gpv) = rpc(&req) else {
        panic!("expected GPV")
    };
    assert_eq!(gpv.parameter_names, ["InternetGatewayDevice."]);
    // Device also reports its Inform values (full read drops what it does not return).
    let tree = Tree::of_inform(INFORM).with(&[
        ParameterValue::new(
            "InternetGatewayDevice.DeviceInfo.UpTime",
            "1234",
            "unsignedInt",
        ),
        ParameterValue::new(
            "InternetGatewayDevice.DeviceInfo.SoftwareVersion",
            "V2",
            "string",
        ),
        ParameterValue::new(
            "InternetGatewayDevice.DeviceInfo.ModelName",
            "BM632w-X",
            "string",
        ),
    ]);
    let values = tree.values(&gpv.parameter_names);
    // Then GPN -> writability (config backups).
    let (_, req) = cpe.reply(req.as_ref().unwrap(), values).await;
    let Rpc::GetParameterNames(gpn) = rpc(&req) else {
        panic!("expected GPN")
    };
    assert_eq!(
        (gpn.parameter_path.as_str(), gpn.next_level),
        ("InternetGatewayDevice.", false)
    );
    let mut names = tree.names(&gpn.parameter_path);
    for p in &mut names.parameter_list {
        p.writable = p.name == "InternetGatewayDevice.DeviceInfo.ProvisioningCode";
    }
    let (status, _) = cpe.reply(req.as_ref().unwrap(), names).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let id = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    let dev = store.get_device(id).await.unwrap().unwrap();
    assert_eq!(
        dev.manufacturer.as_deref(),
        Some("Huawei Technologies Co., Ltd.")
    );
    assert_eq!(dev.software_version.as_deref(), Some("V100R001IRQC56B017"));
    // Not in Inform -> from full read.
    assert_eq!(dev.model_name.as_deref(), Some("BM632w-X"));
    assert_eq!(dev.data_model.as_deref(), Some("InternetGatewayDevice"));
    assert_eq!(dev.last_remote_addr.as_deref(), Some("127.0.0.1"));
    assert!(dev.connection_request_url.is_some());

    let params = store
        .get_params(id, "InternetGatewayDevice.DeviceInfo.")
        .await
        .unwrap();
    let get = |p: &str| {
        params
            .iter()
            .find(|x| x.path.ends_with(p))
            .and_then(|x| x.value.clone())
    };
    assert_eq!(get("UpTime").as_deref(), Some("1234"));
    assert_eq!(
        get("SoftwareVersion").as_deref(),
        Some("V2"),
        "GPV result overrides Inform value"
    );
    assert_eq!(
        get("HardwareVersion").as_deref(),
        Some("40501"),
        "from the Inform, and read again"
    );

    let tasks = store.list_tasks(id, 10).await.unwrap();
    assert_eq!(tasks.len(), 2);
    assert!(tasks.iter().all(|t| t.state == TaskState::Succeeded));
    assert_eq!(
        store
            .get_params(id, "InternetGatewayDevice.DeviceInfo.ProvisioningCode")
            .await
            .unwrap()[0]
            .writable,
        Some(true)
    );
    assert_eq!(store.list_events(id, 10).await.unwrap()[0].kind, "inform");

    // Periodic Inform of a known device -> no new full read.
    let mut cpe = Cpe::connect(addr).await;
    cpe.post(INFORM.to_vec()).await;
    let (status, _) = cpe.post(Vec::new()).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// Known device on new firmware (BOOT, other SoftwareVersion) -> full read again, as at
/// zero-touch. Same firmware -> no read.
#[tokio::test]
async fn new_firmware_is_read_again() {
    let (_c, store, addr) = setup(Duration::from_secs(30)).await;
    known_device(&store, addr).await;
    let inform = String::from_utf8(INFORM.to_vec()).unwrap();

    // Same firmware -> nothing to do.
    let mut cpe = Cpe::connect(addr).await;
    cpe.post(INFORM.to_vec()).await;
    let (status, _) = cpe.post(Vec::new()).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // New firmware after upgrade -> whole tree again.
    let upgraded = inform
        .replace("V100R001IRQC56B017", "V100R001IRQC56B018")
        .replace("2 PERIODIC", "1 BOOT")
        .replace("2026-10-03T11:26:23.700Z", "2026-10-03T12:00:00.000Z");
    let mut cpe = Cpe::connect(addr).await;
    cpe.post(upgraded.into_bytes()).await;
    let (_, req) = cpe.post(Vec::new()).await;
    let Rpc::GetParameterValues(gpv) = rpc(&req) else {
        panic!("expected the full read")
    };
    assert_eq!(gpv.parameter_names, ["InternetGatewayDevice."]);
}

/// Params of a simulated CPE: its Inform + [`Tree::with`] + what the ACS sets.
/// Object read drops stored rows it does not return (ADR-111) -> stub answers with all it
/// has, as a real device does.
struct Tree(std::collections::BTreeMap<String, ParameterValue>);

impl Tree {
    fn of_inform(inform: &[u8]) -> Self {
        let env = Envelope::decode(inform).unwrap().unwrap();
        let Body::Rpc(Rpc::Inform(inf)) = env.body else {
            panic!("not an Inform")
        };
        Self(
            inf.parameter_list
                .into_iter()
                .map(|p| (p.name.clone(), p))
                .collect(),
        )
    }

    fn with(mut self, params: &[ParameterValue]) -> Self {
        self.set(params);
        self
    }

    fn set(&mut self, params: &[ParameterValue]) {
        for p in params {
            self.0.insert(p.name.clone(), p.clone());
        }
    }

    /// GPV: object name -> all under it.
    fn values(&self, names: &[String]) -> GetParameterValuesResponse {
        GetParameterValuesResponse {
            parameter_list: self
                .0
                .values()
                .filter(|p| {
                    names.iter().any(|n| {
                        if n.is_empty() || n.ends_with('.') {
                            p.name.starts_with(n.as_str())
                        } else {
                            &p.name == n
                        }
                    })
                })
                .cloned()
                .collect(),
        }
    }

    /// GPN of the whole subtree under `path`: objects + parameters.
    fn names(&self, path: &str) -> dhonomos_cwmp_codec::GetParameterNamesResponse {
        let mut names = std::collections::BTreeSet::new();
        for name in self.0.keys().filter(|n| n.starts_with(path)) {
            for (i, _) in name.match_indices('.') {
                if i + 1 >= path.len() {
                    names.insert(name[..=i].to_owned());
                }
            }
            names.insert(name.clone());
        }
        dhonomos_cwmp_codec::GetParameterNamesResponse {
            parameter_list: names
                .into_iter()
                .map(|name| dhonomos_cwmp_codec::ParameterInfo {
                    name,
                    writable: false,
                })
                .collect(),
        }
    }
}

/// One CPE session: send `inform`, answer the ACS until session end (reads from Inform
/// params, writes applied). Returns the ACS requests, sorted.
async fn answer_session(addr: SocketAddr, inform: Vec<u8>) -> Vec<String> {
    let tree = Tree::of_inform(&inform);
    answer_session_with(addr, inform, tree).await
}

/// [`answer_session`] for a CPE that has `tree`.
async fn answer_session_with(addr: SocketAddr, inform: Vec<u8>, mut tree: Tree) -> Vec<String> {
    let mut cpe = Cpe::connect(addr).await;
    cpe.post(inform).await;
    let mut asked = Vec::new();
    let (mut status, mut req) = cpe.post(Vec::new()).await;
    while status == StatusCode::OK {
        let answer: Rpc = match rpc(&req) {
            Rpc::GetParameterValues(r) => {
                asked.push(format!(
                    "GetParameterValues {}",
                    r.parameter_names.join(",")
                ));
                tree.values(&r.parameter_names).into()
            }
            Rpc::GetParameterNames(r) => {
                asked.push(format!("GetParameterNames {}", r.parameter_path));
                tree.names(&r.parameter_path).into()
            }
            Rpc::SetParameterValues(r) => {
                asked.push("SetParameterValues".into());
                tree.set(&r.parameter_list);
                dhonomos_cwmp_codec::SetParameterValuesResponse { status: 0 }.into()
            }
            other => panic!("unexpected request {other:?}"),
        };
        (status, req) = cpe.reply(req.as_ref().unwrap(), answer).await;
    }
    asked.sort();
    asked
}

/// Pre-registered device: record exists before 1st Inform -> Inform creates no device.
/// Still 1st contact (no SoftwareVersion until an Inform reports one) -> full read +
/// new-device presets. Next Inform, same firmware -> neither.
/// Device created by its 1st Inform -> same.
#[tokio::test]
async fn a_preregistered_device_is_read_whole_at_its_first_inform() {
    let presets = dhonomos_core::Presets::from_yaml(
        r#"
presets:
  - name: first-contact
    when: { new_device: true }
    run:
      - kind: set_parameter_values
        payload:
          values:
            - { name: InternetGatewayDevice.ManagementServer.PeriodicInformInterval, value: "600", type: unsignedInt }
  - name: every-inform
    when: { oui: 202BC1 }
    run:
      - kind: set_parameter_values
        payload:
          values:
            - { name: InternetGatewayDevice.ManagementServer.PeriodicInformInterval, value: "3600", type: unsignedInt }
"#,
    )
    .unwrap();
    let (_c, store, addr) =
        setup_custom(Duration::from_secs(30), |b| b.with_presets(presets)).await;

    let full_read = [
        "GetParameterNames InternetGatewayDevice.",
        "GetParameterValues InternetGatewayDevice.",
    ];
    // Tasks of `kind` queued by `by` for the device.
    let queued = async |device: uuid::Uuid, kind: &str, by: &str| {
        store
            .list_tasks(device, 100)
            .await
            .unwrap()
            .into_iter()
            .filter(|t| t.kind == kind && t.created_by.as_deref() == Some(by))
            .count()
    };

    // Pre-registered: record exists, no firmware version.
    let pre = CwmpIdentity {
        serial_number: "PREREG1".into(),
        ..identity()
    };
    let out = store
        .preregister_cwmp_device(DEFAULT_TENANT, &pre, &[])
        .await
        .unwrap();
    assert!(out.created, "pre-registration creates the record");
    let device = out.id;
    assert_eq!(
        store
            .get_device(device)
            .await
            .unwrap()
            .unwrap()
            .software_version,
        None
    );

    // 1st Inform -> whole tree + names read, new-device presets apply.
    let asked = answer_session(
        addr,
        inform_at(&pre.serial_number, &[], "2026-10-14T09:00:00Z"),
    )
    .await;
    assert_eq!(
        asked,
        [
            full_read[0],
            full_read[1],
            "SetParameterValues",
            "SetParameterValues"
        ]
    );
    assert_eq!(
        queued(device, "get_parameter_values", "system:bootstrap").await,
        1
    );
    assert_eq!(
        queued(device, "get_parameter_names", "system:bootstrap").await,
        1
    );
    assert_eq!(
        queued(device, "set_parameter_values", "preset:first-contact").await,
        1
    );
    assert_eq!(
        queued(device, "set_parameter_values", "preset:every-inform").await,
        1
    );
    let known = store.get_device(device).await.unwrap().unwrap();
    assert_eq!(
        known.software_version.as_deref(),
        Some("V100R001IRQC56B017")
    );

    // Next Inform (later CurrentTime -> no dedup), same firmware -> only the every-Inform
    // preset runs.
    let asked = answer_session(
        addr,
        inform_at(&pre.serial_number, &[], "2026-10-14T10:00:00Z"),
    )
    .await;
    assert_eq!(asked, ["SetParameterValues"]);
    assert_eq!(
        queued(device, "get_parameter_values", "system:bootstrap").await,
        1
    );
    assert_eq!(
        queued(device, "get_parameter_names", "system:bootstrap").await,
        1
    );
    assert_eq!(
        queued(device, "set_parameter_values", "preset:first-contact").await,
        1
    );
    assert_eq!(
        queued(device, "set_parameter_values", "preset:every-inform").await,
        2
    );

    // Created by its 1st Inform -> same.
    let serial = "NEWBYINFORM";
    let asked = answer_session(addr, inform_at(serial, &[], "2026-10-14T09:00:00Z")).await;
    assert_eq!(
        asked,
        [
            full_read[0],
            full_read[1],
            "SetParameterValues",
            "SetParameterValues"
        ]
    );
    let created = store
        .find_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                serial_number: serial.into(),
                ..identity()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        queued(created, "get_parameter_values", "system:bootstrap").await,
        1
    );
    assert_eq!(
        queued(created, "set_parameter_values", "preset:first-contact").await,
        1
    );
    let asked = answer_session(addr, inform_at(serial, &[], "2026-10-14T10:00:00Z")).await;
    assert_eq!(asked, ["SetParameterValues"]);
    assert_eq!(
        queued(created, "get_parameter_values", "system:bootstrap").await,
        1
    );
    assert_eq!(
        queued(created, "set_parameter_values", "preset:first-contact").await,
        1
    );
}

async fn known_device(store: &Store, addr: SocketAddr) -> uuid::Uuid {
    // Session 1: register + finish bootstrap read (device reports its Inform values).
    let tree = Tree::of_inform(INFORM);
    let mut cpe = Cpe::connect(addr).await;
    cpe.post(INFORM.to_vec()).await;
    let (_, req) = cpe.post(Vec::new()).await;
    let (_, req) = cpe
        .reply(
            req.as_ref().unwrap(),
            tree.values(&["InternetGatewayDevice.".into()]),
        )
        .await;
    cpe.reply(req.as_ref().unwrap(), tree.names("InternetGatewayDevice."))
        .await;
    store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap()
}

async fn enqueue(store: &Store, device: uuid::Uuid, kind: TaskKind) -> uuid::Uuid {
    let (k, payload) = kind.to_row();
    store
        .enqueue_task(&NewTask::new(DEFAULT_TENANT, device, k, payload))
        .await
        .unwrap()
        .0
}

/// Download of a stored file -> carries its size + SHA-256 (USP devices check the image).
#[tokio::test]
async fn stored_file_download_carries_size_and_sha256() {
    let (_c, store, _) = setup(Duration::from_secs(30)).await;
    let device = store
        .preregister_cwmp_device(DEFAULT_TENANT, &identity(), &[])
        .await
        .unwrap()
        .id;
    let file = uuid::Uuid::now_v7();
    store
        .insert_file(&dhonomos_store::NewFile {
            id: file,
            tenant_id: DEFAULT_TENANT,
            name: "fw.bin".into(),
            file_type: "1 Firmware Upgrade Image".into(),
            size_bytes: 1234,
            sha256: vec![0xab; 32],
            version: None,
            device_id: None,
        })
        .await
        .unwrap();
    let signer = dhonomos_core::FileSigner::new(
        b"k".to_vec(),
        "http://files.test",
        Duration::from_secs(3600),
    );
    let kind = TaskKind::from_row("download", &serde_json::json!({ "file_id": file })).unwrap();
    let resolved =
        dhonomos_core::files::resolve_download(&store, Some(&signer), DEFAULT_TENANT, device, kind)
            .await
            .unwrap();
    let TaskKind::Download {
        file_size,
        sha256,
        url,
        ..
    } = resolved
    else {
        panic!("not a download")
    };
    assert_eq!(
        (file_size, sha256.as_str()),
        (1234, "ab".repeat(32).as_str())
    );
    assert!(url.starts_with("http://files.test/files/"));
}

/// Device upload (config backup holds its secrets) -> back to that device only.
/// Dispatch refuses it for any other device (audit M-2).
#[tokio::test]
async fn device_uploaded_file_is_sent_back_only_to_that_device() {
    let (_c, store, _) = setup(Duration::from_secs(30)).await;
    let owner = store
        .preregister_cwmp_device(DEFAULT_TENANT, &identity(), &[])
        .await
        .unwrap()
        .id;
    let other = store
        .preregister_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                serial_number: "111111".into(),
                ..identity()
            },
            &[],
        )
        .await
        .unwrap()
        .id;
    let new_file = |device_id| {
        let id = uuid::Uuid::now_v7();
        dhonomos_store::NewFile {
            id,
            tenant_id: DEFAULT_TENANT,
            name: format!("{id}.cfg"),
            file_type: "3 Vendor Configuration File".into(),
            size_bytes: 10,
            sha256: vec![1; 32],
            version: None,
            device_id,
        }
    };
    let backup = new_file(Some(owner));
    let shared = new_file(None);
    store.insert_file(&backup).await.unwrap();
    store.insert_file(&shared).await.unwrap();
    let signer = dhonomos_core::FileSigner::new(
        b"k".to_vec(),
        "http://files.test",
        Duration::from_secs(3600),
    );
    let resolve = |file: uuid::Uuid, device: uuid::Uuid| {
        let store = store.clone();
        let signer = signer.clone();
        async move {
            let kind =
                TaskKind::from_row("download", &serde_json::json!({ "file_id": file })).unwrap();
            dhonomos_core::files::resolve_download(
                &store,
                Some(&signer),
                DEFAULT_TENANT,
                device,
                kind,
            )
            .await
        }
    };
    assert!(resolve(backup.id, owner).await.is_ok());
    let refused = resolve(backup.id, other).await.unwrap_err();
    assert!(
        refused.contains("can only be sent back to that device"),
        "{refused}"
    );
    // File not uploaded by any device (firmware) -> any device.
    assert!(resolve(shared.id, other).await.is_ok());
}

#[tokio::test]
async fn download_completes_with_transfer_complete_in_a_later_session() {
    let (_c, store, addr) = setup(Duration::from_millis(300)).await;
    let device = known_device(&store, addr).await;
    let task = enqueue(
        &store,
        device,
        TaskKind::Download {
            file_id: None,
            file_type: "1 Firmware Upgrade Image".into(),
            url: "http://files/fw.bin".into(),
            username: String::new(),
            password: String::new(),
            file_size: 0,
            target_file_name: String::new(),
            sha256: String::new(),
            delay_seconds: 0,
        },
    )
    .await;

    let mut cpe = Cpe::connect(addr).await;
    cpe.post(INFORM.to_vec()).await;
    let (_, req) = cpe.post(Vec::new()).await;
    let Rpc::Download(dl) = rpc(&req) else {
        panic!("expected Download")
    };
    assert_eq!(dl.command_key, task.simple().to_string());
    // Accepted, not finished yet.
    let resp = DownloadResponse {
        status: 1,
        ..DownloadResponse::default()
    };
    let (status, _) = cpe.reply(req.as_ref().unwrap(), resp).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        store.get_task(task).await.unwrap().unwrap().state,
        TaskState::Running
    );

    // Aborted session -> must not restart the transfer.
    let mut cpe = Cpe::connect(addr).await;
    cpe.post(INFORM.to_vec()).await;
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(
        store.get_task(task).await.unwrap().unwrap().state,
        TaskState::Running
    );

    // After upgrade -> CPE reports completion.
    let mut cpe = Cpe::connect(addr).await;
    cpe.post(INFORM.to_vec()).await;
    let tc = Envelope::rpc(
        CwmpNamespace::V1_0,
        "tc1",
        TransferComplete {
            command_key: task.simple().to_string(),
            fault: TransferFault::default(),
            start_time: "2026-10-03T00:00:00Z".into(),
            complete_time: "2026-10-03T00:01:00Z".into(),
        },
    );
    let (_, resp) = cpe.post(tc.encode().into_bytes()).await;
    assert!(matches!(rpc(&resp), Rpc::TransferCompleteResponse(_)));
    let (status, _) = cpe.post(Vec::new()).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        store.get_task(task).await.unwrap().unwrap().state,
        TaskState::Succeeded
    );
    let kinds: Vec<_> = store
        .list_events(device, 20)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert!(kinds.contains(&"transfer_complete".to_owned()));
}

#[tokio::test]
async fn timed_out_session_requeues_its_task() {
    let (_c, store, addr) = setup(Duration::from_millis(300)).await;
    let device = known_device(&store, addr).await;
    let task = enqueue(&store, device, TaskKind::Reboot).await;

    let mut cpe = Cpe::connect(addr).await;
    cpe.post(INFORM.to_vec()).await;
    let (_, req) = cpe.post(Vec::new()).await;
    assert!(matches!(rpc(&req), Rpc::Reboot(_)));
    // CPE goes silent.
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(
        store.get_task(task).await.unwrap().unwrap().state,
        TaskState::Pending
    );

    // Next session -> sent again + completed.
    let mut cpe = Cpe::connect(addr).await;
    cpe.post(INFORM.to_vec()).await;
    let (_, req) = cpe.post(Vec::new()).await;
    assert!(matches!(rpc(&req), Rpc::Reboot(_)));
    cpe.reply(req.as_ref().unwrap(), RebootResponse {}).await;
    let t = store.get_task(task).await.unwrap().unwrap();
    assert_eq!((t.state, t.attempts), (TaskState::Succeeded, 2));
}

#[tokio::test]
async fn stored_files_are_sent_as_signed_urls() {
    let signer = dhonomos_core::FileSigner::new(
        b"k".to_vec(),
        "http://files.test:7548",
        Duration::from_secs(3600),
    );
    let (_c, store, addr) = setup_with(Duration::from_secs(30), Some(signer.clone())).await;
    let device = known_device(&store, addr).await;
    let file = uuid::Uuid::now_v7();
    store
        .insert_file(&dhonomos_store::NewFile {
            device_id: None,
            id: file,
            tenant_id: DEFAULT_TENANT,
            name: "fw-2.0.bin".into(),
            file_type: "1 Firmware Upgrade Image".into(),
            size_bytes: 4096,
            sha256: vec![0; 32],
            version: Some("2.0".into()),
        })
        .await
        .unwrap();
    let missing = enqueue(
        &store,
        device,
        TaskKind::Download {
            file_id: Some(uuid::Uuid::now_v7()),
            file_type: String::new(),
            url: String::new(),
            username: String::new(),
            password: String::new(),
            file_size: 0,
            target_file_name: String::new(),
            sha256: String::new(),
            delay_seconds: 0,
        },
    )
    .await;
    let task = enqueue(
        &store,
        device,
        TaskKind::Download {
            file_id: Some(file),
            file_type: String::new(),
            url: String::new(),
            username: String::new(),
            password: String::new(),
            file_size: 0,
            target_file_name: String::new(),
            sha256: String::new(),
            delay_seconds: 0,
        },
    )
    .await;

    let mut cpe = Cpe::connect(addr).await;
    cpe.post(INFORM.to_vec()).await;
    let (_, req) = cpe.post(Vec::new()).await;
    let Rpc::Download(dl) = rpc(&req) else {
        panic!("expected Download")
    };
    assert_eq!(dl.command_key, task.simple().to_string());
    assert!(
        dl.url.starts_with(&format!(
            "http://files.test:7548/files/{file}/fw-2.0.bin?d={device}&e="
        )),
        "{}",
        dl.url
    );
    assert_eq!(
        (
            dl.file_size,
            dl.file_type.as_str(),
            dl.target_file_name.as_str()
        ),
        (4096, "1 Firmware Upgrade Image", "fw-2.0.bin")
    );
    // Task with missing file -> failed, not sent.
    let t = store.get_task(missing).await.unwrap().unwrap();
    assert_eq!(t.state, TaskState::Failed);
    assert!(t.error.unwrap().contains("not found"));
}

fn fault_code(e: &Option<Envelope>) -> Option<u32> {
    match &e.as_ref()?.body {
        Body::Fault(f) => Some(f.code),
        Body::Rpc(_) => None,
    }
}

#[tokio::test]
async fn quarantined_devices_get_no_tasks_until_activated() {
    use dhonomos_core::{Onboarding, OnboardingMode};
    let policy = Onboarding {
        mode: OnboardingMode::Quarantine,
        allowed_ouis: vec![],
    };
    let (_c, store, addr) = setup_full(Duration::from_secs(30), None, policy).await;
    let mut cpe = Cpe::connect(addr).await;
    let (_, resp) = cpe.post(INFORM.to_vec()).await;
    assert!(matches!(rpc(&resp), Rpc::InformResponse(_)));
    let (status, _) = cpe.post(Vec::new()).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "no zero-touch read while quarantined"
    );
    let id = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store.get_device(id).await.unwrap().unwrap().status,
        "quarantined"
    );

    store
        .set_device_status(DEFAULT_TENANT, id, "active")
        .await
        .unwrap();
    let mut cpe = Cpe::connect(addr).await;
    cpe.post(INFORM.to_vec()).await;
    let (_, req) = cpe.post(Vec::new()).await;
    assert!(
        matches!(rpc(&req), Rpc::GetParameterValues(_)),
        "queued work runs after activation"
    );
}

#[tokio::test]
async fn preregistered_mode_and_oui_allowlist() {
    use dhonomos_core::{Onboarding, OnboardingMode};
    let policy = Onboarding {
        mode: OnboardingMode::Preregistered,
        allowed_ouis: vec!["202bc1".into()],
    };
    let (_c, store, addr) = setup_full(Duration::from_secs(30), None, policy).await;
    let mut cpe = Cpe::connect(addr).await;
    let (_, resp) = cpe.post(INFORM.to_vec()).await;
    assert_eq!(fault_code(&resp), Some(8001), "unknown device rejected");
    assert!(
        store
            .find_cwmp_device(DEFAULT_TENANT, &identity())
            .await
            .unwrap()
            .is_none()
    );

    store
        .preregister_cwmp_device(DEFAULT_TENANT, &identity(), &[])
        .await
        .unwrap();
    let mut cpe = Cpe::connect(addr).await;
    let (_, resp) = cpe.post(INFORM.to_vec()).await;
    assert!(
        matches!(rpc(&resp), Rpc::InformResponse(_)),
        "pre-registered device accepted"
    );

    // Retired devices -> turned away.
    let id = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    store
        .set_device_status(DEFAULT_TENANT, id, "retired")
        .await
        .unwrap();
    let mut cpe = Cpe::connect(addr).await;
    let (_, resp) = cpe.post(INFORM.to_vec()).await;
    assert_eq!(fault_code(&resp), Some(8001));
}

#[tokio::test]
async fn oui_allowlist_rejects_other_vendors() {
    use dhonomos_core::Onboarding;
    let policy = Onboarding {
        allowed_ouis: vec!["00AA00".into()],
        ..Onboarding::default()
    };
    let (_c, store, addr) = setup_full(Duration::from_secs(30), None, policy).await;
    let mut cpe = Cpe::connect(addr).await;
    let (_, resp) = cpe.post(INFORM.to_vec()).await;
    assert_eq!(fault_code(&resp), Some(8001));
    assert!(
        store
            .list_devices(DEFAULT_TENANT, 10, 0)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn value_change_informs_become_change_events() {
    let (_c, store, addr) = setup(Duration::from_secs(30)).await;
    let device = known_device(&store, addr).await;
    // Same Inform as VALUE CHANGE + new software version.
    let changed = String::from_utf8(INFORM.to_vec())
        .unwrap()
        .replace("2 PERIODIC", "4 VALUE CHANGE")
        .replace("V100R001IRQC56B017", "V200");
    let mut cpe = Cpe::connect(addr).await;
    let (_, resp) = cpe.post(changed.into_bytes()).await;
    assert!(matches!(rpc(&resp), Rpc::InformResponse(_)));
    let events = store.list_events(device, 10).await.unwrap();
    let change = events
        .iter()
        .find(|e| e.kind == "parameter_change")
        .expect("change event");
    let changes = change.detail["changes"].as_array().unwrap();
    assert_eq!(
        changes.len(),
        1,
        "only the parameter that differs: {changes:?}"
    );
    assert_eq!(
        changes[0]["path"],
        "InternetGatewayDevice.DeviceInfo.SoftwareVersion"
    );
    assert_eq!(
        (changes[0]["old"].as_str(), changes[0]["new"].as_str()),
        (Some("V100R001IRQC56B017"), Some("V200"))
    );
}

#[tokio::test]
async fn presets_queue_tasks_once_per_device() {
    let presets = dhonomos_core::Presets::from_yaml(
        r#"
presets:
  - name: interval
    when: { oui: 202BC1 }
    once: true
    run:
      - kind: set_parameter_values
        payload:
          values:
            - { name: InternetGatewayDevice.ManagementServer.PeriodicInformInterval, value: "3600", type: unsignedInt }
  - name: other-vendor
    when: { oui: 00AA00 }
    run:
      - kind: reboot
"#,
    )
    .unwrap();
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
    let backend =
        CwmpBackend::new(store.clone(), DEFAULT_TENANT, CpeCredentials::None).with_presets(presets);
    let config = Config {
        auth: AuthMode::None,
        ..Config::default()
    };
    let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(AcsServer::new(config, backend).serve(listener, std::future::pending()));

    for _ in 0..2 {
        // Answer all until session end.
        answer_session(addr, INFORM.to_vec()).await;
    }
    let id = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    let tasks = store.list_tasks(id, 20).await.unwrap();
    let spv: Vec<_> = tasks
        .iter()
        .filter(|t| t.kind == "set_parameter_values")
        .collect();
    assert_eq!(
        spv.len(),
        1,
        "once: true queues a single task across sessions"
    );
    assert_eq!(spv[0].state, TaskState::Succeeded);
    assert!(
        tasks.iter().all(|t| t.kind != "reboot"),
        "other vendor's preset did not match"
    );
    let params = store
        .get_params(
            id,
            "InternetGatewayDevice.ManagementServer.PeriodicInformInterval",
        )
        .await
        .unwrap();
    assert_eq!(params[0].value.as_deref(), Some("3600"));
}

#[tokio::test]
async fn scripts_declare_state_and_are_traced() {
    let presets = dhonomos_core::Presets::from_yaml(
        r#"
presets:
  - name: provision
    when: { oui: 202BC1 }
    args: { interval: "600" }
    script_source: |
      pub fn main(device, args) {
          let path = "InternetGatewayDevice.ManagementServer.PeriodicInformInterval";
          if device.get(path).is_none() {
              device.log("interval unknown");
          }
          device.set_typed(path, args["interval"], "unsignedInt");
          if !device.has_tag("provisioned") {
              device.tag("provisioned");
          }
          device.set_virtual("interval_ok", device.get(path) == Some(args["interval"]));
      }
"#,
    )
    .unwrap();
    let (_c, store, addr) =
        setup_custom(Duration::from_secs(30), move |b| b.with_presets(presets)).await;

    let mut seen_spv = Vec::new();
    for _ in 0..2 {
        let mut tree = Tree::of_inform(INFORM);
        let mut cpe = Cpe::connect(addr).await;
        cpe.post(INFORM.to_vec()).await;
        let (mut status, mut req) = cpe.post(Vec::new()).await;
        while status == StatusCode::OK {
            let answer: Rpc = match rpc(&req) {
                Rpc::SetParameterValues(spv) => {
                    seen_spv.push(spv.parameter_list.clone());
                    tree.set(&spv.parameter_list);
                    dhonomos_cwmp_codec::SetParameterValuesResponse { status: 0 }.into()
                }
                Rpc::GetParameterNames(gpn) => tree.names(&gpn.parameter_path).into(),
                Rpc::GetParameterValues(gpv) => tree.values(&gpv.parameter_names).into(),
                other => panic!("unexpected request {other:?}"),
            };
            (status, req) = cpe.reply(req.as_ref().unwrap(), answer).await;
        }
    }
    // Declared x1, set x1: 2nd run finds the stored value -> declares nothing new.
    assert_eq!(seen_spv.len(), 1);
    assert_eq!(seen_spv[0][0].value, "600");
    assert_eq!(seen_spv[0][0].xsd_type.as_deref(), Some("unsignedInt"));

    let id = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    let dev = store.get_device(id).await.unwrap().unwrap();
    assert!(dev.tags.contains(&"provisioned".to_owned()));
    let runs: Vec<_> = store
        .list_events(id, 50)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "script")
        .collect();
    assert_eq!(runs.len(), 2, "every run is traced");
    // Newest first: 2nd run changed nothing.
    assert_eq!(runs[0].detail["tasks"], serde_json::json!([]));
    assert_eq!(runs[0].detail["tags_added"], serde_json::json!([]));
    assert_eq!(
        runs[1].detail["tasks"],
        serde_json::json!(["set_parameter_values"])
    );
    assert_eq!(
        runs[1].detail["logs"],
        serde_json::json!(["interval unknown"])
    );
    assert_eq!(runs[1].detail["error"], serde_json::Value::Null);
    // Virtual parameter follows the stored value: false before SPV, true after.
    assert_eq!(
        runs[1].detail["virtual"],
        serde_json::json!([["VirtualParameters.interval_ok", "false"]])
    );
    assert_eq!(
        runs[0].detail["virtual"],
        serde_json::json!([["VirtualParameters.interval_ok", "true"]])
    );
    let v = store
        .get_params(id, "VirtualParameters.interval_ok")
        .await
        .unwrap();
    assert_eq!(
        (v[0].value.as_deref(), v[0].writable),
        (Some("true"), Some(false))
    );
}

#[tokio::test]
async fn zero_touch_issues_connection_request_credentials() {
    let secrets = std::sync::Arc::new(
        dhonomos_core::SecretBox::from_base64("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "k1")
            .unwrap(),
    );
    let sb = secrets.clone();
    let (_c, store, addr) = setup_custom(Duration::from_secs(30), move |b| {
        b.with_secrets(sb).with_per_device_connection_requests()
    })
    .await;
    let mut cpe = Cpe::connect(addr).await;
    cpe.post(INFORM.to_vec()).await;
    let (_, req) = cpe.post(Vec::new()).await;
    assert!(matches!(rpc(&req), Rpc::GetParameterValues(_)));
    let (_, req) = cpe
        .reply(
            req.as_ref().unwrap(),
            GetParameterValuesResponse {
                parameter_list: vec![],
            },
        )
        .await;
    assert!(matches!(rpc(&req), Rpc::GetParameterNames(_)));
    let (_, req) = cpe
        .reply(
            req.as_ref().unwrap(),
            dhonomos_cwmp_codec::GetParameterNamesResponse {
                parameter_list: vec![],
            },
        )
        .await;
    let Rpc::SetParameterValues(spv) = rpc(&req) else {
        panic!("expected the credential SPV, got {req:?}")
    };
    let get = |suffix: &str| {
        spv.parameter_list
            .iter()
            .find(|p| p.name.ends_with(suffix))
            .unwrap()
            .value
            .clone()
    };
    let (user, pass) = (
        get(".ConnectionRequestUsername"),
        get(".ConnectionRequestPassword"),
    );
    assert!(user.starts_with("dhonomos-") && pass.len() == 24);

    let id = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    // Password stored encrypted only + not used before the CPE accepts it.
    let rows: String = store
        .list_tasks(id, 100)
        .await
        .unwrap()
        .iter()
        .map(|t| t.payload.to_string())
        .collect();
    assert!(!rows.contains(&pass), "no plaintext password in the queue");
    assert!(
        store
            .get_credential(id, "connection_request")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_credential(id, "connection_request_pending")
            .await
            .unwrap()
            .is_some()
    );

    let (status, _) = cpe
        .reply(
            req.as_ref().unwrap(),
            dhonomos_cwmp_codec::SetParameterValuesResponse { status: 0 },
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let active = store
        .get_credential(id, "connection_request")
        .await
        .unwrap()
        .expect("promoted once accepted");
    assert_eq!(active.username, user);
    assert_eq!(
        secrets
            .open_credential(id, &active.ciphertext, &active.nonce)
            .unwrap(),
        pass.as_bytes()
    );
    assert!(
        store
            .get_credential(id, "connection_request_pending")
            .await
            .unwrap()
            .is_none()
    );
    // Snapshot never holds the secret.
    let params = store
        .get_params(
            id,
            "InternetGatewayDevice.ManagementServer.ConnectionRequestPassword",
        )
        .await
        .unwrap();
    assert!(
        params
            .iter()
            .all(|p| p.value.as_deref() != Some(pass.as_str()))
    );
}

#[tokio::test]
async fn per_device_acs_credentials_replace_the_shared_one() {
    use base64::Engine as _;
    let secrets = std::sync::Arc::new(
        dhonomos_core::SecretBox::from_base64("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "k1")
            .unwrap(),
    );
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
    let backend = CwmpBackend::new(
        store.clone(),
        DEFAULT_TENANT,
        CpeCredentials::Shared {
            username: "shared".into(),
            password: "shared-pw".into(),
        },
    )
    .with_secrets(secrets.clone())
    .with_per_device_acs_auth();
    let config = Config {
        auth: AuthMode::Basic,
        ..Config::default()
    };
    let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(AcsServer::new(config, backend).serve(listener, std::future::pending()));

    let basic = |u: &str, p: &str| {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
        )
    };
    // One session: Inform with `auth`, then answer all -> Inform reply + SPV requests seen.
    let session = async |inform: Vec<u8>, auth: String| {
        let io = TokioIo::new(TcpStream::connect(addr).await.unwrap());
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        let mut post = async |body: Vec<u8>| {
            let resp = sender
                .send_request(
                    Request::post("/")
                        .header("authorization", auth.clone())
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
        let mut spvs = Vec::new();
        if status == StatusCode::OK && fault_code(&first).is_none() {
            let (mut status, mut req) = post(Vec::new()).await;
            while status == StatusCode::OK {
                let env = req.as_ref().unwrap();
                let answer: Rpc = match rpc(&req) {
                    Rpc::SetParameterValues(spv) => {
                        spvs.push(spv.parameter_list.clone());
                        dhonomos_cwmp_codec::SetParameterValuesResponse { status: 0 }.into()
                    }
                    Rpc::GetParameterNames(_) => {
                        dhonomos_cwmp_codec::GetParameterNamesResponse::default().into()
                    }
                    _ => GetParameterValuesResponse::default().into(),
                };
                let reply =
                    Envelope::rpc(CwmpNamespace::V1_0, env.header.id.clone().unwrap(), answer);
                (status, req) = post(reply.encode().into_bytes()).await;
            }
        }
        (status, first, spvs)
    };

    // 1st contact with shared credential -> zero-touch sets the device's own.
    let (_, _, spvs) = session(INFORM.to_vec(), basic("shared", "shared-pw")).await;
    let creds = spvs
        .iter()
        .find(|l| {
            l.iter()
                .any(|p| p.name.ends_with(".ManagementServer.Password"))
        })
        .expect("ACS credential SPV");
    let get = |suffix: &str| {
        creds
            .iter()
            .find(|p| p.name.ends_with(suffix))
            .unwrap()
            .value
            .clone()
    };
    let (user, pass) = (
        get(".ManagementServer.Username"),
        get(".ManagementServer.Password"),
    );
    assert!(user.starts_with("acs-"));
    let device = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    assert!(
        store
            .get_credential(device, "acs_auth")
            .await
            .unwrap()
            .is_some()
    );

    // Shared one works until the CPE uses its own credential (no lockout).
    let (_, reply, _) = session(INFORM.to_vec(), basic("shared", "shared-pw")).await;
    assert_eq!(fault_code(&reply), None);
    // CPE uses it -> shared credential refused for this device from now on...
    let (s, reply, _) = session(INFORM.to_vec(), basic(&user, &pass)).await;
    assert_eq!((s, fault_code(&reply)), (StatusCode::OK, None));
    let (_, reply, _) = session(INFORM.to_vec(), basic("shared", "shared-pw")).await;
    assert_eq!(
        fault_code(&reply),
        Some(8001),
        "shared credential after its own"
    );
    // ...and no other device can use this device's credential.
    let other = String::from_utf8(INFORM.to_vec()).unwrap().replace(
        "<SerialNumber>000000</SerialNumber>",
        "<SerialNumber>999999</SerialNumber>",
    );
    let (_, reply, _) = session(other.into_bytes(), basic(&user, &pass)).await;
    assert_eq!(
        fault_code(&reply),
        Some(8001),
        "another device's credential"
    );
    assert!(
        store
            .find_cwmp_device(
                DEFAULT_TENANT,
                &CwmpIdentity {
                    serial_number: "999999".into(),
                    ..identity()
                }
            )
            .await
            .unwrap()
            .is_none(),
        "refused before anything was stored"
    );

    // SPV answer lost, but CPE applied the new credential -> pending one accepted + active.
    let third = CwmpIdentity {
        serial_number: "333333".into(),
        ..identity()
    };
    let d3 = store
        .preregister_cwmp_device(DEFAULT_TENANT, &third, &[])
        .await
        .unwrap()
        .id;
    let (ct, nonce) = secrets.seal_credential(d3, b"pending-pw").unwrap();
    store
        .put_credential(&dhonomos_store::SealedCredential {
            device_id: d3,
            kind: "acs_auth_pending".into(),
            username: "acs-pending".into(),
            ciphertext: ct,
            nonce,
            key_id: "k1".into(),
        })
        .await
        .unwrap();
    let inform3 = String::from_utf8(INFORM.to_vec()).unwrap().replace(
        "<SerialNumber>000000</SerialNumber>",
        "<SerialNumber>333333</SerialNumber>",
    );
    let (_, reply, _) = session(inform3.into_bytes(), basic("acs-pending", "pending-pw")).await;
    assert_eq!(fault_code(&reply), None);
    assert!(
        store
            .get_credential(d3, "acs_auth")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .get_credential(d3, "acs_auth_pending")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn per_device_credentials_and_task_secrets() {
    use dhonomos_cwmp_server::{DigestInput, digest_response};
    let secrets = std::sync::Arc::new(
        dhonomos_core::SecretBox::from_base64("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "k1")
            .unwrap(),
    );
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
    let device = store
        .preregister_cwmp_device(DEFAULT_TENANT, &identity(), &[])
        .await
        .unwrap()
        .id;
    let (ct, nonce) = secrets.seal_credential(device, b"device-pw").unwrap();
    store
        .put_credential(&dhonomos_store::SealedCredential {
            device_id: device,
            kind: "acs_auth".into(),
            username: "cpe-000000".into(),
            ciphertext: ct,
            nonce,
            key_id: "k1".into(),
        })
        .await
        .unwrap();
    // Download task, password stored encrypted.
    let (kind, mut payload) = TaskKind::Download {
        file_id: None,
        file_type: "1 Firmware Upgrade Image".into(),
        url: "http://files/fw.bin".into(),
        username: "dl".into(),
        password: "file-pw".into(),
        file_size: 0,
        target_file_name: String::new(),
        sha256: String::new(),
        delay_seconds: 0,
    }
    .to_row();
    let task_id = uuid::Uuid::now_v7();
    secrets
        .encrypt_fields(&mut payload, &dhonomos_core::secrets::task_context(task_id))
        .unwrap();
    store
        .enqueue_task_with_id(
            task_id,
            &NewTask {
                priority: 10,
                ..NewTask::new(DEFAULT_TENANT, device, kind, payload)
            },
        )
        .await
        .unwrap();

    let backend =
        CwmpBackend::new(store.clone(), DEFAULT_TENANT, CpeCredentials::None).with_secrets(secrets);
    let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        AcsServer::new(Config::default(), backend).serve(listener, std::future::pending()),
    );

    let io = TokioIo::new(TcpStream::connect(addr).await.unwrap());
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);
    let post = async |sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
                      auth: Option<String>,
                      body: Vec<u8>| {
        let mut req = Request::post("/");
        if let Some(a) = auth {
            req = req.header("authorization", a);
        }
        let resp = sender
            .send_request(req.body(Full::new(Bytes::from(body))).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, headers, Envelope::decode(&bytes).unwrap())
    };
    let (status, headers, _) = post(&mut sender, None, INFORM.to_vec()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let challenge = headers
        .get_all("www-authenticate")
        .iter()
        .nth(1)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let nonce = challenge
        .split("nonce=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let response = digest_response(&DigestInput {
        sha256: false,
        username: "cpe-000000",
        realm: "dhonomos",
        password: "device-pw",
        method: "POST",
        uri: "/",
        nonce,
        nc: "00000001",
        cnonce: "abc",
    });
    let auth = format!(
        r#"Digest username="cpe-000000", realm="dhonomos", nonce="{nonce}", uri="/", qop=auth, nc=00000001, cnonce="abc", response="{response}""#
    );
    let (status, _, _) = post(&mut sender, Some(auth), INFORM.to_vec()).await;
    assert_eq!(status, StatusCode::OK, "per-device credential accepted");
    let (_, _, req) = post(&mut sender, None, Vec::new()).await;
    let Rpc::Download(dl) = rpc(&req) else {
        panic!("expected Download")
    };
    assert_eq!(
        (dl.username.as_str(), dl.password.as_str()),
        ("dl", "file-pw"),
        "decrypted when sent"
    );
}

/// Captured Inform + extra event codes.
fn inform_with(events: &[&str]) -> Vec<u8> {
    let mut env = Envelope::decode(INFORM).unwrap().unwrap();
    let Body::Rpc(Rpc::Inform(inf)) = &mut env.body else {
        panic!()
    };
    for e in events {
        inf.events.push(dhonomos_cwmp_codec::EventStruct {
            event_code: (*e).into(),
            command_key: String::new(),
        });
    }
    env.encode().into_bytes()
}

#[tokio::test]
async fn diagnostics_run_across_two_sessions() {
    use dhonomos_core::diagnostics::DiagTest;
    use dhonomos_cwmp_codec::SetParameterValuesResponse;

    let (_c, store, addr) = setup(Duration::from_millis(300)).await;
    let device = known_device(&store, addr).await;
    let task = enqueue(
        &store,
        device,
        TaskKind::Diagnostic {
            test: DiagTest::IpPing,
            params: [("host", "192.0.2.1"), ("count", "3")]
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        },
    )
    .await;

    // Session 1: ACS sets inputs + requests the test.
    let mut cpe = Cpe::connect(addr).await;
    cpe.post(INFORM.to_vec()).await;
    let (_, req) = cpe.post(Vec::new()).await;
    let Rpc::SetParameterValues(spv) = rpc(&req) else {
        panic!("expected SetParameterValues")
    };
    let obj = "InternetGatewayDevice.IPPingDiagnostics.";
    let set: Vec<(&str, &str)> = spv
        .parameter_list
        .iter()
        .map(|p| (p.name.as_str(), p.value.as_str()))
        .collect();
    assert_eq!(
        set,
        [
            (&*format!("{obj}Host"), "192.0.2.1"),
            (&*format!("{obj}NumberOfRepetitions"), "3"),
            (&*format!("{obj}DiagnosticsState"), "Requested"),
        ],
        "TR-098 device: IGD object"
    );
    // TR-069: ParameterKey max 32 chars -> task ID without hyphens.
    assert_eq!(spv.parameter_key, task.simple().to_string());
    assert!(spv.parameter_key.len() <= 32);
    let (status, _) = cpe
        .reply(
            req.as_ref().unwrap(),
            SetParameterValuesResponse { status: 0 },
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        store.get_task(task).await.unwrap().unwrap().state,
        TaskState::Running
    );

    // Session 2: 8 DIAGNOSTICS COMPLETE -> ACS reads results.
    let mut cpe = Cpe::connect(addr).await;
    cpe.post(inform_with(&["8 DIAGNOSTICS COMPLETE"])).await;
    let (_, req) = cpe.post(Vec::new()).await;
    let Rpc::GetParameterValues(gpv) = rpc(&req) else {
        panic!("expected GetParameterValues")
    };
    assert_eq!(gpv.parameter_names, [obj]);
    let values = [
        ("DiagnosticsState", "Complete"),
        ("SuccessCount", "3"),
        ("FailureCount", "0"),
        ("AverageResponseTime", "12"),
        ("MinimumResponseTime", "10"),
        ("MaximumResponseTime", "15"),
    ];
    let resp = GetParameterValuesResponse {
        parameter_list: values
            .iter()
            .map(|(n, v)| ParameterValue::new(format!("{obj}{n}"), *v, "string"))
            .collect(),
    };
    let (status, _) = cpe.reply(req.as_ref().unwrap(), resp).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let t = store.get_task(task).await.unwrap().unwrap();
    assert_eq!(t.state, TaskState::Succeeded, "{:?}", t.error);
    let r = t.result.unwrap();
    assert_eq!(r["test"], "ip_ping");
    assert_eq!(r["result"]["success_count"], 3);
    assert_eq!(r["result"]["avg_ms"], 12);
}

/// TR-111 Binding Request from the Connection Request port.
fn stun_binding(username: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (t, v) in [
        (0x0006u16, username.as_bytes()),
        (0xC001, b"dslforum.org/TR-111 ".as_slice()),
    ] {
        body.extend_from_slice(&t.to_be_bytes());
        body.extend_from_slice(&u16::try_from(v.len()).unwrap().to_be_bytes());
        body.extend_from_slice(v);
        body.resize(body.len().div_ceil(4) * 4, 0);
    }
    let mut m = vec![0x00, 0x01];
    m.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    m.extend_from_slice(&0x2112_A442u32.to_be_bytes());
    m.extend_from_slice(&[9; 12]);
    m.extend(body);
    m
}

#[tokio::test]
async fn udp_connection_request_through_stun() {
    use std::sync::Arc;

    use hmac::{Hmac, KeyInit, Mac};

    let (_c, store, addr) = setup(Duration::from_millis(300)).await;
    let device = known_device(&store, addr).await;

    let stun = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let stun_addr = stun.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let secret = b"stun-secret".to_vec();
    tokio::spawn(dhonomos_cwmp_server::stun::serve(
        stun.clone(),
        tx,
        Some(dhonomos_core::nat::stun_passwords(secret.clone())),
    ));
    tokio::spawn(dhonomos_core::nat::record_bindings(
        store.clone(),
        DEFAULT_TENANT,
        rx,
    ));

    // CPE binds from its CR port -> learns its address.
    // Unsigned updates do not count; signed with its STUN password -> count.
    let cpe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0u8; 1500];
    cpe.send_to(&stun_binding(&device.to_string()), stun_addr)
        .await
        .unwrap();
    let _ = cpe.recv_from(&mut buf).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        store.udp_cr_address(device).await.unwrap().is_none(),
        "unsigned"
    );
    let password = dhonomos_core::nat::stun_password(&secret, device);
    let mut signed = stun_binding(&device.to_string());
    let len = u16::try_from(signed.len() - 20 + 24).unwrap();
    signed[2..4].copy_from_slice(&len.to_be_bytes());
    let mut mac = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(password.as_bytes()).unwrap();
    mac.update(&signed);
    let tag = mac.finalize().into_bytes();
    signed.extend_from_slice(&[0x00, 0x08, 0x00, 0x14]);
    signed.extend_from_slice(&tag);
    cpe.send_to(&signed, stun_addr).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), cpe.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..2], &[0x01, 0x01], "Binding Success Response");
    assert!(n > 20);
    for _ in 0..50 {
        if store.udp_cr_address(device).await.unwrap().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (learned, _) = store.udp_cr_address(device).await.unwrap().unwrap();
    assert_eq!(learned, cpe.local_addr().unwrap().to_string());

    // Wake -> signed UDP CR from the STUN socket.
    let waker = dhonomos_core::Waker::new(
        store.clone(),
        Some(dhonomos_cwmp_server::ConnReqCredentials {
            username: "cpe".into(),
            password: "secret".into(),
        }),
        Duration::from_millis(500),
    )
    .with_address_policy(dhonomos_cwmp_server::AddressPolicy::permit_all())
    .with_udp(stun.clone());
    let outcome = waker.wake(device).await;
    assert_eq!(
        outcome,
        dhonomos_core::WakeOutcome::SentUdp,
        "{}",
        outcome.describe()
    );
    let woken = store.get_device(device).await.unwrap().unwrap();
    assert!(woken.last_wake_at.is_some());
    assert_eq!(woken.last_wake_method.as_deref(), Some("udp"));
    assert_eq!(
        woken.last_wake_outcome.as_deref(),
        Some("sent over UDP (device behind NAT)")
    );
    assert_eq!(
        woken.udp_cr_address.as_deref(),
        Some(learned.as_str()),
        "the device row shows the address it was woken at"
    );
    let (n, from) = tokio::time::timeout(Duration::from_secs(2), cpe.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, stun_addr, "from the address the CPE bound to");
    let msg = std::str::from_utf8(&buf[..n]).unwrap();
    let query = msg
        .strip_prefix("GET http://")
        .and_then(|r| r.split_once('?'))
        .map(|(_, q)| q.split(' ').next().unwrap())
        .unwrap();
    let get = |k: &str| {
        query
            .split('&')
            .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
            .unwrap()
    };
    assert_eq!(get("un"), "cpe");
    let mut mac = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(b"secret").unwrap();
    mac.update(format!("{}{}{}{}", get("ts"), get("id"), get("un"), get("cn")).as_bytes());
    let sig: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    assert_eq!(get("sig"), sig, "the CPE can verify the signature");
}

/// CPE over its session limit -> retry (8005) before anything is stored.
#[tokio::test]
async fn sessions_over_the_limit_get_retry() {
    let (_c, store, addr) = setup_custom(Duration::from_secs(5), |b| b.with_session_limit(2)).await;
    let mut faults = Vec::new();
    for _ in 0..3 {
        // New connection per session, like a CPE.
        let mut cpe = Cpe::connect(addr).await;
        let (_, env) = cpe.post(INFORM.to_vec()).await;
        faults.push(match env.map(|e| e.body) {
            Some(Body::Fault(f)) => Some(f.code),
            _ => None,
        });
    }
    assert_eq!(faults, vec![None, None, Some(8005)]);
    let device = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    let informs = store
        .list_events(device, 10)
        .await
        .unwrap()
        .iter()
        .filter(|e| e.kind == "inform")
        .count();
    assert_eq!(informs, 2, "the third Inform left no trace");
}

/// Session limit changes while the ACS runs (runtime settings): off -> on -> off.
#[tokio::test]
async fn the_session_limit_changes_while_running() {
    let limits = std::sync::OnceLock::new();
    let (_c, _store, addr) = setup_custom(Duration::from_secs(5), |b| {
        let _ = limits.set(b.limits());
        b
    })
    .await;
    let limits = limits.get().unwrap();
    let session = async || {
        let mut cpe = Cpe::connect(addr).await;
        let (_, env) = cpe.post(INFORM.to_vec()).await;
        fault_code(&env)
    };
    for _ in 0..3 {
        assert_eq!(session().await, None, "no limit at start");
    }
    limits.sessions.set_per_minute(1);
    assert_eq!(session().await, None);
    assert_eq!(session().await, Some(8005), "limited without a restart");
    limits.sessions.set_per_minute(0);
    assert_eq!(session().await, None, "off again");
}

// ---------------------------------------------------------------------------------------
// Audit fixes: M-4, L-1, L-3, L-5.
// ---------------------------------------------------------------------------------------

/// Captured Inform for device `serial` + extra events + given CurrentTime.
fn inform_at(serial: &str, events: &[&str], current_time: &str) -> Vec<u8> {
    let mut env = Envelope::decode(INFORM).unwrap().unwrap();
    let Body::Rpc(Rpc::Inform(inf)) = &mut env.body else {
        panic!()
    };
    inf.device_id.serial_number = serial.into();
    inf.current_time = current_time.into();
    for e in events {
        inf.events.push(dhonomos_cwmp_codec::EventStruct {
            event_code: (*e).into(),
            command_key: String::new(),
        });
    }
    env.encode().into_bytes()
}

fn basic(user: &str, password: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
    )
}

fn secret_box() -> std::sync::Arc<dhonomos_core::SecretBox> {
    std::sync::Arc::new(
        dhonomos_core::SecretBox::from_base64("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "k1")
            .unwrap(),
    )
}

/// Seen by one scripted session: status + body of the Inform answer, params of each SPV
/// the ACS sent.
type Seen = (StatusCode, Option<Envelope>, Vec<Vec<ParameterValue>>);

/// Scripted CPE action on an SPV.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Spv {
    /// Apply + answer.
    Apply,
    /// Vanish before the answer (never applied, as far as the test cares).
    Vanish,
    /// Fault 9003 (SPV is atomic -> nothing applied).
    Refuse,
}

/// One CPE session, Basic `auth` on every request. GPV + GPN answered empty.
/// SPV: `apply_spv` -> success, else CPE vanishes (never applied).
async fn session_as(addr: SocketAddr, inform: Vec<u8>, auth: &str, apply_spv: bool) -> Seen {
    let spv = if apply_spv { Spv::Apply } else { Spv::Vanish };
    session_spv(addr, inform, auth, spv).await
}

/// [`session_as`] + option to refuse the SPV.
async fn session_spv(addr: SocketAddr, inform: Vec<u8>, auth: &str, on_spv: Spv) -> Seen {
    let io = TokioIo::new(TcpStream::connect(addr).await.unwrap());
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);
    let mut post = async |body: Vec<u8>| {
        let resp = sender
            .send_request(
                Request::post("/")
                    .header("authorization", auth)
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
    let mut spvs = Vec::new();
    if status == StatusCode::OK && fault_code(&first).is_none() {
        let (mut status, mut req) = post(Vec::new()).await;
        while status == StatusCode::OK {
            let env = req.as_ref().unwrap();
            let id = env.header.id.clone().unwrap();
            let answer: Rpc = match rpc(&req) {
                Rpc::SetParameterValues(spv) => {
                    spvs.push(spv.parameter_list.clone());
                    match on_spv {
                        Spv::Vanish => break,
                        Spv::Refuse => {
                            let fault = Envelope {
                                header: dhonomos_cwmp_codec::Header {
                                    id: Some(id),
                                    ..Default::default()
                                },
                                body: Body::Fault(dhonomos_cwmp_codec::Fault::new(
                                    9003,
                                    "Invalid arguments",
                                )),
                                namespace: CwmpNamespace::V1_0,
                            };
                            (status, req) = post(fault.encode().into_bytes()).await;
                            continue;
                        }
                        Spv::Apply => {}
                    }
                    dhonomos_cwmp_codec::SetParameterValuesResponse { status: 0 }.into()
                }
                Rpc::GetParameterNames(_) => {
                    dhonomos_cwmp_codec::GetParameterNamesResponse::default().into()
                }
                _ => GetParameterValuesResponse::default().into(),
            };
            let reply = Envelope::rpc(CwmpNamespace::V1_0, id, answer);
            (status, req) = post(reply.encode().into_bytes()).await;
        }
    }
    (status, first, spvs)
}

/// ACS username + password set by an SPV list, if any.
fn acs_credentials_in(spvs: &[Vec<ParameterValue>]) -> Option<(String, String)> {
    let value = |suffix: &str| {
        spvs.iter().flatten().find_map(|p| {
            p.name
                .ends_with(&format!(".ManagementServer.{suffix}"))
                .then(|| p.value.clone())
        })
    };
    Some((value("Username")?, value("Password")?))
}

/// CR username + password set by an SPV list, if any.
fn cr_credentials_in(spvs: &[Vec<ParameterValue>]) -> Option<(String, String)> {
    let value = |suffix: &str| {
        spvs.iter().flatten().find_map(|p| {
            p.name
                .ends_with(&format!(".ManagementServer.{suffix}"))
                .then(|| p.value.clone())
        })
    };
    Some((
        value("ConnectionRequestUsername")?,
        value("ConnectionRequestPassword")?,
    ))
}

/// ACS with Basic auth, shared credential `shared`/`shared-pw`.
async fn shared_credential_acs(
    onboarding: dhonomos_core::Onboarding,
    customize: impl FnOnce(CwmpBackend) -> CwmpBackend,
) -> (ContainerAsync<Postgres>, Store, SocketAddr) {
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
    let backend = customize(
        CwmpBackend::new(
            store.clone(),
            DEFAULT_TENANT,
            CpeCredentials::Shared {
                username: "shared".into(),
                password: "shared-pw".into(),
            },
        )
        .with_secrets(secret_box())
        .with_onboarding(onboarding),
    );
    let config = Config {
        auth: AuthMode::Basic,
        session_timeout: Duration::from_secs(5),
        ..Config::default()
    };
    let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(AcsServer::new(config, backend).serve(listener, std::future::pending()));
    (container, store, addr)
}

async fn credential_tasks(store: &Store, device: uuid::Uuid) -> usize {
    store
        .list_tasks(device, 100)
        .await
        .unwrap()
        .iter()
        .filter(|t| t.created_by.as_deref() == Some("system:acs-credentials"))
        .count()
}

/// M-4: anyone with the shared credential can send BOOTSTRAP for a device not yet on its
/// own credential. Must not swap the credential being provisioned.
#[tokio::test]
async fn a_shared_session_cannot_swap_a_pending_acs_credential() {
    let (_c, store, addr) = shared_credential_acs(dhonomos_core::Onboarding::default(), |b| {
        b.with_per_device_acs_auth()
    })
    .await;
    let shared = basic("shared", "shared-pw");

    // Device 1st contact: credential sent, not applied yet.
    let first = inform_at("000000", &["0 BOOTSTRAP"], "2026-10-03T11:00:00Z");
    let (_, _, spvs) = session_as(addr, first, &shared, false).await;
    let (user1, pass1) = acs_credentials_in(&spvs).expect("the credential is sent");
    let device = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    let pending = store
        .get_credential(device, "acs_auth_pending")
        .await
        .unwrap()
        .unwrap();

    // Attacker with shared credential bootstraps the same device again + again, at any time.
    // (Unanswered task handed out max 3x -> 2 attempts here.)
    for time in ["2026-10-03T11:00:05Z", "1999-01-01T00:00:00Z"] {
        let again = inform_at("000000", &["0 BOOTSTRAP"], time);
        let (_, _, spvs) = session_as(addr, again, &shared, false).await;
        // -> only the credential already pending.
        assert_eq!(
            acs_credentials_in(&spvs),
            Some((user1.clone(), pass1.clone())),
            "{time}"
        );
    }
    let still = store
        .get_credential(device, "acs_auth_pending")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (still.ciphertext, still.nonce),
        (pending.ciphertext, pending.nonce)
    );
    assert_eq!(
        credential_tasks(&store, device).await,
        1,
        "one task, however often"
    );
    // No key from the CurrentTime the CPE sends.
    let by_time = format!("acs-credentials:{device}:2026-10-03T11:00:05Z");
    assert!(
        store
            .existing_idempotency_keys(DEFAULT_TENANT, &[by_time])
            .await
            .unwrap()
            .is_empty()
    );
}

/// CPE refuses the credentials with a fault (SPV atomic -> nothing applied) -> not stuck:
/// next trigger issues new ones. Ordinary Informs send nothing more.
#[tokio::test]
async fn refused_per_device_credentials_are_issued_again_at_the_next_trigger() {
    let (_c, store, addr) = shared_credential_acs(dhonomos_core::Onboarding::default(), |b| {
        b.with_per_device_acs_auth()
            .with_per_device_connection_requests()
    })
    .await;
    let shared = basic("shared", "shared-pw");
    let first = inform_at("000000", &["0 BOOTSTRAP"], "2026-10-03T11:00:00Z");
    let (_, _, spvs) = session_spv(addr, first, &shared, Spv::Refuse).await;
    let (_, acs_pass1) = acs_credentials_in(&spvs).expect("ACS credentials are sent");
    let (_, cr_pass1) = cr_credentials_in(&spvs).expect("Connection Request credentials are sent");
    let device = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    // Both tasks ended with the fault -> credentials wait as pending, no secret in the error.
    let tasks = store.list_tasks(device, 100).await.unwrap();
    let credential_tasks: Vec<_> = tasks
        .iter()
        .filter(|t| {
            t.kind == "set_parameter_values" && t.created_by.as_deref() != Some("system:bootstrap")
        })
        .collect();
    assert_eq!(credential_tasks.len(), 2);
    for t in &credential_tasks {
        assert_eq!(t.state, TaskState::Failed);
        let error = t.error.as_deref().unwrap();
        assert!(error.starts_with("9003 Invalid arguments"), "{error}");
        assert!(!error.contains(&acs_pass1) && !error.contains(&cr_pass1));
    }
    for kind in ["acs_auth_pending", "connection_request_pending"] {
        assert!(store.get_credential(device, kind).await.unwrap().is_some());
    }

    // Ordinary Inform -> not sent again.
    let (_, _, spvs) = session_as(addr, INFORM.to_vec(), &shared, true).await;
    assert!(spvs.is_empty());

    // Next BOOTSTRAP -> sent with new passwords, CPE accepts this time.
    let again = inform_at("000000", &["0 BOOTSTRAP"], "2026-10-03T11:30:00Z");
    let (_, _, spvs) = session_as(addr, again, &shared, true).await;
    let (_, acs_pass2) = acs_credentials_in(&spvs).expect("new ACS credentials");
    let (_, cr_pass2) = cr_credentials_in(&spvs).expect("new Connection Request credentials");
    assert_ne!(acs_pass2, acs_pass1);
    assert_ne!(cr_pass2, cr_pass1);
    for kind in ["acs_auth", "connection_request"] {
        assert!(store.get_credential(device, kind).await.unwrap().is_some());
    }
    for kind in ["acs_auth_pending", "connection_request_pending"] {
        assert!(store.get_credential(device, kind).await.unwrap().is_none());
    }
}

/// Task end without CPE fault (here: sessions lost before CPE answer) -> maybe applied
/// -> later trigger keeps its credential.
#[tokio::test]
async fn a_lost_credential_session_keeps_the_pending_credential() {
    let (_c, store, addr) = shared_credential_acs(dhonomos_core::Onboarding::default(), |b| {
        b.with_per_device_acs_auth()
    })
    .await;
    let shared = basic("shared", "shared-pw");
    // SPV handed out x3. Sessions that lose it -> noticed only when the next device session
    // replaces them.
    let first = inform_at("000000", &["0 BOOTSTRAP"], "2026-10-03T11:00:00Z");
    let (_, _, spvs) = session_as(addr, first, &shared, false).await;
    let (user, pass) = acs_credentials_in(&spvs).expect("the credential is sent");
    for _ in 0..2 {
        let (_, _, spvs) = session_as(addr, INFORM.to_vec(), &shared, false).await;
        assert_eq!(
            acs_credentials_in(&spvs),
            Some((user.clone(), pass.clone()))
        );
    }
    let device = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    let pending = store
        .get_credential(device, "acs_auth_pending")
        .await
        .unwrap()
        .unwrap();

    let again = inform_at("000000", &["0 BOOTSTRAP"], "2026-10-03T11:30:00Z");
    let (_, _, spvs) = session_as(addr, again, &shared, true).await;
    assert_eq!(acs_credentials_in(&spvs), None, "nothing is sent again");
    let tasks = store.list_tasks(device, 100).await.unwrap();
    let sent: Vec<_> = tasks
        .iter()
        .filter(|t| t.created_by.as_deref() == Some("system:acs-credentials"))
        .collect();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].state, TaskState::Failed);
    assert!(
        sent[0]
            .error
            .as_deref()
            .unwrap()
            .starts_with("session aborted"),
        "{:?}",
        sent[0].error
    );
    let still = store
        .get_credential(device, "acs_auth_pending")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (still.ciphertext, still.nonce),
        (pending.ciphertext, pending.nonce)
    );
}

/// M-4: device has the credential (applied, not yet used) -> shared session cannot replace
/// it either. New one wanted -> operator deletes the old one.
#[tokio::test]
async fn an_applied_acs_credential_is_not_replaced_by_a_shared_session() {
    let (_c, store, addr) = shared_credential_acs(dhonomos_core::Onboarding::default(), |b| {
        b.with_per_device_acs_auth()
    })
    .await;
    let shared = basic("shared", "shared-pw");
    let first = inform_at("000000", &["0 BOOTSTRAP"], "2026-10-03T11:00:00Z");
    let (_, _, spvs) = session_as(addr, first, &shared, true).await;
    let (user, pass) = acs_credentials_in(&spvs).expect("the credential is sent");
    let device = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    let active = store
        .get_credential(device, "acs_auth")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.username, user);

    // Attack: bootstrap as the device with the shared credential, before the device used its
    // own -> no new credential sent or stored.
    let again = inform_at("000000", &["0 BOOTSTRAP"], "2026-10-03T11:30:00Z");
    let (status, reply, spvs) = session_as(addr, again, &shared, true).await;
    assert_eq!((status, fault_code(&reply)), (StatusCode::OK, None));
    assert_eq!(acs_credentials_in(&spvs), None);
    let now = store
        .get_credential(device, "acs_auth")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(now.ciphertext, active.ciphertext);
    assert!(
        store
            .get_credential(device, "acs_auth_pending")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(credential_tasks(&store, device).await, 1);
    // Device keeps working with what it got.
    let own = basic(&user, &pass);
    let (status, reply, _) = session_as(addr, INFORM.to_vec(), &own, true).await;
    assert_eq!((status, fault_code(&reply)), (StatusCode::OK, None));
    let (_, reply, _) = session_as(addr, INFORM.to_vec(), &shared, true).await;
    assert_eq!(
        fault_code(&reply),
        Some(8001),
        "and the shared one is refused now"
    );

    // Re-provision = operator decision: delete the credential -> next BOOTSTRAP (device reset
    // to shared credential) gets a new one.
    assert!(store.delete_credential(device, "acs_auth").await.unwrap());
    let reset = inform_at("000000", &["0 BOOTSTRAP"], "2026-10-04T08:00:00Z");
    let (_, _, spvs) = session_as(addr, reset, &shared, true).await;
    let (new_user, new_pass) = acs_credentials_in(&spvs).expect("a new credential");
    assert_eq!(new_user, user, "usernames are derived from the device");
    assert_ne!(new_pass, pass);
    assert_eq!(credential_tasks(&store, device).await, 2);
}

// ---------------------------------------------------------------------------------------
// ADR-112: firmware change -> same CR credential sent again.
// ---------------------------------------------------------------------------------------

/// [`inform_at`] on firmware `software_version`.
fn inform_on(serial: &str, events: &[&str], current_time: &str, software_version: &str) -> Vec<u8> {
    let mut env = Envelope::decode(&inform_at(serial, events, current_time))
        .unwrap()
        .unwrap();
    let Body::Rpc(Rpc::Inform(inf)) = &mut env.body else {
        panic!()
    };
    for p in &mut inf.parameter_list {
        if p.name == "InternetGatewayDevice.DeviceInfo.SoftwareVersion" {
            p.value = software_version.into();
        }
    }
    env.encode().into_bytes()
}

/// Last store/replace time of the device credential of `kind`.
async fn rotated_at(store: &Store, device: uuid::Uuid, kind: &str) -> time::OffsetDateTime {
    sqlx::query_scalar(
        "SELECT rotated_at FROM device_credentials WHERE device_id = $1 AND kind = $2",
    )
    .bind(device)
    .bind(kind)
    .fetch_one(store.pool())
    .await
    .unwrap()
}

/// Device tasks that carry its CR credentials.
async fn cr_credential_tasks(store: &Store, device: uuid::Uuid) -> Vec<dhonomos_store::Task> {
    store
        .list_tasks(device, 100)
        .await
        .unwrap()
        .into_iter()
        .filter(|t| t.created_by.as_deref() == Some("system:cr-credentials"))
        .collect()
}

/// Active CR username + password of the device.
async fn active_cr(store: &Store, device: uuid::Uuid) -> (String, String) {
    let c = store
        .get_credential(device, "connection_request")
        .await
        .unwrap()
        .expect("an active connection request credential");
    let password = secret_box()
        .open_credential(device, &c.ciphertext, &c.nonce)
        .unwrap();
    (c.username, String::from_utf8(password).unwrap())
}

/// Device provisioned at 1st contact (BOOTSTRAP, CPE accepts) -> device + its CR credentials.
async fn provisioned(
    store: &Store,
    addr: SocketAddr,
    auth: &str,
) -> (uuid::Uuid, (String, String)) {
    let first = inform_at("000000", &["0 BOOTSTRAP"], "2026-10-03T11:00:00Z");
    let (_, _, spvs) = session_as(addr, first, auth, true).await;
    let cr = cr_credentials_in(&spvs).expect("Connection Request credentials are sent");
    let device = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active_cr(store, device).await, cr);
    (device, cr)
}

async fn has_pending_cr(store: &Store, device: uuid::Uuid) -> bool {
    store
        .get_credential(device, "connection_request_pending")
        .await
        .unwrap()
        .is_some()
}

/// Firmware change alone (no BOOTSTRAP) -> active CR credential sent again as is.
/// No new one made, stored one not touched.
#[tokio::test]
async fn a_firmware_change_sends_the_same_connection_request_credential_again() {
    let (_c, store, addr) = shared_credential_acs(dhonomos_core::Onboarding::default(), |b| {
        b.with_per_device_acs_auth()
            .with_per_device_connection_requests()
    })
    .await;
    let shared = basic("shared", "shared-pw");
    let (device, cr) = provisioned(&store, addr, &shared).await;
    assert!(!has_pending_cr(&store, device).await);
    let before = store
        .get_credential(device, "connection_request")
        .await
        .unwrap()
        .unwrap();
    let rotated = rotated_at(&store, device, "connection_request").await;

    let time = "2026-10-03T12:00:00Z";
    let upgraded = inform_on("000000", &["1 BOOT"], time, "V100R001IRQC56B018");
    let (_, _, spvs) = session_as(addr, upgraded, &shared, true).await;
    assert_eq!(
        cr_credentials_in(&spvs),
        Some(cr.clone()),
        "the same credential"
    );
    assert_eq!(
        acs_credentials_in(&spvs),
        None,
        "the ACS credential is not sent again"
    );

    assert!(!has_pending_cr(&store, device).await);
    let after = store
        .get_credential(device, "connection_request")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (after.ciphertext, after.nonce),
        (before.ciphertext, before.nonce)
    );
    assert_eq!(
        rotated_at(&store, device, "connection_request").await,
        rotated
    );
    assert_eq!(active_cr(&store, device).await, cr);

    let tasks = cr_credential_tasks(&store, device).await;
    assert_eq!(tasks.len(), 2, "the first one and the resend");
    assert!(tasks.iter().all(|t| t.state == TaskState::Succeeded));
    let key = format!("cr-credentials-resend:{device}:{time}");
    assert_eq!(
        store
            .existing_idempotency_keys(DEFAULT_TENANT, &[key])
            .await
            .unwrap()
            .len(),
        1
    );
    let rows: String = tasks.iter().map(|t| t.payload.to_string()).collect();
    assert!(!rows.contains(&cr.1), "no plaintext password in the queue");
    assert_eq!(credential_tasks(&store, device).await, 1, "one ACS task");
}

/// Resend keyed by the Inform: same firmware-change Inform again -> nothing sent.
/// (Stored firmware set back here -> it is a firmware change again.)
#[tokio::test]
async fn the_same_firmware_change_inform_sends_it_once() {
    let (_c, store, addr) = shared_credential_acs(dhonomos_core::Onboarding::default(), |b| {
        b.with_per_device_connection_requests()
    })
    .await;
    let shared = basic("shared", "shared-pw");
    let (device, cr) = provisioned(&store, addr, &shared).await;
    let time = "2026-10-03T12:00:00Z";
    let upgraded = inform_on("000000", &["1 BOOT"], time, "V100R001IRQC56B018");
    let (_, _, spvs) = session_as(addr, upgraded.clone(), &shared, true).await;
    assert_eq!(cr_credentials_in(&spvs), Some(cr));

    sqlx::query("UPDATE devices SET software_version = 'V100R001IRQC56B017' WHERE id = $1")
        .bind(device)
        .execute(store.pool())
        .await
        .unwrap();
    let (_, _, spvs) = session_as(addr, upgraded, &shared, true).await;
    assert_eq!(cr_credentials_in(&spvs), None, "not sent twice");
    assert_eq!(cr_credential_tasks(&store, device).await.len(), 2);
    assert!(!has_pending_cr(&store, device).await);
}

/// BOOTSTRAP -> active CR credential still rotated, with or without a firmware change in
/// the same Inform.
#[tokio::test]
async fn a_bootstrap_still_issues_a_new_connection_request_credential() {
    let (_c, store, addr) = shared_credential_acs(dhonomos_core::Onboarding::default(), |b| {
        b.with_per_device_connection_requests()
    })
    .await;
    let shared = basic("shared", "shared-pw");
    let (device, cr1) = provisioned(&store, addr, &shared).await;

    let reset = inform_at("000000", &["0 BOOTSTRAP"], "2026-10-03T12:00:00Z");
    let (_, _, spvs) = session_as(addr, reset, &shared, true).await;
    let cr2 = cr_credentials_in(&spvs).expect("new credentials");
    assert_eq!(cr2.0, cr1.0, "usernames are derived from the device");
    assert_ne!(cr2.1, cr1.1);
    assert_eq!(active_cr(&store, device).await, cr2);
    assert!(!has_pending_cr(&store, device).await);

    // Factory reset onto new firmware -> rotated too, not sent again.
    let time = "2026-10-03T13:00:00Z";
    let reset = inform_on(
        "000000",
        &["0 BOOTSTRAP", "1 BOOT"],
        time,
        "V100R001IRQC56B018",
    );
    let (_, _, spvs) = session_as(addr, reset, &shared, true).await;
    let cr3 = cr_credentials_in(&spvs).expect("new credentials");
    assert_ne!(cr3.1, cr2.1);
    assert_eq!(active_cr(&store, device).await, cr3);
    assert!(!has_pending_cr(&store, device).await);
    let key = format!("cr-credentials-resend:{device}:{time}");
    assert!(
        store
            .existing_idempotency_keys(DEFAULT_TENANT, &[key])
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(cr_credential_tasks(&store, device).await.len(), 3);
}

/// Firmware change while a new CR credential is pending -> pending one sent, not the active
/// one; no other made.
#[tokio::test]
async fn a_firmware_change_with_a_pending_credential_sends_that_one() {
    let (_c, store, addr) = shared_credential_acs(dhonomos_core::Onboarding::default(), |b| {
        b.with_per_device_connection_requests()
    })
    .await;
    let shared = basic("shared", "shared-pw");
    let (device, cr1) = provisioned(&store, addr, &shared).await;

    // BOOTSTRAP, session lost before CPE answer -> new one stays pending.
    let reset = inform_at("000000", &["0 BOOTSTRAP"], "2026-10-03T12:00:00Z");
    let (_, _, spvs) = session_as(addr, reset, &shared, false).await;
    let cr2 = cr_credentials_in(&spvs).expect("new credentials");
    assert_ne!(cr2.1, cr1.1);
    assert!(has_pending_cr(&store, device).await);

    let time = "2026-10-03T13:00:00Z";
    let upgraded = inform_on("000000", &["1 BOOT"], time, "V100R001IRQC56B018");
    let (_, _, spvs) = session_as(addr, upgraded, &shared, true).await;
    assert_eq!(
        cr_credentials_in(&spvs),
        Some(cr2.clone()),
        "the pending one"
    );
    assert_eq!(active_cr(&store, device).await, cr2);
    assert!(!has_pending_cr(&store, device).await);
    assert_eq!(
        cr_credential_tasks(&store, device).await.len(),
        2,
        "no third credential"
    );
    let key = format!("cr-credentials-resend:{device}:{time}");
    assert!(
        store
            .existing_idempotency_keys(DEFAULT_TENANT, &[key])
            .await
            .unwrap()
            .is_empty()
    );
}

/// M-4: quarantine mode -> nothing issued before an operator admits the device.
/// Then next Inform provisions it.
#[tokio::test]
async fn quarantined_devices_get_credentials_after_they_are_admitted() {
    use dhonomos_core::{Onboarding, OnboardingMode};
    let (_c, store, addr) = shared_credential_acs(
        Onboarding {
            mode: OnboardingMode::Quarantine,
            allowed_ouis: vec![],
        },
        |b| {
            b.with_per_device_acs_auth()
                .with_per_device_connection_requests()
        },
    )
    .await;
    let shared = basic("shared", "shared-pw");
    for time in ["2026-10-03T11:00:00Z", "2026-10-03T11:01:00Z"] {
        let bootstrap = inform_at("000000", &["0 BOOTSTRAP"], time);
        let (_, _, spvs) = session_as(addr, bootstrap, &shared, true).await;
        assert!(spvs.is_empty(), "no task runs while quarantined");
    }
    let device = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store.get_device(device).await.unwrap().unwrap().status,
        "quarantined"
    );
    assert!(
        store.list_credentials(device).await.unwrap().is_empty(),
        "nothing issued, not even a pending credential"
    );
    assert_eq!(credential_tasks(&store, device).await, 0);

    // Operator admits the device -> next (ordinary) Inform provisions it.
    store
        .set_device_status(DEFAULT_TENANT, device, "active")
        .await
        .unwrap();
    let (_, _, spvs) = session_as(addr, INFORM.to_vec(), &shared, true).await;
    assert!(acs_credentials_in(&spvs).is_some(), "ACS credentials sent");
    let kinds: Vec<String> = store
        .list_credentials(device)
        .await
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert_eq!(kinds, ["acs_auth", "connection_request"]);
    // Only once.
    let (_, _, spvs) = session_as(addr, INFORM.to_vec(), &shared, true).await;
    assert!(spvs.is_empty());
}

/// M-4: pre-registered device = admitted by an operator -> provisioned at 1st Inform,
/// bootstrap or not.
#[tokio::test]
async fn preregistered_devices_are_provisioned_at_first_contact() {
    use dhonomos_core::{Onboarding, OnboardingMode};
    let (_c, store, addr) = shared_credential_acs(
        Onboarding {
            mode: OnboardingMode::Preregistered,
            allowed_ouis: vec![],
        },
        |b| b.with_per_device_acs_auth(),
    )
    .await;
    let shared = basic("shared", "shared-pw");
    let (_, reply, spvs) = session_as(addr, INFORM.to_vec(), &shared, true).await;
    assert_eq!(
        fault_code(&reply),
        Some(8001),
        "unknown devices are refused"
    );
    assert!(spvs.is_empty());
    let device = store
        .preregister_cwmp_device(DEFAULT_TENANT, &identity(), &[])
        .await
        .unwrap()
        .id;
    let (_, _, spvs) = session_as(addr, INFORM.to_vec(), &shared, true).await;
    assert!(acs_credentials_in(&spvs).is_some());
    assert!(
        store
            .get_credential(device, "acs_auth")
            .await
            .unwrap()
            .is_some()
    );
}

/// CPE applied the credential in rollout (next to the current one), answer lost -> may use
/// either; new one then replaces the old.
#[tokio::test]
async fn either_the_current_or_the_pending_acs_credential_works() {
    let secrets = secret_box();
    let (_c, store, addr) =
        shared_credential_acs(dhonomos_core::Onboarding::default(), |b| b).await;
    let device = store
        .preregister_cwmp_device(DEFAULT_TENANT, &identity(), &[])
        .await
        .unwrap()
        .id;
    let put = async |kind: &str, password: &str| {
        let (ciphertext, nonce) = secrets
            .seal_credential(device, password.as_bytes())
            .unwrap();
        store
            .put_credential(&dhonomos_store::SealedCredential {
                device_id: device,
                kind: kind.into(),
                username: "acs-roll".into(),
                ciphertext,
                nonce,
                key_id: "k1".into(),
            })
            .await
            .unwrap();
    };
    put("acs_auth", "old-pw").await;
    put("acs_auth_pending", "new-pw").await;

    // Old password still works + new one stays waiting.
    let (_, reply, _) = session_as(addr, INFORM.to_vec(), &basic("acs-roll", "old-pw"), true).await;
    assert_eq!(fault_code(&reply), None);
    assert!(
        store
            .get_credential(device, "acs_auth_pending")
            .await
            .unwrap()
            .is_some()
    );
    let (status, _, _) = session_as(addr, INFORM.to_vec(), &basic("acs-roll", "wrong"), true).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // New one works -> becomes the credential.
    let (status, reply, _) =
        session_as(addr, INFORM.to_vec(), &basic("acs-roll", "new-pw"), true).await;
    assert_eq!((status, fault_code(&reply)), (StatusCode::OK, None));
    assert!(
        store
            .get_credential(device, "acs_auth_pending")
            .await
            .unwrap()
            .is_none()
    );
    let active = store
        .get_credential(device, "acs_auth")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        secrets
            .open_credential(device, &active.ciphertext, &active.nonce)
            .unwrap(),
        b"new-pw"
    );
    // Old password gone for good.
    let (status, _, _) =
        session_as(addr, INFORM.to_vec(), &basic("acs-roll", "old-pw"), true).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// L-1: TransferComplete names a task by CommandKey; other device's task != its own.
#[tokio::test]
async fn transfer_complete_cannot_complete_another_devices_task() {
    let (_c, store, addr) = setup(Duration::from_secs(30)).await;
    let victim = store
        .preregister_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                serial_number: "VICTIM".into(),
                ..identity()
            },
            &[],
        )
        .await
        .unwrap()
        .id;
    let task = enqueue(
        &store,
        victim,
        TaskKind::Download {
            file_id: None,
            file_type: "1 Firmware Upgrade Image".into(),
            url: "http://files/fw.bin".into(),
            username: String::new(),
            password: String::new(),
            file_size: 0,
            target_file_name: String::new(),
            sha256: String::new(),
            delay_seconds: 0,
        },
    )
    .await;
    store.next_task(victim).await.unwrap().unwrap();
    assert_eq!(
        store.get_task(task).await.unwrap().unwrap().state,
        TaskState::Running
    );

    // Other device reports TransferComplete for it.
    let mut cpe = Cpe::connect(addr).await;
    cpe.post(INFORM.to_vec()).await;
    let tc = Envelope::rpc(
        CwmpNamespace::V1_0,
        "tc1",
        TransferComplete {
            command_key: task.simple().to_string(),
            fault: TransferFault::default(),
            start_time: "2026-10-03T00:00:00Z".into(),
            complete_time: "2026-10-03T00:01:00Z".into(),
        },
    );
    let (_, resp) = cpe.post(tc.encode().into_bytes()).await;
    assert!(matches!(rpc(&resp), Rpc::TransferCompleteResponse(_)));
    let t = store.get_task(task).await.unwrap().unwrap();
    assert_eq!((t.state, t.result), (TaskState::Running, None));
    // Same with a failure report.
    let failed = Envelope::rpc(
        CwmpNamespace::V1_0,
        "tc2",
        TransferComplete {
            command_key: task.simple().to_string(),
            fault: TransferFault {
                fault_code: 9010,
                fault_string: "forged".into(),
            },
            start_time: String::new(),
            complete_time: String::new(),
        },
    );
    cpe.post(failed.encode().into_bytes()).await;
    let t = store.get_task(task).await.unwrap().unwrap();
    assert_eq!((t.state, t.error), (TaskState::Running, None));
}

impl Cpe {
    /// Connect from loopback address `source` (all 127.0.0.0/8 is local on Linux).
    async fn connect_from(source: &str, addr: SocketAddr) -> Self {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind(format!("{source}:0").parse().unwrap()).unwrap();
        let io = TokioIo::new(socket.connect(addr).await.unwrap());
        let (sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        Self { sender }
    }
}

/// L-3: shared credential -> anyone can claim any identity. Claim must not use up the real
/// device's sessions.
#[tokio::test]
async fn claiming_a_device_does_not_use_up_its_sessions() {
    let (_c, store, addr) = setup_custom(Duration::from_secs(5), |b| b.with_session_limit(2)).await;
    let fault = |env: &Option<Envelope>| fault_code(env);
    // Claimant from other address -> limited after its own 2 sessions...
    let mut results = Vec::new();
    for _ in 0..4 {
        let mut cpe = Cpe::connect_from("127.0.0.2", addr).await;
        let (_, env) = cpe.post(INFORM.to_vec()).await;
        results.push(fault(&env));
    }
    assert_eq!(results, [None, None, Some(8005), Some(8005)]);
    // ...but the device has its own allowance.
    let mut cpe = Cpe::connect(addr).await;
    let (_, env) = cpe.post(INFORM.to_vec()).await;
    assert_eq!(fault(&env), None, "the real device is not limited");
    assert!(
        store
            .find_cwmp_device(DEFAULT_TENANT, &identity())
            .await
            .unwrap()
            .is_some()
    );
}

/// L-3: CPE with another device's credential -> turned away before the session limit is
/// touched.
#[tokio::test]
async fn rejected_claims_do_not_count_against_the_session_limit() {
    let (_c, store, addr) = shared_credential_acs(dhonomos_core::Onboarding::default(), |b| {
        b.with_per_device_acs_auth().with_session_limit(2)
    })
    .await;
    let shared = basic("shared", "shared-pw");
    // 2 devices, each on its own credential.
    let mut own = Vec::new();
    for serial in ["000000", "111111"] {
        let bootstrap = inform_at(serial, &["0 BOOTSTRAP"], "2026-10-03T11:00:00Z");
        let (_, _, spvs) = session_as(addr, bootstrap, &shared, true).await;
        let (user, pass) = acs_credentials_in(&spvs).unwrap();
        own.push(basic(&user, &pass));
    }
    // Device 1 credential claims device 0 -> refused every time (8001, not 8005).
    for _ in 0..4 {
        let (_, reply, _) = session_as(
            addr,
            inform_at("000000", &[], "2026-10-03T12:00:00Z"),
            &own[1],
            true,
        )
        .await;
        assert_eq!(fault_code(&reply), Some(8001));
    }
    // Device 0 itself still gets its sessions.
    for _ in 0..2 {
        let (_, reply, _) = session_as(addr, INFORM.to_vec(), &own[0], true).await;
        assert_eq!(fault_code(&reply), None);
    }
    let _ = store;
}

/// GPV response: `n` parameters under `prefix`.
fn gpv_of(prefix: &str, n: usize) -> GetParameterValuesResponse {
    GetParameterValuesResponse {
        parameter_list: (0..n)
            .map(|i| ParameterValue::new(format!("{prefix}{i}.V"), "v", "string"))
            .collect(),
    }
}

/// L-5: names must be under a data model root; message stored only up to a limit.
#[tokio::test]
async fn reported_parameters_must_be_in_the_data_model_and_within_the_message_limit() {
    let (_c, store, addr) =
        setup_custom(Duration::from_secs(30), |b| b.with_param_limits(5, 100)).await;
    let mut cpe = Cpe::connect(addr).await;
    cpe.post(INFORM.to_vec()).await;
    let (_, req) = cpe.post(Vec::new()).await;
    assert!(matches!(rpc(&req), Rpc::GetParameterValues(_)));
    // 3 names outside the roots first, then 8 valid.
    let mut list: Vec<ParameterValue> = ["Evil.A", "X_Vendor.B", "Devicex.C"]
        .iter()
        .map(|n| ParameterValue::new(*n, "1", "string"))
        .collect();
    list.extend(gpv_of("InternetGatewayDevice.Test.", 8).parameter_list);
    // Then the Inform values: over message limit -> not stored again, but not dropped from
    // the snapshot either (a limit never deletes).
    list.extend(
        Tree::of_inform(INFORM)
            .values(&["InternetGatewayDevice.".into()])
            .parameter_list,
    );
    cpe.reply(
        req.as_ref().unwrap(),
        GetParameterValuesResponse {
            parameter_list: list,
        },
    )
    .await;
    let device = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    let paths = async |prefix: &str| -> Vec<String> {
        store
            .get_params(device, prefix)
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.path)
            .collect()
    };
    for bad in ["Evil.", "X_Vendor.", "Devicex."] {
        assert!(paths(bad).await.is_empty(), "{bad}");
    }
    assert_eq!(
        paths("InternetGatewayDevice.Test.").await,
        (0..5)
            .map(|i| format!("InternetGatewayDevice.Test.{i}.V"))
            .collect::<Vec<_>>(),
        "the first five valid ones"
    );
    // Inform had 7 params; 5 kept (10 stored in all).
    assert_eq!(paths("").await.len(), 10);
}

/// L-5: device keeps max its limit; known params still updated.
#[tokio::test]
async fn a_device_keeps_at_most_its_parameter_limit() {
    let (_c, store, addr) =
        setup_custom(Duration::from_secs(30), |b| b.with_param_limits(50_000, 8)).await;
    let mut cpe = Cpe::connect(addr).await;
    cpe.post(INFORM.to_vec()).await;
    let (_, req) = cpe.post(Vec::new()).await;
    // Inform stored 7 params; 1 more fits. Full read reports those 7 too.
    let tree =
        Tree::of_inform(INFORM).with(&gpv_of("InternetGatewayDevice.Test.", 5).parameter_list);
    let (_, req) = cpe
        .reply(
            req.as_ref().unwrap(),
            tree.values(&["InternetGatewayDevice.".into()]),
        )
        .await;
    let device = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(store.get_params(device, "").await.unwrap().len(), 8);
    assert_eq!(
        store
            .get_params(device, "InternetGatewayDevice.Test.")
            .await
            .unwrap()
            .len(),
        1
    );
    // At the limit -> GPN updates known params, adds nothing.
    assert!(matches!(rpc(&req), Rpc::GetParameterNames(_)));
    let mut names = tree
        .with(&[ParameterValue::new(
            "InternetGatewayDevice.New.Thing",
            "",
            "string",
        )])
        .names("InternetGatewayDevice.");
    for p in &mut names.parameter_list {
        p.writable = true;
    }
    cpe.reply(req.as_ref().unwrap(), names).await;
    let all = store.get_params(device, "").await.unwrap();
    assert_eq!(all.len(), 8, "still at the limit");
    let known = all
        .iter()
        .find(|p| p.path == "InternetGatewayDevice.Test.0.V")
        .unwrap();
    assert_eq!(known.writable, Some(true));
    assert!(
        all.iter()
            .all(|p| p.path != "InternetGatewayDevice.New.Thing")
    );
}

/// L-6: CPE (or whatever answers at its address) asks for Basic auth -> no CR password
/// unless the operator allows it.
#[tokio::test]
async fn connection_requests_answer_basic_challenges_only_when_allowed() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // "CPE" with Basic only, accepts cpe/secret.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/cr", listener.local_addr().unwrap());
    let sent_passwords = Arc::new(AtomicUsize::new(0));
    let accepted = Arc::new(AtomicUsize::new(0));
    {
        let (sent_passwords, accepted) = (sent_passwords.clone(), accepted.clone());
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (sent_passwords, accepted) = (sent_passwords.clone(), accepted.clone());
                tokio::spawn(async move {
                    let svc =
                        hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                            let (sent_passwords, accepted) =
                                (sent_passwords.clone(), accepted.clone());
                            async move {
                                let auth = req
                                    .headers()
                                    .get("authorization")
                                    .and_then(|v| v.to_str().ok())
                                    .map(str::to_owned);
                                let mut resp = hyper::Response::new(Full::new(Bytes::new()));
                                match auth {
                                    Some(a) if a == basic("cpe", "secret") => {
                                        sent_passwords.fetch_add(1, Ordering::SeqCst);
                                        accepted.fetch_add(1, Ordering::SeqCst);
                                        *resp.status_mut() = StatusCode::NO_CONTENT;
                                    }
                                    Some(_) => {
                                        sent_passwords.fetch_add(1, Ordering::SeqCst);
                                        *resp.status_mut() = StatusCode::UNAUTHORIZED;
                                    }
                                    None => {
                                        *resp.status_mut() = StatusCode::UNAUTHORIZED;
                                        resp.headers_mut().insert(
                                            "www-authenticate",
                                            "Basic realm=\"cpe\"".parse().unwrap(),
                                        );
                                    }
                                }
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

    let (_c, store, _addr) = setup(Duration::from_secs(30)).await;
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
    let waker = |basic: bool| {
        dhonomos_core::Waker::new(
            store.clone(),
            Some(dhonomos_cwmp_server::ConnReqCredentials {
                username: "cpe".into(),
                password: "secret".into(),
            }),
            Duration::from_secs(2),
        )
        .with_address_policy(dhonomos_cwmp_server::AddressPolicy::permit_all())
        .with_basic_auth(basic)
    };

    let outcome = waker(false).wake(device).await;
    assert!(
        matches!(&outcome, dhonomos_core::WakeOutcome::Failed(e) if e.contains("Basic")),
        "{}",
        outcome.describe()
    );
    assert_eq!(
        sent_passwords.load(Ordering::SeqCst),
        0,
        "no password left the ACS"
    );
    let failed = store.get_device(device).await.unwrap().unwrap();
    assert_eq!(failed.last_wake_method, None, "nothing was sent");
    assert!(
        failed
            .last_wake_outcome
            .as_deref()
            .is_some_and(|o| o.starts_with("failed: ") && o.contains("Basic")),
        "{:?}",
        failed.last_wake_outcome
    );

    let outcome = waker(true).wake(device).await;
    assert_eq!(
        outcome,
        dhonomos_core::WakeOutcome::Sent,
        "{}",
        outcome.describe()
    );
    let woken = store.get_device(device).await.unwrap().unwrap();
    assert_eq!(woken.last_wake_method.as_deref(), Some("http"));
    assert_eq!(woken.last_wake_outcome.as_deref(), Some("sent"));
    assert!(
        woken.last_wake_at > failed.last_wake_at,
        "the latest wake wins"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------------------
// ADR-108: firmware images read again at every boot.
// ---------------------------------------------------------------------------------------

/// Captured Inform as a TR-181 device: params under `Device.`, given serial number, events
/// (besides captured `2 PERIODIC`), CurrentTime, firmware version.
fn tr181_inform_at(
    serial: &str,
    events: &[&str],
    current_time: &str,
    software_version: &str,
) -> Vec<u8> {
    let mut env = Envelope::decode(INFORM).unwrap().unwrap();
    let Body::Rpc(Rpc::Inform(inf)) = &mut env.body else {
        panic!()
    };
    inf.device_id.serial_number = serial.into();
    inf.current_time = current_time.into();
    for p in &mut inf.parameter_list {
        p.name = p.name.replacen("InternetGatewayDevice.", "Device.", 1);
        if p.name == "Device.DeviceInfo.SoftwareVersion" {
            p.value = software_version.into();
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

/// Device has seen its firmware image rows (as after a full read of a device with them).
async fn knows_firmware_images(store: &Store, device: uuid::Uuid) {
    store
        .upsert_params(
            device,
            &[dhonomos_store::ParamUpdate {
                path: "Device.DeviceInfo.FirmwareImage.1.Version".into(),
                value: Some("V1".into()),
                ..Default::default()
            }],
        )
        .await
        .unwrap();
}

/// TR-181 boot showing `Device.DeviceInfo.FirmwareImage.` -> ACS reads that object again
/// (fallback to the other image changes neither firmware version nor any zero-touch trigger).
/// Not shown, or TR-098 device -> not asked. Resent Inform -> read x1.
/// Boot read whole anyway (BOOTSTRAP, new firmware, 1st contact) -> no extra read.
#[tokio::test]
async fn a_boot_reads_the_firmware_images_again() {
    const IMAGES: &str = "GetParameterValues Device.DeviceInfo.FirmwareImage.";
    const FULL_READ: [&str; 2] = ["GetParameterNames Device.", "GetParameterValues Device."];
    let (_c, store, addr) = setup(Duration::from_secs(30)).await;
    let id_of = |serial: &str| CwmpIdentity {
        serial_number: serial.into(),
        ..identity()
    };
    // Image reads queued by the ACS for the device.
    let boot_reads = async |device: uuid::Uuid| {
        store
            .list_tasks(device, 100)
            .await
            .unwrap()
            .into_iter()
            .filter(|t| {
                t.kind == "get_parameter_values" && t.created_by.as_deref() == Some("system:boot")
            })
            .count()
    };
    // Session of a device with firmware image rows -> a read returns them.
    let images = [ParameterValue::new(
        "Device.DeviceInfo.FirmwareImage.1.Version",
        "V1",
        "string",
    )];
    let with_images = |inform: Vec<u8>| {
        let tree = Tree::of_inform(&inform).with(&images);
        answer_session_with(addr, inform, tree)
    };

    // New device -> read whole; object not shown yet -> boot asks nothing.
    let serial = "FWIMG1";
    let asked = answer_session(
        addr,
        tr181_inform_at(serial, &[], "2026-10-19T09:00:00Z", "V1"),
    )
    .await;
    assert_eq!(asked, FULL_READ);
    let device = store
        .find_cwmp_device(DEFAULT_TENANT, &id_of(serial))
        .await
        .unwrap()
        .unwrap();
    let asked = answer_session(
        addr,
        tr181_inform_at(serial, &["1 BOOT"], "2026-10-19T09:10:00Z", "V1"),
    )
    .await;
    assert!(asked.is_empty(), "{asked:?}");
    assert_eq!(boot_reads(device).await, 0);

    // Object shown -> boot followed by a read of it, nothing else.
    knows_firmware_images(&store, device).await;
    let asked = with_images(tr181_inform_at(
        serial,
        &["1 BOOT"],
        "2026-10-19T09:20:00Z",
        "V1",
    ))
    .await;
    assert_eq!(asked, [IMAGES]);
    assert_eq!(boot_reads(device).await, 1);
    let key = format!("boot-fwimage:{device}:2026-10-19T09:20:00Z");
    assert_eq!(
        store
            .existing_idempotency_keys(DEFAULT_TENANT, &[key])
            .await
            .unwrap()
            .len(),
        1
    );
    // Not at an ordinary Inform.
    let asked = with_images(tr181_inform_at(serial, &[], "2026-10-19T09:30:00Z", "V1")).await;
    assert!(asked.is_empty(), "{asked:?}");
    // Same Inform again (retransmission) -> same boot.
    let asked = with_images(tr181_inform_at(
        serial,
        &["1 BOOT"],
        "2026-10-19T09:20:00Z",
        "V1",
    ))
    .await;
    assert!(asked.is_empty(), "{asked:?}");
    assert_eq!(boot_reads(device).await, 1);
    // Next boot = new boot.
    let asked = with_images(tr181_inform_at(
        serial,
        &["1 BOOT"],
        "2026-10-19T10:00:00Z",
        "V1",
    ))
    .await;
    assert_eq!(asked, [IMAGES]);
    assert_eq!(boot_reads(device).await, 2);

    // Read whole anyway: factory reset (BOOTSTRAP) + new firmware.
    let asked = with_images(tr181_inform_at(
        serial,
        &["0 BOOTSTRAP", "1 BOOT"],
        "2026-10-19T11:00:00Z",
        "V1",
    ))
    .await;
    assert_eq!(asked, FULL_READ);
    let asked = with_images(tr181_inform_at(
        serial,
        &["1 BOOT"],
        "2026-10-19T12:00:00Z",
        "V2",
    ))
    .await;
    assert_eq!(asked, FULL_READ);
    assert_eq!(boot_reads(device).await, 2);

    // Read whole anyway: 1st contact of a pre-registered device with the rows.
    let pre = id_of("FWIMG2");
    let device = store
        .preregister_cwmp_device(DEFAULT_TENANT, &pre, &[])
        .await
        .unwrap()
        .id;
    knows_firmware_images(&store, device).await;
    let asked = with_images(tr181_inform_at(
        &pre.serial_number,
        &["1 BOOT"],
        "2026-10-19T09:00:00Z",
        "V1",
    ))
    .await;
    assert_eq!(asked, FULL_READ);
    assert_eq!(boot_reads(device).await, 0);

    // TR-098 device -> not asked, whatever else is stored.
    let serial = "FWIMG3";
    let asked = answer_session(addr, inform_at(serial, &[], "2026-10-19T09:00:00Z")).await;
    assert_eq!(
        asked,
        [
            "GetParameterNames InternetGatewayDevice.",
            "GetParameterValues InternetGatewayDevice."
        ]
    );
    let device = store
        .find_cwmp_device(DEFAULT_TENANT, &id_of(serial))
        .await
        .unwrap()
        .unwrap();
    knows_firmware_images(&store, device).await;
    let asked = answer_session(addr, inform_at(serial, &["1 BOOT"], "2026-10-19T09:10:00Z")).await;
    assert!(asked.is_empty(), "{asked:?}");
    assert_eq!(boot_reads(device).await, 0);
}

/// Seed of the stale-parameter tests: 2 Ethernet interfaces (2nd with object rows),
/// table count, a virtual parameter.
async fn seed_ethernet(store: &Store, device: uuid::Uuid) {
    let rows: Vec<dhonomos_store::ParamUpdate> = [
        "Device.Ethernet.Interface.1.Name",
        "Device.Ethernet.Interface.2.Name",
        "Device.Ethernet.Interface.2.",
        "Device.Ethernet.Interface.2.Stats.",
        "Device.Ethernet.InterfaceNumberOfEntries",
        "VirtualParameters.x",
    ]
    .iter()
    .map(|path| dhonomos_store::ParamUpdate {
        path: (*path).into(),
        value: (!path.ends_with('.')).then(|| "v".into()),
        ..Default::default()
    })
    .collect();
    store.upsert_params(device, &rows).await.unwrap();
}

/// Stored device paths under `Device.Ethernet.` and `VirtualParameters.`.
async fn ethernet_rows(store: &Store, device: uuid::Uuid) -> Vec<String> {
    let mut rows: Vec<String> = Vec::new();
    for prefix in ["Device.Ethernet.", "VirtualParameters."] {
        rows.extend(
            store
                .get_params(device, prefix)
                .await
                .unwrap()
                .into_iter()
                .map(|p| p.path),
        );
    }
    rows
}

/// One session: answer the ACS task with `answer` -> request it got.
async fn answer_task(addr: SocketAddr, answer: impl FnOnce(&Envelope) -> Envelope) -> Rpc {
    let mut cpe = Cpe::connect(addr).await;
    cpe.post(INFORM.to_vec()).await;
    let (_, req) = cpe.post(Vec::new()).await;
    let request = rpc(&req).clone();
    let (status, _) = cpe
        .post(answer(req.as_ref().unwrap()).encode().into_bytes())
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    request
}

fn reply_with(to: &Envelope, rpc: impl Into<Rpc>) -> Envelope {
    Envelope::rpc(CwmpNamespace::V1_0, to.header.id.clone().unwrap(), rpc)
}

/// ADR-111: values read of an object drops leaves it no longer returns + object rows of
/// instances it no longer has. Rows outside the object stay.
#[tokio::test]
async fn a_values_read_of_an_object_drops_what_the_device_no_longer_reports() {
    let (_c, store, addr) = setup(Duration::from_secs(30)).await;
    let device = known_device(&store, addr).await;
    seed_ethernet(&store, device).await;
    let task = enqueue(
        &store,
        device,
        TaskKind::GetParameterValues {
            names: vec!["Device.Ethernet.".into()],
        },
    )
    .await;
    let asked = answer_task(addr, |req| {
        reply_with(
            req,
            GetParameterValuesResponse {
                parameter_list: vec![
                    ParameterValue::new("Device.Ethernet.Interface.1.Name", "eth0", "string"),
                    ParameterValue::new(
                        "Device.Ethernet.InterfaceNumberOfEntries",
                        "1",
                        "unsignedInt",
                    ),
                ],
            },
        )
    })
    .await;
    assert!(matches!(asked, Rpc::GetParameterValues(_)));
    assert_eq!(
        ethernet_rows(&store, device).await,
        [
            "Device.Ethernet.Interface.1.Name",
            "Device.Ethernet.InterfaceNumberOfEntries",
            "VirtualParameters.x",
        ]
    );
    let t = store.get_task(task).await.unwrap().unwrap();
    assert_eq!(t.state, TaskState::Succeeded);
    assert_eq!(
        t.result,
        Some(serde_json::json!({ "parameters": 2, "removed": 3 }))
    );
}

/// ADR-111: names read of whole subtree drops object rows it does not return + all under a
/// gone instance. Not a leaf of a live object (values read's job).
#[tokio::test]
async fn a_names_read_drops_vanished_objects_but_not_the_leaves_of_live_ones() {
    let (_c, store, addr) = setup(Duration::from_secs(30)).await;
    let device = known_device(&store, addr).await;
    seed_ethernet(&store, device).await;
    let info = |name: &str| dhonomos_cwmp_codec::ParameterInfo {
        name: name.into(),
        writable: false,
    };
    let names = dhonomos_cwmp_codec::GetParameterNamesResponse {
        parameter_list: vec![
            info("Device.Ethernet."),
            info("Device.Ethernet.Interface."),
            info("Device.Ethernet.Interface.1."),
            info("Device.Ethernet.Interface.1.Name"),
        ],
    };

    // Next level only -> nothing dropped.
    let task = enqueue(
        &store,
        device,
        TaskKind::GetParameterNames {
            path: "Device.Ethernet.".into(),
            next_level: true,
        },
    )
    .await;
    let reply = names.clone();
    answer_task(addr, |req| reply_with(req, reply)).await;
    let rows = ethernet_rows(&store, device).await;
    assert!(
        rows.iter()
            .any(|p| p == "Device.Ethernet.Interface.2.Stats."),
        "{rows:?}"
    );
    assert_eq!(
        store.get_task(task).await.unwrap().unwrap().result.unwrap()["removed"],
        0
    );

    // Whole subtree.
    let task = enqueue(
        &store,
        device,
        TaskKind::GetParameterNames {
            path: "Device.Ethernet.".into(),
            next_level: false,
        },
    )
    .await;
    answer_task(addr, |req| reply_with(req, names)).await;
    assert_eq!(
        ethernet_rows(&store, device).await,
        [
            "Device.Ethernet.",
            "Device.Ethernet.Interface.",
            "Device.Ethernet.Interface.1.",
            "Device.Ethernet.Interface.1.Name",
            "Device.Ethernet.InterfaceNumberOfEntries",
            "VirtualParameters.x",
        ]
    );
    let t = store.get_task(task).await.unwrap().unwrap();
    assert_eq!(t.state, TaskState::Succeeded);
    assert_eq!(t.result.unwrap()["removed"], 3);
}

/// ADR-111: read refused by the device -> drops nothing.
#[tokio::test]
async fn a_refused_read_drops_nothing() {
    let (_c, store, addr) = setup(Duration::from_secs(30)).await;
    let device = known_device(&store, addr).await;
    seed_ethernet(&store, device).await;
    let before = ethernet_rows(&store, device).await;
    let task = enqueue(
        &store,
        device,
        TaskKind::GetParameterValues {
            names: vec!["Device.Ethernet.".into()],
        },
    )
    .await;
    answer_task(addr, |req| Envelope {
        header: dhonomos_cwmp_codec::Header {
            id: req.header.id.clone(),
            ..Default::default()
        },
        body: Body::Fault(dhonomos_cwmp_codec::Fault::new(
            9005,
            "Invalid parameter name",
        )),
        namespace: CwmpNamespace::V1_0,
    })
    .await;
    assert_eq!(
        store.get_task(task).await.unwrap().unwrap().state,
        TaskState::Failed
    );
    assert_eq!(ethernet_rows(&store, device).await, before);
}

/// ADR-111: read of whole tree, nothing returned under it -> broken answer, drops nothing.
#[tokio::test]
async fn an_empty_read_of_the_whole_tree_drops_nothing() {
    let (_c, store, addr) = setup(Duration::from_secs(30)).await;
    let device = known_device(&store, addr).await;
    let rows: Vec<dhonomos_store::ParamUpdate> = [
        "InternetGatewayDevice.LANDevice.1.Name",
        "InternetGatewayDevice.LANDevice.2.Name",
        "InternetGatewayDevice.LANDevice.2.",
    ]
    .iter()
    .map(|path| dhonomos_store::ParamUpdate {
        path: (*path).into(),
        value: (!path.ends_with('.')).then(|| "v".into()),
        ..Default::default()
    })
    .collect();
    store.upsert_params(device, &rows).await.unwrap();
    let paths = async || -> Vec<String> {
        store
            .get_params(device, "")
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.path)
            .collect()
    };
    let before = paths().await;
    assert!(before.len() > rows.len(), "the Inform's rows as well");
    let task = enqueue(
        &store,
        device,
        TaskKind::GetParameterValues {
            names: vec!["InternetGatewayDevice.".into()],
        },
    )
    .await;
    answer_task(addr, |req| {
        reply_with(req, GetParameterValuesResponse::default())
    })
    .await;
    assert_eq!(paths().await, before);
    let t = store.get_task(task).await.unwrap().unwrap();
    assert_eq!(t.state, TaskState::Succeeded);
    assert_eq!(
        t.result,
        Some(serde_json::json!({ "parameters": 0, "removed": 0 }))
    );
}
