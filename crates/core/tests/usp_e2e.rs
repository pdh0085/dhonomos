//! USP e2e: UspService + Mosquitto + PostgreSQL, scripted Agent on MQTT.
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dhonomos_core::{Presets, TaskKind, UspConfig, UspService};
use dhonomos_store::{DEFAULT_TENANT, NewTask, Store, TaskState};
use dhonomos_usp_mtp::{MqttConfig, MqttMtp};
use dhonomos_usp_proto::msg::{self, body::MsgBody, request::ReqType, response::RespType};
use dhonomos_usp_proto::record::{self, record::RecordType};
use dhonomos_usp_proto::{UspVersion, builder};
use prost::Message as _;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{GenericImage, ImageExt};

const CTRL: &str = "self::dhonomos-test";
const CTRL_TOPIC: &str = "usp/controller/test";
const AGENT: &str = "proto::agent-1";
const AGENT_TOPIC: &str = "usp/agent/1";

/// Controller read at Agent connect (as Agents log it): DeviceInfo identity params by name.
/// Not the object -> DeviceLog + ProcessStatus can be 10s of KB on a pay-per-byte link.
const IDENTITY_GET: &str = "get Device.DeviceInfo.Manufacturer,Device.DeviceInfo.ManufacturerOUI,\
Device.DeviceInfo.ProductClass,Device.DeviceInfo.SerialNumber,Device.DeviceInfo.ModelName,\
Device.DeviceInfo.SoftwareVersion,Device.DeviceInfo.HardwareVersion";

fn rec_bytes(m: &msg::Msg) -> Vec<u8> {
    builder::no_session_record(UspVersion { major: 1, minor: 3 }, AGENT, CTRL, m).encode_to_vec()
}

/// Get answered from `tree` (full paths -> values), like an Agent: 1 result per requested path.
/// Object path -> all params under it, grouped by object (none if the Agent has none).
/// Missing param path -> error result `7026 Invalid path`.
/// Object read drops stored rows it does not return (ADR-111) -> stub answers with all it has.
fn get_reply(
    id: &str,
    g: &msg::Get,
    tree: &std::collections::BTreeMap<String, String>,
) -> msg::Msg {
    let results = g
        .param_paths
        .iter()
        .map(|path| {
            let mut objects: std::collections::BTreeMap<&str, HashMap<String, String>> =
                Default::default();
            for (name, value) in tree.iter().filter(|(name, _)| {
                if path.ends_with('.') {
                    name.starts_with(path.as_str())
                } else {
                    *name == path
                }
            }) {
                let (object, param) = name.split_at(name.rfind('.').unwrap() + 1);
                objects
                    .entry(object)
                    .or_default()
                    .insert(param.to_owned(), value.clone());
            }
            if objects.is_empty() && !path.ends_with('.') {
                return msg::get_resp::RequestedPathResult {
                    requested_path: path.clone(),
                    err_code: 7026,
                    err_msg: "Invalid path".into(),
                    resolved_path_results: Vec::new(),
                };
            }
            msg::get_resp::RequestedPathResult {
                requested_path: path.clone(),
                err_code: 0,
                err_msg: String::new(),
                resolved_path_results: objects
                    .into_iter()
                    .map(|(object, params)| msg::get_resp::ResolvedPathResult {
                        resolved_path: object.to_owned(),
                        result_params: params,
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

/// Minimal Agent: Get from DeviceInfo + values set, takes Set, logs what it saw.
async fn run_agent(
    mtp: MqttMtp,
    mut rx: tokio::sync::mpsc::Receiver<dhonomos_usp_mtp::Inbound>,
    seen: Arc<std::sync::Mutex<Vec<String>>>,
) {
    let mut tree: std::collections::BTreeMap<String, String> = [
        ("Manufacturer", "Acme"),
        ("ManufacturerOUI", "00AA00"),
        ("ProductClass", "Box"),
        ("SerialNumber", "U1"),
        ("SoftwareVersion", "2.0"),
    ]
    .into_iter()
    .map(|(k, v)| (format!("Device.DeviceInfo.{k}"), v.to_owned()))
    .collect();
    while let Some(i) = rx.recv().await {
        let rec = record::Record::decode(i.payload).unwrap();
        let Some(RecordType::NoSessionContext(ns)) = rec.record_type else {
            continue;
        };
        let m = msg::Msg::decode(ns.payload.as_slice()).unwrap();
        let id = m.header.as_ref().unwrap().msg_id.clone();
        let Some(MsgBody::Request(req)) = m.body.and_then(|b| b.msg_body) else {
            continue;
        };
        let reply = match req.req_type {
            Some(ReqType::Get(g)) => {
                seen.lock()
                    .unwrap()
                    .push(format!("get {}", g.param_paths.join(",")));
                get_reply(&id, &g, &tree)
            }
            Some(ReqType::Set(s)) => {
                for o in &s.update_objs {
                    for p in &o.param_settings {
                        seen.lock()
                            .unwrap()
                            .push(format!("set {}{}={}", o.obj_path, p.param, p.value));
                        tree.insert(format!("{}{}", o.obj_path, p.param), p.value.clone());
                    }
                }
                builder::response(&id, RespType::SetResp(msg::SetResp::default()))
            }
            _ => builder::error(
                &id,
                dhonomos_usp_proto::ErrorCode::MESSAGE_NOT_SUPPORTED,
                "no",
            ),
        };
        mtp.send(CTRL_TOPIC, rec_bytes(&reply)).await.unwrap();
    }
}

#[tokio::test]
async fn usp_agent_onboarding_presets_and_value_change() {
    let pg = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let store = Store::connect(
        &format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            pg.get_host_port_ipv4(5432).await.unwrap()
        ),
        4,
    )
    .await
    .unwrap();
    store.migrate().await.unwrap();
    let broker = GenericImage::new("eclipse-mosquitto", "2")
        .with_exposed_port(1883.tcp())
        .with_wait_for(WaitFor::message_on_stderr("running"))
        .with_cmd(["mosquitto", "-c", "/mosquitto-no-auth.conf"])
        .start()
        .await
        .unwrap();
    let port = broker.get_host_port_ipv4(1883).await.unwrap();
    let mqtt = |id: &str, topic: &str| MqttConfig {
        host: "127.0.0.1".into(),
        port,
        client_id: id.into(),
        credentials: None,
        controller_topic: topic.into(),
        keep_alive: Duration::from_secs(30),
        tls: None,
    };
    // Same preset form as for CWMP devices: set once per device.
    let presets = Presets::from_yaml(
        r#"
presets:
  - name: usp-interval
    when: { events: ["USP CONNECT"], oui: 00AA00 }
    once: true
    run:
      - kind: set_parameter_values
        payload: { values: [ { name: Device.LocalAgent.Controller.1.PeriodicNotifInterval, value: "600" } ] }
"#,
    )
    .unwrap();
    let svc = UspService::start(
        store.clone(),
        UspConfig {
            mqtt: Some(mqtt("ctrl", CTRL_TOPIC)),
            websocket: false,
            onboarding: dhonomos_core::Onboarding::default(),
            stomp: None,
            mqtt_broker: None,
            metrics: None,
            files: None,
            secrets: None,
            ws_client_tls: None,
            auto_subscribe: true,
            wg_sweep_interval: dhonomos_core::DEFAULT_WG_SWEEP_INTERVAL,
            wg_incomplete_retry: dhonomos_core::DEFAULT_WG_INCOMPLETE_RETRY,
            wg_ip_poll_interval: dhonomos_core::DEFAULT_WG_IP_POLL_INTERVAL,
            wg_ip_poll_limit: dhonomos_core::DEFAULT_WG_IP_POLL_LIMIT,
            endpoint_id: CTRL.into(),
            request_timeout: Duration::from_secs(5),
            full_read_timeout: Duration::from_secs(5),
            tenant_id: DEFAULT_TENANT,
            presets: presets.into(),
        },
    );

    let (agent_mtp, agent_rx) = MqttMtp::start(mqtt("agent", AGENT_TOPIC));
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    tokio::spawn(run_agent(agent_mtp.clone(), agent_rx, seen.clone()));
    tokio::time::sleep(Duration::from_millis(500)).await;

    let connect = record::Record {
        version: "1.3".into(),
        to_id: CTRL.into(),
        from_id: AGENT.into(),
        record_type: Some(RecordType::MqttConnect(record::MqttConnectRecord {
            version: 1,
            subscribed_topic: AGENT_TOPIC.into(),
        })),
        ..Default::default()
    };
    agent_mtp
        .send(CTRL_TOPIC, connect.encode_to_vec())
        .await
        .unwrap();

    // Registration, DeviceInfo, preset Set -> in this order.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let device = loop {
        if let Some(id) = store.find_usp_device(DEFAULT_TENANT, AGENT).await.unwrap() {
            let tasks = store.list_tasks(id, 10).await.unwrap();
            if tasks.iter().any(|t| t.state == TaskState::Succeeded) {
                break id;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "agent was not onboarded: {:?}",
            seen.lock().unwrap()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert!(svc.is_connected(AGENT));
    let d = store.get_device(device).await.unwrap().unwrap();
    assert_eq!(
        (
            d.protocol.as_str(),
            d.manufacturer.as_deref(),
            d.serial_number.as_deref(),
            d.software_version.as_deref()
        ),
        ("usp", Some("Acme"), Some("U1"), Some("2.0"))
    );
    let log = seen.lock().unwrap().clone();
    assert_eq!(log[0], IDENTITY_GET);
    // Subscription table read before the Controller adds its subscriptions.
    assert_eq!(log[1], "get Device.LocalAgent.Subscription.");
    assert_eq!(
        log[2],
        "set Device.LocalAgent.Controller.1.PeriodicNotifInterval=600"
    );
    // New Agent -> full read, after the preset (lower priority).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !seen.lock().unwrap().iter().any(|l| l == "get Device.") {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no full read: {:?}",
            seen.lock().unwrap()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // ValueChange notification -> normalized parameter_change event.
    let notify = builder::request(
        "n-1",
        ReqType::Notify(msg::Notify {
            subscription_id: "vc".into(),
            send_resp: false,
            notification: Some(msg::notify::Notification::ValueChange(
                msg::notify::ValueChange {
                    param_path: "Device.LocalAgent.Controller.1.PeriodicNotifInterval".into(),
                    param_value: "900".into(),
                },
            )),
        }),
    );
    agent_mtp
        .send(CTRL_TOPIC, rec_bytes(&notify))
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let events = store.list_events(device, 10).await.unwrap();
        if let Some(e) = events.iter().find(|e| e.kind == "parameter_change") {
            let c = &e.detail["changes"][0];
            assert_eq!(
                (c["old"].as_str(), c["new"].as_str()),
                (Some("600"), Some("900"))
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no parameter_change event"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Small Agent: Get on DeviceInfo, Set, Add (subscriptions); else error.
fn answer(req: ReqType, id: &str) -> msg::Msg {
    match req {
        ReqType::Get(g) => {
            let params: HashMap<String, String> = [
                ("Manufacturer", "Acme"),
                ("ManufacturerOUI", "00AA00"),
                ("ProductClass", "WsBox"),
                ("SerialNumber", "W1"),
                ("SoftwareVersion", "3.0"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
            builder::response(
                id,
                RespType::GetResp(msg::GetResp {
                    req_path_results: vec![msg::get_resp::RequestedPathResult {
                        requested_path: g.param_paths[0].clone(),
                        err_code: 0,
                        err_msg: String::new(),
                        resolved_path_results: vec![msg::get_resp::ResolvedPathResult {
                            resolved_path: "Device.DeviceInfo.".into(),
                            result_params: params,
                        }],
                    }],
                }),
            )
        }
        ReqType::Set(_) => builder::response(id, RespType::SetResp(msg::SetResp::default())),
        ReqType::Add(_) => builder::response(id, RespType::AddResp(msg::AddResp::default())),
        _ => builder::error(
            id,
            dhonomos_usp_proto::ErrorCode::MESSAGE_NOT_SUPPORTED,
            "no",
        ),
    }
}

#[tokio::test]
#[allow(clippy::result_large_err)]
async fn controller_connects_to_an_agent_websocket_server() {
    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::tungstenite::Message;
    const WS_AGENT: &str = "proto::agent-ws-server";

    let pg = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let store = Store::connect(
        &format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            pg.get_host_port_ipv4(5432).await.unwrap()
        ),
        4,
    )
    .await
    .unwrap();
    store.migrate().await.unwrap();

    // Agent WebSocket server: announces itself, then answers requests.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/usp", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_hdr_async(
            tcp,
            |_: &tokio_tungstenite::tungstenite::handshake::server::Request,
             mut resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                resp.headers_mut().insert(
                    "sec-websocket-protocol",
                    tokio_tungstenite::tungstenite::http::HeaderValue::from_static("v1.usp"),
                );
                Ok(resp)
            },
        )
        .await
        .unwrap();
        let (mut sink, mut stream) = ws.split();
        let version = UspVersion { major: 1, minor: 3 };
        let hello = builder::websocket_connect_record(version, WS_AGENT, CTRL);
        sink.send(Message::Binary(hello.encode_to_vec().into()))
            .await
            .unwrap();
        while let Some(Ok(Message::Binary(b))) = stream.next().await {
            let rec = record::Record::decode(b).unwrap();
            let Some(RecordType::NoSessionContext(ns)) = rec.record_type else {
                continue;
            };
            let m = msg::Msg::decode(ns.payload.as_slice()).unwrap();
            let id = m.header.as_ref().unwrap().msg_id.clone();
            let Some(MsgBody::Request(req)) = m.body.and_then(|b| b.msg_body) else {
                continue;
            };
            let reply = answer(req.req_type.unwrap(), &id);
            let out = builder::no_session_record(version, WS_AGENT, CTRL, &reply);
            sink.send(Message::Binary(out.encode_to_vec().into()))
                .await
                .unwrap();
        }
    });

    // Agent registered with its server URL before the Controller starts.
    let device = store
        .preregister_usp_device(DEFAULT_TENANT, WS_AGENT, &[])
        .await
        .unwrap()
        .id;
    assert!(
        store
            .set_usp_ws_url(DEFAULT_TENANT, device, Some(&url))
            .await
            .unwrap()
    );
    let svc = UspService::start(
        store.clone(),
        UspConfig {
            mqtt: None,
            websocket: true,
            onboarding: dhonomos_core::Onboarding::default(),
            stomp: None,
            mqtt_broker: None,
            metrics: None,
            files: None,
            secrets: None,
            ws_client_tls: None,
            auto_subscribe: true,
            wg_sweep_interval: dhonomos_core::DEFAULT_WG_SWEEP_INTERVAL,
            wg_incomplete_retry: dhonomos_core::DEFAULT_WG_INCOMPLETE_RETRY,
            wg_ip_poll_interval: dhonomos_core::DEFAULT_WG_IP_POLL_INTERVAL,
            wg_ip_poll_limit: dhonomos_core::DEFAULT_WG_IP_POLL_LIMIT,
            endpoint_id: CTRL.into(),
            request_timeout: Duration::from_secs(5),
            full_read_timeout: Duration::from_secs(5),
            tenant_id: DEFAULT_TENANT,
            presets: Presets::default().into(),
        },
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let d = store.get_device(device).await.unwrap().unwrap();
        if svc.is_connected(WS_AGENT) && d.software_version.as_deref() == Some("3.0") {
            assert_eq!(d.serial_number.as_deref(), Some("W1"));
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the Agent was not reached"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Agent answers a Set, then closes its WebSocket at once (obuspa: Set changes its own MTP).
/// Response must not be lost -> task succeeds at 1st attempt, Set sent once.
/// Old bug: close requeued the task during response recording -> result dropped, request resent.
#[tokio::test]
#[allow(clippy::result_large_err)]
async fn response_just_before_a_close_is_kept() {
    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest as _};
    const WS_AGENT: &str = "proto::agent-closes";
    const ROUNDS: usize = 20;

    let pg = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let store = Store::connect(
        &format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            pg.get_host_port_ipv4(5432).await.unwrap()
        ),
        4,
    )
    .await
    .unwrap();
    store.migrate().await.unwrap();
    let svc = UspService::start(
        store.clone(),
        UspConfig {
            mqtt: None,
            websocket: true,
            onboarding: dhonomos_core::Onboarding::default(),
            stomp: None,
            mqtt_broker: None,
            metrics: None,
            files: None,
            secrets: None,
            ws_client_tls: None,
            auto_subscribe: true,
            wg_sweep_interval: dhonomos_core::DEFAULT_WG_SWEEP_INTERVAL,
            wg_incomplete_retry: dhonomos_core::DEFAULT_WG_INCOMPLETE_RETRY,
            wg_ip_poll_interval: dhonomos_core::DEFAULT_WG_IP_POLL_INTERVAL,
            wg_ip_poll_limit: dhonomos_core::DEFAULT_WG_IP_POLL_LIMIT,
            endpoint_id: CTRL.into(),
            request_timeout: Duration::from_secs(5),
            full_read_timeout: Duration::from_secs(5),
            tenant_id: DEFAULT_TENANT,
            presets: Presets::default().into(),
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/usp?eid={WS_AGENT}", listener.local_addr().unwrap());
    let router = svc.ws_mtp().unwrap().router();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    // Agent: connect, answer requests, close right after each SetResp, connect again
    // (like obuspa after an MTP change).
    let sets = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let agent_sets = sets.clone();
    tokio::spawn(async move {
        let version = UspVersion { major: 1, minor: 3 };
        loop {
            let mut req = url.as_str().into_client_request().unwrap();
            req.headers_mut().insert(
                "sec-websocket-protocol",
                tokio_tungstenite::tungstenite::http::HeaderValue::from_static("v1.usp"),
            );
            let Ok((ws, _)) = tokio_tungstenite::connect_async(req).await else {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };
            let (mut sink, mut stream) = ws.split();
            let hello = builder::websocket_connect_record(version, WS_AGENT, CTRL);
            sink.send(Message::Binary(hello.encode_to_vec().into()))
                .await
                .unwrap();
            while let Some(Ok(Message::Binary(b))) = stream.next().await {
                let rec = record::Record::decode(b).unwrap();
                let Some(RecordType::NoSessionContext(ns)) = rec.record_type else {
                    continue;
                };
                let m = msg::Msg::decode(ns.payload.as_slice()).unwrap();
                let id = m.header.as_ref().unwrap().msg_id.clone();
                let Some(MsgBody::Request(req)) = m.body.and_then(|b| b.msg_body) else {
                    continue;
                };
                let req = req.req_type.unwrap();
                let is_set = matches!(req, ReqType::Set(_));
                let reply = answer(req, &id);
                let out = builder::no_session_record(version, WS_AGENT, CTRL, &reply);
                sink.send(Message::Binary(out.encode_to_vec().into()))
                    .await
                    .unwrap();
                if is_set {
                    agent_sets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = sink.send(Message::Close(None)).await;
                    break;
                }
            }
        }
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let device = loop {
        if let Some(id) = store
            .find_usp_device(DEFAULT_TENANT, WS_AGENT)
            .await
            .unwrap()
            && svc.is_connected(WS_AGENT)
        {
            break id;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the Agent did not connect"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    for round in 0..ROUNDS {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while !svc.is_connected(WS_AGENT) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "round {round}: the Agent did not reconnect"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let (task, _) = store
            .enqueue_task(&dhonomos_store::NewTask::new(
                DEFAULT_TENANT,
                device,
                "set_parameter_values",
                serde_json::json!({ "values": [ {
                    "name": "Device.LocalAgent.Controller.1.MTP.1.WebSocket.EnableEncryption",
                    "value": if round % 2 == 0 { "true" } else { "false" },
                    "type": "boolean",
                } ] }),
            ))
            .await
            .unwrap();
        svc.wake(device, WS_AGENT).await;
        let t = loop {
            let t = store.get_task(task).await.unwrap().unwrap();
            if t.state != TaskState::Pending && t.state != TaskState::Running {
                break t;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "round {round}: the task did not finish"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(
            (t.state, t.attempts),
            (TaskState::Succeeded, 1),
            "round {round}: {:?}",
            t.error
        );
    }
    assert_eq!(
        sets.load(std::sync::atomic::Ordering::SeqCst),
        ROUNDS,
        "each Set was sent once"
    );
}

/// Minimal STOMP 1.2 client for the tests.
struct StompClient {
    tcp: tokio::net::TcpStream,
    buf: Vec<u8>,
}

impl StompClient {
    async fn connect(addr: std::net::SocketAddr) -> Self {
        Self {
            tcp: tokio::net::TcpStream::connect(addr).await.unwrap(),
            buf: Vec::new(),
        }
    }

    async fn send(&mut self, f: &dhonomos_usp_mtp::stomp::Frame) {
        use tokio::io::AsyncWriteExt as _;
        self.tcp.write_all(&f.encode()).await.unwrap();
    }

    /// Next frame; `None` -> broker closed the connection.
    async fn next(&mut self) -> Option<dhonomos_usp_mtp::stomp::Frame> {
        self.next_within(Duration::from_secs(10))
            .await
            .expect("no frame from the broker")
    }

    /// Like [`Self::next`], but gives up after `wait` with no data (nothing lost).
    async fn next_within(
        &mut self,
        wait: Duration,
    ) -> Result<Option<dhonomos_usp_mtp::stomp::Frame>, tokio::time::error::Elapsed> {
        use dhonomos_usp_mtp::stomp::{Frame, Parsed};
        use tokio::io::AsyncReadExt as _;
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

/// USP over the embedded STOMP broker (US-06, ADR-092).
/// Agent: shared login -> destination from CONNECTED -> STOMPConnect Record -> registered + read.
/// Wrong passcode + unknown destination -> refused.
#[tokio::test]
async fn usp_agent_over_the_embedded_stomp_broker() {
    use dhonomos_usp_mtp::stomp::{Frame, USP_CONTENT_TYPE};
    const AGENT: &str = "os::00AA00-STOMP1";

    let pg = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let store = Store::connect(
        &format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            pg.get_host_port_ipv4(5432).await.unwrap()
        ),
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
            stomp: Some(dhonomos_usp_mtp::StompConfig {
                login: Some(("cpe".into(), "factory".into())),
                ..dhonomos_usp_mtp::StompConfig::default()
            }),
            mqtt_broker: None,
            metrics: None,
            files: None,
            secrets: None,
            ws_client_tls: None,
            auto_subscribe: true,
            wg_sweep_interval: dhonomos_core::DEFAULT_WG_SWEEP_INTERVAL,
            wg_incomplete_retry: dhonomos_core::DEFAULT_WG_INCOMPLETE_RETRY,
            wg_ip_poll_interval: dhonomos_core::DEFAULT_WG_IP_POLL_INTERVAL,
            wg_ip_poll_limit: dhonomos_core::DEFAULT_WG_IP_POLL_LIMIT,
            endpoint_id: CTRL.into(),
            request_timeout: Duration::from_secs(5),
            full_read_timeout: Duration::from_secs(5),
            tenant_id: DEFAULT_TENANT,
            presets: Presets::default().into(),
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let broker = svc.stomp_mtp().unwrap().clone();
    tokio::spawn(async move {
        broker
            .serve(listener, None, std::future::pending())
            .await
            .unwrap()
    });
    let connect = |passcode: &str| {
        Frame::new(
            "STOMP",
            &[
                ("accept-version", "1.2"),
                ("host", "dhonomos"),
                ("login", "cpe"),
                ("passcode", passcode),
                ("endpoint-id", AGENT),
                ("heart-beat", "0,0"),
            ],
        )
    };

    // Wrong passcode -> ERROR + connection closed.
    let mut bad = StompClient::connect(addr).await;
    bad.send(&connect("guess")).await;
    let e = bad.next().await.unwrap();
    assert_eq!(e.command, "ERROR");
    assert!(bad.next().await.is_none());

    // Agent: CONNECTED gives its destination -> subscribe + hello.
    let mut agent = StompClient::connect(addr).await;
    agent.send(&connect("factory")).await;
    let connected = agent.next().await.unwrap();
    assert_eq!(connected.command, "CONNECTED");
    let dest = connected.header("subscribe-dest").unwrap().to_owned();
    assert_eq!(dest, format!("/queue/usp.agent.{AGENT}"));
    agent
        .send(&Frame::new(
            "SUBSCRIBE",
            &[("id", "0"), ("destination", &dest), ("ack", "auto")],
        ))
        .await;
    let version = UspVersion { major: 1, minor: 3 };
    let record = |r: record::Record| {
        let mut f = Frame::new(
            "SEND",
            &[
                ("destination", "/queue/usp.controller"),
                ("content-type", USP_CONTENT_TYPE),
                ("reply-to-dest", &dest),
            ],
        );
        f.body = r.encode_to_vec().into();
        f
    };
    agent
        .send(&record(builder::stomp_connect_record(
            version, AGENT, CTRL, &dest,
        )))
        .await;

    // Answer the Controller until it reads the Agent whole (full read of a new Agent).
    let mut seen = Vec::new();
    while !seen.iter().any(|p: &String| p == "Device.") {
        let m = agent
            .next()
            .await
            .expect("the broker closed the connection");
        assert_eq!(m.command, "MESSAGE");
        assert_eq!(
            (m.header("destination"), m.header("content-type")),
            (Some(dest.as_str()), Some(USP_CONTENT_TYPE))
        );
        let rec = record::Record::decode(m.body).unwrap();
        let Some(RecordType::NoSessionContext(ns)) = rec.record_type else {
            continue;
        };
        let msg = msg::Msg::decode(ns.payload.as_slice()).unwrap();
        let id = msg.header.as_ref().unwrap().msg_id.clone();
        let Some(MsgBody::Request(req)) = msg.body.and_then(|b| b.msg_body) else {
            continue;
        };
        let req = req.req_type.unwrap();
        if let ReqType::Get(g) = &req {
            seen.extend(g.param_paths.iter().cloned());
        }
        let reply = answer(req, &id);
        agent
            .send(&record(builder::no_session_record(
                version, AGENT, CTRL, &reply,
            )))
            .await;
    }
    let device = store
        .find_usp_device(DEFAULT_TENANT, AGENT)
        .await
        .unwrap()
        .unwrap();
    let d = store.get_device(device).await.unwrap().unwrap();
    assert_eq!(
        (d.protocol.as_str(), d.software_version.as_deref()),
        ("usp", Some("3.0"))
    );
    // Agent connected to us -> address known.
    assert_eq!(d.last_remote_addr.as_deref(), Some("127.0.0.1"));
    assert!(svc.is_connected(AGENT));

    // Only the Controller destination takes Records.
    let mut wrong = record(builder::stomp_connect_record(version, AGENT, CTRL, &dest));
    wrong.headers[0].1 = "/queue/elsewhere".into();
    agent.send(&wrong).await;
    loop {
        match agent.next().await {
            Some(f) if f.command == "ERROR" => break,
            Some(_) => {}
            None => panic!("closed without an ERROR"),
        }
    }
    assert!(agent.next().await.is_none());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while svc.is_connected(AGENT) {
        assert!(tokio::time::Instant::now() < deadline, "still connected");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// USP Agent admission (CO-12) over STOMP, mode = pre-registered only.
/// Unknown -> disconnected, not registered. Pre-registered -> served.
/// Retired -> disconnected again.
#[tokio::test]
async fn usp_admission_policy() {
    use dhonomos_usp_mtp::stomp::{Frame, USP_CONTENT_TYPE};
    const AGENT: &str = "os::00AA00-ADMIT1";

    let pg = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let store = Store::connect(
        &format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            pg.get_host_port_ipv4(5432).await.unwrap()
        ),
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
            onboarding: dhonomos_core::Onboarding {
                mode: dhonomos_core::OnboardingMode::Preregistered,
                allowed_ouis: Vec::new(),
            },
            stomp: Some(dhonomos_usp_mtp::StompConfig::default()),
            mqtt_broker: None,
            metrics: None,
            files: None,
            secrets: None,
            ws_client_tls: None,
            auto_subscribe: true,
            wg_sweep_interval: dhonomos_core::DEFAULT_WG_SWEEP_INTERVAL,
            wg_incomplete_retry: dhonomos_core::DEFAULT_WG_INCOMPLETE_RETRY,
            wg_ip_poll_interval: dhonomos_core::DEFAULT_WG_IP_POLL_INTERVAL,
            wg_ip_poll_limit: dhonomos_core::DEFAULT_WG_IP_POLL_LIMIT,
            endpoint_id: CTRL.into(),
            request_timeout: Duration::from_secs(5),
            full_read_timeout: Duration::from_secs(5),
            tenant_id: DEFAULT_TENANT,
            presets: Presets::default().into(),
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let broker = svc.stomp_mtp().unwrap().clone();
    tokio::spawn(async move {
        broker
            .serve(listener, None, std::future::pending())
            .await
            .unwrap()
    });
    // Connect, subscribe, hello -> client.
    let hello = async || {
        let mut agent = StompClient::connect(addr).await;
        agent
            .send(&Frame::new(
                "STOMP",
                &[("accept-version", "1.2"), ("endpoint-id", AGENT)],
            ))
            .await;
        let dest = agent
            .next()
            .await
            .unwrap()
            .header("subscribe-dest")
            .unwrap()
            .to_owned();
        agent
            .send(&Frame::new(
                "SUBSCRIBE",
                &[("id", "0"), ("destination", &dest)],
            ))
            .await;
        let mut f = Frame::new(
            "SEND",
            &[
                ("destination", "/queue/usp.controller"),
                ("content-type", USP_CONTENT_TYPE),
            ],
        );
        f.body =
            builder::stomp_connect_record(UspVersion { major: 1, minor: 3 }, AGENT, CTRL, &dest)
                .encode_to_vec()
                .into();
        agent.send(&f).await;
        agent
    };

    // Unknown: disconnected, not registered.
    let mut agent = hello().await;
    assert!(
        agent.next().await.is_none(),
        "an unknown Agent is disconnected"
    );
    assert!(
        store
            .find_usp_device(DEFAULT_TENANT, AGENT)
            .await
            .unwrap()
            .is_none()
    );

    // Pre-registered: served (Controller reads its DeviceInfo).
    let device = store
        .preregister_usp_device(DEFAULT_TENANT, AGENT, &[])
        .await
        .unwrap()
        .id;
    let mut agent = hello().await;
    let m = agent
        .next()
        .await
        .expect("a pre-registered Agent is served");
    assert_eq!(m.command, "MESSAGE");
    drop(agent);

    // Retired: disconnected again.
    store
        .set_device_status(DEFAULT_TENANT, device, "retired")
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while svc.is_connected(AGENT) {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut agent = hello().await;
    assert!(
        agent.next().await.is_none(),
        "a retired Agent is disconnected"
    );
}

/// Agent with some Controller subscriptions (kept across reboots) -> Add only the missing one.
#[tokio::test]
async fn only_missing_subscriptions_are_added() {
    use dhonomos_usp_mtp::stomp::{Frame, USP_CONTENT_TYPE};
    const AGENT: &str = "os::00AA00-SUBS1";

    let pg = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let store = Store::connect(
        &format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            pg.get_host_port_ipv4(5432).await.unwrap()
        ),
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
            secrets: None,
            ws_client_tls: None,
            auto_subscribe: true,
            wg_sweep_interval: dhonomos_core::DEFAULT_WG_SWEEP_INTERVAL,
            wg_incomplete_retry: dhonomos_core::DEFAULT_WG_INCOMPLETE_RETRY,
            wg_ip_poll_interval: dhonomos_core::DEFAULT_WG_IP_POLL_INTERVAL,
            wg_ip_poll_limit: dhonomos_core::DEFAULT_WG_IP_POLL_LIMIT,
            endpoint_id: CTRL.into(),
            request_timeout: Duration::from_secs(5),
            full_read_timeout: Duration::from_secs(5),
            tenant_id: DEFAULT_TENANT,
            presets: Presets::default().into(),
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let broker = svc.stomp_mtp().unwrap().clone();
    tokio::spawn(async move {
        broker
            .serve(listener, None, std::future::pending())
            .await
            .unwrap()
    });
    let version = UspVersion { major: 1, minor: 3 };
    let mut agent = StompClient::connect(addr).await;
    agent
        .send(&Frame::new(
            "STOMP",
            &[("accept-version", "1.2"), ("endpoint-id", AGENT)],
        ))
        .await;
    let dest = agent
        .next()
        .await
        .unwrap()
        .header("subscribe-dest")
        .unwrap()
        .to_owned();
    agent
        .send(&Frame::new(
            "SUBSCRIBE",
            &[("id", "0"), ("destination", &dest)],
        ))
        .await;
    let record = |r: record::Record| {
        let mut f = Frame::new(
            "SEND",
            &[
                ("destination", "/queue/usp.controller"),
                ("content-type", USP_CONTENT_TYPE),
            ],
        );
        f.body = r.encode_to_vec().into();
        f
    };
    agent
        .send(&record(builder::stomp_connect_record(
            version, AGENT, CTRL, &dest,
        )))
        .await;

    // Answer until the full read. Subscription table: 2 of the 3 IDs.
    let mut added: Vec<Vec<String>> = Vec::new();
    loop {
        let m = agent
            .next()
            .await
            .expect("the broker closed the connection");
        let rec = record::Record::decode(m.body).unwrap();
        let Some(RecordType::NoSessionContext(ns)) = rec.record_type else {
            continue;
        };
        let msg = msg::Msg::decode(ns.payload.as_slice()).unwrap();
        let id = msg.header.as_ref().unwrap().msg_id.clone();
        let Some(MsgBody::Request(req)) = msg.body.and_then(|b| b.msg_body) else {
            continue;
        };
        let req = req.req_type.unwrap();
        let reply = match &req {
            ReqType::Get(g) if g.param_paths[0] == "Device.LocalAgent.Subscription." => {
                let sub = |i: u32, sid: &str| msg::get_resp::ResolvedPathResult {
                    resolved_path: format!("Device.LocalAgent.Subscription.{i}."),
                    result_params: [("ID".to_owned(), sid.to_owned())].into(),
                };
                builder::response(
                    &id,
                    RespType::GetResp(msg::GetResp {
                        req_path_results: vec![msg::get_resp::RequestedPathResult {
                            requested_path: g.param_paths[0].clone(),
                            err_code: 0,
                            err_msg: String::new(),
                            resolved_path_results: vec![
                                sub(1, "dhonomos-boot"),
                                sub(2, "dhonomos-bulkdata"),
                            ],
                        }],
                    }),
                )
            }
            ReqType::Get(g) if g.param_paths[0] == "Device." => break,
            ReqType::Add(a) => {
                added.push(
                    a.create_objs
                        .iter()
                        .flat_map(|o| &o.param_settings)
                        .filter(|p| p.param == "ID")
                        .map(|p| p.value.clone())
                        .collect(),
                );
                answer(req, &id)
            }
            _ => answer(req, &id),
        };
        agent
            .send(&record(builder::no_session_record(
                version, AGENT, CTRL, &reply,
            )))
            .await;
    }
    assert_eq!(added, vec![vec!["dhonomos-operation-complete".to_owned()]]);
}

/// PostgreSQL container, schema applied.
async fn postgres() -> (
    testcontainers_modules::testcontainers::ContainerAsync<Postgres>,
    Store,
) {
    let pg = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let store = Store::connect(
        &format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            pg.get_host_port_ipv4(5432).await.unwrap()
        ),
        4,
    )
    .await
    .unwrap();
    store.migrate().await.unwrap();
    (pg, store)
}

/// USP service, embedded STOMP broker as only transport -> listen address.
async fn stomp_service(store: &Store, auto_subscribe: bool) -> (UspService, std::net::SocketAddr) {
    stomp_service_with_presets(store, auto_subscribe, Presets::default()).await
}

/// [`stomp_service`] + provisioning presets.
async fn stomp_service_with_presets(
    store: &Store,
    auto_subscribe: bool,
    presets: Presets,
) -> (UspService, std::net::SocketAddr) {
    stomp_service_with_timeouts(
        store,
        auto_subscribe,
        presets,
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .await
}

/// [`stomp_service`] + presets + timeouts: ordinary requests, full data model reads.
async fn stomp_service_with_timeouts(
    store: &Store,
    auto_subscribe: bool,
    presets: Presets,
    request_timeout: Duration,
    full_read_timeout: Duration,
) -> (UspService, std::net::SocketAddr) {
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
            secrets: None,
            ws_client_tls: None,
            auto_subscribe,
            wg_sweep_interval: dhonomos_core::DEFAULT_WG_SWEEP_INTERVAL,
            wg_incomplete_retry: dhonomos_core::DEFAULT_WG_INCOMPLETE_RETRY,
            wg_ip_poll_interval: dhonomos_core::DEFAULT_WG_IP_POLL_INTERVAL,
            wg_ip_poll_limit: dhonomos_core::DEFAULT_WG_IP_POLL_LIMIT,
            endpoint_id: CTRL.into(),
            request_timeout,
            full_read_timeout,
            tenant_id: DEFAULT_TENANT,
            presets: presets.into(),
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let broker = svc.stomp_mtp().unwrap().clone();
    tokio::spawn(async move {
        broker
            .serve(listener, None, std::future::pending())
            .await
            .unwrap()
    });
    (svc, addr)
}

/// Pre-registered Agent: record exists before 1st connect -> no device created at 1st contact.
/// Still 1st contact (no software version until 1st DeviceInfo read)
/// -> full read + new-device presets.
/// Next connect, same firmware, subscriptions kept -> neither queued again.
#[tokio::test]
async fn a_preregistered_agent_is_read_whole_at_its_first_contact() {
    const EID: &str = "os::00AA00-PREREG1";
    let (_pg, store) = postgres().await;
    // `every-connect` queued after the full read in the connect sequence
    // -> its n-th task = decision for the n-th connection made.
    let presets = Presets::from_yaml(
        r#"
presets:
  - name: first-contact
    when: { events: ["USP CONNECT"], new_device: true }
    run:
      - kind: set_parameter_values
        payload: { values: [ { name: Device.LocalAgent.Controller.1.PeriodicNotifInterval, value: "600" } ] }
  - name: every-connect
    when: { events: ["USP CONNECT"] }
    run:
      - kind: set_parameter_values
        payload: { values: [ { name: Device.LocalAgent.Controller.1.Alias, value: "x" } ] }
"#,
    )
    .unwrap();
    let (svc, addr) = stomp_service_with_presets(&store, true, presets).await;
    let gsdm = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let device = store
        .preregister_usp_device(DEFAULT_TENANT, EID, &[])
        .await
        .unwrap();
    assert!(device.created, "pre-registration creates the record");
    let device = device.id;
    assert_eq!(
        store
            .get_device(device)
            .await
            .unwrap()
            .unwrap()
            .software_version,
        None
    );
    // Device tasks of `kind`, made by `by`.
    let queued = async |kind: &str, by: &str| {
        store
            .list_tasks(device, 100)
            .await
            .unwrap()
            .into_iter()
            .filter(|t| t.kind == kind && t.created_by.as_deref() == Some(by))
            .collect::<Vec<_>>()
    };
    let wait_for_connect_decision = async |n: usize| {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while queued("set_parameter_values", "preset:every-connect")
            .await
            .len()
            < n
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the Controller did not finish connection {n}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };

    // 1st contact: whole `Device.` tree queued + read.
    let subscriptions = SubscriptionTable::default();
    let agent =
        ScriptedAgent::spawn_with_subscriptions(addr, EID, "4.0", gsdm.clone(), &subscriptions);
    wait_for_connect_decision(1).await;
    let reads = queued("get_parameter_values", "system:bootstrap").await;
    assert_eq!(reads.len(), 1, "one full read at the first contact");
    assert_eq!(
        reads[0].payload,
        serde_json::json!({ "names": ["Device."] })
    );
    assert_eq!(
        queued("set_parameter_values", "preset:first-contact")
            .await
            .len(),
        1
    );
    wait_for("the full read to reach the Agent", || {
        agent.saw("get Device.") == 1
    })
    .await;
    let known = store.get_device(device).await.unwrap().unwrap();
    assert_eq!(known.software_version.as_deref(), Some("4.0"));
    agent.disconnect(&svc).await;

    // Same firmware again: no 1st contact, no more reads.
    let agent =
        ScriptedAgent::spawn_with_subscriptions(addr, EID, "4.0", gsdm.clone(), &subscriptions);
    wait_for_connect_decision(2).await;
    assert_eq!(
        queued("get_parameter_values", "system:bootstrap")
            .await
            .len(),
        1,
        "no second full read"
    );
    assert_eq!(
        queued("set_parameter_values", "preset:first-contact")
            .await
            .len(),
        1,
        "new-device presets apply once"
    );
    agent.disconnect(&svc).await;
}

/// Agent DeviceInfo: software version + missing identity params (full paths -> error answer).
struct Identity {
    software_version: String,
    missing: Vec<String>,
    subscriptions: SubscriptionTable,
}

/// DeviceInfo identity params, by name.
const IDENTITY_PARAMS: [&str; 7] = [
    "Manufacturer",
    "ManufacturerOUI",
    "ProductClass",
    "SerialNumber",
    "ModelName",
    "SoftwareVersion",
    "HardwareVersion",
];

impl Identity {
    /// Value of DeviceInfo param `param` (missing or not).
    fn value(&self, param: &str) -> Option<&str> {
        Some(match param {
            "Manufacturer" => "Acme",
            "ManufacturerOUI" => "00AA00",
            "ProductClass" => "WsBox",
            "SerialNumber" => "W1",
            "ModelName" => "Model-X",
            "SoftwareVersion" => self.software_version.as_str(),
            "HardwareVersion" => "HW-2",
            _ => return None,
        })
    }

    /// Identity params the Agent has, by full path.
    fn values(&self) -> std::collections::BTreeMap<String, String> {
        IDENTITY_PARAMS
            .iter()
            .map(|param| format!("Device.DeviceInfo.{param}"))
            .filter(|path| !self.missing.contains(path))
            .filter_map(|path| {
                let value = self.value(&path["Device.DeviceInfo.".len()..])?.to_owned();
                Some((path, value))
            })
            .collect()
    }
}

/// IDs in an Agent subscription table. Clones share the table.
/// Same table for all [`ScriptedAgent`]s of 1 Agent -> subscriptions kept across connections.
/// New table -> subscriptions lost (factory reset). Each added subscription is kept.
#[derive(Clone, Default)]
struct SubscriptionTable {
    ids: Arc<std::sync::Mutex<Vec<String>>>,
    /// Read of the table -> error answer.
    unreadable: bool,
}

impl SubscriptionTable {
    fn holding(ids: &[&str]) -> Self {
        Self {
            ids: Arc::new(std::sync::Mutex::new(
                ids.iter().map(|i| (*i).to_owned()).collect(),
            )),
            unreadable: false,
        }
    }

    fn unreadable() -> Self {
        Self {
            unreadable: true,
            ..Self::default()
        }
    }

    fn ids(&self) -> Vec<String> {
        self.ids.lock().unwrap().clone()
    }

    /// Agent answer to a Get of the table.
    fn reply(&self, id: &str, requested: &str) -> msg::Msg {
        if self.unreadable {
            return builder::error(
                id,
                dhonomos_usp_proto::ErrorCode::INTERNAL_ERROR,
                "the subscription table cannot be read",
            );
        }
        let rows = self
            .ids()
            .into_iter()
            .enumerate()
            .map(|(i, sid)| msg::get_resp::ResolvedPathResult {
                resolved_path: format!("{requested}{}.", i + 1),
                result_params: [("ID".to_owned(), sid)].into(),
            })
            .collect();
        builder::response(
            id,
            RespType::GetResp(msg::GetResp {
                req_path_results: vec![msg::get_resp::RequestedPathResult {
                    requested_path: requested.to_owned(),
                    err_code: 0,
                    err_msg: String::new(),
                    resolved_path_results: rows,
                }],
            }),
        )
    }

    /// Keep the subscriptions an Add creates.
    fn add(&self, a: &msg::Add) {
        let mut ids = self.ids.lock().unwrap();
        for o in a
            .create_objs
            .iter()
            .filter(|o| o.obj_path == "Device.LocalAgent.Subscription.")
        {
            for p in o.param_settings.iter().filter(|p| p.param == "ID") {
                if !ids.contains(&p.value) {
                    ids.push(p.value.clone());
                }
            }
        }
    }
}

/// Agent on the embedded STOMP broker, answers Controller requests like [`answer`], but:
/// own software version; DeviceInfo params by name -> 1 result per path;
/// object reads -> DeviceInfo identity + what it [`has`](Self::has).
/// Log: `get <path>`, `add <path>`, `gsdm`.
/// Each GetSupportedDM answer -> model with 1 param `Gen<n>`,
/// `n` = answers of all Agents sharing `gsdm`.
/// Subscription table: the given [`SubscriptionTable`], else empty at start.
/// Keeps what the Controller adds.
struct ScriptedAgent {
    eid: String,
    seen: Arc<std::sync::Mutex<Vec<String>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    task: tokio::task::JoinHandle<()>,
    /// Messages sent by the Agent on its own (notifications).
    outbox: tokio::sync::mpsc::UnboundedSender<msg::Msg>,
    /// Requests (as logged in `seen`) taken + never answered, once each.
    ignore: Arc<std::sync::Mutex<Vec<String>>>,
    /// Set -> Agent connects again, new connection replaces the old.
    reconnect: Arc<std::sync::atomic::AtomicBool>,
    /// Set -> reconnect without STOMPConnect Record.
    quiet: Arc<std::sync::atomic::AtomicBool>,
    /// Set -> Agent echoes Set values in `updated_params` (else leaves them out).
    echo_set: Arc<std::sync::atomic::AtomicBool>,
    /// Params besides DeviceInfo identity (full path, value) -> returned by object reads.
    extra: Arc<std::sync::Mutex<std::collections::BTreeMap<String, String>>>,
}

impl ScriptedAgent {
    fn spawn(
        addr: std::net::SocketAddr,
        eid: &str,
        software_version: &str,
        gsdm: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        Self::spawn_slow(addr, eid, software_version, gsdm, Vec::new())
    }

    /// [`ScriptedAgent::spawn`] + wait before answering requests logged as given entries
    /// (`get <path>`, `gsdm`): `(entry, delay)`.
    fn spawn_slow(
        addr: std::net::SocketAddr,
        eid: &str,
        software_version: &str,
        gsdm: Arc<std::sync::atomic::AtomicUsize>,
        delays: Vec<(String, Duration)>,
    ) -> Self {
        let identity = Identity {
            software_version: software_version.to_owned(),
            missing: Vec::new(),
            subscriptions: SubscriptionTable::default(),
        };
        Self::start(addr, eid, identity, gsdm, delays)
    }

    /// [`ScriptedAgent::spawn`] + given subscription table.
    fn spawn_with_subscriptions(
        addr: std::net::SocketAddr,
        eid: &str,
        software_version: &str,
        gsdm: Arc<std::sync::atomic::AtomicUsize>,
        subscriptions: &SubscriptionTable,
    ) -> Self {
        let identity = Identity {
            software_version: software_version.to_owned(),
            missing: Vec::new(),
            subscriptions: subscriptions.clone(),
        };
        Self::start(addr, eid, identity, gsdm, Vec::new())
    }

    /// [`ScriptedAgent::spawn`] + DeviceInfo params missing (full paths) -> `7026 Invalid path`.
    fn spawn_lacking(
        addr: std::net::SocketAddr,
        eid: &str,
        software_version: &str,
        gsdm: Arc<std::sync::atomic::AtomicUsize>,
        missing: &[&str],
    ) -> Self {
        let identity = Identity {
            software_version: software_version.to_owned(),
            missing: missing.iter().map(|p| (*p).to_owned()).collect(),
            subscriptions: SubscriptionTable::default(),
        };
        Self::start(addr, eid, identity, gsdm, Vec::new())
    }

    fn start(
        addr: std::net::SocketAddr,
        eid: &str,
        identity: Identity,
        gsdm: Arc<std::sync::atomic::AtomicUsize>,
        delays: Vec<(String, Duration)>,
    ) -> Self {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ignore = Arc::new(std::sync::Mutex::new(Vec::new()));
        let reconnect = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let quiet = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let echo_set = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let extra = Arc::new(std::sync::Mutex::new(Default::default()));
        let (outbox, outgoing) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(Self::run(
            addr,
            eid.to_owned(),
            identity,
            gsdm,
            delays,
            seen.clone(),
            stop.clone(),
            outgoing,
            ignore.clone(),
            reconnect.clone(),
            quiet.clone(),
            echo_set.clone(),
            extra.clone(),
        ));
        Self {
            eid: eid.to_owned(),
            seen,
            stop,
            task,
            outbox,
            ignore,
            reconnect,
            quiet,
            echo_set,
            extra,
        }
    }

    /// From now on: Agent has param `path` = `value`.
    fn has(&self, path: &str, value: &str) {
        self.extra
            .lock()
            .unwrap()
            .insert(path.to_owned(), value.to_owned());
    }

    /// Next request logged as `entry` (`get <path>`, `gsdm`) -> taken, never answered.
    /// Lost with its connection (see [`Self::reconnect`]).
    fn ignore_next(&self, entry: &str) {
        self.ignore.lock().unwrap().push(entry.to_owned());
    }

    /// Connect again, as after an address change.
    /// New connection replaces the old one; Agent drops the old one.
    fn reconnect(&self) {
        self.reconnect
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// [`Self::reconnect`] without STOMPConnect Record
    /// -> nothing the Controller could take for a connect.
    fn reconnect_quietly(&self) {
        self.quiet.store(true, std::sync::atomic::Ordering::SeqCst);
        self.reconnect();
    }

    /// From now on: echo set values in `updated_params`.
    fn echo_sets(&self) {
        self.echo_set
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Send Boot! notification (Agent restarted) with this `Cause`.
    fn boot(&self, cause: &str) {
        self.boot_with_id(&format!("boot-{cause}"), cause);
    }

    /// [`ScriptedAgent::boot`] with the Notify `msg_id`.
    /// Same ID again = Agent resends a Notify with no answer.
    fn boot_with_id(&self, msg_id: &str, cause: &str) {
        let notify = builder::request(
            msg_id,
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

    #[allow(clippy::too_many_arguments)]
    async fn run(
        addr: std::net::SocketAddr,
        eid: String,
        identity: Identity,
        gsdm: Arc<std::sync::atomic::AtomicUsize>,
        delays: Vec<(String, Duration)>,
        seen: Arc<std::sync::Mutex<Vec<String>>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        mut outgoing: tokio::sync::mpsc::UnboundedReceiver<msg::Msg>,
        ignore: Arc<std::sync::Mutex<Vec<String>>>,
        reconnect: Arc<std::sync::atomic::AtomicBool>,
        quiet: Arc<std::sync::atomic::AtomicBool>,
        echo_set: Arc<std::sync::atomic::AtomicBool>,
        extra: Arc<std::sync::Mutex<std::collections::BTreeMap<String, String>>>,
    ) {
        use dhonomos_usp_mtp::stomp::{Frame, USP_CONTENT_TYPE};
        use std::sync::atomic::Ordering::SeqCst;
        let version = UspVersion { major: 1, minor: 3 };
        let record = |r: record::Record| {
            let mut f = Frame::new(
                "SEND",
                &[
                    ("destination", "/queue/usp.controller"),
                    ("content-type", USP_CONTENT_TYPE),
                ],
            );
            f.body = r.encode_to_vec().into();
            f
        };
        // 1 connection: login, subscribe, STOMPConnect Record (unless `announce` is off).
        let connect = async |announce: bool| {
            let mut agent = StompClient::connect(addr).await;
            agent
                .send(&Frame::new(
                    "STOMP",
                    &[("accept-version", "1.2"), ("endpoint-id", &eid)],
                ))
                .await;
            let dest = agent
                .next()
                .await
                .unwrap()
                .header("subscribe-dest")
                .unwrap()
                .to_owned();
            agent
                .send(&Frame::new(
                    "SUBSCRIBE",
                    &[("id", "0"), ("destination", &dest)],
                ))
                .await;
            if announce {
                agent
                    .send(&record(builder::stomp_connect_record(
                        version, &eid, CTRL, &dest,
                    )))
                    .await;
            }
            agent
        };
        let mut agent = connect(true).await;
        while !stop.load(SeqCst) {
            if reconnect.swap(false, SeqCst) {
                // New connection replaces the old one -> unanswered requests dropped with it.
                agent = connect(!quiet.load(SeqCst)).await;
            }
            while let Ok(notification) = outgoing.try_recv() {
                agent
                    .send(&record(builder::no_session_record(
                        version,
                        &eid,
                        CTRL,
                        &notification,
                    )))
                    .await;
            }
            let Ok(next) = agent.next_within(Duration::from_millis(100)).await else {
                continue;
            };
            let Some(m) = next else { return };
            let rec = record::Record::decode(m.body).unwrap();
            let Some(RecordType::NoSessionContext(ns)) = rec.record_type else {
                continue;
            };
            let msg = msg::Msg::decode(ns.payload.as_slice()).unwrap();
            let id = msg.header.as_ref().unwrap().msg_id.clone();
            let Some(MsgBody::Request(req)) = msg.body.and_then(|b| b.msg_body) else {
                continue;
            };
            let req = req.req_type.unwrap();
            // Log entry of this request -> ignore + delay lookup.
            let entry = match &req {
                ReqType::Get(g) => Some(format!("get {}", g.param_paths.join(","))),
                ReqType::GetSupportedDm(_) => Some("gsdm".to_owned()),
                _ => None,
            };
            let ignored = entry.as_ref().is_some_and(|entry| {
                let mut ignore = ignore.lock().unwrap();
                ignore
                    .iter()
                    .position(|e| e == entry)
                    .map(|i| ignore.remove(i))
                    .is_some()
            });
            if ignored {
                seen.lock().unwrap().extend(entry);
                continue;
            }
            let delay = delays
                .iter()
                .find(|(e, _)| Some(e) == entry.as_ref())
                .map(|(_, d)| *d);
            let reply = match &req {
                ReqType::Get(g) => {
                    seen.lock()
                        .unwrap()
                        .push(format!("get {}", g.param_paths.join(",")));
                    if reads_identity(g) {
                        device_info_reply(&id, g, &identity)
                    } else if g.param_paths == ["Device.LocalAgent.Subscription."] {
                        identity.subscriptions.reply(&id, &g.param_paths[0])
                    } else {
                        let mut tree = identity.values();
                        tree.extend(extra.lock().unwrap().clone());
                        get_reply(&id, g, &tree)
                    }
                }
                ReqType::Add(a) => {
                    for o in &a.create_objs {
                        seen.lock().unwrap().push(format!("add {}", o.obj_path));
                    }
                    identity.subscriptions.add(a);
                    answer(req.clone(), &id)
                }
                ReqType::GetSupportedDm(_) => {
                    seen.lock().unwrap().push("gsdm".into());
                    let n = gsdm.fetch_add(1, SeqCst) + 1;
                    builder::response(&id, RespType::GetSupportedDmResp(supported_dm(n)))
                }
                ReqType::Set(set) if echo_set.load(SeqCst) => {
                    builder::response(&id, RespType::SetResp(echo_set_resp(set)))
                }
                _ => answer(req.clone(), &id),
            };
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            agent
                .send(&record(builder::no_session_record(
                    version, &eid, CTRL, &reply,
                )))
                .await;
        }
    }

    fn saw(&self, what: &str) -> usize {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|l| *l == what)
            .count()
    }

    /// Wait for the subscription table read.
    /// Step after the supported data model (auto subscriptions on).
    async fn until_model_step_done(&self) {
        wait_for("the Controller to reach the subscriptions", || {
            self.saw("get Device.LocalAgent.Subscription.") > 0
        })
        .await;
    }

    /// Close the connection + wait until the Controller notices.
    async fn disconnect(self, svc: &UspService) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        self.task.await.unwrap();
        wait_for("the Controller to see the disconnect", || {
            !svc.is_connected(&self.eid)
        })
        .await;
    }
}

/// SetResp: every value of `set` reported as updated.
fn echo_set_resp(set: &msg::Set) -> msg::SetResp {
    use msg::set_resp::updated_object_result::{OperationStatus, operation_status};
    msg::SetResp {
        updated_obj_results: set
            .update_objs
            .iter()
            .map(|o| msg::set_resp::UpdatedObjectResult {
                requested_path: o.obj_path.clone(),
                oper_status: Some(OperationStatus {
                    oper_status: Some(operation_status::OperStatus::OperSuccess(
                        operation_status::OperationSuccess {
                            updated_inst_results: vec![msg::set_resp::UpdatedInstanceResult {
                                affected_path: o.obj_path.clone(),
                                param_errs: vec![],
                                updated_params: o
                                    .param_settings
                                    .iter()
                                    .map(|p| (p.param.clone(), p.value.clone()))
                                    .collect(),
                            }],
                        },
                    )),
                }),
            })
            .collect(),
    }
}

/// `g` asks only for DeviceInfo params by full path.
fn reads_identity(g: &msg::Get) -> bool {
    !g.param_paths.is_empty()
        && g.param_paths
            .iter()
            .all(|p| p.starts_with("Device.DeviceInfo.") && !p.ends_with('.'))
}

/// Get of DeviceInfo params by name, answered like an Agent: 1 result per requested path,
/// param under its object. Missing (or unknown) path -> error result `7026 Invalid path`,
/// nothing resolved.
fn device_info_reply(id: &str, g: &msg::Get, identity: &Identity) -> msg::Msg {
    let value = |param: &str| identity.value(param);
    let results = g
        .param_paths
        .iter()
        .map(|path| {
            let param = path.strip_prefix("Device.DeviceInfo.").unwrap_or_default();
            match value(param).filter(|_| !identity.missing.contains(path)) {
                Some(v) => msg::get_resp::RequestedPathResult {
                    requested_path: path.clone(),
                    err_code: 0,
                    err_msg: String::new(),
                    resolved_path_results: vec![msg::get_resp::ResolvedPathResult {
                        resolved_path: "Device.DeviceInfo.".into(),
                        result_params: [(param.to_owned(), v.to_owned())].into(),
                    }],
                },
                None => msg::get_resp::RequestedPathResult {
                    requested_path: path.clone(),
                    err_code: 7026,
                    err_msg: "Invalid path".into(),
                    resolved_path_results: Vec::new(),
                },
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

/// Supported data model: 1 object, 1 param `Gen<n>`.
fn supported_dm(n: usize) -> msg::GetSupportedDmResp {
    use msg::get_supported_dm_resp as g;
    msg::GetSupportedDmResp {
        req_obj_results: vec![g::RequestedObjectResult {
            req_obj_path: "Device.".into(),
            supported_objs: vec![g::SupportedObjectResult {
                supported_obj_path: "Device.".into(),
                access: g::ObjAccessType::ObjReadOnly as i32,
                supported_params: vec![g::SupportedParamResult {
                    param_name: format!("Gen{n}"),
                    access: g::ParamAccessType::ParamReadOnly as i32,
                    value_type: g::ParamValueType::ParamString as i32,
                    value_change: g::ValueChangeType::ValueChangeAllowed as i32,
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

/// Poll `cond` up to 15 s.
async fn wait_for(what: &str, cond: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !cond() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Stored `Gen<n>` model of the device -> (name of its 1 param, row ID, fingerprint).
async fn stored_model(store: &Store, device: uuid::Uuid) -> Option<(String, uuid::Uuid, String)> {
    let m = store.device_supported_model(device).await.unwrap()?;
    let gen_name = m.model["objects"][0]["params"][0]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    Some((gen_name, m.id, m.fingerprint))
}

/// Unknown software version -> device not told apart from other builds of the model
/// -> supported data model read at every connection, kept for this device only.
/// Known software version -> 1 shared model per firmware.
#[tokio::test]
async fn models_of_unknown_firmware_are_fetched_every_time_and_not_shared() {
    use std::sync::atomic::Ordering::SeqCst;
    let (_pg, store) = postgres().await;
    let (svc, addr) = stomp_service(&store, true).await;
    let gsdm = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let device = async |eid: &str| {
        store
            .find_usp_device(DEFAULT_TENANT, eid)
            .await
            .unwrap()
            .unwrap()
    };

    // Unknown version: model read, kept for this device only.
    let a = ScriptedAgent::spawn(addr, "os::00AA00-UNK1", "", gsdm.clone());
    a.until_model_step_done().await;
    assert_eq!(gsdm.load(SeqCst), 1);
    let unk1 = device("os::00AA00-UNK1").await;
    let (gen_name, row, fingerprint) = stored_model(&store, unk1).await.unwrap();
    assert_eq!(gen_name, "Gen1");
    assert_eq!(fingerprint, dhonomos_store::device_fingerprint(unk1));
    a.disconnect(&svc).await;

    // Each connection asks again -> device model replaced in place.
    let a = ScriptedAgent::spawn(addr, "os::00AA00-UNK1", "", gsdm.clone());
    a.until_model_step_done().await;
    assert_eq!(gsdm.load(SeqCst), 2);
    let (gen_name, again, _) = stored_model(&store, unk1).await.unwrap();
    assert_eq!((gen_name.as_str(), again), ("Gen2", row));
    a.disconnect(&svc).await;

    // Other device, same model, unknown version -> own model.
    let b = ScriptedAgent::spawn(addr, "os::00AA00-UNK2", "", gsdm.clone());
    b.until_model_step_done().await;
    assert_eq!(gsdm.load(SeqCst), 3);
    let unk2 = device("os::00AA00-UNK2").await;
    let (gen_name, other, fingerprint) = stored_model(&store, unk2).await.unwrap();
    assert_eq!(gen_name, "Gen3");
    assert_ne!(other, row);
    assert_eq!(fingerprint, dhonomos_store::device_fingerprint(unk2));
    b.disconnect(&svc).await;

    // Known version: read once per firmware, then shared + reused.
    let c = ScriptedAgent::spawn(addr, "os::00AA00-KNOWN1", "7.0", gsdm.clone());
    c.until_model_step_done().await;
    assert_eq!(gsdm.load(SeqCst), 4);
    let known1 = device("os::00AA00-KNOWN1").await;
    let (gen_name, shared, fingerprint) = stored_model(&store, known1).await.unwrap();
    assert_eq!(gen_name, "Gen4");
    assert_eq!(
        fingerprint,
        dhonomos_core::usp::firmware_fingerprint(&store.get_device(known1).await.unwrap().unwrap())
            .unwrap()
    );
    c.disconnect(&svc).await;
    for eid in ["os::00AA00-KNOWN1", "os::00AA00-KNOWN2"] {
        let agent = ScriptedAgent::spawn(addr, eid, "7.0", gsdm.clone());
        agent.until_model_step_done().await;
        assert_eq!(gsdm.load(SeqCst), 4, "{eid} reuses the cached model");
        agent.disconnect(&svc).await;
    }
    let known2 = device("os::00AA00-KNOWN2").await;
    assert_eq!(
        stored_model(&store, known2).await.map(|m| m.1),
        Some(shared)
    );
}

/// Operator "refresh data model": connected Agent -> asked again, model replaced in place
/// (same-firmware devices see it). Offline Agent -> cached model deleted, read at next connect.
#[tokio::test]
async fn refreshing_the_data_model_reads_the_agent_again() {
    use dhonomos_core::usp::DataModelRefresh;
    use std::sync::atomic::Ordering::SeqCst;
    const AGENT: &str = "os::00AA00-REFRESH1";
    const SIBLING: &str = "os::00AA00-REFRESH2";
    let (_pg, store) = postgres().await;
    let (svc, addr) = stomp_service(&store, true).await;
    let gsdm = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let agent = ScriptedAgent::spawn(addr, AGENT, "7.0", gsdm.clone());
    agent.until_model_step_done().await;
    let sibling = ScriptedAgent::spawn(addr, SIBLING, "7.0", gsdm.clone());
    sibling.until_model_step_done().await;
    assert_eq!(
        gsdm.load(SeqCst),
        1,
        "the sibling shares the firmware's model"
    );
    let id = store
        .find_usp_device(DEFAULT_TENANT, AGENT)
        .await
        .unwrap()
        .unwrap();
    let sibling_id = store
        .find_usp_device(DEFAULT_TENANT, SIBLING)
        .await
        .unwrap()
        .unwrap();
    let device = store.get_device(id).await.unwrap().unwrap();
    let fingerprint = dhonomos_core::usp::firmware_fingerprint(&device).unwrap();
    let (gen_name, row, _) = stored_model(&store, id).await.unwrap();
    assert_eq!(gen_name, "Gen1");

    // Connected: read now, model replaced in place, sibling sees it too.
    assert_eq!(
        svc.refresh_data_model(&device).await.unwrap(),
        DataModelRefresh::Refreshing
    );
    let sibling_sees = async || stored_model(&store, sibling_id).await.map(|m| m.0);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while sibling_sees().await.as_deref() != Some("Gen2") {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the model was not read again"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        stored_model(&store, id).await.map(|m| (m.0, m.1)),
        Some(("Gen2".into(), row))
    );

    // Offline: cached model deleted now -> devices of the firmware have none until
    // their Agents connect.
    agent.disconnect(&svc).await;
    assert_eq!(
        svc.refresh_data_model(&device).await.unwrap(),
        DataModelRefresh::Queued
    );
    assert_eq!(store.supported_model_id(&fingerprint).await.unwrap(), None);
    assert!(stored_model(&store, id).await.is_none());
    assert!(stored_model(&store, sibling_id).await.is_none());
    assert_eq!(gsdm.load(SeqCst), 2);

    // Next connection reads it.
    let agent = ScriptedAgent::spawn(addr, AGENT, "7.0", gsdm.clone());
    agent.until_model_step_done().await;
    assert_eq!(gsdm.load(SeqCst), 3);
    let (gen_name, _, found) = stored_model(&store, id).await.unwrap();
    assert_eq!((gen_name.as_str(), found), ("Gen3", fingerprint));
    agent.disconnect(&svc).await;
    sibling.disconnect(&svc).await;
}

/// `auto_subscribe: false` -> Controller writes no subscriptions into the Agent:
/// nothing added, table not even read.
#[tokio::test]
async fn no_subscriptions_are_added_when_automatic_ones_are_off() {
    let (_pg, store) = postgres().await;
    let gsdm = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (on, on_addr) = stomp_service(&store, true).await;
    let (off, off_addr) = stomp_service(&store, false).await;

    // Same Agent behaviour on both Controllers.
    // Different versions -> neither uses the other's cached model.
    // New Agent -> full read at the end.
    let with = ScriptedAgent::spawn(on_addr, "os::00AA00-SUBS-ON", "1.0", gsdm.clone());
    let without = ScriptedAgent::spawn(off_addr, "os::00AA00-SUBS-OFF", "1.1", gsdm.clone());
    wait_for("the full reads", || {
        with.saw("get Device.") > 0 && without.saw("get Device.") > 0
    })
    .await;
    let log = |a: &ScriptedAgent| a.seen.lock().unwrap().clone();
    let subs = |l: &[String]| {
        l.iter()
            .filter(|x| x.contains("LocalAgent.Subscription."))
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        subs(&log(&with)),
        [
            "get Device.LocalAgent.Subscription.",
            "add Device.LocalAgent.Subscription.",
            "add Device.LocalAgent.Subscription.",
            "add Device.LocalAgent.Subscription.",
        ],
        "control: the default adds the three subscriptions"
    );
    assert_eq!(
        subs(&log(&without)),
        Vec::<String>::new(),
        "{:?}",
        log(&without)
    );
    // Rest of the connect sequence = same.
    assert!(log(&without).contains(&IDENTITY_GET.to_owned()));
    assert!(log(&without).contains(&"gsdm".to_owned()));
    with.disconnect(&on).await;
    without.disconnect(&off).await;
}

/// Preset: 1 task per connection, queued after the full-read decision of the connect sequence
/// -> its n-th task = decision for the n-th connection made.
const EVERY_CONNECT: &str = r#"
presets:
  - name: every-connect
    when: { events: ["USP CONNECT"] }
    run:
      - kind: set_parameter_values
        payload: { values: [ { name: Device.LocalAgent.Controller.1.Alias, value: "x" } ] }
"#;

/// Poll `cond` up to 15 s.
async fn wait_until(what: &str, cond: impl AsyncFn() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !cond().await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Device the Controller registers for Agent `eid` (waits up to 15 s).
async fn registered(store: &Store, eid: &str) -> uuid::Uuid {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(id) = store.find_usp_device(DEFAULT_TENANT, eid).await.unwrap() {
            return id;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{eid} was not registered"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Wait for the full-read decision at the `n`-th connection of the device
/// (see [`EVERY_CONNECT`]).
async fn connection_decided(store: &Store, device: uuid::Uuid, n: usize) {
    wait_until("the Controller to finish the connection", async || {
        tasks_of(
            store,
            device,
            "set_parameter_values",
            "preset:every-connect",
        )
        .await
            >= n
    })
    .await;
}

/// Count of device tasks of `kind`, made by `by`.
async fn tasks_of(store: &Store, device: uuid::Uuid, kind: &str, by: &str) -> usize {
    store
        .list_tasks(device, 100)
        .await
        .unwrap()
        .into_iter()
        .filter(|t| t.kind == kind && t.created_by.as_deref() == Some(by))
        .count()
}

/// Count of full `Device.` reads the Controller queued on its own.
async fn full_reads(store: &Store, device: uuid::Uuid) -> usize {
    tasks_of(store, device, "get_parameter_values", "system:bootstrap").await
}

/// Task with idempotency `key` exists.
async fn has_task_key(store: &Store, key: &str) -> bool {
    !store
        .existing_idempotency_keys(DEFAULT_TENANT, &[key.to_owned()])
        .await
        .unwrap()
        .is_empty()
}

/// Idempotency key of the full read for an Agent that lost its state today (UTC).
fn state_lost_key(device: uuid::Uuid) -> String {
    format!(
        "usp-full-read:{device}:state-lost:{}",
        time::OffsetDateTime::now_utc().date()
    )
}

/// Event details of `kind` for the device, latest first.
async fn events_of(store: &Store, device: uuid::Uuid, kind: &str) -> Vec<serde_json::Value> {
    store
        .list_events(device, 100)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == kind)
        .map(|e| e.detail)
        .collect()
}

/// `usp_state_lost` event details of the device, latest first.
async fn lost_state_events(store: &Store, device: uuid::Uuid) -> Vec<serde_json::Value> {
    events_of(store, device, "usp_state_lost").await
}

/// Factory reset -> Controller subscriptions gone.
/// No `dhonomos-boot` -> not even its Boot! event reaches the Controller.
/// Known Agent + same firmware + no such subscription -> full read (ADR-107), max 1/day.
/// New Agent -> full read by firmware version alone, though it lacks the subscription too.
/// Agent with the subscription -> no new read.
#[tokio::test]
async fn an_agent_that_lost_the_controllers_subscriptions_is_read_whole_once_a_day() {
    const EID: &str = "os::00AA00-LOST1";
    let (_pg, store) = postgres().await;
    let presets = Presets::from_yaml(EVERY_CONNECT).unwrap();
    let (svc, addr) = stomp_service_with_presets(&store, true, presets).await;
    let gsdm = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // 1st contact: read for the firmware version only, though the new Agent
    // lacks the subscription (Controller adds it).
    let kept = SubscriptionTable::default();
    let agent = ScriptedAgent::spawn_with_subscriptions(addr, EID, "5.0", gsdm.clone(), &kept);
    let device = registered(&store, EID).await;
    connection_decided(&store, device, 1).await;
    assert_eq!(agent.saw("get Device.LocalAgent.Subscription."), 1);
    assert_eq!(full_reads(&store, device).await, 1);
    assert!(has_task_key(&store, &format!("usp-full-read:{device}:5.0")).await);
    assert!(!has_task_key(&store, &state_lost_key(device)).await);
    assert!(lost_state_events(&store, device).await.is_empty());
    assert!(kept.ids().contains(&"dhonomos-boot".to_owned()));
    wait_for("the full read to reach the Agent", || {
        agent.saw("get Device.") == 1
    })
    .await;
    agent.disconnect(&svc).await;

    // Reconnect with the subscription -> no read.
    let agent = ScriptedAgent::spawn_with_subscriptions(addr, EID, "5.0", gsdm.clone(), &kept);
    connection_decided(&store, device, 2).await;
    assert_eq!(agent.saw("get Device.LocalAgent.Subscription."), 1);
    assert_eq!(full_reads(&store, device).await, 1);
    assert!(!has_task_key(&store, &state_lost_key(device)).await);
    assert!(lost_state_events(&store, device).await.is_empty());
    agent.disconnect(&svc).await;

    // Factory reset: same firmware back, table with only its own subscriptions
    // -> full read, event says why.
    let reset = SubscriptionTable::holding(&["vendor-1"]);
    let agent = ScriptedAgent::spawn_with_subscriptions(addr, EID, "5.0", gsdm.clone(), &reset);
    connection_decided(&store, device, 3).await;
    assert_eq!(full_reads(&store, device).await, 2);
    assert!(has_task_key(&store, &state_lost_key(device)).await);
    assert_eq!(
        lost_state_events(&store, device).await,
        [serde_json::json!({ "reason": "subscriptions_missing" })]
    );
    wait_for("the full read to reach the Agent", || {
        agent.saw("get Device.") == 1
    })
    .await;
    // Controller added its subscriptions anyway.
    assert!(reset.ids().contains(&"dhonomos-boot".to_owned()));
    assert!(reset.ids().contains(&"vendor-1".to_owned()));
    agent.disconnect(&svc).await;

    // Later same day, again without them (lost at each restart) -> no 2nd read.
    let forgetful = SubscriptionTable::holding(&[]);
    let agent = ScriptedAgent::spawn_with_subscriptions(addr, EID, "5.0", gsdm.clone(), &forgetful);
    connection_decided(&store, device, 4).await;
    assert_eq!(agent.saw("get Device.LocalAgent.Subscription."), 1);
    assert_eq!(full_reads(&store, device).await, 2, "read once a day");
    agent.disconnect(&svc).await;
}

/// Subscription table not readable -> loss unknown -> no full read for that.
#[tokio::test]
async fn an_unreadable_subscription_table_is_not_taken_for_a_lost_state() {
    const EID: &str = "os::00AA00-LOST2";
    let (_pg, store) = postgres().await;
    let presets = Presets::from_yaml(EVERY_CONNECT).unwrap();
    let (svc, addr) = stomp_service_with_presets(&store, true, presets).await;
    let gsdm = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let agent = ScriptedAgent::spawn(addr, EID, "5.0", gsdm.clone());
    let device = registered(&store, EID).await;
    connection_decided(&store, device, 1).await;
    agent.disconnect(&svc).await;
    assert_eq!(full_reads(&store, device).await, 1);

    // Known, same firmware, table answers with an error.
    let agent = ScriptedAgent::spawn_with_subscriptions(
        addr,
        EID,
        "5.0",
        gsdm.clone(),
        &SubscriptionTable::unreadable(),
    );
    connection_decided(&store, device, 2).await;
    assert_eq!(agent.saw("get Device.LocalAgent.Subscription."), 1);
    assert_eq!(full_reads(&store, device).await, 1);
    assert!(!has_task_key(&store, &state_lost_key(device)).await);
    assert!(lost_state_events(&store, device).await.is_empty());
    agent.disconnect(&svc).await;
}

/// Auto subscriptions off -> table not read -> lost subscriptions not seen -> no read.
#[tokio::test]
async fn a_lost_state_is_not_looked_for_when_automatic_subscriptions_are_off() {
    const EID: &str = "os::00AA00-LOST3";
    let (_pg, store) = postgres().await;
    let presets = Presets::from_yaml(EVERY_CONNECT).unwrap();
    let (svc, addr) = stomp_service_with_presets(&store, false, presets).await;
    let gsdm = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let agent = ScriptedAgent::spawn(addr, EID, "5.0", gsdm.clone());
    let device = registered(&store, EID).await;
    connection_decided(&store, device, 1).await;
    agent.disconnect(&svc).await;
    assert_eq!(full_reads(&store, device).await, 1);

    let agent = ScriptedAgent::spawn_with_subscriptions(
        addr,
        EID,
        "5.0",
        gsdm.clone(),
        &SubscriptionTable::holding(&["vendor-1"]),
    );
    connection_decided(&store, device, 2).await;
    assert_eq!(agent.saw("get Device.LocalAgent.Subscription."), 0);
    assert_eq!(full_reads(&store, device).await, 1);
    assert!(!has_task_key(&store, &state_lost_key(device)).await);
    assert!(lost_state_events(&store, device).await.is_empty());
    agent.disconnect(&svc).await;
}

/// Boot! with `Cause` = factory reset -> full read (ADR-107); other causes -> none.
/// Read queued before the drain -> same drain sends it.
/// Same 1/day read as for a missing subscription.
#[tokio::test]
async fn a_boot_after_a_factory_reset_reads_the_agent_whole() {
    const EID: &str = "os::00AA00-LOST4";
    let (_pg, store) = postgres().await;
    let presets = Presets::from_yaml(EVERY_CONNECT).unwrap();
    let (svc, addr) = stomp_service_with_presets(&store, true, presets).await;
    let gsdm = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let agent = ScriptedAgent::spawn(addr, EID, "5.0", gsdm.clone());
    let device = registered(&store, EID).await;
    connection_decided(&store, device, 1).await;
    wait_for("the full read of the new Agent", || {
        agent.saw("get Device.") == 1
    })
    .await;
    assert_eq!(full_reads(&store, device).await, 1);

    // Ordinary restart: Boot! recorded, no read.
    agent.boot("LocalReboot");
    wait_until("the Boot! to be recorded", async || {
        events_of(&store, device, "usp_event").await.len() == 1
    })
    .await;
    assert_eq!(full_reads(&store, device).await, 1);
    assert!(!has_task_key(&store, &state_lost_key(device)).await);
    assert!(lost_state_events(&store, device).await.is_empty());

    // Factory reset: full read, in the drain the Boot! starts.
    agent.boot("RemoteFactoryReset");
    wait_until("the state-lost event", async || {
        lost_state_events(&store, device).await.len() == 1
    })
    .await;
    assert_eq!(
        lost_state_events(&store, device).await,
        [serde_json::json!({ "reason": "boot_cause", "cause": "RemoteFactoryReset" })]
    );
    assert!(has_task_key(&store, &state_lost_key(device)).await);
    assert_eq!(full_reads(&store, device).await, 2);
    wait_for("the full read to reach the Agent", || {
        agent.saw("get Device.") == 2
    })
    .await;

    // Another one same day: recorded, read = same task.
    agent.boot("LocalFactoryReset");
    wait_until("the second state-lost event", async || {
        lost_state_events(&store, device).await.len() == 2
    })
    .await;
    assert_eq!(
        lost_state_events(&store, device).await[0],
        serde_json::json!({ "reason": "boot_cause", "cause": "LocalFactoryReset" })
    );
    assert_eq!(full_reads(&store, device).await, 2, "read once a day");
    agent.disconnect(&svc).await;
}

/// Count of firmware image reads queued at a Boot! (ADR-108).
async fn boot_image_reads(store: &Store, device: uuid::Uuid) -> usize {
    tasks_of(store, device, "get_parameter_values", "system:boot").await
}

/// Wait until all device tasks are done.
async fn queue_idle(store: &Store, device: uuid::Uuid) {
    wait_until("the queue to be drained", async || {
        store
            .list_tasks(device, 100)
            .await
            .unwrap()
            .iter()
            .all(|t| t.state == TaskState::Succeeded)
    })
    .await;
}

/// Boot! -> Controller reads the Agent firmware images again (ADR-108).
/// Why: fallback to the other image after a failed boot changes neither firmware version
/// nor `FirmwareUpdated`. Only Agents with the object in stored params are read (else fail
/// at each boot). Resent Boot! -> 1 read. Next boot -> read again.
#[tokio::test]
async fn a_boot_reads_the_firmware_images_again() {
    const EID: &str = "os::00AA00-FWIMG1";
    const IMAGES: &str = "get Device.DeviceInfo.FirmwareImage.";
    let (_pg, store) = postgres().await;
    let presets = Presets::from_yaml(EVERY_CONNECT).unwrap();
    let (svc, addr) = stomp_service_with_presets(&store, true, presets).await;
    let gsdm = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let agent = ScriptedAgent::spawn(addr, EID, "5.0", gsdm.clone());
    let device = registered(&store, EID).await;
    connection_decided(&store, device, 1).await;
    wait_for("the full read of the new Agent", || {
        agent.saw("get Device.") == 1
    })
    .await;
    queue_idle(&store, device).await;

    // Full read did not see the object -> nothing to read at boot.
    agent.boot_with_id("boot-a", "LocalReboot");
    wait_until("the Boot! to be recorded", async || {
        events_of(&store, device, "usp_event").await.len() == 1
    })
    .await;
    assert_eq!(boot_image_reads(&store, device).await, 0);
    assert_eq!(agent.saw(IMAGES), 0);

    // Now it has (as after a full read of an Agent with the object).
    agent.has("Device.DeviceInfo.FirmwareImage.1.Version", "5.0");
    store
        .upsert_params(
            device,
            &[dhonomos_store::ParamUpdate {
                path: "Device.DeviceInfo.FirmwareImage.1.Version".into(),
                value: Some("5.0".into()),
                ..Default::default()
            }],
        )
        .await
        .unwrap();
    agent.boot_with_id("boot-b", "LocalReboot");
    wait_until("the second Boot! to be recorded", async || {
        events_of(&store, device, "usp_event").await.len() == 2
    })
    .await;
    assert_eq!(boot_image_reads(&store, device).await, 1);
    assert!(has_task_key(&store, &format!("boot-fwimage:{device}:boot-b")).await);
    wait_for("the read to reach the Agent", || agent.saw(IMAGES) == 1).await;
    queue_idle(&store, device).await;

    // Agent resends the same Notify -> same boot, 1 read.
    agent.boot_with_id("boot-b", "LocalReboot");
    wait_until("the resent Boot! to be recorded", async || {
        events_of(&store, device, "usp_event").await.len() == 3
    })
    .await;
    assert_eq!(boot_image_reads(&store, device).await, 1);
    assert_eq!(agent.saw(IMAGES), 1);

    // Next boot = another boot.
    agent.boot_with_id("boot-c", "LocalReboot");
    wait_until("the third boot to be read", async || {
        boot_image_reads(&store, device).await == 2
    })
    .await;
    wait_for("the second read to reach the Agent", || {
        agent.saw(IMAGES) == 2
    })
    .await;
    agent.disconnect(&svc).await;
}

/// No separate firmware image read at a boot with a full read -> images part of the full read.
/// Cases: full read waiting in the queue (operator refresh or connect sequence),
/// boot = factory reset. Full read already run -> next boot still read.
#[tokio::test]
async fn a_boot_followed_by_a_full_read_does_not_read_the_firmware_images_alone() {
    const EID: &str = "os::00AA00-FWIMG2";
    const IMAGES: &str = "get Device.DeviceInfo.FirmwareImage.";
    let (_pg, store) = postgres().await;
    let presets = Presets::from_yaml(EVERY_CONNECT).unwrap();
    let (svc, addr) = stomp_service_with_presets(&store, true, presets).await;
    let gsdm = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let agent = ScriptedAgent::spawn(addr, EID, "5.0", gsdm.clone());
    let device = registered(&store, EID).await;
    connection_decided(&store, device, 1).await;
    wait_for("the full read of the new Agent", || {
        agent.saw("get Device.") == 1
    })
    .await;
    queue_idle(&store, device).await;
    agent.has("Device.DeviceInfo.FirmwareImage.1.Version", "5.0");
    store
        .upsert_params(
            device,
            &[dhonomos_store::ParamUpdate {
                path: "Device.DeviceInfo.FirmwareImage.1.Version".into(),
                value: Some("5.0".into()),
                ..Default::default()
            }],
        )
        .await
        .unwrap();
    let boots = async || events_of(&store, device, "usp_event").await.len();

    // Full read waits in the queue (no drain until the Boot!).
    let (kind, payload) = TaskKind::GetParameterValues {
        names: vec!["Device.".into()],
    }
    .to_row();
    store
        .enqueue_task(&NewTask {
            created_by: Some("api".into()),
            ..NewTask::new(DEFAULT_TENANT, device, kind, payload)
        })
        .await
        .unwrap();
    agent.boot_with_id("boot-a", "LocalReboot");
    wait_until("the Boot! to be recorded", async || boots().await == 1).await;
    assert_eq!(boot_image_reads(&store, device).await, 0);
    wait_for("the waiting full read to reach the Agent", || {
        agent.saw("get Device.") == 2
    })
    .await;
    queue_idle(&store, device).await;
    assert_eq!(agent.saw(IMAGES), 0);

    // Factory reset: Boot! queues the full read -> images included.
    agent.boot_with_id("boot-b", "LocalFactoryReset");
    wait_until("the state-lost event", async || {
        lost_state_events(&store, device).await.len() == 1
    })
    .await;
    wait_until("the second Boot! to be recorded", async || {
        boots().await == 2
    })
    .await;
    assert_eq!(boot_image_reads(&store, device).await, 0);
    wait_for("the full read to reach the Agent", || {
        agent.saw("get Device.") == 3
    })
    .await;
    queue_idle(&store, device).await;
    assert_eq!(agent.saw(IMAGES), 0);

    // Both reads done; ordinary boot after them -> read again.
    agent.boot_with_id("boot-c", "LocalReboot");
    wait_for("the read of the images to reach the Agent", || {
        agent.saw(IMAGES) == 1
    })
    .await;
    assert_eq!(boot_image_reads(&store, device).await, 1);
    agent.disconnect(&svc).await;
}

/// Controller read at every connection (pay-per-byte links) = Agent identity:
/// 7 DeviceInfo params by name. Object itself (real Agent: 32 KiB log, 1000s of process
/// params, direct params + descendants not kept out by `max_depth`) -> only in the full read.
#[tokio::test]
async fn connecting_reads_the_identity_parameters_and_not_the_whole_of_device_info() {
    const EID: &str = "os::00AA00-IDENT1";
    let (_pg, store) = postgres().await;
    let (svc, addr) = stomp_service(&store, true).await;
    let agent = ScriptedAgent::spawn(
        addr,
        EID,
        "9.0",
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    );
    wait_for("the full read of the new Agent", || {
        agent.saw("get Device.") > 0
    })
    .await;

    // 1 DeviceInfo read: exactly the 7 params, each by full path.
    let log = agent.seen.lock().unwrap().clone();
    let device_info: Vec<_> = log
        .iter()
        .filter(|l| l.starts_with("get Device.DeviceInfo."))
        .collect();
    assert_eq!(device_info, [IDENTITY_GET], "{log:?}");
    let paths: Vec<_> = IDENTITY_GET["get ".len()..].split(',').collect();
    assert_eq!(paths.len(), 7);
    assert!(
        paths.iter().all(|p| !p.ends_with('.')),
        "no object among the paths: {paths:?}"
    );

    // Registry entry + stored params filled.
    let device = store
        .find_usp_device(DEFAULT_TENANT, EID)
        .await
        .unwrap()
        .unwrap();
    let d = store.get_device(device).await.unwrap().unwrap();
    assert_eq!(
        (
            d.manufacturer.as_deref(),
            d.oui.as_deref(),
            d.product_class.as_str(),
            d.serial_number.as_deref(),
            d.model_name.as_deref(),
            d.software_version.as_deref(),
            d.hardware_version.as_deref(),
        ),
        (
            Some("Acme"),
            Some("00AA00"),
            "WsBox",
            Some("W1"),
            Some("Model-X"),
            Some("9.0"),
            Some("HW-2"),
        )
    );
    let stored = store
        .get_param_values(
            device,
            &[
                "Device.DeviceInfo.ModelName".to_owned(),
                "Device.DeviceInfo.HardwareVersion".to_owned(),
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        stored.get("Device.DeviceInfo.ModelName"),
        Some(&Some("Model-X".to_owned()))
    );
    assert_eq!(
        stored.get("Device.DeviceInfo.HardwareVersion"),
        Some(&Some("HW-2".to_owned()))
    );
    agent.disconnect(&svc).await;
}

/// Agent missing an identity param -> error (7026) for that path; registered from the others.
/// None of them -> still served.
#[tokio::test]
async fn an_agent_lacking_identity_parameters_is_registered_from_the_others() {
    const IDENTITY: [&str; 7] = [
        "Manufacturer",
        "ManufacturerOUI",
        "ProductClass",
        "SerialNumber",
        "ModelName",
        "SoftwareVersion",
        "HardwareVersion",
    ];
    let (_pg, store) = postgres().await;
    let (svc, addr) = stomp_service(&store, true).await;
    let gsdm = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let path = |name: &str| format!("Device.DeviceInfo.{name}");

    // No HardwareVersion: other 6 applied.
    const SOME: &str = "os::00AA00-IDENT-SOME";
    let agent = ScriptedAgent::spawn_lacking(
        addr,
        SOME,
        "9.1",
        gsdm.clone(),
        &["Device.DeviceInfo.HardwareVersion"],
    );
    agent.until_model_step_done().await;
    assert_eq!(agent.saw(IDENTITY_GET), 1);
    let device = store
        .find_usp_device(DEFAULT_TENANT, SOME)
        .await
        .unwrap()
        .unwrap();
    let d = store.get_device(device).await.unwrap().unwrap();
    assert_eq!(
        (
            d.manufacturer.as_deref(),
            d.oui.as_deref(),
            d.product_class.as_str(),
            d.serial_number.as_deref(),
            d.model_name.as_deref(),
            d.software_version.as_deref(),
            d.hardware_version.as_deref(),
        ),
        (
            Some("Acme"),
            Some("00AA00"),
            "WsBox",
            Some("W1"),
            Some("Model-X"),
            Some("9.1"),
            None,
        )
    );
    let paths: Vec<String> = IDENTITY.iter().map(|n| path(n)).collect();
    let stored = store.get_param_values(device, &paths).await.unwrap();
    for name in &IDENTITY[..6] {
        assert!(
            stored.get(&path(name)).is_some_and(Option::is_some),
            "{name} is stored: {stored:?}"
        );
    }
    assert_eq!(
        stored.get(&path("ModelName")),
        Some(&Some("Model-X".to_owned()))
    );
    assert!(
        !stored.contains_key(&path("HardwareVersion")),
        "an error result stores nothing: {stored:?}"
    );
    agent.disconnect(&svc).await;

    // None of them: nothing to fill in, Agent still registered + served.
    const NONE: &str = "os::00AA00-IDENT-NONE";
    let all: Vec<String> = IDENTITY.iter().map(|n| path(n)).collect();
    let all: Vec<&str> = all.iter().map(String::as_str).collect();
    let agent = ScriptedAgent::spawn_lacking(addr, NONE, "9.2", gsdm, &all);
    agent.until_model_step_done().await;
    let device = store
        .find_usp_device(DEFAULT_TENANT, NONE)
        .await
        .unwrap()
        .unwrap();
    let d = store.get_device(device).await.unwrap().unwrap();
    assert_eq!(
        (d.manufacturer, d.serial_number, d.software_version),
        (None, None, None)
    );
    assert!(svc.is_connected(NONE));
    agent.disconnect(&svc).await;
}

/// Slow Agent (busy right after boot): whole data model answer takes longer than request timeout
/// -> Controller waits up to the full-read timeout: full read of a new Agent + GetSupportedDM.
/// Ordinary request -> still gives up at request timeout, late answer dropped.
#[tokio::test]
async fn a_slow_agent_gets_the_full_read_timeout_for_reads_of_the_whole_model_only() {
    use std::sync::atomic::AtomicUsize;
    const EID: &str = "os::00AA00-SLOW1";
    const SLOW: Duration = Duration::from_secs(3);
    let (_pg, store) = postgres().await;
    // Ordinary requests wait 1 s, whole model reads 15 s; Agent takes 3 s for its slow ones.
    let (svc, addr) = stomp_service_with_timeouts(
        &store,
        true,
        Presets::default(),
        Duration::from_secs(1),
        Duration::from_secs(15),
    )
    .await;
    let agent = ScriptedAgent::spawn_slow(
        addr,
        EID,
        "6.0",
        Arc::new(AtomicUsize::new(0)),
        ["get Device.", "gsdm", "get Device.Slow."]
            .map(|entry| (entry.to_owned(), SLOW))
            .into(),
    );

    // Full read of the new Agent answered after 3 s -> kept.
    let device = loop {
        if let Some(id) = store.find_usp_device(DEFAULT_TENANT, EID).await.unwrap() {
            break id;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let state_of = async |kind: &str, by: Option<&str>| {
        store
            .list_tasks(device, 100)
            .await
            .unwrap()
            .into_iter()
            .find(|t| t.kind == kind && t.created_by.as_deref() == by)
            .map(|t| t.state)
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while state_of("get_parameter_values", Some("system:bootstrap")).await
        != Some(TaskState::Succeeded)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the slow full read did not complete: {:?} {:?}",
            state_of("get_parameter_values", Some("system:bootstrap")).await,
            agent.seen.lock().unwrap()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Supported data model came the same way.
    assert!(stored_model(&store, device).await.is_some());
    assert_eq!(agent.saw("gsdm"), 1);

    // Ordinary Get answered after 3 s -> given up after 1 s; late answer changes nothing.
    // (With the long timeout it would succeed at 3 s.)
    let (kind, payload) = dhonomos_core::TaskKind::GetParameterValues {
        names: vec!["Device.Slow.".into()],
    }
    .to_row();
    let (task, _) = store
        .enqueue_task(&NewTask::new(DEFAULT_TENANT, device, kind, payload))
        .await
        .unwrap();
    assert!(svc.wake(device, EID).await);
    wait_for("the Agent to be asked", || {
        agent.saw("get Device.Slow.") > 0
    })
    .await;
    let state = async || {
        store
            .list_tasks(device, 100)
            .await
            .unwrap()
            .into_iter()
            .find(|t| t.id == task)
            .unwrap()
            .state
    };
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert_eq!(state().await, TaskState::Pending, "given up on at 1 s");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        state().await,
        TaskState::Pending,
        "the late answer is dropped"
    );
    agent.disconnect(&svc).await;
}

/// Task queued for the Agent as a read of `path` -> its ID.
async fn queue_read(
    store: &Store,
    device: uuid::Uuid,
    path: &str,
    max_attempts: i32,
) -> uuid::Uuid {
    let (kind, payload) = TaskKind::GetParameterValues {
        names: vec![path.to_owned()],
    }
    .to_row();
    store
        .enqueue_task(&NewTask {
            max_attempts,
            ..NewTask::new(DEFAULT_TENANT, device, kind, payload)
        })
        .await
        .unwrap()
        .0
}

async fn task_row(store: &Store, device: uuid::Uuid, id: uuid::Uuid) -> dhonomos_store::Task {
    store
        .list_tasks(device, 100)
        .await
        .unwrap()
        .into_iter()
        .find(|t| t.id == id)
        .unwrap()
}

/// Connected Agent, read whole, nothing queued.
/// Request timeout 30 s = far longer than any wait of the tests below.
async fn settled_agent(store: &Store, eid: &str) -> (UspService, ScriptedAgent, uuid::Uuid) {
    let (svc, addr) = stomp_service_with_timeouts(
        store,
        true,
        Presets::default(),
        Duration::from_secs(30),
        Duration::from_secs(30),
    )
    .await;
    let agent = ScriptedAgent::spawn(addr, eid, "8.0", Arc::default());
    let device = registered(store, eid).await;
    wait_for("the full read of the new Agent", || {
        agent.saw("get Device.") == 1
    })
    .await;
    queue_idle(store, device).await;
    (svc, agent, device)
}

/// Agent address change -> connects again, new connection replaces the old.
/// Request sent over the old one -> dropped with it (ADR-109).
/// Controller sees this when the new connection is up, no wait for request timeout (30 s here)
/// -> task back in the queue, sent again over the new connection.
#[tokio::test]
async fn a_task_lost_with_a_replaced_connection_is_sent_again_at_once() {
    const EID: &str = "os::00AA00-REPL1";
    let (_pg, store) = postgres().await;
    let (svc, agent, device) = settled_agent(&store, EID).await;

    agent.ignore_next("get Device.Test.");
    let task = queue_read(&store, device, "Device.Test.", 3).await;
    assert!(svc.wake(device, EID).await);
    wait_for("the Agent to take the request", || {
        agent.saw("get Device.Test.") == 1
    })
    .await;
    assert_eq!(
        task_row(&store, device, task).await.state,
        TaskState::Running
    );

    // Agent connects again; its unanswered request went with the old connection.
    let started = std::time::Instant::now();
    agent.reconnect();
    wait_until("the task to succeed", async || {
        task_row(&store, device, task).await.state == TaskState::Succeeded
    })
    .await;
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "sent again at once, not after the request timeout: {:?}",
        started.elapsed()
    );
    let row = task_row(&store, device, task).await;
    assert_eq!(row.attempts, 2, "the lost request used an attempt");
    assert_eq!(agent.saw("get Device.Test."), 2);
    agent.disconnect(&svc).await;
}

/// Max 1 attempt -> replaced connection fails the task, error says why.
/// Drain goes on -> next task sent over the new connection at once.
#[tokio::test]
async fn a_task_with_no_attempt_left_fails_when_its_connection_is_replaced() {
    const EID: &str = "os::00AA00-REPL2";
    let (_pg, store) = postgres().await;
    let (svc, agent, device) = settled_agent(&store, EID).await;

    agent.ignore_next("get Device.First.");
    let first = queue_read(&store, device, "Device.First.", 1).await;
    let second = queue_read(&store, device, "Device.Second.", 3).await;
    assert!(svc.wake(device, EID).await);
    wait_for("the Agent to take the request", || {
        agent.saw("get Device.First.") == 1
    })
    .await;

    let started = std::time::Instant::now();
    // No STOMPConnect Record on the new connection -> drain goes on by itself.
    agent.reconnect_quietly();
    wait_until("the second task to succeed", async || {
        task_row(&store, device, second).await.state == TaskState::Succeeded
    })
    .await;
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the next task went out at once, not after the request timeout: {:?}",
        started.elapsed()
    );
    let row = task_row(&store, device, first).await;
    assert_eq!(row.state, TaskState::Failed);
    assert_eq!(row.attempts, 1);
    assert_eq!(
        row.error.as_deref(),
        Some("the connection was replaced before the agent answered")
    );
    assert_eq!(agent.saw("get Device.First."), 1, "not sent again");
    assert_eq!(agent.saw("get Device.Second."), 1);
    agent.disconnect(&svc).await;
}

/// Set with a secret value -> stored empty in the snapshot (as CWMP), with and without
/// `updated_params` echo. Other value of the Set -> stored as set.
#[tokio::test]
async fn a_secret_set_over_usp_stays_out_of_the_snapshot() {
    const EID: &str = "os::00AA00-SECRET1";
    const SECRET: &str = "Device.WiFi.AccessPoint.1.Security.KeyPassphrase";
    const SSID: &str = "Device.WiFi.SSID.1.SSID";
    let (_pg, store) = postgres().await;
    let (svc, agent, device) = settled_agent(&store, EID).await;
    let set = async |secret: &str, ssid: &str| {
        let (kind, payload) = TaskKind::SetParameterValues {
            values: vec![
                dhonomos_core::SetValue {
                    name: SECRET.into(),
                    value: secret.into(),
                    xsd_type: None,
                    secret: true,
                },
                dhonomos_core::SetValue {
                    name: SSID.into(),
                    value: ssid.into(),
                    xsd_type: None,
                    secret: false,
                },
            ],
        }
        .to_row();
        let task = store
            .enqueue_task(&NewTask::new(DEFAULT_TENANT, device, kind, payload))
            .await
            .unwrap()
            .0;
        assert!(svc.wake(device, EID).await);
        wait_until("the Set to succeed", async || {
            task_row(&store, device, task).await.state == TaskState::Succeeded
        })
        .await;
        store
            .get_param_values(device, &[SECRET.to_owned(), SSID.to_owned()])
            .await
            .unwrap()
    };

    // Agent leaves updated_params out -> requested values stored.
    let stored = set("invented-passphrase-1", "home-1").await;
    assert_eq!(stored.get(SECRET), Some(&Some(String::new())));
    assert_eq!(stored.get(SSID), Some(&Some("home-1".to_owned())));

    // Agent echoes both values.
    agent.echo_sets();
    let stored = set("invented-passphrase-2", "home-2").await;
    assert_eq!(stored.get(SECRET), Some(&Some(String::new())));
    assert_eq!(stored.get(SSID), Some(&Some("home-2".to_owned())));
    agent.disconnect(&svc).await;
}

/// ADR-111: Get of an object -> stored rows under it not returned anymore are dropped.
/// Task result gives the count.
#[tokio::test]
async fn a_get_of_an_object_drops_what_the_agent_no_longer_reports() {
    const EID: &str = "os::00AA00-PRUNE1";
    let (_pg, store) = postgres().await;
    let (svc, agent, device) = settled_agent(&store, EID).await;
    agent.has("Device.Ethernet.Interface.1.Name", "eth0");
    let seed: Vec<dhonomos_store::ParamUpdate> = [
        "Device.Ethernet.Interface.1.Name",
        "Device.Ethernet.Interface.2.Name",
    ]
    .iter()
    .map(|path| dhonomos_store::ParamUpdate {
        path: (*path).into(),
        value: Some("v".into()),
        ..Default::default()
    })
    .collect();
    store.upsert_params(device, &seed).await.unwrap();

    let task = queue_read(&store, device, "Device.Ethernet.", 3).await;
    assert!(svc.wake(device, EID).await);
    wait_until("the read to succeed", async || {
        task_row(&store, device, task).await.state == TaskState::Succeeded
    })
    .await;
    let rows: Vec<String> = store
        .get_params(device, "Device.Ethernet.")
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.path)
        .collect();
    assert_eq!(rows, ["Device.Ethernet.Interface.1.Name"]);
    assert_eq!(
        task_row(&store, device, task).await.result,
        Some(serde_json::json!({ "parameters": 1, "errors": [], "removed": 1 }))
    );
    agent.disconnect(&svc).await;
}

/// USP service, WebSocket MTP as only transport (Agent connects to `url`).
/// Last contact of connected Agents updated every `touch_every`.
async fn websocket_service(
    store: &Store,
    eid: &str,
    touch_every: Duration,
) -> (UspService, String) {
    let svc = UspService::start_with_touch_interval(
        store.clone(),
        UspConfig {
            mqtt: None,
            websocket: true,
            onboarding: dhonomos_core::Onboarding::default(),
            stomp: None,
            mqtt_broker: None,
            metrics: None,
            files: None,
            secrets: None,
            ws_client_tls: None,
            auto_subscribe: true,
            wg_sweep_interval: dhonomos_core::DEFAULT_WG_SWEEP_INTERVAL,
            wg_incomplete_retry: dhonomos_core::DEFAULT_WG_INCOMPLETE_RETRY,
            wg_ip_poll_interval: dhonomos_core::DEFAULT_WG_IP_POLL_INTERVAL,
            wg_ip_poll_limit: dhonomos_core::DEFAULT_WG_IP_POLL_LIMIT,
            endpoint_id: CTRL.into(),
            request_timeout: Duration::from_secs(2),
            full_read_timeout: Duration::from_secs(2),
            tenant_id: DEFAULT_TENANT,
            presets: Presets::default().into(),
        },
        touch_every,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/usp?eid={eid}", listener.local_addr().unwrap());
    let router = svc.ws_mtp().unwrap().router();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (svc, url)
}

type AgentSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Agent: hello over WebSocket, then never reads or sends on its own.
/// Returns after the Controller registered it.
async fn silent_websocket_agent(
    svc: &UspService,
    store: &Store,
    url: &str,
    eid: &str,
) -> (AgentSocket, uuid::Uuid) {
    use futures_util::SinkExt as _;
    use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest as _};
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert(
        "sec-websocket-protocol",
        tokio_tungstenite::tungstenite::http::HeaderValue::from_static("v1.usp"),
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let hello = builder::websocket_connect_record(UspVersion { major: 1, minor: 3 }, eid, CTRL);
    ws.send(Message::Binary(hello.encode_to_vec().into()))
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let device = loop {
        if let Some(id) = store.find_usp_device(DEFAULT_TENANT, eid).await.unwrap()
            && svc.is_connected(eid)
        {
            break id;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the Agent did not connect"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    (ws, device)
}

async fn last_contact(store: &Store, device: uuid::Uuid) -> time::OffsetDateTime {
    store
        .get_device(device)
        .await
        .unwrap()
        .unwrap()
        .last_contact_at
        .unwrap()
}

/// Agent sends 1 frame, then silent, socket open -> last contact stays = time of that frame,
/// however often the toucher runs. Controller has not heard from it -> must not claim so.
#[tokio::test]
async fn silent_websocket_agent_keeps_the_time_of_its_last_frame() {
    use futures_util::SinkExt as _;
    use time::{Duration as Span, OffsetDateTime};
    use tokio_tungstenite::tungstenite::Message;
    const WS_AGENT: &str = "proto::agent-silent";

    let (_pg, store) = postgres().await;
    let (svc, url) = websocket_service(&store, WS_AGENT, Duration::from_millis(200)).await;
    let (mut agent, device) = silent_websocket_agent(&svc, &store, &url, WS_AGENT).await;

    tokio::time::sleep(Duration::from_millis(700)).await;
    let frame_at = OffsetDateTime::now_utc();
    // Any frame = Agent heard from.
    agent.send(Message::Pong(Vec::new().into())).await.unwrap();
    // ~10 toucher runs.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let checked_at = OffsetDateTime::now_utc();
    let contact = last_contact(&store, device).await;
    assert!(
        contact >= frame_at - Span::milliseconds(50)
            && contact <= frame_at + Span::milliseconds(500),
        "last contact {contact} is not the frame's time {frame_at}"
    );
    assert!(
        checked_at - contact >= Span::milliseconds(1500),
        "last contact {contact} follows the toucher ({checked_at})"
    );
    assert!(svc.is_connected(WS_AGENT), "the socket is still open");
}

/// Connection end -> last contact = last receive on the connection, not the toucher write
/// 1 min ago (toucher never runs again here).
#[tokio::test]
async fn closed_websocket_connection_leaves_its_last_frame_as_the_last_contact() {
    use futures_util::SinkExt as _;
    use time::{Duration as Span, OffsetDateTime};
    use tokio_tungstenite::tungstenite::Message;
    const WS_AGENT: &str = "proto::agent-closing";

    let (_pg, store) = postgres().await;
    let (svc, url) = websocket_service(&store, WS_AGENT, Duration::from_secs(3600)).await;
    let (mut agent, device) = silent_websocket_agent(&svc, &store, &url, WS_AGENT).await;

    tokio::time::sleep(Duration::from_millis(500)).await;
    let frame_at = OffsetDateTime::now_utc();
    agent.send(Message::Pong(Vec::new().into())).await.unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        frame_at - last_contact(&store, device).await >= Span::milliseconds(400),
        "nothing has written the frame yet"
    );

    // Socket just goes away (no Close frame: that would be a last word of its own).
    let closed_at = OffsetDateTime::now_utc();
    drop(agent);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let contact = loop {
        let contact = last_contact(&store, device).await;
        if !svc.is_connected(WS_AGENT) && contact >= frame_at - Span::milliseconds(50) {
            break contact;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "last contact {contact} never became the frame's time {frame_at}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(contact <= frame_at + Span::milliseconds(500), "{contact}");
    assert!(
        closed_at - contact >= Span::milliseconds(500),
        "last contact {contact} is the time of the close ({closed_at})"
    );
}

/// Minimal MQTT 5.0 Agent for the tests, to the embedded broker.
struct MqttAgent {
    tcp: tokio::net::TcpStream,
    buf: bytes::BytesMut,
}

impl MqttAgent {
    async fn connect(addr: std::net::SocketAddr) -> Self {
        Self {
            tcp: tokio::net::TcpStream::connect(addr).await.unwrap(),
            buf: bytes::BytesMut::new(),
        }
    }

    async fn send(&mut self, p: rumqttc::v5::mqttbytes::v5::Packet) {
        use tokio::io::AsyncWriteExt as _;
        let mut b = bytes::BytesMut::new();
        p.write(&mut b, None).unwrap();
        self.tcp.write_all(&b).await.unwrap();
    }

    /// Next packet; `None` -> broker closed the connection.
    async fn next(&mut self) -> Option<rumqttc::v5::mqttbytes::v5::Packet> {
        self.next_within(Duration::from_secs(10))
            .await
            .expect("no packet from the broker")
    }

    async fn next_within(
        &mut self,
        wait: Duration,
    ) -> Result<Option<rumqttc::v5::mqttbytes::v5::Packet>, tokio::time::error::Elapsed> {
        use rumqttc::v5::mqttbytes::{Error, v5::Packet};
        use tokio::io::AsyncReadExt as _;
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            match Packet::read(&mut self.buf, Some(16 << 20)) {
                Ok(p) => return Ok(Some(p)),
                Err(Error::InsufficientBytes(_)) => {}
                Err(e) => panic!("unreadable packet from the broker: {e}"),
            }
            match tokio::time::timeout(wait, self.tcp.read(&mut chunk)).await? {
                Ok(0) | Err(_) => return Ok(None),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// CONNECT like an Agent (`claim`: its `usp-endpoint-id`) -> CONNACK.
    async fn hello(
        &mut self,
        claim: Option<&str>,
        keep_alive: u16,
        login: Option<(&str, &str)>,
    ) -> rumqttc::v5::mqttbytes::v5::ConnAck {
        use rumqttc::v5::mqttbytes::v5::{Connect, ConnectProperties, Login, Packet};
        let properties = claim.map(|eid| {
            let mut p = ConnectProperties::new();
            p.user_properties = vec![("usp-endpoint-id".into(), eid.into())];
            p
        });
        self.send(Packet::Connect(
            Connect {
                keep_alive,
                client_id: "test-agent".into(),
                clean_start: true,
                properties,
            },
            None,
            login.map(|(u, p)| Login::new(u, p)),
        ))
        .await;
        match self.next().await {
            Some(Packet::ConnAck(ack)) => ack,
            other => panic!("expected a CONNACK, got {other:?}"),
        }
    }

    async fn subscribe(&mut self, topic: &str) {
        use rumqttc::v5::mqttbytes::{
            QoS,
            v5::{Filter, Packet, Subscribe},
        };
        self.send(Packet::Subscribe(Subscribe {
            pkid: 1,
            filters: vec![Filter::new(topic, QoS::AtLeastOnce)],
            properties: None,
        }))
        .await;
        loop {
            match self.next().await {
                Some(Packet::SubAck(_)) => return,
                Some(Packet::Publish(_)) => {}
                other => panic!("expected a SUBACK, got {other:?}"),
            }
        }
    }

    /// Record to the Controller, QoS 1, replies to `reply_topic`.
    async fn record(&mut self, topic: &str, reply_topic: Option<&str>, r: record::Record) {
        use rumqttc::v5::mqttbytes::{
            QoS,
            v5::{Packet, Publish, PublishProperties},
        };
        self.send(Packet::Publish(Publish {
            qos: QoS::AtLeastOnce,
            topic: bytes::Bytes::copy_from_slice(topic.as_bytes()),
            pkid: 1,
            payload: r.encode_to_vec().into(),
            properties: Some(PublishProperties {
                response_topic: reply_topic.map(str::to_owned),
                content_type: Some("usp.msg".into()),
                ..PublishProperties::default()
            }),
            ..Publish::default()
        }))
        .await;
    }

    /// Answer Controller requests (ack each PUBLISH) until a Get of `last` -> paths asked for.
    async fn answer_until_read_of(
        &mut self,
        eid: &str,
        reply_topic: &str,
        last: &str,
    ) -> Vec<String> {
        use rumqttc::v5::mqttbytes::v5::{Packet, PubAck};
        let mut seen = Vec::new();
        while !seen.iter().any(|p: &String| p == last) {
            let Some(Packet::Publish(p)) = self.next().await.or_else(|| panic!("closed")) else {
                continue;
            };
            self.send(Packet::PubAck(PubAck::new(p.pkid, None))).await;
            let rec = record::Record::decode(p.payload).unwrap();
            let Some(RecordType::NoSessionContext(ns)) = rec.record_type else {
                continue;
            };
            let msg = msg::Msg::decode(ns.payload.as_slice()).unwrap();
            let id = msg.header.as_ref().unwrap().msg_id.clone();
            let Some(MsgBody::Request(req)) = msg.body.and_then(|b| b.msg_body) else {
                continue;
            };
            let req = req.req_type.unwrap();
            if let ReqType::Get(g) = &req {
                seen.extend(g.param_paths.iter().cloned());
            }
            let reply = answer(req, &id);
            let rec =
                builder::no_session_record(UspVersion { major: 1, minor: 3 }, eid, CTRL, &reply);
            self.record(CTRL_TOPIC, Some(reply_topic), rec).await;
        }
        seen
    }
}

/// USP service, embedded MQTT broker as only transport -> listen address.
async fn mqtt_broker_service(
    store: &Store,
    onboarding: dhonomos_core::Onboarding,
    login: Option<(&str, &str)>,
) -> (UspService, std::net::SocketAddr) {
    let svc = UspService::start(
        store.clone(),
        UspConfig {
            mqtt: None,
            websocket: false,
            onboarding,
            stomp: None,
            mqtt_broker: Some(dhonomos_usp_mtp::MqttBrokerConfig {
                login: login.map(|(u, p)| (u.to_owned(), p.to_owned())),
                controller_topic: CTRL_TOPIC.into(),
                ..dhonomos_usp_mtp::MqttBrokerConfig::default()
            }),
            metrics: None,
            files: None,
            secrets: None,
            ws_client_tls: None,
            auto_subscribe: true,
            wg_sweep_interval: dhonomos_core::DEFAULT_WG_SWEEP_INTERVAL,
            wg_incomplete_retry: dhonomos_core::DEFAULT_WG_INCOMPLETE_RETRY,
            wg_ip_poll_interval: dhonomos_core::DEFAULT_WG_IP_POLL_INTERVAL,
            wg_ip_poll_limit: dhonomos_core::DEFAULT_WG_IP_POLL_LIMIT,
            endpoint_id: CTRL.into(),
            request_timeout: Duration::from_secs(5),
            full_read_timeout: Duration::from_secs(5),
            tenant_id: DEFAULT_TENANT,
            presets: Presets::default().into(),
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let broker = svc.mqtt_broker_mtp().unwrap().clone();
    tokio::spawn(async move {
        broker
            .serve(listener, None, std::future::pending())
            .await
            .unwrap()
    });
    (svc, addr)
}

async fn disconnected_within(svc: &UspService, eid: &str, limit: Duration) -> Duration {
    let started = tokio::time::Instant::now();
    while svc.is_connected(eid) {
        assert!(
            started.elapsed() < limit,
            "{eid} is still connected after {limit:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    started.elapsed()
}

/// USP over the embedded MQTT broker (ADR-093).
/// Agent: shared account -> topic in CONNACK -> MQTTConnectRecord -> registered + read.
/// Refused: wrong password, other Agent identity, foreign topic. Disconnect seen at once.
#[tokio::test]
async fn usp_agent_over_the_embedded_mqtt_broker() {
    use rumqttc::v5::mqttbytes::{
        QoS,
        v5::{ConnectReturnCode, Packet, PubAckReason, Publish},
    };
    const AGENT: &str = "os::00AA00-MQTT1";
    const OTHER: &str = "os::00AA00-MQTT-OTHER";

    let (_pg, store) = postgres().await;
    let (svc, addr) = mqtt_broker_service(
        &store,
        dhonomos_core::Onboarding::default(),
        Some(("cpe", "factory")),
    )
    .await;

    // Wrong password -> CONNACK says so, connection closes.
    let mut bad = MqttAgent::connect(addr).await;
    let ack = bad.hello(Some(AGENT), 60, Some(("cpe", "guess"))).await;
    assert_eq!(ack.code, ConnectReturnCode::BadUserNamePassword);
    assert!(bad.next().await.is_none());
    // Same for no login.
    let mut anon = MqttAgent::connect(addr).await;
    let ack = anon.hello(Some(AGENT), 60, None).await;
    assert_eq!(ack.code, ConnectReturnCode::BadUserNamePassword);

    // Agent: CONNACK gives its topic -> subscribe + hello.
    let mut agent = MqttAgent::connect(addr).await;
    let ack = agent.hello(Some(AGENT), 60, Some(("cpe", "factory"))).await;
    assert_eq!(ack.code, ConnectReturnCode::Success);
    let topic = ack.properties.unwrap().user_properties[0].1.clone();
    assert_eq!(topic, format!("usp/agent/{AGENT}"));
    agent.subscribe(&topic).await;
    let version = UspVersion { major: 1, minor: 3 };
    agent
        .record(
            CTRL_TOPIC,
            Some(&topic),
            builder::mqtt_connect_record(version, AGENT, CTRL, &topic),
        )
        .await;
    agent.answer_until_read_of(AGENT, &topic, "Device.").await;
    let device = store
        .find_usp_device(DEFAULT_TENANT, AGENT)
        .await
        .unwrap()
        .unwrap();
    let d = store.get_device(device).await.unwrap().unwrap();
    assert_eq!(
        (d.protocol.as_str(), d.software_version.as_deref()),
        ("usp", Some("3.0"))
    );
    // Agent connected to us -> address known.
    assert_eq!(d.last_remote_addr.as_deref(), Some("127.0.0.1"));
    assert!(svc.is_connected(AGENT));

    // Other Agent identity in a Record on this connection -> dropped by the Controller
    // (ADR-087): nobody registered under it, this Agent stays.
    agent
        .record(
            CTRL_TOPIC,
            Some(&topic),
            builder::mqtt_connect_record(version, OTHER, CTRL, &topic),
        )
        .await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(!svc.is_connected(OTHER));
    assert!(
        store
            .find_usp_device(DEFAULT_TENANT, OTHER)
            .await
            .unwrap()
            .is_none()
    );
    assert!(svc.is_connected(AGENT));

    // Only the Controller topic takes Records.
    agent
        .send(Packet::Publish(Publish {
            qos: QoS::AtLeastOnce,
            topic: bytes::Bytes::from_static(b"usp/agent/someone-else"),
            pkid: 9,
            payload: builder::mqtt_connect_record(version, AGENT, CTRL, &topic)
                .encode_to_vec()
                .into(),
            ..Publish::default()
        }))
        .await;
    loop {
        match agent.next().await {
            Some(Packet::PubAck(a)) if a.pkid == 9 => {
                assert_eq!(a.reason, PubAckReason::NotAuthorized);
                break;
            }
            Some(_) => {}
            None => panic!("closed without a PUBACK"),
        }
    }

    // Agent socket gone -> Controller knows at once, not at the next timeout.
    drop(agent);
    let took = disconnected_within(&svc, AGENT, Duration::from_secs(3)).await;
    assert!(took < Duration::from_secs(2), "{took:?}");
}

/// Agent with no name before its 1st Record (no `usp-endpoint-id`) -> named by that Record,
/// then served like any other.
#[tokio::test]
async fn mqtt_agent_without_a_claim_is_named_by_its_first_record() {
    const AGENT: &str = "os::00AA00-MQTT2";
    const MY_TOPIC: &str = "my/own/topic";

    let (_pg, store) = postgres().await;
    let (svc, addr) = mqtt_broker_service(&store, dhonomos_core::Onboarding::default(), None).await;
    let mut agent = MqttAgent::connect(addr).await;
    let ack = agent.hello(None, 60, None).await;
    // No name for a topic -> Agent uses its configured topic.
    assert!(ack.properties.unwrap().user_properties.is_empty());
    agent.subscribe(MY_TOPIC).await;
    agent
        .record(
            CTRL_TOPIC,
            Some(MY_TOPIC),
            builder::mqtt_connect_record(UspVersion { major: 1, minor: 3 }, AGENT, CTRL, MY_TOPIC),
        )
        .await;
    agent.answer_until_read_of(AGENT, MY_TOPIC, "Device.").await;
    assert!(svc.is_connected(AGENT));
    assert!(
        store
            .find_usp_device(DEFAULT_TENANT, AGENT)
            .await
            .unwrap()
            .is_some()
    );
}

/// USP Agent admission (CO-12) on the embedded MQTT broker, pre-registered only.
/// Unknown -> DISCONNECT 0x87, not registered. Pre-registered -> served.
/// Retired -> refused again.
#[tokio::test]
async fn mqtt_admission_policy() {
    use rumqttc::v5::mqttbytes::v5::{DisconnectReasonCode, Packet};
    const AGENT: &str = "os::00AA00-MQTT-ADMIT";

    let (_pg, store) = postgres().await;
    let (svc, addr) = mqtt_broker_service(
        &store,
        dhonomos_core::Onboarding {
            mode: dhonomos_core::OnboardingMode::Preregistered,
            allowed_ouis: Vec::new(),
        },
        None,
    )
    .await;
    // Connect, subscribe, hello -> client + its topic.
    let hello = async || {
        let mut agent = MqttAgent::connect(addr).await;
        let ack = agent.hello(Some(AGENT), 60, None).await;
        let topic = ack.properties.unwrap().user_properties[0].1.clone();
        agent.subscribe(&topic).await;
        agent
            .record(
                CTRL_TOPIC,
                Some(&topic),
                builder::mqtt_connect_record(
                    UspVersion { major: 1, minor: 3 },
                    AGENT,
                    CTRL,
                    &topic,
                ),
            )
            .await;
        agent
    };

    // Unknown: told so, disconnected, not registered.
    let mut agent = hello().await;
    let reason = loop {
        match agent.next().await {
            Some(Packet::Disconnect(d)) => break d.reason_code,
            Some(_) => {}
            None => panic!("closed without a DISCONNECT"),
        }
    };
    assert_eq!(reason, DisconnectReasonCode::NotAuthorized);
    assert!(agent.next().await.is_none());
    assert!(
        store
            .find_usp_device(DEFAULT_TENANT, AGENT)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!svc.is_connected(AGENT));

    // Pre-registered: served (Controller reads its DeviceInfo).
    let device = store
        .preregister_usp_device(DEFAULT_TENANT, AGENT, &[])
        .await
        .unwrap()
        .id;
    let mut agent = hello().await;
    loop {
        match agent.next().await {
            Some(Packet::Publish(_)) => break,
            Some(_) => {}
            None => panic!("a pre-registered Agent is served"),
        }
    }
    drop(agent);
    disconnected_within(&svc, AGENT, Duration::from_secs(3)).await;

    // Retired: refused again.
    store
        .set_device_status(DEFAULT_TENANT, device, "retired")
        .await
        .unwrap();
    let mut agent = hello().await;
    let reason = loop {
        match agent.next().await {
            Some(Packet::Disconnect(d)) => break d.reason_code,
            Some(_) => {}
            None => panic!("closed without a DISCONNECT"),
        }
    };
    assert_eq!(reason, DisconnectReasonCode::NotAuthorized);
}

/// Silent Agent -> cut off 1.5 Keep Alive periods after its last packet.
/// Controller knows at once: no wait for the next request timeout.
#[tokio::test]
async fn silent_mqtt_agent_is_disconnected_promptly() {
    const AGENT: &str = "os::00AA00-MQTT-SILENT";

    let (_pg, store) = postgres().await;
    let (svc, addr) = mqtt_broker_service(&store, dhonomos_core::Onboarding::default(), None).await;
    let mut agent = MqttAgent::connect(addr).await;
    let ack = agent.hello(Some(AGENT), 1, None).await;
    let topic = ack.properties.unwrap().user_properties[0].1.clone();
    agent.subscribe(&topic).await;
    agent
        .record(
            CTRL_TOPIC,
            Some(&topic),
            builder::mqtt_connect_record(UspVersion { major: 1, minor: 3 }, AGENT, CTRL, &topic),
        )
        .await;
    // Agent answers the 1st Controller question (-> registered), then goes silent.
    // Until then it keeps up with the 1 s Keep Alive.
    let answering = agent.answer_until_read_of(AGENT, &topic, "Device.DeviceInfo.SerialNumber");
    tokio::time::timeout(Duration::from_secs(20), answering)
        .await
        .expect("the Controller did not read the Agent");
    assert!(svc.is_connected(AGENT));
    // Now nothing, socket still open (device lost power).
    let silent_since = tokio::time::Instant::now();
    let took = disconnected_within(&svc, AGENT, Duration::from_secs(5)).await;
    assert!(
        silent_since.elapsed() >= Duration::from_millis(1000),
        "cut off after {took:?}"
    );
    // Agent gets the reason.
    loop {
        match agent.next().await {
            Some(rumqttc::v5::mqttbytes::v5::Packet::Disconnect(d)) => {
                assert_eq!(
                    d.reason_code,
                    rumqttc::v5::mqttbytes::v5::DisconnectReasonCode::KeepAliveTimeout
                );
                break;
            }
            Some(_) => {}
            None => panic!("closed without a DISCONNECT"),
        }
    }
}

/// EndpointID with a client cert issued in the DB
/// -> refused without that cert on the MTPs Dhonomos serves (H-3).
/// Watcher feeds them from the DB. Cert revoked -> EndpointID free again.
#[tokio::test]
async fn an_agent_with_a_certificate_issued_is_refused_on_the_shared_account() {
    use rumqttc::v5::mqttbytes::v5::ConnectReturnCode;
    const AGENT: &str = "os::00AA00-BOUND1";
    const OTHER: &str = "os::00AA00-BOUND2";

    let (_pg, store) = postgres().await;
    let (svc, addr) = mqtt_broker_service(
        &store,
        dhonomos_core::Onboarding::default(),
        Some(("cpe", "factory")),
    )
    .await;
    let device = store
        .upsert_usp_device(DEFAULT_TENANT, AGENT, None)
        .await
        .unwrap()
        .id;
    let try_connect = |eid: &'static str| async move {
        let mut agent = MqttAgent::connect(addr).await;
        agent
            .hello(Some(eid), 60, Some(("cpe", "factory")))
            .await
            .code
    };
    assert_eq!(try_connect(AGENT).await, ConnectReturnCode::Success);

    // Cert issued -> watcher picks it up.
    let cert = store
        .record_certificate(
            DEFAULT_TENANT,
            device,
            "01",
            "fingerprint-01",
            time::OffsetDateTime::now_utc() + time::Duration::days(30),
            true,
            None,
        )
        .await
        .unwrap();
    let watcher = tokio::spawn(dhonomos_core::usp::watch_certificates(
        store.clone(),
        DEFAULT_TENANT,
        svc.clone(),
        Duration::from_millis(50),
    ));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while try_connect(AGENT).await == ConnectReturnCode::Success {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the EndpointID is still open to the shared account"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(try_connect(AGENT).await, ConnectReturnCode::NotAuthorized);
    // Other EndpointIDs not affected.
    assert_eq!(try_connect(OTHER).await, ConnectReturnCode::Success);

    // Revoked -> cert no longer binds the EndpointID.
    store
        .revoke_certificate(device, cert, Some("test"), None)
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while try_connect(AGENT).await != ConnectReturnCode::Success {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the EndpointID is still bound after the certificate was revoked"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    watcher.abort();
}
