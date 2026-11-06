//! Controller tests: in-memory transport + scripted Agent.
#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use dhonomos_usp_controller::{Controller, Handler, Transport, UspError};
use dhonomos_usp_mtp::Inbound;
use dhonomos_usp_proto::msg::{self, body::MsgBody, request::ReqType, response::RespType};
use dhonomos_usp_proto::record::{self, record::RecordType};
use dhonomos_usp_proto::{ErrorCode, UspVersion, builder};
use prost::Message as _;
use tokio::sync::mpsc;

const CTRL: &str = "self::ctrl";
const AGENT: &str = "os::agent-1";
const AGENT_TOPIC: &str = "usp/agent/1";

#[derive(Clone)]
struct Wire(mpsc::UnboundedSender<(String, Vec<u8>)>);

impl Transport for Wire {
    async fn send(&self, address: &str, bytes: Vec<u8>) -> Result<Option<u64>, String> {
        self.0
            .send((address.to_owned(), bytes))
            .map(|()| None)
            .map_err(|e| e.to_string())
    }
}

#[derive(Default, Clone)]
struct Log(Arc<Mutex<Vec<String>>>);

impl Handler for Log {
    async fn agent_connected(&self, eid: &str, v: UspVersion) {
        self.0.lock().unwrap().push(format!("connected {eid} {v}"));
    }
    async fn agent_disconnected(&self, eid: &str) {
        self.0.lock().unwrap().push(format!("disconnected {eid}"));
    }
    async fn notify(&self, eid: &str, msg_id: &str, n: msg::Notify) {
        self.0
            .lock()
            .unwrap()
            .push(format!("notify {eid} {} {msg_id}", n.subscription_id));
    }
}

type Ctrl = Controller<Wire, Log>;
type WireRx = mpsc::UnboundedReceiver<(String, Vec<u8>)>;

fn setup(timeout: Duration) -> (Arc<Ctrl>, WireRx, Log) {
    let (tx, rx) = mpsc::unbounded_channel();
    let log = Log::default();
    (
        Arc::new(Controller::new(CTRL, Wire(tx), log.clone(), timeout)),
        rx,
        log,
    )
}

fn agent_record(version: &str, ty: RecordType) -> Inbound {
    let rec = record::Record {
        version: version.into(),
        to_id: CTRL.into(),
        from_id: AGENT.into(),
        record_type: Some(ty),
        ..Default::default()
    };
    Inbound {
        topic: "usp/controller".into(),
        reply_to: Some(AGENT_TOPIC.into()),
        payload: Bytes::from(rec.encode_to_vec()),
        closed: false,
        opened: false,
        sender: None,
        replaced_by: None,
    }
}

fn agent_msg(version: &str, m: &msg::Msg) -> Inbound {
    agent_record(
        version,
        RecordType::NoSessionContext(record::NoSessionContextRecord {
            payload: m.encode_to_vec(),
        }),
    )
}

fn connect(version: &str) -> Inbound {
    agent_record(
        version,
        RecordType::MqttConnect(record::MqttConnectRecord {
            version: 1,
            subscribed_topic: AGENT_TOPIC.into(),
        }),
    )
}

/// Decode a Controller send -> (topic, record version, message).
fn sent(item: (String, Vec<u8>)) -> (String, String, msg::Msg) {
    let rec = record::Record::decode(item.1.as_slice()).unwrap();
    let Some(RecordType::NoSessionContext(ns)) = rec.record_type else {
        panic!()
    };
    (
        item.0,
        rec.version,
        msg::Msg::decode(ns.payload.as_slice()).unwrap(),
    )
}

fn msg_id(m: &msg::Msg) -> String {
    m.header.as_ref().unwrap().msg_id.clone()
}

#[tokio::test]
async fn get_round_trip_with_version_negotiation() {
    let (ctrl, mut wire, log) = setup(Duration::from_secs(5));
    ctrl.handle(connect("1.3")).await;
    assert!(ctrl.is_connected(AGENT));
    assert_eq!(log.0.lock().unwrap()[0], format!("connected {AGENT} 1.3"));

    let c = ctrl.clone();
    let req = tokio::spawn(async move {
        c.request(
            AGENT,
            ReqType::Get(msg::Get {
                param_paths: vec!["Device.DeviceInfo.".into()],
                max_depth: 0,
            }),
        )
        .await
    });
    let (topic, version, m) = sent(wire.recv().await.unwrap());
    assert_eq!(
        (topic.as_str(), version.as_str()),
        (AGENT_TOPIC, "1.3"),
        "reply to the Agent's topic in its version"
    );
    let resp = builder::response(msg_id(&m), RespType::GetResp(msg::GetResp::default()));
    ctrl.handle(agent_msg("1.3", &resp)).await;
    let got = req.await.unwrap().unwrap();
    assert!(matches!(got.resp_type, Some(RespType::GetResp(_))));
}

#[tokio::test]
async fn agent_errors_and_timeouts() {
    let (ctrl, mut wire, _) = setup(Duration::from_millis(300));
    ctrl.handle(connect("1.5")).await;
    let c = ctrl.clone();
    let req = tokio::spawn(async move {
        c.request(
            AGENT,
            ReqType::Delete(msg::Delete {
                allow_partial: false,
                obj_paths: vec!["Device.X.1.".into()],
            }),
        )
        .await
    });
    let (_, _, m) = sent(wire.recv().await.unwrap());
    ctrl.handle(agent_msg(
        "1.5",
        &builder::error(msg_id(&m), ErrorCode::OBJECT_DOES_NOT_EXIST, "nope"),
    ))
    .await;
    assert_eq!(
        req.await.unwrap(),
        Err(UspError::Agent {
            code: ErrorCode::OBJECT_DOES_NOT_EXIST,
            message: "nope".into()
        })
    );

    // No answer -> timeout.
    let r = ctrl.request(AGENT, ReqType::Get(msg::Get::default())).await;
    assert_eq!(r, Err(UspError::Timeout));
    // Unknown agent.
    assert_eq!(
        ctrl.request("os::other", ReqType::Get(msg::Get::default()))
            .await,
        Err(UspError::NotConnected)
    );
}

/// Runtime settings -> new timeout applies while running.
#[tokio::test]
async fn the_request_timeout_changes_while_running() {
    let (ctrl, _wire, _) = setup(Duration::from_secs(3600));
    ctrl.handle(connect("1.5")).await;
    ctrl.set_timeout(Duration::from_millis(100));
    assert_eq!(ctrl.timeout(), Duration::from_millis(100));
    let started = std::time::Instant::now();
    let r = ctrl.request(AGENT, ReqType::Get(msg::Get::default())).await;
    assert_eq!(r, Err(UspError::Timeout));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the new timeout applied"
    );
}

#[tokio::test]
async fn notify_is_acknowledged_and_delivered() {
    let (ctrl, mut wire, log) = setup(Duration::from_secs(5));
    ctrl.handle(connect("1.5")).await;
    let notify = builder::request(
        "n-1",
        ReqType::Notify(msg::Notify {
            subscription_id: "boot".into(),
            send_resp: true,
            notification: None,
        }),
    );
    ctrl.handle(agent_msg("1.5", &notify)).await;
    let (_, _, m) = sent(wire.recv().await.unwrap());
    assert_eq!(msg_id(&m), "n-1", "NotifyResp echoes the Notify msg_id");
    let Some(MsgBody::Response(r)) = m.body.unwrap().msg_body else {
        panic!()
    };
    assert!(
        matches!(r.resp_type, Some(RespType::NotifyResp(ref n)) if n.subscription_id == "boot")
    );
    assert!(
        log.0
            .lock()
            .unwrap()
            .contains(&format!("notify {AGENT} boot n-1")),
        "the handler gets the message ID of the Notify"
    );
}

#[tokio::test]
async fn disconnect_fails_outstanding_requests() {
    let (ctrl, mut wire, log) = setup(Duration::from_secs(5));
    ctrl.handle(connect("1.5")).await;
    let c = ctrl.clone();
    let req =
        tokio::spawn(async move { c.request(AGENT, ReqType::Get(msg::Get::default())).await });
    wire.recv().await.unwrap();
    ctrl.handle(agent_record(
        "1.5",
        RecordType::Disconnect(record::DisconnectRecord {
            reason: "bye".into(),
            reason_code: 0,
        }),
    ))
    .await;
    assert_eq!(req.await.unwrap(), Err(UspError::Disconnected));
    assert!(!ctrl.is_connected(AGENT));
    assert!(
        log.0
            .lock()
            .unwrap()
            .contains(&format!("disconnected {AGENT}"))
    );
}

#[tokio::test]
async fn foreign_records_and_unsupported_requests() {
    let (ctrl, mut wire, log) = setup(Duration::from_secs(5));
    // Record to another Controller -> ignored.
    let mut foreign = connect("1.5");
    let mut rec = record::Record::decode(foreign.payload.clone()).unwrap();
    rec.to_id = "self::someone-else".into();
    foreign.payload = Bytes::from(rec.encode_to_vec());
    ctrl.handle(foreign).await;
    assert!(!ctrl.is_connected(AGENT));

    // Get *to* the Controller -> 7001; Agent learned implicitly.
    ctrl.handle(agent_msg("1.5", &builder::get("g-1", &["Device."], 0)))
        .await;
    assert!(ctrl.is_connected(AGENT));
    assert_eq!(
        log.0.lock().unwrap().len(),
        1,
        "implicit connect reported once"
    );
    let (_, _, m) = sent(wire.recv().await.unwrap());
    let Some(MsgBody::Error(e)) = m.body.unwrap().msg_body else {
        panic!()
    };
    assert_eq!(e.err_code, 7001);

    // Garbage -> dropped, no effect.
    ctrl.handle(Inbound {
        topic: "t".into(),
        reply_to: None,
        payload: Bytes::from_static(b"\xff\xff"),
        closed: false,
        opened: false,
        sender: None,
        replaced_by: None,
    })
    .await;
}

/// `ws:` address -> send fails (closed WebSocket). Rest -> wire.
#[derive(Clone)]
struct HalfBroken(mpsc::UnboundedSender<(String, Vec<u8>)>);

impl Transport for HalfBroken {
    async fn send(&self, address: &str, bytes: Vec<u8>) -> Result<Option<u64>, String> {
        if address.starts_with("ws:") {
            return Err("no WebSocket connection".into());
        }
        self.0
            .send((address.to_owned(), bytes))
            .map(|()| None)
            .map_err(|e| e.to_string())
    }
}

#[tokio::test]
async fn requests_fall_back_to_another_mtp() {
    let (tx, mut wire) = mpsc::unbounded_channel();
    let log = Log::default();
    let ctrl = Arc::new(Controller::new(
        CTRL,
        HalfBroken(tx),
        log.clone(),
        Duration::from_secs(5),
    ));
    // Heard on MQTT, then WebSocket (most recent).
    ctrl.handle(connect("1.3")).await;
    let mut ws = agent_msg(
        "1.3",
        &builder::request("n", ReqType::Notify(msg::Notify::default())),
    );
    ws.reply_to = Some(format!("ws:{AGENT}"));
    ctrl.handle(ws).await;

    let c = ctrl.clone();
    let req =
        tokio::spawn(async move { c.request(AGENT, ReqType::Get(msg::Get::default())).await });
    // WebSocket send fails -> request over MQTT.
    let (topic, _, m) = sent(wire.recv().await.unwrap());
    assert_eq!(topic, AGENT_TOPIC);
    let resp = builder::response(msg_id(&m), RespType::GetResp(msg::GetResp::default()));
    ctrl.handle(agent_msg("1.3", &resp)).await;
    assert!(req.await.unwrap().is_ok());

    // WebSocket lost -> Agent kept (MQTT left). MQTT lost too -> disconnected.
    ctrl.handle(Inbound {
        topic: "ws".into(),
        reply_to: Some(format!("ws:{AGENT}")),
        payload: Bytes::new(),
        closed: true,
        opened: false,
        sender: None,
        replaced_by: None,
    })
    .await;
    assert!(ctrl.is_connected(AGENT));
    ctrl.handle(agent_record(
        "1.3",
        RecordType::Disconnect(record::DisconnectRecord::default()),
    ))
    .await;
    assert!(!ctrl.is_connected(AGENT));
    assert!(
        log.0
            .lock()
            .unwrap()
            .iter()
            .any(|e| e == &format!("disconnected {AGENT}"))
    );
}

/// No posing as another Agent: `from_id` != sender the MTP vouches for
/// (own MQTT topic, own WebSocket) -> Record dropped.
/// -> no takeover of the other Agent's reply address, no fake notifications for it.
#[tokio::test]
async fn records_from_another_sender_are_refused() {
    let (ctrl, mut wire, log) = setup(Duration::from_secs(1));
    // Attacker's own account publishes on usp/controller/os::attacker ...
    let mut spoof = connect("1.3");
    spoof.topic = "usp/controller/os::attacker".into();
    spoof.sender = Some("os::attacker".into());
    spoof.reply_to = Some("usp/agent/os::attacker".into());
    ctrl.handle(spoof).await;
    let notify = msg::Msg {
        header: Some(msg::Header {
            msg_id: "n1".into(),
            msg_type: msg::header::MsgType::Notify as i32,
        }),
        body: Some(msg::Body {
            msg_body: Some(msg::body::MsgBody::Request(msg::Request {
                req_type: Some(msg::request::ReqType::Notify(msg::Notify {
                    subscription_id: "sub-1".into(),
                    send_resp: true,
                    ..Default::default()
                })),
            })),
        }),
    };
    let mut fake = agent_msg("1.3", &notify);
    fake.sender = Some("os::attacker".into());
    ctrl.handle(fake).await;
    // ... but claims to be AGENT -> nothing accepted for AGENT.
    assert!(!ctrl.is_connected(AGENT));
    assert!(
        log.0.lock().unwrap().is_empty(),
        "{:?}",
        log.0.lock().unwrap()
    );
    assert!(wire.try_recv().is_err(), "nothing was sent back");

    // From its own topic -> AGENT accepted as before.
    let mut genuine = connect("1.3");
    genuine.sender = Some(AGENT.into());
    ctrl.handle(genuine).await;
    assert!(ctrl.is_connected(AGENT));
}

const ATTACKER: &str = "os::attacker";
const ATTACKER_TOPIC: &str = "usp/agent/os::attacker";

/// Record from `from` on its own MTP connection -> MTP vouches for it.
fn record_from(from: &str, topic: &str, ty: RecordType) -> Inbound {
    let mut inbound = agent_record("1.3", ty);
    let mut rec = record::Record::decode(inbound.payload.clone()).unwrap();
    rec.from_id = from.into();
    inbound.payload = Bytes::from(rec.encode_to_vec());
    inbound.reply_to = Some(topic.into());
    inbound.sender = Some(from.into());
    inbound
}

fn connect_as(from: &str, topic: &str) -> Inbound {
    record_from(
        from,
        topic,
        RecordType::MqttConnect(record::MqttConnectRecord {
            version: 1,
            subscribed_topic: topic.into(),
        }),
    )
}

fn msg_from(from: &str, topic: &str, m: &msg::Msg) -> Inbound {
    record_from(
        from,
        topic,
        RecordType::NoSessionContext(record::NoSessionContextRecord {
            payload: m.encode_to_vec(),
        }),
    )
}

fn get_resp_for(path: &str) -> RespType {
    RespType::GetResp(msg::GetResp {
        req_path_results: vec![msg::get_resp::RequestedPathResult {
            requested_path: path.into(),
            ..Default::default()
        }],
    })
}

/// Authenticated Agent cannot answer or fail a request sent to another Agent.
/// -> request stays outstanding, real Agent's answer still completes it.
#[tokio::test]
async fn an_agent_cannot_answer_a_request_sent_to_another() {
    let (ctrl, mut wire, _) = setup(Duration::from_secs(5));
    ctrl.handle(connect("1.3")).await;
    ctrl.handle(connect_as(ATTACKER, ATTACKER_TOPIC)).await;

    let c = ctrl.clone();
    let mut req = tokio::spawn(async move {
        c.request(
            AGENT,
            ReqType::Get(msg::Get {
                param_paths: vec!["Device.DeviceInfo.".into()],
                max_depth: 0,
            }),
        )
        .await
    });
    let (topic, _, m) = sent(wire.recv().await.unwrap());
    assert_eq!(topic, AGENT_TOPIC);
    let id = msg_id(&m);

    // Attacker knows the msg_id (e.g. guessed) -> forged Response ...
    let forged = builder::response(&id, get_resp_for("forged"));
    ctrl.handle(msg_from(ATTACKER, ATTACKER_TOPIC, &forged))
        .await;
    // ... + forged Error.
    let error = builder::error(&id, ErrorCode::MESSAGE_FAILED, "forged");
    ctrl.handle(msg_from(ATTACKER, ATTACKER_TOPIC, &error))
        .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut req)
            .await
            .is_err(),
        "the request is still outstanding"
    );

    // Agent the request went to -> answers.
    let genuine = builder::response(&id, get_resp_for("genuine"));
    ctrl.handle(agent_msg("1.3", &genuine)).await;
    let got = req.await.unwrap().unwrap();
    let Some(RespType::GetResp(r)) = got.resp_type else {
        panic!()
    };
    assert_eq!(r.req_path_results[0].requested_path, "genuine");
}

/// Wrong Response type from the right Agent -> request fails.
/// (An Error fits any request.)
#[tokio::test]
async fn a_response_of_the_wrong_type_fails_the_request() {
    let (ctrl, mut wire, _) = setup(Duration::from_secs(5));
    ctrl.handle(connect("1.3")).await;
    let c = ctrl.clone();
    let req =
        tokio::spawn(async move { c.request(AGENT, ReqType::Set(msg::Set::default())).await });
    let (_, _, m) = sent(wire.recv().await.unwrap());
    let wrong = builder::response(msg_id(&m), get_resp_for("Device."));
    ctrl.handle(agent_msg("1.3", &wrong)).await;
    let Err(UspError::Agent { code, message }) = req.await.unwrap() else {
        panic!("a mismatched Response completes the request with an error")
    };
    assert_eq!(code, ErrorCode::MESSAGE_FAILED);
    assert!(
        message.contains("GetResp") && message.contains("SetResp"),
        "{message}"
    );
    // Request gone -> right answer afterwards changes nothing.
    ctrl.handle(agent_msg(
        "1.3",
        &builder::response(msg_id(&m), RespType::SetResp(msg::SetResp::default())),
    ))
    .await;
}

/// Each request kind -> its own Response type.
#[tokio::test]
async fn each_request_is_answered_by_its_own_response_type() {
    let (ctrl, mut wire, _) = setup(Duration::from_secs(5));
    ctrl.handle(connect("1.3")).await;
    let cases = [
        (
            ReqType::Get(msg::Get::default()),
            RespType::GetResp(msg::GetResp::default()),
        ),
        (
            ReqType::GetInstances(msg::GetInstances::default()),
            RespType::GetInstancesResp(msg::GetInstancesResp::default()),
        ),
        (
            ReqType::GetSupportedDm(msg::GetSupportedDm::default()),
            RespType::GetSupportedDmResp(msg::GetSupportedDmResp::default()),
        ),
        (
            ReqType::GetSupportedProtocol(msg::GetSupportedProtocol::default()),
            RespType::GetSupportedProtocolResp(msg::GetSupportedProtocolResp::default()),
        ),
        (
            ReqType::Set(msg::Set::default()),
            RespType::SetResp(msg::SetResp::default()),
        ),
        (
            ReqType::Add(msg::Add::default()),
            RespType::AddResp(msg::AddResp::default()),
        ),
        (
            ReqType::Delete(msg::Delete::default()),
            RespType::DeleteResp(msg::DeleteResp::default()),
        ),
        (
            ReqType::Operate(msg::Operate::default()),
            RespType::OperateResp(msg::OperateResp::default()),
        ),
        (
            ReqType::Register(msg::Register::default()),
            RespType::RegisterResp(msg::RegisterResp::default()),
        ),
        (
            ReqType::Deregister(msg::Deregister::default()),
            RespType::DeregisterResp(msg::DeregisterResp::default()),
        ),
    ];
    for (req, resp) in cases {
        let c = ctrl.clone();
        let task = tokio::spawn(async move { c.request(AGENT, req).await });
        let (_, _, m) = sent(wire.recv().await.unwrap());
        ctrl.handle(agent_msg(
            "1.3",
            &builder::response(msg_id(&m), resp.clone()),
        ))
        .await;
        let got = task.await.unwrap().unwrap();
        assert_eq!(got.resp_type, Some(resp));
    }
}

/// `msg_id` = `dhonomos-` + 128 random bits -> not guessable by another Agent.
#[tokio::test]
async fn message_ids_are_random() {
    let (ctrl, mut wire, _) = setup(Duration::from_millis(50));
    ctrl.handle(connect("1.3")).await;
    let mut ids = std::collections::HashSet::new();
    for _ in 0..20 {
        let c = ctrl.clone();
        let task =
            tokio::spawn(async move { c.request(AGENT, ReqType::Get(msg::Get::default())).await });
        let (_, _, m) = sent(wire.recv().await.unwrap());
        let id = msg_id(&m);
        let hex = id.strip_prefix("dhonomos-").unwrap();
        assert!(
            hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "{id}"
        );
        assert!(ids.insert(id), "message IDs repeat");
        assert_eq!(task.await.unwrap(), Err(UspError::Timeout));
    }
}

const STUCK: &str = "os::stuck";

fn notify_msg(id: &str, subscription: &str) -> msg::Msg {
    builder::request(
        id,
        ReqType::Notify(msg::Notify {
            subscription_id: subscription.into(),
            send_resp: true,
            notification: None,
        }),
    )
}

/// `stall:` address -> send never finishes (Agent connection takes nothing).
/// Other addresses -> wire.
#[derive(Clone)]
struct Stalling(mpsc::UnboundedSender<(String, Vec<u8>)>);

impl Transport for Stalling {
    async fn send(&self, address: &str, bytes: Vec<u8>) -> Result<Option<u64>, String> {
        if address.starts_with("stall:") {
            std::future::pending::<()>().await;
        }
        self.0
            .send((address.to_owned(), bytes))
            .map(|()| None)
            .map_err(|e| e.to_string())
    }
}

/// Agent whose replies cannot be sent must not block the loop that serves every Agent.
/// Its Notify -> NotifyResp, send never returns.
/// Records of others (+ rest of its own) -> still handled at once.
#[tokio::test]
async fn an_agent_that_takes_nothing_does_not_hold_up_the_others() {
    let (tx, mut wire) = mpsc::unbounded_channel();
    let log = Log::default();
    let ctrl = Arc::new(Controller::new(
        CTRL,
        Stalling(tx),
        log.clone(),
        Duration::from_secs(5),
    ));
    let (inbound_tx, inbound) = mpsc::channel(256);
    let runner = ctrl.clone();
    tokio::spawn(async move { runner.run(inbound).await });

    // Many Notifies of the stuck Agent, answers never leave ...
    for i in 0..100 {
        let n = notify_msg(&format!("s-{i}"), "sub");
        inbound_tx
            .send(msg_from(STUCK, "stall:os::stuck", &n))
            .await
            .unwrap();
    }
    // ... then another Agent's -> acknowledged at once.
    let n = notify_msg("n-1", "boot");
    inbound_tx
        .send(msg_from(AGENT, AGENT_TOPIC, &n))
        .await
        .unwrap();
    let (topic, _, m) = sent(
        tokio::time::timeout(Duration::from_secs(2), wire.recv())
            .await
            .expect("the other Agent's NotifyResp was held up")
            .unwrap(),
    );
    assert_eq!((topic.as_str(), msg_id(&m).as_str()), (AGENT_TOPIC, "n-1"));
    // Every Notify handled, stuck Agent's too.
    for _ in 0..100 {
        let handled = log
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.starts_with("notify "))
            .count();
        if handled == 101 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "not every Notify was handled: {:?}",
        log.0.lock().unwrap().len()
    );
}

/// Panics on 1st send.
#[derive(Clone)]
struct PanicsOnce(
    mpsc::UnboundedSender<(String, Vec<u8>)>,
    Arc<std::sync::atomic::AtomicBool>,
);

impl Transport for PanicsOnce {
    async fn send(&self, address: &str, bytes: Vec<u8>) -> Result<Option<u64>, String> {
        assert!(
            self.1.swap(true, std::sync::atomic::Ordering::SeqCst),
            "transport failure (expected by the test)"
        );
        self.0
            .send((address.to_owned(), bytes))
            .map(|()| None)
            .map_err(|e| e.to_string())
    }
}

/// Panic in a send -> ends the task that sends the Agent's replies.
/// Later replies -> own new task, not stuck.
#[tokio::test]
async fn a_send_that_panics_does_not_leave_the_agents_replies_stuck() {
    let (tx, mut wire) = mpsc::unbounded_channel();
    let ctrl = Arc::new(Controller::new(
        CTRL,
        PanicsOnce(tx, Arc::default()),
        Log::default(),
        Duration::from_secs(5),
    ));
    ctrl.handle(connect("1.3")).await;
    ctrl.handle(agent_msg("1.3", &notify_msg("n-0", "sub")))
        .await;
    // Task runs + panics.
    tokio::time::sleep(Duration::from_millis(100)).await;
    ctrl.handle(agent_msg("1.3", &notify_msg("n-1", "sub")))
        .await;
    let (_, _, m) = sent(
        tokio::time::timeout(Duration::from_secs(2), wire.recv())
            .await
            .expect("the reply after the panic was never sent")
            .unwrap(),
    );
    assert_eq!(msg_id(&m), "n-1");
}

/// Earlier send -> longer delay -> sends made at once would finish in reverse order.
#[derive(Clone)]
struct Slow(
    mpsc::UnboundedSender<(String, Vec<u8>)>,
    Arc<std::sync::atomic::AtomicUsize>,
);

impl Transport for Slow {
    async fn send(&self, address: &str, bytes: Vec<u8>) -> Result<Option<u64>, String> {
        let n = self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(100 - 20 * n.min(4) as u64)).await;
        self.0
            .send((address.to_owned(), bytes))
            .map(|()| None)
            .map_err(|e| e.to_string())
    }
}

/// Replies to one Agent -> in order, one at a time. Record handling does not wait for them.
#[tokio::test]
async fn replies_to_an_agent_leave_in_order() {
    let (tx, mut wire) = mpsc::unbounded_channel();
    let ctrl = Arc::new(Controller::new(
        CTRL,
        Slow(tx, Arc::default()),
        Log::default(),
        Duration::from_secs(5),
    ));
    ctrl.handle(connect("1.3")).await;
    for i in 0..5 {
        let n = notify_msg(&format!("n-{i}"), "sub");
        let started = std::time::Instant::now();
        ctrl.handle(agent_msg("1.3", &n)).await;
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "handling waited for the send"
        );
    }
    let mut ids = Vec::new();
    for _ in 0..5 {
        let (topic, _, m) = sent(
            tokio::time::timeout(Duration::from_secs(5), wire.recv())
                .await
                .unwrap()
                .unwrap(),
        );
        assert_eq!(topic, AGENT_TOPIC);
        ids.push(msg_id(&m));
    }
    assert_eq!(ids, ["n-0", "n-1", "n-2", "n-3", "n-4"]);
}

/// Disconnect Record -> removes an address of its own sender only (L-2).
/// External broker: address = Response Topic the sender chose -> can name another Agent's.
#[tokio::test]
async fn a_disconnect_record_only_removes_an_address_of_its_own_sender() {
    let (ctrl, _wire, log) = setup(Duration::from_secs(5));
    ctrl.handle(connect_as(AGENT, AGENT_TOPIC)).await;
    ctrl.handle(connect_as(ATTACKER, ATTACKER_TOPIC)).await;

    // Attacker disconnects with the victim's topic as Response Topic,
    // on its own topic (vouched) or on the shared one (not).
    for sender in [Some(ATTACKER.to_owned()), None] {
        let mut evil = record_from(
            ATTACKER,
            AGENT_TOPIC,
            RecordType::Disconnect(record::DisconnectRecord::default()),
        );
        evil.sender = sender;
        ctrl.handle(evil).await;
        assert!(ctrl.is_connected(AGENT), "the victim keeps its address");
        assert_eq!(
            ctrl.connected_agent_addresses()
                .into_iter()
                .find(|(e, _)| e == AGENT)
                .unwrap()
                .1,
            [AGENT_TOPIC]
        );
        assert!(
            !log.0
                .lock()
                .unwrap()
                .contains(&format!("disconnected {AGENT}"))
        );
    }

    // Agent leaves 1 of several MTPs -> loses that one only ...
    ctrl.handle(connect_as(ATTACKER, "ws:os::attacker")).await;
    ctrl.handle(record_from(
        ATTACKER,
        "ws:os::attacker",
        RecordType::Disconnect(record::DisconnectRecord::default()),
    ))
    .await;
    assert!(ctrl.is_connected(ATTACKER));
    // ... and gone with its last.
    ctrl.handle(record_from(
        ATTACKER,
        ATTACKER_TOPIC,
        RecordType::Disconnect(record::DisconnectRecord::default()),
    ))
    .await;
    assert!(!ctrl.is_connected(ATTACKER));
    assert!(
        log.0
            .lock()
            .unwrap()
            .contains(&format!("disconnected {ATTACKER}"))
    );
    assert!(ctrl.is_connected(AGENT));
}

/// Address nobody vouched for never outranks a vouched one, however recent (H-3).
/// (External broker: Agent on the shared topic can claim to be anybody.)
/// -> requests try vouched addresses first.
#[tokio::test]
async fn an_address_nobody_vouched_for_never_outranks_one_that_was() {
    let (ctrl, mut wire, _log) = setup(Duration::from_secs(5));
    let order = |ctrl: &Ctrl| {
        ctrl.connected_agent_addresses()
            .into_iter()
            .find(|(e, _)| e == AGENT)
            .unwrap()
            .1
    };
    // Agent on its WebSocket (MTP vouches) ...
    ctrl.handle(connect_as(AGENT, "ws:os::agent-1")).await;
    // ... + somebody claiming to be it on the shared topic of an external broker.
    let mut claim = connect_as(AGENT, "usp/agent/evil");
    claim.sender = None;
    ctrl.handle(claim.clone()).await;
    assert_eq!(order(&ctrl), ["ws:os::agent-1", "usp/agent/evil"]);
    let c = ctrl.clone();
    let req =
        tokio::spawn(async move { c.request(AGENT, ReqType::Get(msg::Get::default())).await });
    let (to, _, m) = sent(wire.recv().await.unwrap());
    assert_eq!(to, "ws:os::agent-1", "the claim is not asked first");
    ctrl.handle(msg_from(
        AGENT,
        "ws:os::agent-1",
        &builder::response(msg_id(&m), RespType::GetResp(msg::GetResp::default())),
    ))
    .await;
    assert!(req.await.unwrap().is_ok());

    // Claim repeated, any count -> no move up. Vouched address -> first (most recent first).
    ctrl.handle(claim).await;
    assert_eq!(order(&ctrl), ["ws:os::agent-1", "usp/agent/evil"]);
    ctrl.handle(connect_as(AGENT, AGENT_TOPIC)).await;
    assert_eq!(
        order(&ctrl),
        [AGENT_TOPIC, "ws:os::agent-1", "usp/agent/evil"]
    );
    ctrl.handle(msg_from(
        AGENT,
        "ws:os::agent-1",
        &builder::request("n", ReqType::Notify(msg::Notify::default())),
    ))
    .await;
    assert_eq!(
        order(&ctrl),
        ["ws:os::agent-1", AGENT_TOPIC, "usp/agent/evil"]
    );
    // Once vouched -> stays vouched when heard without the MTP's word.
    let mut again = connect_as(AGENT, AGENT_TOPIC);
    again.sender = None;
    ctrl.handle(again).await;
    assert_eq!(
        order(&ctrl),
        [AGENT_TOPIC, "ws:os::agent-1", "usp/agent/evil"]
    );
    // Vouched ones lost -> only the claim left.
    for closed in [AGENT_TOPIC, "ws:os::agent-1"] {
        ctrl.handle(Inbound {
            topic: "x".into(),
            reply_to: Some(closed.into()),
            payload: Bytes::new(),
            closed: true,
            opened: false,
            sender: None,
            replaced_by: None,
        })
        .await;
    }
    assert_eq!(order(&ctrl), ["usp/agent/evil"]);
}

/// Request with own longer timeout -> still waits after the usual timeout, gets answered.
/// Usual request -> gives up on time.
#[tokio::test]
async fn a_request_can_have_a_longer_timeout_of_its_own() {
    let (ctrl, mut wire, _) = setup(Duration::from_millis(200));
    ctrl.handle(connect("1.3")).await;

    let c = ctrl.clone();
    let slow = tokio::spawn(async move {
        c.request_with_timeout(
            AGENT,
            ReqType::Get(msg::Get::default()),
            Duration::from_secs(10),
        )
        .await
    });
    let (_, _, slow_req) = sent(wire.recv().await.unwrap());
    // Usual timeout 200 ms: no answer -> ends.
    let started = std::time::Instant::now();
    let usual = ctrl.request(AGENT, ReqType::Get(msg::Get::default())).await;
    assert_eq!(usual, Err(UspError::Timeout));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the usual timeout applies to the usual request"
    );
    // Slow request outlived that timeout, still waiting.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!slow.is_finished(), "the longer timeout has not run out");
    ctrl.handle(agent_msg(
        "1.3",
        &builder::response(
            msg_id(&slow_req),
            RespType::GetResp(msg::GetResp::default()),
        ),
    ))
    .await;
    let got = slow.await.unwrap().unwrap();
    assert!(matches!(got.resp_type, Some(RespType::GetResp(_))));

    // Own timeout -> ends too.
    let started = std::time::Instant::now();
    let r = ctrl
        .request_with_timeout(
            AGENT,
            ReqType::Get(msg::Get::default()),
            Duration::from_millis(400),
        )
        .await;
    assert_eq!(r, Err(UspError::Timeout));
    assert!(
        started.elapsed() >= Duration::from_millis(400),
        "it waited for its own timeout"
    );
}

/// Captured log output for asserts.
#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogBuf {
    /// Capture logs of `level` and above on this thread, until guard drop.
    fn capture(&self, level: tracing::Level) -> tracing::subscriber::DefaultGuard {
        let buf = self.clone();
        tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(level)
                .with_writer(move || buf.clone())
                .finish(),
        )
    }

    /// Late-response lines.
    fn late_responses(&self) -> Vec<String> {
        self.lines_containing("arrived after the request timed out")
    }

    fn lines_containing(&self, needle: &str) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|l| l.contains(needle))
            .map(str::to_owned)
            .collect()
    }
}

/// Answer to a timed-out request -> dropped, 1 info line (Agent, `msg_id`, lateness).
/// No line: answer to a request never ours, answer from an Agent the request did not go to.
#[tokio::test]
async fn a_late_response_is_logged_once_and_dropped() {
    let logs = LogBuf::default();
    let _capture = logs.capture(tracing::Level::INFO);
    let (ctrl, mut wire, _) = setup(Duration::from_millis(100));
    ctrl.handle(connect("1.3")).await;
    ctrl.handle(connect_as(ATTACKER, ATTACKER_TOPIC)).await;

    let r = ctrl.request(AGENT, ReqType::Get(msg::Get::default())).await;
    assert_eq!(r, Err(UspError::Timeout));
    let (_, _, m) = sent(wire.recv().await.unwrap());
    let id = msg_id(&m);
    let resp = builder::response(&id, RespType::GetResp(msg::GetResp::default()));

    // Wrong Agent -> not an answer; request still remembered for the real one.
    ctrl.handle(msg_from(ATTACKER, ATTACKER_TOPIC, &resp)).await;
    // Never ours.
    let stranger = builder::response("dhonomos-never-sent", RespType::GetResp(Default::default()));
    ctrl.handle(agent_msg("1.3", &stranger)).await;
    assert!(
        logs.late_responses().is_empty(),
        "{:?}",
        logs.late_responses()
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    ctrl.handle(agent_msg("1.3", &resp)).await;
    let lines = logs.late_responses();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("INFO"), "{}", lines[0]);
    assert!(lines[0].contains(AGENT), "{}", lines[0]);
    assert!(lines[0].contains(&id), "{}", lines[0]);
    assert!(lines[0].contains("timeout_ms=100"), "{}", lines[0]);
    let late: u128 = lines[0]
        .split("late_ms=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no late_ms in {}", lines[0]));
    assert!(late >= 50, "{}", lines[0]);

    // Logged once: repeated answer -> unknown now.
    ctrl.handle(agent_msg("1.3", &resp)).await;
    assert_eq!(logs.late_responses().len(), 1);
    // Error = answer too.
    let r = ctrl.request(AGENT, ReqType::Get(msg::Get::default())).await;
    assert_eq!(r, Err(UspError::Timeout));
    let (_, _, m2) = sent(wire.recv().await.unwrap());
    ctrl.handle(agent_msg(
        "1.3",
        &builder::error(msg_id(&m2), ErrorCode::MESSAGE_FAILED, "busy"),
    ))
    .await;
    assert_eq!(logs.late_responses().len(), 2);
}

/// Timed-out requests remembered: most recent 256 only.
#[tokio::test]
async fn only_recent_timeouts_are_remembered() {
    let logs = LogBuf::default();
    let _capture = logs.capture(tracing::Level::INFO);
    let (ctrl, mut wire, _) = setup(Duration::from_millis(1));
    ctrl.handle(connect("1.3")).await;
    let mut ids = Vec::new();
    for _ in 0..300 {
        let r = ctrl.request(AGENT, ReqType::Get(msg::Get::default())).await;
        assert_eq!(r, Err(UspError::Timeout));
        ids.push(msg_id(&sent(wire.recv().await.unwrap()).2));
    }
    let answer = async |id: &str| {
        let resp = builder::response(id, RespType::GetResp(msg::GetResp::default()));
        ctrl.handle(agent_msg("1.3", &resp)).await;
    };
    // Oldest 44 (300 - 256) forgotten ...
    answer(&ids[0]).await;
    answer(&ids[43]).await;
    assert!(logs.late_responses().is_empty());
    // ... rest remembered.
    answer(&ids[44]).await;
    answer(&ids[299]).await;
    assert_eq!(logs.late_responses().len(), 2);
}

// ---------------------------------------------------------------------------------------------
// New connection of an Agent replaces its old one (ADR-109)

const STOMP_AGENT: &str = "stomp:os::agent-1";

/// Connection serials like the MTPs Dhonomos serves: each send reports the serial current
/// when it takes the Record (`serial`; test moves it on -> connection replaced).
/// `hold` set -> 1st send returns only after `release` notify, Record already on the wire
/// -> send overtaken by the replacement.
#[derive(Clone)]
struct Numbered {
    wire: mpsc::UnboundedSender<(String, Vec<u8>)>,
    serial: Arc<std::sync::atomic::AtomicU64>,
    hold: Arc<std::sync::atomic::AtomicBool>,
    release: Arc<tokio::sync::Notify>,
}

impl Transport for Numbered {
    async fn send(&self, address: &str, bytes: Vec<u8>) -> Result<Option<u64>, String> {
        use std::sync::atomic::Ordering::SeqCst;
        let serial = self.serial.load(SeqCst);
        self.wire
            .send((address.to_owned(), bytes))
            .map_err(|e| e.to_string())?;
        if self.hold.swap(false, SeqCst) {
            self.release.notified().await;
        }
        Ok(Some(serial))
    }
}

type NumberedCtrl = Controller<Numbered, Log>;

/// Controller with [`Numbered`] transport + Agent heard on its STOMP address.
async fn numbered(timeout: Duration) -> (Arc<NumberedCtrl>, WireRx, Numbered) {
    let (tx, wire) = mpsc::unbounded_channel();
    let transport = Numbered {
        wire: tx,
        serial: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        hold: Arc::default(),
        release: Arc::default(),
    };
    let ctrl = Arc::new(Controller::new(
        CTRL,
        transport.clone(),
        Log::default(),
        timeout,
    ));
    ctrl.handle(on_stomp(agent_msg(
        "1.3",
        &builder::request("n", ReqType::Notify(msg::Notify::default())),
    )))
    .await;
    assert!(ctrl.is_connected(AGENT));
    (ctrl, wire, transport)
}

/// `inbound` as if received on the Agent's STOMP connection.
fn on_stomp(mut inbound: Inbound) -> Inbound {
    inbound.reply_to = Some(STOMP_AGENT.into());
    inbound
}

/// MTP report: connection `serial` of the Agent at `address` replaced another.
fn replaced(address: &str, serial: u64) -> Inbound {
    Inbound {
        topic: "stomp".into(),
        reply_to: Some(address.into()),
        payload: Bytes::new(),
        closed: false,
        opened: false,
        sender: Some(AGENT.into()),
        replaced_by: Some(serial),
    }
}

fn get_task(ctrl: &Arc<NumberedCtrl>) -> tokio::task::JoinHandle<Result<msg::Response, UspError>> {
    let c = ctrl.clone();
    tokio::spawn(async move {
        c.request(
            AGENT,
            ReqType::Get(msg::Get {
                param_paths: vec!["Device.DeviceInfo.".into()],
                max_depth: 0,
            }),
        )
        .await
    })
}

fn get_resp(id: &str) -> msg::Msg {
    builder::response(id, RespType::GetResp(msg::GetResp::default()))
}

/// Requests over the replaced connection -> fail at once, long before the timeout.
/// Request over the new connection -> untouched. Later answers to old ones -> dropped.
#[tokio::test]
async fn requests_sent_over_a_replaced_connection_fail_at_once() {
    use std::sync::atomic::Ordering::SeqCst;
    let logs = LogBuf::default();
    let _capture = logs.capture(tracing::Level::INFO);
    let (ctrl, mut wire, transport) = numbered(Duration::from_secs(30)).await;

    // 2 requests over connection 1; Agent answers neither.
    let (first, second) = (get_task(&ctrl), get_task(&ctrl));
    let (_, _, m1) = sent(wire.recv().await.unwrap());
    let (_, _, m2) = sent(wire.recv().await.unwrap());

    // Replacement on another MTP's connection of the Agent -> not this one.
    ctrl.handle(replaced("ws:os::agent-1", 99)).await;
    // Connection 2 of the same address -> replaces it.
    transport.serial.store(2, SeqCst);
    let started = std::time::Instant::now();
    ctrl.handle(replaced(STOMP_AGENT, 2)).await;
    for task in [first, second] {
        let r = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the request was not failed")
            .unwrap();
        assert_eq!(r, Err(UspError::ConnectionReplaced));
    }
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "well under the 30 s timeout"
    );
    assert!(ctrl.is_connected(AGENT), "the Agent is still reachable");

    // New request -> over connection 2. Replacement reported again -> request untouched
    // (MTP says it once, but nothing depends on that).
    let third = get_task(&ctrl);
    let (_, _, m3) = sent(wire.recv().await.unwrap());
    ctrl.handle(replaced(STOMP_AGENT, 2)).await;
    // Agent answers an old-connection request after all, over the new one
    // -> dropped, logged once at info, nothing waits for it.
    ctrl.handle(on_stomp(agent_msg("1.3", &get_resp(&msg_id(&m1)))))
        .await;
    let lines = logs.lines_containing("connection the request was sent over was replaced");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("INFO"), "{}", lines[0]);
    assert!(lines[0].contains(AGENT), "{}", lines[0]);
    assert!(lines[0].contains(&msg_id(&m1)), "{}", lines[0]);
    // Logged once; other old one remembered too; one never sent -> unknown.
    ctrl.handle(on_stomp(agent_msg("1.3", &get_resp(&msg_id(&m1)))))
        .await;
    ctrl.handle(on_stomp(agent_msg("1.3", &get_resp(&msg_id(&m2)))))
        .await;
    ctrl.handle(on_stomp(agent_msg("1.3", &get_resp("dhonomos-never-sent"))))
        .await;
    assert_eq!(
        logs.lines_containing("connection the request was sent over was replaced")
            .len(),
        2
    );
    // None of that answered the 3rd request -> answered by its own.
    assert!(!third.is_finished());
    ctrl.handle(on_stomp(agent_msg("1.3", &get_resp(&msg_id(&m3)))))
        .await;
    assert!(third.await.unwrap().is_ok());
}

/// Send that returns only after the replacement report -> also told apart.
/// Send says which connection took it -> old one -> request failed then.
#[tokio::test]
async fn a_send_overtaken_by_the_replacement_is_failed_when_it_returns() {
    use std::sync::atomic::Ordering::SeqCst;
    let (ctrl, mut wire, transport) = numbered(Duration::from_secs(30)).await;

    transport.hold.store(true, SeqCst);
    let first = get_task(&ctrl);
    // Record out on connection 1, send has not said so yet.
    sent(wire.recv().await.unwrap());
    transport.serial.store(2, SeqCst);
    ctrl.handle(replaced(STOMP_AGENT, 2)).await;
    assert!(!first.is_finished(), "not known to be on connection 1 yet");
    transport.release.notify_one();
    let r = tokio::time::timeout(Duration::from_secs(5), first)
        .await
        .expect("the request was not failed")
        .unwrap();
    assert_eq!(r, Err(UspError::ConnectionReplaced));

    // Next send takes connection 2, whatever came before -> answered.
    let second = get_task(&ctrl);
    let (_, _, m2) = sent(wire.recv().await.unwrap());
    ctrl.handle(on_stomp(agent_msg("1.3", &get_resp(&msg_id(&m2)))))
        .await;
    assert!(second.await.unwrap().is_ok());
}

/// Replacing connection then closed -> Agent gone + its requests.
/// Later connection -> judged by its own serial, not by earlier reports.
#[tokio::test]
async fn an_agent_that_closes_after_a_replacement_is_gone_and_can_come_back() {
    use std::sync::atomic::Ordering::SeqCst;
    let (ctrl, mut wire, transport) = numbered(Duration::from_secs(30)).await;
    transport.serial.store(5, SeqCst);
    ctrl.handle(replaced(STOMP_AGENT, 5)).await;
    let pending = get_task(&ctrl);
    sent(wire.recv().await.unwrap());
    ctrl.handle(Inbound {
        closed: true,
        replaced_by: None,
        ..replaced(STOMP_AGENT, 0)
    })
    .await;
    assert_eq!(pending.await.unwrap(), Err(UspError::Disconnected));
    assert!(!ctrl.is_connected(AGENT));

    // Reconnect, serial above all before -> requests not failed by reports
    // about the old connections.
    transport.serial.store(6, SeqCst);
    ctrl.handle(on_stomp(agent_msg(
        "1.3",
        &builder::request("n", ReqType::Notify(msg::Notify::default())),
    )))
    .await;
    let again = get_task(&ctrl);
    let (_, _, m) = sent(wire.recv().await.unwrap());
    ctrl.handle(on_stomp(agent_msg("1.3", &get_resp(&msg_id(&m)))))
        .await;
    assert!(again.await.unwrap().is_ok());
}
