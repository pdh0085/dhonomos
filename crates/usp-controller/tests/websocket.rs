//! Agent on the WebSocket MTP (US-05): connect, request/response, close.
#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use dhonomos_usp_controller::{Controller, Handler};
use dhonomos_usp_mtp::{MultiMtp, WsMtp};
use dhonomos_usp_proto::msg::{self, request::ReqType, response::RespType};
use dhonomos_usp_proto::record::{self, record::RecordType};
use dhonomos_usp_proto::{UspVersion, builder};
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{self, Message};

const CTRL: &str = "self::ctrl";
const AGENT: &str = "os::ws-agent";

#[derive(Default, Clone)]
struct Log(Arc<Mutex<Vec<String>>>);

impl Handler for Log {
    async fn agent_connected(&self, eid: &str, _v: UspVersion) {
        self.0.lock().unwrap().push(format!("connected {eid}"));
    }
    async fn agent_disconnected(&self, eid: &str) {
        self.0.lock().unwrap().push(format!("disconnected {eid}"));
    }
    async fn notify(&self, _eid: &str, _msg_id: &str, _n: msg::Notify) {}
}

async fn wait_for(log: &Log, entry: &str) {
    for _ in 0..100 {
        if log.0.lock().unwrap().iter().any(|e| e == entry) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no {entry:?} in {:?}", log.0.lock().unwrap());
}

#[tokio::test]
async fn agent_over_websocket() {
    let (tx, inbound) = mpsc::channel(64);
    let ws = WsMtp::new(tx);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = ws.router();
    tokio::spawn(async move { axum::serve(listener, router).await });
    let log = Log::default();
    let mtp = MultiMtp {
        ws: Some(ws.clone()),
        ..MultiMtp::default()
    };
    let ctrl = Arc::new(Controller::new(
        CTRL,
        mtp,
        log.clone(),
        Duration::from_secs(5),
    ));
    let runner = ctrl.clone();
    tokio::spawn(async move { runner.run(inbound).await });

    // No EndpointID -> upgrade refused.
    let bad = format!("ws://{addr}/usp").into_client_request().unwrap();
    assert!(matches!(
        tokio_tungstenite::connect_async(bad).await,
        Err(tungstenite::Error::Http(r)) if r.status() == 400
    ));

    let mut req = format!("ws://{addr}/usp?eid={AGENT}")
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("Sec-WebSocket-Protocol", "v1.usp".parse().unwrap());
    let (mut agent, resp) = tokio_tungstenite::connect_async(req).await.unwrap();
    assert_eq!(resp.headers()["sec-websocket-protocol"], "v1.usp");

    let connect = builder::websocket_connect_record(UspVersion::CURRENT, AGENT, CTRL);
    agent
        .send(Message::binary(connect.encode_to_vec()))
        .await
        .unwrap();
    wait_for(&log, &format!("connected {AGENT}")).await;
    assert_eq!(ws.connections(), 1);

    // Record with from_id != EndpointID of the connection -> dropped.
    let spoof = builder::websocket_connect_record(UspVersion::CURRENT, "os::other", CTRL);
    agent
        .send(Message::binary(spoof.encode_to_vec()))
        .await
        .unwrap();

    let c = ctrl.clone();
    let get = tokio::spawn(async move {
        c.request(
            AGENT,
            ReqType::Get(msg::Get {
                param_paths: vec!["Device.DeviceInfo.".into()],
                max_depth: 0,
            }),
        )
        .await
    });
    let frame = agent.next().await.unwrap().unwrap();
    let rec = record::Record::decode(frame.into_data().as_ref()).unwrap();
    assert_eq!(rec.to_id, AGENT);
    let Some(RecordType::NoSessionContext(ns)) = rec.record_type else {
        panic!()
    };
    let m = msg::Msg::decode(ns.payload.as_slice()).unwrap();
    let id = m.header.unwrap().msg_id;
    let resp = builder::response(id, RespType::GetResp(msg::GetResp::default()));
    let reply = builder::no_session_record(UspVersion::CURRENT, AGENT, CTRL, &resp);
    agent
        .send(Message::binary(reply.encode_to_vec()))
        .await
        .unwrap();
    assert!(get.await.unwrap().is_ok());
    assert!(!ctrl.is_connected("os::other"));

    // Socket closed -> Agent disconnected.
    agent.close(None).await.unwrap();
    wait_for(&log, &format!("disconnected {AGENT}")).await;
    assert!(!ctrl.is_connected(AGENT));
    assert_eq!(ws.connections(), 0);
}

type AgentSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Agent connects to the WebSocket server of the Controller + sends a Connect Record.
async fn agent_connects(addr: std::net::SocketAddr) -> AgentSocket {
    let mut req = format!("ws://{addr}/usp?eid={AGENT}")
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("Sec-WebSocket-Protocol", "v1.usp".parse().unwrap());
    let (mut agent, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let connect = builder::websocket_connect_record(UspVersion::CURRENT, AGENT, CTRL);
    agent
        .send(Message::binary(connect.encode_to_vec()))
        .await
        .unwrap();
    agent
}

/// `msg_id` of the next request from the Controller to the Agent.
async fn next_request_id(agent: &mut AgentSocket) -> String {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), agent.next())
            .await
            .expect("no request for the Agent")
            .unwrap()
            .unwrap();
        let Message::Binary(payload) = frame else {
            continue;
        };
        let rec = record::Record::decode(payload.as_ref()).unwrap();
        let Some(RecordType::NoSessionContext(ns)) = rec.record_type else {
            panic!()
        };
        let m = msg::Msg::decode(ns.payload.as_slice()).unwrap();
        return m.header.unwrap().msg_id;
    }
}

async fn answer_get(agent: &mut AgentSocket, id: &str) {
    let resp = builder::response(id, RespType::GetResp(msg::GetResp::default()));
    let reply = builder::no_session_record(UspVersion::CURRENT, AGENT, CTRL, &resp);
    agent
        .send(Message::binary(reply.encode_to_vec()))
        .await
        .unwrap();
}

/// Agent reconnects -> new connection replaces the old one, sends over the old one lost.
/// -> request fails at once (ADR-109), not at its timeout.
/// Agent still reachable; new connection takes the next request; late answer dropped.
#[tokio::test]
async fn a_request_over_a_replaced_websocket_connection_fails_at_once() {
    let (tx, inbound) = mpsc::channel(64);
    let ws = WsMtp::new(tx);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = ws.router();
    tokio::spawn(async move { axum::serve(listener, router).await });
    let log = Log::default();
    let mtp = MultiMtp {
        ws: Some(ws.clone()),
        ..MultiMtp::default()
    };
    // Long timeout: request must not wait for it.
    let ctrl = Arc::new(Controller::new(
        CTRL,
        mtp,
        log.clone(),
        Duration::from_secs(60),
    ));
    let runner = ctrl.clone();
    tokio::spawn(async move { runner.run(inbound).await });

    let get = |ctrl: &Arc<Controller<MultiMtp, Log>>| {
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
    };

    let mut old = agent_connects(addr).await;
    wait_for(&log, &format!("connected {AGENT}")).await;
    let lost = get(&ctrl);
    let lost_id = next_request_id(&mut old).await;

    // Agent address changed -> connects again, never answers the request.
    let started = std::time::Instant::now();
    let mut new = agent_connects(addr).await;
    let r = tokio::time::timeout(Duration::from_secs(10), lost)
        .await
        .expect("the request was not failed")
        .unwrap();
    assert_eq!(
        r,
        Err(dhonomos_usp_controller::UspError::ConnectionReplaced)
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "far from the 60 s timeout"
    );
    assert!(ctrl.is_connected(AGENT), "the Agent is still reachable");
    assert!(
        !log.0
            .lock()
            .unwrap()
            .iter()
            .any(|e| e == &format!("disconnected {AGENT}")),
        "the replaced connection's end is not the Agent's"
    );

    // Next request -> new connection, answered.
    let next = get(&ctrl);
    let next_id = next_request_id(&mut new).await;
    // Late answer to the lost one over the new connection -> dropped;
    // other request not mistaken for it.
    answer_get(&mut new, &lost_id).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!next.is_finished());
    answer_get(&mut new, &next_id).await;
    assert!(next.await.unwrap().is_ok());
    assert_eq!(ws.connections(), 1);
}
