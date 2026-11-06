//! Last contact (`last_contact_at`) of Agents on the WebSocket + STOMP MTPs.
#![allow(clippy::unwrap_used)]

use std::time::{Duration, SystemTime};

use dhonomos_usp_mtp::stomp::{Frame, Parsed};
use dhonomos_usp_mtp::{MultiMtp, StompConfig, StompMtp, WsMtp};
use futures_util::SinkExt as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

/// `now - t`; 0 if `t` is in the future.
fn ago(t: SystemTime) -> Duration {
    SystemTime::now().duration_since(t).unwrap_or_default()
}

/// `t >= since` with 2 ms slack -> MTP clocks are rounded to 1 ms.
fn at_or_after(t: SystemTime, since: SystemTime) -> bool {
    t + Duration::from_millis(2) >= since
}

async fn poll<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn websocket_agent_is_heard_from_on_every_kind_of_frame_and_on_nothing_else() {
    const EID: &str = "os::heard-ws";
    let (tx, mut inbound) = mpsc::channel(16);
    let ws = WsMtp::new(tx);
    let multi = MultiMtp {
        ws: Some(ws.clone()),
        ..MultiMtp::default()
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/usp?eid={EID}", listener.local_addr().unwrap());
    let router = ws.router();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let mut req = url.as_str().into_client_request().unwrap();
    req.headers_mut()
        .insert("sec-websocket-protocol", "v1.usp".parse().unwrap());
    let (mut agent, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    // Agent never reads -> answers no Ping -> only its own frames count.
    poll("the connection", || ws.last_heard(EID)).await;

    for (kind, frame) in [
        ("Binary", Message::binary(vec![1, 2, 3])),
        ("Ping", Message::Ping(vec![9].into())),
        ("Pong", Message::Pong(Vec::new().into())),
    ] {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let before = ws.last_heard(EID).unwrap();
        assert!(
            ago(before) >= Duration::from_millis(250),
            "idle before {kind}"
        );
        let sent = SystemTime::now();
        agent.send(frame).await.unwrap();
        let heard = poll(&format!("a {kind} frame to count"), || {
            ws.last_heard(EID).filter(|t| at_or_after(*t, sent))
        })
        .await;
        assert!(ago(heard) < Duration::from_secs(2));
    }
    while inbound.try_recv().is_ok() {}

    // Socket open + silent -> time of last frame stays, however long.
    // Listing agrees, also via `MultiMtp`.
    let last = ws.last_heard(EID).unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(ws.last_heard(EID), Some(last));
    assert_eq!(ws.heard_from(), vec![(EID.to_owned(), last)]);
    assert_eq!(multi.heard_from().get(EID), Some(&last));
    assert_eq!(multi.heard_from().len(), 1);

    // Close frame -> connection end; its last time kept, taken once.
    let sent = SystemTime::now();
    agent.send(Message::Close(None)).await.unwrap();
    poll("the close", || ws.last_heard(EID).is_none().then_some(())).await;
    assert!(multi.heard_from().is_empty());
    let finale = multi.take_final_heard(EID).unwrap();
    assert!(at_or_after(finale, sent), "the Close frame counts");
    assert_eq!(multi.take_final_heard(EID), None);
    assert_eq!(ws.take_final_heard(EID), None);
}

/// STOMP Agent with no heart-beat negotiated (like obuspa).
struct Agent {
    tcp: tokio::net::TcpStream,
    buf: Vec<u8>,
}

impl Agent {
    /// Connect + subscribe, wait for the broker RECEIPT of the subscription.
    async fn connect(addr: std::net::SocketAddr, eid: &str) -> Self {
        let mut agent = Self {
            tcp: tokio::net::TcpStream::connect(addr).await.unwrap(),
            buf: Vec::new(),
        };
        agent
            .send(&Frame::new(
                "STOMP",
                &[
                    ("accept-version", "1.2"),
                    ("endpoint-id", eid),
                    ("heart-beat", "0,0"),
                ],
            ))
            .await;
        let connected = agent.next().await;
        assert_eq!(connected.command, "CONNECTED");
        let dest = connected.header("subscribe-dest").unwrap().to_owned();
        agent
            .send(&Frame::new(
                "SUBSCRIBE",
                &[("id", "0"), ("destination", &dest), ("receipt", "r1")],
            ))
            .await;
        assert_eq!(agent.next().await.command, "RECEIPT");
        agent
    }

    async fn send(&mut self, f: &Frame) {
        self.tcp.write_all(&f.encode()).await.unwrap();
    }

    async fn next(&mut self) -> Frame {
        let mut chunk = vec![0u8; 4096];
        loop {
            match Frame::parse(&self.buf, 1 << 20).unwrap() {
                Parsed::Heartbeat(n) => {
                    self.buf.drain(..n);
                    continue;
                }
                Parsed::Frame(f, n) => {
                    self.buf.drain(..n);
                    return f;
                }
                Parsed::Incomplete => {}
            }
            let n = tokio::time::timeout(Duration::from_secs(5), self.tcp.read(&mut chunk))
                .await
                .unwrap()
                .unwrap();
            assert!(n > 0, "the broker closed the connection");
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

async fn broker() -> (StompMtp, std::net::SocketAddr) {
    let (tx, _inbound) = mpsc::channel(16);
    let stomp = StompMtp::new(tx, StompConfig::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = stomp.clone();
    tokio::spawn(async move {
        serving
            .serve(listener, None, std::future::pending())
            .await
            .unwrap()
    });
    (stomp, addr)
}

#[tokio::test]
async fn stomp_heartbeat_newlines_count_even_when_nothing_else_is_sent() {
    const EID: &str = "os::heard-beat";
    let (stomp, addr) = broker().await;
    let mut agent = Agent::connect(addr, EID).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let idle = stomp.last_heard(EID).unwrap();
    let sent = SystemTime::now();
    assert!(ago(idle) >= Duration::from_secs(1), "idle before the beat");
    // Bare EOL = heart-beat (broker told the agent none is needed).
    agent.tcp.write_all(b"\n").await.unwrap();
    poll("the heart-beat to count", || {
        stomp.last_heard(EID).filter(|t| at_or_after(*t, sent))
    })
    .await;
}

/// Agent silent between Records -> still alive while its TCP stack ACKs broker data
/// (also kernel keepalive probes, broker enables them on every socket).
/// -> broker view stays current, Agent sends nothing.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn stomp_agent_without_heartbeat_is_heard_through_tcp_acknowledgements() {
    const EID: &str = "os::heard-tcp";
    let (stomp, addr) = broker().await;
    let agent = Agent::connect(addr, EID).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let idle = stomp.last_heard(EID).unwrap();
    assert!(ago(idle) >= Duration::from_secs(1), "idle: heard {idle:?}");

    // Broker sends a Record. Agent does not read it; its kernel ACKs it.
    let sent = SystemTime::now();
    stomp.send(EID, vec![1, 2, 3]).await.unwrap();
    let heard = poll("the acknowledgement to count", || {
        stomp.last_heard(EID).filter(|t| at_or_after(*t, sent))
    })
    .await;
    assert!(ago(heard) < Duration::from_secs(2));
    assert!(agent.buf.is_empty(), "the agent read nothing");

    // Connection end -> last time = last kernel ACK, kept once for the Controller
    // (Controller learns of the close later).
    drop(agent);
    poll("the close", || {
        stomp.last_heard(EID).is_none().then_some(())
    })
    .await;
    let finale = stomp.take_final_heard(EID).unwrap();
    assert!(at_or_after(finale, sent));
    assert_eq!(stomp.take_final_heard(EID), None);
}
