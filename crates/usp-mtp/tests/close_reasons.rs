//! Why a USP connection closed: close line of each MTP -> `reason=<label>`, either side.
//! Tests read the reason back from the log, as an operator would.
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use dhonomos_usp_mtp::stomp::{Frame, Parsed};
use dhonomos_usp_mtp::{Inbound, MqttBrokerConfig, MqttBrokerMtp, StompConfig, StompMtp, WsMtp};
use futures_util::{SinkExt as _, StreamExt as _};
use rumqttc::v5::mqttbytes::v5::{
    Connect, ConnectProperties, Disconnect, DisconnectReasonCode, Packet,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

/// Captured log text.
#[derive(Clone, Default)]
struct LogBuf(Arc<std::sync::Mutex<Vec<u8>>>);

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
    /// Capture info+ logs of this thread until guard drop.
    /// `#[tokio::test]` -> servers run on this thread too.
    fn capture(&self) -> tracing::subscriber::DefaultGuard {
        let buf = self.clone();
        tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::INFO)
                .with_writer(move || buf.clone())
                .finish(),
        )
    }

    fn lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Wait for the `message` line (close log text) of `eid` -> the line.
    async fn line(&self, message: &str, eid: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let found = self
                .lines()
                .into_iter()
                .find(|l| l.contains(message) && l.contains(eid));
            if let Some(l) = found {
                return l;
            }
            assert!(
                Instant::now() < deadline,
                "no {message:?} line for {eid}: {:#?}",
                self.lines()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// `reason` of the `message` close line of `eid`.
    async fn reason(&self, message: &str, eid: &str) -> String {
        let line = self.line(message, eid).await;
        let reason = reason_of(&line).to_owned();
        assert!(line.contains("connected_secs="), "{line}");
        reason
    }
}

fn reason_of(line: &str) -> &str {
    line.split("reason=")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .unwrap_or_else(|| panic!("no reason in {line}"))
}

/// Close `tcp` with RST, not FIN.
fn reset(tcp: TcpStream) {
    socket2::SockRef::from(&tcp)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    drop(tcp);
}

// ---------------------------------------------------------------------------------------------
// STOMP

const STOMP_CLOSED: &str = "USP STOMP closed";

struct StompAgent {
    tcp: TcpStream,
    buf: Vec<u8>,
}

impl StompAgent {
    async fn login_with(addr: SocketAddr, eid: &str, heart_beat: &str) -> Self {
        let mut a = Self {
            tcp: TcpStream::connect(addr).await.unwrap(),
            buf: Vec::new(),
        };
        a.send(&Frame::new(
            "STOMP",
            &[
                ("accept-version", "1.2"),
                ("endpoint-id", eid),
                ("heart-beat", heart_beat),
            ],
        ))
        .await;
        let connected = a.next().await.expect("CONNECTED");
        assert_eq!(connected.command, "CONNECTED");
        a
    }

    async fn login(addr: SocketAddr, eid: &str) -> Self {
        Self::login_with(addr, eid, "0,0").await
    }

    async fn send(&mut self, f: &Frame) {
        self.tcp.write_all(&f.encode()).await.unwrap();
    }

    async fn next(&mut self) -> Option<Frame> {
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            match Frame::parse(&self.buf, 1 << 20).unwrap() {
                Parsed::Heartbeat(n) => {
                    self.buf.drain(..n);
                    continue;
                }
                Parsed::Frame(f, n) => {
                    self.buf.drain(..n);
                    return Some(f);
                }
                Parsed::Incomplete => {}
            }
            match tokio::time::timeout(Duration::from_secs(5), self.tcp.read(&mut chunk))
                .await
                .expect("nothing from the broker")
            {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }
}

async fn stomp_broker(config: StompConfig) -> (StompMtp, SocketAddr, mpsc::Receiver<Inbound>) {
    let (tx, inbound) = mpsc::channel(64);
    let stomp = StompMtp::new(tx, config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = stomp.clone();
    tokio::spawn(async move {
        serving
            .serve(listener, None, std::future::pending())
            .await
            .unwrap()
    });
    (stomp, addr, inbound)
}

#[tokio::test]
async fn a_closed_stomp_connection_says_why() {
    let logs = LogBuf::default();
    let _capture = logs.capture();
    let (stomp, addr, _inbound) = stomp_broker(StompConfig {
        heartbeat_ms: 100,
        ..StompConfig::default()
    })
    .await;
    let reason = async |eid: &str| logs.reason(STOMP_CLOSED, eid).await;

    // Agent says goodbye.
    let mut a = StompAgent::login(addr, "os::stomp-goodbye").await;
    a.send(&Frame::new("DISCONNECT", &[])).await;
    assert_eq!(reason("os::stomp-goodbye").await, "agent_closed");

    // Agent TCP connection ends, nothing said.
    let a = StompAgent::login(addr, "os::stomp-eof").await;
    drop(a);
    assert_eq!(reason("os::stomp-eof").await, "eof");

    // Agent resets the connection -> error logged too.
    let a = StompAgent::login(addr, "os::stomp-reset").await;
    reset(a.tcp);
    let line = logs.line(STOMP_CLOSED, "os::stomp-reset").await;
    assert_eq!(reason_of(&line), "reset");
    assert!(line.contains("error="), "{line}");

    // Frame not supported by the broker.
    let mut a = StompAgent::login(addr, "os::stomp-protocol").await;
    a.send(&Frame::new("ACK", &[("id", "1")])).await;
    let line = logs.line(STOMP_CLOSED, "os::stomp-protocol").await;
    assert_eq!(reason_of(&line), "protocol_error");
    assert!(line.contains("ACK is not supported"), "{line}");

    // Not a frame (header without colon).
    let mut a = StompAgent::login(addr, "os::stomp-garbage").await;
    a.tcp.write_all(b"SEND\nno-colon-here\n\n\0").await.unwrap();
    assert_eq!(reason("os::stomp-garbage").await, "bad_frame");

    // Heart-beat promised, Agent stays quiet.
    let _quiet = StompAgent::login_with(addr, "os::stomp-quiet", "100,100").await;
    assert_eq!(reason("os::stomp-quiet").await, "idle_timeout");

    // Server asked to close it.
    let _a = StompAgent::login(addr, "os::stomp-kicked").await;
    while !stomp.disconnect("os::stomp-kicked") {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(reason("os::stomp-kicked").await, "closed_by_server");

    // Newer connection of the same Agent replaces it -> only the old one closes.
    let _old = StompAgent::login(addr, "os::stomp-twice").await;
    let _new = StompAgent::login(addr, "os::stomp-twice").await;
    let lines = {
        logs.line(STOMP_CLOSED, "os::stomp-twice").await;
        logs.lines()
            .into_iter()
            .filter(|l| l.contains(STOMP_CLOSED) && l.contains("os::stomp-twice"))
            .collect::<Vec<_>>()
    };
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(reason_of(&lines[0]), "replaced");
    assert_eq!(stomp.connections(), 1);
}

// ---------------------------------------------------------------------------------------------
// WebSocket

const WS_CLOSED: &str = "USP WebSocket closed";

type AgentSocket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

async fn ws_server(ws: WsMtp) -> (WsMtp, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = ws.router();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (ws, addr)
}

fn ws_request(
    addr: SocketAddr,
    eid: &str,
) -> tokio_tungstenite::tungstenite::handshake::client::Request {
    let mut req = format!("ws://{addr}/usp?eid={eid}")
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("sec-websocket-protocol", "v1.usp".parse().unwrap());
    req
}

async fn ws_agent(ws: &WsMtp, addr: SocketAddr, eid: &str) -> AgentSocket {
    let socket = tokio_tungstenite::connect_async(ws_request(addr, eid))
        .await
        .unwrap()
        .0;
    wait_until("the connection to be registered", || {
        ws.last_heard(eid).is_some()
    })
    .await;
    socket
}

/// Waits (up to 10 s) until `cond` holds.
async fn wait_until(what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn a_closed_websocket_connection_says_why() {
    let logs = LogBuf::default();
    let _capture = logs.capture();
    let (tx, _inbound) = mpsc::channel::<Inbound>(64);
    let (ws, addr) = ws_server(WsMtp::new(tx.clone())).await;
    let reason = async |eid: &str| logs.reason(WS_CLOSED, eid).await;

    // Agent sends a Close frame.
    let mut a = ws_agent(&ws, addr, "os::ws-goodbye").await;
    a.close(None).await.unwrap();
    assert_eq!(reason("os::ws-goodbye").await, "agent_closed");

    // TCP end without Close frame -> stream end under an open WebSocket.
    let a = ws_agent(&ws, addr, "os::ws-eof").await;
    drop(a);
    assert_eq!(reason("os::ws-eof").await, "eof");

    // Agent resets the connection.
    let tcp = TcpStream::connect(addr).await.unwrap();
    socket2::SockRef::from(&tcp)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    let (a, _) = tokio_tungstenite::client_async(ws_request(addr, "os::ws-reset"), tcp)
        .await
        .unwrap();
    wait_until("the connection to be registered", || {
        ws.last_heard("os::ws-reset").is_some()
    })
    .await;
    drop(a);
    let line = logs.line(WS_CLOSED, "os::ws-reset").await;
    assert_eq!(reason_of(&line), "reset");
    assert!(line.contains("error="), "{line}");

    // Server asked to close -> Close frame to the Agent.
    let mut a = ws_agent(&ws, addr, "os::ws-kicked").await;
    assert!(ws.disconnect("os::ws-kicked"));
    assert_eq!(reason("os::ws-kicked").await, "closed_by_server");
    assert!(matches!(a.next().await, Some(Ok(Message::Close(_)))));

    // Newer connection of the same Agent replaces it -> only the old one closes.
    let mut old = ws_agent(&ws, addr, "os::ws-twice").await;
    let _new = tokio_tungstenite::connect_async(ws_request(addr, "os::ws-twice"))
        .await
        .unwrap();
    // Old one dropped by the server, no message.
    assert!(!matches!(
        tokio::time::timeout(Duration::from_secs(5), old.next())
            .await
            .unwrap(),
        Some(Ok(Message::Binary(_)))
    ));
    let line = logs.line(WS_CLOSED, "os::ws-twice").await;
    assert_eq!(reason_of(&line), "replaced");
    let lines = logs
        .lines()
        .into_iter()
        .filter(|l| l.contains(WS_CLOSED) && l.contains("os::ws-twice"))
        .count();
    assert_eq!(lines, 1);
    assert_eq!(ws.connections(), 1);
}

#[tokio::test]
async fn a_silent_websocket_agent_is_closed_for_idleness() {
    let logs = LogBuf::default();
    let _capture = logs.capture();
    let (tx, _inbound) = mpsc::channel::<Inbound>(8);
    let (ws, addr) = ws_server(
        WsMtp::new(tx).with_keepalive(Duration::from_millis(100), Duration::from_millis(400)),
    )
    .await;
    // Connected, never polled again -> no Pong, nothing read.
    let _silent = ws_agent(&ws, addr, "os::ws-silent").await;
    assert_eq!(
        logs.reason(WS_CLOSED, "os::ws-silent").await,
        "idle_timeout"
    );
}

#[tokio::test]
#[allow(clippy::result_large_err)]
async fn the_controller_as_websocket_client_says_why_a_connection_closed() {
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    let logs = LogBuf::default();
    let _capture = logs.capture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/usp", listener.local_addr().unwrap());
    let (tx, mut inbound) = mpsc::channel::<Inbound>(16);
    let mtp = WsMtp::new(tx);
    let _handle = mtp.connect_to(
        "proto::agent-ws-srv".into(),
        url,
        "self::dhonomos".into(),
        None,
    );

    // Agent server accepts, then sends a Close frame.
    let (tcp, _) = listener.accept().await.unwrap();
    let mut socket = tokio_tungstenite::accept_hdr_async(tcp, |_: &Request, mut resp: Response| {
        resp.headers_mut()
            .insert("sec-websocket-protocol", HeaderValue::from_static("v1.usp"));
        Ok(resp)
    })
    .await
    .unwrap();
    let opened = tokio::time::timeout(Duration::from_secs(5), inbound.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(opened.opened);
    socket.send(Message::Close(None)).await.unwrap();
    let line = logs
        .line(
            "USP WebSocket closed (Controller as client)",
            "proto::agent-ws-srv",
        )
        .await;
    assert_eq!(reason_of(&line), "agent_closed");
}

// ---------------------------------------------------------------------------------------------
// Embedded MQTT broker

const MQTT_CLOSED: &str = "USP MQTT closed";

struct MqttAgent {
    tcp: TcpStream,
    buf: BytesMut,
}

impl MqttAgent {
    async fn connect(addr: SocketAddr, eid: &str, keep_alive: u16) -> Self {
        let mut props = ConnectProperties::new();
        props.user_properties = vec![("usp-endpoint-id".into(), eid.into())];
        let mut a = Self {
            tcp: TcpStream::connect(addr).await.unwrap(),
            buf: BytesMut::new(),
        };
        a.send(Packet::Connect(
            Connect {
                keep_alive,
                client_id: format!("c-{eid}"),
                clean_start: true,
                properties: Some(props),
            },
            None,
            None,
        ))
        .await;
        let Some(Packet::ConnAck(_)) = a.next().await else {
            panic!("expected a CONNACK");
        };
        a
    }

    async fn send(&mut self, p: Packet) {
        let mut b = BytesMut::new();
        p.write(&mut b, None).unwrap();
        self.tcp.write_all(&b).await.unwrap();
    }

    /// Next packet; `None` -> broker closed the connection.
    async fn next(&mut self) -> Option<Packet> {
        use rumqttc::v5::mqttbytes::Error;
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            match Packet::read(&mut self.buf, Some(1 << 20)) {
                Ok(p) => return Some(p),
                Err(Error::InsufficientBytes(_)) => {}
                Err(e) => panic!("unreadable packet from the broker: {e}"),
            }
            match tokio::time::timeout(Duration::from_secs(5), self.tcp.read(&mut chunk))
                .await
                .expect("nothing from the broker")
            {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }
}

async fn mqtt_broker() -> (MqttBrokerMtp, SocketAddr, mpsc::Receiver<Inbound>) {
    let (tx, inbound) = mpsc::channel(64);
    let broker = MqttBrokerMtp::new(tx, MqttBrokerConfig::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = broker.clone();
    tokio::spawn(async move {
        serving
            .serve(listener, None, std::future::pending())
            .await
            .unwrap()
    });
    (broker, addr, inbound)
}

#[tokio::test]
async fn a_closed_mqtt_connection_says_why() {
    let logs = LogBuf::default();
    let _capture = logs.capture();
    let (broker, addr, _inbound) = mqtt_broker().await;
    let reason = async |eid: &str| logs.reason(MQTT_CLOSED, eid).await;

    // Agent says goodbye.
    let mut a = MqttAgent::connect(addr, "os::mqtt-goodbye", 60).await;
    a.send(Packet::Disconnect(Disconnect::new(
        DisconnectReasonCode::NormalDisconnection,
    )))
    .await;
    assert_eq!(reason("os::mqtt-goodbye").await, "agent_closed");

    // Agent TCP connection ends, nothing said.
    let a = MqttAgent::connect(addr, "os::mqtt-eof", 60).await;
    drop(a);
    assert_eq!(reason("os::mqtt-eof").await, "eof");

    // Agent resets the connection -> error logged too.
    let a = MqttAgent::connect(addr, "os::mqtt-reset", 60).await;
    reset(a.tcp);
    let line = logs.line(MQTT_CLOSED, "os::mqtt-reset").await;
    assert_eq!(reason_of(&line), "reset");
    assert!(line.contains("error="), "{line}");

    // Protocol error: 2nd CONNECT.
    let mut a = MqttAgent::connect(addr, "os::mqtt-protocol", 60).await;
    a.send(Packet::Connect(
        Connect {
            keep_alive: 60,
            client_id: "again".into(),
            clean_start: true,
            properties: None,
        },
        None,
        None,
    ))
    .await;
    let line = logs.line(MQTT_CLOSED, "os::mqtt-protocol").await;
    assert_eq!(reason_of(&line), "protocol_error");
    assert!(line.contains("a second CONNECT"), "{line}");

    // Not a packet (reserved packet type).
    let mut a = MqttAgent::connect(addr, "os::mqtt-garbage", 60).await;
    a.tcp.write_all(&[0x00, 0x00]).await.unwrap();
    assert_eq!(reason("os::mqtt-garbage").await, "bad_frame");

    // Silent for 1.5x Keep Alive.
    let _quiet = MqttAgent::connect(addr, "os::mqtt-quiet", 1).await;
    assert_eq!(reason("os::mqtt-quiet").await, "idle_timeout");

    // Server asked to close it.
    let _a = MqttAgent::connect(addr, "os::mqtt-kicked", 60).await;
    assert!(broker.disconnect("os::mqtt-kicked"));
    assert_eq!(reason("os::mqtt-kicked").await, "closed_by_server");

    // Newer connection of the same Agent replaces it -> only the old one closes.
    let mut old = MqttAgent::connect(addr, "os::mqtt-twice", 60).await;
    let _new = MqttAgent::connect(addr, "os::mqtt-twice", 60).await;
    let Some(Packet::Disconnect(d)) = old.next().await else {
        panic!("the old connection is told");
    };
    assert_eq!(d.reason_code, DisconnectReasonCode::SessionTakenOver);
    let lines: Vec<_> = {
        logs.line(MQTT_CLOSED, "os::mqtt-twice").await;
        logs.lines()
            .into_iter()
            .filter(|l| l.contains(MQTT_CLOSED) && l.contains("os::mqtt-twice"))
            .collect()
    };
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(reason_of(&lines[0]), "replaced");
    assert_eq!(broker.connections(), 1);
}
