//! Controller as WebSocket client (US-05). Fake Agent = WebSocket server.
#![allow(clippy::unwrap_used)]

use std::time::Duration;

use dhonomos_usp_mtp::{Inbound, WsMtp};
use futures_util::{SinkExt as _, StreamExt as _};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;

type AgentSocket = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

/// Accept 1 connection + `v1.usp` handshake.
///
/// Also returns `Sec-WebSocket-Extensions` sent by the Controller.
#[allow(clippy::result_large_err)]
async fn accept_usp(listener: &TcpListener) -> (AgentSocket, String) {
    let (tcp, _) = listener.accept().await.unwrap();
    let mut announced = String::new();
    let ws = tokio_tungstenite::accept_hdr_async(tcp, |req: &Request, mut resp: Response| {
        let h = |n: &str| {
            req.headers()
                .get(n)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        };
        assert_eq!(h("sec-websocket-protocol"), "v1.usp");
        announced = h("sec-websocket-extensions");
        resp.headers_mut()
            .insert("sec-websocket-protocol", HeaderValue::from_static("v1.usp"));
        Ok(resp)
    })
    .await
    .unwrap();
    (ws, announced)
}

/// Fake Agent, 1 connection: check handshake, send `hello`.
/// Binary messages got -> `seen`. Close when told.
async fn agent_once(
    listener: &TcpListener,
    seen: mpsc::Sender<(Vec<u8>, String)>,
    close: tokio::sync::oneshot::Receiver<()>,
) {
    let (ws, announced) = accept_usp(listener).await;
    let (mut sink, mut stream) = ws.split();
    sink.send(Message::Binary(b"hello".to_vec().into()))
        .await
        .unwrap();
    tokio::pin!(close);
    loop {
        tokio::select! {
            _ = &mut close => {
                let _ = sink.send(Message::Close(None)).await;
                return;
            }
            msg = stream.next() => match msg {
                Some(Ok(Message::Binary(b))) => seen.send((b.to_vec(), announced.clone())).await.unwrap(),
                Some(Ok(_)) => {}
                _ => return,
            }
        }
    }
}

async fn next(rx: &mut mpsc::Receiver<Inbound>) -> Inbound {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn controller_connects_to_an_agent_server_and_reconnects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/usp", listener.local_addr().unwrap());
    let (inbound_tx, mut inbound) = mpsc::channel(16);
    let mtp = WsMtp::new(inbound_tx);
    let (seen_tx, mut seen) = mpsc::channel(4);

    let (close_tx, close_rx) = tokio::sync::oneshot::channel();
    let agent = {
        let seen_tx = seen_tx.clone();
        async move {
            agent_once(&listener, seen_tx, close_rx).await;
            listener
        }
    };
    let agent = tokio::spawn(agent);
    let handle = mtp.connect_to("proto::agent-ws".into(), url, "self::dhonomos".into(), None);

    // 1st: notice "Agent reachable" (Agent waits for the Controller to speak).
    // Then its Record, same as from an Agent that connected to us.
    let opened = next(&mut inbound).await;
    assert!(opened.opened && opened.payload.is_empty());
    assert_eq!(opened.reply_to.as_deref(), Some("ws:proto::agent-ws"));
    let first = next(&mut inbound).await;
    assert_eq!(
        (first.reply_to.as_deref(), &first.payload[..], first.closed),
        (Some("ws:proto::agent-ws"), &b"hello"[..], false)
    );
    // Records -> same connection, Controller EndpointID announced.
    mtp.send("proto::agent-ws", b"get".to_vec()).await.unwrap();
    let (got, announced) = tokio::time::timeout(Duration::from_secs(5), seen.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"get");
    assert_eq!(announced, r#"bbf-usp-protocol; eid="self::dhonomos""#);
    assert_eq!(mtp.connections(), 1);

    // Agent closes -> Controller hears it + reconnects.
    close_tx.send(()).unwrap();
    let listener = agent.await.unwrap();
    let closed = next(&mut inbound).await;
    assert!(closed.closed);
    let (_close2, close_rx2) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move { agent_once(&listener, seen_tx, close_rx2).await });
    assert!(next(&mut inbound).await.opened, "reconnected");
    let again = next(&mut inbound).await;
    assert_eq!(&again.payload[..], b"hello", "reconnected");

    // Drop handle -> connection closed, Controller hears it.
    drop(handle);
    assert!(next(&mut inbound).await.closed);
    assert_eq!(mtp.connections(), 0);
    assert!(mtp.send("proto::agent-ws", b"x".to_vec()).await.is_err());
}

/// Controller: ping every 100 ms, give up after 400 ms silence.
fn short_keepalive_mtp() -> (WsMtp, mpsc::Receiver<Inbound>) {
    let (tx, inbound) = mpsc::channel(16);
    let mtp = WsMtp::new(tx).with_keepalive(Duration::from_millis(100), Duration::from_millis(400));
    (mtp, inbound)
}

#[tokio::test]
async fn silent_agent_server_is_given_up_on_and_unregistered() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/usp", listener.local_addr().unwrap());
    let (mtp, mut inbound) = short_keepalive_mtp();
    let handle = mtp.connect_to("proto::dead".into(), url, "self::dhonomos".into(), None);

    // Agent: handshake, then never reads or answers (= power lost, socket still open).
    let (_silent, _) = accept_usp(&listener).await;
    assert!(next(&mut inbound).await.opened);
    assert_eq!(mtp.connections(), 1);

    let started = std::time::Instant::now();
    let closed = next(&mut inbound).await;
    assert!(closed.closed);
    assert_eq!(closed.reply_to.as_deref(), Some("ws:proto::dead"));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(mtp.connections(), 0);
    assert!(mtp.send("proto::dead", b"x".to_vec()).await.is_err());
    drop(handle);
}

#[tokio::test]
async fn responsive_agent_server_outlives_the_idle_limit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/usp", listener.local_addr().unwrap());
    let (mtp, mut inbound) = short_keepalive_mtp();
    let (seen_tx, _seen) = mpsc::channel(4);
    let (_close_tx, close_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move { agent_once(&listener, seen_tx, close_rx).await });
    let _handle = mtp.connect_to("proto::alive".into(), url, "self::dhonomos".into(), None);

    assert!(next(&mut inbound).await.opened);
    assert_eq!(&next(&mut inbound).await.payload[..], b"hello");
    // Agent silent, but polling its stream answers pings with pongs
    // -> well past idle limit: connection still up, no close reported.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(mtp.connections(), 1);
    assert!(inbound.try_recv().is_err(), "no closed notice");
}
