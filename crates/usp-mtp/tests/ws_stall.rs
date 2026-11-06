//! WebSocket MTP: Agent stops reading -> only its own connection stalls.
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use dhonomos_usp_mtp::{Inbound, WsMtp};
use futures_util::StreamExt as _;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

fn request(
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

#[tokio::test]
async fn an_agent_that_stops_reading_does_not_hold_up_others_and_is_closed() {
    let (tx, mut inbound) = mpsc::channel::<Inbound>(256);
    let ws = WsMtp::new(tx).with_write_timeout(Duration::from_millis(500));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = ws.router();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    // Stuck Agent: 4 KiB receive buffer, never reads.
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    socket.connect(&addr.into()).unwrap();
    socket.set_nonblocking(true).unwrap();
    let tcp = TcpStream::from_std(socket.into()).unwrap();
    let (_stuck, _) = tokio_tungstenite::client_async(request(addr, "os::stuck"), tcp)
        .await
        .unwrap();
    let (mut fine, _) = tokio_tungstenite::connect_async(request(addr, "os::fine"))
        .await
        .unwrap();
    while ws.connections() < 2 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Records until path to Agent + its queue are full; sends do not wait.
    let started = Instant::now();
    let mut sent = 0;
    let mut refused = None;
    for _ in 0..200 {
        match ws.send("os::stuck", vec![0u8; 256 << 10]).await {
            Ok(_) => sent += 1,
            Err(e) => {
                refused = Some(e.to_string());
                break;
            }
        }
        // -> connection task writes what it can.
        tokio::task::yield_now().await;
    }
    let refused = refused.expect("the queue of a stalled Agent fills up");
    assert!(refused.contains("queue full"), "{refused}");
    assert!(sent >= 5, "{sent} Records queued");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{sent} sends took {:?}",
        started.elapsed()
    );

    // Other Agent still served meanwhile.
    ws.send("os::fine", vec![1, 2, 3]).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), fine.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(got.into_data().as_ref(), [1, 2, 3]);

    // Record write > write timeout + 1 s per 128 KiB -> stalled connection closed,
    // Controller told.
    let closed = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let i = inbound.recv().await.unwrap();
            if i.closed {
                break i;
            }
        }
    })
    .await
    .expect("the stalled connection was not closed");
    assert_eq!(closed.reply_to.as_deref(), Some("ws:os::stuck"));
    assert_eq!(ws.connections(), 1);
    assert!(ws.send("os::stuck", vec![1]).await.is_err());
    ws.send("os::fine", vec![4]).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), fine.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(got.into_data().as_ref(), [4]);
}
