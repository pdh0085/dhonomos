//! WebSocket MTP, Controller as client (US-05), for Agents with a WebSocket server.
//! Controller connects out: `ws://` or `wss://`, subprotocol `v1.usp`,
//! own EID in the `bbf-usp-protocol` extension.
//! Connection kept open; reconnect with backoff.
//! Records flow = Agents that connect in.

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt as _, StreamExt as _};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::{debug, info, warn};

use crate::close::{Cause, CloseReason};
use crate::ws::{WS_PREFIX, WsMtp};
use crate::{Inbound, MtpError, write_within};

/// Max wait between connection attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// TLS for outgoing `wss://`: system store + extra CA certificates (PEM),
/// e.g. the CA of the Agent certificates.
pub fn client_tls(extra_ca_pem: Option<&str>) -> Result<Arc<rustls::ClientConfig>, MtpError> {
    use rustls_pki_types::pem::PemObject as _;
    let bad = |e: &dyn std::fmt::Display| MtpError::Tls(e.to_string());
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if let Some(pem) = extra_ca_pem {
        for cert in rustls_pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots.add(cert.map_err(|e| bad(&e))?).map_err(|e| bad(&e))?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| bad(&e))?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

/// Drop -> client stops, connection closed, Controller told the Agent is gone.
#[derive(Debug)]
pub struct ClientHandle(Option<tokio::sync::watch::Sender<bool>>);

impl Drop for ClientHandle {
    fn drop(&mut self) {
        if let Some(stop) = self.0.take() {
            let _ = stop.send(true);
        }
    }
}

impl WsMtp {
    /// Keep a connection to Agent `endpoint_id` at `url` until the handle is dropped.
    ///
    /// `controller_eid` -> sent to the Agent. `tls` needed for `wss://`.
    /// Agent pinged; silent connection -> closed + re-made, as for Agents that connect in
    /// (see [`WsMtp::with_keepalive`]).
    pub fn connect_to(
        &self,
        endpoint_id: String,
        url: String,
        controller_eid: String,
        tls: Option<Arc<rustls::ClientConfig>>,
    ) -> ClientHandle {
        let mtp = self.clone();
        let (stop_tx, mut stop) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            loop {
                let started = Instant::now();
                let attempt = tokio::select! {
                    r = connect(&url, &controller_eid, tls.clone()) => r,
                    _ = stop.changed() => return,
                };
                match attempt {
                    Ok(socket) => {
                        info!(agent = %endpoint_id, %url, "USP WebSocket connected (Controller as client)");
                        let connected = Instant::now();
                        let (stopped, cause) = run(&mtp, &endpoint_id, socket, &mut stop).await;
                        cause.count("ws_client");
                        info!(
                            agent = %endpoint_id,
                            reason = %cause.reason,
                            error = cause.error.as_deref(),
                            connected_secs = connected.elapsed().as_secs(),
                            "USP WebSocket closed (Controller as client)"
                        );
                        if stopped {
                            return;
                        }
                    }
                    Err(e) => {
                        metrics::counter!("dhonomos_usp_ws_client_failures_total").increment(1);
                        debug!(agent = %endpoint_id, %url, error = %e, "connecting to the Agent failed");
                    }
                }
                // Long-lived connection -> backoff reset.
                if started.elapsed() > MAX_BACKOFF {
                    backoff = Duration::from_secs(1);
                }
                tokio::select! {
                    () = tokio::time::sleep(backoff) => {}
                    _ = stop.changed() => return,
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        });
        ClientHandle(Some(stop_tx))
    }
}

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

async fn connect(
    url: &str,
    controller_eid: &str,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> Result<Socket, MtpError> {
    let fail = |e: &dyn std::fmt::Display| MtpError::Unavailable(e.to_string());
    let mut request = url.into_client_request().map_err(|e| fail(&e))?;
    let headers = request.headers_mut();
    headers.insert("sec-websocket-protocol", HeaderValue::from_static("v1.usp"));
    let ext = format!("bbf-usp-protocol; eid=\"{controller_eid}\"");
    headers.insert(
        "sec-websocket-extensions",
        HeaderValue::from_str(&ext).map_err(|e| fail(&e))?,
    );
    let uri = request.uri().clone();
    let host = uri
        .host()
        .ok_or_else(|| fail(&"URL has no host"))?
        .to_owned();
    let secure = uri.scheme_str() == Some("wss");
    let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
    let tcp = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect((host.trim_matches(['[', ']']), port)),
    )
    .await
    .map_err(|_| fail(&"connect timed out"))?
    .map_err(|e| fail(&e))?;
    crate::enable_tcp_keepalive(&tcp);
    let connector = match (secure, tls) {
        (true, Some(cfg)) => Some(tokio_tungstenite::Connector::Rustls(cfg)),
        (true, None) => return Err(MtpError::Tls("wss:// needs a TLS configuration".into())),
        (false, _) => Some(tokio_tungstenite::Connector::Plain),
    };
    // Limit = MQTT MTP + WebSocket server.
    let limit = crate::mqtt::MAX_PACKET_SIZE as usize;
    let config = WebSocketConfig::default()
        .max_message_size(Some(limit))
        .max_frame_size(Some(limit));
    let (socket, response) = tokio::time::timeout(
        Duration::from_secs(15),
        tokio_tungstenite::client_async_tls_with_config(request, tcp, Some(config), connector),
    )
    .await
    .map_err(|_| fail(&"WebSocket handshake timed out"))?
    .map_err(|e| fail(&e))?;
    let protocol = response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok());
    if protocol != Some("v1.usp") {
        return Err(fail(&format!(
            "the Agent did not accept the v1.usp subprotocol ({protocol:?})"
        )));
    }
    Ok(socket)
}

/// Serve one connection -> (stopped by the client?, close cause).
async fn run(
    mtp: &WsMtp,
    eid: &str,
    socket: Socket,
    stop: &mut tokio::sync::watch::Receiver<bool>,
) -> (bool, Cause) {
    let (id, mut rx, close, heard, replaced) = mtp.register(eid, None, None);
    if let Some(signal) = replaced {
        let _ = mtp.deliver(signal).await;
    }
    // Agent (server) waits for the Controller -> tell the Controller the Agent is reachable.
    let _ = mtp
        .deliver(Inbound {
            topic: "ws".into(),
            reply_to: Some(format!("{WS_PREFIX}{eid}")),
            payload: bytes::Bytes::new(),
            closed: false,
            opened: true,
            sender: Some(eid.to_string()),
            replaced_by: None,
        })
        .await;
    let (mut sink, mut stream) = socket.split();
    let mut stopped = false;
    // Any frame from the Agent = alive. Pings -> a live Agent answers.
    let mut last_heard = tokio::time::Instant::now();
    let mut ping = tokio::time::interval_at(last_heard + mtp.ping_interval, mtp.ping_interval);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let cause: Cause = loop {
        tokio::select! {
            _ = ping.tick() => {
                if last_heard.elapsed() >= mtp.idle_limit {
                    info!(agent = %eid, "no WebSocket traffic from the Agent; closing");
                    // Dead peer may never drain the send buffer -> bounded wait.
                    let _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        sink.send(Message::Close(None)),
                    )
                    .await;
                    break CloseReason::IdleTimeout.into();
                }
                let frame = sink.send(Message::Ping(bytes::Bytes::new()));
                if let Err(cause) = write_within("ws", mtp.write_timeout, 0, frame).await {
                    break cause;
                }
            }
            _ = stop.changed() => {
                let frame = sink.send(Message::Close(None));
                let _ = write_within("ws", mtp.write_timeout, 0, frame).await;
                stopped = true;
                break CloseReason::ClosedByServer.into();
            }
            out = rx.recv() => match out {
                Some(bytes) => {
                    let len = bytes.len();
                    let record = sink.send(Message::Binary(bytes));
                    if let Err(cause) = write_within("ws", mtp.write_timeout, len, record).await {
                        break cause;
                    }
                }
                None => break close.queue_closed().into(),
            },
            msg = stream.next() => {
                if matches!(msg, Some(Ok(_))) {
                    last_heard = tokio::time::Instant::now();
                    heard.touch();
                }
                match msg {
                    Some(Ok(Message::Binary(payload))) => {
                        metrics::counter!("dhonomos_usp_ws_received_total").increment(1);
                        let inbound = Inbound {
                            topic: "ws".into(),
                            reply_to: Some(format!("{WS_PREFIX}{eid}")),
                            payload,
                            closed: false,
                            opened: false,
                            sender: Some(eid.to_string()),
                            replaced_by: None,
                        };
                        if mtp.deliver(inbound).await.is_err() {
                            break CloseReason::DeliveryFailed.into();
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        let frame = sink.send(Message::Pong(p));
                        if let Err(cause) = write_within("ws", mtp.write_timeout, 0, frame).await {
                            break cause;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break CloseReason::AgentClosed.into(),
                    Some(Ok(Message::Text(_))) => warn!(agent = %eid, "text frame ignored (USP uses binary frames)"),
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        debug!(agent = %eid, error = %e, "WebSocket error");
                        break Cause::read_chain(&e);
                    }
                }
            }
        }
    };
    mtp.unregister(eid, id).await;
    (stopped, cause)
}
