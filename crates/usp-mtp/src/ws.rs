//! WebSocket MTP, Controller as server (US-05).
//! Agent -> `/usp?eid=<EndpointID>`, subprotocol `v1.usp`, Records in binary frames.
//!
//! wss + client cert -> cert `urn:bbf:usp:id:` subjectAltName must name the `eid` (US-08).
//! Revoked cert (SHA-256 fingerprint, [`WsMtp::set_revoked`]) -> refused, its connections closed.
//!
//! No client cert = only a claim -> never replaces a live connection with cert (409 Conflict).
//! Connection with cert -> replaces any.
//! Anonymous Agents allowed? Operator choice (`--usp-ws-client-cert`, `--usp-ws-allow-anonymous`).
//! EndpointID with issued cert -> connections without cert refused (403), any way in
//! ([`WsMtp::set_certificate_bound`]).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::Extension;
use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::close::{Cause, CloseReason, CloseSignal};
use crate::heard::{Closed, Heard};
use crate::identity::{CertPolicy, ClientCert, Refusal};
use crate::{Inbound, MtpError, SEND_QUEUE, enqueue, valid_eid, write_within};

/// Address prefix of WebSocket connections in `Inbound::reply_to`.
pub const WS_PREFIX: &str = "ws:";

/// Ping interval per connected Agent.
pub const DEFAULT_PING_INTERVAL: Duration = Duration::from_secs(30);

/// Max Agent silence (no frame of any kind, pongs incl.) -> then close.
/// Agent without power never closes its socket.
pub const DEFAULT_IDLE_LIMIT: Duration = Duration::from_secs(90);

#[derive(Debug)]
struct Conn {
    /// Serial. Taken under the conns lock -> grows in register order, never reused.
    id: u64,
    tx: mpsc::Sender<Bytes>,
    /// SHA-256 of the Agent TLS client cert.
    fingerprint: Option<String>,
    /// Source address (Agents connecting in).
    peer: Option<std::net::IpAddr>,
    /// Close + reason.
    close: Arc<CloseSignal>,
    /// Last time the Agent sent anything.
    heard: Arc<Heard>,
}

type Conns = Arc<Mutex<HashMap<String, Conn>>>;

/// New connection state: ID, send queue of Records, close signal, stamp (task updates it
/// per received frame), [`Inbound`] for the Controller if it replaced one.
/// That [`Inbound`] -> delivered by the task (WebSocket connection takes Records at once).
type Registered = (
    u64,
    mpsc::Receiver<Bytes>,
    Arc<CloseSignal>,
    Arc<Heard>,
    Option<Inbound>,
);

/// WebSocket MTP endpoint. Cheap clone.
#[derive(Debug, Clone)]
pub struct WsMtp {
    conns: Conns,
    inbound: mpsc::Sender<Inbound>,
    next: Arc<std::sync::atomic::AtomicU64>,
    /// EndpointIDs that need a client cert + revoked client certs.
    policy: CertPolicy,
    /// Last-heard time of Agents of just-closed connections.
    closed: Closed,
    pub(crate) ping_interval: Duration,
    pub(crate) idle_limit: Duration,
    /// Max write time to an Agent without progress -> then close.
    pub(crate) write_timeout: Duration,
}

impl WsMtp {
    /// Records from any connection -> `inbound`.
    pub fn new(inbound: mpsc::Sender<Inbound>) -> Self {
        Self {
            conns: Arc::default(),
            inbound,
            next: Arc::default(),
            policy: CertPolicy::default(),
            closed: Closed::default(),
            ping_interval: DEFAULT_PING_INTERVAL,
            idle_limit: DEFAULT_IDLE_LIMIT,
            write_timeout: crate::WRITE_TIMEOUT,
        }
    }

    /// Set ping interval + max Agent silence before close
    /// (defaults: [`DEFAULT_PING_INTERVAL`], [`DEFAULT_IDLE_LIMIT`]).
    /// For Agent -> Dhonomos connections + Dhonomos -> Agent ones ([`WsMtp::connect_to`]).
    #[must_use]
    pub fn with_keepalive(mut self, ping_interval: Duration, idle_limit: Duration) -> Self {
        self.ping_interval = ping_interval;
        self.idle_limit = idle_limit;
        self
    }

    /// Set max write time of a message to an Agent before close (default 30 s, +1 s per
    /// 128 KiB of a Record).
    /// Agent stops reading -> must not hold its connection + Record queue forever.
    #[must_use]
    pub fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = timeout;
        self
    }

    /// Replace revoked client cert fingerprints (SHA-256, hex) + close connections with one.
    /// Returns count closed.
    pub fn set_revoked(&self, fingerprints: HashSet<String>) -> usize {
        let Ok(conns) = self.conns.lock() else {
            return 0;
        };
        let mut closed = 0;
        for (eid, c) in conns.iter() {
            if c.fingerprint
                .as_ref()
                .is_some_and(|f| fingerprints.contains(f))
            {
                warn!(agent = %eid, "closing a connection made with a revoked certificate");
                c.close.close(CloseReason::Revoked);
                closed += 1;
            }
        }
        // Still under conns lock -> connection registering meanwhile: closed above or sees new set.
        self.policy.replace_revoked(fingerprints);
        closed
    }

    /// Replace EndpointIDs with an issued client cert.
    /// Agent for one of them -> must show a cert naming it, over wss.
    /// Plain `ws://` or wss without cert -> refused (403). Open connections stay.
    pub fn set_certificate_bound(&self, eids: HashSet<String>) {
        self.policy.set_bound(eids);
    }

    /// Router: `GET /usp` (WebSocket upgrade).
    pub fn router(&self) -> Router {
        Router::new()
            .route("/usp", get(upgrade))
            .with_state(self.clone())
    }

    /// Send a Record to the Agent connected as `endpoint_id`: queue it + return.
    /// Agent not reading -> queue full -> call fails at once (stalled writes close the connection).
    /// Returns serial of the connection with the Record (see [`crate::MultiMtp::send`]).
    pub async fn send(&self, endpoint_id: &str, payload: Vec<u8>) -> Result<u64, MtpError> {
        let (tx, serial) = self
            .conns
            .lock()
            .ok()
            .and_then(|c| c.get(endpoint_id).map(|c| (c.tx.clone(), c.id)))
            .ok_or_else(|| {
                MtpError::Unavailable(format!("no WebSocket connection for {endpoint_id}"))
            })?;
        enqueue(&tx, Bytes::from(payload), "ws", endpoint_id)?;
        metrics::counter!("dhonomos_usp_ws_sent_total").increment(1);
        Ok(serial)
    }

    /// Serve `/usp` over TLS until `shutdown` resolves.
    pub async fn serve_tls(
        &self,
        listener: tokio::net::TcpListener,
        tls: tokio_rustls::TlsAcceptor,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> std::io::Result<()> {
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::server::conn::auto;
        use hyper_util::service::TowerToHyperService;
        let router = self.router();
        tokio::pin!(shutdown);
        loop {
            let (stream, remote) = tokio::select! {
                () = &mut shutdown => return Ok(()),
                accepted = listener.accept() => match accepted {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(error = %e, "accept failed");
                        continue;
                    }
                },
            };
            crate::enable_tcp_keepalive(&stream);
            let (tls, router) = (tls.clone(), router.clone());
            tokio::spawn(async move {
                let stream = match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    tls.accept(stream),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        metrics::counter!("dhonomos_usp_ws_tls_handshake_failures_total")
                            .increment(1);
                        dhonomos_common::connection_refused!(
                            "usp_ws",
                            "tls_handshake",
                            remote,
                            error = %e
                        );
                        return;
                    }
                    Err(_) => {
                        dhonomos_common::connection_refused!(
                            "usp_ws",
                            "tls_handshake_timeout",
                            remote
                        );
                        return;
                    }
                };
                let peer = ClientCert::of(stream.get_ref().1);
                let svc = TowerToHyperService::new(
                    router
                        .layer(Extension(PeerCert(peer)))
                        .layer(Extension(ConnectInfo(remote))),
                );
                if let Err(e) = auto::Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(stream), svc)
                    .await
                {
                    debug!(%remote, error = %e, "connection closed with error");
                }
            });
        }
    }

    /// Open Agent connections.
    pub fn connections(&self) -> usize {
        self.conns.lock().map_or(0, |c| c.len())
    }

    /// Source address of Agent `endpoint_id`, while connected to this server.
    pub fn peer_addr(&self, endpoint_id: &str) -> Option<std::net::IpAddr> {
        self.conns
            .lock()
            .ok()
            .and_then(|c| c.get(endpoint_id).and_then(|c| c.peer))
    }

    /// Last frame of any kind (Ping, Pong incl.) from Agent `endpoint_id` on its open connection.
    /// Server pings every Agent -> live one heard at least once per ping interval.
    pub fn last_heard(&self, endpoint_id: &str) -> Option<SystemTime> {
        let heard = self
            .conns
            .lock()
            .ok()
            .and_then(|c| c.get(endpoint_id).map(|c| c.heard.clone()))?;
        Some(heard.get())
    }

    /// Every connected Agent + time of its last frame.
    pub fn heard_from(&self) -> Vec<(String, SystemTime)> {
        let conns: Vec<(String, Arc<Heard>)> = self.conns.lock().map_or_else(
            |_| Vec::new(),
            |c| {
                c.iter()
                    .map(|(e, c)| (e.clone(), c.heard.clone()))
                    .collect()
            },
        );
        conns.into_iter().map(|(e, h)| (e, h.get())).collect()
    }

    /// Last frame time of Agent `endpoint_id` on its last closed connection. Given once
    /// (see [`crate::MultiMtp::take_final_heard`]).
    pub fn take_final_heard(&self, endpoint_id: &str) -> Option<SystemTime> {
        self.closed.take(endpoint_id)
    }

    /// Close connection of `endpoint_id`, if any.
    pub fn disconnect(&self, endpoint_id: &str) -> bool {
        self.conns
            .lock()
            .ok()
            .and_then(|c| {
                c.get(endpoint_id)
                    .map(|c| c.close.close(CloseReason::ClosedByServer))
            })
            .is_some()
    }

    /// New connection + state for its task.
    /// Call under conns lock -> IDs grow in register order.
    fn new_conn(
        &self,
        fingerprint: Option<String>,
        peer: Option<std::net::IpAddr>,
    ) -> (Conn, Registered) {
        let id = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (tx, rx) = mpsc::channel::<Bytes>(SEND_QUEUE);
        let close = Arc::new(CloseSignal::default());
        let heard = Heard::new();
        let conn = Conn {
            id,
            tx,
            fingerprint,
            peer,
            close: close.clone(),
            heard: heard.clone(),
        };
        (conn, (id, rx, close, heard, None))
    }

    /// `conn` in place of the connection of `eid`, if any -> signal for the Controller.
    fn install(&self, conns: &mut HashMap<String, Conn>, eid: &str, conn: Conn) -> Option<Inbound> {
        let serial = conn.id;
        let old = conns.insert(eid.to_owned(), conn);
        metrics::gauge!("dhonomos_usp_ws_connections").set(conns.len() as f64);
        old.map(|old| {
            // Old connection ends by queue close -> reason noted for it.
            old.close.note(CloseReason::Replaced);
            Inbound::replaced("ws", format!("{WS_PREFIX}{eid}"), eid, serial)
        })
    }

    /// New connection for `eid`, replaces any older one (Controller -> Agent connections).
    /// Returns `Registered`. `fingerprint` = Agent client cert, if any.
    /// Returned close signal fires when the connection must close (cert revoked) + reason.
    pub(crate) fn register(
        &self,
        eid: &str,
        fingerprint: Option<String>,
        peer: Option<std::net::IpAddr>,
    ) -> Registered {
        let Ok(mut conns) = self.conns.lock() else {
            return self.new_conn(fingerprint, peer).1;
        };
        let (conn, mut registered) = self.new_conn(fingerprint, peer);
        registered.4 = self.install(&mut conns, eid, conn);
        registered
    }

    /// [`WsMtp::register`] for an Agent that connected in.
    /// Refused: no client cert + live connection with cert (see `may_replace`), or cert revoked.
    /// Check + replace = one step.
    pub(crate) fn register_inbound(
        &self,
        eid: &str,
        fingerprint: Option<String>,
        peer: Option<std::net::IpAddr>,
    ) -> Result<Registered, Refusal> {
        let Ok(mut conns) = self.conns.lock() else {
            return Err(Refusal::Outranked);
        };
        let live = conns.get(eid).and_then(|c| c.fingerprint.as_deref());
        self.policy.admit(live, fingerprint.as_deref())?;
        let (conn, mut registered) = self.new_conn(fingerprint, peer);
        registered.4 = self.install(&mut conns, eid, conn);
        Ok(registered)
    }

    /// [`WsMtp::register_inbound`] would refuse `eid` with cert `fingerprint` (if any) now?
    /// -> upgrade answers 409 before the handshake ends.
    fn would_conflict(&self, eid: &str, fingerprint: Option<&str>) -> bool {
        self.conns.lock().is_ok_and(|conns| {
            let live = conns.get(eid).and_then(|c| c.fingerprint.as_deref());
            self.policy.admit(live, fingerprint).is_err()
        })
    }

    /// Received Record -> Controller.
    pub(crate) async fn deliver(&self, inbound: Inbound) -> Result<(), ()> {
        self.inbound.send(inbound).await.map_err(|_| ())
    }

    /// Drop connection `id`. Not replaced by a newer one -> Controller told the Agent is gone.
    pub(crate) async fn unregister(&self, eid: &str, id: u64) {
        let current = self.conns.lock().ok().and_then(|mut conns| {
            let current = conns.get(eid).is_some_and(|c| c.id == id);
            let removed = if current { conns.remove(eid) } else { None };
            if removed.is_some() {
                metrics::gauge!("dhonomos_usp_ws_connections").set(conns.len() as f64);
            }
            removed
        });
        if let Some(conn) = current {
            // Controller told below -> connection already gone by then.
            self.closed.record(eid, conn.heard.get());
            let _ = self
                .inbound
                .send(Inbound {
                    topic: "ws".into(),
                    reply_to: Some(format!("{WS_PREFIX}{eid}")),
                    payload: Bytes::new(),
                    closed: true,
                    opened: false,
                    sender: Some(eid.to_string()),
                    replaced_by: None,
                })
                .await;
        }
    }
}

/// Client cert of a TLS connection. `None` = none.
#[derive(Debug, Clone)]
struct PeerCert(Option<ClientCert>);

async fn upgrade(
    State(mtp): State<WsMtp>,
    Query(mut q): Query<HashMap<String, String>>,
    peer: Option<Extension<PeerCert>>,
    remote: Option<Extension<ConnectInfo<std::net::SocketAddr>>>,
    ws: WebSocketUpgrade,
) -> Response {
    let peer_addr = remote.map(|Extension(ConnectInfo(a))| a);
    let remote = peer_addr.map(|a| a.ip().to_canonical());
    let Some(eid) = q.remove("eid").filter(|e| !e.is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            "the eid query parameter is required",
        )
            .into_response();
    };
    // EndpointID = registry key + in logs -> nothing odd gets in.
    if !valid_eid(&eid) {
        metrics::counter!("dhonomos_usp_ws_rejected_total").increment(1);
        dhonomos_common::request_refused!(
            "usp_ws",
            "invalid_endpoint_id",
            peer_addr,
            agent = ?dhonomos_common::refusal::clip(&eid)
        );
        return (
            StatusCode::BAD_REQUEST,
            "the eid query parameter is not a valid EndpointID",
        )
            .into_response();
    }
    let peer = peer.and_then(|Extension(PeerCert(p))| p);
    if let Some(p) = &peer
        && !p.ids.contains(&eid)
    {
        metrics::counter!("dhonomos_usp_ws_rejected_total").increment(1);
        dhonomos_common::request_refused!(
            "usp_ws",
            "certificate_mismatch",
            peer_addr,
            agent = %eid,
            certificate = ?p.ids
        );
        return (
            StatusCode::FORBIDDEN,
            "the client certificate is not issued to this EndpointID",
        )
            .into_response();
    }
    // Revoked cert, or no cert for an EndpointID with an issued one (plain ws:// too)
    // -> weaker way in shut.
    if let Err(refusal) = mtp.policy.check(Some(&eid), peer.as_ref()) {
        metrics::counter!("dhonomos_usp_ws_rejected_total").increment(1);
        dhonomos_common::request_refused!(
            "usp_ws",
            refusal.reason(),
            peer_addr,
            agent = %eid
        );
        return (StatusCode::FORBIDDEN, refusal.message()).into_response();
    }
    let fingerprint = peer.map(|p| p.fingerprint);
    // Agent with only a claim must not take over one that proved its EndpointID.
    if mtp.would_conflict(&eid, fingerprint.as_deref()) {
        metrics::counter!("dhonomos_usp_ws_rejected_total").increment(1);
        dhonomos_common::request_refused!(
            "usp_ws",
            Refusal::Outranked.reason(),
            peer_addr,
            agent = %eid
        );
        return (StatusCode::CONFLICT, Refusal::Outranked.message()).into_response();
    }
    // Limit = MQTT MTP (crate::mqtt::MAX_PACKET_SIZE).
    let limit = crate::mqtt::MAX_PACKET_SIZE as usize;
    ws.max_message_size(limit)
        .max_frame_size(limit)
        .protocols(["v1.usp"])
        .on_upgrade(move |socket| serve(mtp, eid, fingerprint, remote, socket))
}

async fn serve(
    mtp: WsMtp,
    eid: String,
    fingerprint: Option<String>,
    remote: Option<std::net::IpAddr>,
    mut socket: WebSocket,
) {
    // Reconnecting Agent replaces its old connection. Except: old has client cert + new has
    // none, or cert revoked meanwhile (race with the checks in `upgrade`).
    let (id, mut rx, close, heard, replaced) = match mtp.register_inbound(&eid, fingerprint, remote)
    {
        Ok(registered) => registered,
        Err(refusal) => {
            metrics::counter!("dhonomos_usp_ws_rejected_total").increment(1);
            dhonomos_common::request_refused!(
                "usp_ws",
                refusal.reason(),
                remote,
                agent = %eid
            );
            let _ = tokio::time::timeout(Duration::from_secs(5), socket.send(Message::Close(None)))
                .await;
            return;
        }
    };
    info!(agent = %eid, remote = %dhonomos_common::refusal::Remote::from(remote), "USP WebSocket connected");
    if let Some(signal) = replaced {
        // Sent on the old connection -> no answer -> tell the Controller.
        let _ = mtp.deliver(signal).await;
    }
    let connected = std::time::Instant::now();
    // Any Agent frame = alive. Pings -> live Agent answers.
    let mut last_heard = tokio::time::Instant::now();
    let mut ping = tokio::time::interval_at(last_heard + mtp.ping_interval, mtp.ping_interval);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let cause: Cause = loop {
        tokio::select! {
            _ = ping.tick() => {
                if last_heard.elapsed() >= mtp.idle_limit {
                    info!(agent = %eid, "no WebSocket traffic from the Agent; closing");
                    // Dead peer may never drain the send buffer -> no wait.
                    let _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        socket.send(Message::Close(None)),
                    )
                    .await;
                    break CloseReason::IdleTimeout.into();
                }
                let frame = socket.send(Message::Ping(Bytes::new()));
                if let Err(cause) = write_within("ws", mtp.write_timeout, 0, frame).await {
                    break cause;
                }
            }
            reason = close.closed() => {
                let frame = socket.send(Message::Close(None));
                let _ = write_within("ws", mtp.write_timeout, 0, frame).await;
                break reason.into();
            }
            out = rx.recv() => match out {
                Some(bytes) => {
                    let len = bytes.len();
                    let record = socket.send(Message::Binary(bytes));
                    if let Err(cause) = write_within("ws", mtp.write_timeout, len, record).await {
                        break cause;
                    }
                }
                None => break close.queue_closed().into(),
            },
            msg = socket.recv() => {
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
    mtp.unregister(&eid, id).await;
    cause.count("ws");
    info!(
        agent = %eid,
        reason = %cause.reason,
        error = cause.error.as_deref(),
        connected_secs = connected.elapsed().as_secs(),
        "USP WebSocket closed"
    );
}

/// WebSocket MTP TLS from PEM text.
/// `client_ca_pem` -> Agents may show client certs of that CA (must, if `require_client_cert`).
pub fn tls_acceptor(
    cert_pem: &str,
    key_pem: &str,
    client_ca_pem: Option<&str>,
    require_client_cert: bool,
) -> Result<tokio_rustls::TlsAcceptor, MtpError> {
    let resolver = dhonomos_pki::tls::CertResolver::from_pem(cert_pem, key_pem)
        .map_err(|e| MtpError::Tls(e.to_string()))?;
    tls_acceptor_with(resolver, client_ca_pem, require_client_cert)
}

/// [`tls_acceptor`] + server cert from `resolver` per new connection,
/// e.g. [`dhonomos_pki::tls::CertResolver`] that follows renewed files.
pub fn tls_acceptor_with(
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
    client_ca_pem: Option<&str>,
    require_client_cert: bool,
) -> Result<tokio_rustls::TlsAcceptor, MtpError> {
    use rustls::server::WebPkiClientVerifier;
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject as _;
    let bad = |e: &dyn std::fmt::Display| MtpError::Tls(e.to_string());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| bad(&e))?;
    let builder = match client_ca_pem {
        Some(ca) => {
            let mut roots = rustls::RootCertStore::empty();
            for c in CertificateDer::pem_slice_iter(ca.as_bytes()) {
                roots.add(c.map_err(|e| bad(&e))?).map_err(|e| bad(&e))?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
            let verifier = if require_client_cert {
                verifier
            } else {
                verifier.allow_unauthenticated()
            };
            builder.with_client_cert_verifier(verifier.build().map_err(|e| bad(&e))?)
        }
        None if require_client_cert => {
            return Err(MtpError::Tls("client certificates need a CA".into()));
        }
        None => builder.with_no_client_auth(),
    };
    let mut config = builder.with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[tokio::test]
    async fn without_a_certificate_a_connection_never_replaces_one_with_a_certificate() {
        let (tx, _inbound) = mpsc::channel(1);
        let ws = WsMtp::new(tx);
        let current = |eid: &str| ws.conns.lock().unwrap().get(eid).map(|c| c.id);

        let (cert_id, ..) = ws
            .register_inbound("os::a", Some("fp".into()), None)
            .unwrap();
        assert_eq!(current("os::a"), Some(cert_id));
        // Claim of the same EndpointID, any number of times -> refused ...
        for _ in 0..3 {
            assert!(ws.register_inbound("os::a", None, None).is_err());
        }
        assert!(ws.would_conflict("os::a", None));
        assert_eq!(current("os::a"), Some(cert_id), "the live connection stays");
        assert_eq!(ws.connections(), 1);
        // ... other EndpointID or any cert -> not refused.
        assert!(!ws.would_conflict("os::b", None));
        assert!(!ws.would_conflict("os::a", Some("renewed")));
        assert!(ws.register_inbound("os::b", None, None).is_ok());
        let (newer_id, ..) = ws
            .register_inbound("os::a", Some("renewed".into()), None)
            .unwrap();
        assert_ne!(newer_id, cert_id);
        assert_eq!(current("os::a"), Some(newer_id));

        // No cert on either side -> newer connection wins.
        let (first, ..) = ws.register_inbound("os::c", None, None).unwrap();
        let (second, ..) = ws.register_inbound("os::c", None, None).unwrap();
        assert_ne!(first, second);
        assert_eq!(current("os::c"), Some(second));
        // Cert takes over from a claim.
        let (third, ..) = ws
            .register_inbound("os::c", Some("fp".into()), None)
            .unwrap();
        assert_eq!(current("os::c"), Some(third));

        // Cert connection gone -> claim may have the EndpointID.
        ws.unregister("os::a", newer_id).await;
        assert!(!ws.would_conflict("os::a", None));
        assert!(ws.register_inbound("os::a", None, None).is_ok());
    }
}
