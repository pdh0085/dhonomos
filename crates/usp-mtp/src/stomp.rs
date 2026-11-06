//! STOMP MTP, Controller = broker (US-06, ADR-092).
//! Agent -> Dhonomos with STOMP 1.2 -> own destination in `CONNECTED` (`subscribe-dest`).
//! Agent sends Records to the Controller destination, gets its own as `MESSAGE` frames.
//!
//! Only what USP needs: `STOMP`/`CONNECT` (with USP `endpoint-id` header), `SUBSCRIBE`,
//! `UNSUBSCRIBE`, `SEND`, `DISCONNECT`, heart-beats. Transactions + acks refused.
//! Nothing stored: Record for an Agent not connected = error.
//!
//! Connection `endpoint-id` = sender the MTP vouches for.
//! TLS + client cert -> must be that EndpointID (`urn:bbf:usp:id:` SAN).
//! No cert -> never replaces a live connection of the same EndpointID with cert.
//! EndpointID with issued cert ([`StompMtp::set_certificate_bound`]) -> refused without cert.
//! Revoked cert ([`StompMtp::set_revoked`]) -> refused, its connections closed.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::close::{Cause, CloseReason, CloseSignal};
use crate::connlimit::{ConnLimiter, ConnPermit};
use crate::heard::{Closed, Heard, Sock, sock_of};
use crate::identity::{CertPolicy, ClientCert, Refusal};
use crate::{Inbound, MtpError, SEND_QUEUE, enqueue, valid_eid, write_all_within};

/// Address prefix of STOMP connections in `Inbound::reply_to`.
pub const STOMP_PREFIX: &str = "stomp:";

/// USP STOMP content type (TR-369).
pub const USP_CONTENT_TYPE: &str = "application/vnd.bbf.usp.msg";

/// Max frame from an authenticated Agent (= MQTT MTP).
const MAX_FRAME: usize = crate::mqtt::MAX_PACKET_SIZE as usize;

/// Max frame before login. `STOMP`/`CONNECT` ~ few 100 bytes; sender = anyone who reaches the port.
const MAX_PRE_AUTH_FRAME: usize = 8 * 1024;

/// Max command + header block from an authenticated Agent. Bodies big (Records), headers never.
const MAX_HEAD: usize = 16 * 1024;

/// Max headers per frame. Each -> 2 heap strings.
const MAX_HEADERS: usize = 64;

/// Max time for a new connection to send its `STOMP`/`CONNECT` frame.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Broker settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StompConfig {
    /// Shared first-contact account (`login`/`passcode`). `None` -> any client.
    pub login: Option<(String, String)>,
    /// Agents send Records here (their `Controller.{i}.MTP.{i}.STOMP.Destination`).
    pub controller_dest: String,
    /// Agent destination = this + its EndpointID (`subscribe-dest`).
    pub agent_dest_prefix: String,
    /// Broker heart-beat offer, both ways, ms (0 = none).
    pub heartbeat_ms: u32,
    /// Max open connections; more -> closed at accept. 0 = unlimited.
    pub max_connections: usize,
    /// Max open connections per address (IPv6: /64); more -> closed at accept. 0 = unlimited.
    pub max_connections_per_ip: usize,
    /// Max write time without progress (writes of 64 KiB each) -> then close.
    /// Agent stops reading -> must not hold its connection + Record queue forever.
    pub write_timeout: Duration,
}

impl Default for StompConfig {
    fn default() -> Self {
        Self {
            login: None,
            controller_dest: "/queue/usp.controller".into(),
            agent_dest_prefix: "/queue/usp.agent.".into(),
            heartbeat_ms: 30_000,
            max_connections: 20_000,
            max_connections_per_ip: 256,
            write_timeout: crate::WRITE_TIMEOUT,
        }
    }
}

/// One STOMP frame.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Frame {
    /// Command, e.g. `SEND`.
    pub command: String,
    /// Headers in order. Repeated header -> first value counts.
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

/// Result of a buffer read.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// Whole frame + bytes used.
    Frame(Frame, usize),
    /// Heart-beat EOLs before a frame -> skip.
    Heartbeat(usize),
    /// Need more bytes.
    Incomplete,
}

impl Frame {
    /// Frame with `command` + headers.
    pub fn new(command: &str, headers: &[(&str, &str)]) -> Self {
        Self {
            command: command.into(),
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            body: Bytes::new(),
        }
    }

    /// First value of header `name`.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// `CONNECT` and `CONNECTED` headers are not escaped (STOMP 1.2).
    fn escaped(command: &str) -> bool {
        command != "CONNECT" && command != "CONNECTED"
    }

    /// Wire form. Body -> `content-length` added.
    pub fn encode(&self) -> Vec<u8> {
        let escape = Self::escaped(&self.command);
        let mut out = Vec::with_capacity(self.body.len() + 128);
        out.extend_from_slice(self.command.as_bytes());
        out.push(b'\n');
        for (k, v) in &self.headers {
            if k == "content-length" {
                continue;
            }
            let (k, v) = if escape {
                (escape_header(k), escape_header(v))
            } else {
                (k.clone(), v.clone())
            };
            out.extend_from_slice(k.as_bytes());
            out.push(b':');
            out.extend_from_slice(v.as_bytes());
            out.push(b'\n');
        }
        if !self.body.is_empty() {
            out.extend_from_slice(format!("content-length:{}\n", self.body.len()).as_bytes());
        }
        out.push(b'\n');
        out.extend_from_slice(&self.body);
        out.push(0);
        out
    }

    /// One frame (or heart-beats) from start of `buf`, whole in one go. `max` = limit of
    /// frame + headers.
    /// Connection (frames in pieces) -> [`FrameParser`]: same, no restart per piece.
    pub fn parse(buf: &[u8], max: usize) -> Result<Parsed, String> {
        FrameParser::default().parse(buf, Limits::new(max, max))
    }
}

/// Frame limits: `frame` = whole frame, `head` = command + headers.
#[derive(Debug, Clone, Copy)]
struct Limits {
    frame: usize,
    head: usize,
}

impl Limits {
    const fn new(frame: usize, head: usize) -> Self {
        Self { frame, head }
    }

    /// Before Agent login.
    const PRE_AUTH: Self = Self::new(MAX_PRE_AUTH_FRAME, MAX_PRE_AUTH_FRAME);

    /// After.
    const AUTHENTICATED: Self = Self::new(MAX_FRAME, MAX_HEAD);
}

/// Command + headers of the frame being read, once complete.
#[derive(Debug)]
struct Head {
    frame: Frame,
    /// Body start in the buffer.
    body_start: usize,
    /// `content-length`, if any. Else body ends at first NUL.
    length: Option<usize>,
}

/// Frames from a buffer that grows with each read.
/// Keeps search position + parsed headers -> time linear in frame size, any piece size.
/// Restart per piece -> quadratic time, peer can force a lot of it.
///
/// After [`Parsed::Frame`] or [`Parsed::Heartbeat`]: drain those bytes before next call
/// -> parser ready for next frame.
#[derive(Debug, Default)]
struct FrameParser {
    /// Resume point: search for blank line at header end.
    head_from: usize,
    head: Option<Head>,
    /// Resume point: search for NUL at body end (no `content-length`).
    nul_from: usize,
}

impl FrameParser {
    fn parse(&mut self, buf: &[u8], limits: Limits) -> Result<Parsed, String> {
        if self.head.is_none() {
            // Heart-beats (+ EOLs after a frame NUL) between frames.
            let eols = buf
                .iter()
                .take_while(|b| **b == b'\n' || **b == b'\r')
                .count();
            if eols > 0 {
                *self = Self::default();
                return Ok(Parsed::Heartbeat(eols));
            }
            let Some((head_end, body_start)) = find_blank_line(buf, &mut self.head_from) else {
                if buf.len() > limits.head {
                    return Err("frame headers too large".into());
                }
                return Ok(Parsed::Incomplete);
            };
            if head_end > limits.head {
                return Err("frame headers too large".into());
            }
            let frame = parse_head(&buf[..head_end])?;
            let length = match frame.header("content-length") {
                Some(len) => {
                    let len: usize = len
                        .trim()
                        .parse()
                        .map_err(|_| format!("bad content-length {len:?}"))?;
                    if body_start.saturating_add(len).saturating_add(1) > limits.frame {
                        return Err("frame too large".into());
                    }
                    Some(len)
                }
                None => None,
            };
            self.nul_from = body_start;
            self.head = Some(Head {
                frame,
                body_start,
                length,
            });
        }
        let Some(head) = &self.head else {
            return Ok(Parsed::Incomplete);
        };
        let body_start = head.body_start;
        let body_len = match head.length {
            Some(len) => {
                if buf.len() < body_start + len + 1 {
                    return Ok(Parsed::Incomplete);
                }
                if buf[body_start + len] != 0 {
                    return Err("frame body not followed by NUL".into());
                }
                len
            }
            None => match buf[self.nul_from..].iter().position(|b| *b == 0) {
                Some(n) => {
                    let len = self.nul_from + n - body_start;
                    if body_start + len + 1 > limits.frame {
                        return Err("frame too large".into());
                    }
                    len
                }
                None => {
                    if buf.len() > limits.frame {
                        return Err("frame too large".into());
                    }
                    self.nul_from = buf.len();
                    return Ok(Parsed::Incomplete);
                }
            },
        };
        let Some(Head { mut frame, .. }) = self.head.take() else {
            return Ok(Parsed::Incomplete);
        };
        frame.body = Bytes::copy_from_slice(&buf[body_start..body_start + body_len]);
        *self = Self::default();
        Ok(Parsed::Frame(frame, body_start + body_len + 1))
    }
}

/// Command + headers from `head` (up to end of last header line).
fn parse_head(head: &[u8]) -> Result<Frame, String> {
    let head = std::str::from_utf8(head).map_err(|_| "frame headers are not UTF-8".to_owned())?;
    let mut lines = head.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let command = lines.next().unwrap_or_default().to_owned();
    if command.is_empty() {
        return Err("frame without a command".into());
    }
    let escape = Frame::escaped(&command);
    let mut headers = Vec::new();
    for line in lines {
        if headers.len() >= MAX_HEADERS {
            return Err(format!("more than {MAX_HEADERS} headers"));
        }
        let Some((k, v)) = line.split_once(':') else {
            return Err(format!("malformed header line {line:?}"));
        };
        let (k, v) = if escape {
            (unescape_header(k)?, unescape_header(v)?)
        } else {
            (k.to_owned(), v.to_owned())
        };
        headers.push((k, v));
    }
    Ok(Frame {
        command,
        headers,
        body: Bytes::new(),
    })
}

/// Header block end -> (end of last header line, body start). Search from `*from`.
/// Not found -> `*from` = resume point for more bytes (just before end: blank line may be cut).
fn find_blank_line(buf: &[u8], from: &mut usize) -> Option<(usize, usize)> {
    let mut i = *from;
    while i < buf.len() {
        match buf[i..].iter().position(|b| *b == b'\n') {
            None => break,
            Some(n) => i += n,
        }
        match buf.get(i + 1) {
            Some(b'\n') => return Some((i, i + 2)),
            Some(b'\r') if buf.get(i + 2) == Some(&b'\n') => return Some((i, i + 3)),
            _ => {}
        }
        i += 1;
    }
    *from = buf.len().saturating_sub(2).max(*from);
    None
}

fn escape_header(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            ':' => out.push_str("\\c"),
            c => out.push(c),
        }
    }
    out
}

fn unescape_header(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('c') => out.push(':'),
            other => return Err(format!("undefined escape \\{}", other.unwrap_or(' '))),
        }
    }
    Ok(out)
}

#[derive(Debug)]
struct Conn {
    /// Serial. Taken under the conns lock -> grows in register order, never reused.
    id: u64,
    tx: mpsc::Sender<Bytes>,
    close: Arc<CloseSignal>,
    /// SHA-256 of the Agent TLS client cert.
    fingerprint: Option<String>,
    /// Source address.
    peer: std::net::IpAddr,
    /// Last time the Agent sent anything.
    heard: Arc<Heard>,
}

type Conns = Arc<Mutex<HashMap<String, Conn>>>;

/// New connection state: ID, send queue of Records, close signal, stamp (task updates it
/// per received byte), [`Inbound`] for the Controller if it replaced one.
/// That [`Inbound`] -> delivered after Agent subscribes (before: Records for it dropped).
type Registered = (
    u64,
    mpsc::Receiver<Bytes>,
    Arc<CloseSignal>,
    Arc<Heard>,
    Option<Inbound>,
);

/// Embedded STOMP broker. Cheap clone.
#[derive(Debug, Clone)]
pub struct StompMtp {
    conns: Conns,
    inbound: mpsc::Sender<Inbound>,
    next: Arc<AtomicU64>,
    config: Arc<StompConfig>,
    /// Last-heard time of Agents of just-closed connections.
    closed: Closed,
    /// Open connections, total + per source address.
    limiter: Arc<ConnLimiter>,
    /// EndpointIDs that need a client cert + revoked client certs.
    policy: CertPolicy,
}

impl StompMtp {
    /// Records from Agents -> `inbound`.
    pub fn new(inbound: mpsc::Sender<Inbound>, config: StompConfig) -> Self {
        Self {
            conns: Arc::default(),
            inbound,
            next: Arc::default(),
            limiter: ConnLimiter::new(config.max_connections, config.max_connections_per_ip),
            config: Arc::new(config),
            closed: Closed::default(),
            policy: CertPolicy::default(),
        }
    }

    pub fn config(&self) -> &StompConfig {
        &self.config
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
    /// Agent for one of them -> must show a cert naming it (STOMP over TLS + client cert).
    /// Shared login + plain connections -> refused for it. Open connections stay.
    pub fn set_certificate_bound(&self, eids: HashSet<String>) {
        self.policy.set_bound(eids);
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
                MtpError::Unavailable(format!("no STOMP connection for {endpoint_id}"))
            })?;
        enqueue(&tx, Bytes::from(payload), "stomp", endpoint_id)?;
        metrics::counter!("dhonomos_usp_stomp_sent_total").increment(1);
        Ok(serial)
    }

    /// Source address of Agent `endpoint_id`, while connected.
    pub fn peer_addr(&self, endpoint_id: &str) -> Option<std::net::IpAddr> {
        self.conns
            .lock()
            .ok()
            .and_then(|c| c.get(endpoint_id).map(|c| c.peer))
    }

    /// Last heard from Agent `endpoint_id` on its open connection = later of: last byte sent
    /// (frames, heart-beats), last TCP ack from its stack (Linux).
    /// No heart-beat negotiated -> nothing between Records, but live Agent answers TCP keepalive.
    pub fn last_heard(&self, endpoint_id: &str) -> Option<SystemTime> {
        let heard = self
            .conns
            .lock()
            .ok()
            .and_then(|c| c.get(endpoint_id).map(|c| c.heard.clone()))?;
        Some(heard.get())
    }

    /// Every connected Agent + last heard time (see [`StompMtp::last_heard`]).
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

    /// Last heard time of Agent `endpoint_id` on its last closed connection. Given once
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

    /// Open Agent connections.
    pub fn connections(&self) -> usize {
        self.conns.lock().map_or(0, |c| c.len())
    }

    /// Accept Agents on `listener` (TLS if `tls`) until `shutdown` resolves.
    pub async fn serve(
        &self,
        listener: tokio::net::TcpListener,
        tls: Option<tokio_rustls::TlsAcceptor>,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> std::io::Result<()> {
        tokio::pin!(shutdown);
        loop {
            let (stream, remote) = tokio::select! {
                () = &mut shutdown => return Ok(()),
                accepted = listener.accept() => match accepted {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(error = %e, "STOMP accept failed");
                        continue;
                    }
                },
            };
            // Over a cap -> close at once, before any task or read buffer.
            let permit = match self.limiter.acquire(remote.ip()) {
                Ok(p) => p,
                Err(refused) => {
                    metrics::counter!(
                        "dhonomos_usp_stomp_refused_connections_total",
                        "reason" => refused.reason()
                    )
                    .increment(1);
                    dhonomos_common::connection_refused!("usp_stomp", refused.reason(), remote);
                    continue;
                }
            };
            crate::enable_tcp_keepalive(&stream);
            let sock = sock_of(&stream);
            let (mtp, tls) = (self.clone(), tls.clone());
            tokio::spawn(async move {
                match tls {
                    None => mtp.session(stream, None, remote.ip(), sock, permit).await,
                    Some(tls) => {
                        let stream =
                            match tokio::time::timeout(CONNECT_TIMEOUT, tls.accept(stream)).await {
                                Ok(Ok(s)) => s,
                                Ok(Err(e)) => {
                                    metrics::counter!(
                                        "dhonomos_usp_stomp_tls_handshake_failures_total"
                                    )
                                    .increment(1);
                                    dhonomos_common::connection_refused!(
                                        "usp_stomp",
                                        "tls_handshake",
                                        remote,
                                        error = %e
                                    );
                                    return;
                                }
                                Err(_) => {
                                    dhonomos_common::connection_refused!(
                                        "usp_stomp",
                                        "tls_handshake_timeout",
                                        remote
                                    );
                                    return;
                                }
                            };
                        let cert = ClientCert::of(stream.get_ref().1);
                        mtp.session(stream, cert, remote.ip(), sock, permit).await;
                    }
                }
            });
        }
    }

    /// New connection for `eid`, replaces older one. Except: old has client cert + new has none,
    /// or new cert revoked. Check + replace = one step.
    fn register(
        &self,
        eid: &str,
        peer: std::net::IpAddr,
        fingerprint: Option<String>,
    ) -> Result<Registered, Refusal> {
        let (tx, rx) = mpsc::channel(SEND_QUEUE);
        let close = Arc::new(CloseSignal::default());
        let heard = Heard::new();
        let Ok(mut conns) = self.conns.lock() else {
            return Err(Refusal::Outranked);
        };
        let live = conns.get(eid).and_then(|c| c.fingerprint.as_deref());
        self.policy.admit(live, fingerprint.as_deref())?;
        // Under the lock -> serials grow in register order.
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let replaced = conns.insert(
            eid.to_owned(),
            Conn {
                id,
                tx,
                close: close.clone(),
                fingerprint,
                peer,
                heard: heard.clone(),
            },
        );
        let replaced = replaced.map(|old| {
            // Reconnecting Agent replaces its old connection.
            old.close.close(CloseReason::Replaced);
            Inbound::replaced("stomp", format!("{STOMP_PREFIX}{eid}"), eid, id)
        });
        metrics::gauge!("dhonomos_usp_stomp_connections").set(conns.len() as f64);
        Ok((id, rx, close, heard, replaced))
    }

    /// [`StompMtp::register`] would refuse `eid` with cert `fingerprint` (if any) now?
    /// -> answer `CONNECT` with `ERROR`, not `CONNECTED`.
    fn would_conflict(&self, eid: &str, fingerprint: Option<&str>) -> bool {
        self.conns.lock().is_ok_and(|conns| {
            let live = conns.get(eid).and_then(|c| c.fingerprint.as_deref());
            self.policy.admit(live, fingerprint).is_err()
        })
    }

    async fn unregister(&self, eid: &str, id: u64) {
        let current = self.conns.lock().ok().and_then(|mut conns| {
            let current = conns.get(eid).is_some_and(|c| c.id == id);
            let removed = if current { conns.remove(eid) } else { None };
            if removed.is_some() {
                metrics::gauge!("dhonomos_usp_stomp_connections").set(conns.len() as f64);
            }
            removed
        });
        if let Some(conn) = current {
            // Controller told below -> connection already gone by then.
            // Socket still open here -> its TCP state counts too.
            self.closed.record(eid, conn.heard.get());
            let _ = self
                .inbound
                .send(Inbound {
                    topic: "stomp".into(),
                    reply_to: Some(format!("{STOMP_PREFIX}{eid}")),
                    payload: Bytes::new(),
                    closed: true,
                    opened: false,
                    sender: Some(eid.to_owned()),
                    replaced_by: None,
                })
                .await;
        }
    }

    /// Check `STOMP`/`CONNECT` frame -> Agent EndpointID + heart-beat (`cx,cy`), or refusal.
    fn accept(&self, f: &Frame, cert: Option<&ClientCert>) -> Result<(String, u32, u32), Rejected> {
        if f.command != "STOMP" && f.command != "CONNECT" {
            return Err(Rejected::new(
                "bad_command",
                format!("expected STOMP or CONNECT, got {}", f.command),
            ));
        }
        if !f
            .header("accept-version")
            .is_some_and(|v| v.split(',').any(|v| v.trim() == "1.2"))
        {
            return Err(Rejected::new("bad_version", "only STOMP 1.2 is supported"));
        }
        if let Some((login, passcode)) = &self.config.login {
            let ok = same(f.header("login").unwrap_or_default(), login)
                & same(f.header("passcode").unwrap_or_default(), passcode);
            if !ok {
                return Err(Rejected::new("bad_login", "invalid login or passcode"));
            }
        }
        let eid = f
            .header("endpoint-id")
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .ok_or_else(|| Rejected::new("bad_endpoint_id", "the endpoint-id header is required"))?
            .to_owned();
        if !valid_eid(&eid) {
            return Err(Rejected::new(
                "bad_endpoint_id",
                "the endpoint-id header is not a valid EndpointID",
            ));
        }
        if let Some(c) = cert
            && !c.ids.contains(&eid)
        {
            warn!(agent = %eid, certificate = ?c.ids, "client certificate does not name this EndpointID");
            return Err(Rejected::new(
                "certificate_mismatch",
                "the client certificate is not issued to this EndpointID",
            ));
        }
        // Revoked cert, or no cert for an EndpointID with an issued one -> weaker way in shut.
        if let Err(refusal) = self.policy.check(Some(&eid), cert) {
            warn!(agent = %eid, reason = refusal.reason(), "STOMP connection refused");
            return Err(Rejected::new(refusal.reason(), refusal.message()));
        }
        // Agent with only a claim must not take over one that proved its EndpointID.
        if self.would_conflict(&eid, cert.map(|c| c.fingerprint.as_str())) {
            warn!(agent = %eid, "connection without a client certificate refused: the EndpointID is connected with one");
            return Err(Rejected::new(
                Refusal::Outranked.reason(),
                Refusal::Outranked.message(),
            ));
        }
        let (cx, cy) = f
            .header("heart-beat")
            .and_then(|h| h.split_once(','))
            .and_then(|(a, b)| Some((a.trim().parse().ok()?, b.trim().parse().ok()?)))
            .unwrap_or((0, 0));
        Ok((eid, cx, cy))
    }

    /// Serve one Agent connection.
    ///
    /// `sock` = TCP socket under `stream` (maybe TLS on top).
    /// Kernel view of it (via [`Heard`]) must not outlive `stream`.
    /// `_permit` = connection slot under the caps -> given back at connection end.
    async fn session<S>(
        &self,
        stream: S,
        cert: Option<ClientCert>,
        peer: std::net::IpAddr,
        sock: Sock,
        _permit: ConnPermit,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let mut buf: Vec<u8> = Vec::with_capacity(4096);
        let write_timeout = self.config.write_timeout;
        // 1st frame = STOMP/CONNECT, small: no login yet.
        let mut parser = FrameParser::default();
        let first = tokio::time::timeout(
            CONNECT_TIMEOUT,
            read_frame(&mut rd, &mut buf, &mut parser, Limits::PRE_AUTH),
        )
        .await;
        let first = match first {
            Ok(Ok(Some(f))) => f,
            Ok(Ok(None)) => {
                metrics::counter!("dhonomos_usp_stomp_rejected_total").increment(1);
                dhonomos_common::connection_refused!("usp_stomp", "no_first_frame", peer);
                return;
            }
            _ => return,
        };
        let (eid, cx, cy) = match self.accept(&first, cert.as_ref()) {
            Ok(v) => v,
            Err(why) => {
                metrics::counter!("dhonomos_usp_stomp_rejected_total").increment(1);
                dhonomos_common::request_refused!("usp_stomp", why.reason, peer);
                let frame = error_frame(&why).encode();
                let _ = put(&mut wr, &frame, write_timeout).await;
                return;
            }
        };
        let sx = self.config.heartbeat_ms;
        let send_every = if sx > 0 && cy > 0 { sx.max(cy) } else { 0 };
        let expect_every = if cx > 0 && sx > 0 { cx.max(sx) } else { 0 };
        let agent_dest = format!("{}{eid}", self.config.agent_dest_prefix);
        let heartbeat = format!("{sx},{sx}");
        let connected = Frame::new(
            "CONNECTED",
            &[
                ("version", "1.2"),
                ("heart-beat", heartbeat.as_str()),
                ("server", "Dhonomos"),
                ("subscribe-dest", agent_dest.as_str()),
            ],
        );
        let connected = connected.encode();
        if put(&mut wr, &connected, write_timeout).await.is_err() {
            return;
        }
        let fingerprint = cert.map(|c| c.fingerprint);
        let (id, mut rx, close, heard, mut replaced) =
            match self.register(&eid, peer.to_canonical(), fingerprint) {
                Ok(registered) => registered,
                Err(refusal) => {
                    // Lost race with checks in `accept`: cert revoked, or connection with
                    // cert registered, since then.
                    metrics::counter!("dhonomos_usp_stomp_rejected_total").increment(1);
                    dhonomos_common::request_refused!(
                        "usp_stomp",
                        refusal.reason(),
                        peer,
                        agent = %eid
                    );
                    let frame = error_frame(refusal.message()).encode();
                    let _ = put(&mut wr, &frame, write_timeout).await;
                    let _ = tokio::time::timeout(Duration::from_secs(5), wr.shutdown()).await;
                    return;
                }
            };
        // Dropped (reverse declaration order) before `rd` + `wr` close the socket.
        let _tcp = heard.watch_tcp(sock);
        info!(agent = %eid, remote = %peer, "USP STOMP connected");
        let connected = std::time::Instant::now();
        let mut subscription: Option<(String, String)> = None;
        let mut message_id: u64 = 0;
        let mut beat = tokio::time::interval(Duration::from_millis(u64::from(send_every.max(1))));
        beat.tick().await;
        let idle_limit = Duration::from_millis(u64::from(expect_every) * 2);
        let mut last_heard = tokio::time::Instant::now();
        let mut chunk = vec![0u8; 16 * 1024];
        let cause: Cause = 'conn: loop {
            // Buffered frames first. Logged in here -> Records may be big, headers still not.
            loop {
                match parser.parse(&buf, Limits::AUTHENTICATED) {
                    Ok(Parsed::Heartbeat(n)) => {
                        buf.drain(..n);
                    }
                    Ok(Parsed::Frame(f, n)) => {
                        buf.drain(..n);
                        let reply = self.handle(&eid, &agent_dest, &f, &mut subscription).await;
                        // Agent subscribed -> takes Records now -> tell the Controller of the
                        // replace (sent on the old one = lost).
                        // Earlier -> Record sent in reaction dropped (no subscription yet).
                        if subscription.is_some()
                            && let Some(signal) = replaced.take()
                        {
                            let _ = self.inbound.send(signal).await;
                        }
                        match reply {
                            Reply::None => {}
                            Reply::Frame(r) => {
                                let r = r.encode();
                                if let Err(e) = put(&mut wr, &r, write_timeout).await {
                                    break 'conn Cause::write(&e);
                                }
                            }
                            Reply::Close(r, cause) => {
                                if let Some(r) = r {
                                    let r = r.encode();
                                    let _ = put(&mut wr, &r, write_timeout).await;
                                }
                                break 'conn cause;
                            }
                        }
                    }
                    Ok(Parsed::Incomplete) => break,
                    Err(why) => {
                        metrics::counter!("dhonomos_usp_stomp_rejected_total").increment(1);
                        dhonomos_common::request_refused!(
                            "usp_stomp",
                            "bad_frame",
                            peer,
                            agent = %eid,
                            error = %why
                        );
                        let r = error_frame(&why).encode();
                        let _ = put(&mut wr, &r, write_timeout).await;
                        break 'conn Cause::because(CloseReason::BadFrame, &why);
                    }
                }
            }
            tokio::select! {
                reason = close.closed() => break reason.into(),
                read = rd.read(&mut chunk) => match read {
                    Ok(0) => break CloseReason::Eof.into(),
                    Err(e) => break Cause::read(&e),
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        last_heard = tokio::time::Instant::now();
                        heard.touch();
                    }
                },
                out = rx.recv() => {
                    let Some(payload) = out else { break close.queue_closed().into() };
                    let Some((sub, dest)) = &subscription else {
                        warn!(agent = %eid, "Record for an Agent that has not subscribed dropped");
                        continue;
                    };
                    message_id += 1;
                    let id = message_id.to_string();
                    let mut m = Frame::new("MESSAGE", &[
                        ("subscription", sub.as_str()),
                        ("message-id", id.as_str()),
                        ("destination", dest.as_str()),
                        ("content-type", USP_CONTENT_TYPE),
                        ("reply-to-dest", self.config.controller_dest.as_str()),
                    ]);
                    m.body = payload;
                    let m = m.encode();
                    if let Err(e) = put(&mut wr, &m, write_timeout).await {
                        break Cause::write(&e);
                    }
                }
                _ = beat.tick(), if send_every > 0 => {
                    if let Err(e) = put(&mut wr, b"\n", write_timeout).await {
                        break Cause::write(&e);
                    }
                }
                () = tokio::time::sleep_until(last_heard + idle_limit), if expect_every > 0 => {
                    debug!(agent = %eid, "no STOMP heart-beat from the Agent; closing");
                    break CloseReason::IdleTimeout.into();
                }
            }
        };
        // Peer that stopped reading may never take the close either.
        let _ = tokio::time::timeout(Duration::from_secs(5), wr.shutdown()).await;
        self.unregister(&eid, id).await;
        cause.count("stomp");
        info!(
            agent = %eid,
            reason = %cause.reason,
            error = cause.error.as_deref(),
            connected_secs = connected.elapsed().as_secs(),
            "USP STOMP closed"
        );
    }

    /// Handle one frame after connection setup.
    async fn handle(
        &self,
        eid: &str,
        agent_dest: &str,
        f: &Frame,
        subscription: &mut Option<(String, String)>,
    ) -> Reply {
        let receipt = |f: &Frame| {
            f.header("receipt")
                .map(|r| Frame::new("RECEIPT", &[("receipt-id", r)]))
        };
        // Protocol rule broken -> ERROR frame to the peer, then close.
        let refuse = |message: &str| {
            Reply::Close(
                Some(error_frame(message)),
                Cause::because(CloseReason::ProtocolError, message),
            )
        };
        match f.command.as_str() {
            "SEND" => {
                if f.header("destination") != Some(self.config.controller_dest.as_str()) {
                    return refuse("unknown destination");
                }
                if f.header("content-type") != Some(USP_CONTENT_TYPE) {
                    return refuse(&format!("content-type must be {USP_CONTENT_TYPE}"));
                }
                metrics::counter!("dhonomos_usp_stomp_received_total").increment(1);
                let inbound = Inbound {
                    topic: self.config.controller_dest.clone(),
                    reply_to: Some(format!("{STOMP_PREFIX}{eid}")),
                    payload: f.body.clone(),
                    closed: false,
                    opened: false,
                    sender: Some(eid.to_owned()),
                    replaced_by: None,
                };
                if self.inbound.send(inbound).await.is_err() {
                    return Reply::Close(None, CloseReason::DeliveryFailed.into());
                }
                receipt(f).map_or(Reply::None, Reply::Frame)
            }
            "SUBSCRIBE" => {
                let id = f.header("id").unwrap_or("0").to_owned();
                let dest = f.header("destination").unwrap_or(agent_dest).to_owned();
                if dest != agent_dest {
                    debug!(agent = %eid, destination = %dest, "Agent subscribed elsewhere than its subscribe-dest");
                }
                *subscription = Some((id, dest));
                receipt(f).map_or(Reply::None, Reply::Frame)
            }
            "UNSUBSCRIBE" => {
                *subscription = None;
                receipt(f).map_or(Reply::None, Reply::Frame)
            }
            "DISCONNECT" => Reply::Close(receipt(f), CloseReason::AgentClosed.into()),
            other => refuse(&format!("{other} is not supported")),
        }
    }
}

/// Write to the Agent. `Err` = failed or stalled for `timeout` (peer not reading)
/// -> close the connection.
async fn put<W: AsyncWrite + Unpin>(
    wr: &mut W,
    bytes: &[u8],
    timeout: Duration,
) -> std::io::Result<()> {
    write_all_within("stomp", wr, bytes, timeout).await
}

/// Answer to a frame.
enum Reply {
    None,
    Frame(Frame),
    /// Answer (if any), then close with this cause.
    Close(Option<Frame>, Cause),
}

/// `CONNECT` refusal: short token for the log + text for the peer in the `ERROR` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rejected {
    reason: &'static str,
    message: String,
}

impl Rejected {
    fn new(reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}

impl std::ops::Deref for Rejected {
    type Target = str;

    fn deref(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn error_frame(message: &str) -> Frame {
    let mut f = Frame::new(
        "ERROR",
        &[("message", message), ("content-type", "text/plain")],
    );
    f.body = Bytes::copy_from_slice(message.as_bytes());
    f
}

/// Read until a whole frame is buffered (heart-beats skipped).
/// `None` = peer closed, or sent no frame, or over `limits`.
async fn read_frame<R: AsyncRead + Unpin>(
    rd: &mut R,
    buf: &mut Vec<u8>,
    parser: &mut FrameParser,
    limits: Limits,
) -> std::io::Result<Option<Frame>> {
    let mut chunk = vec![0u8; 4096];
    loop {
        match parser.parse(buf, limits) {
            Ok(Parsed::Heartbeat(n)) => {
                buf.drain(..n);
                continue;
            }
            Ok(Parsed::Frame(f, n)) => {
                buf.drain(..n);
                return Ok(Some(f));
            }
            Ok(Parsed::Incomplete) => {}
            Err(_) => return Ok(None),
        }
        let n = rd.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Constant-time string comparison.
pub(crate) fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |x, (p, q)| x | (p ^ q)) == 0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn frame(bytes: &[u8]) -> (Frame, usize) {
        match Frame::parse(bytes, 1 << 20) {
            Ok(Parsed::Frame(f, n)) => (f, n),
            other => panic!("not a frame: {other:?}"),
        }
    }

    #[test]
    fn frames_round_trip_with_escapes_and_binary_bodies() {
        let mut f = Frame::new("SEND", &[("destination", "/queue/a:b"), ("x", "l1\nl2\\")]);
        f.body = Bytes::from_static(b"\x00\x01binary\x00");
        let wire = f.encode();
        assert!(
            std::str::from_utf8(&wire[..40])
                .unwrap_or_default()
                .contains("destination:/queue/a\\cb")
        );
        let (back, used) = frame(&wire);
        assert_eq!(used, wire.len());
        assert_eq!(back.header("destination"), Some("/queue/a:b"));
        assert_eq!(back.header("x"), Some("l1\nl2\\"));
        assert_eq!(back.body, f.body);
    }

    #[test]
    fn connect_headers_are_not_unescaped_and_bodies_end_at_nul() {
        let (f, _) = frame(b"CONNECT\r\naccept-version:1.2\r\nlogin:a\\b\r\n\r\n\x00");
        assert_eq!(f.command, "CONNECT");
        assert_eq!(f.header("login"), Some("a\\b"));
        let (f, n) = frame(b"SEND\ndestination:/q\n\nhello\x00\n\nNEXT");
        assert_eq!((f.body.as_ref(), n), (b"hello".as_ref(), 27));
    }

    #[test]
    fn heartbeats_partial_frames_and_limits() {
        assert_eq!(Frame::parse(b"\n\r\nSEND", 100), Ok(Parsed::Heartbeat(3)));
        assert_eq!(
            Frame::parse(b"SEND\ncontent-length:10\n\nabc", 100),
            Ok(Parsed::Incomplete)
        );
        assert!(Frame::parse(b"SEND\ncontent-length:500\n\n", 100).is_err());
        assert!(Frame::parse(b"SEND\nbad header\n\n\x00", 100).is_err());
        assert!(Frame::parse(b"SEND\nx:\\q\n\n\x00", 100).is_err());
    }

    /// `whole` -> `parser` in `piece`-byte pieces (like a connection), until result != more.
    fn feed(
        parser: &mut FrameParser,
        whole: &[u8],
        piece: usize,
        limits: Limits,
    ) -> Result<Parsed, String> {
        let mut buf = Vec::new();
        let mut last = Ok(Parsed::Incomplete);
        for chunk in whole.chunks(piece) {
            buf.extend_from_slice(chunk);
            last = parser.parse(&buf, limits);
            if !matches!(last, Ok(Parsed::Incomplete)) {
                break;
            }
        }
        last
    }

    #[test]
    fn before_login_a_frame_is_small() {
        let connect = |extra: usize| {
            let mut f = b"CONNECT\naccept-version:1.2\nendpoint-id:os::A\npad:".to_vec();
            f.extend(vec![b'x'; extra]);
            f.extend_from_slice(b"\n\n\x00");
            f
        };
        let pre = Limits::PRE_AUTH;
        // Normal-size CONNECT -> read.
        let ok = feed(&mut FrameParser::default(), &connect(100), 7, pre);
        assert!(matches!(ok, Ok(Parsed::Frame(..))), "{ok:?}");
        // Endless headers -> refused at the cap, not at 8 MiB (while 1st frame still arriving).
        let mut p = FrameParser::default();
        let junk = vec![b'a'; MAX_PRE_AUTH_FRAME + 1];
        let e = feed(&mut p, &junk, 1024, pre).unwrap_err();
        assert!(e.contains("too large"), "{e}");
        // Same for a header block over the cap that does end.
        let e = feed(
            &mut FrameParser::default(),
            &connect(MAX_PRE_AUTH_FRAME),
            4096,
            pre,
        )
        .unwrap_err();
        assert!(e.contains("too large"), "{e}");
        // Body length over the cap -> refused from headers alone.
        let big = b"SEND\ncontent-length:100000\n\n".to_vec();
        assert!(feed(&mut FrameParser::default(), &big, 4096, pre).is_err());
        // Same frame after login -> ok.
        assert!(matches!(
            feed(
                &mut FrameParser::default(),
                &connect(MAX_PRE_AUTH_FRAME),
                4096,
                Limits::AUTHENTICATED
            ),
            Ok(Parsed::Frame(..))
        ));
        // Body without content-length -> bounded too.
        let mut f = b"SEND\ndestination:/q\n\n".to_vec();
        f.extend(vec![b'x'; MAX_PRE_AUTH_FRAME]);
        assert!(feed(&mut FrameParser::default(), &f, 4096, pre).is_err());
    }

    #[test]
    fn a_frame_has_a_few_headers() {
        let frame = |n: usize| {
            let mut f = b"SEND\n".to_vec();
            for i in 0..n {
                f.extend_from_slice(format!("h{i}:v\n").as_bytes());
            }
            f.extend_from_slice(b"\n\x00");
            f
        };
        for limits in [Limits::PRE_AUTH, Limits::AUTHENTICATED] {
            let ok = feed(
                &mut FrameParser::default(),
                &frame(MAX_HEADERS),
                4096,
                limits,
            );
            assert!(matches!(ok, Ok(Parsed::Frame(..))), "{ok:?}");
            let e = feed(
                &mut FrameParser::default(),
                &frame(MAX_HEADERS + 1),
                4096,
                limits,
            )
            .unwrap_err();
            assert!(e.contains("headers"), "{e}");
        }
        // 1000s of tiny headers -> refused at the 65th, within the head cap.
        let e = Frame::parse(&frame(5000), 1 << 20).unwrap_err();
        assert!(e.contains("headers") || e.contains("too large"), "{e}");
    }

    #[test]
    fn a_blank_line_cut_in_two_pieces_is_found() {
        for wire in [
            b"SEND\na:b\n\nbody\x00".as_slice(),
            b"SEND\r\na:b\r\n\r\nbody\x00".as_slice(),
            b"SEND\na:b\n\r\nbody\x00".as_slice(),
        ] {
            for piece in 1..=wire.len() {
                let parsed = feed(
                    &mut FrameParser::default(),
                    wire,
                    piece,
                    Limits::AUTHENTICATED,
                );
                match parsed {
                    Ok(Parsed::Frame(f, n)) => {
                        assert_eq!((f.body.as_ref(), n), (b"body".as_ref(), wire.len()));
                    }
                    other => panic!("{piece}-byte pieces of {wire:?}: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn frames_follow_each_other_in_one_buffer() {
        let mut parser = FrameParser::default();
        let mut buf = b"\nSEND\nx:1\n\nab\x00\n\nSEND\nx:2\ncontent-length:2\n\ncd\x00".to_vec();
        let mut seen = Vec::new();
        while !buf.is_empty() {
            match parser.parse(&buf, Limits::AUTHENTICATED).unwrap() {
                Parsed::Heartbeat(n) => {
                    buf.drain(..n);
                }
                Parsed::Frame(f, n) => {
                    seen.push((f.header("x").unwrap().to_owned(), f.body));
                    buf.drain(..n);
                }
                Parsed::Incomplete => panic!("incomplete: {buf:?}"),
            }
        }
        assert_eq!(
            seen,
            vec![
                ("1".to_owned(), Bytes::from_static(b"ab")),
                ("2".to_owned(), Bytes::from_static(b"cd")),
            ]
        );
    }

    #[test]
    fn a_big_frame_in_small_pieces_is_read_in_linear_time() {
        // 8 MiB (max Record) in 4 KiB pieces.
        // Restart per piece -> ~4 MiB searched x2000 = GBs, many seconds.
        let body = vec![b'x'; MAX_FRAME - 1024];
        for with_length in [true, false] {
            let mut wire = b"SEND\ndestination:/queue/usp.controller\n".to_vec();
            if with_length {
                wire.extend_from_slice(format!("content-length:{}\n", body.len()).as_bytes());
            }
            wire.push(b'\n');
            wire.extend_from_slice(&body);
            wire.push(0);
            let started = std::time::Instant::now();
            let parsed = feed(
                &mut FrameParser::default(),
                &wire,
                4096,
                Limits::AUTHENTICATED,
            );
            let took = started.elapsed();
            match parsed {
                Ok(Parsed::Frame(f, n)) => {
                    assert_eq!((f.body.len(), n), (body.len(), wire.len()));
                }
                other => panic!("content-length {with_length}: {other:?}"),
            }
            assert!(
                took < Duration::from_secs(1),
                "content-length {with_length}: took {took:?}"
            );
        }
    }

    #[test]
    fn connect_is_checked() {
        let (tx, _rx) = mpsc::channel(1);
        let mtp = StompMtp::new(
            tx,
            StompConfig {
                login: Some(("cpe".into(), "pw".into())),
                ..StompConfig::default()
            },
        );
        let connect = |headers: &[(&str, &str)]| Frame::new("STOMP", headers);
        let ok = connect(&[
            ("accept-version", "1.0,1.2"),
            ("login", "cpe"),
            ("passcode", "pw"),
            ("endpoint-id", "os::X"),
            ("heart-beat", "5000,10000"),
        ]);
        assert_eq!(mtp.accept(&ok, None), Ok(("os::X".to_owned(), 5000, 10000)));
        let mut bad = ok.clone();
        bad.headers[2].1 = "nope".into();
        assert!(mtp.accept(&bad, None).is_err(), "wrong passcode");
        let mut old = ok.clone();
        old.headers[0].1 = "1.1".into();
        assert!(mtp.accept(&old, None).is_err(), "STOMP 1.1 only");
        let mut no_eid = ok.clone();
        no_eid.headers.retain(|(k, _)| k != "endpoint-id");
        assert!(mtp.accept(&no_eid, None).is_err());
        for bad_eid in ["os::a/b", "os::a+", "os:: a", "os::a\u{7f}"] {
            let mut bad = ok.clone();
            bad.headers[3].1 = bad_eid.into();
            assert!(mtp.accept(&bad, None).is_err(), "{bad_eid:?}");
        }
        let cert = |id: &str, fp: &str| ClientCert {
            ids: vec![id.to_owned()],
            fingerprint: fp.to_owned(),
        };
        assert!(
            mtp.accept(&ok, Some(&cert("os::Y", "fp"))).is_err(),
            "certificate for another EndpointID"
        );
        assert!(mtp.accept(&ok, Some(&cert("os::X", "fp"))).is_ok());
    }

    #[test]
    fn certificates_outrank_claims_and_revoked_ones_are_refused() {
        let (tx, _rx) = mpsc::channel(1);
        let mtp = StompMtp::new(tx, StompConfig::default());
        let connect = Frame::new(
            "STOMP",
            &[("accept-version", "1.2"), ("endpoint-id", "os::X")],
        );
        let cert = |fp: &str| ClientCert {
            ids: vec!["os::X".to_owned()],
            fingerprint: fp.to_owned(),
        };
        let peer: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        // EndpointID with issued client cert -> cert needed.
        assert!(mtp.accept(&connect, None).is_ok());
        mtp.set_certificate_bound(["os::X".to_owned()].into());
        let e = mtp.accept(&connect, None).unwrap_err();
        assert!(e.contains("bound to a client certificate"), "{e}");
        assert!(mtp.accept(&connect, Some(&cert("fp"))).is_ok());
        mtp.set_certificate_bound(HashSet::new());

        // Connection with cert not replaced by one without.
        let (id, ..) = mtp.register("os::X", peer, Some("fp".into())).unwrap();
        let e = mtp.accept(&connect, None).unwrap_err();
        assert!(e.contains("connected with a client certificate"), "{e}");
        assert_eq!(
            mtp.register("os::X", peer, None).err(),
            Some(Refusal::Outranked)
        );
        assert_eq!(mtp.connections(), 1);
        // Any cert takes over.
        let (newer, ..) = mtp.register("os::X", peer, Some("renewed".into())).unwrap();
        assert_ne!(id, newer);

        // Revoke cert -> its connection closed + cert refused from then on.
        assert_eq!(mtp.set_revoked(["unrelated".to_owned()].into()), 0);
        assert_eq!(mtp.set_revoked(["renewed".to_owned()].into()), 1);
        let e = mtp.accept(&connect, Some(&cert("renewed"))).unwrap_err();
        assert!(e.contains("revoked"), "{e}");
        assert_eq!(
            mtp.register("os::Y", peer, Some("renewed".into())).err(),
            Some(Refusal::Revoked)
        );
        assert!(mtp.accept(&connect, Some(&cert("another"))).is_ok());
    }
}
