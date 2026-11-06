//! One client connection: negotiation (STARTTLS, SASL PLAIN, resource bind) -> few stanzas.
//!
//! States, in client order:
//!
//! 1. `Plain`: stream in clear text. Only `<starttls/>` offered, required.
//!    Anything else -> `not-authorized`.
//! 2. `Secure`: TLS up, stream reopened. Only SASL PLAIN offered.
//! 3. `Authed`: logged in, stream reopened. Only resource bind accepted (session step optional).
//! 4. `Bound`: in the live session table. Pings, session steps, CR answers handled.
//!    Rest refused or dropped. Never routed to another JID.
//!
//! Accept -> bound resource: deadline. After: close on idle timeout.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::Condition;
use crate::attempts::Locked;
use crate::connlimit::ConnPermit;
use crate::sasl::{matching, parse_plain};
use crate::server::{ACS_LOCALPART, CrReply, Inner, Registration, random_hex};
use crate::wire::{self, Features, NS_BIND, NS_PING, NS_SASL, NS_SESSION, NS_STANZAS, NS_TLS};
use crate::xml::{Element, Event, MAX_STANZA, NS_CLIENT, Parser, StreamHeader};

/// Max time of an account lookup or a note to the application.
const ACCOUNTS_TIMEOUT: Duration = Duration::from_secs(10);
/// Max write time of the last bytes (stream error, close).
const GOODBYE_TIMEOUT: Duration = Duration::from_secs(2);
/// Max resource length (RFC 6122 allows 1023).
const MAX_RESOURCE: usize = 256;
/// Stanza burst + rate per second after it.
/// Device pings ~1 per 30 s -> stops only a flooding client.
const STANZA_BURST: f64 = 100.0;
const STANZA_PER_SECOND: f64 = 10.0;

/// End reason of a connection (or of one `drive`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    /// Start TLS next.
    StartTls,
    /// Orderly close with `</stream:stream>`.
    Closed,
    /// Close with this stream error.
    Error(Condition),
    /// Transport failed or peer left -> nothing to send.
    Io,
}

#[derive(Debug)]
enum Phase {
    Plain,
    Secure,
    Authed(String),
    Bound,
}

#[derive(Debug)]
struct Bound {
    account: String,
    reg: Registration,
}

/// Stanza token bucket: burst, steady refill.
#[derive(Debug)]
struct Budget {
    tokens: f64,
    at: Instant,
}

impl Budget {
    fn new() -> Self {
        Self {
            tokens: STANZA_BURST,
            at: Instant::now(),
        }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        let earned = now.saturating_duration_since(self.at).as_secs_f64() * STANZA_PER_SECOND;
        self.tokens = (self.tokens + earned).min(STANZA_BURST);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct Session {
    server: Arc<Inner>,
    peer: IpAddr,
    parser: Parser,
    phase: Phase,
    /// Own stream header sent on the current stream.
    header_sent: bool,
    /// SASL PLAIN started without initial response -> wait for `<response/>`.
    sasl_pending: bool,
    /// Bytes to write at the next chance.
    out: String,
    /// Bytes received on the connection.
    received: u64,
    last_rx: Instant,
    /// Deadline for a bound resource.
    pre_auth: Instant,
    bound: Option<Bound>,
    budget: Budget,
}

/// Run one accepted connection to its end. `_permit` = its slot under the caps.
pub(crate) async fn run(server: Arc<Inner>, tcp: TcpStream, peer: IpAddr, _permit: ConnPermit) {
    let mut session = Session {
        pre_auth: Instant::now() + server.config.pre_auth_timeout,
        server,
        peer,
        parser: Parser::new(),
        phase: Phase::Plain,
        header_sent: false,
        sasl_pending: false,
        out: String::new(),
        received: 0,
        last_rx: Instant::now(),
        bound: None,
        budget: Budget::new(),
    };
    let end = session.connection(tcp).await;
    session.cleanup(end).await;
}

/// Write `bytes` + flush. Longer than `timeout` -> `TimedOut`.
async fn write_to<S: AsyncWrite + Unpin>(
    io: &mut S,
    bytes: &[u8],
    timeout: Duration,
) -> std::io::Result<()> {
    tokio::time::timeout(timeout, async {
        io.write_all(bytes).await?;
        io.flush().await
    })
    .await
    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
}

fn resource_ok(resource: &str) -> bool {
    !resource.is_empty() && resource.len() <= MAX_RESOURCE && !resource.contains(char::is_control)
}

/// Defined condition of a stanza error (`<error><not-authorized xmlns=.../></error>`),
/// else `undefined-condition`.
/// Only the condition name kept; rest of the stanza (xmppc echoes the request) dropped unread.
fn error_condition(iq: &Element) -> String {
    iq.children
        .iter()
        .find(|c| c.name == "error")
        .and_then(|e| e.children.iter().find(|c| c.is(NS_STANZAS, &c.name)))
        .map(|c| c.name.as_str())
        .filter(|n| n.len() <= 64 && n.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
        .unwrap_or("undefined-condition")
        .to_owned()
}

impl Session {
    async fn connection(&mut self, mut tcp: TcpStream) -> End {
        match self.drive(&mut tcp).await {
            End::StartTls => {}
            end => {
                self.goodbye(&mut tcp, end).await;
                return end;
            }
        }
        let accepted = tokio::time::timeout_at(self.pre_auth, self.server.tls.accept(tcp)).await;
        let mut tls = match accepted {
            Ok(Ok(tls)) => tls,
            Ok(Err(e)) => {
                metrics::counter!("dhonomos_xmpp_tls_handshake_failures_total").increment(1);
                dhonomos_common::connection_refused!(
                    "xmpp",
                    "tls_handshake",
                    self.peer,
                    error = %e
                );
                return End::Io;
            }
            Err(_) => {
                dhonomos_common::connection_refused!("xmpp", "tls_handshake_timeout", self.peer);
                return End::Io;
            }
        };
        self.phase = Phase::Secure;
        self.parser.restart();
        self.header_sent = false;
        let end = match self.drive(&mut tls).await {
            // STARTTLS only offered in clear text.
            End::StartTls => End::Error(Condition::InternalServerError),
            end => end,
        };
        self.goodbye(&mut tls, end).await;
        end
    }

    /// Input wait deadline: bound-resource deadline, after bind -> idle timeout.
    fn deadline(&self) -> Instant {
        if self.bound.is_some() {
            self.last_rx + self.server.idle_timeout()
        } else {
            self.pre_auth
        }
    }

    async fn flush<S: AsyncWrite + Unpin>(&mut self, io: &mut S) -> std::io::Result<()> {
        if self.out.is_empty() {
            return Ok(());
        }
        let bytes = std::mem::take(&mut self.out);
        write_to(io, bytes.as_bytes(), self.server.config.write_timeout).await
    }

    /// Read + answer until connection end or TLS start.
    async fn drive<S>(&mut self, io: &mut S) -> End
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut shutdown = self.server.shutdown.subscribe();
        loop {
            // Buffered input first: one read may hold several elements.
            loop {
                match self.parser.next_event() {
                    Ok(Some(event)) => {
                        if let Some(end) = self.event(event).await {
                            if end == End::StartTls && self.flush(io).await.is_err() {
                                return End::Io;
                            }
                            return end;
                        }
                    }
                    Ok(None) => break,
                    Err(condition) => return End::Error(condition),
                }
            }
            if self.flush(io).await.is_err() {
                return End::Io;
            }
            if *shutdown.borrow() {
                return End::Error(Condition::SystemShutdown);
            }
            let deadline = self.deadline();
            let write_timeout = self.server.config.write_timeout;
            let close = self.bound.as_ref().map(|b| Arc::clone(&b.reg.close));
            let outbox = self.bound.as_mut().map(|b| &mut b.reg.outbox);
            let buf = self.parser.read_buffer();
            tokio::select! {
                biased;
                _ = shutdown.changed() => return End::Error(Condition::SystemShutdown),
                reason = async {
                    match &close {
                        Some(c) => c.fired().await,
                        None => std::future::pending().await,
                    }
                } => return End::Error(reason),
                item = async {
                    match outbox {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    // Stanza queued by another task for this connection.
                    let Some(bytes) = item else { return End::Io };
                    let written = write_to(io, &bytes, write_timeout).await;
                    if let Some(b) = &self.bound {
                        b.reg.queued.fetch_sub(bytes.len(), Ordering::AcqRel);
                    }
                    if written.is_err() {
                        return End::Io;
                    }
                }
                read = io.read_buf(buf) => match read {
                    Ok(0) | Err(_) => return End::Io,
                    Ok(n) => {
                        self.received += n as u64;
                        self.last_rx = Instant::now();
                    }
                },
                () = tokio::time::sleep_until(deadline) => {
                    return End::Error(Condition::ConnectionTimeout);
                }
            }
        }
    }

    /// Last bytes: pending output + stream error or stream end -> connection close.
    async fn goodbye<S: AsyncWrite + Unpin>(&mut self, io: &mut S, end: End) {
        let mut tail = std::mem::take(&mut self.out);
        match end {
            End::Closed => {
                if self.header_sent {
                    tail.push_str(wire::STREAM_CLOSE);
                }
            }
            End::Error(condition) => {
                metrics::counter!(
                    "dhonomos_xmpp_stream_errors_total",
                    "condition" => condition.name()
                )
                .increment(1);
                debug!(peer = %self.peer, condition = condition.name(), "XMPP stream closed with an error");
                // Not logged: own shutdown, device reconnect (old session -> conflict),
                // bound device gone quiet.
                let ordinary = matches!(condition, Condition::SystemShutdown | Condition::Conflict)
                    || (condition == Condition::ConnectionTimeout && self.bound.is_some());
                if !ordinary {
                    dhonomos_common::connection_refused!(
                        "xmpp",
                        "stream_error",
                        self.peer,
                        condition = condition.name()
                    );
                }
                // Peer sent nothing -> send nothing. Port scan gets no answer.
                if self.received > 0 {
                    if !self.header_sent {
                        tail.push_str(&wire::stream_header(
                            &random_hex(12),
                            &self.server.config.domain,
                        ));
                        self.header_sent = true;
                    }
                    tail.push_str(&wire::stream_error(condition));
                }
            }
            End::Io | End::StartTls => return,
        }
        if !tail.is_empty() {
            let _ = write_to(io, tail.as_bytes(), GOODBYE_TIMEOUT).await;
        }
        let _ = tokio::time::timeout(GOODBYE_TIMEOUT, io.shutdown()).await;
    }

    /// Session over -> leave the table + tell the application.
    async fn cleanup(&mut self, end: End) {
        debug!(peer = %self.peer, ?end, "XMPP connection ended");
        let Some(bound) = self.bound.take() else {
            return;
        };
        if self.server.unregister(&bound.account, bound.reg.id) {
            let note = self
                .server
                .accounts
                .disconnected(&bound.account, bound.reg.connected_at);
            if tokio::time::timeout(ACCOUNTS_TIMEOUT, note).await.is_err() {
                warn!(account = %bound.account, "noting an XMPP disconnect timed out");
            }
        }
    }

    // Events

    async fn event(&mut self, event: Event) -> Option<End> {
        match event {
            Event::StreamOpen(header) => self.stream_open(&header),
            Event::StreamClose => Some(End::Closed),
            Event::Stanza(el) => match self.phase {
                Phase::Plain => self.plain_stanza(&el),
                Phase::Secure => self.secure_stanza(&el).await,
                Phase::Authed(_) => self.authed_stanza(&el).await,
                Phase::Bound => self.bound_stanza(el),
            },
        }
    }

    /// Client stream open -> own header + features of the next step.
    fn stream_open(&mut self, header: &StreamHeader) -> Option<End> {
        let domain = &self.server.config.domain;
        if !header
            .to
            .as_deref()
            .is_some_and(|to| to.eq_ignore_ascii_case(domain))
        {
            return Some(End::Error(Condition::HostUnknown));
        }
        let major = header
            .version
            .as_deref()
            .and_then(|v| v.split('.').next())
            .and_then(|m| m.parse::<u32>().ok());
        if major.is_none_or(|m| m < 1) {
            return Some(End::Error(Condition::UnsupportedVersion));
        }
        let features = match self.phase {
            Phase::Plain => Features::StartTls,
            Phase::Secure => Features::Sasl,
            Phase::Authed(_) => Features::Bind,
            Phase::Bound => return Some(End::Error(Condition::NotWellFormed)),
        };
        self.out
            .push_str(&wire::stream_header(&random_hex(12), domain));
        self.header_sent = true;
        self.out.push_str(&wire::features(features));
        None
    }

    /// Before TLS: STARTTLS or nothing.
    fn plain_stanza(&mut self, el: &Element) -> Option<End> {
        if !el.is(NS_TLS, "starttls") {
            return Some(End::Error(Condition::NotAuthorized));
        }
        // Bytes after `<starttls/>` came in clear text -> must not be read as TLS input.
        if self.parser.buffered() > 0 {
            return Some(End::Error(Condition::NotWellFormed));
        }
        self.out.push_str(&wire::proceed());
        Some(End::StartTls)
    }

    /// After TLS: SASL PLAIN.
    async fn secure_stanza(&mut self, el: &Element) -> Option<End> {
        if self.sasl_pending {
            if el.is(NS_SASL, "abort") {
                return self.sasl_failure("aborted");
            }
            if !el.is(NS_SASL, "response") {
                return Some(End::Error(Condition::NotAuthorized));
            }
            self.sasl_pending = false;
            return self.sasl_payload(el).await;
        }
        if !el.is(NS_SASL, "auth") {
            return Some(End::Error(Condition::NotAuthorized));
        }
        if el.attr("mechanism") != Some("PLAIN") {
            return self.sasl_failure("invalid-mechanism");
        }
        if el.text.trim().is_empty() {
            // No initial response -> ask for it.
            self.out.push_str(&wire::sasl_challenge());
            self.sasl_pending = true;
            return None;
        }
        self.sasl_payload(el).await
    }

    /// SASL failure not about the password (bad message, unknown mechanism) -> stream close.
    fn sasl_failure(&mut self, condition: &'static str) -> Option<End> {
        dhonomos_common::request_refused!("xmpp", "sasl_failure", self.peer, condition);
        self.sasl_failed(condition)
    }

    /// SASL failure, logged by the caller -> stream close.
    fn sasl_failed(&mut self, condition: &str) -> Option<End> {
        metrics::counter!("dhonomos_xmpp_auth_total", "result" => "fail").increment(1);
        self.out.push_str(&wire::sasl_failure(condition));
        Some(End::Closed)
    }

    /// SASL failure: no `account`, or wrong password.
    /// Account name = device claim, not a secret -> logged, shows what is guessed.
    fn password_refused(&mut self, account: &str) -> Option<End> {
        dhonomos_common::request_refused!(
            "xmpp",
            "auth_failed",
            self.peer,
            username = ?dhonomos_common::refusal::clip(account)
        );
        self.sasl_failed("not-authorized")
    }

    /// PLAIN message in `<auth/>` or `<response/>`.
    async fn sasl_payload(&mut self, el: &Element) -> Option<End> {
        let text = el.text.trim();
        let message = if text == "=" {
            Vec::new()
        } else {
            match base64::engine::general_purpose::STANDARD.decode(text) {
                Ok(m) => m,
                Err(_) => return self.sasl_failure("incorrect-encoding"),
            }
        };
        let (account, password) = match parse_plain(&message, &self.server.config.domain) {
            Ok(parsed) => parsed,
            Err(refusal) => return self.sasl_failure(refusal.condition()),
        };
        let client = Inner::client(self.peer);
        let slot = match self.server.attempts.reserve(&account, client) {
            Ok(slot) => slot,
            Err(Locked) => {
                metrics::counter!("dhonomos_xmpp_auth_total", "result" => "locked").increment(1);
                dhonomos_common::request_refused!(
                    "xmpp",
                    "auth_locked",
                    self.peer,
                    username = ?dhonomos_common::refusal::clip(&account)
                );
                self.out.push_str(&wire::sasl_failure("not-authorized"));
                return Some(End::Closed);
            }
        };
        // ACS own JID is never an account, whatever the application says.
        if account.eq_ignore_ascii_case(ACS_LOCALPART) {
            return self.password_refused(&account);
        }
        let lookup = self.server.accounts.credentials(&account);
        let credentials = match tokio::time::timeout(ACCOUNTS_TIMEOUT, lookup).await {
            Ok(Ok(credentials)) => credentials,
            _ => {
                // Never checked -> not the device's fault, slot refunded.
                slot.refund();
                self.out
                    .push_str(&wire::sasl_failure("temporary-auth-failure"));
                return Some(End::Closed);
            }
        };
        let passwords: Vec<&[u8]> = credentials.iter().map(|c| c.password.as_slice()).collect();
        let Some(i) = matching(&passwords, &password) else {
            // Slot stays counted.
            drop(slot);
            return self.password_refused(&account);
        };
        slot.success();
        metrics::counter!("dhonomos_xmpp_auth_total", "result" => "ok").increment(1);
        info!(%account, remote = %self.peer, "XMPP login accepted");
        let accepted = self.server.accounts.accepted(&account, &credentials[i]);
        if tokio::time::timeout(ACCOUNTS_TIMEOUT, accepted)
            .await
            .is_err()
        {
            warn!(%account, "noting an XMPP login timed out");
        }
        self.out.push_str(&wire::sasl_success());
        self.parser.restart();
        self.header_sent = false;
        self.phase = Phase::Authed(account);
        None
    }

    /// After SASL: resource bind only.
    async fn authed_stanza(&mut self, el: &Element) -> Option<End> {
        let Phase::Authed(account) = &self.phase else {
            return Some(End::Error(Condition::InternalServerError));
        };
        let bind = el
            .child(NS_BIND, "bind")
            .filter(|_| el.is(NS_CLIENT, "iq") && el.attr("type") == Some("set"));
        let Some(bind) = bind else {
            return Some(End::Error(Condition::NotAuthorized));
        };
        let id = el.attr("id");
        let requested = bind
            .child(NS_BIND, "resource")
            .map(|r| r.text.as_str())
            .filter(|r| !r.is_empty());
        let resource = match requested {
            Some(r) if resource_ok(r) => r.to_owned(),
            // No resource from device (xmppc, empty Resource) -> server picks one.
            None => format!("cwmp-{}", random_hex(6)),
            Some(_) => {
                self.out.push_str(&wire::stanza_error(
                    "iq",
                    id,
                    None,
                    None,
                    "modify",
                    "bad-request",
                ));
                return None;
            }
        };
        let Some(id) = id else {
            self.out.push_str(&wire::stanza_error(
                "iq",
                None,
                None,
                None,
                "modify",
                "bad-request",
            ));
            return None;
        };
        let account = account.clone();
        let reg = self.server.register(&account, &resource);
        let note = self.server.accounts.connected(&account, reg.connected_at);
        if tokio::time::timeout(ACCOUNTS_TIMEOUT, note).await.is_err() {
            warn!(%account, "noting an XMPP connect timed out");
        }
        debug!(%account, peer = %self.peer, "XMPP session bound");
        self.out.push_str(&wire::bind_result(id, &reg.jid));
        self.parser.set_max_stanza(MAX_STANZA);
        self.phase = Phase::Bound;
        self.bound = Some(Bound { account, reg });
        None
    }

    // Stanzas of a bound session

    fn bound_stanza(&mut self, mut el: Element) -> Option<End> {
        if !self.budget.take() {
            return Some(End::Error(Condition::PolicyViolation));
        }
        if el.ns.as_deref() != Some(NS_CLIENT) {
            return Some(End::Error(Condition::InvalidNamespace));
        }
        let Some(bound) = &self.bound else {
            return Some(End::Error(Condition::InternalServerError));
        };
        let jid = bound.reg.jid.clone();
        // Client `from` ignored (RFC 6120 sec. 8.1.2.1) -> stanza is from the bound JID.
        // xmppc with empty resource sends `user@domain/` = not a valid JID.
        el.set_attr("from", &jid);
        debug!(stanza = el.name.as_str(), "XMPP stanza");
        match el.name.as_str() {
            "iq" => self.iq(&el, &jid),
            "presence" | "message" => {
                self.presence_or_message(&el, &jid);
                None
            }
            _ => Some(End::Error(Condition::UnsupportedStanzaType)),
        }
    }

    /// `to` is for the server (+ the account it speaks for):
    /// no address, the domain, or the own bare JID.
    fn for_the_server(&self, to: Option<&str>, jid: &str) -> bool {
        let Some(to) = to.filter(|t| !t.is_empty()) else {
            return true;
        };
        let bare = jid.split_once('/').map_or(jid, |(bare, _)| bare);
        to.eq_ignore_ascii_case(&self.server.config.domain) || to.eq_ignore_ascii_case(bare)
    }

    fn iq(&mut self, el: &Element, jid: &str) -> Option<End> {
        let id = el.attr("id").filter(|i| !i.is_empty());
        let kind = el.attr("type");
        if matches!(kind, Some("result" | "error")) {
            // Answer. To a CR sent on this session -> that CR done.
            if let (Some(id), Some(bound)) = (id, &self.bound) {
                let reply = if kind == Some("result") {
                    CrReply::Result
                } else {
                    CrReply::Error(error_condition(el))
                };
                self.server
                    .complete(&bound.account, bound.reg.id, id, reply);
            }
            return None;
        }
        let to = el.attr("to").filter(|t| !t.is_empty());
        let (Some(id), Some("get" | "set")) = (id, kind) else {
            self.out.push_str(&wire::stanza_error(
                "iq",
                id,
                to,
                Some(jid),
                "modify",
                "bad-request",
            ));
            return None;
        };
        if !self.for_the_server(to, jid) {
            // Never routed between clients.
            self.out.push_str(&wire::stanza_error(
                "iq",
                Some(id),
                to,
                Some(jid),
                "cancel",
                "service-unavailable",
            ));
            return None;
        }
        let [payload] = el.children.as_slice() else {
            self.out.push_str(&wire::stanza_error(
                "iq",
                Some(id),
                to,
                Some(jid),
                "modify",
                "bad-request",
            ));
            return None;
        };
        let get = kind == Some("get");
        if (get && payload.is(NS_PING, "ping")) || (!get && payload.is(NS_SESSION, "session")) {
            self.out.push_str(&wire::iq_result(id, to, jid));
        } else if !get && payload.is(NS_BIND, "bind") {
            // Bind only once.
            self.out.push_str(&wire::stanza_error(
                "iq",
                Some(id),
                to,
                Some(jid),
                "cancel",
                "not-allowed",
            ));
        } else {
            self.out.push_str(&wire::stanza_error(
                "iq",
                Some(id),
                to,
                Some(jid),
                "cancel",
                "service-unavailable",
            ));
        }
        None
    }

    /// Presence taken, goes nowhere; message dropped.
    /// For another JID -> refused: no path from one device to another.
    fn presence_or_message(&mut self, el: &Element, jid: &str) {
        let to = el.attr("to").filter(|t| !t.is_empty());
        if self.for_the_server(to, jid) || el.attr("type") == Some("error") {
            return;
        }
        if let Some(to) = to {
            self.out.push_str(&wire::stanza_error(
                &el.name,
                el.attr("id"),
                Some(to),
                Some(jid),
                "cancel",
                "service-unavailable",
            ));
        }
    }
}
