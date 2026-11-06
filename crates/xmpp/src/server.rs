//! Server: listener, table of live sessions, pending CRs, app plug-in ([`Accounts`]).

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use dhonomos_pki::tls::CertResolver;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

use crate::Condition;
use crate::attempts::Attempts;
use crate::connlimit::ConnLimiter;
use crate::{session, wire};

/// ACS local part: CRs come from `acs@<domain>/dhonomos`.
///
/// Device told to accept CRs from this JID (`ConnReqAllowedJabberIDs`) -> no login as it.
pub const ACS_LOCALPART: &str = "acs";
/// Resource the ACS sends CRs from.
const ACS_RESOURCE: &str = "dhonomos";

#[derive(Debug, Clone)]
pub struct XmppConfig {
    /// XMPP domain served (JID = `<account>@<domain>`).
    /// TLS cert must cover it -> devices check the cert against it.
    pub domain: String,
    /// Silent this long -> session closed.
    /// Device pings every `KeepAliveInterval` -> set to a few of those.
    pub idle_timeout: Duration,
    /// Max time from accept to bound resource.
    pub pre_auth_timeout: Duration,
    /// Write without progress this long -> connection closed.
    pub write_timeout: Duration,
    /// Max open connections; more closed at accept. 0 = unlimited.
    pub max_connections: usize,
    /// Max open connections per address (IPv6: /64). 0 = unlimited.
    pub max_connections_per_ip: usize,
    /// Max bytes waiting to be written to one connection; reader further behind -> closed.
    pub queue_limit: usize,
}

impl XmppConfig {
    /// Default limits for `domain`: keep-alive 30 s -> 120 s idle.
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            idle_timeout: Duration::from_secs(3 * 30 + 30),
            pre_auth_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            max_connections: 50_000,
            max_connections_per_ip: 1024,
            queue_limit: 256 * 1024,
        }
    }
}

/// Password that logs an account in.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    pub password: Vec<u8>,
    /// Still being provisioned on the device.
    /// 1st login with it -> becomes the device password ([`Accounts::accepted`]).
    pub pending: bool,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("password", &"********")
            .field("pending", &self.pending)
            .finish()
    }
}

/// Account lookup failed (DB down).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("account lookup failed")]
pub struct Unavailable;

/// App side: the accounts.
#[async_trait::async_trait]
pub trait Accounts: Send + Sync + 'static {
    /// Passwords `account` (JID local part) may log in with, active one first.
    ///
    /// Empty -> no such account. Server compares in constant time.
    async fn credentials(&self, account: &str) -> Result<Vec<Credential>, Unavailable>;

    /// `account` logged in with `credential`.
    async fn accepted(&self, account: &str, credential: &Credential);

    /// `account` has a bound session since `at`.
    ///
    /// `at` unique per session (microsecond precision)
    /// -> `disconnected` can tell its own session from a newer one.
    async fn connected(&self, account: &str, at: SystemTime);

    /// Session connected at `at` ended; account has no newer one.
    async fn disconnected(&self, account: &str, at: SystemTime);
}

/// How a CR ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrOutcome {
    /// Device answered `result`: got the request, takes it from here.
    Acknowledged,
    /// Device answered `error`; value = condition name (`not-authorized`).
    Rejected(String),
    /// No answer in time.
    TimedOut,
    /// Device has no session here (or it ended before the answer).
    NotConnected,
}

/// CR could not be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SendError {
    /// Credentials hold a char XML cannot carry.
    #[error("the connection request credentials cannot be sent in XML")]
    Unrepresentable,
    /// Request larger than the connection queue limit.
    #[error("the connection request is larger than the XMPP connection queue")]
    TooLarge,
    /// Session queue full: device does not read.
    #[error("the device is not reading from its XMPP connection")]
    QueueFull,
}

/// Answer to a CR.
#[derive(Debug)]
pub(crate) enum CrReply {
    Result,
    Error(String),
}

/// Tells a session to end.
#[derive(Debug, Default)]
pub(crate) struct CloseSignal {
    notify: Notify,
    reason: Mutex<Option<Condition>>,
}

impl CloseSignal {
    /// End the session with a stream error; first reason wins.
    pub(crate) fn fire(&self, reason: Condition) {
        self.reason
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert(reason);
        self.notify.notify_one();
    }

    pub(crate) async fn fired(&self) -> Condition {
        self.notify.notified().await;
        self.reason
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .unwrap_or(Condition::InternalServerError)
    }
}

/// Bound session as kept in the table.
#[derive(Debug)]
struct Live {
    id: u64,
    jid: String,
    tx: mpsc::UnboundedSender<Bytes>,
    queued: Arc<AtomicUsize>,
    close: Arc<CloseSignal>,
}

/// CR waiting for its answer.
#[derive(Debug)]
struct PendingCr {
    account: String,
    session: u64,
    done: oneshot::Sender<CrReply>,
}

#[derive(Debug, Default)]
struct Registry {
    sessions: HashMap<String, Live>,
    pending: HashMap<String, PendingCr>,
}

/// What a session gets at bind.
#[derive(Debug)]
pub(crate) struct Registration {
    pub(crate) id: u64,
    pub(crate) jid: String,
    pub(crate) outbox: mpsc::UnboundedReceiver<Bytes>,
    pub(crate) queued: Arc<AtomicUsize>,
    pub(crate) close: Arc<CloseSignal>,
    pub(crate) connected_at: SystemTime,
}

pub(crate) struct Inner {
    pub(crate) config: XmppConfig,
    pub(crate) accounts: Arc<dyn Accounts>,
    pub(crate) tls: TlsAcceptor,
    pub(crate) limiter: Arc<ConnLimiter>,
    pub(crate) attempts: Attempts,
    registry: Mutex<Registry>,
    next: AtomicU64,
    /// `config.idle_timeout` in ms, changeable at runtime.
    idle_timeout_ms: AtomicU64,
    pub(crate) shutdown: watch::Sender<bool>,
}

impl Inner {
    /// Max silence before a connection is closed.
    pub(crate) fn idle_timeout(&self) -> Duration {
        Duration::from_millis(self.idle_timeout_ms.load(Ordering::Relaxed))
    }
}

/// `d` in whole ms, saturated.
fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("domain", &self.config.domain)
            .finish_non_exhaustive()
    }
}

/// Clones share all state.
#[derive(Debug, Clone)]
pub struct XmppServer {
    inner: Arc<Inner>,
}

/// `n` random bytes as hex.
///
/// Not for secrets: stream IDs, resources, request IDs -> only checked against their receiver.
pub(crate) fn random_hex(n: usize) -> String {
    use std::fmt::Write as _;
    static FALLBACK: AtomicU64 = AtomicU64::new(0);
    let mut raw = vec![0u8; n];
    if getrandom::fill(&mut raw).is_err() {
        let seed = FALLBACK.fetch_add(1, Ordering::Relaxed)
            ^ SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(0));
        for (i, b) in raw.iter_mut().enumerate() {
            *b = seed.to_le_bytes()[i % 8].wrapping_add(i as u8);
        }
    }
    raw.iter().fold(String::with_capacity(n * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Listener TLS: 1.2 + 1.3, cert from `resolver` (follows its files).
///
/// No client certs, no ALPN: STARTTLS needs neither.
pub fn tls_acceptor(resolver: Arc<CertResolver>) -> Result<TlsAcceptor, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// TCP keepalive on an accepted socket -> kernel notices a device gone without close (power loss).
///
/// Probes after 60 s idle, then every 10 s; 3 unanswered -> socket error. Same as USP MTPs.
/// Best effort.
fn enable_tcp_keepalive(stream: &TcpStream) {
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(10))
        .with_retries(3);
    if let Err(e) = socket2::SockRef::from(stream).set_tcp_keepalive(&ka) {
        debug!(error = %e, "could not enable TCP keepalive");
    }
}

impl XmppServer {
    /// Server for `config.domain`. No listening before [`XmppServer::serve`].
    pub fn new(config: XmppConfig, accounts: Arc<dyn Accounts>, tls: TlsAcceptor) -> Self {
        let limiter = ConnLimiter::new(config.max_connections, config.max_connections_per_ip);
        let idle_timeout_ms = AtomicU64::new(millis(config.idle_timeout));
        Self {
            inner: Arc::new(Inner {
                idle_timeout_ms,
                config,
                accounts,
                tls,
                limiter,
                attempts: Attempts::default(),
                registry: Mutex::default(),
                next: AtomicU64::new(1),
                shutdown: watch::channel(false).0,
            }),
        }
    }

    /// Set max silence before close. Each connection uses it from its next wait on.
    pub fn set_idle_timeout(&self, timeout: Duration) {
        self.inner
            .idle_timeout_ms
            .store(millis(timeout), Ordering::Relaxed);
    }

    /// Max silence before a connection is closed.
    pub fn idle_timeout(&self) -> Duration {
        self.inner.idle_timeout()
    }

    pub fn domain(&self) -> &str {
        &self.inner.config.domain
    }

    /// `account` has a bound session here?
    pub fn is_connected(&self, account: &str) -> bool {
        self.inner.lock().sessions.contains_key(account)
    }

    /// Full JID (`account@domain/resource`) of the bound session of `account`, if any.
    pub fn jid(&self, account: &str) -> Option<String> {
        self.inner
            .lock()
            .sessions
            .get(account)
            .map(|l| l.jid.clone())
    }

    /// Count of bound sessions.
    pub fn connections(&self) -> usize {
        self.inner.lock().sessions.len()
    }

    /// Accept on `listener` until `shutdown` resolves.
    ///
    /// Then tell sessions the server is going away + give them ~2 s to end.
    pub async fn serve(
        &self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()>,
    ) -> std::io::Result<()> {
        tokio::pin!(shutdown);
        loop {
            let (stream, remote) = tokio::select! {
                () = &mut shutdown => break,
                accepted = listener.accept() => match accepted {
                    Ok(a) => a,
                    Err(e) => {
                        // Likely out of file descriptors -> sleep, no spin.
                        warn!(error = %e, "XMPP accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                },
            };
            // Over a cap -> close at once, before any task, handshake or buffer exists.
            let permit = match self.inner.limiter.acquire(remote.ip()) {
                Ok(p) => p,
                Err(refused) => {
                    metrics::counter!(
                        "dhonomos_xmpp_refused_connections_total",
                        "reason" => refused.reason()
                    )
                    .increment(1);
                    dhonomos_common::connection_refused!("xmpp", refused.reason(), remote);
                    continue;
                }
            };
            enable_tcp_keepalive(&stream);
            let _ = stream.set_nodelay(true);
            tokio::spawn(session::run(
                Arc::clone(&self.inner),
                stream,
                remote.ip(),
                permit,
            ));
        }
        let _ = self.inner.shutdown.send(true);
        for _ in 0..40 {
            if self.inner.limiter.open() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    }

    /// Ask device `account` (JID local part) to open a CWMP session.
    ///
    /// Sends a CR (TR-069 Annex K) with `username` + `password`; device checks them against
    /// its own. Waits up to `timeout` for the answer. Credentials never logged.
    pub async fn send_connection_request(
        &self,
        account: &str,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<CrOutcome, SendError> {
        let id = format!("cr-{}", random_hex(12));
        let from = format!(
            "{ACS_LOCALPART}@{}/{ACS_RESOURCE}",
            self.inner.config.domain
        );
        let (done, answer) = oneshot::channel();
        let (tx, queued, close, stanza) = {
            let mut reg = self.inner.lock();
            let Some(live) = reg.sessions.get(account) else {
                return Ok(CrOutcome::NotConnected);
            };
            let stanza = wire::connection_request(&id, &from, &live.jid, username, password)
                .ok_or(SendError::Unrepresentable)?;
            let sent = (
                live.tx.clone(),
                Arc::clone(&live.queued),
                Arc::clone(&live.close),
                stanza,
            );
            let session = live.id;
            reg.pending.insert(
                id.clone(),
                PendingCr {
                    account: account.to_owned(),
                    session,
                    done,
                },
            );
            sent
        };
        // Any exit from here -> request removed from pending.
        let _forget = Forget {
            inner: &self.inner,
            id: &id,
        };
        let len = stanza.len();
        if len > self.inner.config.queue_limit {
            return Err(SendError::TooLarge);
        }
        if queued.fetch_add(len, Ordering::AcqRel) + len > self.inner.config.queue_limit {
            queued.fetch_sub(len, Ordering::AcqRel);
            warn!(%account, "XMPP connection is not reading; closing it");
            close.fire(Condition::ResourceConstraint);
            return Err(SendError::QueueFull);
        }
        if tx.send(Bytes::from(stanza)).is_err() {
            return Ok(CrOutcome::NotConnected);
        }
        metrics::counter!("dhonomos_xmpp_connection_requests_sent_total").increment(1);
        Ok(match tokio::time::timeout(timeout, answer).await {
            Ok(Ok(CrReply::Result)) => CrOutcome::Acknowledged,
            Ok(Ok(CrReply::Error(condition))) => CrOutcome::Rejected(condition),
            // Session ended, request unanswered.
            Ok(Err(_)) => CrOutcome::NotConnected,
            Err(_) => CrOutcome::TimedOut,
        })
    }
}

/// Drop -> CR removed from pending.
struct Forget<'a> {
    inner: &'a Inner,
    id: &'a str,
}

impl Drop for Forget<'_> {
    fn drop(&mut self) {
        self.inner.lock().pending.remove(self.id);
    }
}

impl Inner {
    fn lock(&self) -> std::sync::MutexGuard<'_, Registry> {
        // Poisoned = only a panic elsewhere mid-update of plain maps -> use it anyway.
        self.registry.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Make `account` reachable at `account@domain/resource`.
    ///
    /// Older session of the account -> told to end with `conflict`.
    pub(crate) fn register(&self, account: &str, resource: &str) -> Registration {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let jid = format!("{account}@{}/{resource}", self.config.domain);
        let (tx, outbox) = mpsc::unbounded_channel();
        let queued = Arc::new(AtomicUsize::new(0));
        let close = Arc::new(CloseSignal::default());
        let old = {
            let mut reg = self.lock();
            let old = reg.sessions.insert(
                account.to_owned(),
                Live {
                    id,
                    jid: jid.clone(),
                    tx,
                    queued: Arc::clone(&queued),
                    close: Arc::clone(&close),
                },
            );
            if let Some(old) = &old {
                // CRs sent to the older session -> never answered.
                reg.pending.retain(|_, p| p.session != old.id);
            }
            metrics::gauge!("dhonomos_xmpp_connections").set(reg.sessions.len() as f64);
            old
        };
        if let Some(old) = old {
            debug!(%account, "XMPP session replaced by a newer one");
            old.close.fire(Condition::Conflict);
        }
        // Microsecond precision = DB timestamp it ends up in.
        let now = SystemTime::now();
        let micros = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_micros());
        let connected_at = SystemTime::UNIX_EPOCH
            + Duration::from_micros(u64::try_from(micros).unwrap_or(u64::MAX));
        Registration {
            id,
            jid,
            outbox,
            queued,
            close,
            connected_at,
        }
    }

    /// Remove session `id` of `account` from the table.
    ///
    /// `true` -> it was the current session (not replaced by a newer one).
    pub(crate) fn unregister(&self, account: &str, id: u64) -> bool {
        let mut reg = self.lock();
        reg.pending.retain(|_, p| p.session != id);
        let current = reg.sessions.get(account).is_some_and(|l| l.id == id);
        if current {
            reg.sessions.remove(account);
        }
        metrics::gauge!("dhonomos_xmpp_connections").set(reg.sessions.len() as f64);
        current
    }

    /// Device answer to CR `id`. Accepted only from the session it was sent to.
    pub(crate) fn complete(&self, account: &str, session: u64, id: &str, reply: CrReply) {
        let pending = {
            let mut reg = self.lock();
            match reg.pending.get(id) {
                Some(p) if p.account == account && p.session == session => reg.pending.remove(id),
                _ => None,
            }
        };
        if let Some(p) = pending {
            let _ = p.done.send(reply);
        }
    }

    /// Source key of `ip` for failed-login counters.
    pub(crate) fn client(ip: IpAddr) -> IpAddr {
        crate::connlimit::source(ip)
    }
}
