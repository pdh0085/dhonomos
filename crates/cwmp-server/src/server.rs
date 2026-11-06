//! HTTP/1.1 listener -> CWMP sessions.

use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dhonomos_cwmp_codec::{Body, Envelope, Rpc};
use dhonomos_cwmp_session::{Reply, Session, SessionError, Step};
use http_body_util::{BodyExt as _, Full, LengthLimitError, Limited};
use hyper::body::{Body as _, Incoming};
use hyper::header::{self, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::auth::{AuthMode, Authenticator, RequestInfo, Verdict};
use crate::backend::{Backend, InformContext};
use crate::connlimit::{ConnLimiter, ConnPermit};

const COOKIE: &str = "dhonomos_session";

/// Max body of an unauthenticated request read + dropped before the 401.
///
/// Inform ~ few KiB; CPE retries it with credentials on the same connection.
/// Larger or slower body -> 401 + `Connection: close`.
const CHALLENGE_DRAIN_LIMIT: usize = 64 << 10;

/// Listener config.
#[derive(Debug, Clone)]
pub struct Config {
    /// CPE auth mode.
    pub auth: AuthMode,
    /// Digest/Basic realm.
    pub realm: String,
    /// Digest nonce lifetime.
    pub nonce_lifetime: Duration,
    /// Accept RFC 2069 Digest (no `qop`): old HTTP stacks send it.
    /// No client nonce or count -> no replay check. Challenge always offers `qop=auth`.
    /// Off once no CPE needs the fallback (L-4).
    pub digest_no_qop: bool,
    /// Bind Digest nonce to the address it was issued to (IPv6: its /64).
    /// Off if CPEs come via several proxies -> address differs between challenge and answer.
    pub digest_bind_client: bool,
    /// Max request body size as received (CW-17).
    pub max_body_bytes: usize,
    /// Max compressed request body size after decompression (CW-01, gzip bombs).
    pub max_decoded_body_bytes: usize,
    /// Idle time -> session aborted. Runtime change: [`AcsServer::set_session_timeout`].
    pub session_timeout: Duration,
    /// Max requests processed at once (CW-17 load shedding).
    pub max_concurrent_requests: usize,
    /// Failed auths from one address (IPv6: /64) within `auth_failure_window`
    /// -> address refused for that long (CW-17). 0 = off.
    pub auth_failure_limit: u32,
    /// See `auth_failure_limit`.
    pub auth_failure_window: Duration,
    /// Time for request headers, from connection open or previous response.
    /// Keep-alive connection silent that long between requests -> closed too.
    /// Must be non-zero (slowloris, H-6).
    pub header_read_timeout: Duration,
    /// Time for the whole request body. Slower -> 408 + connection closed.
    /// Must be non-zero.
    pub body_read_timeout: Duration,
    /// Time for the TLS handshake.
    pub tls_handshake_timeout: Duration,
    /// Max open connections; more -> closed at once. 0 = unlimited.
    pub max_connections: usize,
    /// Max open connections from one address (IPv6: one /64); more -> closed at once.
    /// CPEs behind CGNAT or a TLS-terminating proxy share an address -> generous default.
    /// 0 = unlimited.
    pub max_connections_per_ip: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            auth: AuthMode::Digest,
            realm: "dhonomos".into(),
            nonce_lifetime: Duration::from_secs(300),
            digest_no_qop: true,
            digest_bind_client: true,
            max_body_bytes: 1 << 20,
            max_decoded_body_bytes: 8 << 20,
            session_timeout: Duration::from_secs(60),
            max_concurrent_requests: 1024,
            auth_failure_limit: 20,
            auth_failure_window: Duration::from_secs(600),
            header_read_timeout: Duration::from_secs(30),
            body_read_timeout: Duration::from_secs(60),
            tls_handshake_timeout: Duration::from_secs(10),
            max_connections: 20_000,
            max_connections_per_ip: 256,
        }
    }
}

/// `d` in whole ms, saturated.
fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

struct Entry<B: Backend> {
    id: String,
    fsm: Session,
    device: Option<B::Device>,
    task: Option<B::Task>,
    username: Option<String>,
    /// Tag of the password the session authenticated with.
    credential: u32,
    last: Instant,
}

/// Auth result of a request.
enum AuthOutcome {
    /// Accepted. `username` = `None` when auth is off.
    Accepted {
        username: Option<String>,
        credential: u32,
    },
    /// Missing or wrong credentials. `username` = presented one, if the header was readable.
    Rejected { username: Option<String> },
    /// Right password, nonce used up or expired -> challenge again with `stale=true`.
    Stale,
}

struct Shared<B: Backend> {
    config: Config,
    backend: B,
    auth: Authenticator,
    sessions: Mutex<HashMap<String, Entry<B>>>,
    by_device: Mutex<HashMap<B::Device, String>>,
    permits: Semaphore,
    guard: crate::guard::AuthGuard,
    connections: Arc<ConnLimiter>,
    /// `config.session_timeout` in ms, changeable at runtime.
    session_timeout_ms: AtomicU64,
}

/// CWMP ACS listener.
pub struct AcsServer<B: Backend> {
    shared: Arc<Shared<B>>,
}

impl<B: Backend> std::fmt::Debug for AcsServer<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcsServer")
            .field("config", &self.shared.config)
            .finish_non_exhaustive()
    }
}

impl<B: Backend> Clone for AcsServer<B> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

/// Bind a listening socket. Unspecified IPv6 (`[::]`) -> dual-stack, IPv4 clients too
/// (ADR-014).
pub fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = socket2::Domain::for_address(addr);
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

fn response(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = status;
    r
}

/// hyper closes the connection after `resp` is sent.
fn close_after(resp: &mut Response<Full<Bytes>>) {
    resp.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
}

/// Undo request `Content-Encoding` (gzip or deflate; CW-01).
///
/// Output capped at `limit` bytes -> small compressed body cannot expand without bound.
fn decode_body(
    encoding: Option<&HeaderValue>,
    body: Bytes,
    limit: usize,
) -> Result<Bytes, StatusCode> {
    let Some(encoding) = encoding else {
        return Ok(body);
    };
    let encoding = encoding
        .to_str()
        .map_err(|_| StatusCode::UNSUPPORTED_MEDIA_TYPE)?
        .trim()
        .to_ascii_lowercase();
    let reader: Box<dyn io::Read + '_> = match encoding.as_str() {
        "" | "identity" => return Ok(body),
        "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(&body[..])),
        // RFC 9110 "deflate" = zlib-wrapped; some clients send a raw stream.
        "deflate" if body.first().is_some_and(|b| b & 0x0f == 8) => {
            Box::new(flate2::read::ZlibDecoder::new(&body[..]))
        }
        "deflate" => Box::new(flate2::read::DeflateDecoder::new(&body[..])),
        _ => return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
    };
    let mut out = Vec::with_capacity(body.len().saturating_mul(4).min(limit));
    io::Read::read_to_end(&mut io::Read::take(reader, limit as u64 + 1), &mut out)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if out.len() > limit {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    Ok(out.into())
}

fn session_cookie(req: &Request<Incoming>) -> Option<String> {
    req.headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            (k == COOKIE).then(|| v.to_owned())
        })
}

fn new_session_id() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).unwrap_or_else(|e| panic!("OS RNG unavailable: {e}"));
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl<B: Backend> AcsServer<B> {
    pub fn new(config: Config, backend: B) -> Self {
        let auth = Authenticator::new(config.auth, &config.realm, config.nonce_lifetime)
            .allow_no_qop(config.digest_no_qop)
            .bind_client(config.digest_bind_client);
        let permits = Semaphore::new(config.max_concurrent_requests);
        let guard =
            crate::guard::AuthGuard::new(config.auth_failure_limit, config.auth_failure_window);
        let connections = ConnLimiter::new(config.max_connections, config.max_connections_per_ip);
        let session_timeout_ms = AtomicU64::new(millis(config.session_timeout));
        Self {
            shared: Arc::new(Shared {
                session_timeout_ms,
                guard,
                connections,
                config,
                backend,
                auth,
                sessions: Mutex::new(HashMap::new()),
                by_device: Mutex::new(HashMap::new()),
                permits,
            }),
        }
    }

    /// Change session idle timeout for this server + its clones.
    /// Effect within the sweep interval (max 1 s).
    pub fn set_session_timeout(&self, timeout: Duration) {
        self.shared
            .session_timeout_ms
            .store(millis(timeout), Ordering::Relaxed);
    }

    /// Idle time -> session aborted.
    pub fn session_timeout(&self) -> Duration {
        Duration::from_millis(self.shared.session_timeout_ms.load(Ordering::Relaxed))
    }

    pub fn backend(&self) -> &B {
        &self.shared.backend
    }

    pub fn session_count(&self) -> usize {
        self.shared.sessions.lock().map_or(0, |s| s.len())
    }

    pub fn connection_count(&self) -> usize {
        self.shared.connections.open()
    }

    /// Accept plain HTTP until `shutdown` resolves (dev, or behind a TLS-terminating proxy).
    /// Also aborts idle sessions.
    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> io::Result<()> {
        self.serve_with(listener, None, shutdown).await
    }

    /// Accept HTTPS until `shutdown` resolves.
    pub async fn serve_tls(
        self,
        listener: TcpListener,
        tls: tokio_rustls::TlsAcceptor,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> io::Result<()> {
        self.serve_with(listener, Some(tls), shutdown).await
    }

    async fn serve_with(
        self,
        listener: TcpListener,
        tls: Option<tokio_rustls::TlsAcceptor>,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> io::Result<()> {
        let sweeper = {
            let this = self.clone();
            tokio::spawn(async move {
                // 1/4 of the timeout, max 1 s -> runtime timeout change takes effect soon.
                let period = (this.shared.config.session_timeout / 4).min(Duration::from_secs(1));
                let mut tick = tokio::time::interval(period.max(Duration::from_millis(50)));
                loop {
                    tick.tick().await;
                    this.expire_idle().await;
                }
            })
        };
        tokio::pin!(shutdown);
        loop {
            let (stream, remote) = tokio::select! {
                () = &mut shutdown => break,
                accepted = listener.accept() => match accepted {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(error = %e, "accept failed");
                        // Out of file descriptors etc. -> no spin on the error.
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                },
            };
            // Over a cap -> closed at once, before a task or read buffer exists.
            let permit = match self.shared.connections.acquire(remote.ip()) {
                Ok(p) => p,
                Err(refused) => {
                    metrics::counter!("dhonomos_cwmp_rejected_total", "reason" => refused.reason())
                        .increment(1);
                    dhonomos_common::connection_refused!("cwmp", refused.reason(), remote);
                    continue;
                }
            };
            let this = self.clone();
            let tls = tls.clone();
            tokio::spawn(async move {
                this.serve_connection(stream, remote, tls, permit).await;
            });
        }
        sweeper.abort();
        Ok(())
    }

    /// One client connection to its end. `_permit` = its slot under the connection caps.
    async fn serve_connection(
        self,
        stream: tokio::net::TcpStream,
        remote: SocketAddr,
        tls: Option<tokio_rustls::TlsAcceptor>,
        _permit: ConnPermit,
    ) {
        // Session per connection -> for CPEs that ignore cookies.
        let conn_session: Arc<Mutex<Option<String>>> = Arc::default();
        let requested = Arc::new(AtomicBool::new(false));
        let svc = {
            let this = self.clone();
            let requested = requested.clone();
            service_fn(move |req| {
                let this = this.clone();
                let conn_session = conn_session.clone();
                requested.store(true, Ordering::Relaxed);
                async move { Ok::<_, Infallible>(this.handle(req, remote, &conn_session).await) }
            })
        };
        let config = &self.shared.config;
        // HTTP/1.1 only (= TLS ALPN list) -> no HTTP/2 preface sniff (no timer covers it),
        // no HTTP/2 stream multiplexing.
        let mut builder = auto::Builder::new(TokioExecutor::new()).http1_only();
        // No timer -> hyper silently ignores the header read timeout.
        // Re-armed after every response -> also ends idle keep-alive connections.
        builder
            .http1()
            .keep_alive(true)
            .timer(TokioTimer::new())
            .header_read_timeout(config.header_read_timeout);
        let result = match tls {
            None => builder.serve_connection(TokioIo::new(stream), svc).await,
            Some(acceptor) => {
                let handshake =
                    tokio::time::timeout(config.tls_handshake_timeout, acceptor.accept(stream))
                        .await;
                match handshake {
                    Ok(Ok(s)) => builder.serve_connection(TokioIo::new(s), svc).await,
                    Ok(Err(e)) => {
                        metrics::counter!("dhonomos_cwmp_tls_handshake_failures_total")
                            .increment(1);
                        dhonomos_common::connection_refused!(
                            "cwmp",
                            "tls_handshake",
                            remote,
                            error = %e
                        );
                        return;
                    }
                    Err(_) => {
                        metrics::counter!(
                            "dhonomos_cwmp_connection_timeouts_total",
                            "phase" => "tls_handshake"
                        )
                        .increment(1);
                        dhonomos_common::connection_refused!(
                            "cwmp",
                            "tls_handshake_timeout",
                            remote
                        );
                        return;
                    }
                }
            }
        };
        if let Err(e) = result {
            if e.downcast_ref::<hyper::Error>()
                .is_some_and(hyper::Error::is_timeout)
            {
                // No request yet -> stalled or trickling client.
                // Else quiet keep-alive connection (normal for CPEs that do not close).
                let phase = if requested.load(Ordering::Relaxed) {
                    "idle"
                } else {
                    "header"
                };
                metrics::counter!("dhonomos_cwmp_connection_timeouts_total", "phase" => phase)
                    .increment(1);
                if phase == "header" {
                    dhonomos_common::connection_refused!("cwmp", "header_timeout", remote);
                } else {
                    debug!(%remote, phase, "connection timed out");
                }
            } else {
                debug!(%remote, error = %e, "connection closed with error");
            }
        }
    }

    async fn expire_idle(&self) {
        let timeout = self.session_timeout();
        let expired: Vec<Entry<B>> = {
            let Ok(mut map) = self.shared.sessions.lock() else {
                return;
            };
            let ids: Vec<String> = map
                .iter()
                .filter(|(_, e)| e.last.elapsed() > timeout)
                .map(|(k, _)| k.clone())
                .collect();
            ids.iter().filter_map(|id| map.remove(id)).collect()
        };
        for e in expired {
            info!(device = ?e.device, "session timed out");
            metrics::counter!("dhonomos_cwmp_session_timeouts_total").increment(1);
            self.end(e, true).await;
        }
    }

    async fn end(&self, entry: Entry<B>, aborted: bool) {
        metrics::counter!(
            "dhonomos_cwmp_sessions_total",
            "outcome" => if aborted { "aborted" } else { "completed" }
        )
        .increment(1);
        metrics::gauge!("dhonomos_cwmp_sessions").decrement(1.0);
        if let Some(device) = entry.device {
            if let Ok(mut by) = self.shared.by_device.lock()
                && by.get(&device) == Some(&entry.id)
            {
                by.remove(&device);
            }
            self.shared
                .backend
                .session_ended(&device, entry.task, aborted)
                .await;
        }
    }

    #[tracing::instrument(name = "cwmp.request", skip_all, fields(remote = %remote))]
    async fn handle(
        &self,
        req: Request<Incoming>,
        remote: SocketAddr,
        conn_session: &Mutex<Option<String>>,
    ) -> Response<Full<Bytes>> {
        let start = Instant::now();
        let resp = self.handle_inner(req, remote, conn_session).await;
        metrics::histogram!("dhonomos_cwmp_request_duration_seconds")
            .record(start.elapsed().as_secs_f64());
        metrics::counter!("dhonomos_cwmp_http_responses_total", "status" => resp.status().as_u16().to_string())
            .increment(1);
        resp
    }

    async fn handle_inner(
        &self,
        req: Request<Incoming>,
        remote: SocketAddr,
        conn_session: &Mutex<Option<String>>,
    ) -> Response<Full<Bytes>> {
        // Refuse before any read -> cheap against password guessing.
        if self.shared.guard.blocked(remote.ip(), Instant::now()) {
            metrics::counter!("dhonomos_cwmp_rejected_total", "reason" => "auth_blocked")
                .increment(1);
            dhonomos_common::request_refused!("cwmp", "auth_blocked", remote);
            return response(StatusCode::FORBIDDEN, "");
        }
        if req.method() != Method::POST {
            return response(StatusCode::METHOD_NOT_ALLOWED, "");
        }
        let cookie =
            session_cookie(&req).or_else(|| conn_session.lock().ok().and_then(|s| s.clone()));
        let authorization = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let encoding = req.headers().get(header::CONTENT_ENCODING).cloned();

        // Outside a session -> authenticate before any use of the body.
        // Basic/Digest do not depend on the body. Unproven peer must not make the server
        // buffer, decompress or parse what it sent.
        let in_session = cookie.as_ref().is_some_and(|c| {
            self.shared
                .sessions
                .lock()
                .is_ok_and(|sessions| sessions.contains_key(c))
        });
        let target = req
            .uri()
            .path_and_query()
            .map_or_else(|| "/".to_owned(), |p| p.as_str().to_owned());
        let mut preauthenticated = None;
        if !in_session {
            let outcome = {
                let Ok(_permit) = self.shared.permits.try_acquire() else {
                    return response(StatusCode::SERVICE_UNAVAILABLE, "busy");
                };
                self.authenticate(authorization.as_deref(), &target, remote)
                    .await
            };
            match outcome {
                AuthOutcome::Accepted {
                    username,
                    credential,
                } => preauthenticated = Some((username, credential)),
                failed => {
                    let stale = matches!(failed, AuthOutcome::Stale);
                    self.auth_failed(remote, authorization.is_some() && !stale, &failed);
                    // Small body -> keep the connection for the CPE retry.
                    let reusable = self
                        .discard_body(req.into_body(), CHALLENGE_DRAIN_LIMIT)
                        .await;
                    let mut challenge = self.challenge(remote, stale);
                    if !reusable {
                        close_after(&mut challenge);
                    }
                    return challenge;
                }
            }
        }

        // Body read with no permit held -> slow uploads cannot starve request processing.
        // Own read deadline; connection caps bound how many run at once.
        let body = match self.read_body(req.into_body(), remote).await {
            Ok(b) => b,
            Err(status) => {
                let mut r = response(status, "");
                if status == StatusCode::REQUEST_TIMEOUT {
                    // Rest of the body still in flight -> connection not reusable.
                    close_after(&mut r);
                }
                return r;
            }
        };
        let Ok(_permit) = self.shared.permits.try_acquire() else {
            return response(StatusCode::SERVICE_UNAVAILABLE, "busy");
        };
        let body = match decode_body(
            encoding.as_ref(),
            body,
            self.shared.config.max_decoded_body_bytes,
        ) {
            Ok(b) => b,
            Err(status) => {
                metrics::counter!("dhonomos_cwmp_rejected_total", "reason" => "content_encoding")
                    .increment(1);
                dhonomos_common::request_refused!(
                    "cwmp",
                    "content_encoding",
                    remote,
                    ?encoding,
                    %status
                );
                return response(status, "");
            }
        };
        let envelope = match Envelope::decode(&body) {
            Ok(e) => e,
            Err(e) => {
                warn!(%remote, error = %e, "undecodable CWMP message");
                return response(StatusCode::BAD_REQUEST, "");
            }
        };

        let is_inform = matches!(
            &envelope,
            Some(Envelope {
                body: Body::Rpc(Rpc::Inform(_)),
                ..
            })
        );
        let (id, entry) = if is_inform {
            // Inform inside a session (CPE starts over on its connection) -> still auth.
            // Cookie only proves the old session.
            let (username, credential) = match preauthenticated {
                Some(done) => done,
                None => match self
                    .authenticate(authorization.as_deref(), &target, remote)
                    .await
                {
                    AuthOutcome::Accepted {
                        username,
                        credential,
                    } => (username, credential),
                    failed => {
                        let stale = matches!(failed, AuthOutcome::Stale);
                        self.auth_failed(remote, authorization.is_some() && !stale, &failed);
                        return self.challenge(remote, stale);
                    }
                },
            };
            self.shared.guard.succeeded(remote.ip());
            // New Inform -> replaces any old session of this client.
            if let Some(old) = cookie
                .as_ref()
                .and_then(|c| self.shared.sessions.lock().ok()?.remove(c))
            {
                self.end(old, true).await;
            }
            let id = new_session_id();
            metrics::gauge!("dhonomos_cwmp_sessions").increment(1.0);
            metrics::counter!("dhonomos_cwmp_informs_total").increment(1);
            let entry = Entry {
                id: id.clone(),
                fsm: Session::new(&id[..8]),
                device: None,
                task: None,
                username,
                credential,
                last: Instant::now(),
            };
            (id, entry)
        } else {
            let taken = cookie
                .as_ref()
                .and_then(|c| Some((c.clone(), self.shared.sessions.lock().ok()?.remove(c)?)));
            match taken {
                Some(t) => t,
                None => {
                    debug!(%remote, "message outside a session");
                    return response(StatusCode::BAD_REQUEST, "");
                }
            }
        };

        let (reply, entry) = self.drive(entry, envelope, remote).await;
        let Some(reply) = reply else {
            return response(StatusCode::BAD_REQUEST, "");
        };

        if let Some(entry) = entry {
            if entry.fsm.is_ended() {
                if let Ok(mut s) = conn_session.lock() {
                    s.take();
                }
                self.end(entry, false).await;
            } else {
                if let Ok(mut s) = conn_session.lock() {
                    *s = Some(id.clone());
                }
                if let Ok(mut map) = self.shared.sessions.lock() {
                    map.insert(id.clone(), entry);
                }
            }
        }

        let mut resp = match reply.to_body() {
            Some(xml) => {
                let mut r = response(StatusCode::OK, xml);
                r.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/xml; charset=\"utf-8\""),
                );
                r
            }
            None => response(StatusCode::NO_CONTENT, ""),
        };
        if is_inform
            && let Ok(v) = HeaderValue::from_str(&format!("{COOKIE}={id}; Path=/; HttpOnly"))
        {
            resp.headers_mut().insert(header::SET_COOKIE, v);
        }
        resp
    }

    /// Check credentials against every password the backend accepts for the username.
    async fn authenticate(
        &self,
        authorization: Option<&str>,
        target: &str,
        remote: SocketAddr,
    ) -> AuthOutcome {
        let auth = &self.shared.auth;
        if auth.mode() == AuthMode::None {
            return AuthOutcome::Accepted {
                username: None,
                credential: 0,
            };
        }
        let Some(presented) = auth.parse(authorization) else {
            return AuthOutcome::Rejected { username: None };
        };
        let request = RequestInfo {
            method: "POST",
            target,
            client: remote.ip(),
        };
        let mut stale = false;
        for c in self.shared.backend.candidates(presented.username()).await {
            match auth.verify(&presented, &request, &c.password) {
                Verdict::Valid => {
                    return AuthOutcome::Accepted {
                        username: Some(presented.username().to_owned()),
                        credential: c.tag,
                    };
                }
                Verdict::Stale => stale = true,
                Verdict::Invalid => {}
            }
        }
        if stale {
            AuthOutcome::Stale
        } else {
            AuthOutcome::Rejected {
                username: Some(presented.username().to_owned()),
            }
        }
    }

    /// 401 with the configured challenges. Nonce bound to client address if
    /// `digest_bind_client`.
    fn challenge(&self, remote: SocketAddr, stale: bool) -> Response<Full<Bytes>> {
        let mut r = response(StatusCode::UNAUTHORIZED, "");
        for c in self.shared.auth.challenges(remote.ip(), stale) {
            if let Ok(v) = HeaderValue::from_str(&c) {
                r.headers_mut().append(header::WWW_AUTHENTICATE, v);
            }
        }
        r
    }

    /// Count a failed auth. 1st request of a Digest exchange has no credentials
    /// (`presented` false) -> challenge round, not a failure.
    fn auth_failed(&self, remote: SocketAddr, presented: bool, outcome: &AuthOutcome) {
        if presented {
            metrics::counter!("dhonomos_cwmp_auth_failures_total").increment(1);
            // Username tried = not a secret -> shows what is guessed.
            let username = match outcome {
                AuthOutcome::Rejected { username } => {
                    username.as_deref().map(dhonomos_common::refusal::clip)
                }
                _ => None,
            };
            dhonomos_common::request_refused!(
                "cwmp",
                "auth_failed",
                remote,
                username = username.as_deref()
            );
            if self.shared.guard.failed(remote.ip(), Instant::now()) {
                warn!(%remote, limit = self.shared.config.auth_failure_limit,
                    "blocking a source after repeated CPE authentication failures");
            }
        }
    }

    /// Read body: max `max_body_bytes`, within `body_read_timeout`. Error = status to answer.
    async fn read_body(&self, body: Incoming, remote: SocketAddr) -> Result<Bytes, StatusCode> {
        let read = Limited::new(body, self.shared.config.max_body_bytes).collect();
        match tokio::time::timeout(self.shared.config.body_read_timeout, read).await {
            Ok(Ok(b)) => Ok(b.to_bytes()),
            Ok(Err(e)) if e.is::<LengthLimitError>() => Err(StatusCode::PAYLOAD_TOO_LARGE),
            Ok(Err(_)) => Err(StatusCode::BAD_REQUEST),
            Err(_) => {
                metrics::counter!("dhonomos_cwmp_rejected_total", "reason" => "body_timeout")
                    .increment(1);
                dhonomos_common::request_refused!("cwmp", "body_timeout", remote);
                Err(StatusCode::REQUEST_TIMEOUT)
            }
        }
    }

    /// Read + drop a body, no buffering. True if it ended within `limit` bytes and
    /// `body_read_timeout` -> connection can carry another request.
    async fn discard_body(&self, mut body: Incoming, limit: usize) -> bool {
        if body.size_hint().lower() > limit as u64 {
            return false;
        }
        let drain = async {
            let mut seen = 0usize;
            while let Some(frame) = body.frame().await {
                let Ok(frame) = frame else { return false };
                seen += frame.data_ref().map_or(0, Bytes::len);
                if seen > limit {
                    return false;
                }
            }
            true
        };
        tokio::time::timeout(self.shared.config.body_read_timeout, drain)
            .await
            .unwrap_or(false)
    }

    /// One session step -> (reply, entry to keep).
    ///
    /// Reply `None` = protocol error, session dropped. Entry `None` = dropped.
    async fn drive(
        &self,
        mut entry: Entry<B>,
        envelope: Option<Envelope>,
        remote: SocketAddr,
    ) -> (Option<Reply>, Option<Entry<B>>) {
        entry.last = Instant::now();
        let step = match entry.fsm.receive(envelope) {
            Ok(s) => s,
            Err(e) => {
                warn!(%remote, device = ?entry.device, error = %e, "CWMP protocol error; dropping session");
                self.end(entry, true).await;
                return (None, None);
            }
        };
        let reply = match step {
            Step::Reply(r) => Ok(r),
            Step::CpeRequest(Rpc::Inform(inform)) => {
                let ctx = InformContext {
                    inform: &inform,
                    cwmp_version: entry.fsm.cwmp_version(),
                    remote,
                    username: entry.username.as_deref(),
                    credential: entry.credential,
                };
                match self.shared.backend.inform(ctx).await {
                    Ok(device) => {
                        self.claim_device(&device, &entry.id).await;
                        entry.device = Some(device);
                        entry.fsm.answer(Ok(()))
                    }
                    Err(fault) => entry.fsm.answer(Err(fault)),
                }
            }
            Step::CpeRequest(rpc) => {
                let outcome = match &entry.device {
                    Some(d) => self.shared.backend.cpe_request(d, &rpc).await,
                    None => Ok(()),
                };
                entry.fsm.answer(outcome)
            }
            Step::AcsTurn { completed } => {
                if let (Some(c), Some(task), Some(d)) =
                    (completed, entry.task.take(), entry.device.as_ref())
                {
                    self.shared.backend.completed(d, task, c).await;
                }
                let next = match &entry.device {
                    Some(d) => self.shared.backend.next_request(d).await,
                    None => None,
                };
                let (task, rpc) = match next {
                    Some((t, r)) => (Some(t), Some(r)),
                    None => (None, None),
                };
                entry.task = task;
                entry.fsm.send(rpc)
            }
        };
        match reply {
            Ok(r) => (Some(r), Some(entry)),
            Err(e @ SessionError::Misuse { .. }) => {
                warn!(error = %e, "session API misuse (backend returned a response as a request?)");
                self.end(entry, true).await;
                (None, None)
            }
            Err(e) => {
                warn!(error = %e, "session error");
                self.end(entry, true).await;
                (None, None)
            }
        }
    }

    /// One session per device (CW-11): older session aborted.
    async fn claim_device(&self, device: &B::Device, session_id: &str) {
        let previous = self
            .shared
            .by_device
            .lock()
            .ok()
            .and_then(|by| by.get(device).cloned());
        if let Some(old_id) = previous.filter(|p| p != session_id)
            && let Some(old) = self
                .shared
                .sessions
                .lock()
                .ok()
                .and_then(|mut m| m.remove(&old_id))
        {
            info!(?device, "replacing an older session of the same device");
            self.end(old, true).await;
        }
        if let Ok(mut by) = self.shared.by_device.lock() {
            by.insert(device.clone(), session_id.to_owned());
        }
    }
}
