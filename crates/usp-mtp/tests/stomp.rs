//! Embedded STOMP broker.
//! Limits: small frames before login, connection caps, Agents that stop reading.
//! Client certs: EndpointIDs they bind + revocation.
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dhonomos_pki::{Ca, Issued, Profile};
use dhonomos_usp_mtp::stomp::{Frame, Parsed, USP_CONTENT_TYPE};
use dhonomos_usp_mtp::{Inbound, MultiMtp, StompConfig, StompMtp, tls_acceptor};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const CONTROLLER_DEST: &str = "/queue/usp.controller";

struct Env {
    stomp: StompMtp,
    addr: SocketAddr,
    inbound: mpsc::Receiver<Inbound>,
}

impl Env {
    async fn start(config: StompConfig) -> Self {
        Self::start_with(config, None).await
    }

    async fn start_with(config: StompConfig, tls: Option<tokio_rustls::TlsAcceptor>) -> Self {
        let (tx, inbound) = mpsc::channel(256);
        let stomp = StompMtp::new(tx, config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = stomp.clone();
        tokio::spawn(async move {
            serving
                .serve(listener, tls, std::future::pending())
                .await
                .unwrap()
        });
        Self {
            stomp,
            addr,
            inbound,
        }
    }

    async fn client(&self) -> Client {
        Client::new(TcpStream::connect(self.addr).await.unwrap())
    }

    /// Client after login + subscribe.
    async fn agent(&self, eid: &str) -> Client {
        let mut c = self.client().await;
        c.login(eid).await;
        c
    }

    async fn inbound(&mut self) -> Inbound {
        tokio::time::timeout(Duration::from_secs(5), self.inbound.recv())
            .await
            .expect("no Inbound")
            .unwrap()
    }
}

/// Client transport: socket, or TLS over one.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

struct Client {
    tcp: Box<dyn Io>,
    buf: Vec<u8>,
}

impl Client {
    fn new(tcp: TcpStream) -> Self {
        tcp.set_nodelay(true).unwrap();
        Self::over(tcp)
    }

    fn over(io: impl Io + 'static) -> Self {
        Self {
            tcp: Box::new(io),
            buf: Vec::new(),
        }
    }

    /// Write; ignore a connection already closed by the broker.
    async fn write(&mut self, bytes: &[u8]) {
        let _ = self.tcp.write_all(bytes).await;
    }

    /// Next frame. `None` -> broker closed (or reset) the connection.
    async fn next(&mut self) -> Option<Frame> {
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            match Frame::parse(&self.buf, 16 << 20).unwrap() {
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

    /// Send `STOMP` for `eid` -> answer: `CONNECTED` or `ERROR`.
    async fn hello(&mut self, eid: &str) -> Frame {
        let stomp = Frame::new(
            "STOMP",
            &[
                ("accept-version", "1.2"),
                ("endpoint-id", eid),
                ("heart-beat", "0,0"),
            ],
        );
        self.write(&stomp.encode()).await;
        self.next().await.expect("CONNECTED or ERROR")
    }

    async fn login(&mut self, eid: &str) {
        let connected = self.hello(eid).await;
        assert_eq!(connected.command, "CONNECTED");
        let dest = connected.header("subscribe-dest").unwrap().to_owned();
        let subscribe = Frame::new(
            "SUBSCRIBE",
            &[("id", "0"), ("destination", &dest), ("receipt", "r1")],
        );
        self.write(&subscribe.encode()).await;
        assert_eq!(self.next().await.expect("RECEIPT").command, "RECEIPT");
    }

    /// true -> broker closes the connection (no frame, or ERROR frame then close).
    async fn is_closed(&mut self) -> bool {
        match self.next().await {
            None => true,
            Some(f) => f.command == "ERROR" && self.next().await.is_none(),
        }
    }
}

async fn poll(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn before_login_a_frame_over_8_kib_closes_the_connection() {
    let env = Env::start(StompConfig::default()).await;
    // Header line with no end -> cap hit long before 8 MiB.
    let mut c = env.client().await;
    c.write(b"CONNECT\npad:").await;
    for _ in 0..4 {
        c.write(&[b'x'; 4096]).await;
    }
    assert!(c.is_closed().await);
    // Big announced body, frame otherwise fine.
    let mut c = env.client().await;
    c.write(b"CONNECT\naccept-version:1.2\nendpoint-id:os::A\ncontent-length:5000000\n\n")
        .await;
    assert!(c.is_closed().await);
    // Body without length, no end.
    let mut c = env.client().await;
    c.write(b"CONNECT\naccept-version:1.2\nendpoint-id:os::A\n\n")
        .await;
    for _ in 0..4 {
        c.write(&[b'x'; 4096]).await;
    }
    assert!(c.is_closed().await);
    assert_eq!(env.stomp.connections(), 0);
    // Normal Agent not affected.
    env.agent("os::B").await;
}

#[tokio::test]
async fn too_many_headers_are_refused() {
    let env = Env::start(StompConfig::default()).await;
    let connect = |extra: usize| {
        let mut f = String::from("STOMP\naccept-version:1.2\nendpoint-id:os::A\n");
        for i in 0..extra {
            f.push_str(&format!("x{i}:v\n"));
        }
        f.push_str("\n\0");
        f
    };
    // Max 64 headers, incl. the 2 of the login.
    let mut c = env.client().await;
    c.write(connect(62).as_bytes()).await;
    assert_eq!(c.next().await.unwrap().command, "CONNECTED");
    let mut c = env.client().await;
    c.write(connect(63).as_bytes()).await;
    assert!(c.is_closed().await);
    // Same after login.
    let mut agent = env.agent("os::B").await;
    let mut send = String::from("SEND\ndestination:/queue/usp.controller\n");
    for i in 0..70 {
        send.push_str(&format!("x{i}:v\n"));
    }
    send.push_str("\n\0");
    agent.write(send.as_bytes()).await;
    assert!(agent.is_closed().await);
}

#[tokio::test]
async fn a_record_in_small_pieces_is_delivered_in_time() {
    let mut env = Env::start(StompConfig::default()).await;
    let mut agent = env.agent("os::A").await;
    // Largest Record, 4 KiB pieces, with and without content-length.
    let body = vec![b'x'; (8 << 20) - 4096];
    for with_length in [true, false] {
        let mut wire =
            format!("SEND\ndestination:{CONTROLLER_DEST}\ncontent-type:{USP_CONTENT_TYPE}\n")
                .into_bytes();
        if with_length {
            wire.extend_from_slice(format!("content-length:{}\n", body.len()).as_bytes());
        }
        wire.push(b'\n');
        wire.extend_from_slice(&body);
        wire.push(0);
        let started = Instant::now();
        for piece in wire.chunks(4096) {
            agent.tcp.write_all(piece).await.unwrap();
        }
        let got = env.inbound().await;
        assert_eq!(got.payload.len(), body.len());
        assert_eq!(got.sender.as_deref(), Some("os::A"));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "content-length {with_length}: {:?}",
            started.elapsed()
        );
    }
}

/// true -> connection refused at accept: any write answered by connection end, not CONNECTED.
async fn refused(env: &Env) -> bool {
    let mut c = env.client().await;
    let stomp = Frame::new(
        "STOMP",
        &[("accept-version", "1.2"), ("endpoint-id", "os::probe")],
    );
    c.write(&stomp.encode()).await;
    c.next().await.is_none()
}

async fn accepted_eventually(env: &Env) -> Client {
    for _ in 0..100 {
        let mut c = env.client().await;
        let stomp = Frame::new(
            "STOMP",
            &[("accept-version", "1.2"), ("endpoint-id", "os::probe")],
        );
        c.write(&stomp.encode()).await;
        if c.next().await.is_some() {
            return c;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no free slot");
}

#[tokio::test]
async fn connections_over_the_per_address_cap_are_closed_at_accept() {
    // All clients from loopback -> 1 address.
    let env = Env::start(StompConfig {
        max_connections_per_ip: 2,
        ..StompConfig::default()
    })
    .await;
    let a = env.agent("os::A").await;
    let _b = env.agent("os::B").await;
    assert!(refused(&env).await, "a third connection");
    assert!(refused(&env).await, "and a fourth");
    assert_eq!(env.stomp.connections(), 2);
    // Connection end -> slot free.
    drop(a);
    let _c = accepted_eventually(&env).await;
}

#[tokio::test]
async fn connections_over_the_global_cap_are_closed_at_accept() {
    let env = Env::start(StompConfig {
        max_connections: 1,
        max_connections_per_ip: 0,
        ..StompConfig::default()
    })
    .await;
    let a = env.agent("os::A").await;
    assert!(refused(&env).await);
    drop(a);
    let _b = accepted_eventually(&env).await;
    // 0 = no cap.
    let env = Env::start(StompConfig {
        max_connections: 0,
        max_connections_per_ip: 0,
        ..StompConfig::default()
    })
    .await;
    let mut held = Vec::new();
    for i in 0..30 {
        held.push(env.agent(&format!("os::{i}")).await);
    }
}

/// Client with tiny receive buffer -> few records fill the path to it.
async fn client_with_a_small_buffer(addr: SocketAddr) -> Client {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    socket.connect(&addr.into()).unwrap();
    socket.set_nonblocking(true).unwrap();
    Client::new(TcpStream::from_std(socket.into()).unwrap())
}

/// Agent logs in, then reads nothing -> stalls only its own connection:
/// sends to it fail at once on full queue, other Agents served,
/// connection closed after write timeout with no progress.
#[tokio::test]
async fn an_agent_that_stops_reading_does_not_hold_up_others_and_is_closed() {
    let mut env = Env::start(StompConfig {
        write_timeout: Duration::from_millis(500),
        ..StompConfig::default()
    })
    .await;
    let mut stuck = client_with_a_small_buffer(env.addr).await;
    stuck.login("os::stuck").await;
    let mut fine = env.agent("os::fine").await;

    // Send Records until path to Agent + its queue full. Calls do not wait.
    let started = Instant::now();
    let mut sent = 0;
    let mut refused = None;
    for _ in 0..200 {
        match env.stomp.send("os::stuck", vec![0u8; 1 << 20]).await {
            Ok(_) => sent += 1,
            Err(e) => {
                refused = Some(e.to_string());
                break;
            }
        }
        // Let broker task write what it can.
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

    // Other Agent served meanwhile.
    env.stomp.send("os::fine", vec![1, 2, 3]).await.unwrap();
    let message = fine.next().await.unwrap();
    assert_eq!(message.command, "MESSAGE");
    assert_eq!(message.body.as_ref(), [1, 2, 3]);

    // Stalled connection closed after write timeout with no progress -> Controller told.
    poll("the stalled connection to close", || {
        env.stomp.connections() == 1
    })
    .await;
    let closed = loop {
        let i = env.inbound().await;
        if i.closed {
            break i;
        }
    };
    assert_eq!(closed.reply_to.as_deref(), Some("stomp:os::stuck"));
    assert!(env.stomp.send("os::stuck", vec![1]).await.is_err());
    env.stomp.send("os::fine", vec![4]).await.unwrap();
    assert_eq!(fine.next().await.unwrap().body.as_ref(), [4]);
}

// --- Client certificates (H-3, M-5) ------------------------------------------------------

fn agent_cert(ca: &Ca, eid: &str) -> Issued {
    ca.issue(&Profile {
        endpoint_id: eid.into(),
        days: 1,
        ..Profile::default()
    })
    .unwrap()
}

fn client_config(ca: &Ca, agent: Option<&Issued>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(ca.cert_pem().as_bytes()).unwrap())
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    Arc::new(match agent {
        Some(a) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from_pem_slice(a.cert_pem.as_bytes()).unwrap()],
                PrivateKeyDer::from_pem_slice(a.key_pem.as_deref().unwrap().as_bytes()).unwrap(),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    })
}

async fn tls_client(addr: SocketAddr, config: Arc<rustls::ClientConfig>) -> Client {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(config)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    Client::over(tls)
}

/// Client certs optional (same as wss).
fn optional_client_certs(ca: &Ca) -> tokio_rustls::TlsAcceptor {
    let server = ca
        .issue(&Profile {
            endpoint_id: "self::ctrl".into(),
            dns_names: vec!["localhost".into()],
            server: true,
            days: 1,
            ..Profile::default()
        })
        .unwrap();
    tls_acceptor(
        &server.cert_pem,
        server.key_pem.as_deref().unwrap(),
        Some(ca.cert_pem()),
        false,
    )
    .unwrap()
}

/// `message` header of an `ERROR` frame.
fn error_of(answer: &Frame) -> &str {
    assert_eq!(answer.command, "ERROR", "{answer:?}");
    answer.header("message").unwrap()
}

/// EndpointID claim (shared login) never takes it from a connection with a cert.
/// Connection with a cert replaces any.
#[tokio::test]
async fn a_claim_never_replaces_a_connection_made_with_a_certificate() {
    let ca = Ca::generate("Test USP CA").unwrap();
    let env = Env::start_with(StompConfig::default(), Some(optional_client_certs(&ca))).await;
    let alice = agent_cert(&ca, "os::alice");
    let mut genuine = tls_client(env.addr, client_config(&ca, Some(&alice))).await;
    genuine.login("os::alice").await;

    // Claim refused every time; live connection stays.
    for _ in 0..3 {
        let mut claim = tls_client(env.addr, client_config(&ca, None)).await;
        let answer = claim.hello("os::alice").await;
        assert!(error_of(&answer).contains("connected with a client certificate"));
    }
    assert_eq!(env.stomp.connections(), 1);
    env.stomp.send("os::alice", vec![1, 2]).await.unwrap();
    assert_eq!(genuine.next().await.unwrap().body.as_ref(), [1, 2]);
    // Claims of other EndpointIDs: not affected, replace each other as before.
    let mut bob = tls_client(env.addr, client_config(&ca, None)).await;
    bob.login("os::bob").await;
    let mut bob_again = tls_client(env.addr, client_config(&ca, None)).await;
    bob_again.login("os::bob").await;
    assert!(bob.is_closed().await, "the first claim was replaced");
    env.stomp.send("os::bob", vec![3]).await.unwrap();
    assert_eq!(bob_again.next().await.unwrap().body.as_ref(), [3]);

    // Cert takes over from a claim + from an older cert.
    let bob_cert = agent_cert(&ca, "os::bob");
    let mut bob_proved = tls_client(env.addr, client_config(&ca, Some(&bob_cert))).await;
    bob_proved.login("os::bob").await;
    assert!(bob_again.is_closed().await);
    let renewed = agent_cert(&ca, "os::alice");
    let mut newer = tls_client(env.addr, client_config(&ca, Some(&renewed))).await;
    newer.login("os::alice").await;
    assert!(genuine.is_closed().await);
    env.stomp.send("os::alice", vec![4]).await.unwrap();
    assert_eq!(newer.next().await.unwrap().body.as_ref(), [4]);
    // Cert of another Agent -> refused.
    let mut mallory = tls_client(env.addr, client_config(&ca, Some(&alice))).await;
    let answer = mallory.hello("os::bob").await;
    assert!(error_of(&answer).contains("not issued to this EndpointID"));
}

/// EndpointID with an issued client cert -> refused without the cert (TLS or plain).
/// Open connections not cut when it becomes bound.
#[tokio::test]
async fn an_endpoint_id_with_a_certificate_issued_is_refused_without_it() {
    let ca = Ca::generate("Test USP CA").unwrap();
    let tls_env = Env::start_with(StompConfig::default(), Some(optional_client_certs(&ca))).await;
    let plain_env = Env::start(StompConfig::default()).await;
    // Controller feeds all MTPs at once this way.
    let multi = |env: &Env| MultiMtp {
        stomp: Some(env.stomp.clone()),
        ..MultiMtp::default()
    };

    // Alice connects with shared login before she gets a cert ...
    let mut before = tls_client(tls_env.addr, client_config(&ca, None)).await;
    before.login("os::alice").await;
    let mut before_plain = Client::new(TcpStream::connect(plain_env.addr).await.unwrap());
    before_plain.login("os::alice").await;
    // ... cert issued now.
    for env in [&tls_env, &plain_env] {
        multi(env).set_certificate_bound(["os::alice".to_owned()].into());
    }
    // Her open connections stay (a cert may be on its way over them).
    tls_env.stomp.send("os::alice", vec![1]).await.unwrap();
    assert_eq!(before.next().await.unwrap().body.as_ref(), [1]);
    assert_eq!(tls_env.stomp.connections(), 1);

    // New ones without cert refused, whatever the MTP login says.
    let mut claim = tls_client(tls_env.addr, client_config(&ca, None)).await;
    let answer = claim.hello("os::alice").await;
    assert!(error_of(&answer).contains("bound to a client certificate"));
    let mut claim_plain = Client::new(TcpStream::connect(plain_env.addr).await.unwrap());
    let answer = claim_plain.hello("os::alice").await;
    assert!(error_of(&answer).contains("bound to a client certificate"));
    // Other EndpointIDs not affected.
    let mut bob = Client::new(TcpStream::connect(plain_env.addr).await.unwrap());
    bob.login("os::bob").await;

    // With cert -> in. EndpointID released -> claims allowed again.
    let alice = agent_cert(&ca, "os::alice");
    let mut proved = tls_client(tls_env.addr, client_config(&ca, Some(&alice))).await;
    proved.login("os::alice").await;
    for env in [&tls_env, &plain_env] {
        multi(env).set_certificate_bound(Default::default());
    }
    let mut claim_plain = Client::new(TcpStream::connect(plain_env.addr).await.unwrap());
    claim_plain.login("os::alice").await;
}

/// Revoked client cert -> refused + its connections closed.
#[tokio::test]
async fn a_revoked_certificate_is_refused_and_its_connections_are_closed() {
    let ca = Ca::generate("Test USP CA").unwrap();
    let mut env = Env::start_with(StompConfig::default(), Some(optional_client_certs(&ca))).await;
    let multi = MultiMtp {
        stomp: Some(env.stomp.clone()),
        ..MultiMtp::default()
    };
    let alice = agent_cert(&ca, "os::alice");
    let mut conn = tls_client(env.addr, client_config(&ca, Some(&alice))).await;
    conn.login("os::alice").await;
    let mut claim = tls_client(env.addr, client_config(&ca, None)).await;
    claim.login("os::bob").await;

    // Revoke other cert -> nothing closed.
    let stranger = agent_cert(&ca, "os::stranger");
    assert_eq!(multi.set_revoked([stranger.sha256.clone()].into()), 0);
    assert_eq!(env.stomp.connections(), 2);
    // Revoke hers -> only her connection closed, Controller hears it.
    assert_eq!(multi.set_revoked([alice.sha256.clone()].into()), 1);
    assert!(conn.is_closed().await);
    let closed = env.inbound().await;
    assert!(closed.closed);
    assert_eq!(closed.reply_to.as_deref(), Some("stomp:os::alice"));
    assert_eq!(env.stomp.connections(), 1);
    // Revoked cert -> no new connection; renewed cert -> ok.
    let mut again = tls_client(env.addr, client_config(&ca, Some(&alice))).await;
    let answer = again.hello("os::alice").await;
    assert!(error_of(&answer).contains("revoked"));
    let renewed = agent_cert(&ca, "os::alice");
    let mut ok = tls_client(env.addr, client_config(&ca, Some(&renewed))).await;
    ok.login("os::alice").await;
    // List replaced as a whole -> cert not in it -> allowed again.
    assert_eq!(multi.set_revoked(Default::default()), 0);
    let mut back = tls_client(env.addr, client_config(&ca, Some(&alice))).await;
    back.login("os::alice").await;
}

/// Log text read back by a test.
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
    /// `#[tokio::test]` runs the broker on this thread too.
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

    fn refusals(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|l| l.contains("refused") || l.contains("refusals suppressed"))
            .map(str::to_owned)
            .collect()
    }
}

#[tokio::test]
async fn a_refused_connect_is_logged_with_the_source_address_and_a_reason() {
    let logs = LogBuf::default();
    let _capture = logs.capture();
    let env = Env::start(StompConfig {
        login: Some(("agent".into(), "secret".into())),
        ..StompConfig::default()
    })
    .await;
    // Own loopback address: log limiter shared by the process.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.62:0".parse().unwrap()).unwrap();
    let mut c = Client::new(socket.connect(env.addr).await.unwrap());
    let answer = c.hello("os::X").await;
    assert_eq!(answer.command, "ERROR");
    let lines = logs.refusals();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("INFO"), "{}", lines[0]);
    assert!(
        lines[0].contains("request refused listener=usp_stomp remote=127.0.0.62 reason=bad_login"),
        "{}",
        lines[0]
    );
}

/// New connection of an Agent replaces the old one, same address.
/// Controller told after new one subscribed, not before -> else a Record sent on notice dropped.
/// Notice has serial of the new connection: `send` reports it from then on, above old serial.
#[tokio::test]
async fn the_controller_is_told_when_a_new_connection_replaces_the_old_one() {
    let mut env = Env::start(StompConfig::default()).await;
    let mut old = env.agent("os::A").await;
    let on_old = env.stomp.send("os::A", vec![1]).await.unwrap();
    assert_eq!(old.next().await.unwrap().body.as_ref(), [1]);
    assert!(
        env.inbound.try_recv().is_err(),
        "a connection that replaces nothing is not reported"
    );

    let mut new = env.client().await;
    let connected = new.hello("os::A").await;
    assert_eq!(connected.command, "CONNECTED");
    assert!(old.is_closed().await, "the old connection is replaced");
    // Old connection end != Agent end; new one not subscribed yet.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), env.inbound.recv())
            .await
            .is_err(),
        "nothing is reported before the new connection subscribes"
    );
    let dest = connected.header("subscribe-dest").unwrap().to_owned();
    let subscribe = Frame::new(
        "SUBSCRIBE",
        &[("id", "0"), ("destination", &dest), ("receipt", "r1")],
    );
    new.write(&subscribe.encode()).await;
    assert_eq!(new.next().await.unwrap().command, "RECEIPT");

    let told = env.inbound().await;
    assert_eq!(told.reply_to.as_deref(), Some("stomp:os::A"));
    assert_eq!(told.sender.as_deref(), Some("os::A"));
    assert!(!told.closed && !told.opened && told.payload.is_empty());
    let on_new = env.stomp.send("os::A", vec![2]).await.unwrap();
    assert_eq!(told.replaced_by, Some(on_new));
    assert!(on_old < on_new);
    assert_eq!(new.next().await.unwrap().body.as_ref(), [2]);
    assert!(env.inbound.try_recv().is_err(), "said once");

    // End of the new connection = Agent end.
    drop(new);
    let closed = env.inbound().await;
    assert!(closed.closed);
    assert_eq!(closed.replaced_by, None);
}
