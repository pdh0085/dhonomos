//! E2E tests of the listener: in-memory backend + real HTTP client.
#![allow(clippy::unwrap_used)]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use dhonomos_cwmp_codec::{
    Body, CwmpNamespace, DeviceId, Envelope, Fault, GetParameterValues, GetParameterValuesResponse,
    Inform, Reboot, RebootResponse, Rpc,
};
use dhonomos_cwmp_server::{
    AcsServer, AuthMode, Backend, Config, DigestInput, InformContext, bind, digest_response,
};
use dhonomos_cwmp_session::Completed;
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

#[derive(Debug, Default)]
struct State {
    queue: VecDeque<Rpc>,
    informs: Vec<String>,
    completed: Vec<Completed>,
    ended: Vec<(String, Option<u32>, bool)>,
    next_task: u32,
}

#[derive(Debug, Default, Clone)]
struct Mock(Arc<Mutex<State>>);

impl Backend for Mock {
    type Device = String;
    type Task = u32;

    async fn password(&self, username: &str) -> Option<String> {
        (username == "cpe").then(|| "secret".to_owned())
    }

    async fn inform(&self, ctx: InformContext<'_>) -> Result<String, Fault> {
        let serial = ctx.inform.device_id.serial_number.clone();
        if serial == "REJECT" {
            return Err(Fault::new(8005, "Retry request"));
        }
        self.0.lock().unwrap().informs.push(serial.clone());
        Ok(serial)
    }

    async fn cpe_request(&self, _: &String, _: &Rpc) -> Result<(), Fault> {
        Ok(())
    }

    async fn next_request(&self, _: &String) -> Option<(u32, Rpc)> {
        let mut s = self.0.lock().unwrap();
        let rpc = s.queue.pop_front()?;
        s.next_task += 1;
        Some((s.next_task, rpc))
    }

    async fn completed(&self, _: &String, _: u32, completed: Completed) {
        self.0.lock().unwrap().completed.push(completed);
    }

    async fn session_ended(&self, device: &String, task: Option<u32>, aborted: bool) {
        self.0
            .lock()
            .unwrap()
            .ended
            .push((device.clone(), task, aborted));
    }
}

async fn start(config: Config, mock: Mock, addr: &str) -> (SocketAddr, AcsServer<Mock>) {
    let listener = bind(addr.parse().unwrap()).unwrap();
    let local = listener.local_addr().unwrap();
    let server = AcsServer::new(config, mock);
    let s = server.clone();
    tokio::spawn(async move { s.serve(listener, std::future::pending()).await });
    (local, server)
}

fn open_config() -> Config {
    Config {
        auth: AuthMode::None,
        ..Config::default()
    }
}

/// Persistent HTTP/1.1 connection.
struct Client {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    cookie: Option<String>,
    use_cookie: bool,
}

struct Resp {
    status: StatusCode,
    headers: hyper::HeaderMap,
    body: Option<Envelope>,
}

impl Client {
    async fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.unwrap();
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);
        Self {
            sender,
            cookie: None,
            use_cookie: true,
        }
    }

    /// Connect from loopback address `source` (127.0.0.0/8 all local on Linux).
    async fn connect_from(source: &str, addr: SocketAddr) -> Self {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind(format!("{source}:0").parse().unwrap()).unwrap();
        let stream = socket.connect(addr).await.unwrap();
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);
        Self {
            sender,
            cookie: None,
            use_cookie: true,
        }
    }

    async fn post_raw(&mut self, body: Vec<u8>, authorization: Option<String>) -> Resp {
        self.post_encoded(body, authorization, None).await
    }

    async fn post_encoded(
        &mut self,
        body: Vec<u8>,
        authorization: Option<String>,
        encoding: Option<&str>,
    ) -> Resp {
        let mut req = Request::post("/").header("content-type", "text/xml");
        if let Some(e) = encoding {
            req = req.header("content-encoding", e);
        }
        if let (true, Some(c)) = (self.use_cookie, &self.cookie) {
            req = req.header("cookie", c.clone());
        }
        if let Some(a) = authorization {
            req = req.header("authorization", a);
        }
        let resp = self
            .sender
            .send_request(req.body(Full::new(Bytes::from(body))).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        if let Some(c) = headers.get("set-cookie") {
            self.cookie = Some(c.to_str().unwrap().split(';').next().unwrap().to_owned());
        }
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        Resp {
            status,
            headers,
            body: Envelope::decode(&bytes).unwrap(),
        }
    }

    async fn post(&mut self, env: Option<Envelope>) -> Resp {
        let body = env.map(|e| e.encode().into_bytes()).unwrap_or_default();
        self.post_raw(body, None).await
    }
}

fn inform(serial: &str) -> Envelope {
    Envelope::rpc(
        CwmpNamespace::V1_0,
        "i1",
        Inform {
            device_id: DeviceId {
                oui: "001122".into(),
                serial_number: serial.into(),
                ..DeviceId::default()
            },
            max_envelopes: 1,
            ..Inform::default()
        },
    )
}

fn rpc_of(r: &Resp) -> &Rpc {
    match &r.body.as_ref().unwrap().body {
        Body::Rpc(rpc) => rpc,
        Body::Fault(f) => panic!("unexpected fault {f:?}"),
    }
}

fn answer(r: &Resp, rpc: impl Into<Rpc>) -> Option<Envelope> {
    let id = r.body.as_ref().unwrap().header.id.clone().unwrap();
    Some(Envelope::rpc(CwmpNamespace::V1_0, id, rpc))
}

#[tokio::test]
async fn full_session_drains_queue() {
    let mock = Mock::default();
    mock.0.lock().unwrap().queue.extend([
        GetParameterValues {
            parameter_names: vec!["Device.DeviceInfo.".into()],
        }
        .into(),
        Rpc::from(Reboot::default()),
    ]);
    let (addr, server) = start(open_config(), mock.clone(), "127.0.0.1:0").await;
    let mut c = Client::connect(addr).await;

    let r = c.post(Some(inform("SN1"))).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(matches!(rpc_of(&r), Rpc::InformResponse(_)));
    assert!(
        c.cookie
            .as_deref()
            .unwrap()
            .starts_with("dhonomos_session=")
    );

    let r = c.post(None).await;
    assert!(matches!(rpc_of(&r), Rpc::GetParameterValues(_)));
    let r = c
        .post(answer(&r, GetParameterValuesResponse::default()))
        .await;
    assert!(matches!(rpc_of(&r), Rpc::Reboot(_)));
    let r = c.post(answer(&r, RebootResponse {})).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);

    let s = mock.0.lock().unwrap();
    assert_eq!(s.informs, ["SN1"]);
    assert_eq!(s.completed.len(), 2);
    assert_eq!(s.ended, [("SN1".to_owned(), None, false)]);
    assert_eq!(server.session_count(), 0);
}

#[tokio::test]
async fn cookieless_cpe_on_one_connection() {
    let mock = Mock::default();
    mock.0
        .lock()
        .unwrap()
        .queue
        .push_back(Reboot::default().into());
    let (addr, _) = start(open_config(), mock.clone(), "127.0.0.1:0").await;
    let mut c = Client::connect(addr).await;
    c.use_cookie = false;
    c.post(Some(inform("SN1"))).await;
    let r = c.post(None).await;
    assert!(matches!(rpc_of(&r), Rpc::Reboot(_)));
    let r = c.post(answer(&r, RebootResponse {})).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn digest_authentication() {
    let mock = Mock::default();
    let (addr, _) = start(Config::default(), mock.clone(), "127.0.0.1:0").await;
    let mut c = Client::connect(addr).await;
    let body = inform("SN1").encode().into_bytes();

    let r = c.post_raw(body.clone(), None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let challenges: Vec<_> = r.headers.get_all("www-authenticate").iter().collect();
    assert_eq!(challenges.len(), 2);
    let md5 = challenges[1].to_str().unwrap();
    assert!(md5.contains("algorithm=MD5"));
    let nonce = md5
        .split("nonce=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();

    let header = |password: &str| {
        let response = digest_response(&DigestInput {
            sha256: false,
            username: "cpe",
            realm: "dhonomos",
            password,
            method: "POST",
            uri: "/",
            nonce,
            nc: "00000001",
            cnonce: "c0ffee",
        });
        format!(
            r#"Digest username="cpe", realm="dhonomos", nonce="{nonce}", uri="/", qop=auth, nc=00000001, cnonce="c0ffee", response="{response}""#
        )
    };
    let r = c.post_raw(body.clone(), Some(header("wrong"))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = c.post_raw(body, Some(header("secret"))).await;
    assert_eq!(r.status, StatusCode::OK);
    // Later messages of the session -> auth by session cookie.
    let r = c.post(None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(mock.0.lock().unwrap().informs, ["SN1"]);
}

#[tokio::test]
async fn repeated_auth_failures_block_the_source() {
    let config = Config {
        auth_failure_limit: 3,
        ..Config::default()
    };
    let (addr, _) = start(config, Mock::default(), "127.0.0.1:0").await;
    let mut c = Client::connect(addr).await;
    let body = inform("SN1").encode().into_bytes();
    let r = c.post_raw(body.clone(), None).await;
    assert_eq!(
        r.status,
        StatusCode::UNAUTHORIZED,
        "challenges do not count"
    );
    let md5 = r.headers.get_all("www-authenticate").iter().nth(1).unwrap();
    let nonce = md5
        .to_str()
        .unwrap()
        .split("nonce=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let header = |password: &str| {
        let response = digest_response(&DigestInput {
            sha256: false,
            username: "cpe",
            realm: "dhonomos",
            password,
            method: "POST",
            uri: "/",
            nonce: &nonce,
            nc: "00000001",
            cnonce: "c0ffee",
        });
        format!(
            r#"Digest username="cpe", realm="dhonomos", nonce="{nonce}", uri="/", qop=auth, nc=00000001, cnonce="c0ffee", response="{response}""#
        )
    };
    for _ in 0..3 {
        let r = c.post_raw(body.clone(), Some(header("guess"))).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    // Blocked now, even with right password.
    let r = c.post_raw(body, Some(header("secret"))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn http_errors() {
    let config = Config {
        max_body_bytes: 4096,
        ..open_config()
    };
    let (addr, _) = start(config, Mock::default(), "127.0.0.1:0").await;

    let mut c = Client::connect(addr).await;
    let resp = c
        .sender
        .send_request(Request::get("/").body(Full::new(Bytes::new())).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

    let mut c = Client::connect(addr).await;
    assert_eq!(
        c.post_raw(b"<html/>".to_vec(), None).await.status,
        StatusCode::BAD_REQUEST
    );
    let mut c = Client::connect(addr).await;
    assert_eq!(
        c.post(None).await.status,
        StatusCode::BAD_REQUEST,
        "no session"
    );
    let mut c = Client::connect(addr).await;
    assert_eq!(
        c.post_raw(vec![b' '; 8192], None).await.status,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

fn compress(kind: &str, data: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use std::io::Write as _;
    match kind {
        "gzip" => {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        "zlib" => {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        _ => {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
    }
}

#[tokio::test]
async fn compressed_requests_are_decoded() {
    let mock = Mock::default();
    mock.0.lock().unwrap().queue.push_back(
        GetParameterValues {
            parameter_names: vec!["Device.DeviceInfo.".into()],
        }
        .into(),
    );
    let (addr, _) = start(open_config(), mock.clone(), "127.0.0.1:0").await;
    let mut c = Client::connect(addr).await;
    let body = compress("gzip", inform("GZ1").encode().as_bytes());
    let r = c.post_encoded(body, None, Some("gzip")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(matches!(rpc_of(&r), Rpc::InformResponse(_)));
    // Empty POST + later messages: may be compressed too.
    let r = c.post_encoded(Vec::new(), None, Some("identity")).await;
    assert!(matches!(rpc_of(&r), Rpc::GetParameterValues(_)));
    let resp = answer(&r, GetParameterValuesResponse::default()).unwrap();
    let r = c
        .post_encoded(
            compress("zlib", resp.encode().as_bytes()),
            None,
            Some("deflate"),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);

    // Raw deflate (no zlib header, sent by some CPEs) + x-gzip alias.
    for (kind, header) in [("raw", "deflate"), ("gzip", "X-GZIP")] {
        let mut c = Client::connect(addr).await;
        let body = compress(kind, inform("GZ2").encode().as_bytes());
        let r = c.post_encoded(body, None, Some(header)).await;
        assert_eq!(r.status, StatusCode::OK, "{header}");
    }
    assert_eq!(mock.0.lock().unwrap().informs, ["GZ1", "GZ2", "GZ2"]);
}

#[tokio::test]
async fn bad_compressed_requests_are_refused() {
    let config = Config {
        max_body_bytes: 4096,
        max_decoded_body_bytes: 64 * 1024,
        ..open_config()
    };
    let (addr, server) = start(config, Mock::default(), "127.0.0.1:0").await;

    // Bomb: tiny on the wire, decoded far above the limit.
    let bomb = compress("gzip", &vec![b' '; 1 << 20]);
    assert!(bomb.len() < 4096);
    let mut c = Client::connect(addr).await;
    let r = c.post_encoded(bomb, None, Some("gzip")).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);

    let mut c = Client::connect(addr).await;
    let mut broken = compress("gzip", inform("X").encode().as_bytes());
    broken.truncate(broken.len() / 2);
    let r = c.post_encoded(broken, None, Some("gzip")).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    let mut c = Client::connect(addr).await;
    let r = c
        .post_encoded(b"not gzip".to_vec(), None, Some("gzip"))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    for encoding in ["br", "gzip, gzip", "compress"] {
        let mut c = Client::connect(addr).await;
        let r = c
            .post_encoded(inform("X").encode().into_bytes(), None, Some(encoding))
            .await;
        assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{encoding}");
    }
    assert_eq!(server.session_count(), 0);
}

#[tokio::test]
async fn rejected_inform_ends_session() {
    let mock = Mock::default();
    let (addr, server) = start(open_config(), mock, "127.0.0.1:0").await;
    let mut c = Client::connect(addr).await;
    let r = c.post(Some(inform("REJECT"))).await;
    assert!(matches!(&r.body.unwrap().body, Body::Fault(f) if f.code == 8005));
    assert_eq!(server.session_count(), 0);
}

#[tokio::test]
async fn idle_session_times_out_and_returns_task() {
    let mock = Mock::default();
    mock.0
        .lock()
        .unwrap()
        .queue
        .push_back(Reboot::default().into());
    let config = Config {
        session_timeout: Duration::from_millis(200),
        ..open_config()
    };
    let (addr, server) = start(config, mock.clone(), "127.0.0.1:0").await;
    let mut c = Client::connect(addr).await;
    c.post(Some(inform("SN1"))).await;
    let r = c.post(None).await;
    assert!(matches!(rpc_of(&r), Rpc::Reboot(_)));
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(server.session_count(), 0);
    assert_eq!(
        mock.0.lock().unwrap().ended,
        [("SN1".to_owned(), Some(1), true)]
    );
}

#[tokio::test]
async fn a_session_timeout_changed_while_running_takes_effect() {
    let mock = Mock::default();
    // Long timeout at start; sweeper still runs max 1/s.
    let config = Config {
        session_timeout: Duration::from_secs(3600),
        ..open_config()
    };
    let (addr, server) = start(config, mock.clone(), "127.0.0.1:0").await;
    let mut c = Client::connect(addr).await;
    c.post(Some(inform("SN1"))).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(server.session_count(), 1);
    server.set_session_timeout(Duration::from_millis(100));
    assert_eq!(server.session_timeout(), Duration::from_millis(100));
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(server.session_count(), 0, "timed out under the new value");
}

#[tokio::test]
async fn new_inform_replaces_session_of_same_device() {
    let mock = Mock::default();
    let (addr, server) = start(open_config(), mock.clone(), "127.0.0.1:0").await;
    let mut a = Client::connect(addr).await;
    a.post(Some(inform("SN1"))).await;
    let mut b = Client::connect(addr).await;
    b.post(Some(inform("SN1"))).await;
    assert_eq!(server.session_count(), 1);
    assert_eq!(
        mock.0.lock().unwrap().ended,
        [("SN1".to_owned(), None, true)]
    );
    // Old session gone.
    assert_eq!(a.post(None).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(b.post(None).await.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn dual_stack_listener() {
    let (addr, _) = start(open_config(), Mock::default(), "[::]:0").await;
    for host in ["127.0.0.1", "::1"] {
        let target = SocketAddr::new(host.parse().unwrap(), addr.port());
        let mut c = Client::connect(target).await;
        assert_eq!(
            c.post(Some(inform(host))).await.status,
            StatusCode::OK,
            "{host}"
        );
    }
}

/// ACS cert follows its PEM files -> renewed pair served to new connections.
#[tokio::test]
async fn tls_certificate_is_reloaded_from_files() {
    use rustls_pki_types::{CertificateDer, ServerName};

    let pair = || {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        (
            ck.cert.pem(),
            ck.signing_key.serialize_pem(),
            CertificateDer::from(ck.cert.der().to_vec()),
        )
    };
    let (a, b) = (pair(), pair());
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    std::fs::write(&cert_path, &a.0).unwrap();
    std::fs::write(&key_path, &a.1).unwrap();
    let acceptor = dhonomos_cwmp_server::acceptor_from_pem(
        &cert_path,
        &key_path,
        Some(Duration::from_millis(50)),
    )
    .unwrap();

    let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let server = AcsServer::new(open_config(), Mock::default());
    tokio::spawn(server.serve_tls(listener, acceptor, std::future::pending()));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(a.2.clone()).unwrap();
    roots.add(b.2.clone()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let served = || async {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        tls.get_ref().1.peer_certificates().unwrap()[0].clone()
    };
    assert_eq!(served().await, a.2);

    // File times can be coarse -> renewal apart from first write.
    tokio::time::sleep(Duration::from_millis(50)).await;
    std::fs::write(&cert_path, &b.0).unwrap();
    std::fs::write(&key_path, &b.1).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while served().await != b.2 {
        assert!(tokio::time::Instant::now() < deadline, "not reloaded");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn tls_listener() {
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let acceptor = dhonomos_cwmp_server::acceptor(vec![cert.clone()], key).unwrap();

    let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let mock = Mock::default();
    let server = AcsServer::new(open_config(), mock.clone());
    tokio::spawn(server.serve_tls(listener, acceptor, std::future::pending()));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    let resp = sender
        .send_request(
            Request::post("/")
                .body(Full::new(Bytes::from(inform("TLS1").encode())))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(mock.0.lock().unwrap().informs, ["TLS1"]);

    // Plaintext client -> nothing useful from TLS port.
    let mut plain = Client::connect(addr).await;
    let r = plain
        .sender
        .send_request(Request::post("/").body(Full::new(Bytes::new())).unwrap())
        .await;
    assert!(r.is_err());
}

// ---------------------------------------------------------------------------------------
// Pre-auth hardening (audit C-1) + connection protection (audit H-6).
// ---------------------------------------------------------------------------------------

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Digest `Authorization` header, user `cpe`, answer to the challenge in `r`.
fn digest_header(r: &Resp, password: &str) -> String {
    digest_header_nc(r, password, 1)
}

/// Same, nonce count `nc`. Nonce valid once per count.
fn digest_header_nc(r: &Resp, password: &str, nc: u32) -> String {
    let nc = format!("{nc:08x}");
    let md5 = r.headers.get_all("www-authenticate").iter().nth(1).unwrap();
    let nonce = md5
        .to_str()
        .unwrap()
        .split("nonce=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let response = digest_response(&DigestInput {
        sha256: false,
        username: "cpe",
        realm: "dhonomos",
        password,
        method: "POST",
        uri: "/",
        nonce,
        nc: &nc,
        cnonce: "c0ffee",
    });
    format!(
        r#"Digest username="cpe", realm="dhonomos", nonce="{nonce}", uri="/", qop=auth, nc={nc}, cnonce="c0ffee", response="{response}""#
    )
}

/// Send request line + headers of a POST, `content_length` body bytes declared.
async fn send_head(addr: SocketAddr, headers: &str, content_length: usize) -> TcpStream {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST / HTTP/1.1\r\nHost: acs\r\nContent-Type: text/xml\r\nContent-Length: {content_length}\r\n{headers}\r\n"
    );
    s.write_all(head.as_bytes()).await.unwrap();
    s
}

/// Status code + lower-case header block of next response, if in time.
async fn read_head(
    s: &mut (impl tokio::io::AsyncRead + Unpin),
    within: Duration,
) -> Option<(u16, String)> {
    let read = async {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let head = String::from_utf8_lossy(&buf).to_lowercase();
        let status = head.split_whitespace().nth(1)?.parse().ok()?;
        Some((status, head))
    };
    tokio::time::timeout(within, read).await.ok().flatten()
}

/// Server closes connection (EOF or reset) within `within`?
async fn closed_within(s: &mut (impl tokio::io::AsyncRead + Unpin), within: Duration) -> bool {
    let wait = async {
        let mut buf = [0u8; 1024];
        while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
    };
    tokio::time::timeout(within, wait).await.is_ok()
}

async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

const SOON: Duration = Duration::from_secs(5);

/// `<Envelope xmlns="<20 KB>"><Body><a/><a/>...`, ~`total` bytes.
/// Tiny on the wire; huge tree if each element keeps its own namespace copy.
fn xml_bomb(total: usize) -> Vec<u8> {
    let mut s = format!("<Envelope xmlns=\"{}\"><Body>", "N".repeat(20_000));
    while s.len() < total {
        s.push_str("<a/>");
    }
    s.push_str("</Body></Envelope>");
    s.into_bytes()
}

#[tokio::test]
async fn unauthenticated_bodies_are_answered_with_a_challenge_and_never_decoded() {
    let mock = Mock::default();
    let (addr, server) = start(Config::default(), mock.clone(), "127.0.0.1:0").await;

    // Small bodies discarded -> connection kept for the CPE retry.
    // Each = 400/415 (bad XML, bad gzip, unknown encoding) if the server read it.
    let mut c = Client::connect(addr).await;
    let garbage: [(&[u8], Option<&str>); 3] = [
        (b"<html/>", None),
        (b"not gzip", Some("gzip")),
        (b"<Envelope/>", Some("br")),
    ];
    for (body, encoding) in garbage {
        let r = c.post_encoded(body.to_vec(), None, encoding).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{encoding:?}");
        assert_eq!(r.headers.get_all("www-authenticate").iter().count(), 2);
    }
    // Same connection still completes the Digest exchange.
    let body = inform("SN1").encode().into_bytes();
    let r = c.post_raw(body.clone(), None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = c.post_raw(body, Some(digest_header(&r, "secret"))).await;
    assert_eq!(r.status, StatusCode::OK);

    // Large or endless body -> not read; answer at once + connection closed.
    // Here: 50 MB declared, 100 bytes sent.
    let mut s = send_head(addr, "", 50 << 20).await;
    s.write_all(&[b' '; 100]).await.unwrap();
    let (status, head) = read_head(&mut s, SOON).await.expect("a response");
    assert_eq!(status, 401);
    assert!(head.contains("www-authenticate: digest"), "{head}");
    assert!(head.contains("connection: close"), "{head}");
    assert!(closed_within(&mut s, SOON).await);

    // 1 MB XML bomb + body above size limit -> 401, not 400 or 413.
    for body in [xml_bomb(1_000_000), vec![b' '; 2 << 20]] {
        let mut s = send_head(addr, "", body.len()).await;
        let (mut r, mut w) = s.split();
        let (_, head) = tokio::join!(
            async {
                // Server may answer + close during this send.
                let _ = w.write_all(&body).await;
            },
            async {
                let mut buf = vec![0u8; 512];
                let n = r.read(&mut buf).await.unwrap_or(0);
                String::from_utf8_lossy(&buf[..n]).to_lowercase()
            }
        );
        assert!(head.starts_with("http/1.1 401"), "{head}");
    }

    // 1 session only, none of the above = auth failure, server healthy.
    assert_eq!(mock.0.lock().unwrap().informs, ["SN1"]);
    assert_eq!(server.session_count(), 1);
    let mut c = Client::connect(addr).await;
    let body = inform("SN2").encode().into_bytes();
    let r = c.post_raw(body.clone(), None).await;
    let r = c.post_raw(body, Some(digest_header(&r, "secret"))).await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn failed_credentials_are_still_counted_without_reading_the_body() {
    let config = Config {
        auth_failure_limit: 2,
        ..Config::default()
    };
    let (addr, _) = start(config, Mock::default(), "127.0.0.1:0").await;
    let mut c = Client::connect(addr).await;
    let challenge = c.post_raw(b"x".to_vec(), None).await;
    assert_eq!(challenge.status, StatusCode::UNAUTHORIZED);
    // Wrong password + hostile body -> counted; 2nd failure blocks the source.
    let wrong = digest_header(&challenge, "guess");
    for _ in 0..2 {
        let r = c.post_raw(b"<html/>".to_vec(), Some(wrong.clone())).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let r = c.post_raw(b"x".to_vec(), None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn messages_keep_their_meaning_after_authentication() {
    let (addr, server) = start(Config::default(), Mock::default(), "127.0.0.1:0").await;
    let mut c = Client::connect(addr).await;
    let challenge = c.post_raw(Vec::new(), None).await;
    // 1 nonce, higher count at each use.
    let auth = |nc| digest_header_nc(&challenge, "secret", nc);

    // Valid credentials + non-Inform -> no new session.
    let r = c.post_raw(Vec::new(), Some(auth(1))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = c.post_raw(b"<html/>".to_vec(), Some(auth(2))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(server.session_count(), 0);

    let body = inform("SN1").encode().into_bytes();
    let r = c.post_raw(body.clone(), Some(auth(3))).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(server.session_count(), 1);

    // Inside the session: cookie enough for other CPE messages...
    assert_eq!(c.post(None).await.status, StatusCode::NO_CONTENT);
    // ...but new Inform on a live session must still authenticate.
    let mut c = Client::connect(addr).await;
    c.post_raw(body.clone(), Some(auth(4))).await;
    assert_eq!(server.session_count(), 1);
    let r = c.post_raw(body, None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(server.session_count(), 1, "the live session is untouched");
}

/// Auth off -> body decoded; parser limits -> bounded cost of a hostile document.
#[tokio::test]
async fn hostile_xml_is_rejected_by_the_parser_limits_when_auth_is_off() {
    let config = Config {
        max_decoded_body_bytes: 8 << 20,
        ..open_config()
    };
    let (addr, server) = start(config, Mock::default(), "127.0.0.1:0").await;

    // 8 MiB of empty elements in 8 KB gzip -> over element limit.
    let mut doc = String::from("<Envelope><Body>");
    while doc.len() < (8 << 20) - 64 {
        doc.push_str("<a/>");
    }
    doc.push_str("</Body></Envelope>");
    let packed = compress("gzip", doc.as_bytes());
    assert!(packed.len() < 1 << 20);
    let mut c = Client::connect(addr).await;
    let r = c.post_encoded(packed, None, Some("gzip")).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // 1 MB of elements under 20 KB namespace -> URI shared, not copied.
    let mut c = Client::connect(addr).await;
    let r = c.post_raw(xml_bomb(1_000_000), None).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    let mut c = Client::connect(addr).await;
    assert_eq!(c.post(Some(inform("OK"))).await.status, StatusCode::OK);
    assert_eq!(server.session_count(), 1);
}

fn short_timeouts() -> Config {
    Config {
        header_read_timeout: Duration::from_millis(300),
        body_read_timeout: Duration::from_millis(400),
        tls_handshake_timeout: Duration::from_millis(300),
        ..open_config()
    }
}

#[tokio::test]
async fn stalled_request_headers_are_cut_off() {
    let (addr, server) = start(short_timeouts(), Mock::default(), "127.0.0.1:0").await;

    // Half a request, then silence.
    let mut partial = TcpStream::connect(addr).await.unwrap();
    partial
        .write_all(b"POST / HTTP/1.1\r\nHost: acs\r\n")
        .await
        .unwrap();
    // Connection that never sends.
    let mut silent = TcpStream::connect(addr).await.unwrap();
    // Headers 1 byte at a time -> under any per-read timer, not under this one.
    let mut trickle = TcpStream::connect(addr).await.unwrap();
    let (mut tr, mut tw) = trickle.split();
    let drip = async {
        for b in b"POST / HTTP/1.1\r\nHost: acs\r\nX-Slow: yyyyyyyyyyyyyyyyyyyy".iter() {
            if tw.write_all(&[*b]).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    let (_, closed) = tokio::join!(drip, closed_within(&mut tr, SOON));
    assert!(closed, "trickled headers");

    assert!(closed_within(&mut partial, SOON).await, "partial headers");
    assert!(closed_within(&mut silent, SOON).await, "silent connection");
    wait_until("connections released", || server.connection_count() == 0).await;
}

#[tokio::test]
async fn idle_keep_alive_connections_are_closed() {
    let (addr, server) = start(short_timeouts(), Mock::default(), "127.0.0.1:0").await;
    let mut s = send_head(addr, "", 0).await;
    let (status, _) = read_head(&mut s, SOON).await.expect("a response");
    assert_eq!(status, 400, "an empty POST outside a session");

    // Kept alive while next request comes in time...
    tokio::time::sleep(Duration::from_millis(100)).await;
    s.write_all(b"POST / HTTP/1.1\r\nHost: acs\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    let (status, _) = read_head(&mut s, SOON).await.expect("a second response");
    assert_eq!(status, 400);

    // ...closed when not.
    assert!(closed_within(&mut s, SOON).await, "idle connection");
    wait_until("connection released", || server.connection_count() == 0).await;
}

#[tokio::test]
async fn slow_body_is_cut_off_and_does_not_block_other_cpes() {
    // 1 processing permit; body being read must not hold it.
    let config = Config {
        max_concurrent_requests: 1,
        ..short_timeouts()
    };
    let (addr, server) = start(config, Mock::default(), "127.0.0.1:0").await;

    // 1000-byte body, 1 byte / 50 ms -> no read stalls, whole body misses deadline.
    let mut slow = send_head(addr, "", 1000).await;
    let (mut slow_r, mut slow_w) = slow.split();
    let drip = async {
        for _ in 0..40 {
            if slow_w.write_all(b" ").await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    let others = async {
        // Meanwhile: normal CPE session served x3.
        tokio::time::sleep(Duration::from_millis(100)).await;
        for serial in ["A", "B", "C"] {
            let mut c = Client::connect(addr).await;
            let r = c.post(Some(inform(serial))).await;
            assert_eq!(r.status, StatusCode::OK, "{serial}");
        }
    };
    let verdict = async {
        let (status, head) = read_head(&mut slow_r, SOON).await.expect("a response");
        assert_eq!(status, 408);
        assert!(head.contains("connection: close"), "{head}");
        assert!(closed_within(&mut slow_r, SOON).await);
    };
    tokio::join!(drip, others, verdict);
    assert_eq!(server.session_count(), 3);

    // Body that never starts -> cut off same way.
    let mut stalled = send_head(addr, "", 1000).await;
    let (status, _) = read_head(&mut stalled, SOON).await.expect("a response");
    assert_eq!(status, 408);
}

/// Open `limit` connections -> next one dropped at once; slot reusable after a close.
async fn assert_connection_cap(config: Config, limit: usize) {
    let (addr, server) = start(config, Mock::default(), "127.0.0.1:0").await;
    let mut held = Vec::new();
    for _ in 0..limit {
        held.push(TcpStream::connect(addr).await.unwrap());
    }
    wait_until("connections admitted", || {
        server.connection_count() == limit
    })
    .await;

    // Over cap: kernel accepts, server closes without a byte.
    let mut over = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(SOON, over.read(&mut buf)).await;
    assert!(matches!(read, Ok(Ok(0) | Err(_))), "{read:?}");
    assert_eq!(server.connection_count(), limit);

    // Admitted connections unaffected.
    let first = held.first_mut().unwrap();
    first
        .write_all(b"POST / HTTP/1.1\r\nHost: acs\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_head(first, SOON).await.expect("a response").0, 400);

    // Connection end -> slot free.
    held.pop();
    wait_until("slot released", || server.connection_count() == limit - 1).await;
    let mut again = send_head(addr, "", 0).await;
    assert_eq!(
        read_head(&mut again, SOON).await.expect("a response").0,
        400
    );
}

#[tokio::test]
async fn connections_per_source_address_are_capped() {
    let config = Config {
        max_connections_per_ip: 3,
        max_connections: 0,
        ..open_config()
    };
    assert_connection_cap(config, 3).await;
}

#[tokio::test]
async fn open_connections_are_capped_globally() {
    let config = Config {
        max_connections: 4,
        max_connections_per_ip: 0,
        ..open_config()
    };
    assert_connection_cap(config, 4).await;
}

#[tokio::test]
async fn stalled_tls_handshake_is_cut_off() {
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let acceptor = dhonomos_cwmp_server::acceptor(vec![cert], key).unwrap();

    let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let config = Config {
        max_connections_per_ip: 2,
        ..short_timeouts()
    };
    let server = AcsServer::new(config, Mock::default());
    tokio::spawn(
        server
            .clone()
            .serve_tls(listener, acceptor, std::future::pending()),
    );

    // First bytes of a ClientHello, then nothing + connection that sends nothing.
    let mut half = TcpStream::connect(addr).await.unwrap();
    half.write_all(&[0x16, 0x03, 0x01, 0x00, 0xf0, 0x01])
        .await
        .unwrap();
    let mut silent = TcpStream::connect(addr).await.unwrap();
    wait_until("connections admitted", || server.connection_count() == 2).await;

    // Both count against per-address cap while stalled...
    let mut over = TcpStream::connect(addr).await.unwrap();
    assert!(closed_within(&mut over, SOON).await, "over the cap");
    // ...handshake deadline frees their slots.
    assert!(closed_within(&mut half, SOON).await, "partial handshake");
    assert!(closed_within(&mut silent, SOON).await, "silent connection");
    wait_until("connections released", || server.connection_count() == 0).await;
}

// ---------------------------------------------------------------------------------------
// Digest hardening (audit L-4).
// ---------------------------------------------------------------------------------------

/// `WWW-Authenticate` values of a 401, lower-case.
fn challenges_of(r: &Resp) -> Vec<String> {
    r.headers
        .get_all("www-authenticate")
        .iter()
        .map(|v| v.to_str().unwrap().to_lowercase())
        .collect()
}

#[tokio::test]
async fn a_digest_request_cannot_be_replayed() {
    let mock = Mock::default();
    let (addr, server) = start(Config::default(), mock.clone(), "127.0.0.1:0").await;
    let body = inform("SN1").encode().into_bytes();
    let mut c = Client::connect(addr).await;
    let challenge = c.post_raw(body.clone(), None).await;
    let auth = digest_header(&challenge, "secret");
    let r = c.post_raw(body.clone(), Some(auth.clone())).await;
    assert_eq!(r.status, StatusCode::OK);

    // Replay of a captured request, on new or old connection.
    for mut again in [Client::connect(addr).await, c] {
        let r = again.post_raw(body.clone(), Some(auth.clone())).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert!(challenges_of(&r).iter().all(|c| c.contains("stale=true")));
    }
    assert_eq!(mock.0.lock().unwrap().informs, ["SN1"]);
    assert_eq!(server.session_count(), 1);

    // Client follows the stale challenge -> gets in.
    let mut c = Client::connect(addr).await;
    let r = c.post_raw(body.clone(), Some(auth)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = c.post_raw(body, Some(digest_header(&r, "secret"))).await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn an_expired_nonce_is_stale_not_a_failed_login() {
    let config = Config {
        nonce_lifetime: Duration::from_secs(1),
        auth_failure_limit: 1,
        ..Config::default()
    };
    let (addr, _) = start(config, Mock::default(), "127.0.0.1:0").await;
    let body = inform("SN1").encode().into_bytes();
    let mut c = Client::connect(addr).await;
    let challenge = c.post_raw(body.clone(), None).await;
    assert!(
        challenges_of(&challenge)
            .iter()
            .all(|c| !c.contains("stale"))
    );
    tokio::time::sleep(Duration::from_millis(2100)).await;

    // Right password + old nonce -> retry with new nonce, not counted as failure (limit = 1).
    let r = c
        .post_raw(body.clone(), Some(digest_header(&challenge, "secret")))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(challenges_of(&r).iter().all(|c| c.contains("stale=true")));
    let r = c
        .post_raw(body.clone(), Some(digest_header(&r, "secret")))
        .await;
    assert_eq!(r.status, StatusCode::OK);

    // Wrong password + old nonce -> ordinary failure.
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let mut c = Client::connect(addr).await;
    let r = c
        .post_raw(body.clone(), Some(digest_header(&challenge, "guess")))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(challenges_of(&r).iter().all(|c| !c.contains("stale")));
    let r = c.post_raw(body, None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "the failure was counted");
}

#[tokio::test]
async fn a_nonce_only_works_for_the_address_it_was_issued_to() {
    let (addr, _) = start(Config::default(), Mock::default(), "127.0.0.1:0").await;
    let body = inform("SN1").encode().into_bytes();
    let mut one = Client::connect_from("127.0.0.2", addr).await;
    let challenge = one.post_raw(body.clone(), None).await;
    let auth = digest_header(&challenge, "secret");
    // Other host with learned nonce + response -> cannot use them.
    let mut other = Client::connect_from("127.0.0.3", addr).await;
    let r = other.post_raw(body.clone(), Some(auth.clone())).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = one.post_raw(body.clone(), Some(auth)).await;
    assert_eq!(r.status, StatusCode::OK);

    // Binding off (CPEs behind proxies, changing addresses) -> it can.
    let config = Config {
        digest_bind_client: false,
        ..Config::default()
    };
    let (addr, _) = start(config, Mock::default(), "127.0.0.1:0").await;
    let mut one = Client::connect_from("127.0.0.2", addr).await;
    let challenge = one.post_raw(body.clone(), None).await;
    let mut other = Client::connect_from("127.0.0.3", addr).await;
    let r = other
        .post_raw(body, Some(digest_header(&challenge, "secret")))
        .await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn the_digest_uri_must_be_the_request_target() {
    let (addr, _) = start(Config::default(), Mock::default(), "127.0.0.1:0").await;
    let body = inform("SN1").encode().into_bytes();
    let mut c = Client::connect(addr).await;
    let challenge = c.post_raw(body.clone(), None).await;
    // Response for another path (helper signs "/") -> no good for "/acs".
    let req = |auth: String| {
        Request::post("/acs")
            .header("content-type", "text/xml")
            .header("authorization", auth)
            .body(Full::new(Bytes::from(body.clone())))
            .unwrap()
    };
    let r = c
        .sender
        .send_request(req(digest_header(&challenge, "secret")))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

/// RFC 2069 response (no qop, no cnonce) for user `cpe`, MD5.
fn legacy_header(r: &Resp, password: &str) -> String {
    use md5::{Digest as _, Md5};
    let md5 = |s: String| {
        Md5::digest(s.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let nonce = digest_nonce(r);
    let ha1 = md5(format!("cpe:dhonomos:{password}"));
    let ha2 = md5("POST:/".to_owned());
    let response = md5(format!("{ha1}:{nonce}:{ha2}"));
    format!(
        r#"Digest username="cpe", realm="dhonomos", nonce="{nonce}", uri="/", algorithm=MD5, response="{response}""#
    )
}

fn digest_nonce(r: &Resp) -> String {
    r.headers
        .get_all("www-authenticate")
        .iter()
        .nth(1)
        .unwrap()
        .to_str()
        .unwrap()
        .split("nonce=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn rfc_2069_digest_is_accepted_unless_switched_off() {
    let body = inform("SN1").encode().into_bytes();
    for (no_qop, expected) in [(true, StatusCode::OK), (false, StatusCode::UNAUTHORIZED)] {
        let config = Config {
            digest_no_qop: no_qop,
            ..Config::default()
        };
        let (addr, _) = start(config, Mock::default(), "127.0.0.1:0").await;
        let mut c = Client::connect(addr).await;
        let challenge = c.post_raw(body.clone(), None).await;
        let r = c
            .post_raw(body.clone(), Some(legacy_header(&challenge, "secret")))
            .await;
        assert_eq!(r.status, expected, "digest_no_qop = {no_qop}");
        // qop=auth: fine either way.
        let mut c = Client::connect(addr).await;
        let challenge = c.post_raw(body.clone(), None).await;
        let r = c
            .post_raw(body.clone(), Some(digest_header(&challenge, "secret")))
            .await;
        assert_eq!(r.status, StatusCode::OK);
    }
}

// ---------------------------------------------------------------------------------------
// Refusal logs with source address.
// ---------------------------------------------------------------------------------------

/// Log text a test reads back.
#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

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
    /// Logs at info+ on this thread until guard drop.
    /// `#[tokio::test]` runs the server on this thread too.
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

    /// Lines of refused connections + requests.
    fn refusals(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|l| l.contains("refused") || l.contains("refusals suppressed"))
            .map(str::to_owned)
            .collect()
    }
}

/// Log line part after its message: `listener=cwmp remote=... reason=...`.
fn fields_of(line: &str) -> &str {
    line.split_once("refused ").map_or(line, |(_, f)| f)
}

#[tokio::test]
async fn a_wrong_password_is_logged_with_the_source_and_username_but_a_challenge_is_not() {
    let logs = LogBuf::default();
    let _capture = logs.capture();
    let (addr, _) = start(Config::default(), Mock::default(), "127.0.0.1:0").await;
    // Own loopback addresses: log limiter shared by the process.
    let mut c = Client::connect_from("127.0.0.41", addr).await;
    let body = inform("SN1").encode().into_bytes();

    // 1st request of Digest exchange = no credentials -> no failure to log.
    let challenge = c.post_raw(body.clone(), None).await;
    assert_eq!(challenge.status, StatusCode::UNAUTHORIZED);
    assert!(logs.refusals().is_empty(), "{:?}", logs.refusals());

    let wrong = c
        .post_raw(body.clone(), Some(digest_header(&challenge, "guess")))
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    let lines = logs.refusals();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("INFO"), "{}", lines[0]);
    assert!(
        fields_of(&lines[0]).starts_with("listener=cwmp remote=127.0.0.41:"),
        "{}",
        lines[0]
    );
    assert!(lines[0].contains("request refused"), "{}", lines[0]);
    assert!(lines[0].contains("reason=auth_failed"), "{}", lines[0]);
    assert!(lines[0].contains(r#"username="cpe""#), "{}", lines[0]);
    assert!(!lines[0].contains("suppressed"), "{}", lines[0]);

    // Same source fails again inside window -> counted, not logged again.
    let again = c
        .post_raw(body.clone(), Some(digest_header(&wrong, "guess2")))
        .await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    assert_eq!(logs.refusals().len(), 1, "{:?}", logs.refusals());

    // Long username -> cut at 64 chars.
    let mut other = Client::connect_from("127.0.0.42", addr).await;
    let challenge = other.post_raw(body.clone(), None).await;
    let long = "x".repeat(100);
    let header = digest_header(&challenge, "guess")
        .replace("username=\"cpe\"", &format!("username=\"{long}\""));
    let r = other.post_raw(body, Some(header)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let lines = logs.refusals();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[1].contains("remote=127.0.0.42:"), "{}", lines[1]);
    assert!(
        lines[1].contains(&format!("username=\"{}\"", "x".repeat(64))),
        "{}",
        lines[1]
    );
    assert!(!lines[1].contains(&"x".repeat(65)), "{}", lines[1]);
}

#[tokio::test]
async fn a_source_blocked_after_failures_is_logged() {
    let logs = LogBuf::default();
    let _capture = logs.capture();
    let config = Config {
        auth_failure_limit: 1,
        ..Config::default()
    };
    let (addr, _) = start(config, Mock::default(), "127.0.0.1:0").await;
    let mut c = Client::connect_from("127.0.0.45", addr).await;
    let challenge = c.post_raw(b"x".to_vec(), None).await;
    let r = c
        .post_raw(b"x".to_vec(), Some(digest_header(&challenge, "guess")))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = c.post_raw(b"x".to_vec(), None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let lines = logs.refusals();
    assert!(
        lines
            .iter()
            .any(|l| l.contains("reason=auth_blocked") && l.contains("remote=127.0.0.45:")),
        "{lines:?}"
    );
}

#[tokio::test]
async fn a_failed_tls_handshake_is_logged_with_the_source_address() {
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let logs = LogBuf::default();
    let _capture = logs.capture();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let acceptor = dhonomos_cwmp_server::acceptor(vec![cert], key).unwrap();
    let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let server = AcsServer::new(open_config(), Mock::default());
    tokio::spawn(server.serve_tls(listener, acceptor, std::future::pending()));

    // Plain HTTP to TLS port, like a scanner.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.43:0".parse().unwrap()).unwrap();
    let mut plain = socket.connect(addr).await.unwrap();
    plain
        .write_all(b"GET / HTTP/1.1\r\nHost: acs\r\n\r\n")
        .await
        .unwrap();
    wait_until("the handshake failure is logged", || {
        !logs.refusals().is_empty()
    })
    .await;
    let lines = logs.refusals();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("INFO"), "{}", lines[0]);
    assert!(
        fields_of(&lines[0]).starts_with("listener=cwmp remote=127.0.0.43:"),
        "{}",
        lines[0]
    );
    assert!(lines[0].contains("connection refused"), "{}", lines[0]);
    assert!(lines[0].contains("reason=tls_handshake"), "{}", lines[0]);
    assert!(lines[0].contains("error="), "{}", lines[0]);
}

#[tokio::test]
async fn invalid_stun_is_logged_but_binding_requests_are_not() {
    let logs = LogBuf::default();
    let _capture = logs.capture();
    let server = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = server.local_addr().unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(dhonomos_cwmp_server::stun::serve(server, tx, None));

    let client = tokio::net::UdpSocket::bind("127.0.0.46:0").await.unwrap();
    // Binding Request (every CPE, every few s) -> answered, not logged.
    let mut binding = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42];
    binding.extend_from_slice(&[7; 12]);
    client.send_to(&binding, addr).await.unwrap();
    let mut buf = [0u8; 512];
    let (n, _) = tokio::time::timeout(SOON, client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(n >= 20);
    // Junk -> logged, not answered.
    client
        .send_to(b"\x16\x03\x01 not stun", addr)
        .await
        .unwrap();
    wait_until("the invalid request is logged", || {
        !logs.refusals().is_empty()
    })
    .await;
    let lines = logs.refusals();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("request refused"), "{}", lines[0]);
    assert!(
        fields_of(&lines[0]).starts_with("listener=stun remote=127.0.0.46:"),
        "{}",
        lines[0]
    );
    assert!(lines[0].contains("reason=invalid"), "{}", lines[0]);
}
