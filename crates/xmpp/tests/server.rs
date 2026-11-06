//! Server over real TCP + TLS. Raw-XML client = xmppc steps:
//! stream, STARTTLS, TLS, stream, SASL PLAIN, stream, bind, presence, ping -> answers CRs.
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use dhonomos_pki::tls::CertResolver;
use dhonomos_xmpp::{
    Accounts, CrOutcome, Credential, SendError, Unavailable, XmppConfig, XmppServer, tls_acceptor,
};
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;

const DOMAIN: &str = "xmpp.test";
const NS_TLS: &str = "urn:ietf:params:xml:ns:xmpp-tls";
const NS_SASL: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const NS_BIND: &str = "urn:ietf:params:xml:ns:xmpp-bind";
const WAIT: Duration = Duration::from_secs(5);

/// Accounts of a test + what the server reported.
#[derive(Default)]
struct Fake {
    credentials: Mutex<HashMap<String, Vec<Credential>>>,
    events: Mutex<Vec<String>>,
    accepted: Mutex<Vec<(String, bool)>>,
    lookups: Mutex<usize>,
    down: Mutex<bool>,
}

impl Fake {
    fn with(accounts: &[(&str, &str, bool)]) -> Arc<Self> {
        let fake = Self::default();
        for (account, password, pending) in accounts {
            fake.credentials
                .lock()
                .unwrap()
                .entry((*account).to_owned())
                .or_default()
                .push(Credential {
                    password: password.as_bytes().to_vec(),
                    pending: *pending,
                });
        }
        Arc::new(fake)
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    fn lookups(&self) -> usize {
        *self.lookups.lock().unwrap()
    }
}

#[async_trait::async_trait]
impl Accounts for Fake {
    async fn credentials(&self, account: &str) -> Result<Vec<Credential>, Unavailable> {
        *self.lookups.lock().unwrap() += 1;
        if *self.down.lock().unwrap() {
            return Err(Unavailable);
        }
        Ok(self
            .credentials
            .lock()
            .unwrap()
            .get(account)
            .cloned()
            .unwrap_or_default())
    }

    async fn accepted(&self, account: &str, credential: &Credential) {
        self.accepted
            .lock()
            .unwrap()
            .push((account.to_owned(), credential.pending));
    }

    async fn connected(&self, account: &str, _at: SystemTime) {
        self.events
            .lock()
            .unwrap()
            .push(format!("connected {account}"));
    }

    async fn disconnected(&self, account: &str, _at: SystemTime) {
        self.events
            .lock()
            .unwrap()
            .push(format!("disconnected {account}"));
    }
}

struct Harness {
    server: XmppServer,
    addr: SocketAddr,
    fake: Arc<Fake>,
    root: CertificateDer<'static>,
    stop: tokio::sync::oneshot::Sender<()>,
    done: tokio::task::JoinHandle<()>,
}

async fn start(fake: Arc<Fake>, tune: impl FnOnce(&mut XmppConfig)) -> Harness {
    let ck = rcgen::generate_simple_self_signed(vec![DOMAIN.to_owned()]).unwrap();
    let resolver = CertResolver::from_pem(&ck.cert.pem(), &ck.signing_key.serialize_pem()).unwrap();
    let mut config = XmppConfig::new(DOMAIN);
    tune(&mut config);
    let server = XmppServer::new(config, fake.clone(), tls_acceptor(resolver).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let s = server.clone();
    let done = tokio::spawn(async move {
        s.serve(listener, async {
            let _ = stopped.await;
        })
        .await
        .unwrap();
    });
    Harness {
        server,
        addr,
        fake,
        root: CertificateDer::from(ck.cert.der().to_vec()),
        stop,
        done,
    }
}

impl Harness {
    async fn client(&self) -> Client {
        Client {
            io: Io::Plain(TcpStream::connect(self.addr).await.unwrap()),
            seen: String::new(),
            root: self.root.clone(),
        }
    }

    /// Client from loopback `source` (all of 127.0.0.0/8 is local on Linux).
    async fn client_from(&self, source: &str) -> Client {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind(format!("{source}:0").parse().unwrap()).unwrap();
        Client {
            io: Io::Plain(socket.connect(self.addr).await.unwrap()),
            seen: String::new(),
            root: self.root.clone(),
        }
    }

    async fn shutdown(self) {
        let _ = self.stop.send(());
        self.done.await.unwrap();
    }
}

enum Io {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    /// During the handshake.
    Gone,
}

struct Client {
    io: Io,
    seen: String,
    root: CertificateDer<'static>,
}

fn stream_open(to: &str) -> String {
    format!(
        "<?xml version='1.0'?><stream:stream to='{to}' xmlns='jabber:client' \
         xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
    )
}

fn plain(authzid: &str, user: &str, pass: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{authzid}\0{user}\0{pass}"))
}

impl Client {
    async fn send(&mut self, s: &str) {
        // Write to a closed connection may fail -> ignored, test checks reads only.
        match &mut self.io {
            Io::Plain(t) => {
                let _ = t.write_all(s.as_bytes()).await;
            }
            Io::Tls(t) => {
                let _ = t.write_all(s.as_bytes()).await;
                let _ = t.flush().await;
            }
            Io::Gone => panic!("no connection"),
        }
    }

    /// One read. `Some(false)` = connection end or reset, `None` = timeout.
    async fn fill(&mut self, wait: Duration) -> Option<bool> {
        let mut buf = [0u8; 8192];
        let read = match &mut self.io {
            Io::Plain(t) => tokio::time::timeout(wait, t.read(&mut buf)).await,
            Io::Tls(t) => tokio::time::timeout(wait, t.read(&mut buf)).await,
            Io::Gone => panic!("no connection"),
        };
        match read {
            Err(_) => None,
            Ok(Ok(0) | Err(_)) => Some(false),
            Ok(Ok(n)) => {
                self.seen.push_str(&String::from_utf8_lossy(&buf[..n]));
                Some(true)
            }
        }
    }

    /// All up to + incl. the first `needle`.
    async fn until(&mut self, needle: &str) -> String {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            if let Some(i) = self.seen.find(needle) {
                let end = i + needle.len();
                return self.seen.drain(..end).collect();
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.fill(left).await {
                Some(true) => {}
                Some(false) => panic!(
                    "connection ended while waiting for {needle:?}; got {:?}",
                    self.seen
                ),
                None => panic!("timed out waiting for {needle:?}; got {:?}", self.seen),
            }
        }
    }

    /// Read until connection end -> all data before it.
    async fn until_closed(&mut self) -> String {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.fill(left).await {
                Some(true) => {}
                Some(false) => return std::mem::take(&mut self.seen),
                None => panic!("the connection stayed open; got {:?}", self.seen),
            }
        }
    }

    /// No data for 300 ms + connection still open.
    async fn quiet(&mut self) {
        assert_eq!(
            self.fill(Duration::from_millis(300)).await,
            None,
            "got {:?}",
            self.seen
        );
        assert!(self.seen.is_empty(), "got {:?}", self.seen);
    }

    async fn upgrade(&mut self) {
        let Io::Plain(tcp) = std::mem::replace(&mut self.io, Io::Gone) else {
            panic!("already TLS");
        };
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.root.clone()).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tls = connector
            .connect(ServerName::try_from(DOMAIN).unwrap(), tcp)
            .await
            .unwrap();
        self.io = Io::Tls(Box::new(tls));
    }

    /// xmppc steps up to TLS: stream, STARTTLS, handshake.
    async fn secure(&mut self) {
        self.send(&stream_open(DOMAIN)).await;
        let features = self.until("</stream:features>").await;
        assert!(
            features.contains(&format!(
                "<starttls xmlns=\"{NS_TLS}\"><required/></starttls>"
            )),
            "{features}"
        );
        self.send(&format!("<starttls xmlns='{NS_TLS}'/>")).await;
        self.until(&format!("<proceed xmlns=\"{NS_TLS}\"/>")).await;
        self.upgrade().await;
    }

    /// Up to SASL PLAIN success + 3rd stream.
    async fn authenticate(&mut self, user: &str, pass: &str) {
        self.secure().await;
        self.send(&stream_open(DOMAIN)).await;
        let features = self.until("</stream:features>").await;
        assert!(
            features.contains("<mechanism>PLAIN</mechanism>"),
            "{features}"
        );
        assert!(!features.contains("starttls"), "{features}");
        self.send(&format!(
            "<auth xmlns='{NS_SASL}' mechanism='PLAIN'>{}</auth>",
            plain("", user, pass)
        ))
        .await;
        self.until(&format!("<success xmlns=\"{NS_SASL}\"/>")).await;
        self.send(&stream_open(DOMAIN)).await;
        let features = self.until("</stream:features>").await;
        assert!(
            features.contains(&format!("<bind xmlns=\"{NS_BIND}\"/>")),
            "{features}"
        );
        assert!(
            features.contains(
                "<session xmlns=\"urn:ietf:params:xml:ns:xmpp-session\"><optional/></session>"
            ),
            "{features}"
        );
    }

    /// Full login, bound -> bound JID.
    async fn login(&mut self, user: &str, pass: &str, resource: &str) -> String {
        self.authenticate(user, pass).await;
        let bind = if resource.is_empty() {
            format!("<bind xmlns='{NS_BIND}'/>")
        } else {
            format!("<bind xmlns='{NS_BIND}'><resource>{resource}</resource></bind>")
        };
        self.send(&format!("<iq type='set' id='bind1'>{bind}</iq>"))
            .await;
        let result = self.until("</iq>").await;
        assert!(
            result.starts_with("<iq type=\"result\" id=\"bind1\">"),
            "{result}"
        );
        let jid = result
            .split("<jid>")
            .nth(1)
            .and_then(|s| s.split("</jid>").next())
            .unwrap()
            .to_owned();
        assert!(jid.starts_with(&format!("{user}@{DOMAIN}/")), "{jid}");
        jid
    }
}

/// Attribute `name` of the first element in `xml`.
fn attr(xml: &str, name: &str) -> String {
    let tag = xml.split('>').next().unwrap();
    let key = format!(" {name}=\"");
    let rest = tag
        .split(&key)
        .nth(1)
        .unwrap_or_else(|| panic!("no {name} in {tag}"));
    rest.split('"').next().unwrap().to_owned()
}

// xmppc sequence

#[tokio::test]
async fn the_whole_xmppc_sequence() {
    let h = start(Fake::with(&[("dev-1", "s3cret", false)]), |_| {}).await;
    let mut c = h.client().await;

    // 1st stream: header + required STARTTLS.
    c.send(&stream_open(DOMAIN)).await;
    let first = c.until("</stream:features>").await;
    assert!(
        first.starts_with("<?xml version='1.0'?><stream:stream "),
        "{first}"
    );
    assert!(
        first.contains("from=\"xmpp.test\"") && first.contains("version=\"1.0\""),
        "{first}"
    );
    assert!(first.contains("xmlns=\"jabber:client\""), "{first}");
    assert!(!first.contains("mechanism"), "no SASL before TLS: {first}");
    // No auth in clear text -> STARTTLS first.
    c.send(&format!("<starttls xmlns='{NS_TLS}'/>")).await;
    c.until("<proceed").await;
    c.until("/>").await;
    c.upgrade().await;

    // 2nd stream, over TLS: SASL PLAIN only.
    c.send(&stream_open(DOMAIN)).await;
    let second = c.until("</stream:features>").await;
    assert!(second.contains("<mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"><mechanism>PLAIN</mechanism></mechanisms>"), "{second}");
    assert!(
        !second.contains("SCRAM")
            && !second.contains("starttls")
            && !second.contains("compress")
            && !second.contains("urn:xmpp:sm"),
        "{second}"
    );
    let stream_id = attr(&second[second.find("<stream:stream").unwrap()..], "id");
    assert!(stream_id.len() >= 16);
    c.send(&format!(
        "<auth xmlns='{NS_SASL}' mechanism='PLAIN'>{}</auth>",
        plain("", "dev-1", "s3cret")
    ))
    .await;
    c.until("<success").await;

    // 3rd stream: bind, resource chosen by server.
    c.send(&stream_open(DOMAIN)).await;
    let third = c.until("</stream:features>").await;
    assert!(
        third.contains("<bind ") && third.contains("<session ") && third.contains("<optional/>"),
        "{third}"
    );
    assert_ne!(
        attr(&third[third.find("<stream:stream").unwrap()..], "id"),
        stream_id
    );
    c.send(&format!(
        "<iq type='set' id='bind1'><bind xmlns='{NS_BIND}'/></iq>"
    ))
    .await;
    let bound = c.until("</iq>").await;
    let jid = bound
        .split("<jid>")
        .nth(1)
        .unwrap()
        .split("</jid>")
        .next()
        .unwrap()
        .to_owned();
    assert!(jid.starts_with("dev-1@xmpp.test/cwmp-"), "{jid}");
    assert_eq!(
        jid.len(),
        "dev-1@xmpp.test/cwmp-".len() + 12,
        "random server resource"
    );
    assert!(h.server.is_connected("dev-1"));
    assert_eq!(h.server.connections(), 1);
    assert_eq!(h.server.jid("dev-1").as_deref(), Some(jid.as_str()));
    assert_eq!(h.server.jid("dev-2"), None, "no such session");
    assert_eq!(h.fake.events(), ["connected dev-1"]);

    // Optional session step, initial presence, xmppc ping (`from` = `user@domain/`).
    c.send("<iq type='set' id='sess1'><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>")
        .await;
    assert_eq!(
        c.until("/>").await,
        "<iq type=\"result\" id=\"sess1\" to=\"".to_owned() + &jid + "\"/>"
    );
    c.send("<presence/>").await;
    c.send("<iq type='get' id='s2c1' to='xmpp.test' from='dev-1@xmpp.test/'><ping xmlns='urn:xmpp:ping'/></iq>")
        .await;
    assert_eq!(
        c.until("/>").await,
        format!("<iq type=\"result\" id=\"s2c1\" from=\"xmpp.test\" to=\"{jid}\"/>")
    );

    // CR from server: exact stanza + device result.
    let server = h.server.clone();
    let request = tokio::spawn(async move {
        server
            .send_connection_request("dev-1", "cr-user", "p&ss<w>rd", Duration::from_secs(5))
            .await
    });
    let cr = c.until("</iq>").await;
    let id = attr(&cr, "id");
    assert!(id.starts_with("cr-") && id.len() > 10, "{id}");
    assert_eq!(
        cr,
        format!(
            "<iq type=\"get\" id=\"{id}\" from=\"acs@xmpp.test/dhonomos\" to=\"{jid}\">\
             <connectionRequest xmlns=\"urn:broadband-forum-org:cwmp:xmppConnReq-1-0\">\
             <username>cr-user</username><password>p&amp;ss&lt;w&gt;rd</password>\
             </connectionRequest></iq>"
        )
    );
    c.send(&format!(
        "<iq type='result' id='{id}' to='acs@xmpp.test/dhonomos' from='{jid}'/>"
    ))
    .await;
    assert_eq!(request.await.unwrap(), Ok(CrOutcome::Acknowledged));

    // Client closes its stream -> server closes its stream + connection.
    c.send("</stream:stream>").await;
    assert_eq!(c.until_closed().await, "</stream:stream>");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!h.server.is_connected("dev-1"));
    assert_eq!(h.server.jid("dev-1"), None);
    assert_eq!(h.fake.events(), ["connected dev-1", "disconnected dev-1"]);
    h.shutdown().await;
}

#[tokio::test]
async fn a_server_chosen_resource_is_random_and_a_chosen_one_is_kept() {
    let h = start(
        Fake::with(&[("dev-1", "pw", false), ("dev-2", "pw", false)]),
        |_| {},
    )
    .await;
    let mut a = h.client().await;
    let mut b = h.client().await;
    let ja = a.login("dev-1", "pw", "").await;
    let jb = b.login("dev-2", "pw", "").await;
    assert!(
        ja.contains("/cwmp-")
            && jb.contains("/cwmp-")
            && ja.split('/').nth(1) != jb.split('/').nth(1)
    );
    let mut c = h.client().await;
    assert_eq!(
        c.login("dev-1", "pw", "my-res").await,
        "dev-1@xmpp.test/my-res"
    );
    h.shutdown().await;
}

// Authentication

#[tokio::test]
async fn a_wrong_password_is_refused_and_the_connection_closed() {
    let fake = Fake::with(&[("dev-1", "right", false)]);
    let h = start(fake, |_| {}).await;
    let mut c = h.client().await;
    c.secure().await;
    c.send(&stream_open(DOMAIN)).await;
    c.until("</stream:features>").await;
    c.send(&format!(
        "<auth xmlns='{NS_SASL}' mechanism='PLAIN'>{}</auth>",
        plain("", "dev-1", "wrong")
    ))
    .await;
    assert_eq!(
        c.until_closed().await,
        format!("<failure xmlns=\"{NS_SASL}\"><not-authorized/></failure></stream:stream>")
    );
    assert!(!h.server.is_connected("dev-1"));
    // Unknown account -> same reply.
    let mut c = h.client().await;
    c.secure().await;
    c.send(&stream_open(DOMAIN)).await;
    c.until("</stream:features>").await;
    c.send(&format!(
        "<auth xmlns='{NS_SASL}' mechanism='PLAIN'>{}</auth>",
        plain("", "nobody", "x")
    ))
    .await;
    assert!(c.until_closed().await.contains("<not-authorized/>"));
    assert!(h.fake.events().is_empty());
    h.shutdown().await;
}

#[tokio::test]
async fn repeated_failures_lock_the_account_for_that_client() {
    let fake = Fake::with(&[("dev-1", "right", false)]);
    let h = start(fake.clone(), |_| {}).await;
    for _ in 0..5 {
        let mut c = h.client().await;
        c.secure().await;
        c.send(&stream_open(DOMAIN)).await;
        c.until("</stream:features>").await;
        c.send(&format!(
            "<auth xmlns='{NS_SASL}' mechanism='PLAIN'>{}</auth>",
            plain("", "dev-1", "wrong")
        ))
        .await;
        assert!(c.until_closed().await.contains("<not-authorized/>"));
    }
    assert_eq!(fake.lookups(), 5);
    // 6th: refused without account lookup, even with right password.
    let mut c = h.client().await;
    c.secure().await;
    c.send(&stream_open(DOMAIN)).await;
    c.until("</stream:features>").await;
    c.send(&format!(
        "<auth xmlns='{NS_SASL}' mechanism='PLAIN'>{}</auth>",
        plain("", "dev-1", "right")
    ))
    .await;
    assert!(c.until_closed().await.contains("<not-authorized/>"));
    assert_eq!(fake.lookups(), 5, "locked: no lookup");
    h.shutdown().await;
}

#[tokio::test]
async fn a_right_password_does_not_count_against_the_limit() {
    let h = start(Fake::with(&[("dev-1", "right", false)]), |_| {}).await;
    for _ in 0..12 {
        let mut c = h.client().await;
        c.login("dev-1", "right", "").await;
    }
    h.shutdown().await;
}

#[tokio::test]
async fn a_pending_password_becomes_the_device_password_on_first_use() {
    let fake = Fake::with(&[("dev-1", "old", false), ("dev-1", "new", true)]);
    let h = start(fake.clone(), |_| {}).await;
    // Active password -> OK, no promotion.
    let mut c = h.client().await;
    c.login("dev-1", "old", "").await;
    assert_eq!(
        *fake.accepted.lock().unwrap(),
        [("dev-1".to_owned(), false)]
    );
    // Pending password -> OK too, reported as pending -> can be promoted.
    let mut c2 = h.client().await;
    c2.login("dev-1", "new", "").await;
    assert_eq!(
        *fake.accepted.lock().unwrap(),
        [("dev-1".to_owned(), false), ("dev-1".to_owned(), true)]
    );
    h.shutdown().await;
}

#[tokio::test]
async fn the_acs_localpart_never_logs_in() {
    let h = start(
        Fake::with(&[("acs", "pw", false), ("ACS", "pw", false)]),
        |_| {},
    )
    .await;
    for user in ["acs", "ACS"] {
        let mut c = h.client().await;
        c.secure().await;
        c.send(&stream_open(DOMAIN)).await;
        c.until("</stream:features>").await;
        c.send(&format!(
            "<auth xmlns='{NS_SASL}' mechanism='PLAIN'>{}</auth>",
            plain("", user, "pw")
        ))
        .await;
        assert!(
            c.until_closed().await.contains("<not-authorized/>"),
            "{user}"
        );
    }
    assert!(!h.server.is_connected("acs"));
    h.shutdown().await;
}

#[tokio::test]
async fn the_authorization_identity_is_empty_or_the_account() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |_| {}).await;
    let mut ok = h.client().await;
    ok.secure().await;
    ok.send(&stream_open(DOMAIN)).await;
    ok.until("</stream:features>").await;
    ok.send(&format!(
        "<auth xmlns='{NS_SASL}' mechanism='PLAIN'>{}</auth>",
        plain("dev-1@xmpp.test", "dev-1", "pw")
    ))
    .await;
    ok.until("<success").await;
    for authzid in ["dev-2@xmpp.test", "dev-1@other.test"] {
        let mut c = h.client().await;
        c.secure().await;
        c.send(&stream_open(DOMAIN)).await;
        c.until("</stream:features>").await;
        c.send(&format!(
            "<auth xmlns='{NS_SASL}' mechanism='PLAIN'>{}</auth>",
            plain(authzid, "dev-1", "pw")
        ))
        .await;
        assert!(
            c.until_closed().await.contains("<invalid-authzid/>"),
            "{authzid}"
        );
    }
    h.shutdown().await;
}

#[tokio::test]
async fn other_mechanisms_and_bad_encodings_fail() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |_| {}).await;
    for (mechanism, body, condition) in [
        ("SCRAM-SHA-256", "biws", "invalid-mechanism"),
        ("DIGEST-MD5", "", "invalid-mechanism"),
        ("PLAIN", "!!not base64!!", "incorrect-encoding"),
        ("PLAIN", "bm8gbnVscw==", "malformed-request"),
    ] {
        let mut c = h.client().await;
        c.secure().await;
        c.send(&stream_open(DOMAIN)).await;
        c.until("</stream:features>").await;
        c.send(&format!(
            "<auth xmlns='{NS_SASL}' mechanism='{mechanism}'>{body}</auth>"
        ))
        .await;
        let reply = c.until_closed().await;
        assert!(
            reply.contains(&format!("<{condition}/>")),
            "{mechanism}: {reply}"
        );
    }
    h.shutdown().await;
}

#[tokio::test]
async fn plain_without_an_initial_response_is_asked_for() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |_| {}).await;
    let mut c = h.client().await;
    c.secure().await;
    c.send(&stream_open(DOMAIN)).await;
    c.until("</stream:features>").await;
    c.send(&format!("<auth xmlns='{NS_SASL}' mechanism='PLAIN'/>"))
        .await;
    c.until(&format!("<challenge xmlns=\"{NS_SASL}\"/>")).await;
    c.send(&format!(
        "<response xmlns='{NS_SASL}'>{}</response>",
        plain("", "dev-1", "pw")
    ))
    .await;
    c.until("<success").await;
    h.shutdown().await;
}

#[tokio::test]
async fn an_unavailable_account_lookup_is_a_temporary_failure_and_does_not_count() {
    let fake = Fake::with(&[("dev-1", "pw", false)]);
    *fake.down.lock().unwrap() = true;
    let h = start(fake.clone(), |_| {}).await;
    for _ in 0..8 {
        let mut c = h.client().await;
        c.secure().await;
        c.send(&stream_open(DOMAIN)).await;
        c.until("</stream:features>").await;
        c.send(&format!(
            "<auth xmlns='{NS_SASL}' mechanism='PLAIN'>{}</auth>",
            plain("", "dev-1", "pw")
        ))
        .await;
        assert!(c.until_closed().await.contains("<temporary-auth-failure/>"));
    }
    *fake.down.lock().unwrap() = false;
    let mut c = h.client().await;
    c.login("dev-1", "pw", "").await;
    h.shutdown().await;
}

// Negotiation order

#[tokio::test]
async fn nothing_but_starttls_is_accepted_in_the_clear() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |_| {}).await;
    for stanza in [
        format!(
            "<auth xmlns='{NS_SASL}' mechanism='PLAIN'>{}</auth>",
            plain("", "dev-1", "pw")
        ),
        "<iq type='get' id='1'><ping xmlns='urn:xmpp:ping'/></iq>".to_owned(),
        "<presence/>".to_owned(),
        format!("<iq type='set' id='b'><bind xmlns='{NS_BIND}'/></iq>"),
    ] {
        let mut c = h.client().await;
        c.send(&stream_open(DOMAIN)).await;
        c.until("</stream:features>").await;
        c.send(&stanza).await;
        let reply = c.until_closed().await;
        assert!(
            reply.contains("<not-authorized xmlns=\"urn:ietf:params:xml:ns:xmpp-streams\"/>"),
            "{stanza} -> {reply}"
        );
        assert!(reply.ends_with("</stream:stream>"));
    }
    assert!(h.fake.events().is_empty());
    h.shutdown().await;
}

#[tokio::test]
async fn bind_and_stanzas_are_refused_before_login_and_login_is_refused_twice() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |_| {}).await;
    // Over TLS, not logged in: bind, ping, 2nd STARTTLS.
    for stanza in [
        format!("<iq type='set' id='b'><bind xmlns='{NS_BIND}'/></iq>"),
        "<iq type='get' id='1'><ping xmlns='urn:xmpp:ping'/></iq>".to_owned(),
        format!("<starttls xmlns='{NS_TLS}'/>"),
    ] {
        let mut c = h.client().await;
        c.secure().await;
        c.send(&stream_open(DOMAIN)).await;
        c.until("</stream:features>").await;
        c.send(&stanza).await;
        assert!(
            c.until_closed().await.contains("<not-authorized "),
            "{stanza}"
        );
    }
    // Logged in, not bound: ping too early.
    let mut c = h.client().await;
    c.authenticate("dev-1", "pw").await;
    c.send("<iq type='get' id='1'><ping xmlns='urn:xmpp:ping'/></iq>")
        .await;
    assert!(c.until_closed().await.contains("<not-authorized "));
    assert!(!h.server.is_connected("dev-1"));
    h.shutdown().await;
}

#[tokio::test]
async fn the_stream_must_be_for_this_domain() {
    let h = start(Fake::with(&[]), |_| {}).await;
    for to in ["other.test", ""] {
        let mut c = h.client().await;
        let header = if to.is_empty() {
            "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>".to_owned()
        } else {
            stream_open(to)
        };
        c.send(&header).await;
        let reply = c.until_closed().await;
        assert!(
            reply.contains("<stream:stream ") && reply.contains("<host-unknown "),
            "{to:?}: {reply}"
        );
    }
    // Domain compare: case-insensitive.
    let mut c = h.client().await;
    c.send(&stream_open("XMPP.Test")).await;
    c.until("</stream:features>").await;
    // No `version` (old stream) -> refused.
    let mut c = h.client().await;
    c.send("<stream:stream to='xmpp.test' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>").await;
    assert!(c.until_closed().await.contains("<unsupported-version "));
    h.shutdown().await;
}

#[tokio::test]
async fn data_behind_starttls_in_the_clear_is_refused() {
    let h = start(Fake::with(&[]), |_| {}).await;
    let mut c = h.client().await;
    c.send(&stream_open(DOMAIN)).await;
    c.until("</stream:features>").await;
    // Attacker bytes after `<starttls/>` -> would be read inside TLS.
    c.send(&format!(
        "<starttls xmlns='{NS_TLS}'/><auth xmlns='{NS_SASL}' mechanism='PLAIN'>x</auth>"
    ))
    .await;
    let reply = c.until_closed().await;
    assert!(!reply.contains("<proceed"), "{reply}");
    assert!(reply.contains("<not-well-formed "), "{reply}");
    h.shutdown().await;
}

// Sessions

#[tokio::test]
async fn a_second_session_of_an_account_replaces_the_first_with_conflict() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |_| {}).await;
    let mut first = h.client().await;
    first.login("dev-1", "pw", "one").await;
    let mut second = h.client().await;
    let jid = second.login("dev-1", "pw", "two").await;
    let end = first.until_closed().await;
    assert_eq!(
        end,
        "<stream:error><conflict xmlns=\"urn:ietf:params:xml:ns:xmpp-streams\"/></stream:error></stream:stream>"
    );
    assert_eq!(h.server.connections(), 1);
    assert!(h.server.is_connected("dev-1"));
    // Old session end does not drop the new one.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(h.server.is_connected("dev-1"));
    assert_eq!(
        h.fake.events(),
        ["connected dev-1", "connected dev-1"],
        "no disconnect for the replaced session"
    );
    second
        .send("<iq type='get' id='p' to='xmpp.test'><ping xmlns='urn:xmpp:ping'/></iq>")
        .await;
    second.until("<iq type=\"result\" id=\"p\"").await;
    second.until("/>").await;
    // CR -> newer session.
    let server = h.server.clone();
    let request = tokio::spawn(async move {
        server
            .send_connection_request("dev-1", "u", "p", Duration::from_secs(5))
            .await
    });
    let cr = second.until("</iq>").await;
    assert_eq!(attr(&cr, "to"), jid);
    second
        .send(&format!("<iq type='result' id='{}'/>", attr(&cr, "id")))
        .await;
    assert_eq!(request.await.unwrap(), Ok(CrOutcome::Acknowledged));
    h.shutdown().await;
}

#[tokio::test]
async fn nothing_is_routed_between_devices() {
    let h = start(
        Fake::with(&[("dev-1", "pw", false), ("dev-2", "pw", false)]),
        |_| {},
    )
    .await;
    let mut a = h.client().await;
    let ja = a.login("dev-1", "pw", "r").await;
    let mut b = h.client().await;
    b.login("dev-2", "pw", "r").await;

    let err = |kind: &str, id: &str, to: &str| {
        format!(
            "<{kind} type=\"error\" id=\"{id}\" from=\"{to}\" to=\"{ja}\"><error type=\"cancel\">\
             <service-unavailable xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\"/></error></{kind}>"
        )
    };
    // To other device (full + bare JID): iq, message, presence.
    a.send("<message to='dev-2@xmpp.test/r' id='m1' type='chat'><body>hi</body></message>")
        .await;
    assert_eq!(
        a.until("</message>").await,
        err("message", "m1", "dev-2@xmpp.test/r")
    );
    a.send("<iq type='get' id='q1' to='dev-2@xmpp.test'><ping xmlns='urn:xmpp:ping'/></iq>")
        .await;
    assert_eq!(a.until("</iq>").await, err("iq", "q1", "dev-2@xmpp.test"));
    a.send("<iq type='set' id='q2' to='dev-2@xmpp.test/r'><x xmlns='urn:x'/></iq>")
        .await;
    assert_eq!(a.until("</iq>").await, err("iq", "q2", "dev-2@xmpp.test/r"));
    a.send("<presence to='dev-2@xmpp.test/r' id='pr1'/>").await;
    assert_eq!(
        a.until("</presence>").await,
        err("presence", "pr1", "dev-2@xmpp.test/r")
    );
    // To another server.
    a.send("<iq type='get' id='q3' to='other.test'><ping xmlns='urn:xmpp:ping'/></iq>")
        .await;
    assert_eq!(a.until("</iq>").await, err("iq", "q3", "other.test"));
    // Other device got none of it.
    b.quiet().await;
    // Errors, results + messages to the server itself -> dropped, no reply.
    a.send("<message to='dev-2@xmpp.test/r' type='error'/><iq type='result' id='x' to='dev-2@xmpp.test/r'/>").await;
    a.send(
        "<message to='xmpp.test'><body>hello</body></message><message><body>hello</body></message>",
    )
    .await;
    a.send("<presence type='unavailable'/>").await;
    a.quiet().await;
    h.shutdown().await;
}

#[tokio::test]
async fn iq_to_the_server_that_it_does_not_know_is_service_unavailable() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |_| {}).await;
    let mut c = h.client().await;
    let jid = c.login("dev-1", "pw", "r").await;
    for (typ, payload, condition) in [
        (
            "get",
            "<query xmlns='http://jabber.org/protocol/disco#info'/>",
            "service-unavailable",
        ),
        (
            "get",
            "<query xmlns='jabber:iq:roster'/>",
            "service-unavailable",
        ),
        (
            "set",
            "<query xmlns='jabber:iq:register'/>",
            "service-unavailable",
        ),
        (
            "set",
            "<ping xmlns='urn:xmpp:ping'/>",
            "service-unavailable",
        ),
        ("set", &format!("<bind xmlns='{NS_BIND}'/>"), "not-allowed"),
        ("get", "", "bad-request"),
    ] {
        c.send(&format!("<iq type='{typ}' id='x1'>{payload}</iq>"))
            .await;
        let reply = c.until("</iq>").await;
        assert_eq!(attr(&reply, "type"), "error", "{payload}");
        assert_eq!(attr(&reply, "to"), jid);
        assert!(
            reply.contains(&format!("<{condition} xmlns=")),
            "{payload}: {reply}"
        );
    }
    // iq without id, or with unknown type.
    c.send("<iq type='get'><ping xmlns='urn:xmpp:ping'/></iq>")
        .await;
    assert!(c.until("</iq>").await.contains("<bad-request "));
    c.send("<iq type='bogus' id='y'/>").await;
    assert!(c.until("</iq>").await.contains("<bad-request "));
    // Ping to bare JID -> answered; ping without address too.
    c.send(&format!(
        "<iq type='get' id='p1' to='{}'><ping xmlns='urn:xmpp:ping'/></iq>",
        jid.split('/').next().unwrap()
    ))
    .await;
    assert!(
        c.until("/>")
            .await
            .starts_with("<iq type=\"result\" id=\"p1\"")
    );
    c.send("<iq type='get' id='p2'><ping xmlns='urn:xmpp:ping'/></iq>")
        .await;
    assert_eq!(
        c.until("/>").await,
        format!("<iq type=\"result\" id=\"p2\" to=\"{jid}\"/>")
    );
    h.shutdown().await;
}

#[tokio::test]
async fn the_client_cannot_choose_who_it_is_from() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |_| {}).await;
    let mut c = h.client().await;
    let jid = c.login("dev-1", "pw", "r").await;
    c.send("<iq type='get' id='f1' from='acs@xmpp.test/dhonomos' to='xmpp.test'><ping xmlns='urn:xmpp:ping'/></iq>").await;
    // Reply -> bound JID, whatever the stanza said.
    assert_eq!(attr(&c.until("/>").await, "to"), jid);
    // Device claiming the ACS JID -> still cannot answer any CR.
    h.shutdown().await;
}

#[tokio::test]
async fn only_the_session_asked_can_answer_a_connection_request() {
    let h = start(
        Fake::with(&[("dev-1", "pw", false), ("dev-2", "pw", false)]),
        |_| {},
    )
    .await;
    let mut a = h.client().await;
    a.login("dev-1", "pw", "r").await;
    let mut b = h.client().await;
    b.login("dev-2", "pw", "r").await;
    let server = h.server.clone();
    let request = tokio::spawn(async move {
        server
            .send_connection_request("dev-1", "u", "p", Duration::from_millis(600))
            .await
    });
    let id = attr(&a.until("</iq>").await, "id");
    // dev-2 got the ID somehow + answers -> ignored, not dev-1.
    b.send(&format!("<iq type='result' id='{id}'/>")).await;
    assert_eq!(request.await.unwrap(), Ok(CrOutcome::TimedOut));
    h.shutdown().await;
}

#[tokio::test]
async fn connection_request_outcomes() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |_| {}).await;
    assert_eq!(
        h.server
            .send_connection_request("dev-1", "u", "p", Duration::from_secs(1))
            .await,
        Ok(CrOutcome::NotConnected)
    );
    let mut c = h.client().await;
    c.login("dev-1", "pw", "r").await;

    // Rejection -> its condition; rest of the stanza ignored.
    let server = h.server.clone();
    let request = tokio::spawn(async move {
        server
            .send_connection_request("dev-1", "u", "wrong", Duration::from_secs(5))
            .await
    });
    let id = attr(&c.until("</iq>").await, "id");
    c.send(&format!(
        "<iq type='error' id='{id}'><connectionRequest xmlns='urn:broadband-forum-org:cwmp:xmppConnReq-1-0'>\
         <username>u</username><password>wrong</password></connectionRequest>\
         <error type='auth'><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"
    ))
    .await;
    assert_eq!(
        request.await.unwrap(),
        Ok(CrOutcome::Rejected("not-authorized".to_owned()))
    );

    // Error, no known condition.
    let server = h.server.clone();
    let request = tokio::spawn(async move {
        server
            .send_connection_request("dev-1", "u", "p", Duration::from_secs(5))
            .await
    });
    let id = attr(&c.until("</iq>").await, "id");
    c.send(&format!("<iq type='error' id='{id}'/>")).await;
    assert_eq!(
        request.await.unwrap(),
        Ok(CrOutcome::Rejected("undefined-condition".to_owned()))
    );

    // No answer in time -> late answer harmless.
    let server = h.server.clone();
    let request = tokio::spawn(async move {
        server
            .send_connection_request("dev-1", "u", "p", Duration::from_millis(200))
            .await
    });
    let id = attr(&c.until("</iq>").await, "id");
    assert_eq!(request.await.unwrap(), Ok(CrOutcome::TimedOut));
    c.send(&format!("<iq type='result' id='{id}'/>")).await;
    c.send("<iq type='get' id='p' to='xmpp.test'><ping xmlns='urn:xmpp:ping'/></iq>")
        .await;
    c.until("<iq type=\"result\" id=\"p\"").await;
    c.until("/>").await;

    // Session ends before answer.
    let server = h.server.clone();
    let request = tokio::spawn(async move {
        server
            .send_connection_request("dev-1", "u", "p", Duration::from_secs(5))
            .await
    });
    c.until("</iq>").await;
    c.send("</stream:stream>").await;
    assert_eq!(request.await.unwrap(), Ok(CrOutcome::NotConnected));

    // Credentials XML cannot carry -> refused before send.
    let mut c = h.client().await;
    c.login("dev-1", "pw", "r").await;
    assert_eq!(
        h.server
            .send_connection_request("dev-1", "u\u{1}", "p", Duration::from_secs(1))
            .await,
        Err(SendError::Unrepresentable)
    );
    c.quiet().await;
    h.shutdown().await;
}

#[tokio::test]
async fn a_request_larger_than_the_queue_is_refused_and_the_session_stays() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |c| {
        c.queue_limit = 4096
    })
    .await;
    let mut c = h.client().await;
    c.login("dev-1", "pw", "r").await;
    let big = "x".repeat(8192);
    assert_eq!(
        h.server
            .send_connection_request("dev-1", &big, "p", Duration::from_secs(1))
            .await,
        Err(SendError::TooLarge)
    );
    c.quiet().await;
    assert!(h.server.is_connected("dev-1"));
    h.shutdown().await;
}

#[tokio::test]
async fn a_device_that_does_not_read_is_closed() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |c| {
        c.queue_limit = 64 * 1024;
        c.write_timeout = Duration::from_millis(500);
    })
    .await;
    // Client logs in, then never reads.
    let mut c = h.client().await;
    c.login("dev-1", "pw", "r").await;
    let big = "x".repeat(30_000);
    let mut refused = false;
    for _ in 0..4000 {
        match h
            .server
            .send_connection_request("dev-1", &big, "p", Duration::ZERO)
            .await
        {
            Ok(CrOutcome::TimedOut) => {}
            Err(SendError::QueueFull) => {
                refused = true;
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(
        refused,
        "the queue must fill up behind a reader that has stopped"
    );
    // Connection closed (blocked write times out).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while h.server.is_connected("dev-1") {
        assert!(tokio::time::Instant::now() < deadline, "still connected");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    h.shutdown().await;
}

// Limits

#[tokio::test]
async fn the_connection_must_bind_before_the_pre_auth_deadline() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |c| {
        c.pre_auth_timeout = Duration::from_millis(1500);
    })
    .await;
    // Nothing sent -> closed silently.
    let mut idle = h.client().await;
    assert_eq!(idle.until_closed().await, "");
    // Stream opened, then nothing -> connection-timeout.
    let mut c = h.client().await;
    c.send(&stream_open(DOMAIN)).await;
    c.until("</stream:features>").await;
    let end = c.until_closed().await;
    assert!(end.contains("<connection-timeout xmlns="), "{end}");
    // Deadline covers TLS handshake + login too: logged in, not bound.
    let mut c = h.client().await;
    c.authenticate("dev-1", "pw").await;
    let end = c.until_closed().await;
    assert!(end.contains("<connection-timeout "), "{end}");
    // Bound session -> no deadline.
    let mut c = h.client().await;
    c.login("dev-1", "pw", "r").await;
    c.quiet().await;
    assert!(h.server.is_connected("dev-1"));
    h.shutdown().await;
}

/// Idle timeout changed at runtime (runtime settings) -> used from the next session wait.
#[tokio::test]
async fn the_idle_timeout_changes_while_running() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |c| {
        c.idle_timeout = Duration::from_secs(3600);
    })
    .await;
    let mut c = h.client().await;
    c.login("dev-1", "pw", "r").await;
    h.server.set_idle_timeout(Duration::from_millis(300));
    assert_eq!(h.server.idle_timeout(), Duration::from_millis(300));
    c.send(" ").await;
    let end = c.until_closed().await;
    assert!(end.contains("<connection-timeout "), "{end}");
    h.shutdown().await;
}

#[tokio::test]
async fn an_idle_session_is_closed() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |c| {
        c.idle_timeout = Duration::from_millis(700);
    })
    .await;
    let mut c = h.client().await;
    c.login("dev-1", "pw", "r").await;
    // Ping within timeout -> stays open.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        c.send("<iq type='get' id='p' to='xmpp.test'><ping xmlns='urn:xmpp:ping'/></iq>")
            .await;
        c.until("<iq type=\"result\" id=\"p\"").await;
        c.until("/>").await;
    }
    // Whitespace = traffic too.
    tokio::time::sleep(Duration::from_millis(300)).await;
    c.send(" ").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(h.server.is_connected("dev-1"));
    let end = c.until_closed().await;
    assert!(end.contains("<connection-timeout "), "{end}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!h.server.is_connected("dev-1"));
    assert_eq!(
        h.fake.events().last().map(String::as_str),
        Some("disconnected dev-1")
    );
    h.shutdown().await;
}

#[tokio::test]
async fn stanza_size_limits_before_and_after_login() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |_| {}).await;
    // Before auth: max 4 KiB.
    let mut c = h.client().await;
    c.secure().await;
    c.send(&stream_open(DOMAIN)).await;
    c.until("</stream:features>").await;
    c.send(&format!(
        "<auth xmlns='{NS_SASL}' mechanism='PLAIN'>{}</auth>",
        "A".repeat(5000)
    ))
    .await;
    assert!(c.until_closed().await.contains("<policy-violation "));
    // After auth: up to 64 KiB.
    let mut c = h.client().await;
    c.login("dev-1", "pw", "r").await;
    c.send(&format!(
        "<message to='xmpp.test'><body>{}</body></message>",
        "x".repeat(20_000)
    ))
    .await;
    c.send("<iq type='get' id='p' to='xmpp.test'><ping xmlns='urn:xmpp:ping'/></iq>")
        .await;
    c.until("<iq type=\"result\" id=\"p\"").await;
    c.until("/>").await;
    c.send(&format!(
        "<message to='xmpp.test'><body>{}</body></message>",
        "x".repeat(70_000)
    ))
    .await;
    assert!(c.until_closed().await.contains("<policy-violation "));
    h.shutdown().await;
}

#[tokio::test]
async fn forbidden_xml_closes_the_stream() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |_| {}).await;
    for (bad, condition) in [
        ("<!DOCTYPE iq [<!ENTITY a 'b'>]>", "restricted-xml"),
        ("<!-- c -->", "restricted-xml"),
        ("<?pi x?>", "restricted-xml"),
        (
            "<message to='xmpp.test'><body>&xxe;</body></message>",
            "restricted-xml",
        ),
        ("<message to='xmpp.test'></iq>", "not-well-formed"),
        ("<message to='xmpp.test' a='1' a='2'/>", "not-well-formed"),
        ("text", "not-well-formed"),
        ("<foo xmlns='jabber:client'/>", "unsupported-stanza-type"),
        (
            "<iq xmlns='jabber:server' id='1' type='get'/>",
            "invalid-namespace",
        ),
    ] {
        let mut c = h.client().await;
        c.login("dev-1", "pw", "r").await;
        c.send(bad).await;
        let end = c.until_closed().await;
        assert!(
            end.contains(&format!(
                "<{condition} xmlns=\"urn:ietf:params:xml:ns:xmpp-streams\"/>"
            )),
            "{bad}: {end}"
        );
        assert!(end.ends_with("</stream:stream>"));
    }
    // Before the stream header + stream level in clear text.
    for bad in ["<!DOCTYPE x>", "GET / HTTP/1.1\r\n\r\n"] {
        let mut c = h.client().await;
        c.send(bad).await;
        let end = c.until_closed().await;
        assert!(
            end.contains("<stream:stream ") && end.contains("</stream:error>"),
            "{bad}: {end}"
        );
    }
    h.shutdown().await;
}

#[tokio::test]
async fn a_flood_of_stanzas_is_cut_off() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |_| {}).await;
    let mut c = h.client().await;
    c.login("dev-1", "pw", "r").await;
    let one = "<iq type='get' id='p' to='xmpp.test'><ping xmlns='urn:xmpp:ping'/></iq>";
    c.send(&one.repeat(300)).await;
    let end = c.until_closed().await;
    assert!(
        end.contains("<policy-violation "),
        "{}",
        &end[end.len().saturating_sub(300)..]
    );
    h.shutdown().await;
}

#[tokio::test]
async fn connections_are_capped_in_total_and_per_address() {
    let h = start(Fake::with(&[]), |c| c.max_connections_per_ip = 2).await;
    let mut a = h.client().await;
    let mut b = h.client().await;
    a.send(&stream_open(DOMAIN)).await;
    b.send(&stream_open(DOMAIN)).await;
    a.until("</stream:features>").await;
    b.until("</stream:features>").await;
    // 3rd closed at accept: no header, no error, nothing.
    let mut third = h.client().await;
    third.send(&stream_open(DOMAIN)).await;
    assert_eq!(third.until_closed().await, "");
    // Slot free after a connection ends.
    drop(a);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut again = h.client().await;
    again.send(&stream_open(DOMAIN)).await;
    again.until("</stream:features>").await;
    h.shutdown().await;

    let h = start(Fake::with(&[]), |c| c.max_connections = 1).await;
    let mut a = h.client().await;
    a.send(&stream_open(DOMAIN)).await;
    a.until("</stream:features>").await;
    let mut b = h.client().await;
    b.send(&stream_open(DOMAIN)).await;
    assert_eq!(b.until_closed().await, "");
    h.shutdown().await;
}

#[tokio::test]
async fn shutdown_tells_sessions_the_server_is_going_away() {
    let h = start(Fake::with(&[("dev-1", "pw", false)]), |_| {}).await;
    let mut c = h.client().await;
    c.login("dev-1", "pw", "r").await;
    let Harness { stop, done, .. } = h;
    let _ = stop.send(());
    let end = c.until_closed().await;
    assert!(end.contains("<system-shutdown "), "{end}");
    done.await.unwrap();
}

// Refusals logged with source address.

/// Log capture of a test.
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
    /// Capture info+ logs of this thread until guard drop.
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

    fn refusals(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|l| l.contains("refused") || l.contains("refusals suppressed"))
            .map(str::to_owned)
            .collect()
    }
}

async fn wait_for_refusals(logs: &LogBuf, count: usize) -> Vec<String> {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let lines = logs.refusals();
        if lines.len() >= count {
            return lines;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out: {lines:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn a_wrong_password_is_logged_with_the_device_address_and_account() {
    let logs = LogBuf::default();
    let _capture = logs.capture();
    let h = start(Fake::with(&[("dev-1", "right", false)]), |_| {}).await;
    // Loopback addresses of their own: the log limiter is shared by the process.
    let mut ok = h.client_from("127.0.0.51").await;
    ok.login("dev-1", "right", "res").await;
    assert!(logs.refusals().is_empty(), "{:?}", logs.refusals());

    let mut c = h.client_from("127.0.0.52").await;
    c.secure().await;
    c.send(&stream_open(DOMAIN)).await;
    c.until("</stream:features>").await;
    c.send(&format!(
        "<auth xmlns='{NS_SASL}' mechanism='PLAIN'>{}</auth>",
        plain("", "dev-1", "wrong")
    ))
    .await;
    assert!(c.until_closed().await.contains("<not-authorized/>"));
    let lines = wait_for_refusals(&logs, 1).await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("INFO"), "{}", lines[0]);
    assert!(
        lines[0].contains("request refused listener=xmpp remote=127.0.0.52 reason=auth_failed"),
        "{}",
        lines[0]
    );
    assert!(lines[0].contains(r#"username="dev-1""#), "{}", lines[0]);
    h.shutdown().await;
}

#[tokio::test]
async fn a_failed_tls_handshake_is_logged_with_the_address() {
    let logs = LogBuf::default();
    let _capture = logs.capture();
    let h = start(Fake::with(&[]), |_| {}).await;
    let mut c = h.client_from("127.0.0.53").await;
    c.send(&stream_open(DOMAIN)).await;
    c.until("</stream:features>").await;
    c.send(&format!("<starttls xmlns='{NS_TLS}'/>")).await;
    c.until(&format!("<proceed xmlns=\"{NS_TLS}\"/>")).await;
    // Not a ClientHello.
    c.send("GET / HTTP/1.1\r\n\r\n").await;
    let lines = wait_for_refusals(&logs, 1).await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0]
            .contains("connection refused listener=xmpp remote=127.0.0.53 reason=tls_handshake"),
        "{}",
        lines[0]
    );
    h.shutdown().await;
}
