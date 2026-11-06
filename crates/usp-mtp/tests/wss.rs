//! WebSocket MTP over TLS, client certificate names the EndpointID (US-05, US-08).
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use dhonomos_pki::{Ca, Issued, Profile};
use dhonomos_usp_mtp::{MultiMtp, WsMtp, tls_acceptor, tls_acceptor_with};
use futures_util::SinkExt;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{self, Message};

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

/// `wss://localhost:<port>/usp?eid=<eid>` with `config`.
async fn connect(
    port: u16,
    eid: &str,
    config: Arc<rustls::ClientConfig>,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    String,
> {
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let tls = tokio_rustls::TlsConnector::from(config)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .map_err(|e| format!("tls: {e}"))?;
    let mut req = format!("wss://localhost:{port}/usp?eid={eid}")
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("Sec-WebSocket-Protocol", "v1.usp".parse().unwrap());
    match tokio_tungstenite::client_async(req, tls).await {
        Ok((ws, _)) => Ok(ws),
        Err(tungstenite::Error::Http(r)) => Err(format!("http {}", r.status().as_u16())),
        Err(e) => Err(format!("ws: {e}")),
    }
}

#[tokio::test]
async fn wss_binds_connections_to_certificate_endpoint_ids() {
    let ca = Ca::generate("Test USP CA").unwrap();
    let server = ca
        .issue(&Profile {
            endpoint_id: "self::ctrl".into(),
            dns_names: vec!["localhost".into()],
            server: true,
            days: 1,
            ..Profile::default()
        })
        .unwrap();
    let acceptor = tls_acceptor(
        &server.cert_pem,
        server.key_pem.as_deref().unwrap(),
        Some(ca.cert_pem()),
        true,
    )
    .unwrap();
    let (tx, mut inbound) = mpsc::channel(8);
    let ws = WsMtp::new(tx);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let srv = ws.clone();
    tokio::spawn(async move {
        srv.serve_tls(listener, acceptor, std::future::pending())
            .await
    });

    let alice = agent_cert(&ca, "os::alice");
    let mut conn = connect(port, "os::alice", client_config(&ca, Some(&alice)))
        .await
        .unwrap();
    conn.send(Message::binary(vec![1, 2, 3])).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), inbound.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.reply_to.as_deref(), Some("ws:os::alice"));
    assert_eq!(&got.payload[..], &[1, 2, 3]);

    // Alice's cert -> not accepted as Bob.
    assert_eq!(
        connect(port, "os::bob", client_config(&ca, Some(&alice)))
            .await
            .err()
            .as_deref(),
        Some("http 403")
    );
    // No client cert -> handshake fails (required).
    assert!(
        connect(port, "os::alice", client_config(&ca, None))
            .await
            .is_err()
    );
    // Revoke Alice's cert -> her connection closed + new ones refused.
    // New cert for her -> works.
    let closed = ws.set_revoked([alice.sha256.clone()].into());
    assert_eq!(closed, 1);
    use futures_util::StreamExt as _;
    let end = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(m)) = conn.next().await {
            if m.is_close() {
                return true;
            }
        }
        true
    })
    .await
    .unwrap();
    assert!(end);
    let gone = tokio::time::timeout(Duration::from_secs(5), inbound.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(gone.closed, "the Controller hears the Agent is gone");
    assert_eq!(
        connect(port, "os::alice", client_config(&ca, Some(&alice)))
            .await
            .err()
            .as_deref(),
        Some("http 403")
    );
    let renewed = agent_cert(&ca, "os::alice");
    connect(port, "os::alice", client_config(&ca, Some(&renewed)))
        .await
        .unwrap();

    // Cert from other CA -> refused too.
    let other = Ca::generate("Other CA").unwrap();
    let mallory = agent_cert(&other, "os::alice");
    assert!(
        connect(port, "os::alice", {
            let mut c = (*client_config(&ca, None)).clone();
            c.client_auth_cert_resolver = client_config(&other, Some(&mallory))
                .client_auth_cert_resolver
                .clone();
            Arc::new(c)
        })
        .await
        .is_err()
    );
}

/// Next Inbound from server to Controller.
async fn next_inbound(
    inbound: &mut mpsc::Receiver<dhonomos_usp_mtp::Inbound>,
) -> dhonomos_usp_mtp::Inbound {
    tokio::time::timeout(Duration::from_secs(5), inbound.recv())
        .await
        .expect("no Inbound")
        .unwrap()
}

/// Wait for `n` open connections (registered after upgrade).
async fn wait_for_connections(ws: &WsMtp, n: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while ws.connections() != n {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

/// Client certs optional -> Agent without cert can claim any EndpointID,
/// except one held with a cert -> 409, live connection stays.
/// Connection with cert -> replaces any.
#[tokio::test]
async fn wss_without_a_certificate_cannot_replace_a_certificate_connection() {
    use futures_util::StreamExt as _;
    let ca = Ca::generate("Test USP CA").unwrap();
    let server = ca
        .issue(&Profile {
            endpoint_id: "self::ctrl".into(),
            dns_names: vec!["localhost".into()],
            server: true,
            days: 1,
            ..Profile::default()
        })
        .unwrap();
    let acceptor = tls_acceptor(
        &server.cert_pem,
        server.key_pem.as_deref().unwrap(),
        Some(ca.cert_pem()),
        false,
    )
    .unwrap();
    let (tx, mut inbound) = mpsc::channel(8);
    let ws = WsMtp::new(tx);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let srv = ws.clone();
    tokio::spawn(async move {
        srv.serve_tls(listener, acceptor, std::future::pending())
            .await
    });
    let anonymous = || client_config(&ca, None);

    let alice = agent_cert(&ca, "os::alice");
    let mut genuine = connect(port, "os::alice", client_config(&ca, Some(&alice)))
        .await
        .unwrap();
    wait_for_connections(&ws, 1).await;

    // Anonymous Agents accepted, but not as Alice.
    assert_eq!(
        connect(port, "os::alice", anonymous())
            .await
            .err()
            .as_deref(),
        Some("http 409")
    );
    let mut bob = connect(port, "os::bob", anonymous()).await.unwrap();
    wait_for_connections(&ws, 2).await;
    // Alice's connection untouched -> Records for her still go there.
    ws.send("os::alice", vec![7, 7]).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), genuine.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&got.into_data()[..], &[7, 7]);

    // Anonymous reconnect -> still replaces anonymous connection.
    let mut bob_again = connect(port, "os::bob", anonymous()).await.unwrap();
    let end = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(m)) = bob.next().await {
            if m.is_close() {
                return;
            }
        }
    })
    .await;
    assert!(end.is_ok(), "the first anonymous connection was replaced");
    // Controller told, with serial of the replacing connection
    // = the one the next Record for Bob goes over.
    let on_bob_again = ws.send("os::bob", vec![1]).await.unwrap();
    let told = next_inbound(&mut inbound).await;
    assert_eq!(told.reply_to.as_deref(), Some("ws:os::bob"));
    assert_eq!(told.sender.as_deref(), Some("os::bob"));
    assert_eq!(told.replaced_by, Some(on_bob_again));
    assert!(!told.closed && !told.opened && told.payload.is_empty());
    let got = tokio::time::timeout(Duration::from_secs(5), bob_again.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&got.into_data()[..], &[1]);

    // Cert connection replaces anything: Alice with renewed cert ...
    let renewed = agent_cert(&ca, "os::alice");
    let mut newer = connect(port, "os::alice", client_config(&ca, Some(&renewed)))
        .await
        .unwrap();
    let end = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(m)) = genuine.next().await {
            if m.is_close() {
                return;
            }
        }
    })
    .await;
    assert!(end.is_ok(), "the older certificate connection was replaced");
    let on_newer = ws.send("os::alice", vec![8]).await.unwrap();
    let told = next_inbound(&mut inbound).await;
    assert_eq!(told.reply_to.as_deref(), Some("ws:os::alice"));
    assert_eq!(told.replaced_by, Some(on_newer));
    assert!(
        on_newer > on_bob_again,
        "serials grow with every connection"
    );
    let got = tokio::time::timeout(Duration::from_secs(5), newer.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&got.into_data()[..], &[8]);
    // ... + Bob once he has one.
    let bob_cert = agent_cert(&ca, "os::bob");
    let mut bob_with_cert = connect(port, "os::bob", client_config(&ca, Some(&bob_cert)))
        .await
        .unwrap();
    // Server registers connection after upgrade -> Record from it = proof.
    bob_with_cert.send(Message::binary(vec![5])).await.unwrap();
    let told = next_inbound(&mut inbound).await;
    assert_eq!(
        told.replaced_by,
        Some(ws.send("os::bob", vec![9]).await.unwrap())
    );
    let got = next_inbound(&mut inbound).await;
    assert_eq!(&got.payload[..], &[5]);
    assert_eq!(
        connect(port, "os::bob", anonymous()).await.err().as_deref(),
        Some("http 409")
    );
}

/// Agent certs from any trusted CA (ours, vendor's) -> connect.
#[tokio::test]
async fn wss_trusts_several_client_cas() {
    let ours = Ca::generate("Our CA").unwrap();
    let vendor = Ca::generate("Vendor factory CA").unwrap();
    let server = ours
        .issue(&Profile {
            endpoint_id: "self::ctrl".into(),
            dns_names: vec!["localhost".into()],
            server: true,
            days: 1,
            ..Profile::default()
        })
        .unwrap();
    let roots = format!("{}\n{}", ours.cert_pem(), vendor.cert_pem());
    let acceptor = tls_acceptor(
        &server.cert_pem,
        server.key_pem.as_deref().unwrap(),
        Some(&roots),
        true,
    )
    .unwrap();
    let (tx, _inbound) = mpsc::channel(8);
    let ws = WsMtp::new(tx);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let srv = ws.clone();
    tokio::spawn(async move {
        srv.serve_tls(listener, acceptor, std::future::pending())
            .await
    });
    // Client trusts our CA for server; own cert from either CA.
    for (issuer, eid) in [(&ours, "os::one"), (&vendor, "os::two")] {
        let agent = agent_cert(issuer, eid);
        let mut config = (*client_config(&ours, None)).clone();
        config.client_auth_cert_resolver = client_config(issuer, Some(&agent))
            .client_auth_cert_resolver
            .clone();
        connect(port, eid, Arc::new(config)).await.unwrap();
    }
    let stranger = Ca::generate("Stranger").unwrap();
    let mallory = agent_cert(&stranger, "os::three");
    let mut config = (*client_config(&ours, None)).clone();
    config.client_auth_cert_resolver = client_config(&stranger, Some(&mallory))
        .client_auth_cert_resolver
        .clone();
    assert!(connect(port, "os::three", Arc::new(config)).await.is_err());
}

/// wss cert follows its PEM files: renewed server cert -> new connections,
/// open connection keeps working.
#[tokio::test]
async fn wss_certificate_is_reloaded_from_files() {
    let ca = Ca::generate("Test USP CA").unwrap();
    let issue = || {
        ca.issue(&Profile {
            endpoint_id: "self::ctrl".into(),
            dns_names: vec!["localhost".into()],
            server: true,
            days: 1,
            ..Profile::default()
        })
        .unwrap()
    };
    let (first, renewed) = (issue(), issue());
    assert_ne!(first.sha256, renewed.sha256);
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    std::fs::write(&cert_path, &first.cert_pem).unwrap();
    std::fs::write(&key_path, first.key_pem.as_deref().unwrap()).unwrap();
    let resolver = dhonomos_pki::tls::CertResolver::from_files(&cert_path, &key_path).unwrap();
    let _watcher = resolver.watch("test", Duration::from_millis(50));
    let acceptor = tls_acceptor_with(resolver, None, false).unwrap();
    let (tx, _inbound) = mpsc::channel(8);
    let ws = WsMtp::new(tx);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let srv = ws.clone();
    tokio::spawn(async move {
        srv.serve_tls(listener, acceptor, std::future::pending())
            .await
    });

    let presented = |conn: &tokio_tungstenite::WebSocketStream<
        tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    >| {
        let chain = conn.get_ref().get_ref().1.peer_certificates().unwrap();
        dhonomos_pki::fingerprint(&chain[0])
    };
    let mut open = connect(port, "os::before", client_config(&ca, None))
        .await
        .unwrap();
    assert_eq!(presented(&open), first.sha256);

    // Coarse file times -> keep renewal apart from first write.
    tokio::time::sleep(Duration::from_millis(50)).await;
    std::fs::write(&cert_path, &renewed.cert_pem).unwrap();
    std::fs::write(&key_path, renewed.key_pem.as_deref().unwrap()).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let conn = connect(port, "os::after", client_config(&ca, None))
            .await
            .unwrap();
        if presented(&conn) == renewed.sha256 {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "not reloaded");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    // Connection with old cert untouched.
    open.send(Message::binary(vec![1])).await.unwrap();
    assert_eq!(ws.connections(), 2);
}

/// Plain WebSocket server (no TLS), short keepalive.
async fn short_keepalive_server() -> (WsMtp, mpsc::Receiver<dhonomos_usp_mtp::Inbound>, u16) {
    let (tx, inbound) = mpsc::channel(8);
    let ws = WsMtp::new(tx).with_keepalive(Duration::from_millis(100), Duration::from_millis(400));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let router = ws.router();
    tokio::spawn(async move { axum::serve(listener, router).await });
    (ws, inbound, port)
}

async fn plain_connect(
    port: u16,
    eid: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let mut req = format!("ws://127.0.0.1:{port}/usp?eid={eid}")
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("Sec-WebSocket-Protocol", "v1.usp".parse().unwrap());
    tokio_tungstenite::connect_async(req).await.unwrap().0
}

/// `eid` = registry key, shown in logs.
/// Not valid as MQTT or STOMP Agent name -> 400 before upgrade.
#[tokio::test]
async fn invalid_endpoint_ids_are_refused() {
    let (ws, _inbound, port) = short_keepalive_server().await;
    let try_eid = |raw: String| async move {
        let mut req = format!("ws://127.0.0.1:{port}/usp?eid={raw}")
            .into_client_request()
            .unwrap();
        req.headers_mut()
            .insert("Sec-WebSocket-Protocol", "v1.usp".parse().unwrap());
        match tokio_tungstenite::connect_async(req).await {
            Ok(_) => Ok(()),
            Err(tungstenite::Error::Http(r)) => Err(r.status().as_u16()),
            Err(e) => panic!("{e}"),
        }
    };
    for bad in [
        "".to_owned(),
        "os::a%2Fb".to_owned(),
        "os::a%2Bb".to_owned(),
        "os::a%23".to_owned(),
        "os::a%20b".to_owned(),
        "os::a%0Ab".to_owned(),
        "os::a%00".to_owned(),
        "os::a%7F".to_owned(),
        "x".repeat(257),
    ] {
        assert_eq!(try_eid(bad.clone()).await, Err(400), "{bad:?}");
    }
    assert_eq!(ws.connections(), 0);
    // Usual EndpointID, also a long one, still connects.
    let _ok = (
        try_eid("oui:00AA00:serial-1".to_owned()).await.unwrap(),
        try_eid("x".repeat(256)).await.unwrap(),
    );
}

#[tokio::test]
async fn silent_agent_is_closed_after_the_idle_limit() {
    let (ws, mut inbound, port) = short_keepalive_server().await;
    // Connected, never polled again -> no Pong sent, nothing read.
    let _silent = plain_connect(port, "os::dead").await;
    let opened = tokio::time::timeout(Duration::from_secs(5), async {
        while ws.connections() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(opened.is_ok());
    let closed = tokio::time::timeout(Duration::from_secs(5), inbound.recv())
        .await
        .expect("the server closes a silent connection")
        .unwrap();
    assert!(closed.closed);
    assert_eq!(closed.reply_to.as_deref(), Some("ws:os::dead"));
    assert_eq!(ws.connections(), 0);
}

#[tokio::test]
async fn responsive_agent_outlives_the_idle_limit() {
    let (ws, mut inbound, port) = short_keepalive_server().await;
    let mut agent = plain_connect(port, "os::alive").await;
    // Polling the stream -> server pings answered automatically.
    let until = tokio::time::Instant::now() + Duration::from_millis(1500);
    while let Ok(m) =
        tokio::time::timeout_at(until, futures_util::StreamExt::next(&mut agent)).await
    {
        assert!(
            !matches!(m, None | Some(Ok(Message::Close(_)))),
            "closed early"
        );
    }
    assert_eq!(ws.connections(), 1);
    assert!(inbound.try_recv().is_err(), "no closed notice");
}

/// `ws://127.0.0.1:<port>/usp?eid=<eid>` (no TLS -> no client cert).
/// Err = HTTP status of refused upgrade.
async fn try_plain_connect(
    port: u16,
    eid: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    u16,
> {
    let mut req = format!("ws://127.0.0.1:{port}/usp?eid={eid}")
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("Sec-WebSocket-Protocol", "v1.usp".parse().unwrap());
    match tokio_tungstenite::connect_async(req).await {
        Ok((ws, _)) => Ok(ws),
        Err(tungstenite::Error::Http(r)) => Err(r.status().as_u16()),
        Err(e) => panic!("{e}"),
    }
}

/// EndpointID with client cert issued -> refused for connections without one:
/// wss without cert + plain `ws://`. Open connections stay.
#[tokio::test]
async fn wss_refuses_endpoint_ids_with_a_certificate_issued_when_none_is_presented() {
    let ca = Ca::generate("Test USP CA").unwrap();
    let server = ca
        .issue(&Profile {
            endpoint_id: "self::ctrl".into(),
            dns_names: vec!["localhost".into()],
            server: true,
            days: 1,
            ..Profile::default()
        })
        .unwrap();
    let acceptor = tls_acceptor(
        &server.cert_pem,
        server.key_pem.as_deref().unwrap(),
        Some(ca.cert_pem()),
        false,
    )
    .unwrap();
    let (tx, _inbound) = mpsc::channel(8);
    let ws = WsMtp::new(tx);
    let tls_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tls_port = tls_listener.local_addr().unwrap().port();
    let srv = ws.clone();
    tokio::spawn(async move {
        srv.serve_tls(tls_listener, acceptor, std::future::pending())
            .await
    });
    let plain_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain_port = plain_listener.local_addr().unwrap().port();
    let router = ws.router();
    tokio::spawn(async move { axum::serve(plain_listener, router).await });
    // Same fan-out the Controller uses for all MTPs.
    let multi = MultiMtp {
        ws: Some(ws.clone()),
        ..MultiMtp::default()
    };
    let anonymous = || client_config(&ca, None);

    // Alice connected without cert before she gets one ...
    let _before = connect(tls_port, "os::alice", anonymous()).await.unwrap();
    let _before_plain = plain_connect(plain_port, "os::alice").await;
    wait_for_connections(&ws, 1).await;
    // ... issued now.
    multi.set_certificate_bound(["os::alice".to_owned()].into());
    assert_eq!(ws.connections(), 1, "her connection stays");

    // New connections without it -> refused, wss or plain.
    assert_eq!(
        connect(tls_port, "os::alice", anonymous())
            .await
            .err()
            .as_deref(),
        Some("http 403")
    );
    assert_eq!(
        try_plain_connect(plain_port, "os::alice").await.err(),
        Some(403)
    );
    // Other EndpointIDs not affected.
    let _bob = try_plain_connect(plain_port, "os::bob").await.unwrap();
    let _carol = connect(tls_port, "os::carol", anonymous()).await.unwrap();

    // With cert -> she is in. EndpointID released -> claims allowed again.
    let alice = agent_cert(&ca, "os::alice");
    let _proved = connect(tls_port, "os::alice", client_config(&ca, Some(&alice)))
        .await
        .unwrap();
    multi.set_certificate_bound(Default::default());
    let _dave = connect(tls_port, "os::dave", anonymous()).await.unwrap();
    // Alice's cert connection live -> claim still refused (409).
    wait_for_connections(&ws, 4).await;
    assert_eq!(
        connect(tls_port, "os::alice", anonymous())
            .await
            .err()
            .as_deref(),
        Some("http 409")
    );

    // Revocation reaches wss via same fan-out.
    assert_eq!(multi.set_revoked([alice.sha256.clone()].into()), 1);
    assert_eq!(
        connect(tls_port, "os::alice", client_config(&ca, Some(&alice)))
            .await
            .err()
            .as_deref(),
        Some("http 403")
    );
}
