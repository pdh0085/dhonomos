//! Real `dhonomos` binary: start + check that every listener answers.
#![allow(clippy::unwrap_used)]

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

const INFORM: &[u8] =
    include_bytes!("../../../crates/cwmp-codec/tests/corpus/genieacs-sim/01-Inform.xml");

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Minimal HTTP/1.1 exchange -> status code.
fn http(port: u16, method: &str, path: &str, body: &[u8]) -> Option<u16> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).ok()?;
    s.write_all(body).ok()?;
    let mut resp = String::new();
    let _ = s.read_to_string(&mut resp);
    resp.split_whitespace().nth(1)?.parse().ok()
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn all_listeners_answer() {
    let pg = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let db = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        pg.get_host_port_ipv4(5432).await.unwrap()
    );
    let (acs, api, files) = (free_port(), free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("dhonomos-smoke-{acs}"));
    let _server = Server(
        Command::new(env!("CARGO_BIN_EXE_dhonomos"))
            .args([
                "--database-url",
                &db,
                "--acs-plaintext",
                "--cpe-auth",
                "none",
                // No secrets key here; admin TOTP requirement (default) needs one.
                "--require-admin-totp",
                "false",
            ])
            .args(["--acs-listen", &format!("127.0.0.1:{acs}")])
            .args(["--api-listen", &format!("127.0.0.1:{api}")])
            .args(["--files-listen", &format!("127.0.0.1:{files}")])
            .arg("--files-dir")
            .arg(&dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    while http(api, "GET", "/healthz", b"") != Some(200) {
        assert!(Instant::now() < deadline, "API did not come up");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        http(acs, "POST", "/", INFORM),
        Some(200),
        "ACS answers an Inform"
    );
    assert_eq!(http(api, "GET", "/api/v1/devices", b""), Some(200));
    assert_eq!(http(api, "GET", "/metrics", b""), Some(200));
    let unsigned = format!("/files/{}/x.bin?d={}&e=0&s=00", uuid(), uuid());
    assert_eq!(
        http(files, "GET", &unsigned, b""),
        Some(403),
        "file server rejects unsigned links"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// One HTTPS GET to `127.0.0.1:port`, trust only `cert` -> status code.
async fn https_status(
    port: u16,
    cert: &rustls_pki_types::CertificateDer<'static>,
    path: &str,
) -> Option<u16> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).ok()?;
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .ok()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .ok()?;
    let mut tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
        .connect(
            rustls_pki_types::ServerName::try_from("localhost").ok()?,
            tcp,
        )
        .await
        .ok()?;
    tls.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .ok()?;
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp).await;
    String::from_utf8_lossy(&resp)
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

#[tokio::test]
async fn file_server_serves_https_from_certificate_files() {
    let pg = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let db = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        pg.get_host_port_ipv4(5432).await.unwrap()
    );
    let (acs, files) = (free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("dhonomos-smoke-tls-{acs}"));
    std::fs::create_dir_all(&dir).unwrap();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let (cert_path, key_path) = (dir.join("files-cert.pem"), dir.join("files-key.pem"));
    std::fs::write(&cert_path, ck.cert.pem()).unwrap();
    std::fs::write(&key_path, ck.signing_key.serialize_pem()).unwrap();
    let cert = rustls_pki_types::CertificateDer::from(ck.cert.der().to_vec());
    let _server = Server(
        Command::new(env!("CARGO_BIN_EXE_dhonomos"))
            .args([
                "--database-url",
                &db,
                "--role",
                "acs",
                "--acs-plaintext",
                "--cpe-auth",
                "none",
            ])
            .args(["--acs-listen", &format!("127.0.0.1:{acs}")])
            .args(["--files-listen", &format!("127.0.0.1:{files}")])
            .arg("--files-dir")
            .arg(&dir)
            .arg("--files-tls-cert")
            .arg(&cert_path)
            .arg("--files-tls-key")
            .arg(&key_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let unsigned = format!("/files/{}/x.bin?d={}&e=0&s=00", uuid(), uuid());
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = https_status(files, &cert, &unsigned).await {
            break status;
        }
        assert!(Instant::now() < deadline, "file server did not come up");
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(status, 403, "file server rejects unsigned links over HTTPS");
    assert_ne!(
        http(files, "GET", &unsigned, b""),
        Some(403),
        "plain HTTP is not served on the TLS port"
    );
    let _ = std::fs::remove_dir_all(dir);
}

fn uuid() -> &'static str {
    "01a10000-0000-7000-8000-000000000000"
}

/// One HTTP/1.1 request with JSON body -> status code.
fn http_json(port: u16, method: &str, path: &str, body: &str) -> Option<u16> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).ok()?;
    s.write_all(body.as_bytes()).ok()?;
    let mut resp = String::new();
    let _ = s.read_to_string(&mut resp);
    resp.split_whitespace().nth(1)?.parse().ok()
}

/// Server process on `db`, API on `api`, log -> `log`.
fn server(db: &str, role: &str, api: u16, log: &std::path::Path) -> Server {
    server_with(db, role, api, log, &[])
}

/// [`server`] + `extra` arguments.
fn server_with(
    db: &str,
    role: &str,
    api: u16,
    log: &std::path::Path,
    extra: &[&std::ffi::OsStr],
) -> Server {
    let (acs, files) = (free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("dhonomos-rts-{api}"));
    Server(
        Command::new(env!("CARGO_BIN_EXE_dhonomos"))
            .args(["--database-url", db, "--role", role])
            .args(["--acs-plaintext", "--cpe-auth", "none"])
            .args(["--require-admin-totp", "false"])
            .args(["--acs-listen", &format!("127.0.0.1:{acs}")])
            .args(["--api-listen", &format!("127.0.0.1:{api}")])
            .args(["--files-listen", &format!("127.0.0.1:{files}")])
            .arg("--files-dir")
            .arg(&dir)
            .args(extra)
            .env("RUST_LOG", "info")
            .env("NO_COLOR", "1")
            .stdout(std::fs::File::create(log).unwrap())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

async fn up(api: u16, log: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while http(api, "GET", "/healthz", b"") != Some(200) {
        assert!(
            Instant::now() < deadline,
            "API on {api} did not come up: {}",
            std::fs::read_to_string(log).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// 6 requests in a row to `api` -> rate limit hit (429)?
fn limited(api: u16) -> bool {
    (0..6).any(|_| http(api, "GET", "/api/v1/devices", b"") == Some(429))
}

/// Runtime setting changed via API of one process -> other process within the poll interval.
/// Stored value refused by a process -> process still starts.
#[tokio::test]
async fn runtime_settings_reach_every_process() {
    let pg = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let db = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        pg.get_host_port_ipv4(5432).await.unwrap()
    );
    let store = dhonomos_store::Store::connect(&db, 2).await.unwrap();
    store.migrate().await.unwrap();
    store
        .set_runtime_setting(
            dhonomos_store::DEFAULT_TENANT,
            "session_hours",
            &serde_json::json!("soon"),
            None,
        )
        .await
        .unwrap();
    let logs = std::env::temp_dir().join(format!("dhonomos-rts-logs-{}", free_port()));
    std::fs::create_dir_all(&logs).unwrap();
    let (api_a, api_b) = (free_port(), free_port());
    let _a = server(&db, "all", api_a, &logs.join("a.log"));
    let _b = server(&db, "api", api_b, &logs.join("b.log"));
    up(api_a, &logs.join("a.log")).await;
    up(api_b, &logs.join("b.log")).await;
    let log_b = std::fs::read_to_string(logs.join("b.log")).unwrap();
    assert!(
        log_b.contains("stored runtime setting ignored") && log_b.contains("session_hours"),
        "{log_b}"
    );

    assert!(!limited(api_b), "the default limit (50/s) is far away");
    assert_eq!(
        http_json(
            api_a,
            "PUT",
            "/api/v1/settings/server/api_rate_limit",
            r#"{"value":"1"}"#
        ),
        Some(200)
    );
    // Applied at once in the changing process ...
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(limited(api_a));
    // ... + within poll interval (5 s) in all others.
    let deadline = Instant::now() + Duration::from_secs(8);
    while !limited(api_b) {
        assert!(Instant::now() < deadline, "process b did not follow");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let _ = std::fs::remove_dir_all(logs);
}

/// One HTTP/1.1 GET -> status code + body.
fn http_get(port: u16, path: &str) -> Option<(u16, String)> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let head = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    s.write_all(head.as_bytes()).ok()?;
    let mut resp = String::new();
    let _ = s.read_to_string(&mut resp);
    let status = resp.split_whitespace().nth(1)?.parse().ok()?;
    let body = resp.split_once("\r\n\r\n")?.1.to_owned();
    Some((status, body))
}

/// Wait until `log` contains `text` (max 20 s).
async fn logged(log: &std::path::Path, text: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let now = std::fs::read_to_string(log).unwrap_or_default();
        if now.contains(text) {
            return;
        }
        assert!(Instant::now() < deadline, "{text:?} not logged: {now}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// No `--alarms` -> alarm engine uses rules stored from the web.
/// Stored rules fail to load -> logged, start with no rules.
/// Same for alarm e-mail settings that do not fit -> start with e-mail off.
/// With the file -> its rules, whatever is stored.
#[tokio::test]
async fn alarm_rules_come_from_the_database_or_the_file() {
    let pg = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let db = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        pg.get_host_port_ipv4(5432).await.unwrap()
    );
    let store = dhonomos_store::Store::connect(&db, 2).await.unwrap();
    store.migrate().await.unwrap();
    store
        .set_alarm_rule_set(
            dhonomos_store::DEFAULT_TENANT,
            "alarms: [{ name: bad, severity: fatal, when: { offline_minutes: 5 } }]",
            None,
        )
        .await
        .unwrap();
    let logs = std::env::temp_dir().join(format!("dhonomos-alarm-logs-{}", free_port()));
    std::fs::create_dir_all(&logs).unwrap();

    let api = free_port();
    let log = logs.join("db.log");
    let a = server(&db, "all", api, &log);
    up(api, &log).await;
    logged(&log, "the stored alarm rules are invalid").await;
    logged(&log, "alarm engine active").await;
    let (status, body) = http_get(api, "/api/v1/settings/alarm-rules").unwrap();
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        (&v["source"], &v["editable"]),
        (&"web".into(), &true.into())
    );
    assert_eq!(v["rules"]["alarms"], serde_json::json!([]));
    drop(a);

    // E-mail settings that do not fit (no recipients) -> no stop without --alarms.
    let api = free_port();
    let log = logs.join("mail.log");
    let m = server_with(
        &db,
        "all",
        api,
        &log,
        &[
            "--smtp-host".as_ref(),
            "mail.example".as_ref(),
            "--alarm-email-from".as_ref(),
            "rms@example.org".as_ref(),
        ],
    );
    up(api, &log).await;
    logged(&log, "alarm e-mail is off").await;
    logged(&log, "alarm engine active").await;
    assert!(
        !std::fs::read_to_string(&log)
            .unwrap()
            .contains("alarm e-mails enabled")
    );
    drop(m);

    let file = logs.join("alarms.yaml");
    std::fs::write(
        &file,
        "alarms: [{ name: from-file, severity: minor, when: { offline_minutes: 9 } }]\n",
    )
    .unwrap();
    let api = free_port();
    let log = logs.join("file.log");
    let _b = server_with(
        &db,
        "all",
        api,
        &log,
        &["--alarms".as_ref(), file.as_os_str()],
    );
    up(api, &log).await;
    let (status, body) = http_get(api, "/api/v1/settings/alarm-rules").unwrap();
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        (&v["source"], &v["editable"]),
        (&"file".into(), &false.into())
    );
    assert_eq!(v["rules"]["alarms"][0]["name"], "from-file");
    let _ = std::fs::remove_dir_all(logs);
}
