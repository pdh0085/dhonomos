//! Small SMTP client for alarm e-mails (NB-07).
//! Implicit TLS (465), STARTTLS (587) or plain relay (25); AUTH PLAIN/LOGIN.
//! One UTF-8 text message per call.
//! TLS trust = system store + optional extra CA file (internal relays).
//! Credentials never sent over an unencrypted connection.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use time::OffsetDateTime;
use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncWrite, AsyncWriteExt as _, BufReader};
use tokio::net::TcpStream;

const TIMEOUT: Duration = Duration::from_secs(20);

/// Connection protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// TLS from 1st byte (usually 465).
    Tls,
    /// Plain -> STARTTLS upgrade (usually 587). Not offered -> refused.
    StartTls,
    /// No encryption (relay on trusted network, port 25) -> no auth.
    None,
}

/// Where + how to send.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// Server name, also checked against its certificate.
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub to: Vec<String>,
    /// Extra trusted CA certs (PEM) -> relays with a private CA.
    pub ca_pem: Option<String>,
}

fn tls_config(ca_pem: Option<&str>) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if let Some(pem) = ca_pem {
        use rustls_pki_types::pem::PemObject as _;
        for cert in rustls_pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert = cert.map_err(|e| format!("CA file: {e}"))?;
            roots.add(cert).map_err(|e| format!("CA file: {e}"))?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Read one reply -> (code, text lines). Multi-line `NNN-` replies joined.
async fn reply<S: AsyncRead + Unpin>(r: &mut BufReader<S>) -> Result<(u16, Vec<String>), String> {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        let n = r.read_line(&mut line).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("the server closed the connection".into());
        }
        let line = line.trim_end().to_owned();
        let code = line
            .get(..3)
            .and_then(|c| c.parse::<u16>().ok())
            .ok_or_else(|| format!("unexpected reply {line:?}"))?;
        let last = line.as_bytes().get(3) != Some(&b'-');
        lines.push(line.get(4..).unwrap_or_default().to_owned());
        if last {
            return Ok((code, lines));
        }
    }
}

async fn command<S: AsyncRead + AsyncWrite + Unpin>(
    r: &mut BufReader<S>,
    line: &str,
    expect: &[u16],
) -> Result<Vec<String>, String> {
    r.get_mut()
        .write_all(format!("{line}\r\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let (code, text) = reply(r).await?;
    if !expect.contains(&code) {
        // Never echo credentials in errors.
        let shown = if line.starts_with("AUTH") {
            "AUTH"
        } else {
            line
        };
        return Err(format!("{shown}: {code} {}", text.join(" ")));
    }
    Ok(text)
}

/// Non-ASCII or CR/LF -> `=?UTF-8?B?...?=`, CR/LF -> space (no header injection).
fn encode_header(v: &str) -> String {
    if v.is_ascii() && !v.contains(['\r', '\n']) {
        v.to_owned()
    } else {
        format!("=?UTF-8?B?{}?=", B64.encode(v.replace(['\r', '\n'], " ")))
    }
}

/// Message = headers + base64 UTF-8 body -> no dot-stuffing needed.
fn message(cfg: &SmtpConfig, subject: &str, body: &str, now: OffsetDateTime) -> String {
    let date = now
        .format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_default();
    let encoded = B64.encode(body.as_bytes());
    let mut wrapped = String::new();
    for chunk in encoded.as_bytes().chunks(76) {
        wrapped.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        wrapped.push_str("\r\n");
    }
    let domain = cfg.from.rsplit('@').next().unwrap_or("dhonomos");
    format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nDate: {date}\r\nMessage-ID: <{}@{domain}>\r\n\
         MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: base64\r\nAuto-Submitted: auto-generated\r\n\r\n{wrapped}",
        cfg.from,
        cfg.to.join(", "),
        encode_header(subject),
        uuid::Uuid::now_v7().simple(),
    )
}

/// EHLO, AUTH, envelope + message on an open (encrypted if needed) connection.
/// `greeted` -> 220 greeting already read.
async fn deliver<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    cfg: &SmtpConfig,
    encrypted: bool,
    greeted: bool,
    subject: &str,
    body: &str,
) -> Result<(), String> {
    let mut r = BufReader::new(stream);
    if !greeted {
        let (code, text) = reply(&mut r).await?;
        if code != 220 {
            return Err(format!("greeting: {code} {}", text.join(" ")));
        }
    }
    let caps = command(&mut r, "EHLO dhonomos", &[250]).await?;
    if let (Some(user), Some(pass)) = (&cfg.username, &cfg.password) {
        if !encrypted {
            return Err("refusing to send credentials without TLS".into());
        }
        let auth = caps
            .iter()
            .find(|c| c.to_ascii_uppercase().starts_with("AUTH"))
            .map(|c| c.to_ascii_uppercase())
            .unwrap_or_default();
        if auth.contains("PLAIN") {
            let token = B64.encode(format!("\0{user}\0{pass}"));
            command(&mut r, &format!("AUTH PLAIN {token}"), &[235]).await?;
        } else {
            command(&mut r, "AUTH LOGIN", &[334]).await?;
            command(&mut r, &format!("AUTH {}", B64.encode(user)), &[334])
                .await
                .map_err(|_| "AUTH: username rejected".to_owned())?;
            command(&mut r, &format!("AUTH {}", B64.encode(pass)), &[235])
                .await
                .map_err(|_| "AUTH: authentication failed".to_owned())?;
        }
    }
    command(&mut r, &format!("MAIL FROM:<{}>", cfg.from), &[250]).await?;
    for to in &cfg.to {
        command(&mut r, &format!("RCPT TO:<{to}>"), &[250, 251]).await?;
    }
    command(&mut r, "DATA", &[354]).await?;
    let msg = message(cfg, subject, body, OffsetDateTime::now_utc());
    r.get_mut()
        .write_all(format!("{msg}.\r\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let (code, text) = reply(&mut r).await?;
    if code != 250 {
        return Err(format!("message: {code} {}", text.join(" ")));
    }
    let _ = command(&mut r, "QUIT", &[221]).await;
    Ok(())
}

async fn send_inner(cfg: &SmtpConfig, subject: &str, body: &str) -> Result<(), String> {
    let tcp = TcpStream::connect((cfg.host.as_str(), cfg.port))
        .await
        .map_err(|e| format!("connecting to {}:{}: {e}", cfg.host, cfg.port))?;
    let server_name = rustls::pki_types::ServerName::try_from(cfg.host.clone())
        .map_err(|e| format!("server name {:?}: {e}", cfg.host))?;
    match cfg.security {
        Security::None => deliver(tcp, cfg, false, false, subject, body).await,
        Security::Tls => {
            let connector = tokio_rustls::TlsConnector::from(tls_config(cfg.ca_pem.as_deref())?);
            let tls = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| format!("TLS: {e}"))?;
            deliver(tls, cfg, true, false, subject, body).await
        }
        Security::StartTls => {
            let mut r = BufReader::new(tcp);
            let (code, text) = reply(&mut r).await?;
            if code != 220 {
                return Err(format!("greeting: {code} {}", text.join(" ")));
            }
            let caps = command(&mut r, "EHLO dhonomos", &[250]).await?;
            if !caps.iter().any(|c| c.eq_ignore_ascii_case("STARTTLS")) {
                return Err("the server does not offer STARTTLS".into());
            }
            command(&mut r, "STARTTLS", &[220]).await?;
            let connector = tokio_rustls::TlsConnector::from(tls_config(cfg.ca_pem.as_deref())?);
            let tls = connector
                .connect(server_name, r.into_inner())
                .await
                .map_err(|e| format!("TLS: {e}"))?;
            // After STARTTLS: new EHLO, no new greeting.
            deliver(tls, cfg, true, true, subject, body).await
        }
    }
}

/// Send one message to all recipients.
pub async fn send(cfg: &SmtpConfig, subject: &str, body: &str) -> Result<(), String> {
    tokio::time::timeout(TIMEOUT, send_inner(cfg, subject, body))
        .await
        .map_err(|_| "timed out".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(port: u16, security: Security) -> SmtpConfig {
        SmtpConfig {
            host: "localhost".into(),
            port,
            security,
            username: None,
            password: None,
            from: "dhonomos@isp.example".into(),
            to: vec!["noc@isp.example".into(), "oncall@isp.example".into()],
            ca_pem: None,
        }
    }

    /// Scripted SMTP server: answer each command, record the session.
    async fn fake_server<S>(stream: S, starttls: bool, greet: bool) -> (Vec<String>, String)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut r = BufReader::new(stream);
        let mut seen = Vec::new();
        let mut data = String::new();
        if greet {
            r.get_mut()
                .write_all(b"220 mail.test ESMTP\r\n")
                .await
                .unwrap_or(());
        }
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                break;
            }
            let cmd = line.trim_end().to_owned();
            seen.push(cmd.clone());
            let answer: &[u8] = if cmd.starts_with("EHLO") {
                if starttls {
                    b"250-mail.test\r\n250-AUTH PLAIN LOGIN\r\n250 STARTTLS\r\n"
                } else {
                    b"250-mail.test\r\n250 AUTH PLAIN\r\n"
                }
            } else if cmd == "DATA" {
                r.get_mut().write_all(b"354 go\r\n").await.unwrap_or(());
                loop {
                    let mut l = String::new();
                    if r.read_line(&mut l).await.unwrap_or(0) == 0 || l == ".\r\n" {
                        break;
                    }
                    data.push_str(&l);
                }
                b"250 queued\r\n"
            } else if cmd == "QUIT" {
                r.get_mut().write_all(b"221 bye\r\n").await.unwrap_or(());
                break;
            } else if cmd == "STARTTLS" {
                r.get_mut()
                    .write_all(b"220 go ahead\r\n")
                    .await
                    .unwrap_or(());
                break;
            } else if cmd.starts_with("AUTH") {
                b"235 ok\r\n"
            } else {
                b"250 ok\r\n"
            };
            r.get_mut().write_all(answer).await.unwrap_or(());
        }
        (seen, data)
    }

    #[tokio::test]
    async fn plain_relay_delivers_a_utf8_message() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
            fake_server(s, false, true).await
        });
        send(
            &config(port, Security::None),
            "[major] offline — Box 서울",
            "No contact for 61 minutes\n.leading dot",
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        let (seen, data) = server.await.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            seen,
            [
                "EHLO dhonomos",
                "MAIL FROM:<dhonomos@isp.example>",
                "RCPT TO:<noc@isp.example>",
                "RCPT TO:<oncall@isp.example>",
                "DATA",
                "QUIT"
            ]
        );
        assert!(data.contains("Subject: =?UTF-8?B?"));
        assert!(data.contains("To: noc@isp.example, oncall@isp.example\r\n"));
        let body: String = data
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or_default()
            .split("\r\n")
            .collect();
        let decoded = String::from_utf8(B64.decode(body).unwrap_or_default()).unwrap_or_default();
        assert_eq!(decoded, "No contact for 61 minutes\n.leading dot");
    }

    #[tokio::test]
    async fn credentials_need_tls() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        tokio::spawn(async move {
            if let Ok((s, _)) = listener.accept().await {
                fake_server(s, false, true).await;
            }
        });
        let cfg = SmtpConfig {
            username: Some("u".into()),
            password: Some("secret".into()),
            ..config(port, Security::None)
        };
        let err = send(&cfg, "s", "b").await.err().unwrap_or_default();
        assert!(err.contains("without TLS"), "{err}");
    }

    #[tokio::test]
    async fn starttls_upgrades_and_authenticates() {
        // Server cert from own CA, trusted via `ca_pem`.
        let ca = dhonomos_pki::Ca::generate("Test CA").unwrap_or_else(|e| panic!("{e}"));
        let issued = ca
            .issue(&dhonomos_pki::Profile {
                endpoint_id: "smtp".into(),
                dns_names: vec!["localhost".into()],
                ip_addresses: Vec::new(),
                server: true,
                days: 1,
            })
            .unwrap_or_else(|e| panic!("{e}"));
        let acceptor = dhonomos_usp_mtp::tls_acceptor(
            &issued.cert_pem,
            issued.key_pem.as_deref().unwrap_or_default(),
            None,
            false,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
            let (before, _) = fake_server(&mut s, true, true).await;
            let tls = acceptor.accept(s).await.unwrap_or_else(|e| panic!("{e}"));
            let (after, data) = fake_server(tls, true, false).await;
            (before, after, data)
        });
        let cfg = SmtpConfig {
            username: Some("noc".into()),
            password: Some("pw".into()),
            ca_pem: Some(ca.cert_pem().to_owned()),
            ..config(port, Security::StartTls)
        };
        send(&cfg, "subject", "body")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let (before, after, data) = server.await.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(before, ["EHLO dhonomos", "STARTTLS"]);
        assert_eq!(after[0], "EHLO dhonomos");
        assert_eq!(after[1], format!("AUTH PLAIN {}", B64.encode("\0noc\0pw")));
        assert!(data.contains("Subject: subject\r\n"));
    }

    #[test]
    fn headers_are_encoded_only_when_needed() {
        assert_eq!(encode_header("plain"), "plain");
        assert!(encode_header("é").starts_with("=?UTF-8?B?"));
        assert!(
            encode_header("a\r\nBcc: x").starts_with("=?UTF-8?B?"),
            "no header injection"
        );
    }
}
