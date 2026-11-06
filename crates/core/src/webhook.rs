//! Outgoing webhooks: JSON POST over HTTP or HTTPS (system trust store).
//! Secret set -> signed: `X-Dhonomos-Signature: sha256=<hex HMAC-SHA256(secret, body)>`.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use http_body_util::{BodyExt as _, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use sha2::Sha256;
use tokio::net::TcpStream;

const TIMEOUT: Duration = Duration::from_secs(10);

/// Signature header value of `body`.
pub fn signature(secret: &str, body: &str) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes())
        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    mac.update(body.as_bytes());
    let hex: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256={hex}")
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(cert);
            }
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map(|b| b.with_root_certificates(roots).with_no_client_auth());
            Arc::new(config.unwrap_or_else(|_| unreachable!("ring supports the default versions")))
        })
        .clone()
}

/// Max response body read.
const MAX_RESPONSE: usize = 4 << 20;

async fn send<S>(
    io: S,
    req: Request<Full<Bytes>>,
) -> Result<(u16, Vec<(String, String)>, Bytes), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| Some((k.as_str().to_owned(), v.to_str().ok()?.to_owned())))
        .collect();
    let body = http_body_util::Limited::new(resp.into_body(), MAX_RESPONSE)
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    Ok((status, headers, body))
}

/// One HTTP(S) request (system trust store for HTTPS) -> status, headers, body (max 4 MiB).
/// Users: webhooks, OpenTelemetry exporter, OIDC.
pub async fn exchange(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Bytes,
) -> Result<(u16, Vec<(String, String)>, Bytes), String> {
    let uri: hyper::Uri = url.parse().map_err(|e| format!("bad URL: {e}"))?;
    let https = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => return Err("URL must be http or https".into()),
    };
    let host = uri.host().ok_or("URL has no host")?.to_owned();
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    let mut req = Request::builder()
        .method(method)
        .uri(uri.path_and_query().map_or("/", |p| p.as_str()))
        .header(
            "host",
            uri.authority().map_or(host.as_str(), |a| a.as_str()),
        )
        .header("user-agent", "Dhonomos");
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let req = req.body(Full::new(body)).map_err(|e| e.to_string())?;
    let work = async {
        let tcp = TcpStream::connect((host.trim_start_matches('[').trim_end_matches(']'), port))
            .await
            .map_err(|e| e.to_string())?;
        if https {
            let name = rustls_pki_types::ServerName::try_from(
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned(),
            )
            .map_err(|e| e.to_string())?;
            let tls = tokio_rustls::TlsConnector::from(tls_config())
                .connect(name, tcp)
                .await
                .map_err(|e| e.to_string())?;
            send(tls, req).await
        } else {
            send(tcp, req).await
        }
    };
    tokio::time::timeout(TIMEOUT, work)
        .await
        .map_err(|_| "timed out".to_owned())?
}

/// `url` -> scheme, host, port only, for logs.
/// Path + query of a webhook URL often hold its token (Slack, Teams, ...), user info a password.
pub fn redact_url(url: &str) -> String {
    let Ok(uri) = url.parse::<hyper::Uri>() else {
        return "<invalid URL>".into();
    };
    match (uri.scheme_str(), uri.host()) {
        (Some(scheme), Some(host)) => match uri.port_u16() {
            Some(port) => format!("{scheme}://{host}:{port}"),
            None => format!("{scheme}://{host}"),
        },
        _ => "<invalid URL>".into(),
    }
}

/// POST `body` (JSON) to `url`. Any 2xx = success.
pub async fn post(url: &str, body: &str, secret: &str) -> Result<(), String> {
    let mut headers = vec![("content-type".to_owned(), "application/json".to_owned())];
    if !secret.is_empty() {
        headers.push(("x-dhonomos-signature".to_owned(), signature(secret, body)));
    }
    match exchange("POST", url, &headers, Bytes::from(body.to_owned())).await? {
        (s, _, _) if (200..300).contains(&s) => Ok(()),
        (s, _, _) => Err(format!("HTTP {s}")),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn signature_format() {
        let s = super::signature("k", "{}");
        assert!(s.starts_with("sha256=") && s.len() == 7 + 64);
    }

    #[test]
    fn logged_urls_keep_scheme_host_and_port_only() {
        use super::redact_url;
        assert_eq!(
            redact_url("https://hooks.example.com/services/T000/B000/XXXXSECRET"),
            "https://hooks.example.com"
        );
        assert_eq!(
            redact_url("http://siem.example.net:8088/collector?token=abc#frag"),
            "http://siem.example.net:8088"
        );
        assert_eq!(
            redact_url("https://user:pass@example.com:8443/hook"),
            "https://example.com:8443"
        );
        assert_eq!(
            redact_url("http://[2001:db8::1]:9000/x"),
            "http://[2001:db8::1]:9000"
        );
        for bad in ["", "not a url", "/just/a/path?token=abc", "ftp"] {
            let shown = redact_url(bad);
            assert_eq!(shown, "<invalid URL>", "{bad:?}");
        }
    }
}
