//! HTTP(S) client -> server hub routes (`/api/v1/wg-hub/...`).
//! 1 connection per request, HTTP/1.1, trust = system store + `--ca-file`.

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use bytes::Bytes;
use dhonomos_wireguard::{HubState, PublicKeyReport, StatusAccepted, StatusReport};
use http_body_util::{BodyExt as _, Full};
use hyper::{Method, Request, StatusCode, header};
use hyper_util::rt::TokioIo;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::config::Server;

/// Timeout of a request other than the long-poll. Long-poll: its wait + this.
const TIMEOUT: Duration = Duration::from_secs(15);
/// Max response body read.
const MAX_RESPONSE: usize = 16 << 20;
/// Max chars of a server error message in the log.
const MAX_ERROR_TEXT: usize = 200;
/// Max bytes of a plain text error body in the log; longer -> left out.
const MAX_PLAIN_BODY: usize = 200;

/// Why a request failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClientError {
    /// No connection, TLS failure or broken response.
    Connect(String),
    Timeout,
    /// 401: server refuses the token.
    Unauthorized,
    /// Other unexpected status + text after the code in the message ([`status_detail`]).
    Status(u16, String),
    /// 2xx answer with an unexpected body.
    BadResponse(String),
}

impl ClientError {
    /// Error kind -> retry loop logs each kind once.
    pub(crate) fn kind(&self) -> String {
        match self {
            Self::Connect(_) => "connect".into(),
            Self::Timeout => "timeout".into(),
            Self::Unauthorized => "unauthorized".into(),
            Self::Status(s, _) => format!("status {s}"),
            Self::BadResponse(_) => "bad response".into(),
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "cannot reach the server: {e}"),
            Self::Timeout => f.write_str("the server did not answer in time"),
            Self::Unauthorized => f.write_str(
                "the server rejected the hub token (401): issue a new one and put it in the token file",
            ),
            Self::Status(s, detail) => write!(f, "the server answered {s}{detail}"),
            Self::BadResponse(e) => write!(f, "the server's answer is not understood: {e}"),
        }
    }
}

/// Answer of the state request.
#[derive(Debug)]
pub(crate) enum StateAnswer {
    /// (New) state + its `ETag`.
    Changed { state: HubState, etag: String },
    /// 304: no change while waiting.
    Unchanged,
}

/// Holds the token; `Debug` must not show it.
pub(crate) struct Client {
    server: Server,
    token: Zeroizing<String>,
    tls: Arc<rustls::ClientConfig>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("server", &self.server.display())
            .field("token", &"<redacted>")
            .finish()
    }
}

/// TLS client config: system roots + certificates in `ca_file`.
fn tls_config(ca_file: Option<&Path>) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if let Some(path) = ca_file {
        let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let mut added = 0;
        for cert in CertificateDer::pem_slice_iter(&pem) {
            let cert = cert.with_context(|| format!("reading {}", path.display()))?;
            roots
                .add(cert)
                .with_context(|| format!("a certificate in {}", path.display()))?;
            added += 1;
        }
        if added == 0 {
            anyhow::bail!("{} holds no PEM certificate", path.display());
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("TLS versions")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

async fn send<S>(
    io: S,
    req: Request<Full<Bytes>>,
) -> Result<(StatusCode, Option<String>, Bytes), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| e.to_string())?;
    let conn = tokio::spawn(conn);
    let result = async {
        let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
        let status = resp.status();
        let etag = resp
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = http_body_util::Limited::new(resp.into_body(), MAX_RESPONSE)
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .to_bytes();
        Ok((status, etag, body))
    }
    .await;
    conn.abort();
    result
}

/// Text after the status code in the message of an error answer.
///
/// Dhonomos error body (`{"error": "..."}`) -> `: <error>`.
/// Else ` <reason>`, also `: <body>` if body = short plain text.
/// HTML pages (e.g. of a reverse proxy) + long bodies -> left out.
fn status_detail(status: StatusCode, body: &[u8]) -> String {
    let api_error = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
        .map(|e| {
            e.trim()
                .chars()
                .filter(|c| !c.is_control())
                .take(MAX_ERROR_TEXT)
                .collect::<String>()
        })
        .filter(|e| !e.is_empty());
    if let Some(e) = api_error {
        return format!(": {e}");
    }
    let mut detail = status
        .canonical_reason()
        .map(|r| format!(" {r}"))
        .unwrap_or_default();
    let plain = (body.len() <= MAX_PLAIN_BODY)
        .then(|| std::str::from_utf8(body).ok())
        .flatten()
        .filter(|t| !t.contains('<'))
        .map(|t| {
            t.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .filter(|c| !c.is_control())
                .collect::<String>()
        })
        .filter(|t| !t.is_empty());
    if let Some(t) = plain {
        detail.push_str(": ");
        detail.push_str(&t);
    }
    detail
}

impl Client {
    pub(crate) fn new(
        server: Server,
        token: Zeroizing<String>,
        ca_file: Option<&Path>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            server,
            token,
            tls: tls_config(ca_file)?,
        })
    }

    /// One request. `path_and_query` = part after `/api/v1`.
    async fn exchange(
        &self,
        method: Method,
        path_and_query: &str,
        if_none_match: Option<&str>,
        body: Option<Vec<u8>>,
        timeout: Duration,
    ) -> Result<(StatusCode, Option<String>, Bytes), ClientError> {
        let s = &self.server;
        let mut req = Request::builder()
            .method(method)
            .uri(format!("{}/api/v1{path_and_query}", s.path))
            .header(header::HOST, s.authority.as_str())
            .header(
                header::USER_AGENT,
                concat!("dhonomos-wg-hub/", env!("CARGO_PKG_VERSION")),
            )
            .header(header::ACCEPT, "application/json")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", self.token.as_str()),
            );
        if let Some(tag) = if_none_match {
            req = req.header(header::IF_NONE_MATCH, tag);
        }
        let body = match body {
            Some(b) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Bytes::from(b)
            }
            None => Bytes::new(),
        };
        let req = req
            .body(Full::new(body))
            .map_err(|e| ClientError::Connect(format!("building the request: {e}")))?;
        let work = async {
            let tcp = TcpStream::connect((s.host.as_str(), s.port))
                .await
                .map_err(|e| e.to_string())?;
            if s.https {
                let name = ServerName::try_from(s.host.clone()).map_err(|e| e.to_string())?;
                let tls = tokio_rustls::TlsConnector::from(self.tls.clone())
                    .connect(name, tcp)
                    .await
                    .map_err(|e| e.to_string())?;
                send(tls, req).await
            } else {
                send(tcp, req).await
            }
        };
        let (status, etag, body) = tokio::time::timeout(timeout, work)
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(ClientError::Connect)?;
        if status == StatusCode::UNAUTHORIZED {
            return Err(ClientError::Unauthorized);
        }
        Ok((status, etag, body))
    }

    /// `GET /wg-hub/state`. With `etag` -> server holds it up to `wait` s, until a state change.
    pub(crate) async fn get_state(
        &self,
        wait: u64,
        etag: Option<&str>,
    ) -> Result<StateAnswer, ClientError> {
        let (status, tag, body) = self
            .exchange(
                Method::GET,
                &format!("/wg-hub/state?wait={wait}"),
                etag,
                None,
                TIMEOUT + Duration::from_secs(wait),
            )
            .await?;
        match status {
            StatusCode::OK => {
                let state: HubState = serde_json::from_slice(&body)
                    .map_err(|e| ClientError::BadResponse(e.to_string()))?;
                let etag = tag.unwrap_or_else(|| format!("\"r{}\"", state.revision));
                Ok(StateAnswer::Changed { state, etag })
            }
            StatusCode::NOT_MODIFIED if etag.is_some() => Ok(StateAnswer::Unchanged),
            s => Err(ClientError::Status(s.as_u16(), status_detail(s, &body))),
        }
    }

    /// `PUT /wg-hub/public-key`.
    pub(crate) async fn put_public_key(&self, public_key: &str) -> Result<(), ClientError> {
        let body = serde_json::to_vec(&PublicKeyReport {
            public_key: public_key.to_owned(),
        })
        .map_err(|e| ClientError::BadResponse(e.to_string()))?;
        let (status, _, body) = self
            .exchange(Method::PUT, "/wg-hub/public-key", None, Some(body), TIMEOUT)
            .await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(ClientError::Status(
                status.as_u16(),
                status_detail(status, &body),
            ))
        }
    }

    /// `POST /wg-hub/status`.
    pub(crate) async fn post_status(
        &self,
        report: &StatusReport,
    ) -> Result<StatusAccepted, ClientError> {
        let body =
            serde_json::to_vec(report).map_err(|e| ClientError::BadResponse(e.to_string()))?;
        let (status, _, body) = self
            .exchange(Method::POST, "/wg-hub/status", None, Some(body), TIMEOUT)
            .await?;
        if status != StatusCode::OK {
            return Err(ClientError::Status(
                status.as_u16(),
                status_detail(status, &body),
            ));
        }
        serde_json::from_slice(&body).map_err(|e| ClientError::BadResponse(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// Log message of an error answer (`code`, `body`).
    fn message(code: u16, body: &[u8]) -> String {
        let status = StatusCode::from_u16(code).unwrap();
        ClientError::Status(code, status_detail(status, body)).to_string()
    }

    #[test]
    fn a_json_error_body_gives_its_error_text() {
        assert_eq!(
            message(400, br#"{"error":"wait must be between 0 and 60"}"#),
            "the server answered 400: wait must be between 0 and 60"
        );
    }

    #[test]
    fn a_long_json_error_is_cut() {
        let body = format!(r#"{{"error":"{}"}}"#, "x".repeat(1000));
        let shown = message(422, body.as_bytes());
        assert_eq!(
            shown,
            format!("the server answered 422: {}", "x".repeat(MAX_ERROR_TEXT))
        );
    }

    #[test]
    fn an_html_error_page_is_left_out() {
        let body = b"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n\
<title>503 Service Unavailable</title>\n</head><body>\n<h1>Service Unavailable</h1>\n\
<p>The server is temporarily unable to service your\nrequest due to maintenance downtime \
or capacity\nproblems. Please try again later.</p>\n</body></html>\n";
        assert_eq!(
            message(503, body),
            "the server answered 503 Service Unavailable"
        );
        // Short HTML body -> left out too.
        assert_eq!(
            message(502, b"<h1>x</h1>"),
            "the server answered 502 Bad Gateway"
        );
    }

    #[test]
    fn a_short_plain_text_body_is_shown() {
        assert_eq!(
            message(502, b"  upstream\n\t connect   error \r\n"),
            "the server answered 502 Bad Gateway: upstream connect error"
        );
        assert_eq!(
            message(503, b""),
            "the server answered 503 Service Unavailable"
        );
        assert_eq!(
            message(503, b" \n "),
            "the server answered 503 Service Unavailable"
        );
    }

    #[test]
    fn a_long_plain_text_body_is_left_out() {
        assert_eq!(
            message(500, &[b'x'; MAX_PLAIN_BODY + 1]),
            "the server answered 500 Internal Server Error"
        );
        assert_eq!(
            message(500, &[b'x'; MAX_PLAIN_BODY]),
            format!(
                "the server answered 500 Internal Server Error: {}",
                "x".repeat(MAX_PLAIN_BODY)
            )
        );
    }

    #[test]
    fn a_non_utf8_body_is_left_out() {
        assert_eq!(
            message(504, b"bad \xff\xfe gateway"),
            "the server answered 504 Gateway Timeout"
        );
    }

    #[test]
    fn the_kind_depends_on_the_status_code_only() {
        let a = ClientError::Status(503, status_detail(StatusCode::SERVICE_UNAVAILABLE, b"a"));
        let b = ClientError::Status(503, status_detail(StatusCode::SERVICE_UNAVAILABLE, b"<p>"));
        assert_eq!(a.kind(), b.kind());
        assert_eq!(a.kind(), "status 503");
    }

    #[test]
    fn the_token_is_not_shown() {
        let server = Server {
            https: true,
            host: "acs.example.org".into(),
            port: 443,
            authority: "acs.example.org".into(),
            path: String::new(),
        };
        let client = Client::new(server, Zeroizing::new("dwh_invented".into()), None).unwrap();
        let shown = format!("{client:?}");
        assert!(!shown.contains("dwh_invented"), "{shown}");
    }

    #[test]
    fn a_ca_file_without_certificates_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, "nothing here\n").unwrap();
        assert!(tls_config(Some(&path)).is_err());
        assert!(tls_config(Some(&dir.path().join("missing.pem"))).is_err());
    }
}
