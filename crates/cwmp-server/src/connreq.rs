//! Connection Request client (TR-069 3.2.2, CW-08): HTTP GET to the CPE ConnectionRequestURL.
//! Digest challenge -> answered.
//! Basic challenge -> only if the operator allows it: password in clear text.

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::Empty;
use hyper::header::{self, HeaderValue};
use hyper::{Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use crate::addrpolicy::AddressPolicy;
use crate::auth::{DigestInput, digest_response};

/// Connection request failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnReqError {
    /// URL not `http://host[:port]/path`.
    #[error("invalid connection request URL {0:?}")]
    InvalidUrl(String),
    /// Host resolves only to addresses refused by the policy (SSRF protection).
    #[error("address not permitted: {0}")]
    Blocked(String),
    /// TCP connect or HTTP exchange failed.
    #[error("connection failed: {0}")]
    Connect(String),
    /// Whole exchange (resolve + GETs) longer than `timeout`.
    #[error("timed out")]
    Timeout,
    /// CPE rejected the credentials, or none configured.
    #[error("authentication rejected")]
    Unauthorized,
    /// CPE asks for Basic + `allow_basic` off.
    /// Plain http -> CR password in clear text -> refused.
    #[error("the CPE asks for Basic authentication over plain http, which is not allowed")]
    BasicRefused,
    /// HTTP status other than 200, 204, 401.
    #[error("unexpected HTTP status {0}")]
    Status(StatusCode),
}

/// CPE credentials (ManagementServer.ConnectionRequestUsername/Password).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnReqCredentials {
    pub username: String,
    pub password: String,
}

/// Resolve the URL host -> first address the policy permits.
async fn resolve(uri: &Uri, policy: &AddressPolicy) -> Result<SocketAddr, ConnReqError> {
    let host = uri
        .host()
        .ok_or_else(|| ConnReqError::InvalidUrl(uri.to_string()))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = uri.port_u16().unwrap_or(80);
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| ConnReqError::Connect(e.to_string()))?
        .collect();
    addrs
        .iter()
        .find(|a| policy.permits(a.ip()))
        .copied()
        .ok_or_else(|| {
            ConnReqError::Blocked(
                addrs
                    .first()
                    .map_or_else(|| host.to_owned(), |a| a.ip().to_string()),
            )
        })
}

async fn get(
    addr: SocketAddr,
    uri: &Uri,
    authorization: Option<String>,
) -> Result<(StatusCode, Vec<String>), ConnReqError> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| ConnReqError::Connect(e.to_string()))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| ConnReqError::Connect(e.to_string()))?;
    tokio::spawn(conn);
    let authority = uri
        .authority()
        .map(|a| a.as_str().to_owned())
        .unwrap_or_default();
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    let mut req = Request::get(path).header(header::HOST, authority);
    if let Some(a) = authorization {
        req = req.header(header::AUTHORIZATION, a);
    }
    let req = req
        .body(Empty::<Bytes>::new())
        .map_err(|e| ConnReqError::Connect(e.to_string()))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| ConnReqError::Connect(e.to_string()))?;
    let challenges = resp
        .headers()
        .get_all(header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|v: &HeaderValue| v.to_str().ok().map(str::to_owned))
        .collect();
    Ok((resp.status(), challenges))
}

fn param<'a>(challenge: &'a str, key: &str) -> Option<&'a str> {
    let i = challenge.find(&format!("{key}="))?;
    let rest = &challenge[i + key.len() + 1..];
    match rest.strip_prefix('"') {
        Some(q) => q.split('"').next(),
        None => rest.split([',', ' ']).next(),
    }
}

/// `Authorization` header for the CPE challenge.
/// Digest preferred (SHA-256 if offered, else MD5); Basic only if `allow_basic`.
/// Digest not answerable -> no fallback to Basic.
fn authorization(
    challenges: &[String],
    uri: &str,
    creds: &ConnReqCredentials,
    allow_basic: bool,
) -> Result<String, ConnReqError> {
    let digest = challenges
        .iter()
        .filter(|c| c.trim_start().to_ascii_lowercase().starts_with("digest"))
        .max_by_key(|c| c.to_ascii_uppercase().contains("SHA-256"));
    if let Some(c) = digest {
        return digest_authorization(c, uri, creds).ok_or(ConnReqError::Unauthorized);
    }
    if !challenges
        .iter()
        .any(|c| c.trim_start().to_ascii_lowercase().starts_with("basic"))
    {
        return Err(ConnReqError::Unauthorized);
    }
    if !allow_basic {
        return Err(ConnReqError::BasicRefused);
    }
    let token = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", creds.username, creds.password));
    Ok(format!("Basic {token}"))
}

fn digest_authorization(c: &str, uri: &str, creds: &ConnReqCredentials) -> Option<String> {
    let realm = param(c, "realm")?;
    let nonce = param(c, "nonce")?;
    let sha256 = param(c, "algorithm").is_some_and(|a| a.eq_ignore_ascii_case("SHA-256"));
    let qop_auth = param(c, "qop").is_some_and(|q| q.split(',').any(|x| x.trim() == "auth"));
    let mut cn = [0u8; 8];
    getrandom::fill(&mut cn).ok()?;
    let cnonce: String = cn.iter().map(|b| format!("{b:02x}")).collect();
    let response = digest_response(&DigestInput {
        sha256,
        username: &creds.username,
        realm,
        password: &creds.password,
        method: "GET",
        uri,
        nonce,
        nc: "00000001",
        cnonce: &cnonce,
    });
    let alg = if sha256 { "SHA-256" } else { "MD5" };
    let opaque = param(c, "opaque")
        .map(|o| format!(r#", opaque="{o}""#))
        .unwrap_or_default();
    Some(if qop_auth {
        format!(
            r#"Digest username="{}", realm="{realm}", nonce="{nonce}", uri="{uri}", algorithm={alg}, qop=auth, nc=00000001, cnonce="{cnonce}", response="{response}"{opaque}"#,
            creds.username
        )
    } else {
        // RFC 2069: no qop.
        let legacy = crate::auth::legacy_digest(
            sha256,
            &creds.username,
            realm,
            &creds.password,
            "GET",
            uri,
            nonce,
        );
        format!(
            r#"Digest username="{}", realm="{realm}", nonce="{nonce}", uri="{uri}", algorithm={alg}, response="{legacy}"{opaque}"#,
            creds.username
        )
    })
}

/// Send a connection request. Success = CPE answers 200 or 204.
/// After that: CPE opens a session, Inform `6 CONNECTION REQUEST`.
/// Contact only addresses `policy` permits.
/// Digest challenge -> answered with the CPE credentials.
/// Basic challenge -> only if `allow_basic`: plain http -> password in clear text.
/// A CPE, or an impostor at its address, can always ask for Basic.
pub async fn connection_request(
    url: &str,
    credentials: Option<&ConnReqCredentials>,
    timeout: Duration,
    policy: &AddressPolicy,
    allow_basic: bool,
) -> Result<(), ConnReqError> {
    let uri: Uri = url
        .parse()
        .map_err(|_| ConnReqError::InvalidUrl(url.to_owned()))?;
    if uri.scheme_str() != Some("http") || uri.host().is_none() {
        return Err(ConnReqError::InvalidUrl(url.to_owned()));
    }
    let path = uri.path_and_query().map_or("/", |p| p.as_str()).to_owned();
    let exchange = async {
        // Resolve once -> both requests go to the checked address.
        let addr = resolve(&uri, policy).await?;
        let (status, challenges) = get(addr, &uri, None).await?;
        if status != StatusCode::UNAUTHORIZED {
            return Ok(status);
        }
        let creds = credentials.ok_or(ConnReqError::Unauthorized)?;
        let header = authorization(&challenges, &path, creds, allow_basic)?;
        Ok(get(addr, &uri, Some(header)).await?.0)
    };
    let status = tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| ConnReqError::Timeout)??;
    match status {
        StatusCode::OK | StatusCode::NO_CONTENT => Ok(()),
        StatusCode::UNAUTHORIZED => Err(ConnReqError::Unauthorized),
        s => Err(ConnReqError::Status(s)),
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use http_body_util::Full;
    use hyper::Response;
    use hyper::service::service_fn;

    use super::*;
    use crate::auth::{AuthMode, Authenticator, RequestInfo, Verdict};

    /// Fake CPE: needs `cpe`/`pw` with `mode`; counts accepted requests.
    async fn fake_cpe(mode: AuthMode) -> (String, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let auth = Arc::new(Authenticator::new(
            mode,
            "cpe-realm",
            Duration::from_secs(60),
        ));
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    return;
                };
                let auth = auth.clone();
                let h = h.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let auth = auth.clone();
                        let h = h.clone();
                        async move {
                            let header = req
                                .headers()
                                .get(header::AUTHORIZATION)
                                .and_then(|v| v.to_str().ok());
                            let target = req
                                .uri()
                                .path_and_query()
                                .map_or("/", |p| p.as_str())
                                .to_owned();
                            let info = RequestInfo {
                                method: "GET",
                                target: &target,
                                client: peer.ip(),
                            };
                            let ok = auth.mode() == AuthMode::None
                                || auth.parse(header).is_some_and(|p| {
                                    auth.verify(&p, &info, "pw") == Verdict::Valid
                                });
                            let mut resp = Response::new(Full::new(Bytes::new()));
                            if ok {
                                h.fetch_add(1, Ordering::SeqCst);
                                *resp.status_mut() = StatusCode::NO_CONTENT;
                            } else {
                                *resp.status_mut() = StatusCode::UNAUTHORIZED;
                                for c in auth.challenges(peer.ip(), false) {
                                    if let Ok(v) = HeaderValue::from_str(&c) {
                                        resp.headers_mut().append(header::WWW_AUTHENTICATE, v);
                                    }
                                }
                            }
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        (format!("http://{addr}/cr/path?x=1"), hits)
    }

    fn creds(password: &str) -> ConnReqCredentials {
        ConnReqCredentials {
            username: "cpe".into(),
            password: password.into(),
        }
    }

    #[tokio::test]
    async fn digest_challenge_is_answered() {
        let (url, hits) = fake_cpe(AuthMode::Digest).await;
        let t = Duration::from_secs(5);
        let any = AddressPolicy::permit_all();
        connection_request(&url, Some(&creds("pw")), t, &any, false)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(matches!(
            connection_request(&url, Some(&creds("bad")), t, &any, false).await,
            Err(ConnReqError::Unauthorized)
        ));
        assert!(matches!(
            connection_request(&url, None, t, &any, false).await,
            Err(ConnReqError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn basic_is_answered_only_when_allowed() {
        let (url, hits) = fake_cpe(AuthMode::Basic).await;
        let t = Duration::from_secs(5);
        let any = AddressPolicy::permit_all();
        // CPE (or anyone at its address) asks for Basic -> nothing sent by default.
        assert!(matches!(
            connection_request(&url, Some(&creds("pw")), t, &any, false).await,
            Err(ConnReqError::BasicRefused)
        ));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        connection_request(&url, Some(&creds("pw")), t, &any, true)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // No credentials -> nothing to refuse or send.
        assert!(matches!(
            connection_request(&url, None, t, &any, true).await,
            Err(ConnReqError::Unauthorized)
        ));
    }

    #[test]
    fn digest_wins_over_basic_and_never_leaks_the_password_to_basic() {
        let c = creds("pw");
        let offered = [
            r#"Basic realm="cpe""#.to_owned(),
            r#"Digest realm="cpe", qop="auth", nonce="n1""#.to_owned(),
        ];
        let header = authorization(&offered, "/cr", &c, false).unwrap_or_default();
        assert!(header.starts_with("Digest "), "{header}");
        assert!(!header.contains("pw"));
        // Digest challenge not answerable -> no fallback to Basic.
        let broken = [
            r#"Basic realm="cpe""#.to_owned(),
            r#"Digest realm="cpe""#.to_owned(),
        ];
        assert!(matches!(
            authorization(&broken, "/cr", &c, true),
            Err(ConnReqError::Unauthorized)
        ));
        assert!(matches!(
            authorization(&[r#"Negotiate"#.to_owned()], "/cr", &c, true),
            Err(ConnReqError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn open_cpes() {
        let (open, open_hits) = fake_cpe(AuthMode::None).await;
        connection_request(
            &open,
            None,
            Duration::from_secs(5),
            &AddressPolicy::permit_all(),
            false,
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(open_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn bad_urls_and_unreachable_hosts() {
        let t = Duration::from_secs(2);
        for url in ["ftp://x/", "not a url", "http:///nohost"] {
            assert!(
                matches!(
                    connection_request(url, None, t, &AddressPolicy::permit_all(), false).await,
                    Err(ConnReqError::InvalidUrl(_))
                ),
                "{url}"
            );
        }
        // Loopback, link-local, metadata addresses -> refused by default.
        // Also via a name that resolves to them.
        for url in [
            "http://127.0.0.1:7547/",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:7547/",
            "http://[::1]:7547/",
        ] {
            assert!(
                matches!(
                    connection_request(url, None, t, &AddressPolicy::default(), false).await,
                    Err(ConnReqError::Blocked(_))
                ),
                "{url}"
            );
        }
        // Nothing listens on port 1.
        assert!(matches!(
            connection_request(
                "http://127.0.0.1:1/",
                None,
                t,
                &AddressPolicy::permit_all(),
                false
            )
            .await,
            Err(ConnReqError::Connect(_))
        ));
    }
}
