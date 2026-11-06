//! Caller: client address + reverse proxy in between or not (ADR-103).
//!
//! API has no own TLS -> on the internet behind a TLS reverse proxy on the same host
//! -> every connection from `127.0.0.1`. So:
//!
//! - **Open mode** (no accounts, no token -> everyone admin): must never be reachable via
//!   the proxy. Any proxy header, or peer = configured trusted proxy
//!   -> [`ClientInfo::proxied`] -> never open mode.
//! - **Per-client limits** (rate limits, login lockouts, pending single sign-on cap) need
//!   the visitor address, not the proxy's. Forwarding headers believed only if the TCP peer
//!   is in `--trusted-proxies`. Client = right-most `X-Forwarded-For` (or `Forwarded: for=`)
//!   address that is not a trusted proxy. Left of it = written by untrusted parties
//!   -> ignored.
//!
//! Also: request scheme + host as a trusted proxy reports them (`X-Forwarded-Proto`,
//! `X-Forwarded-Host`), configured public address ([`PublicOrigin`], `--public-url`)
//! -> for the cross-site request check.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, Uri};
use axum::middleware::Next;
use axum::response::Response;
use dhonomos_core::Cidr;

use crate::AppState;

/// Headers a reverse proxy adds to a forwarded request.
/// Any of them -> came through a proxy (or wants to look so).
const PROXY_HEADERS: [&str; 5] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
];

/// Each kind of proxy set-up hint -> max 1 log per this interval.
const HINT_EVERY: Duration = Duration::from_secs(600);

/// Scheme the visitor's browser used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn parse(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("https") {
            Some(Self::Https)
        } else if s.eq_ignore_ascii_case("http") {
            Some(Self::Http)
        } else {
            None
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// What the server knows about the sender of a request.
#[derive(Debug, Clone)]
pub(crate) struct ClientInfo {
    /// Key of limits + logs: TCP peer, or behind a trusted proxy the client it names.
    /// `unknown` if the server does not give it (tests).
    pub(crate) ip: String,
    /// Proxy header or trusted-proxy peer -> not a direct local call
    /// -> never the anonymous admin of open mode.
    pub(crate) proxied: bool,
    /// TCP peer in `--trusted-proxies`.
    pub(crate) trusted_peer: bool,
    /// Visitor scheme, per trusted proxy (`X-Forwarded-Proto`).
    pub(crate) scheme: Option<Scheme>,
    /// Visitor host, per trusted proxy (`X-Forwarded-Host`).
    pub(crate) forwarded_host: Option<String>,
}

impl ClientInfo {
    /// Visitor -> proxy over HTTPS, per trusted proxy.
    pub(crate) fn https(&self) -> bool {
        self.scheme == Some(Scheme::Https)
    }

    pub(crate) fn unknown() -> Self {
        Self {
            ip: "unknown".into(),
            proxied: false,
            trusted_peer: false,
            scheme: None,
            forwarded_host: None,
        }
    }
}

/// Address from a forwarding header: `1.2.3.4`, `1.2.3.4:5678`, `[::1]`, `[::1]:5678`,
/// optional quotes. Else `None` (`unknown`, `_hidden`).
fn parse_node(s: &str) -> Option<IpAddr> {
    let s = s.trim().trim_matches('"');
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some(sa.ip());
    }
    s.strip_prefix('[')?.strip_suffix(']')?.parse().ok()
}

/// Entries of all `X-Forwarded-For` lines, left to right (`None` = not an address).
fn xff_chain(headers: &HeaderMap) -> Vec<Option<IpAddr>> {
    headers
        .get_all("x-forwarded-for")
        .iter()
        .flat_map(|v| match v.to_str() {
            Ok(v) => v.split(',').map(parse_node).collect(),
            Err(_) => vec![None],
        })
        .collect()
}

/// `for=` of each element of all RFC 7239 `Forwarded` lines, left to right
/// (`None` = no address).
fn forwarded_chain(headers: &HeaderMap) -> Vec<Option<IpAddr>> {
    headers
        .get_all("forwarded")
        .iter()
        .flat_map(|v| match v.to_str() {
            Ok(v) => v
                .split(',')
                .map(|element| {
                    element.split(';').find_map(|pair| {
                        let (k, v) = pair.split_once('=')?;
                        k.trim()
                            .eq_ignore_ascii_case("for")
                            .then(|| parse_node(v))?
                    })
                })
                .collect(),
            Err(_) => vec![None],
        })
        .collect()
}

/// Client in a forwarded chain = right-most hop that is not a trusted proxy.
///
/// Non-address hop on the way from the right -> `None`.
/// All hops trusted -> left-most one.
fn client_of(chain: &[Option<IpAddr>], trusted: &impl Fn(IpAddr) -> bool) -> Option<IpAddr> {
    let mut leftmost = None;
    for hop in chain.iter().rev() {
        let ip = (*hop)?;
        if !trusted(ip) {
            return Some(ip);
        }
        leftmost = Some(ip);
    }
    leftmost
}

/// Client a trusted proxy forwarded, from `X-Forwarded-For` or `Forwarded`.
///
/// Proxy appends to one of them; the other can be planted by the visitor + passed through.
/// Both present + different clients -> neither believed.
fn forwarded_client(headers: &HeaderMap, trusted: &impl Fn(IpAddr) -> bool) -> Option<IpAddr> {
    let (xff, fwd) = (xff_chain(headers), forwarded_chain(headers));
    match (xff.is_empty(), fwd.is_empty()) {
        (true, true) => None,
        (false, true) => client_of(&xff, trusted),
        (true, false) => client_of(&fwd, trusted),
        (false, false) => {
            let (a, b) = (client_of(&xff, trusted), client_of(&fwd, trusted));
            (a == b).then_some(a).flatten()
        }
    }
}

/// Who sent a request. `peer` = TCP peer, `trusted` = configured proxies.
pub(crate) fn resolve(peer: Option<IpAddr>, headers: &HeaderMap, trusted: &[Cidr]) -> ClientInfo {
    let is_trusted = |ip: IpAddr| trusted.iter().any(|c| c.contains(ip));
    let trusted_peer = peer.is_some_and(is_trusted);
    let mut info = ClientInfo {
        ip: peer.map_or_else(|| "unknown".to_owned(), |p| p.to_canonical().to_string()),
        proxied: trusted_peer || PROXY_HEADERS.iter().any(|h| headers.contains_key(*h)),
        trusted_peer,
        scheme: None,
        forwarded_host: None,
    };
    if trusted_peer {
        if let Some(client) = forwarded_client(headers, &is_trusted) {
            info.ip = client.to_canonical().to_string();
        }
        // Last list entry = from the nearest proxy.
        info.scheme = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| Scheme::parse(v.trim()));
        // Last entry, as for the scheme: nearest (trusted) proxy appended it,
        // earlier ones may come from the visitor.
        info.forwarded_host = headers
            .get("x-forwarded-host")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty());
    }
    info
}

/// Proxy set-up messages that would repeat per request
/// -> each kind max once per [`HINT_EVERY`].
#[derive(Debug, Default)]
pub(crate) struct Hints(Mutex<HashMap<&'static str, Instant>>);

impl Hints {
    /// Hint `kind` may be given now -> also marks it as given.
    pub(crate) fn due(&self, kind: &'static str, now: Instant) -> bool {
        let Ok(mut given) = self.0.lock() else {
            return false;
        };
        if given
            .get(kind)
            .is_some_and(|at| now.saturating_duration_since(*at) < HINT_EVERY)
        {
            return false;
        }
        given.insert(kind, now);
        true
    }
}

/// Log what is wrong with the proxy set-up, as seen in the request.
fn hint(s: &AppState, info: &ClientInfo, headers: &HeaderMap) {
    let now = Instant::now();
    let trusted_proxies = !s.config.trusted_proxies.is_empty();
    if headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|p| p.trim().eq_ignore_ascii_case("https")))
        && !s.config.secure_cookies
        && s.hints.due("https-without-secure-cookies", now)
    {
        tracing::warn!(
            "a request arrived over HTTPS through a proxy (X-Forwarded-Proto: https) but --secure-cookies is off: the session cookie lacks the Secure attribute and the __Host- prefix; turn it on"
        );
    }
    if info.proxied && !trusted_proxies && s.hints.due("proxy-without-trusted-proxies", now) {
        tracing::warn!(
            peer = %info.ip,
            "a request carries proxy headers but --trusted-proxies is not set: every visitor counts as the proxy's address for rate limits and login lockouts; set --trusted-proxies 127.0.0.1/32 (the proxy's address)"
        );
    } else if info.proxied
        && trusted_proxies
        && !info.trusted_peer
        && s.hints.due("proxy-headers-from-untrusted-peer", now)
    {
        tracing::debug!(
            peer = %info.ip,
            "proxy headers from a peer that is not in --trusted-proxies are ignored"
        );
    }
    if info.trusted_peer
        && !["forwarded", "x-forwarded-for"]
            .iter()
            .any(|h| headers.contains_key(*h))
        && s.hints.due("trusted-proxy-without-forwarding", now)
    {
        tracing::debug!(
            peer = %info.ip,
            "a trusted proxy sent no X-Forwarded-For or Forwarded header: the proxy's own address is used as the client's"
        );
    }
}

/// Middleware on the whole router: resolve the caller -> [`ClientInfo`] request extension
/// for everything below (limits, authentication, handlers).
pub(crate) async fn client_info(
    State(s): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let info = resolve(peer, req.headers(), &s.config.trusted_proxies);
    hint(&s, &info, req.headers());
    req.extensions_mut().insert(info);
    next.run(req).await
}

/// Caller of a request that went through [`client_info`].
pub(crate) fn info_of(req: &Request) -> ClientInfo {
    req.extensions()
        .get::<ClientInfo>()
        .cloned()
        .unwrap_or_else(ClientInfo::unknown)
}

/// UI address as visitors type it: `https://rms.example.org` (`--public-url`).
///
/// Cross-site request check: `Origin` must match it exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicOrigin {
    scheme: Scheme,
    host: String,
    port: u16,
}

impl FromStr for PublicOrigin {
    type Err = String;

    /// `http://host[:port]` or `https://host[:port]`; no user name, path, query, fragment.
    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || {
            format!(
                "invalid address {s:?}: expected e.g. https://rms.example.org (scheme, host and optional port only)"
            )
        };
        let s = s.trim();
        let s = s.strip_suffix('/').unwrap_or(s);
        let (scheme, authority) = s.split_once("://").ok_or_else(bad)?;
        let scheme = Scheme::parse(scheme).ok_or_else(bad)?;
        if authority.is_empty()
            || authority.contains(['/', '?', '#', '@', '\\'])
            || authority
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(bad());
        }
        let uri: Uri = format!("{}://{authority}", scheme.as_str())
            .parse()
            .map_err(|_| bad())?;
        let host = uri.host().ok_or_else(bad)?;
        // After the host: nothing, or `:` + port.
        let rest = authority
            .get(host.len()..)
            .filter(|_| authority.len() >= host.len())
            .ok_or_else(bad)?;
        let port = match rest.strip_prefix(':') {
            None if rest.is_empty() => match scheme {
                Scheme::Http => 80,
                Scheme::Https => 443,
            },
            Some(p) => p.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(bad)?,
            None => return Err(bad()),
        };
        Ok(Self {
            scheme,
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

impl fmt::Display for PublicOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let default = match self.scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        };
        write!(f, "{}://{}", self.scheme.as_str(), self.host)?;
        if self.port != default {
            write!(f, ":{}", self.port)?;
        }
        Ok(())
    }
}

impl PublicOrigin {
    /// `Origin` value = this address exactly (scheme, host, port; default port may be left out).
    pub(crate) fn matches(&self, origin: &str) -> bool {
        origin.parse::<Self>().is_ok_and(|o| o == *self)
    }

    pub fn is_https(&self) -> bool {
        self.scheme == Scheme::Https
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                *k,
                HeaderValue::from_str(v).unwrap_or_else(|_| panic!("{v}")),
            );
        }
        h
    }

    fn cidrs(list: &[&str]) -> Vec<Cidr> {
        list.iter()
            .map(|c| c.parse().unwrap_or_else(|e| panic!("{c}: {e}")))
            .collect()
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap_or_else(|_| panic!("{s}")))
    }

    #[test]
    fn without_trusted_proxies_the_peer_is_the_client_and_headers_only_mark_a_proxy() {
        let h = headers(&[("x-forwarded-for", "203.0.113.7")]);
        let c = resolve(ip("198.51.100.9"), &h, &[]);
        assert_eq!(c.ip, "198.51.100.9", "a header from anyone is not believed");
        assert!(c.proxied, "but it shows the request is not a direct call");
        assert!(!c.trusted_peer);
        assert_eq!((c.scheme, c.forwarded_host), (None, None));

        let direct = resolve(ip("127.0.0.1"), &HeaderMap::new(), &[]);
        assert_eq!((direct.ip.as_str(), direct.proxied), ("127.0.0.1", false));
        let unknown = resolve(None, &HeaderMap::new(), &[]);
        assert_eq!(unknown.ip, "unknown");
        // Each of the 5 headers -> proxied.
        for name in PROXY_HEADERS {
            let c = resolve(ip("127.0.0.1"), &headers(&[(name, "x")]), &[]);
            assert!(c.proxied, "{name}");
        }
    }

    #[test]
    fn a_trusted_proxy_names_the_client_by_the_rightmost_untrusted_address() {
        let trusted = cidrs(&["127.0.0.1/32", "10.0.0.0/8"]);
        let client = |peer: &str, pairs: &[(&'static str, &str)]| {
            resolve(ip(peer), &headers(pairs), &trusted).ip
        };
        // Proxy appended the real peer; visitor entries to the left -> ignored.
        assert_eq!(
            client(
                "127.0.0.1",
                &[("x-forwarded-for", "1.1.1.1, 2.2.2.2, 203.0.113.7")]
            ),
            "203.0.113.7",
            "a spoofed left-most entry does not count"
        );
        assert_eq!(
            client("127.0.0.1", &[("x-forwarded-for", "203.0.113.7")]),
            "203.0.113.7"
        );
        // Other trusted proxy in the chain -> skipped.
        assert_eq!(
            client(
                "127.0.0.1",
                &[("x-forwarded-for", "9.9.9.9, 203.0.113.7, 10.1.2.3")]
            ),
            "203.0.113.7"
        );
        // Several header lines = one list.
        assert_eq!(
            client(
                "127.0.0.1",
                &[
                    ("x-forwarded-for", "9.9.9.9"),
                    ("x-forwarded-for", "203.0.113.7")
                ]
            ),
            "203.0.113.7"
        );
        // Ports, brackets and IPv6.
        assert_eq!(
            client("127.0.0.1", &[("x-forwarded-for", "203.0.113.7:51234")]),
            "203.0.113.7"
        );
        assert_eq!(
            client("127.0.0.1", &[("x-forwarded-for", "[2001:db8::1]:443")]),
            "2001:db8::1"
        );
        assert_eq!(
            client("127.0.0.1", &[("x-forwarded-for", "[2001:db8::1]")]),
            "2001:db8::1"
        );
        // All hops trusted -> first = client.
        assert_eq!(
            client("127.0.0.1", &[("x-forwarded-for", "10.9.9.9, 10.1.2.3")]),
            "10.9.9.9"
        );
        // Nearest entry not an address -> not believed.
        assert_eq!(
            client("127.0.0.1", &[("x-forwarded-for", "203.0.113.7, unknown")]),
            "127.0.0.1"
        );
        // Trusted proxy, nothing forwarded -> proxy = client.
        assert_eq!(client("127.0.0.1", &[]), "127.0.0.1");
        // IPv4-mapped IPv6 peer = IPv4.
        assert_eq!(
            client("::ffff:127.0.0.1", &[("x-forwarded-for", "203.0.113.7")]),
            "203.0.113.7"
        );
    }

    #[test]
    fn an_untrusted_peers_forwarding_headers_are_ignored() {
        let trusted = cidrs(&["127.0.0.1/32"]);
        let h = headers(&[
            ("x-forwarded-for", "203.0.113.7"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "rms.example.org"),
        ]);
        let c = resolve(ip("198.51.100.9"), &h, &trusted);
        assert_eq!(c.ip, "198.51.100.9");
        assert!(c.proxied && !c.trusted_peer);
        assert_eq!((c.scheme, c.forwarded_host.clone()), (None, None));
        assert!(!c.https());
    }

    #[test]
    fn the_rfc_7239_forwarded_header_works_too() {
        let trusted = cidrs(&["127.0.0.1/32"]);
        let client =
            |pairs: &[(&'static str, &str)]| resolve(ip("127.0.0.1"), &headers(pairs), &trusted).ip;
        assert_eq!(
            client(&[(
                "forwarded",
                "for=1.1.1.1;proto=http, for=203.0.113.7;proto=https"
            )]),
            "203.0.113.7"
        );
        assert_eq!(
            client(&[("forwarded", "For=\"[2001:db8:cafe::17]:4711\"")]),
            "2001:db8:cafe::17"
        );
        assert_eq!(client(&[("forwarded", "for=_hidden")]), "127.0.0.1");
        assert_eq!(client(&[("forwarded", "by=127.0.0.1")]), "127.0.0.1");
        // Both headers, different clients -> one planted, unknown which -> neither.
        assert_eq!(
            client(&[
                ("x-forwarded-for", "203.0.113.7"),
                ("forwarded", "for=198.51.100.1")
            ]),
            "127.0.0.1"
        );
        assert_eq!(
            client(&[
                ("x-forwarded-for", "203.0.113.7"),
                ("forwarded", "for=203.0.113.7")
            ]),
            "203.0.113.7"
        );
    }

    #[test]
    fn scheme_and_host_come_from_trusted_proxies_only() {
        let trusted = cidrs(&["127.0.0.1/32"]);
        let c = resolve(
            ip("127.0.0.1"),
            &headers(&[
                ("x-forwarded-for", "203.0.113.7"),
                ("x-forwarded-proto", "http, https"),
                ("x-forwarded-host", "planted.example , Rms.Example.org "),
            ]),
            &trusted,
        );
        assert_eq!(c.scheme, Some(Scheme::Https), "the nearest proxy's entry");
        assert!(c.https());
        // Last entry from the nearest proxy; first maybe from the visitor.
        assert_eq!(c.forwarded_host.as_deref(), Some("Rms.Example.org"));
        let odd = resolve(
            ip("127.0.0.1"),
            &headers(&[("x-forwarded-proto", "gopher")]),
            &trusted,
        );
        assert_eq!(odd.scheme, None);
        assert!(odd.proxied);
    }

    #[test]
    fn a_trusted_peer_is_a_proxy_even_without_headers() {
        let c = resolve(ip("127.0.0.1"), &HeaderMap::new(), &cidrs(&["127.0.0.0/8"]));
        assert!(c.proxied && c.trusted_peer);
    }

    #[test]
    fn hints_are_rate_limited() {
        let h = Hints::default();
        let t0 = Instant::now();
        assert!(h.due("a", t0));
        assert!(!h.due("a", t0 + Duration::from_secs(1)));
        assert!(h.due("b", t0 + Duration::from_secs(1)));
        assert!(h.due("a", t0 + HINT_EVERY + Duration::from_secs(1)));
    }

    #[test]
    fn the_public_address_is_compared_exactly() {
        let p: PublicOrigin = "https://Rms.Example.org/"
            .parse()
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p.to_string(), "https://rms.example.org");
        assert!(p.is_https());
        assert!(p.matches("https://rms.example.org"));
        assert!(
            p.matches("https://RMS.example.org:443"),
            "default port may be left out"
        );
        for other in [
            "http://rms.example.org",
            "https://rms.example.org:8443",
            "https://evil.example.org",
            "https://rms.example.org.evil.example",
            "https://sub.rms.example.org",
            "null",
            "",
            "https://rms.example.org/path",
        ] {
            assert!(!p.matches(other), "{other}");
        }
        let odd: PublicOrigin = "http://10.0.0.5:8080"
            .parse()
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(odd.to_string(), "http://10.0.0.5:8080");
        assert!(!odd.is_https());
        assert!(odd.matches("http://10.0.0.5:8080"));
        assert!(!odd.matches("http://10.0.0.5"));
        let v6: PublicOrigin = "https://[2001:db8::1]:8443"
            .parse()
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(v6.matches("https://[2001:db8::1]:8443"));
        for bad in [
            "rms.example.org",
            "ftp://rms.example.org",
            "https://",
            "https://rms.example.org/ui",
            "https://rms.example.org?x=1",
            "https://user@rms.example.org",
            "https://rms.example.org:99999",
            "https://rms example.org",
        ] {
            assert!(bad.parse::<PublicOrigin>().is_err(), "{bad}");
        }
    }
}
