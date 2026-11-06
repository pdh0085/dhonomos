//! CPE -> ACS HTTP auth: Basic + Digest (RFC 7616, MD5 + SHA-256, qop=auth).
//!
//! Digest nonce, stateless: `<unix-seconds>-<random salt>-<hex HMAC-SHA256(secret,
//! seconds, salt, client)>` -> own nonce per challenge.
//! Nonce valid only for the address it was issued to (IPv6: its /64) + younger than lifetime.
//! Highest accepted nonce count (`nc`) per nonce kept -> captured `Authorization` header
//! cannot be replayed (L-4). Only requests that proved the password kept; memory bounded.
//! Digest `uri` must name the request target.
//! Well-formed but expired nonce, or replayed count, + otherwise correct response
//! -> `stale=true` -> client retries with new nonce, password not treated as wrong.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest as _, Md5};
use sha2::Sha256;

/// Required CPE authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthMode {
    /// No auth (development only).
    None,
    /// HTTP Basic (production: TLS only).
    Basic,
    #[default]
    Digest,
}

/// Digest hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Md5,
    Sha256,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn hash(alg: Algorithm, data: &str) -> String {
    match alg {
        Algorithm::Md5 => hex(&Md5::digest(data.as_bytes())),
        Algorithm::Sha256 => hex(&Sha256::digest(data.as_bytes())),
    }
}

/// Constant-time comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Parse `key=value, key="quoted, value"` lists.
fn parse_params(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = s.trim();
    while !rest.is_empty() {
        let Some(eq) = rest.find('=') else { break };
        let key = rest[..eq]
            .trim()
            .trim_start_matches(',')
            .trim()
            .to_ascii_lowercase();
        rest = rest[eq + 1..].trim_start();
        let value;
        if let Some(q) = rest.strip_prefix('"') {
            let mut v = String::new();
            let mut chars = q.char_indices();
            let mut end = q.len();
            while let Some((i, c)) = chars.next() {
                match c {
                    '\\' => {
                        if let Some((_, n)) = chars.next() {
                            v.push(n);
                        }
                    }
                    '"' => {
                        end = i + 1;
                        break;
                    }
                    c => v.push(c),
                }
            }
            value = v;
            rest = &q[end.min(q.len())..];
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            value = rest[..end].trim().to_owned();
            rest = &rest[end..];
        }
        rest = rest.trim_start().trim_start_matches(',').trim_start();
        out.push((key, value));
    }
    out
}

/// Max nonces with remembered counts; oldest forgotten first.
const MAX_TRACKED_NONCES: usize = 100_000;

/// Check `Authorization` headers + build challenges.
#[derive(Debug)]
pub(crate) struct Authenticator {
    mode: AuthMode,
    realm: String,
    secret: [u8; 32],
    nonce_lifetime: Duration,
    /// Accept RFC 2069 responses (no `qop`) -> no client nonce, no count.
    allow_no_qop: bool,
    /// Nonce valid only for the address it was issued to.
    bind_client: bool,
    max_tracked: usize,
    used: Mutex<NonceCounts>,
}

/// Request data for the auth check.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RequestInfo<'a> {
    pub method: &'a str,
    /// As sent (path + query).
    pub target: &'a str,
    pub client: IpAddr,
}

/// Result of a credential check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Valid,
    /// Password right, but nonce expired or count used before -> client retries with new
    /// nonce (`stale=true`). Not a failed login.
    Stale,
    Invalid,
}

/// Highest accepted `nc` per nonce. Key (issue time, rest of nonce) -> oldest nonces first.
#[derive(Debug, Default)]
struct NonceCounts(BTreeMap<(u64, String), u32>);

impl NonceCounts {
    /// Record `nc` for the nonce. false -> this count or higher accepted before.
    fn claim(&mut self, nonce: (u64, &str), nc: u32, oldest_valid: u64, cap: usize) -> bool {
        // Nonces older than lifetime refused before this point -> forget them.
        if self
            .0
            .first_key_value()
            .is_some_and(|((ts, _), _)| *ts < oldest_valid)
        {
            self.0 = self.0.split_off(&(oldest_valid, String::new()));
        }
        let key = (nonce.0, nonce.1.to_owned());
        if let Some(last) = self.0.get_mut(&key) {
            if nc <= *last {
                return false;
            }
            *last = nc;
            return true;
        }
        while self.0.len() >= cap.max(1) {
            self.0.pop_first();
        }
        self.0.insert(key, nc);
        true
    }
}

/// Credentials from a request, to check against a stored password.
#[derive(Debug)]
pub(crate) enum Presented {
    Basic {
        username: String,
        password: String,
    },
    Digest {
        username: String,
        params: Vec<(String, String)>,
    },
}

impl Presented {
    pub(crate) fn username(&self) -> &str {
        match self {
            Self::Basic { username, .. } | Self::Digest { username, .. } => username,
        }
    }
}

/// Digest `uri` names the request target? = path + query as sent, or path only (some HTTP
/// stacks leave the query out of the digest). Absolute URL of the request also accepted.
fn uri_matches(uri: &str, target: &str) -> bool {
    let uri = ["http://", "https://"]
        .iter()
        .find_map(|scheme| uri.strip_prefix(scheme))
        .map_or(uri, |rest| rest.find('/').map_or("/", |i| &rest[i..]));
    uri == target || uri == target.split_once('?').map_or(target, |(path, _)| path)
}

impl Authenticator {
    pub(crate) fn new(mode: AuthMode, realm: &str, nonce_lifetime: Duration) -> Self {
        let mut secret = [0u8; 32];
        // No OS randomness -> server cannot authenticate, unrecoverable.
        getrandom::fill(&mut secret).unwrap_or_else(|e| panic!("OS RNG unavailable: {e}"));
        Self {
            mode,
            realm: realm.to_owned(),
            secret,
            nonce_lifetime,
            allow_no_qop: true,
            bind_client: true,
            max_tracked: MAX_TRACKED_NONCES,
            used: Mutex::default(),
        }
    }

    /// Accept RFC 2069 Digest responses (no `qop`)?
    /// No client nonce + no count -> open to chosen-nonce attacks, no replay check.
    pub(crate) fn allow_no_qop(mut self, allow: bool) -> Self {
        self.allow_no_qop = allow;
        self
    }

    /// Tie nonces to the address they were issued to?
    pub(crate) fn bind_client(mut self, bind: bool) -> Self {
        self.bind_client = bind;
        self
    }

    /// Max nonces with remembered counts.
    #[cfg(test)]
    fn max_tracked(mut self, max: usize) -> Self {
        self.max_tracked = max;
        self
    }

    pub(crate) fn mode(&self) -> AuthMode {
        self.mode
    }

    fn mac(&self, ts: u64, salt: &str, client: IpAddr) -> String {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.secret)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        mac.update(ts.to_string().as_bytes());
        mac.update(b"-");
        mac.update(salt.as_bytes());
        if self.bind_client {
            match crate::guard::source(client) {
                IpAddr::V4(a) => {
                    mac.update(&[4]);
                    mac.update(&a.octets());
                }
                IpAddr::V6(a) => {
                    mac.update(&[6]);
                    mac.update(&a.octets());
                }
            }
        }
        hex(&mac.finalize().into_bytes())
    }

    fn nonce_at(&self, ts: u64, client: IpAddr) -> String {
        let mut salt = [0u8; 8];
        getrandom::fill(&mut salt).unwrap_or_else(|e| panic!("OS RNG unavailable: {e}"));
        let salt = hex(&salt);
        format!("{ts}-{salt}-{}", self.mac(ts, &salt, client))
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    /// Issue time of a nonce this server issued to `client` (expired or not) + rest of the
    /// nonce (= its ID).
    fn issued_to<'a>(&self, nonce: &'a str, client: IpAddr) -> Option<(u64, &'a str)> {
        let (ts, rest) = nonce.split_once('-')?;
        let (salt, mac) = rest.split_once('-')?;
        let ts = ts.parse::<u64>().ok()?;
        ct_eq(mac.as_bytes(), self.mac(ts, salt, client).as_bytes()).then_some((ts, rest))
    }

    fn expired(&self, ts: u64) -> bool {
        Self::now().saturating_sub(ts) > self.nonce_lifetime.as_secs()
    }

    /// `WWW-Authenticate` values for a 401. `stale` -> Digest client: credentials fine, only
    /// the nonce to replace.
    pub(crate) fn challenges(&self, client: IpAddr, stale: bool) -> Vec<String> {
        match self.mode {
            AuthMode::None => Vec::new(),
            AuthMode::Basic => vec![format!(r#"Basic realm="{}""#, self.realm)],
            AuthMode::Digest => {
                let nonce = self.nonce_at(Self::now(), client);
                let stale = if stale { ", stale=true" } else { "" };
                // SHA-256 first (RFC 7616 preference); MD5 for older CPEs.
                ["SHA-256", "MD5"]
                    .iter()
                    .map(|alg| {
                        format!(
                            r#"Digest realm="{}", qop="auth", algorithm={alg}, nonce="{nonce}"{stale}"#,
                            self.realm
                        )
                    })
                    .collect()
            }
        }
    }

    /// Credentials from an `Authorization` header of the configured mode.
    pub(crate) fn parse(&self, header: Option<&str>) -> Option<Presented> {
        let header = header?.trim();
        let (scheme, rest) = header.split_once(' ')?;
        match self.mode {
            AuthMode::Basic if scheme.eq_ignore_ascii_case("Basic") => {
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(rest.trim())
                    .ok()?;
                let text = String::from_utf8(raw).ok()?;
                let (u, p) = text.split_once(':')?;
                Some(Presented::Basic {
                    username: u.to_owned(),
                    password: p.to_owned(),
                })
            }
            AuthMode::Digest if scheme.eq_ignore_ascii_case("Digest") => {
                let params = parse_params(rest);
                let username = params.iter().find(|(k, _)| k == "username")?.1.clone();
                Some(Presented::Digest { username, params })
            }
            _ => None,
        }
    }

    /// Check credentials against the stored password.
    /// Accepted Digest request remembered -> same request again = [`Verdict::Stale`].
    pub(crate) fn verify(
        &self,
        presented: &Presented,
        request: &RequestInfo<'_>,
        password: &str,
    ) -> Verdict {
        match presented {
            Presented::Basic { password: p, .. } => {
                if ct_eq(p.as_bytes(), password.as_bytes()) {
                    Verdict::Valid
                } else {
                    Verdict::Invalid
                }
            }
            Presented::Digest { username, params } => {
                let get = |k: &str| {
                    params
                        .iter()
                        .find(|(key, _)| key == k)
                        .map(|(_, v)| v.as_str())
                };
                let (Some(realm), Some(nonce), Some(uri), Some(response)) =
                    (get("realm"), get("nonce"), get("uri"), get("response"))
                else {
                    return Verdict::Invalid;
                };
                if realm != self.realm || !uri_matches(uri, request.target) {
                    return Verdict::Invalid;
                }
                let Some((ts, id)) = self.issued_to(nonce, request.client) else {
                    return Verdict::Invalid;
                };
                let alg = match get("algorithm").map(str::to_ascii_uppercase).as_deref() {
                    None | Some("MD5") => Algorithm::Md5,
                    Some("SHA-256") => Algorithm::Sha256,
                    _ => return Verdict::Invalid,
                };
                let ha1 = hash(alg, &format!("{username}:{realm}:{password}"));
                let ha2 = hash(alg, &format!("{}:{uri}", request.method));
                let (expected, count) = match get("qop") {
                    Some("auth") => {
                        let (Some(nc), Some(cnonce)) = (get("nc"), get("cnonce")) else {
                            return Verdict::Invalid;
                        };
                        let Some(count) = u32::from_str_radix(nc, 16).ok().filter(|_| {
                            (1..=8).contains(&nc.len()) && nc.bytes().all(|b| b.is_ascii_hexdigit())
                        }) else {
                            return Verdict::Invalid;
                        };
                        (
                            hash(alg, &format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")),
                            Some(count),
                        )
                    }
                    // RFC 2069 (no qop): still seen on old CPEs.
                    None if self.allow_no_qop => (hash(alg, &format!("{ha1}:{nonce}:{ha2}")), None),
                    None | Some(_) => return Verdict::Invalid,
                };
                if !ct_eq(
                    expected.as_bytes(),
                    response.to_ascii_lowercase().as_bytes(),
                ) {
                    return Verdict::Invalid;
                }
                // Password right -> only now touch the used-count memory
                // -> client without the password cannot fill it.
                if self.expired(ts) {
                    return Verdict::Stale;
                }
                let Some(count) = count else {
                    return Verdict::Valid;
                };
                let oldest_valid = Self::now().saturating_sub(self.nonce_lifetime.as_secs());
                let fresh = match self.used.lock() {
                    Ok(mut used) => used.claim((ts, id), count, oldest_valid, self.max_tracked),
                    // Poisoned lock -> only replay protection lost, not logins.
                    Err(_) => true,
                };
                if fresh {
                    Verdict::Valid
                } else {
                    Verdict::Stale
                }
            }
        }
    }
}

/// RFC 2069 Digest response (no qop): CPEs with old HTTP stacks.
pub(crate) fn legacy_digest(
    sha256: bool,
    username: &str,
    realm: &str,
    password: &str,
    method: &str,
    uri: &str,
    nonce: &str,
) -> String {
    let alg = if sha256 {
        Algorithm::Sha256
    } else {
        Algorithm::Md5
    };
    let ha1 = hash(alg, &format!("{username}:{realm}:{password}"));
    let ha2 = hash(alg, &format!("{method}:{uri}"));
    hash(alg, &format!("{ha1}:{nonce}:{ha2}"))
}

/// Input of a client Digest computation (qop=auth).
#[derive(Debug, Clone, Copy)]
pub struct DigestInput<'a> {
    /// SHA-256, else MD5.
    pub sha256: bool,
    pub username: &'a str,
    /// From the challenge.
    pub realm: &'a str,
    pub password: &'a str,
    pub method: &'a str,
    pub uri: &'a str,
    /// From the challenge.
    pub nonce: &'a str,
    /// Nonce count, e.g. `00000001`.
    pub nc: &'a str,
    /// Client nonce.
    pub cnonce: &'a str,
}

/// Client Digest `response` value (tests + connection-request client).
pub fn digest_response(i: &DigestInput<'_>) -> String {
    let alg = if i.sha256 {
        Algorithm::Sha256
    } else {
        Algorithm::Md5
    };
    let ha1 = hash(alg, &format!("{}:{}:{}", i.username, i.realm, i.password));
    let ha2 = hash(alg, &format!("{}:{}", i.method, i.uri));
    hash(
        alg,
        &format!("{ha1}:{}:{}:{}:auth:{ha2}", i.nonce, i.nc, i.cnonce),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7));

    fn nonce_of(challenge: &str) -> String {
        parse_params(challenge.trim_start_matches("Digest "))
            .into_iter()
            .find(|(k, _)| k == "nonce")
            .map(|(_, v)| v)
            .unwrap_or_default()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or_else(|_| panic!("{s}"))
    }

    fn req(client: IpAddr) -> RequestInfo<'static> {
        RequestInfo {
            method: "POST",
            target: "/acs",
            client,
        }
    }

    /// Digest `Authorization` value for user `cpe`, password `pw`.
    fn header(nonce: &str, uri: &str, nc: &str, sha256: bool) -> String {
        let resp = digest_response(&DigestInput {
            sha256,
            username: "cpe",
            realm: "dhonomos",
            password: "pw",
            method: "POST",
            uri,
            nonce,
            nc,
            cnonce: "abc",
        });
        let alg = if sha256 { "SHA-256" } else { "MD5" };
        format!(
            r#"Digest username="cpe", realm="dhonomos", nonce="{nonce}", uri="{uri}", algorithm={alg}, qop=auth, nc={nc}, cnonce="abc", response="{resp}""#
        )
    }

    fn authenticator() -> Authenticator {
        Authenticator::new(AuthMode::Digest, "dhonomos", Duration::from_secs(300))
    }

    fn check(a: &Authenticator, client: IpAddr, header: &str) -> Verdict {
        let p = a.parse(Some(header)).unwrap_or_else(|| panic!("parse"));
        a.verify(&p, &req(client), "pw")
    }

    #[test]
    fn rfc_2617_md5_example() {
        // RFC 2617 section 3.5 example.
        let r = digest_response(&DigestInput {
            sha256: false,
            username: "Mufasa",
            realm: "testrealm@host.com",
            password: "Circle Of Life",
            method: "GET",
            uri: "/dir/index.html",
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093",
            nc: "00000001",
            cnonce: "0a4f113b",
        });
        assert_eq!(r, "6629fae49393a05397450978507c4ef1");
    }

    #[test]
    fn digest_round_trip_both_algorithms() {
        let a = authenticator();
        let challenges = a.challenges(CLIENT, false);
        assert_eq!(challenges.len(), 2);
        assert!(challenges.iter().all(|c| !c.contains("stale")));
        for (i, (sha, challenge)) in [(true, &challenges[0]), (false, &challenges[1])]
            .into_iter()
            .enumerate()
        {
            // Both challenges = same nonce -> 2nd answer = its next use.
            let nonce = nonce_of(challenge);
            let h = header(&nonce, "/acs", &format!("{:08x}", i + 1), sha);
            let p = a.parse(Some(&h)).unwrap_or_else(|| panic!("parse failed"));
            assert_eq!(p.username(), "cpe");
            // Wrong password + wrong method leave no trace -> right one still works.
            assert_eq!(a.verify(&p, &req(CLIENT), "wrong"), Verdict::Invalid);
            let get = RequestInfo {
                method: "GET",
                ..req(CLIENT)
            };
            assert_eq!(a.verify(&p, &get, "pw"), Verdict::Invalid);
            assert_eq!(a.verify(&p, &req(CLIENT), "pw"), Verdict::Valid);
        }
    }

    #[test]
    fn forged_or_expired_nonces_fail() {
        let a = authenticator();
        let other = authenticator();
        let foreign = nonce_of(&other.challenges(CLIENT, false)[1]);
        assert!(a.issued_to(&foreign, CLIENT).is_none());
        assert_eq!(
            check(&a, CLIENT, &header(&foreign, "/acs", "00000001", false)),
            Verdict::Invalid
        );
        assert!(a.issued_to("garbage", CLIENT).is_none());
        assert!(a.issued_to("1-2-3", CLIENT).is_none());
        assert!(a.issued_to("1-2", CLIENT).is_none());
        // Own nonce, issued 301 s ago: right response -> stale, wrong -> rejected.
        let old = a.nonce_at(Authenticator::now() - 301, CLIENT);
        assert!(a.issued_to(&old, CLIENT).is_some());
        assert_eq!(
            check(&a, CLIENT, &header(&old, "/acs", "00000001", false)),
            Verdict::Stale
        );
        let bad = header(&old, "/acs", "00000001", false).replace("response=\"", "response=\"0");
        assert_eq!(check(&a, CLIENT, &bad), Verdict::Invalid);
        // Forged timestamp on a valid MAC -> nonce not younger.
        let (_, rest) = old.split_once('-').unwrap_or_default();
        let young = format!("{}-{rest}", Authenticator::now());
        assert!(a.issued_to(&young, CLIENT).is_none());
        assert!(
            a.issued_to(&a.nonce_at(Authenticator::now(), CLIENT), CLIENT)
                .is_some()
        );
    }

    #[test]
    fn every_challenge_gets_its_own_nonce() {
        let a = authenticator();
        let first = nonce_of(&a.challenges(CLIENT, false)[0]);
        let second = nonce_of(&a.challenges(CLIENT, false)[0]);
        assert_ne!(
            first, second,
            "even within the same second, for the same client"
        );
    }

    #[test]
    fn stale_flag_is_in_the_challenge_only_when_asked() {
        let a = authenticator();
        for c in a.challenges(CLIENT, true) {
            assert!(c.ends_with(", stale=true"), "{c}");
        }
    }

    #[test]
    fn nonces_belong_to_the_client_they_were_issued_to() {
        let a = authenticator();
        let nonce = nonce_of(&a.challenges(CLIENT, false)[1]);
        let h = header(&nonce, "/acs", "00000001", false);
        let elsewhere = ip("192.0.2.8");
        assert_eq!(check(&a, elsewhere, &h), Verdict::Invalid);
        assert_eq!(check(&a, CLIENT, &h), Verdict::Valid);

        // IPv6: /64 only. Privacy addresses of one subscriber change.
        let v6 = ip("2001:db8:1:2::10");
        let same_prefix = ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd");
        let other_prefix = ip("2001:db8:1:3::10");
        let nonce = nonce_of(&a.challenges(v6, false)[1]);
        let h = header(&nonce, "/acs", "00000001", false);
        assert_eq!(check(&a, other_prefix, &h), Verdict::Invalid);
        assert_eq!(check(&a, same_prefix, &h), Verdict::Valid);

        // Switched off -> nonce works from anywhere.
        let a = authenticator().bind_client(false);
        let nonce = nonce_of(&a.challenges(CLIENT, false)[1]);
        let h = header(&nonce, "/acs", "00000001", false);
        assert_eq!(check(&a, elsewhere, &h), Verdict::Valid);
    }

    #[test]
    fn a_used_nonce_count_is_not_accepted_again() {
        let a = authenticator();
        let nonce = nonce_of(&a.challenges(CLIENT, false)[1]);
        let first = header(&nonce, "/acs", "00000001", false);
        assert_eq!(check(&a, CLIENT, &first), Verdict::Valid);
        assert_eq!(check(&a, CLIENT, &first), Verdict::Stale, "replayed header");
        // Next count ok; lower or equal -> stale.
        assert_eq!(
            check(&a, CLIENT, &header(&nonce, "/acs", "00000003", false)),
            Verdict::Valid
        );
        assert_eq!(
            check(&a, CLIENT, &header(&nonce, "/acs", "00000002", false)),
            Verdict::Stale
        );
        assert_eq!(
            check(&a, CLIENT, &header(&nonce, "/acs", "00000004", false)),
            Verdict::Valid
        );
        // Other nonce -> starts at 1 again.
        let nonce2 = a.nonce_at(Authenticator::now() - 1, CLIENT);
        assert_eq!(
            check(&a, CLIENT, &header(&nonce2, "/acs", "00000001", false)),
            Verdict::Valid
        );
        // Malformed count -> rejected outright.
        for nc in ["", "0000000g", "123456789", "+1"] {
            assert_eq!(
                check(&a, CLIENT, &header(&nonce2, "/acs", nc, false)),
                Verdict::Invalid,
                "{nc:?}"
            );
        }
    }

    #[test]
    fn only_requests_with_the_password_are_remembered() {
        let a = authenticator().max_tracked(2);
        let remembered = |a: &Authenticator| a.used.lock().map_or(0, |u| u.0.len());
        // Wrong password -> never reaches the memory.
        let nonce = nonce_of(&a.challenges(CLIENT, false)[1]);
        let p = a
            .parse(Some(&header(&nonce, "/acs", "00000001", false)))
            .unwrap_or_else(|| panic!("parse"));
        assert_eq!(a.verify(&p, &req(CLIENT), "wrong"), Verdict::Invalid);
        assert_eq!(remembered(&a), 0);
        // Memory bounded: oldest nonce forgotten first.
        let now = Authenticator::now();
        for i in 0..5 {
            let nonce = a.nonce_at(now - 10 + i, CLIENT);
            assert_eq!(
                check(&a, CLIENT, &header(&nonce, "/acs", "00000001", false)),
                Verdict::Valid
            );
            assert!(remembered(&a) <= 2);
        }
        assert_eq!(remembered(&a), 2);
    }

    #[test]
    fn used_counts_of_expired_nonces_are_forgotten() {
        let mut counts = NonceCounts::default();
        assert!(counts.claim((100, "a"), 1, 0, 10));
        assert!(counts.claim((200, "b"), 1, 0, 10));
        assert!(!counts.claim((200, "b"), 1, 150, 10), "still remembered");
        assert_eq!(counts.0.len(), 1, "the nonce from 100 s is gone");
        assert!(
            counts.claim((100, "a"), 1, 150, 10),
            "forgotten means unknown"
        );
    }

    #[test]
    fn uri_must_name_the_request_target() {
        let a = authenticator();
        let nonce = nonce_of(&a.challenges(CLIENT, false)[1]);
        assert_eq!(
            check(&a, CLIENT, &header(&nonce, "/other", "00000001", false)),
            Verdict::Invalid
        );
        // Whole URL ok; other path or query not.
        assert_eq!(
            check(
                &a,
                CLIENT,
                &header(&nonce, "http://acs.example:7547/acs", "00000001", false)
            ),
            Verdict::Valid
        );
        assert!(uri_matches("/a?b=1", "/a?b=1"));
        assert!(uri_matches("https://h/a?b=1", "/a?b=1"));
        assert!(uri_matches("http://h", "/"));
        assert!(uri_matches("/a", "/a?b=1"), "the query may be left out");
        assert!(!uri_matches("/a?b=2", "/a?b=1"));
        assert!(!uri_matches("/a?b=1", "/a"));
        assert!(!uri_matches("http://h/a", "/b"));
        assert!(!uri_matches("ftp://h/a", "/a"));
        assert!(!uri_matches("/", "/a"));
        assert!(!uri_matches("", "/a"));
    }

    #[test]
    fn rfc_2069_responses_are_a_setting() {
        let nonce_for = |a: &Authenticator| nonce_of(&a.challenges(CLIENT, false)[1]);
        let legacy = |nonce: &str| {
            let resp = legacy_digest(false, "cpe", "dhonomos", "pw", "POST", "/acs", nonce);
            format!(
                r#"Digest username="cpe", realm="dhonomos", nonce="{nonce}", uri="/acs", algorithm=MD5, response="{resp}""#
            )
        };
        let a = authenticator();
        assert_eq!(check(&a, CLIENT, &legacy(&nonce_for(&a))), Verdict::Valid);
        let a = authenticator().allow_no_qop(false);
        assert_eq!(check(&a, CLIENT, &legacy(&nonce_for(&a))), Verdict::Invalid);
        // With qop -> same server ok.
        let h = header(&nonce_for(&a), "/acs", "00000001", false);
        assert_eq!(check(&a, CLIENT, &h), Verdict::Valid);
    }

    #[test]
    fn basic() {
        let a = Authenticator::new(AuthMode::Basic, "dhonomos", Duration::from_secs(300));
        let p = a.parse(Some("Basic Y3BlOnB3")).unwrap_or_else(|| panic!());
        assert_eq!(p.username(), "cpe");
        assert_eq!(a.verify(&p, &req(CLIENT), "pw"), Verdict::Valid);
        assert_eq!(a.verify(&p, &req(CLIENT), "other"), Verdict::Invalid);
        assert!(a.parse(Some("Digest username=\"x\"")).is_none());
    }

    #[test]
    fn param_parser_handles_quotes_and_commas() {
        let p = parse_params(r#"username="a, b", realm=r, nc=00000001 ,qop="auth", x="q\"q""#);
        assert_eq!(p[0], ("username".into(), "a, b".into()));
        assert_eq!(p[1], ("realm".into(), "r".into()));
        assert_eq!(p[2], ("nc".into(), "00000001".into()));
        assert_eq!(p[3], ("qop".into(), "auth".into()));
        assert_eq!(p[4], ("x".into(), "q\"q".into()));
    }
}
