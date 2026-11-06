//! Allowed targets of Connection Requests (SE-03: CPE-reported URL must not make the ACS a
//! proxy into its own network).
//!
//! Check on the resolved IP -> host name that later resolves to a blocked address
//! (DNS rebinding) still refused.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// IP network, e.g. `10.0.0.0/8`, `fd00::/8`. Bare address = /32 or /128.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// `ip` inside the network? IPv4-mapped IPv6 = IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip.to_canonical()) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (addr, prefix) = s.split_once('/').unwrap_or((s, ""));
        let net: IpAddr = addr
            .parse()
            .map_err(|_| format!("invalid network {s:?}: expected e.g. 10.0.0.0/8"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = if prefix.is_empty() {
            max
        } else {
            prefix
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("invalid prefix length in {s:?}"))?
        };
        Ok(Self { net, prefix })
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.net, self.prefix)
    }
}

/// Never a sensible CR target: this host, link-local (incl. cloud metadata 169.254.169.254),
/// multicast, broadcast, unspecified.
/// No private ranges: ISP management networks often use them.
const BUILT_IN_DENY: &[&str] = &[
    "0.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "::/128",
    "::1/128",
    "fe80::/10",
    "ff00::/8",
];

/// Allow + deny lists for CR targets.
///
/// Order: explicit deny wins.
/// Allow list set -> only allow list (may re-open built-in denied ranges, e.g. loopback for
/// lab simulators).
/// No allow list -> all except the built-in deny list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressPolicy {
    allow: Vec<Cidr>,
    deny: Vec<Cidr>,
    built_in: bool,
}

impl Default for AddressPolicy {
    fn default() -> Self {
        Self::new(Vec::new(), Vec::new())
    }
}

impl AddressPolicy {
    /// Built-in deny list + `deny`. `allow` non-empty -> only `allow`, `deny` still wins.
    pub fn new(allow: Vec<Cidr>, deny: Vec<Cidr>) -> Self {
        Self {
            allow,
            deny,
            built_in: true,
        }
    }

    /// Permit every address (tests, labs).
    pub fn permit_all() -> Self {
        Self {
            allow: Vec::new(),
            deny: Vec::new(),
            built_in: false,
        }
    }

    /// CR to `ip` allowed?
    pub fn permits(&self, ip: IpAddr) -> bool {
        if self.deny.iter().any(|c| c.contains(ip)) {
            return false;
        }
        if !self.allow.is_empty() {
            return self.allow.iter().any(|c| c.contains(ip));
        }
        !(self.built_in
            && BUILT_IN_DENY
                .iter()
                .filter_map(|c| c.parse::<Cidr>().ok())
                .any(|c| c.contains(ip)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or_else(|_| panic!("{s}"))
    }

    fn cidr(s: &str) -> Cidr {
        s.parse().unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn networks() {
        assert!(cidr("10.0.0.0/8").contains(ip("10.200.1.1")));
        assert!(!cidr("10.0.0.0/8").contains(ip("11.0.0.1")));
        assert!(cidr("0.0.0.0/0").contains(ip("203.0.113.1")));
        assert!(!cidr("0.0.0.0/0").contains(ip("2001:db8::1")));
        assert!(cidr("fd00::/8").contains(ip("fd12::1")));
        assert!(cidr("192.0.2.7").contains(ip("192.0.2.7")));
        assert!(!cidr("192.0.2.7").contains(ip("192.0.2.8")));
        // IPv4-mapped IPv6 = IPv4.
        assert!(cidr("127.0.0.0/8").contains(ip("::ffff:127.0.0.1")));
        assert_eq!(cidr("10.0.0.0/8").to_string(), "10.0.0.0/8");
        for bad in ["10.0.0.0/33", "fd00::/129", "nonsense", "10.0.0.0/x"] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad}");
        }
    }

    #[test]
    fn default_policy() {
        let p = AddressPolicy::default();
        for denied in [
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "::ffff:169.254.169.254",
            "239.1.1.1",
        ] {
            assert!(!p.permits(ip(denied)), "{denied}");
        }
        for permitted in ["203.0.113.5", "10.1.2.3", "100.64.0.9", "2001:db8::5"] {
            assert!(p.permits(ip(permitted)), "{permitted}");
        }
        assert!(AddressPolicy::permit_all().permits(ip("127.0.0.1")));
    }

    #[test]
    fn allow_and_deny_lists() {
        let p = AddressPolicy::new(
            vec![cidr("10.0.0.0/8"), cidr("127.0.0.0/8")],
            vec![cidr("10.9.0.0/16")],
        );
        assert!(p.permits(ip("10.20.30.1")));
        assert!(p.permits(ip("127.0.0.1")), "allow re-opens built-in ranges");
        assert!(!p.permits(ip("10.9.1.1")), "deny wins");
        assert!(!p.permits(ip("203.0.113.5")), "only allowed networks");
        let p = AddressPolicy::new(Vec::new(), vec![cidr("10.0.0.0/8")]);
        assert!(!p.permits(ip("10.20.30.1")));
        assert!(p.permits(ip("203.0.113.5")));
    }
}
