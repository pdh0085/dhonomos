//! Kernel state as plain data: links + WireGuard config + IPv4 addresses, policy rules,
//! routes of tables above the kernel's own.
//! Kernel layer reads it -> planner compares it with the desired state.

use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;

use dhonomos_wireguard::Ipv4Prefix;
use zeroize::Zeroizing;

/// PSK: 32 bytes, never all zeros (= WireGuard "none"). Zeroed on drop.
/// `Debug` = `********` -> never printed in logs or plans.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Psk(pub(crate) Zeroizing<[u8; 32]>);

impl fmt::Debug for Psk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("********")
    }
}

/// Planner input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Observed {
    /// All links, hub's + others.
    pub(crate) links: Vec<Link>,
    pub(crate) rules: Vec<Rule>,
    /// IPv4 routes of all tables > 255.
    pub(crate) routes: Vec<Route>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Link {
    pub(crate) name: String,
    pub(crate) index: u32,
    pub(crate) wireguard: bool,
    /// Admin up.
    pub(crate) up: bool,
    pub(crate) mtu: u32,
    /// IPv4 address + prefix length.
    pub(crate) addresses: Vec<(Ipv4Addr, u8)>,
    /// `/proc/sys/net/ipv4/conf/<name>/rp_filter`, trimmed. Hub links only.
    pub(crate) rp_filter: Option<String>,
    /// WireGuard config. Hub links only.
    pub(crate) device: Option<Device>,
}

/// WireGuard side of an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Device {
    /// Public key of the private key. `None` -> no private key set.
    pub(crate) public_key: Option<String>,
    /// UDP port.
    pub(crate) listen_port: u16,
    pub(crate) peers: Vec<Peer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Peer {
    /// Base64.
    pub(crate) public_key: String,
    pub(crate) allowed_ips: BTreeSet<Ipv4Prefix>,
    /// Also allowed IPs that are not canonical IPv4 prefixes (e.g. IPv6).
    pub(crate) other_allowed_ips: bool,
    /// `None` = no PSK (all zeros in the kernel).
    pub(crate) preshared_key: Option<Psk>,
    /// Persistent keepalive, s (0 = off).
    pub(crate) keepalive: u16,
}

/// IPv4 policy rule, only the fields that tell the hub's rules apart.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Rule {
    pub(crate) priority: u32,
    /// `iif` interface name.
    pub(crate) iif: Option<String>,
    /// Lookup table (0 = not a `lookup` rule).
    pub(crate) table: u32,
    /// Selectors or action other than `iif ... lookup <table>`.
    pub(crate) other: bool,
}

/// Route type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RouteKind {
    /// Delivered via an interface.
    Unicast,
    Unreachable,
    /// Other type (blackhole, prohibit, throw, ...) by number.
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Route {
    pub(crate) table: u32,
    pub(crate) dst: Ipv4Prefix,
    pub(crate) kind: RouteKind,
    /// Output interface name.
    pub(crate) oif: Option<String>,
    /// Output interface index -> delete exactly this route.
    pub(crate) oif_index: Option<u32>,
    /// Preferred source.
    pub(crate) src: Option<Ipv4Addr>,
    pub(crate) metric: u32,
    /// Gateway, multiple next hops or other attributes the hub never sets.
    pub(crate) other: bool,
}
