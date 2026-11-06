//! IPv4 prefixes + allocation rules of overlay networks (design 13 sec. 3, sec. 4).
//!
//! Network = 1 tunnel prefix, from server address pool or set by an operator.
//! Hub = first host (`.1`); members -> lowest free host after it.
//! Device member may have LAN prefixes behind it ("site prefixes"), reached by other
//! members via the hub. Must not overlap each other or tunnel prefix
//! -> WireGuard routes by AllowedIPs inside one interface.

use std::collections::HashSet;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use time::{Duration, OffsetDateTime};

/// Shortest tunnel prefix (/16 -> 65,533 members).
pub const NETWORK_MIN_LEN: u8 = 16;
/// Longest tunnel prefix (/29 -> 5 members + hub).
pub const NETWORK_MAX_LEN: u8 = 29;
/// Tunnel prefix length when create request gives none.
pub const DEFAULT_NETWORK_LEN: u8 = 24;
/// Shortest address pool accepted.
pub const POOL_MIN_LEN: u8 = 8;
/// Longest address pool accepted: must hold a network.
pub const POOL_MAX_LEN: u8 = NETWORK_MAX_LEN;
/// Shortest site prefix. Wider -> claims a large part of the address space.
pub const SITE_MIN_LEN: u8 = 8;
/// Max site prefixes per member.
pub const MAX_SITE_PREFIXES: usize = 64;
/// First hub port handed out (WireGuard's customary port).
pub const DEFAULT_LISTEN_PORT: u16 = 51820;

/// Never a tunnel or LAN prefix: "this network", loopback, link-local, multicast,
/// reserved class E.
const RESERVED: [Ipv4Prefix; 4] = [
    Ipv4Prefix::from_parts(0x0000_0000, 8),
    Ipv4Prefix::from_parts(0x7f00_0000, 8),
    Ipv4Prefix::from_parts(0xa9fe_0000, 16),
    Ipv4Prefix::from_parts(0xe000_0000, 3),
];

/// IPv4 prefix, canonical form: host bits of the address = 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Prefix {
    network: u32,
    len: u8,
}

/// Why a prefix text was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParsePrefixError {
    /// Not `a.b.c.d/length`.
    #[error("{0:?} is not an IPv4 prefix (expected a.b.c.d/length, e.g. 10.77.0.0/24)")]
    Syntax(String),
    /// Address has bits set after the length.
    #[error("{given} has host bits set; the network address is {network}")]
    HostBits {
        /// As given.
        given: String,
        /// Probably meant.
        network: Ipv4Prefix,
    },
}

const fn mask(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - len) }
}

impl Ipv4Prefix {
    /// For constants: `network` must be canonical already.
    const fn from_parts(network: u32, len: u8) -> Self {
        Self { network, len }
    }

    /// `addr` with host bits cleared; `None` if `len` > 32.
    pub fn containing(addr: Ipv4Addr, len: u8) -> Option<Self> {
        (len <= 32).then(|| Self {
            network: u32::from(addr) & mask(len),
            len,
        })
    }

    /// Prefix `addr/len`; `None` if `len` > 32 or `addr` has host bits set.
    pub fn new(addr: Ipv4Addr, len: u8) -> Option<Self> {
        Self::containing(addr, len).filter(|p| p.network() == addr)
    }

    /// Network address = first address of the prefix.
    pub fn network(self) -> Ipv4Addr {
        Ipv4Addr::from(self.network)
    }

    /// Length, bits.
    pub fn prefix_len(self) -> u8 {
        self.len
    }

    /// Address count.
    pub fn size(self) -> u64 {
        1u64 << (32 - u32::from(self.len))
    }

    /// Last address (= broadcast address of a subnet).
    pub fn last(self) -> Ipv4Addr {
        Ipv4Addr::from(self.network | !mask(self.len))
    }

    pub fn contains_addr(self, addr: Ipv4Addr) -> bool {
        u32::from(addr) & mask(self.len) == self.network
    }

    /// `other` inside or equal.
    pub fn contains(self, other: Self) -> bool {
        self.len <= other.len && self.contains_addr(other.network())
    }

    /// Any shared address. Two prefixes: one contains the other, or apart.
    pub fn overlaps(self, other: Self) -> bool {
        self.contains(other) || other.contains(self)
    }

    /// Touches a range no tunnel or LAN can use (see `RESERVED`).
    pub fn is_reserved(self) -> bool {
        RESERVED.iter().any(|r| r.overlaps(self))
    }
}

impl fmt::Display for Ipv4Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), self.len)
    }
}

impl FromStr for Ipv4Prefix {
    type Err = ParsePrefixError;

    /// `a.b.c.d/length`, host bits clear. Bare address != prefix.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || ParsePrefixError::Syntax(s.chars().take(64).collect());
        let (addr, len) = s.split_once('/').ok_or_else(bad)?;
        if len.is_empty() || len.len() > 2 || !len.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        let len: u8 = len.parse().map_err(|_| bad())?;
        let addr: Ipv4Addr = addr.parse().map_err(|_| bad())?;
        let network = Self::containing(addr, len).ok_or_else(bad)?;
        if network.network() != addr {
            return Err(ParsePrefixError::HostBits {
                given: s.chars().take(64).collect(),
                network,
            });
        }
        Ok(network)
    }
}

/// As text, `"10.77.0.0/24"`.
impl serde::Serialize for Ipv4Prefix {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// From text, as strict as [`FromStr`].
impl<'de> serde::Deserialize<'de> for Ipv4Prefix {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Why a tunnel prefix was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetworkPrefixError {
    /// Length outside [`NETWORK_MIN_LEN`]..=[`NETWORK_MAX_LEN`].
    #[error("the prefix length must be between {NETWORK_MIN_LEN} and {NETWORK_MAX_LEN}")]
    Length,
    /// Address pool outside [`POOL_MIN_LEN`]..=[`POOL_MAX_LEN`].
    #[error("the address pool must be an IPv4 prefix between /{POOL_MIN_LEN} and /{POOL_MAX_LEN}")]
    PoolLength,
    /// Prefix touches a reserved range.
    #[error("{0} is in a reserved range (this network, loopback, link-local, multicast)")]
    Reserved(Ipv4Prefix),
    /// Block of this length > pool.
    #[error("a /{len} block does not fit in the address pool {pool}")]
    LargerThanPool {
        /// Requested length.
        len: u8,
        pool: Ipv4Prefix,
    },
    /// Each block of this length in the pool overlaps a network.
    #[error("the address pool {pool} has no free /{len} block left")]
    Exhausted {
        /// Requested length.
        len: u8,
        pool: Ipv4Prefix,
    },
    /// Prefix overlaps tunnel prefix of another network.
    #[error("{prefix} overlaps {other}, the tunnel prefix of another network")]
    Overlaps {
        /// Refused prefix.
        prefix: Ipv4Prefix,
        /// Prefix it hits.
        other: Ipv4Prefix,
    },
}

impl NetworkPrefixError {
    /// Valid request, but hit current state (pool used up, prefix taken)
    /// -> not wrong in itself.
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Exhausted { .. } | Self::Overlaps { .. })
    }
}

/// Check the server address pool setting.
pub fn check_pool(pool: Ipv4Prefix) -> Result<(), NetworkPrefixError> {
    if !(POOL_MIN_LEN..=POOL_MAX_LEN).contains(&pool.prefix_len()) {
        return Err(NetworkPrefixError::PoolLength);
    }
    if pool.is_reserved() {
        return Err(NetworkPrefixError::Reserved(pool));
    }
    Ok(())
}

/// Lowest free aligned `/len` block in `pool`, no overlap with `taken` tunnel prefixes
/// (other networks of the tenant).
pub fn allocate_network_prefix(
    pool: Ipv4Prefix,
    len: u8,
    taken: &[Ipv4Prefix],
) -> Result<Ipv4Prefix, NetworkPrefixError> {
    if !(NETWORK_MIN_LEN..=NETWORK_MAX_LEN).contains(&len) {
        return Err(NetworkPrefixError::Length);
    }
    if len < pool.prefix_len() {
        return Err(NetworkPrefixError::LargerThanPool { len, pool });
    }
    // Pool starts on a boundary of its own length -> each 1-block step aligned too.
    let block = 1u32 << (32 - u32::from(len));
    let mut next = Some(pool.network);
    while let Some(start) = next {
        let candidate = Ipv4Prefix {
            network: start,
            len,
        };
        if !pool.contains(candidate) {
            break;
        }
        if !taken.iter().any(|t| t.overlaps(candidate)) {
            return Ok(candidate);
        }
        next = start.checked_add(block);
    }
    Err(NetworkPrefixError::Exhausted { len, pool })
}

/// Check operator-chosen tunnel prefix: length, usable range, no overlap with `taken`.
/// Outside the address pool = OK.
pub fn check_network_prefix(
    prefix: Ipv4Prefix,
    taken: &[Ipv4Prefix],
) -> Result<(), NetworkPrefixError> {
    if !(NETWORK_MIN_LEN..=NETWORK_MAX_LEN).contains(&prefix.prefix_len()) {
        return Err(NetworkPrefixError::Length);
    }
    if prefix.is_reserved() {
        return Err(NetworkPrefixError::Reserved(prefix));
    }
    if let Some(other) = taken.iter().find(|t| t.overlaps(prefix)) {
        return Err(NetworkPrefixError::Overlaps {
            prefix,
            other: *other,
        });
    }
    Ok(())
}

/// Hub address = first host of the tunnel prefix.
pub fn hub_address(network: Ipv4Prefix) -> Ipv4Addr {
    Ipv4Addr::from(network.network.saturating_add(1))
}

/// Member address, held now or before, + revoke time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsedAddress {
    pub address: Ipv4Addr,
    /// Member revoke time; `None` -> member still holds the address.
    pub revoked_at: Option<OffsetDateTime>,
}

/// Addresses not to give out at `now`: members not revoked + revoked `< reuse_delay` ago.
/// Why: peer with old config must not meet a new owner of its address.
pub fn addresses_in_use(
    rows: &[UsedAddress],
    now: OffsetDateTime,
    reuse_delay: Duration,
) -> HashSet<Ipv4Addr> {
    rows.iter()
        .filter(|r| match r.revoked_at {
            None => true,
            // Deadline overflow -> never passes.
            Some(at) => at.checked_add(reuse_delay).is_none_or(|free| now < free),
        })
        .map(|r| r.address)
        .collect()
}

/// Lowest host not in `in_use`. Never network address, broadcast, hub (`.1`).
/// `None` -> network full.
pub fn allocate_member_address(
    network: Ipv4Prefix,
    in_use: &HashSet<Ipv4Addr>,
) -> Option<Ipv4Addr> {
    let first = network.network.checked_add(2)?;
    let last = u32::from(network.last()).checked_sub(1)?;
    (first..=last)
        .map(Ipv4Addr::from)
        .find(|a| !in_use.contains(a))
}

/// Why a list of site prefixes was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SitePrefixError {
    /// More than [`MAX_SITE_PREFIXES`].
    #[error("a member has at most {MAX_SITE_PREFIXES} site prefixes")]
    TooMany,
    /// `0.0.0.0/0`.
    #[error("the default route 0.0.0.0/0 cannot be a site prefix")]
    Default,
    /// Shorter than [`SITE_MIN_LEN`].
    #[error("{0} is shorter than /{SITE_MIN_LEN}")]
    TooShort(Ipv4Prefix),
    /// Prefix touches a reserved range.
    #[error("{0} is in a reserved range (this network, loopback, link-local, multicast)")]
    Reserved(Ipv4Prefix),
    /// 2 list entries overlap (or equal).
    #[error("{0} and {1} in the list overlap")]
    Repeated(Ipv4Prefix, Ipv4Prefix),
    /// Prefix overlaps tunnel prefix of the network.
    #[error("{prefix} overlaps {network}, the tunnel prefix of the network")]
    OverlapsNetwork {
        /// Refused prefix.
        prefix: Ipv4Prefix,
        /// Tunnel prefix.
        network: Ipv4Prefix,
    },
    /// Prefix overlaps a site prefix of another member.
    #[error("{prefix} overlaps {other}, a site prefix of another member of the network")]
    OverlapsMember {
        /// Refused prefix.
        prefix: Ipv4Prefix,
        /// Prefix it hits.
        other: Ipv4Prefix,
    },
}

impl SitePrefixError {
    /// Valid list, but hit current network state -> not wrong in itself.
    pub fn is_conflict(&self) -> bool {
        matches!(
            self,
            Self::OverlapsNetwork { .. } | Self::OverlapsMember { .. }
        )
    }
}

/// Check new site prefixes of a member: each usable, not default route.
/// No overlap with: rest of list, tunnel prefix `network`, `others`
/// (site prefixes of other non-revoked members of the network).
pub fn check_site_prefixes(
    network: Ipv4Prefix,
    prefixes: &[Ipv4Prefix],
    others: &[Ipv4Prefix],
) -> Result<(), SitePrefixError> {
    if prefixes.len() > MAX_SITE_PREFIXES {
        return Err(SitePrefixError::TooMany);
    }
    for (i, &prefix) in prefixes.iter().enumerate() {
        if prefix.prefix_len() == 0 {
            return Err(SitePrefixError::Default);
        }
        if prefix.prefix_len() < SITE_MIN_LEN {
            return Err(SitePrefixError::TooShort(prefix));
        }
        if prefix.is_reserved() {
            return Err(SitePrefixError::Reserved(prefix));
        }
        if let Some(&twin) = prefixes[..i].iter().find(|p| p.overlaps(prefix)) {
            return Err(SitePrefixError::Repeated(twin, prefix));
        }
        if prefix.overlaps(network) {
            return Err(SitePrefixError::OverlapsNetwork { prefix, network });
        }
        if let Some(&other) = others.iter().find(|o| o.overlaps(prefix)) {
            return Err(SitePrefixError::OverlapsMember { prefix, other });
        }
    }
    Ok(())
}

/// Lowest hub port from [`DEFAULT_LISTEN_PORT`] up, not in `used`.
pub fn lowest_free_port(used: &[u16]) -> Option<u16> {
    let used: HashSet<u16> = used.iter().copied().collect();
    (DEFAULT_LISTEN_PORT..=u16::MAX).find(|p| !used.contains(p))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn p(s: &str) -> Ipv4Prefix {
        s.parse().unwrap()
    }

    fn a(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn prefixes_are_read_strictly() {
        assert_eq!(p("10.77.0.0/24").to_string(), "10.77.0.0/24");
        assert_eq!(p("0.0.0.0/0").prefix_len(), 0);
        assert_eq!(p("192.168.1.7/32").network(), a("192.168.1.7"));
        // Host bits -> operator probably meant other prefix: refused + hint.
        assert_eq!(
            "10.77.0.5/24".parse::<Ipv4Prefix>(),
            Err(ParsePrefixError::HostBits {
                given: "10.77.0.5/24".into(),
                network: p("10.77.0.0/24"),
            })
        );
        for bad in [
            "10.77.0.0",
            "10.77.0.0/",
            "10.77.0.0/33",
            "10.77.0.0/+24",
            "10.77.0.0/-1",
            "10.77.0.0/024",
            "10.77.0.0/2 4",
            "010.77.0.0/24",
            "10.77.0/24",
            "::/0",
            "fd00::/64",
            "",
            "/24",
        ] {
            assert!(
                matches!(bad.parse::<Ipv4Prefix>(), Err(ParsePrefixError::Syntax(_))),
                "{bad:?}"
            );
        }
        // Long input -> not echoed back whole.
        let long = "x".repeat(1000);
        let Err(ParsePrefixError::Syntax(shown)) = long.parse::<Ipv4Prefix>() else {
            panic!("accepted");
        };
        assert_eq!(shown.len(), 64);
    }

    #[test]
    fn containment_and_overlap() {
        let net = p("10.77.0.0/24");
        assert!(net.contains(p("10.77.0.128/25")));
        assert!(net.contains(net));
        assert!(!net.contains(p("10.77.0.0/16")));
        assert!(net.overlaps(p("10.77.0.0/16")) && p("10.77.0.0/16").overlaps(net));
        assert!(!net.overlaps(p("10.77.1.0/24")));
        assert!(net.contains_addr(a("10.77.0.255")) && !net.contains_addr(a("10.77.1.0")));
        assert_eq!(net.size(), 256);
        assert_eq!(net.last(), a("10.77.0.255"));
        assert_eq!(p("0.0.0.0/0").size(), 1 << 32);
        assert_eq!(p("0.0.0.0/0").last(), a("255.255.255.255"));
        assert!(p("0.0.0.0/0").overlaps(net));
        assert_eq!(Ipv4Prefix::new(a("10.77.0.1"), 24), None);
        assert_eq!(Ipv4Prefix::new(a("10.77.0.0"), 33), None);
        assert_eq!(Ipv4Prefix::containing(a("10.77.0.9"), 24), Some(net));
    }

    #[test]
    fn reserved_ranges() {
        for r in [
            "0.0.0.0/8",
            "127.0.0.0/8",
            "127.5.0.0/16",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "240.0.0.0/8",
            "255.255.255.0/24",
        ] {
            assert!(p(r).is_reserved(), "{r}");
        }
        for ok in [
            "10.0.0.0/8",
            "100.64.0.0/10",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ] {
            assert!(!p(ok).is_reserved(), "{ok}");
        }
    }

    #[test]
    fn the_pool_setting_is_checked() {
        assert_eq!(check_pool(p("10.77.0.0/16")), Ok(()));
        assert_eq!(check_pool(p("10.0.0.0/8")), Ok(()));
        assert_eq!(check_pool(p("10.77.0.0/29")), Ok(()));
        assert_eq!(
            check_pool(p("10.0.0.0/7")),
            Err(NetworkPrefixError::PoolLength)
        );
        assert_eq!(
            check_pool(p("10.77.0.0/30")),
            Err(NetworkPrefixError::PoolLength)
        );
        assert_eq!(
            check_pool(p("127.0.0.0/8")),
            Err(NetworkPrefixError::Reserved(p("127.0.0.0/8")))
        );
    }

    #[test]
    fn networks_take_the_lowest_free_aligned_block() {
        let pool = p("10.77.0.0/16");
        assert_eq!(
            allocate_network_prefix(pool, 24, &[]),
            Ok(p("10.77.0.0/24"))
        );
        // 2nd network -> next block.
        assert_eq!(
            allocate_network_prefix(pool, 24, &[p("10.77.0.0/24")]),
            Ok(p("10.77.1.0/24"))
        );
        // Fill holes before extending the end.
        assert_eq!(
            allocate_network_prefix(pool, 24, &[p("10.77.0.0/24"), p("10.77.2.0/24")]),
            Ok(p("10.77.1.0/24"))
        );
        // Bigger network in the way -> skipped as a whole.
        assert_eq!(
            allocate_network_prefix(pool, 24, &[p("10.77.0.0/23")]),
            Ok(p("10.77.2.0/24"))
        );
        // Smaller one -> its /24 taken; block not squeezed in next to it.
        assert_eq!(
            allocate_network_prefix(pool, 24, &[p("10.77.0.128/25")]),
            Ok(p("10.77.1.0/24"))
        );
        // Other block sizes -> aligned to own size.
        assert_eq!(
            allocate_network_prefix(pool, 25, &[p("10.77.0.0/26")]),
            Ok(p("10.77.0.128/25"))
        );
        assert_eq!(
            allocate_network_prefix(pool, 29, &[p("10.77.0.0/29"), p("10.77.0.16/29")]),
            Ok(p("10.77.0.8/29"))
        );
        assert_eq!(
            allocate_network_prefix(pool, 20, &[p("10.77.0.0/24")]),
            Ok(p("10.77.16.0/20"))
        );
        assert_eq!(allocate_network_prefix(pool, 16, &[]), Ok(pool));
        // Taken prefix covering whole pool -> nothing left; ones outside -> no effect.
        assert_eq!(
            allocate_network_prefix(pool, 24, &[p("192.168.0.0/24"), p("10.0.0.0/8")]),
            Err(NetworkPrefixError::Exhausted { len: 24, pool }),
            "a /8 network covers the whole pool"
        );
        assert_eq!(
            allocate_network_prefix(pool, 24, &[p("192.168.0.0/24")]),
            Ok(p("10.77.0.0/24"))
        );
    }

    #[test]
    fn the_pool_runs_out() {
        let pool = p("10.77.0.0/24");
        let mut taken = Vec::new();
        for want in [
            "10.77.0.0/26",
            "10.77.0.64/26",
            "10.77.0.128/26",
            "10.77.0.192/26",
        ] {
            let got = allocate_network_prefix(pool, 26, &taken).unwrap();
            assert_eq!(got, p(want));
            taken.push(got);
        }
        assert_eq!(
            allocate_network_prefix(pool, 26, &taken),
            Err(NetworkPrefixError::Exhausted { len: 26, pool })
        );
        // Smaller blocks do not fit either: pool full.
        assert!(allocate_network_prefix(pool, 29, &taken).is_err());
        // Freed block -> given out again.
        taken.remove(1);
        assert_eq!(
            allocate_network_prefix(pool, 26, &taken),
            Ok(p("10.77.0.64/26"))
        );
        // Last block of address space -> no overflow in the walk.
        let top = p("255.255.0.0/16");
        assert_eq!(
            allocate_network_prefix(top, 17, &[p("255.255.0.0/17")]),
            Ok(p("255.255.128.0/17"))
        );
        assert!(allocate_network_prefix(top, 17, &[top]).is_err());
        // Whole /16 pool of /24s: 256 blocks.
        let pool = p("10.77.0.0/16");
        let all: Vec<_> = (0..=255u32)
            .map(|i| Ipv4Prefix::new(Ipv4Addr::from(0x0a4d_0000 | (i << 8)), 24).unwrap())
            .collect();
        assert_eq!(
            allocate_network_prefix(pool, 24, &all),
            Err(NetworkPrefixError::Exhausted { len: 24, pool })
        );
        assert_eq!(
            allocate_network_prefix(pool, 24, &all[..255]),
            Ok(p("10.77.255.0/24"))
        );
    }

    #[test]
    fn allocation_lengths_are_limited() {
        let pool = p("10.77.0.0/16");
        for len in [0, 8, 15, 30, 32] {
            assert_eq!(
                allocate_network_prefix(pool, len, &[]),
                Err(NetworkPrefixError::Length),
                "/{len}"
            );
        }
        assert!(allocate_network_prefix(pool, 29, &[]).is_ok());
        // Pool < requested block.
        assert_eq!(
            allocate_network_prefix(p("10.77.0.0/24"), 20, &[]),
            Err(NetworkPrefixError::LargerThanPool {
                len: 20,
                pool: p("10.77.0.0/24")
            })
        );
        assert_eq!(
            allocate_network_prefix(p("10.77.0.0/24"), 24, &[]),
            Ok(p("10.77.0.0/24"))
        );
    }

    #[test]
    fn explicit_network_prefixes_are_checked() {
        let taken = [p("10.77.0.0/24"), p("172.16.8.0/22")];
        // Outside the pool = OK.
        assert_eq!(check_network_prefix(p("192.168.100.0/24"), &taken), Ok(()));
        assert_eq!(check_network_prefix(p("10.77.1.0/24"), &taken), Ok(()));
        assert_eq!(check_network_prefix(p("172.16.12.0/22"), &taken), Ok(()));
        // Equal, inside, containing -> all overlaps.
        for (new, other) in [
            ("10.77.0.0/24", "10.77.0.0/24"),
            ("10.77.0.128/25", "10.77.0.0/24"),
            ("10.77.0.0/16", "10.77.0.0/24"),
            ("172.16.9.0/24", "172.16.8.0/22"),
        ] {
            assert_eq!(
                check_network_prefix(p(new), &taken),
                Err(NetworkPrefixError::Overlaps {
                    prefix: p(new),
                    other: p(other)
                }),
                "{new}"
            );
        }
        for len in [8, 15, 30, 32] {
            let prefix = Ipv4Prefix::containing(a("192.168.0.0"), len).unwrap();
            assert_eq!(
                check_network_prefix(prefix, &[]),
                Err(NetworkPrefixError::Length)
            );
        }
        assert_eq!(check_network_prefix(p("192.168.0.0/16"), &[]), Ok(()));
        assert_eq!(check_network_prefix(p("192.168.0.0/29"), &[]), Ok(()));
        assert_eq!(
            check_network_prefix(p("127.1.0.0/24"), &[]),
            Err(NetworkPrefixError::Reserved(p("127.1.0.0/24")))
        );
        assert!(
            NetworkPrefixError::Exhausted {
                len: 24,
                pool: p("10.0.0.0/8")
            }
            .is_conflict()
        );
        assert!(!NetworkPrefixError::Length.is_conflict());
    }

    #[test]
    fn the_hub_takes_the_first_host() {
        assert_eq!(hub_address(p("10.77.0.0/24")), a("10.77.0.1"));
        assert_eq!(hub_address(p("10.77.8.0/21")), a("10.77.8.1"));
    }

    #[test]
    fn members_get_the_lowest_free_host_after_the_hub() {
        let net = p("10.77.0.0/24");
        let none = HashSet::new();
        assert_eq!(allocate_member_address(net, &none), Some(a("10.77.0.2")));
        let used: HashSet<_> = [a("10.77.0.2"), a("10.77.0.3"), a("10.77.0.5")].into();
        assert_eq!(allocate_member_address(net, &used), Some(a("10.77.0.4")));
        // Hub, network address, broadcast never given out, even if not in the set.
        let mut all: HashSet<Ipv4Addr> = (2..=254u32)
            .map(|i| Ipv4Addr::from(0x0a4d_0000 | i))
            .collect();
        assert_eq!(
            allocate_member_address(net, &all),
            None,
            "the .255 broadcast stays"
        );
        all.remove(&a("10.77.0.254"));
        assert_eq!(allocate_member_address(net, &all), Some(a("10.77.0.254")));
        // /29 -> 5 member addresses: net+2 .. net+6.
        let small = p("10.77.0.8/29");
        let mut used = HashSet::new();
        for want in [
            "10.77.0.10",
            "10.77.0.11",
            "10.77.0.12",
            "10.77.0.13",
            "10.77.0.14",
        ] {
            let got = allocate_member_address(small, &used).unwrap();
            assert_eq!(got, a(want));
            used.insert(got);
        }
        assert_eq!(allocate_member_address(small, &used), None);
        // /16 -> starts at .0.2, crosses 3rd octet.
        let big = p("10.77.0.0/16");
        let used: HashSet<_> = (2..=255u32)
            .map(|i| Ipv4Addr::from(0x0a4d_0000 | i))
            .collect();
        assert_eq!(allocate_member_address(big, &used), Some(a("10.77.1.0")));
    }

    #[test]
    fn revoked_addresses_wait_out_the_reuse_delay() {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(100);
        let rows = [
            UsedAddress {
                address: a("10.77.0.2"),
                revoked_at: None,
            },
            UsedAddress {
                address: a("10.77.0.3"),
                revoked_at: Some(now - Duration::hours(1)),
            },
            UsedAddress {
                address: a("10.77.0.4"),
                revoked_at: Some(now - Duration::hours(25)),
            },
            UsedAddress {
                address: a("10.77.0.5"),
                revoked_at: Some(now - Duration::hours(24)),
            },
            UsedAddress {
                address: a("10.77.0.6"),
                revoked_at: Some(now - Duration::minutes(1439)),
            },
        ];
        let day = Duration::hours(24);
        let used = addresses_in_use(&rows, now, day);
        // Held, revoked 1 h ago, revoked 23 h 59 min ago -> taken; 24 h -> free.
        assert_eq!(
            used,
            [a("10.77.0.2"), a("10.77.0.3"), a("10.77.0.6")]
                .into_iter()
                .collect()
        );
        assert_eq!(
            allocate_member_address(p("10.77.0.0/24"), &used),
            Some(a("10.77.0.4"))
        );
        // No delay -> only live members hold addresses.
        let used = addresses_in_use(&rows, now, Duration::ZERO);
        assert_eq!(used, [a("10.77.0.2")].into_iter().collect());
        // Revoke time in the future (clock skew) -> address still held.
        let rows = [UsedAddress {
            address: a("10.77.0.9"),
            revoked_at: Some(now + Duration::hours(1)),
        }];
        assert_eq!(addresses_in_use(&rows, now, day).len(), 1);
        // Absurd delay -> no overflow.
        let rows = [UsedAddress {
            address: a("10.77.0.9"),
            revoked_at: Some(now),
        }];
        assert_eq!(addresses_in_use(&rows, now, Duration::MAX).len(), 1);
    }

    #[test]
    fn site_prefixes_must_not_collide() {
        let net = p("10.77.0.0/24");
        let others = [p("192.168.10.0/24"), p("172.20.0.0/16")];
        let ok = |list: &[&str]| {
            let list: Vec<_> = list.iter().map(|s| p(s)).collect();
            check_site_prefixes(net, &list, &others)
        };
        assert_eq!(ok(&[]), Ok(()));
        assert_eq!(ok(&["192.168.20.0/24", "192.168.30.0/24"]), Ok(()));
        assert_eq!(
            ok(&["10.0.0.0/8"]).unwrap_err(),
            SitePrefixError::OverlapsNetwork {
                prefix: p("10.0.0.0/8"),
                network: net
            }
        );
        assert_eq!(
            ok(&["10.77.0.64/26"]),
            Err(SitePrefixError::OverlapsNetwork {
                prefix: p("10.77.0.64/26"),
                network: net
            })
        );
        assert_eq!(ok(&["10.77.1.0/24"]), Ok(()));
        // Equal, contained, containing prefixes of other members -> collide.
        for (new, other) in [
            ("192.168.10.0/24", "192.168.10.0/24"),
            ("192.168.10.128/25", "192.168.10.0/24"),
            ("192.168.0.0/16", "192.168.10.0/24"),
            ("172.20.5.0/24", "172.20.0.0/16"),
        ] {
            assert_eq!(
                ok(&[new]),
                Err(SitePrefixError::OverlapsMember {
                    prefix: p(new),
                    other: p(other)
                }),
                "{new}"
            );
        }
        // Inside the list too.
        assert_eq!(
            ok(&["192.168.20.0/24", "192.168.20.0/24"]),
            Err(SitePrefixError::Repeated(
                p("192.168.20.0/24"),
                p("192.168.20.0/24")
            ))
        );
        assert_eq!(
            ok(&["192.168.20.0/24", "192.168.20.128/25"]),
            Err(SitePrefixError::Repeated(
                p("192.168.20.0/24"),
                p("192.168.20.128/25")
            ))
        );
    }

    #[test]
    fn site_prefixes_have_sane_sizes_and_ranges() {
        let net = p("10.77.0.0/24");
        let check = |s: &str| check_site_prefixes(net, &[p(s)], &[]);
        assert_eq!(check("0.0.0.0/0"), Err(SitePrefixError::Default));
        assert_eq!(
            check("128.0.0.0/1"),
            Err(SitePrefixError::TooShort(p("128.0.0.0/1")))
        );
        assert_eq!(
            check("192.0.0.0/7"),
            Err(SitePrefixError::TooShort(p("192.0.0.0/7")))
        );
        assert_eq!(check("192.0.0.0/8"), Ok(()));
        assert_eq!(check("192.168.1.0/24"), Ok(()));
        assert_eq!(
            check("192.168.1.7/32"),
            Ok(()),
            "a single host is a site too"
        );
        assert_eq!(
            check("127.0.0.0/8"),
            Err(SitePrefixError::Reserved(p("127.0.0.0/8")))
        );
        assert_eq!(
            check("224.0.0.0/8"),
            Err(SitePrefixError::Reserved(p("224.0.0.0/8")))
        );
        let many: Vec<_> = (0..=MAX_SITE_PREFIXES as u32)
            .map(|i| Ipv4Prefix::new(Ipv4Addr::from(0xc0a8_0000 | (i << 8)), 24).unwrap())
            .collect();
        assert_eq!(
            check_site_prefixes(net, &many, &[]),
            Err(SitePrefixError::TooMany)
        );
        assert_eq!(
            check_site_prefixes(net, &many[..MAX_SITE_PREFIXES], &[]),
            Ok(())
        );
        assert!(
            SitePrefixError::OverlapsMember {
                prefix: net,
                other: net
            }
            .is_conflict()
        );
        assert!(!SitePrefixError::Default.is_conflict());
    }

    #[test]
    fn hub_ports_start_at_the_customary_one() {
        assert_eq!(lowest_free_port(&[]), Some(51820));
        assert_eq!(lowest_free_port(&[51820, 51821, 22]), Some(51822));
        assert_eq!(lowest_free_port(&[51821]), Some(51820));
        let all: Vec<u16> = (DEFAULT_LISTEN_PORT..=u16::MAX).collect();
        assert_eq!(lowest_free_port(&all), None);
    }
}
