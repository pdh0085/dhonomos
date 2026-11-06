//! Planner: changes so that the kernel matches the hub state.
//! Pure: [`Desired`] vs [`Observed`] -> [`Action`]s in run order.
//!
//! Hub owns only: links `dwg<port>`, rules at exactly its priority with such a link as `iif`,
//! routing tables `base+1..=base+65535`. Never touch anything else.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::Ipv4Addr;

use dhonomos_wireguard::{
    HubState, Ipv4Prefix, interface_name, key_from_text, parse_interface_name,
};

use crate::observed::{Link, Observed, Psk, Route, RouteKind, Rule};

/// `rp_filter` of hub interfaces = loose.
/// Strict -> reverse-path check ignores the `iif` rule -> drops traffic from the sites.
pub(crate) const RP_FILTER: &str = "2";

/// Target kernel state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Desired {
    /// Hub public key. `None` = no key yet (dry run) -> no interface matches.
    pub(crate) public_key: Option<String>,
    /// Table of a network = this + its port.
    pub(crate) table_base: u32,
    /// Priority of the `iif` rules.
    pub(crate) rule_priority: u32,
    /// Sorted by port.
    pub(crate) interfaces: Vec<DesiredInterface>,
}

/// Interface of one network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DesiredInterface {
    /// `dwg<port>`.
    pub(crate) name: String,
    /// UDP port.
    pub(crate) port: u16,
    /// Hub address in the tunnel prefix.
    pub(crate) address: Ipv4Addr,
    /// Tunnel prefix.
    pub(crate) prefix: Ipv4Prefix,
    pub(crate) mtu: u32,
    pub(crate) table: u32,
    pub(crate) peers: Vec<DesiredPeer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DesiredPeer {
    pub(crate) public_key: String,
    pub(crate) allowed_ips: BTreeSet<Ipv4Prefix>,
    /// `None` = no PSK.
    pub(crate) preshared_key: Option<Psk>,
}

impl Desired {
    /// Kernel state for `state`.
    ///
    /// Port already seen -> network skipped. Key already seen in the network -> peer skipped.
    /// (Server never sends these.)
    /// Invalid PSK -> whole state fails -> kernel unchanged, never a peer without its PSK.
    pub(crate) fn from_state(
        state: &HubState,
        public_key: Option<String>,
        table_base: u32,
        rule_priority: u32,
    ) -> anyhow::Result<Self> {
        let mut by_port = BTreeMap::new();
        for n in &state.networks {
            if by_port.contains_key(&n.listen_port) {
                continue;
            }
            let mut keys = BTreeSet::new();
            let mut peers = Vec::new();
            for p in &n.peers {
                if !keys.insert(p.public_key.as_str()) {
                    continue;
                }
                let preshared_key = match &p.preshared_key {
                    Some(text) => Some(Psk(key_from_text(text).map_err(|_| {
                        anyhow::anyhow!(
                            "the pre-shared key of peer {} in network {} is not a key",
                            short_key(&p.public_key),
                            n.name
                        )
                    })?)),
                    None => None,
                };
                peers.push(DesiredPeer {
                    public_key: p.public_key.clone(),
                    allowed_ips: p.allowed_ips.iter().copied().collect(),
                    preshared_key,
                });
            }
            by_port.insert(
                n.listen_port,
                DesiredInterface {
                    name: interface_name(n.listen_port),
                    port: n.listen_port,
                    address: n.address,
                    prefix: n.prefix,
                    mtu: u32::from(n.mtu),
                    table: table_base + u32::from(n.listen_port),
                    peers,
                },
            );
        }
        Ok(Self {
            public_key,
            table_base,
            rule_priority,
            interfaces: by_port.into_values().collect(),
        })
    }

    /// `table` is a hub table.
    fn owns_table(&self, table: u32) -> bool {
        table > self.table_base && table - self.table_base <= u32::from(u16::MAX)
    }
}

/// Route target.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RouteTarget {
    /// Out of an interface, optional preferred source.
    Dev {
        iface: String,
        src: Option<Ipv4Addr>,
    },
    Unreachable,
}

/// Route the hub wants.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RouteSpec {
    pub(crate) table: u32,
    pub(crate) dst: Ipv4Prefix,
    pub(crate) target: RouteTarget,
}

impl RouteSpec {
    /// Kernel `route` = exactly this one.
    fn matches(&self, route: &Route) -> bool {
        if route.table != self.table || route.dst != self.dst || route.metric != 0 || route.other {
            return false;
        }
        match &self.target {
            RouteTarget::Dev { iface, src } => {
                route.kind == RouteKind::Unicast
                    && route.oif.as_deref() == Some(iface.as_str())
                    && route.src == *src
            }
            RouteTarget::Unreachable => route.kind == RouteKind::Unreachable && route.oif.is_none(),
        }
    }
}

impl fmt::Display for RouteSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.target {
            RouteTarget::Dev { iface, src: None } => write!(f, "{} dev {iface}", self.dst)?,
            RouteTarget::Dev {
                iface,
                src: Some(src),
            } => write!(f, "{} dev {iface} src {src}", self.dst)?,
            RouteTarget::Unreachable => write!(f, "unreachable {}", self.dst)?,
        }
        write!(f, " table {}", self.table)
    }
}

impl DesiredInterface {
    /// Routes of its table: tunnel prefix, site prefixes of each peer, unreachable default.
    /// Unreachable default -> tunnel traffic never takes the host default route.
    pub(crate) fn routes(&self) -> Vec<RouteSpec> {
        let dev = |src| RouteTarget::Dev {
            iface: self.name.clone(),
            src,
        };
        let mut routes = vec![RouteSpec {
            table: self.table,
            dst: self.prefix,
            target: dev(Some(self.address)),
        }];
        let sites: BTreeSet<Ipv4Prefix> = self
            .peers
            .iter()
            .flat_map(|p| p.allowed_ips.iter().copied())
            .filter(|ip| !self.prefix.contains(*ip))
            .collect();
        routes.extend(sites.into_iter().map(|dst| RouteSpec {
            table: self.table,
            dst,
            target: dev(None),
        }));
        routes.push(RouteSpec {
            table: self.table,
            dst: Ipv4Prefix::containing(Ipv4Addr::UNSPECIFIED, 0)
                .unwrap_or_else(|| unreachable!("0 is a valid length")),
            target: RouteTarget::Unreachable,
        });
        routes
    }
}

/// One kernel change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// Link delete -> its addresses + routes gone too.
    DeleteLink { name: String },
    /// Delete a policy rule.
    DeleteRule(Rule),
    /// Delete a route.
    DeleteRoute(Route),
    /// Create a WireGuard link.
    CreateLink { name: String },
    /// Set hub private key + listen port.
    ConfigureDevice { iface: String, listen_port: u16 },
    /// Remove a peer.
    RemovePeer { iface: String, public_key: String },
    /// Add peer, or set it: allowed IPs replaced, PSK set (`None` = none), keepalive cleared.
    /// PSK set from outside -> replaced.
    SetPeer {
        iface: String,
        public_key: String,
        allowed_ips: Vec<Ipv4Prefix>,
        preshared_key: Option<Psk>,
        new: bool,
    },
    /// Delete an IPv4 address.
    DeleteAddress {
        iface: String,
        address: Ipv4Addr,
        len: u8,
    },
    /// Add an IPv4 address.
    AddAddress {
        iface: String,
        address: Ipv4Addr,
        len: u8,
    },
    /// Set the MTU.
    SetMtu { iface: String, mtu: u32 },
    /// Set `rp_filter` = [`RP_FILTER`].
    SetRpFilter { iface: String },
    /// Set the link up.
    SetUp { iface: String },
    /// Add a route.
    AddRoute(RouteSpec),
    /// Add rule `iif <iface> lookup <table>` at `priority`.
    AddRule {
        iface: String,
        table: u32,
        priority: u32,
    },
}

/// Public key for logs: first 8 chars.
pub(crate) fn short_key(key: &str) -> String {
    let head: String = key.chars().take(8).collect();
    format!("{head}…")
}

fn list(ips: &[Ipv4Prefix]) -> String {
    if ips.is_empty() {
        return "(none)".into();
    }
    ips.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// PSK note in peer action text: present or not, never the key.
fn psk_note(psk: Option<&Psk>) -> &'static str {
    if psk.is_some() {
        " with a pre-shared key"
    } else {
        ""
    }
}

fn route_text(r: &Route) -> String {
    let mut s = match r.kind {
        RouteKind::Unicast => r.dst.to_string(),
        RouteKind::Unreachable => format!("unreachable {}", r.dst),
        RouteKind::Other(t) => format!("type {t} {}", r.dst),
    };
    if let Some(oif) = &r.oif {
        s.push_str(&format!(" dev {oif}"));
    }
    s.push_str(&format!(" table {}", r.table));
    s
}

fn rule_text(r: &Rule) -> String {
    format!("iif {} table {}", r.iif.as_deref().unwrap_or("?"), r.table)
}

impl Action {
    /// Text before run (dry run, failures).
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::DeleteLink { name } => format!("delete interface {name}"),
            Self::DeleteRule(r) => format!("delete rule {}", rule_text(r)),
            Self::DeleteRoute(r) => format!("delete route {}", route_text(r)),
            Self::CreateLink { name } => format!("create interface {name}"),
            Self::ConfigureDevice { iface, listen_port } => {
                format!("set private key and listen port {listen_port} on {iface}")
            }
            Self::RemovePeer { iface, public_key } => {
                format!("remove peer {} from {iface}", short_key(public_key))
            }
            Self::SetPeer {
                iface,
                public_key,
                allowed_ips,
                preshared_key,
                new,
            } => format!(
                "{} peer {} on {iface} allowed {}{}",
                if *new { "add" } else { "update" },
                short_key(public_key),
                list(allowed_ips),
                psk_note(preshared_key.as_ref())
            ),
            Self::DeleteAddress {
                iface,
                address,
                len,
            } => format!("delete address {address}/{len} from {iface}"),
            Self::AddAddress {
                iface,
                address,
                len,
            } => format!("add address {address}/{len} to {iface}"),
            Self::SetMtu { iface, mtu } => format!("set mtu {mtu} on {iface}"),
            Self::SetRpFilter { iface } => format!("set rp_filter {RP_FILTER} on {iface}"),
            Self::SetUp { iface } => format!("set {iface} up"),
            Self::AddRoute(r) => format!("add route {r}"),
            Self::AddRule {
                iface,
                table,
                priority,
            } => format!("add rule iif {iface} table {table} priority {priority}"),
        }
    }

    /// Text after run (log line).
    pub(crate) fn done(&self) -> String {
        match self {
            Self::DeleteLink { name } => format!("deleted interface {name}"),
            Self::DeleteRule(r) => format!("deleted rule {}", rule_text(r)),
            Self::DeleteRoute(r) => format!("deleted route {}", route_text(r)),
            Self::CreateLink { name } => format!("created interface {name}"),
            Self::ConfigureDevice { iface, listen_port } => {
                format!("set private key and listen port {listen_port} on {iface}")
            }
            Self::RemovePeer { iface, public_key } => {
                format!("peer removed {} from {iface}", short_key(public_key))
            }
            Self::SetPeer {
                iface,
                public_key,
                allowed_ips,
                preshared_key,
                new,
            } => format!(
                "peer {} {} on {iface} allowed {}{}",
                if *new { "added" } else { "updated" },
                short_key(public_key),
                list(allowed_ips),
                psk_note(preshared_key.as_ref())
            ),
            Self::DeleteAddress {
                iface,
                address,
                len,
            } => format!("deleted address {address}/{len} from {iface}"),
            Self::AddAddress {
                iface,
                address,
                len,
            } => format!("added address {address}/{len} to {iface}"),
            Self::SetMtu { iface, mtu } => format!("set mtu {mtu} on {iface}"),
            Self::SetRpFilter { iface } => format!("set rp_filter {RP_FILTER} on {iface}"),
            Self::SetUp { iface } => format!("set {iface} up"),
            Self::AddRoute(r) => format!("added route {r}"),
            Self::AddRule {
                iface,
                table,
                priority,
            } => format!("added rule iif {iface} table {table} priority {priority}"),
        }
    }
}

/// Actions so that `observed` = `desired`, in this order:
/// (1) delete unwanted hub links;
/// (2) delete unwanted hub rules + routes in hub tables;
/// (3) per interface by port: create, key + port, peers, address, MTU, `rp_filter`, up;
/// (4) add missing routes, then missing rules.
/// Kernel in sync -> no actions.
pub(crate) fn plan(desired: &Desired, observed: &Observed) -> Vec<Action> {
    let mut actions = Vec::new();
    let wanted: BTreeSet<&str> = desired.interfaces.iter().map(|i| i.name.as_str()).collect();

    // 1. Links.
    let mut kept: BTreeMap<&str, &Link> = BTreeMap::new();
    let mut deleted: BTreeSet<&str> = BTreeSet::new();
    for link in &observed.links {
        if parse_interface_name(&link.name).is_none() {
            continue;
        }
        if wanted.contains(link.name.as_str()) && link.wireguard {
            kept.insert(&link.name, link);
        } else {
            actions.push(Action::DeleteLink {
                name: link.name.clone(),
            });
            deleted.insert(&link.name);
        }
    }

    // 2. Rules, then routes.
    let wanted_rules: BTreeSet<(&str, u32)> = desired
        .interfaces
        .iter()
        .map(|i| (i.name.as_str(), i.table))
        .collect();
    let mut kept_rules: BTreeSet<(&str, u32)> = BTreeSet::new();
    for rule in &observed.rules {
        let Some(iif) = rule.iif.as_deref() else {
            continue;
        };
        if rule.priority != desired.rule_priority || parse_interface_name(iif).is_none() {
            continue;
        }
        let key = (iif, rule.table);
        if !rule.other && wanted_rules.contains(&key) && kept_rules.insert(key) {
            continue;
        }
        actions.push(Action::DeleteRule(rule.clone()));
    }
    let wanted_routes: Vec<RouteSpec> = desired
        .interfaces
        .iter()
        .flat_map(DesiredInterface::routes)
        .collect();
    let mut kept_routes = vec![false; wanted_routes.len()];
    for route in &observed.routes {
        if !desired.owns_table(route.table) {
            continue;
        }
        if route.oif.as_deref().is_some_and(|o| deleted.contains(o)) {
            continue; // Deleted with its link.
        }
        if let Some(i) = wanted_routes
            .iter()
            .enumerate()
            .position(|(i, w)| !kept_routes[i] && w.matches(route))
        {
            kept_routes[i] = true;
            continue;
        }
        actions.push(Action::DeleteRoute(route.clone()));
    }

    // 3. Interfaces.
    for want in &desired.interfaces {
        let iface = || want.name.clone();
        let link = kept.get(want.name.as_str()).copied();
        if link.is_none() {
            actions.push(Action::CreateLink { name: iface() });
        }
        let device = link.and_then(|l| l.device.as_ref());
        let key_ok = |d: &crate::observed::Device| {
            desired.public_key.is_some() && d.public_key == desired.public_key
        };
        if !device.is_some_and(|d| key_ok(d) && d.listen_port == want.port) {
            actions.push(Action::ConfigureDevice {
                iface: iface(),
                listen_port: want.port,
            });
        }
        let have = device.map_or(&[][..], |d| &d.peers[..]);
        for peer in have {
            if !want.peers.iter().any(|p| p.public_key == peer.public_key) {
                actions.push(Action::RemovePeer {
                    iface: iface(),
                    public_key: peer.public_key.clone(),
                });
            }
        }
        for peer in &want.peers {
            let current = have.iter().find(|p| p.public_key == peer.public_key);
            let in_sync = current.is_some_and(|c| {
                c.allowed_ips == peer.allowed_ips
                    && !c.other_allowed_ips
                    && c.preshared_key == peer.preshared_key
                    && c.keepalive == 0
            });
            if !in_sync {
                actions.push(Action::SetPeer {
                    iface: iface(),
                    public_key: peer.public_key.clone(),
                    allowed_ips: peer.allowed_ips.iter().copied().collect(),
                    preshared_key: peer.preshared_key.clone(),
                    new: current.is_none(),
                });
            }
        }
        let address = (want.address, want.prefix.prefix_len());
        let addresses = link.map_or(&[][..], |l| &l.addresses[..]);
        for &(a, len) in addresses {
            if (a, len) != address {
                actions.push(Action::DeleteAddress {
                    iface: iface(),
                    address: a,
                    len,
                });
            }
        }
        if !addresses.contains(&address) {
            actions.push(Action::AddAddress {
                iface: iface(),
                address: address.0,
                len: address.1,
            });
        }
        if !link.is_some_and(|l| l.mtu == want.mtu) {
            actions.push(Action::SetMtu {
                iface: iface(),
                mtu: want.mtu,
            });
        }
        if !link.is_some_and(|l| l.rp_filter.as_deref() == Some(RP_FILTER)) {
            actions.push(Action::SetRpFilter { iface: iface() });
        }
        if !link.is_some_and(|l| l.up) {
            actions.push(Action::SetUp { iface: iface() });
        }
    }

    // 4. Routes before rules -> rule never points to an empty table.
    for (route, kept) in wanted_routes.into_iter().zip(kept_routes) {
        if !kept {
            actions.push(Action::AddRoute(route));
        }
    }
    for want in &desired.interfaces {
        if !kept_rules.contains(&(want.name.as_str(), want.table)) {
            actions.push(Action::AddRule {
                iface: want.name.clone(),
                table: want.table,
                priority: desired.rule_priority,
            });
        }
    }
    actions
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use dhonomos_wireguard::{HubNetwork, HubPeer};
    use uuid::Uuid;

    use super::*;
    use crate::observed::{Device, Peer};

    const HUB_KEY: &str = "HUBHUBHUBHUBHUBHUBHUBHUBHUBHUBHUBHUBHUBHUB0=";
    const KEY_A: &str = "AAAAAAAAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=";
    const KEY_B: &str = "BBBBBBBBbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbA=";
    const KEY_D: &str = "DDDDDDDDdddddddddddddddddddddddddddddddddddA=";

    fn p(s: &str) -> Ipv4Prefix {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn peer(key: &str, ips: &[&str]) -> HubPeer {
        HubPeer {
            member_id: Uuid::nil(),
            kind: "device".into(),
            public_key: key.into(),
            allowed_ips: ips.iter().map(|s| p(s)).collect(),
            preshared_key: None,
        }
    }

    /// Invented PSK, all bytes `n`.
    fn psk_text(n: u8) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode([n; 32])
    }

    fn psk(n: u8) -> Psk {
        Psk(zeroize::Zeroizing::new([n; 32]))
    }

    fn network(port: u16, prefix: &str, peers: Vec<HubPeer>) -> HubNetwork {
        let prefix = p(prefix);
        HubNetwork {
            id: Uuid::from_u128(u128::from(port)),
            name: format!("n{port}"),
            interface: interface_name(port),
            listen_port: port,
            prefix,
            address: Ipv4Addr::from(u32::from(prefix.network()) + 1),
            mtu: 1420,
            peers,
        }
    }

    /// N1 on 51820 (A + B with sites), N2 on 51821 (D with site prefix of A).
    fn two_networks() -> HubState {
        HubState {
            hub_id: Uuid::nil(),
            revision: 1,
            networks: vec![
                network(
                    51821,
                    "10.77.1.0/24",
                    vec![peer(KEY_D, &["10.77.1.2/32", "192.168.10.0/24"])],
                ),
                network(
                    51820,
                    "10.77.0.0/24",
                    vec![
                        peer(KEY_A, &["10.77.0.2/32", "192.168.10.0/24"]),
                        peer(KEY_B, &["10.77.0.3/32", "192.168.20.0/24"]),
                    ],
                ),
            ],
        }
    }

    fn desired(state: &HubState) -> Desired {
        Desired::from_state(state, Some(HUB_KEY.into()), 100_000, 10_000).unwrap()
    }

    /// Kernel after `desired` applied, + foreign items.
    fn in_sync(d: &Desired) -> Observed {
        let mut o = Observed::default();
        o.links.push(foreign_link("eth0", 2));
        for (n, i) in d.interfaces.iter().enumerate() {
            o.links.push(Link {
                name: i.name.clone(),
                index: 10 + n as u32,
                wireguard: true,
                up: true,
                mtu: i.mtu,
                addresses: vec![(i.address, i.prefix.prefix_len())],
                rp_filter: Some("2".into()),
                device: Some(Device {
                    public_key: d.public_key.clone(),
                    listen_port: i.port,
                    peers: i
                        .peers
                        .iter()
                        .map(|p| Peer {
                            public_key: p.public_key.clone(),
                            allowed_ips: p.allowed_ips.clone(),
                            other_allowed_ips: false,
                            preshared_key: p.preshared_key.clone(),
                            keepalive: 0,
                        })
                        .collect(),
                }),
            });
            o.rules.push(Rule {
                priority: d.rule_priority,
                iif: Some(i.name.clone()),
                table: i.table,
                other: false,
            });
            for r in i.routes() {
                o.routes.push(observed_route(&r, 10 + n as u32));
            }
        }
        o.rules.push(Rule {
            priority: 0,
            iif: None,
            table: 255,
            other: false,
        });
        o
    }

    fn observed_route(r: &RouteSpec, index: u32) -> Route {
        match &r.target {
            RouteTarget::Dev { iface, src } => Route {
                table: r.table,
                dst: r.dst,
                kind: RouteKind::Unicast,
                oif: Some(iface.clone()),
                oif_index: Some(index),
                src: *src,
                metric: 0,
                other: false,
            },
            RouteTarget::Unreachable => Route {
                table: r.table,
                dst: r.dst,
                kind: RouteKind::Unreachable,
                oif: None,
                oif_index: None,
                src: None,
                metric: 0,
                other: false,
            },
        }
    }

    fn foreign_link(name: &str, index: u32) -> Link {
        Link {
            name: name.into(),
            index,
            wireguard: name.contains("wg"),
            up: false,
            mtu: 1500,
            addresses: vec![(ip("192.168.10.1"), 24)],
            rp_filter: None,
            device: None,
        }
    }

    fn texts(actions: &[Action]) -> Vec<String> {
        actions.iter().map(Action::describe).collect()
    }

    #[test]
    fn desired_state_by_port_with_tables_and_routes() {
        let d = desired(&two_networks());
        let names: Vec<_> = d.interfaces.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["dwg51820", "dwg51821"]);
        assert_eq!(d.interfaces[0].table, 151_820);
        assert_eq!(d.interfaces[0].address, ip("10.77.0.1"));
        let routes: Vec<String> = d.interfaces[0]
            .routes()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            routes,
            [
                "10.77.0.0/24 dev dwg51820 src 10.77.0.1 table 151820",
                "192.168.10.0/24 dev dwg51820 table 151820",
                "192.168.20.0/24 dev dwg51820 table 151820",
                "unreachable 0.0.0.0/0 table 151820",
            ]
        );
    }

    #[test]
    fn a_fresh_host_gets_everything() {
        let d = desired(&two_networks());
        let o = Observed {
            links: vec![foreign_link("lo", 1), foreign_link("eth0", 2)],
            ..Observed::default()
        };
        assert_eq!(
            texts(&plan(&d, &o)),
            [
                "create interface dwg51820",
                "set private key and listen port 51820 on dwg51820",
                "add peer AAAAAAAA… on dwg51820 allowed 10.77.0.2/32,192.168.10.0/24",
                "add peer BBBBBBBB… on dwg51820 allowed 10.77.0.3/32,192.168.20.0/24",
                "add address 10.77.0.1/24 to dwg51820",
                "set mtu 1420 on dwg51820",
                "set rp_filter 2 on dwg51820",
                "set dwg51820 up",
                "create interface dwg51821",
                "set private key and listen port 51821 on dwg51821",
                "add peer DDDDDDDD… on dwg51821 allowed 10.77.1.2/32,192.168.10.0/24",
                "add address 10.77.1.1/24 to dwg51821",
                "set mtu 1420 on dwg51821",
                "set rp_filter 2 on dwg51821",
                "set dwg51821 up",
                "add route 10.77.0.0/24 dev dwg51820 src 10.77.0.1 table 151820",
                "add route 192.168.10.0/24 dev dwg51820 table 151820",
                "add route 192.168.20.0/24 dev dwg51820 table 151820",
                "add route unreachable 0.0.0.0/0 table 151820",
                "add route 10.77.1.0/24 dev dwg51821 src 10.77.1.1 table 151821",
                "add route 192.168.10.0/24 dev dwg51821 table 151821",
                "add route unreachable 0.0.0.0/0 table 151821",
                "add rule iif dwg51820 table 151820 priority 10000",
                "add rule iif dwg51821 table 151821 priority 10000",
            ]
        );
    }

    #[test]
    fn an_in_sync_kernel_gives_nothing() {
        let d = desired(&two_networks());
        assert_eq!(plan(&d, &in_sync(&d)), []);
        // Nothing wanted, nothing there.
        let empty = Desired::from_state(
            &HubState {
                hub_id: Uuid::nil(),
                revision: 1,
                networks: vec![],
            },
            Some(HUB_KEY.into()),
            100_000,
            10_000,
        )
        .unwrap();
        assert_eq!(plan(&empty, &in_sync(&empty)), []);
    }

    #[test]
    fn peers_added_removed_and_changed() {
        let before = desired(&two_networks());
        let o = in_sync(&before);
        let mut state = two_networks();
        // N1: B leaves, C joins, A gets another site.
        state.networks[1].peers = vec![
            peer(
                KEY_A,
                &["10.77.0.2/32", "192.168.10.0/24", "192.168.11.0/24"],
            ),
            peer(KEY_D, &["10.77.0.4/32"]),
        ];
        assert_eq!(
            texts(&plan(&desired(&state), &o)),
            [
                "delete route 192.168.20.0/24 dev dwg51820 table 151820",
                "remove peer BBBBBBBB… from dwg51820",
                "update peer AAAAAAAA… on dwg51820 allowed 10.77.0.2/32,192.168.10.0/24,192.168.11.0/24",
                "add peer DDDDDDDD… on dwg51820 allowed 10.77.0.4/32",
                "add route 192.168.11.0/24 dev dwg51820 table 151820",
            ]
        );
    }

    #[test]
    fn allowed_ips_are_compared_as_sets() {
        let d = desired(&two_networks());
        let mut o = in_sync(&d);
        // Same set, other order (kernel order) -> BTreeSet ignores it.
        let dev = o.links[1].device.as_mut().unwrap();
        let ips: Vec<_> = dev.peers[0].allowed_ips.iter().rev().copied().collect();
        dev.peers[0].allowed_ips = ips.into_iter().collect();
        assert_eq!(plan(&d, &o), []);
        // PSK, keepalive or IPv6 allowed IP set from outside -> cleared.
        for change in [
            |p: &mut Peer| p.preshared_key = Some(psk(9)),
            |p: &mut Peer| p.keepalive = 25,
            |p: &mut Peer| p.other_allowed_ips = true,
        ] {
            let mut o = in_sync(&d);
            change(&mut o.links[1].device.as_mut().unwrap().peers[1]);
            assert_eq!(
                texts(&plan(&d, &o)),
                ["update peer BBBBBBBB… on dwg51820 allowed 10.77.0.3/32,192.168.20.0/24"]
            );
        }
    }

    #[test]
    fn preshared_keys_are_set_changed_and_cleared() {
        let mut state = two_networks();
        state.networks[1].peers[1].preshared_key = Some(psk_text(1));
        let d = desired(&state);
        assert_eq!(d.interfaces[0].peers[1].preshared_key, Some(psk(1)));
        let update = "update peer BBBBBBBB… on dwg51820 allowed 10.77.0.3/32,192.168.20.0/24";
        // Set: peer without PSK gets it.
        let before = in_sync(&desired(&two_networks()));
        let actions = plan(&d, &before);
        assert_eq!(texts(&actions), [format!("{update} with a pre-shared key")]);
        let Action::SetPeer { preshared_key, .. } = &actions[0] else {
            panic!("{actions:?}");
        };
        assert_eq!(preshared_key.as_ref(), Some(&psk(1)));
        // In sync: nothing.
        assert_eq!(plan(&d, &in_sync(&d)), []);
        // Changed or replaced from outside -> desired one again.
        for kernel in [2, 9] {
            let mut o = in_sync(&d);
            o.links[1].device.as_mut().unwrap().peers[1].preshared_key = Some(psk(kernel));
            assert_eq!(
                texts(&plan(&d, &o)),
                [format!("{update} with a pre-shared key")]
            );
        }
        // Cleared: server stopped sending it.
        let actions = plan(&desired(&two_networks()), &in_sync(&d));
        assert_eq!(texts(&actions), [update]);
        let Action::SetPeer { preshared_key, .. } = &actions[0] else {
            panic!("{actions:?}");
        };
        assert_eq!(*preshared_key, None);
        // New peer -> PSK in the add.
        let o = Observed {
            links: vec![foreign_link("eth0", 2)],
            ..Observed::default()
        };
        assert!(
            texts(&plan(&d, &o)).contains(
                &"add peer BBBBBBBB… on dwg51820 allowed 10.77.0.3/32,192.168.20.0/24 with a pre-shared key"
                    .to_owned()
            )
        );
    }

    #[test]
    fn a_bad_preshared_key_fails_the_state_and_no_key_is_ever_shown() {
        for bad in ["", "short", &"A".repeat(43), &psk_text(0)] {
            let mut state = two_networks();
            state.networks[1].peers[0].preshared_key = Some(bad.to_owned());
            let e = Desired::from_state(&state, Some(HUB_KEY.into()), 100_000, 10_000)
                .unwrap_err()
                .to_string();
            assert_eq!(
                e, "the pre-shared key of peer AAAAAAAA… in network n51820 is not a key",
                "{bad:?}"
            );
        }
        let mut state = two_networks();
        state.networks[1].peers[0].preshared_key = Some(psk_text(7));
        let d = desired(&state);
        let shown = format!(
            "{d:?} {:?} {:?}",
            plan(&d, &in_sync(&desired(&two_networks()))),
            in_sync(&d)
        );
        assert!(!shown.contains(&psk_text(7)), "{shown}");
        assert!(!shown.contains("7, 7, 7"), "{shown}");
        assert!(shown.contains("preshared_key: Some(********)"), "{shown}");
    }

    #[test]
    fn a_port_change_replaces_link_rule_and_table() {
        let o = in_sync(&desired(&two_networks()));
        let mut state = two_networks();
        state.networks[0] = network(
            51825,
            "10.77.1.0/24",
            vec![peer(KEY_D, &["10.77.1.2/32", "192.168.10.0/24"])],
        );
        let actions = plan(&desired(&state), &o);
        assert_eq!(
            texts(&actions),
            [
                "delete interface dwg51821",
                "delete rule iif dwg51821 table 151821",
                // Routes via dwg51821 gone with the link; unreachable stays.
                "delete route unreachable 0.0.0.0/0 table 151821",
                "create interface dwg51825",
                "set private key and listen port 51825 on dwg51825",
                "add peer DDDDDDDD… on dwg51825 allowed 10.77.1.2/32,192.168.10.0/24",
                "add address 10.77.1.1/24 to dwg51825",
                "set mtu 1420 on dwg51825",
                "set rp_filter 2 on dwg51825",
                "set dwg51825 up",
                "add route 10.77.1.0/24 dev dwg51825 src 10.77.1.1 table 151825",
                "add route 192.168.10.0/24 dev dwg51825 table 151825",
                "add route unreachable 0.0.0.0/0 table 151825",
                "add rule iif dwg51825 table 151825 priority 10000",
            ]
        );
    }

    #[test]
    fn a_removed_network_is_cleaned_up() {
        let o = in_sync(&desired(&two_networks()));
        let mut state = two_networks();
        state.networks.remove(0);
        assert_eq!(
            texts(&plan(&desired(&state), &o)),
            [
                "delete interface dwg51821",
                "delete rule iif dwg51821 table 151821",
                "delete route unreachable 0.0.0.0/0 table 151821",
            ]
        );
        // Table left without link (e.g. after a crash) -> emptied too.
        let mut o = in_sync(&desired(&state));
        o.routes.push(Route {
            table: 165_535,
            dst: p("192.168.99.0/24"),
            kind: RouteKind::Unicast,
            oif: Some("eth0".into()),
            oif_index: Some(2),
            src: None,
            metric: 0,
            other: false,
        });
        assert_eq!(
            texts(&plan(&desired(&state), &o)),
            ["delete route 192.168.99.0/24 dev eth0 table 165535"]
        );
    }

    #[test]
    fn foreign_links_rules_and_tables_are_never_touched() {
        let d = desired(&two_networks());
        let mut o = in_sync(&d);
        for name in ["wg0", "dwgfoo", "dwg0", "dwg051820", "dwg65536", "Dwg51820"] {
            o.links.push(foreign_link(name, 99));
        }
        for rule in [
            // Other priority.
            Rule {
                priority: 9_999,
                iif: Some("dwg51822".into()),
                table: 151_822,
                other: false,
            },
            // Not a dwg interface.
            Rule {
                priority: 10_000,
                iif: Some("wg0".into()),
                table: 151_822,
                other: false,
            },
            Rule {
                priority: 10_000,
                iif: None,
                table: 151_822,
                other: false,
            },
            Rule {
                priority: 32_766,
                iif: None,
                table: 254,
                other: false,
            },
        ] {
            o.rules.push(rule);
        }
        for table in [100_000, 165_536, 200, 51_820] {
            o.routes.push(Route {
                table,
                dst: p("0.0.0.0/0"),
                kind: RouteKind::Unreachable,
                oif: None,
                oif_index: None,
                src: None,
                metric: 0,
                other: false,
            });
        }
        assert_eq!(plan(&d, &o), []);
    }

    #[test]
    fn the_same_site_prefix_in_two_networks_gets_two_tables() {
        let d = desired(&two_networks());
        let site = p("192.168.10.0/24");
        let tables: Vec<u32> = d
            .interfaces
            .iter()
            .flat_map(|i| i.routes())
            .filter(|r| r.dst == site)
            .map(|r| r.table)
            .collect();
        assert_eq!(tables, [151_820, 151_821]);
        // One missing -> added; other kept.
        let mut o = in_sync(&d);
        o.routes.retain(|r| !(r.table == 151_821 && r.dst == site));
        assert_eq!(
            texts(&plan(&d, &o)),
            ["add route 192.168.10.0/24 dev dwg51821 table 151821"]
        );
    }

    #[test]
    fn drift_is_repaired() {
        let d = desired(&two_networks());
        let mut o = in_sync(&d);
        let link = &mut o.links[1];
        link.mtu = 1500;
        link.up = false;
        link.rp_filter = Some("1".into());
        link.addresses = vec![(ip("10.77.9.1"), 24), (ip("10.77.0.1"), 16)];
        let dev = link.device.as_mut().unwrap();
        dev.listen_port = 1234;
        assert_eq!(
            texts(&plan(&d, &o)),
            [
                "set private key and listen port 51820 on dwg51820",
                "delete address 10.77.9.1/24 from dwg51820",
                "delete address 10.77.0.1/16 from dwg51820",
                "add address 10.77.0.1/24 to dwg51820",
                "set mtu 1420 on dwg51820",
                "set rp_filter 2 on dwg51820",
                "set dwg51820 up",
            ]
        );
        // Other private key, or none.
        for key in [Some("OTHER".to_owned()), None] {
            let mut o = in_sync(&d);
            o.links[2].device.as_mut().unwrap().public_key = key;
            assert_eq!(
                texts(&plan(&d, &o)),
                ["set private key and listen port 51821 on dwg51821"]
            );
        }
        // No key file yet (dry run) -> key set on every interface.
        let unknown = Desired {
            public_key: None,
            ..d.clone()
        };
        assert_eq!(
            texts(&plan(&unknown, &in_sync(&d))),
            [
                "set private key and listen port 51820 on dwg51820",
                "set private key and listen port 51821 on dwg51821",
            ]
        );
    }

    #[test]
    fn wrong_or_duplicate_rules_and_routes_are_replaced() {
        let d = desired(&two_networks());
        let mut o = in_sync(&d);
        // Rules: duplicate, other table, extra selectors.
        o.rules.push(o.rules[0].clone());
        o.rules.push(Rule {
            priority: 10_000,
            iif: Some("dwg51821".into()),
            table: 151_820,
            other: false,
        });
        o.rules[1].other = true;
        // Routes: with metric, duplicate, tunnel route without source.
        let mut metric = o.routes[1].clone();
        metric.metric = 5;
        o.routes.push(metric);
        o.routes.push(o.routes[3].clone());
        o.routes[0].src = None;
        assert_eq!(
            texts(&plan(&d, &o)),
            [
                "delete rule iif dwg51821 table 151821",
                "delete rule iif dwg51820 table 151820",
                "delete rule iif dwg51821 table 151820",
                "delete route 10.77.0.0/24 dev dwg51820 table 151820",
                "delete route 192.168.10.0/24 dev dwg51820 table 151820",
                "delete route unreachable 0.0.0.0/0 table 151820",
                "add route 10.77.0.0/24 dev dwg51820 src 10.77.0.1 table 151820",
                "add rule iif dwg51821 table 151821 priority 10000",
            ]
        );
    }

    #[test]
    fn a_dwg_link_that_is_not_wireguard_is_recreated() {
        let d = desired(&two_networks());
        let mut o = in_sync(&d);
        o.links[1].wireguard = false;
        o.links[1].device = None;
        let actions = texts(&plan(&d, &o));
        assert_eq!(actions[0], "delete interface dwg51820");
        assert_eq!(actions[1], "create interface dwg51820");
        // Its routes gone with it -> added again.
        assert!(
            actions.contains(&"add route 192.168.10.0/24 dev dwg51820 table 151820".to_owned())
        );
        assert!(
            !actions.iter().any(|a| a.starts_with("delete route")),
            "{actions:?}"
        );
        assert!(
            !actions.iter().any(|a| a.starts_with("add rule")),
            "{actions:?}"
        );
    }

    #[test]
    fn duplicate_ports_and_peers_in_a_state_are_ignored() {
        let mut state = two_networks();
        state.networks.push(network(51820, "10.77.5.0/24", vec![]));
        state.networks[1].peers.push(peer(KEY_A, &["10.77.0.9/32"]));
        let d = desired(&state);
        assert_eq!(d.interfaces.len(), 2);
        assert_eq!(d.interfaces[0].prefix, p("10.77.0.0/24"));
        assert_eq!(d.interfaces[0].peers.len(), 2);
    }

    #[test]
    fn short_keys() {
        assert_eq!(short_key(KEY_A), "AAAAAAAA…");
        assert_eq!(short_key("abc"), "abc…");
    }
}
