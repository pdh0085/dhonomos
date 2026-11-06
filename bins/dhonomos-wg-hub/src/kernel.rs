//! Kernel side: read [`Observed`], carry out [`Action`]s.
//! Links, addresses, MTU, routes, rules -> rtnetlink.
//! WireGuard config (private key, port, peers) -> WireGuard generic netlink family.
//! Its client is sync -> runs on the blocking pool.
//! `rp_filter` = file in `/proc/sys`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::{Context as _, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use dhonomos_wireguard::{Ipv4Prefix, parse_interface_name};
use futures_util::TryStreamExt as _;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::address::AddressAttribute;
use rtnetlink::packet_route::link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage};
use rtnetlink::packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleFlags, RuleMessage};
use rtnetlink::{
    AddressMessageBuilder, Handle, IpVersion, LinkUnspec, LinkWireguard, RouteMessageBuilder,
};
use tokio::task::JoinHandle;
use wireguard_uapi::linux::set::{self, WgPeerF};
use wireguard_uapi::{DeviceInterface, WgSocket, get};
use zeroize::{Zeroize as _, Zeroizing};

use crate::observed::{Device, Link, Observed, Peer, Psk, Route, RouteKind, Rule};
use crate::plan::{Action, RP_FILTER, RouteSpec, RouteTarget};

/// Hub private key, raw bytes.
pub(crate) type PrivateKey = Arc<Zeroizing<[u8; 32]>>;

/// Key text (base64) -> 32 bytes.
pub(crate) fn key_bytes(key: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let mut raw = Zeroizing::new(
        STANDARD
            .decode(key)
            .map_err(|_| anyhow!("not a WireGuard key"))?,
    );
    let mut bytes = Zeroizing::new([0u8; 32]);
    if raw.len() != 32 {
        raw.zeroize();
        return Err(anyhow!("not a WireGuard key"));
    }
    bytes.copy_from_slice(&raw);
    Ok(bytes)
}

fn rp_filter_path(iface: &str) -> String {
    format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter")
}

/// rtnetlink connection + hub key for the WireGuard calls.
pub(crate) struct Kernel {
    handle: Handle,
    connection: JoinHandle<()>,
    key: Option<PrivateKey>,
}

impl fmt::Debug for Kernel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kernel").finish_non_exhaustive()
    }
}

impl Drop for Kernel {
    fn drop(&mut self) {
        self.connection.abort();
    }
}

/// WireGuard device as the kernel reports it. Runs on the blocking pool.
pub(crate) async fn read_device(name: String) -> anyhow::Result<get::Device> {
    tokio::task::spawn_blocking(move || {
        let mut socket =
            WgSocket::connect().context("connecting to the WireGuard netlink family")?;
        socket
            .get_device(DeviceInterface::from_name(name.as_str()))
            .with_context(|| format!("reading the WireGuard configuration of {name}"))
    })
    .await
    .context("the WireGuard reader stopped")?
}

/// One WireGuard config change. Runs on the blocking pool.
async fn write_device<F>(change: F) -> anyhow::Result<()>
where
    F: FnOnce(&mut WgSocket) -> anyhow::Result<()> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut socket =
            WgSocket::connect().context("connecting to the WireGuard netlink family")?;
        change(&mut socket)
    })
    .await
    .context("the WireGuard writer stopped")?
}

fn device_of(mut d: get::Device) -> Device {
    if let Some(k) = d.private_key.as_mut() {
        k.zeroize();
    }
    let device = Device {
        public_key: d.public_key.map(|k| STANDARD.encode(k)),
        listen_port: d.listen_port,
        peers: d
            .peers
            .iter()
            .map(|p| {
                let mut allowed_ips = BTreeSet::new();
                let mut other = false;
                for a in &p.allowed_ips {
                    match a.ipaddr {
                        IpAddr::V4(v4) => match Ipv4Prefix::new(v4, a.cidr_mask) {
                            Some(prefix) => {
                                allowed_ips.insert(prefix);
                            }
                            None => other = true,
                        },
                        IpAddr::V6(_) => other = true,
                    }
                }
                Peer {
                    public_key: STANDARD.encode(p.public_key),
                    allowed_ips,
                    other_allowed_ips: other,
                    preshared_key: (p.preshared_key != [0; 32])
                        .then(|| Psk(Zeroizing::new(p.preshared_key))),
                    keepalive: p.persistent_keepalive_interval,
                }
            })
            .collect(),
    };
    for p in &mut d.peers {
        p.preshared_key.zeroize();
    }
    device
}

fn link_of(m: &LinkMessage) -> Link {
    let mut link = Link {
        name: String::new(),
        index: m.header.index,
        wireguard: false,
        up: m.header.flags.contains(LinkFlags::Up),
        mtu: 0,
        addresses: Vec::new(),
        rp_filter: None,
        device: None,
    };
    for attr in &m.attributes {
        match attr {
            LinkAttribute::IfName(n) => link.name.clone_from(n),
            LinkAttribute::Mtu(mtu) => link.mtu = *mtu,
            LinkAttribute::LinkInfo(infos) => {
                link.wireguard |= infos
                    .iter()
                    .any(|i| matches!(i, LinkInfo::Kind(InfoKind::Wireguard)));
            }
            _ => {}
        }
    }
    link
}

fn rule_of(m: &RuleMessage) -> Rule {
    let h = &m.header;
    let mut rule = Rule {
        priority: 0,
        iif: None,
        table: u32::from(h.table),
        other: h.action != RuleAction::ToTable
            || h.dst_len != 0
            || h.src_len != 0
            || h.tos != 0
            || h.flags.contains(RuleFlags::Invert),
    };
    for attr in &m.attributes {
        match attr {
            RuleAttribute::Priority(p) => rule.priority = *p,
            RuleAttribute::Iifname(n) => rule.iif = Some(n.clone()),
            RuleAttribute::Table(t) => rule.table = *t,
            // Kernel: "not set" = 0, false or -1.
            RuleAttribute::FwMark(0)
            | RuleAttribute::FwMask(0)
            | RuleAttribute::L3MDev(false)
            | RuleAttribute::SuppressPrefixLen(u32::MAX)
            | RuleAttribute::SuppressIfGroup(u32::MAX) => {}
            RuleAttribute::Destination(_)
            | RuleAttribute::Source(_)
            | RuleAttribute::Goto(_)
            | RuleAttribute::FwMark(_)
            | RuleAttribute::FwMask(_)
            | RuleAttribute::TunId(_)
            | RuleAttribute::SuppressIfGroup(_)
            | RuleAttribute::SuppressPrefixLen(_)
            | RuleAttribute::Oifname(_)
            | RuleAttribute::L3MDev(true)
            | RuleAttribute::UidRange(_)
            | RuleAttribute::IpProtocol(_)
            | RuleAttribute::SourcePortRange(_)
            | RuleAttribute::DestinationPortRange(_) => rule.other = true,
            _ => {}
        }
    }
    rule
}

fn route_of(m: &RouteMessage, names: &BTreeMap<u32, String>) -> Option<Route> {
    let h = &m.header;
    if h.address_family != AddressFamily::Inet {
        return None;
    }
    let mut table = u32::from(h.table);
    let mut dst = Ipv4Addr::UNSPECIFIED;
    let mut oif_index = None;
    let mut src = None;
    let mut metric = 0;
    let mut other = h.source_prefix_length != 0 || h.tos != 0;
    for attr in &m.attributes {
        match attr {
            RouteAttribute::Table(t) => table = *t,
            RouteAttribute::Destination(RouteAddress::Inet(a)) => dst = *a,
            RouteAttribute::Oif(i) => oif_index = Some(*i),
            RouteAttribute::PrefSource(RouteAddress::Inet(a)) => src = Some(*a),
            RouteAttribute::Priority(p) => metric = *p,
            RouteAttribute::Gateway(_)
            | RouteAttribute::MultiPath(_)
            | RouteAttribute::Via(_)
            | RouteAttribute::Encap(_)
            | RouteAttribute::Source(_)
            | RouteAttribute::Mark(_) => other = true,
            _ => {}
        }
    }
    let kind = match h.kind {
        RouteType::Unicast => RouteKind::Unicast,
        RouteType::Unreachable => RouteKind::Unreachable,
        k => RouteKind::Other(u8::from(k)),
    };
    Some(Route {
        table,
        dst: Ipv4Prefix::containing(dst, h.destination_prefix_length)?,
        kind,
        oif: oif_index.and_then(|i| names.get(&i).cloned()),
        oif_index,
        src,
        metric,
        other,
    })
}

fn route_type(kind: RouteKind) -> RouteType {
    match kind {
        RouteKind::Unicast => RouteType::Unicast,
        RouteKind::Unreachable => RouteType::Unreachable,
        RouteKind::Other(k) => RouteType::from(k),
    }
}

impl Kernel {
    /// Open an rtnetlink connection. `key` only needed to set the private key.
    pub(crate) fn connect(key: Option<PrivateKey>) -> anyhow::Result<Self> {
        let (conn, handle, _) =
            rtnetlink::new_connection().context("opening an rtnetlink socket")?;
        Ok(Self {
            handle,
            connection: tokio::spawn(conn),
            key,
        })
    }

    /// Read everything the planner looks at. Read only.
    pub(crate) async fn observe(&self) -> anyhow::Result<Observed> {
        let mut links = Vec::new();
        let mut stream = self.handle.link().get().execute();
        while let Some(m) = stream.try_next().await.context("listing links")? {
            links.push(link_of(&m));
        }
        let names: BTreeMap<u32, String> =
            links.iter().map(|l| (l.index, l.name.clone())).collect();

        let mut stream = self.handle.address().get().execute();
        while let Some(m) = stream.try_next().await.context("listing addresses")? {
            if m.header.family != AddressFamily::Inet {
                continue;
            }
            let mut address = None;
            for attr in &m.attributes {
                match attr {
                    AddressAttribute::Local(IpAddr::V4(a)) => address = Some(*a),
                    AddressAttribute::Address(IpAddr::V4(a)) if address.is_none() => {
                        address = Some(*a);
                    }
                    _ => {}
                }
            }
            if let (Some(a), Some(link)) = (
                address,
                links.iter_mut().find(|l| l.index == m.header.index),
            ) {
                link.addresses.push((a, m.header.prefix_len));
            }
        }

        for link in &mut links {
            if parse_interface_name(&link.name).is_none() {
                continue;
            }
            link.rp_filter = tokio::fs::read_to_string(rp_filter_path(&link.name))
                .await
                .ok()
                .map(|s| s.trim().to_owned());
            if link.wireguard {
                link.device = Some(device_of(read_device(link.name.clone()).await?));
            }
        }

        let mut rules = Vec::new();
        let mut stream = self.handle.rule().get(IpVersion::V4).execute();
        while let Some(m) = stream.try_next().await.context("listing rules")? {
            rules.push(rule_of(&m));
        }

        let mut routes = Vec::new();
        let mut query = RouteMessageBuilder::<Ipv4Addr>::new().build();
        query.header.table = RouteHeader::RT_TABLE_UNSPEC;
        query.header.protocol = RouteProtocol::Unspec;
        query.header.kind = RouteType::Unspec;
        let mut stream = self.handle.route().get(query).execute();
        while let Some(m) = stream.try_next().await.context("listing routes")? {
            if let Some(r) = route_of(&m, &names).filter(|r| r.table > 255) {
                routes.push(r);
            }
        }
        Ok(Observed {
            links,
            rules,
            routes,
        })
    }

    async fn index_of(&self, name: &str) -> anyhow::Result<u32> {
        let mut stream = self
            .handle
            .link()
            .get()
            .match_name(name.to_owned())
            .execute();
        match stream.try_next().await {
            Ok(Some(m)) => Ok(m.header.index),
            Ok(None) | Err(_) => Err(anyhow!("there is no interface {name}")),
        }
    }

    pub(crate) async fn execute(&self, action: &Action) -> anyhow::Result<()> {
        match action {
            Action::DeleteLink { name } => {
                let index = self.index_of(name).await?;
                self.handle.link().del(index).execute().await?;
            }
            Action::DeleteRule(rule) => {
                let mut m = RuleMessage::default();
                m.header.family = AddressFamily::Inet;
                m.header.action = RuleAction::Unspec;
                m.header.table = RouteHeader::RT_TABLE_UNSPEC;
                m.attributes.push(RuleAttribute::Priority(rule.priority));
                if let Some(iif) = &rule.iif {
                    m.attributes.push(RuleAttribute::Iifname(iif.clone()));
                }
                if rule.table != 0 {
                    m.attributes.push(RuleAttribute::Table(rule.table));
                }
                self.handle.rule().del(m).execute().await?;
            }
            Action::DeleteRoute(route) => {
                let mut b = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(route.dst.network(), route.dst.prefix_len())
                    .table_id(route.table);
                if let Some(i) = route.oif_index {
                    b = b.output_interface(i);
                }
                if route.metric != 0 {
                    b = b.priority(route.metric);
                }
                let mut m = b.build();
                m.header.protocol = RouteProtocol::Unspec;
                m.header.scope = RouteScope::NoWhere;
                m.header.kind = route_type(route.kind);
                self.handle.route().del(m).execute().await?;
            }
            Action::CreateLink { name } => {
                self.handle
                    .link()
                    .add(LinkWireguard::new(name).build())
                    .execute()
                    .await?;
            }
            Action::ConfigureDevice { iface, listen_port } => {
                let key = self.key.clone().context("the hub key is not loaded")?;
                let (name, port) = (iface.clone(), *listen_port);
                write_device(move |s| {
                    s.set_device(
                        set::Device::from_ifname(name.as_str())
                            .private_key(&key)
                            .listen_port(port),
                    )?;
                    Ok(())
                })
                .await?;
            }
            Action::RemovePeer { iface, public_key } => {
                let peer = key_bytes(public_key).context("the peer's public key")?;
                let name = iface.clone();
                write_device(move |s| {
                    s.set_device(set::Device::from_ifname(name.as_str()).peers(vec![
                        set::Peer::from_public_key(&peer).flags(vec![WgPeerF::RemoveMe]),
                    ]))?;
                    Ok(())
                })
                .await?;
            }
            Action::SetPeer {
                iface,
                public_key,
                allowed_ips,
                preshared_key,
                ..
            } => {
                let peer = key_bytes(public_key).context("the peer's public key")?;
                let name = iface.clone();
                let ips: Vec<(IpAddr, u8)> = allowed_ips
                    .iter()
                    .map(|p| (IpAddr::V4(p.network()), p.prefix_len()))
                    .collect();
                // All zeros = no PSK.
                let psk = Zeroizing::new(preshared_key.as_ref().map_or([0u8; 32], |k| *k.0));
                write_device(move |s| {
                    let allowed = ips
                        .iter()
                        .map(|(ip, len)| set::AllowedIp {
                            ipaddr: ip,
                            cidr_mask: Some(*len),
                        })
                        .collect();
                    s.set_device(set::Device::from_ifname(name.as_str()).peers(vec![
                        set::Peer::from_public_key(&peer)
                            .flags(vec![WgPeerF::ReplaceAllowedIps])
                            .preshared_key(&psk)
                            .persistent_keepalive_interval(0)
                            .allowed_ips(allowed),
                    ]))?;
                    Ok(())
                })
                .await?;
            }
            Action::DeleteAddress {
                iface,
                address,
                len,
            } => {
                let index = self.index_of(iface).await?;
                let m = AddressMessageBuilder::<Ipv4Addr>::new()
                    .index(index)
                    .address(*address, *len)
                    .build();
                self.handle.address().del(m).execute().await?;
            }
            Action::AddAddress {
                iface,
                address,
                len,
            } => {
                let index = self.index_of(iface).await?;
                self.handle
                    .address()
                    .add(index, IpAddr::V4(*address), *len)
                    .execute()
                    .await?;
            }
            Action::SetMtu { iface, mtu } => {
                let index = self.index_of(iface).await?;
                self.handle
                    .link()
                    .set(LinkUnspec::new_with_index(index).mtu(*mtu).build())
                    .execute()
                    .await?;
            }
            Action::SetRpFilter { iface } => {
                let path = rp_filter_path(iface);
                tokio::fs::write(&path, format!("{RP_FILTER}\n"))
                    .await
                    .with_context(|| format!("writing {path}"))?;
            }
            Action::SetUp { iface } => {
                let index = self.index_of(iface).await?;
                self.handle
                    .link()
                    .set(LinkUnspec::new_with_index(index).up().build())
                    .execute()
                    .await?;
            }
            Action::AddRoute(route) => self.add_route(route).await?,
            Action::AddRule {
                iface,
                table,
                priority,
            } => {
                self.handle
                    .rule()
                    .add()
                    .input_interface(iface.clone())
                    .table_id(*table)
                    .priority(*priority)
                    .action(RuleAction::ToTable)
                    .v4()
                    .execute()
                    .await?;
            }
        }
        Ok(())
    }

    async fn add_route(&self, route: &RouteSpec) -> anyhow::Result<()> {
        let b = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(route.dst.network(), route.dst.prefix_len())
            .table_id(route.table);
        let m = match &route.target {
            RouteTarget::Dev { iface, src } => {
                let index = self.index_of(iface).await?;
                let mut b = b.output_interface(index).scope(RouteScope::Link);
                if let Some(src) = src {
                    b = b.pref_source(*src);
                }
                b.build()
            }
            RouteTarget::Unreachable => b.kind(RouteType::Unreachable).build(),
        };
        self.handle.route().add(m).execute().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// Kernel dump of `ip rule add iif dwg51820 lookup 151820 pref 10000`.
    fn dumped_rule() -> RuleMessage {
        let mut m = RuleMessage::default();
        m.header.family = AddressFamily::Inet;
        m.header.table = 252;
        m.header.action = RuleAction::ToTable;
        m.attributes = vec![
            RuleAttribute::Table(151_820),
            RuleAttribute::SuppressPrefixLen(u32::MAX),
            RuleAttribute::Protocol(RouteProtocol::Unspec),
            RuleAttribute::Iifname("dwg51820".into()),
            RuleAttribute::Priority(10_000),
        ];
        m
    }

    #[test]
    fn rules_as_the_kernel_dumps_them() {
        assert_eq!(
            rule_of(&dumped_rule()),
            Rule {
                priority: 10_000,
                iif: Some("dwg51820".into()),
                table: 151_820,
                other: false,
            }
        );
        let mut m = dumped_rule();
        m.attributes.push(RuleAttribute::FwMark(7));
        assert!(rule_of(&m).other);
        let mut m = dumped_rule();
        m.attributes[1] = RuleAttribute::SuppressPrefixLen(0);
        assert!(rule_of(&m).other);
        let mut m = dumped_rule();
        m.header.flags = RuleFlags::Invert;
        assert!(rule_of(&m).other);
        let mut m = dumped_rule();
        m.header.action = RuleAction::Unreachable;
        assert!(rule_of(&m).other);
    }

    #[test]
    fn routes_as_the_kernel_dumps_them() {
        let names = BTreeMap::from([(7, "dwg51820".to_owned())]);
        let m = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::new(10, 77, 0, 0), 24)
            .table_id(151_820)
            .output_interface(7)
            .pref_source(Ipv4Addr::new(10, 77, 0, 1))
            .build();
        assert_eq!(
            route_of(&m, &names),
            Some(Route {
                table: 151_820,
                dst: "10.77.0.0/24".parse().unwrap(),
                kind: RouteKind::Unicast,
                oif: Some("dwg51820".into()),
                oif_index: Some(7),
                src: Some(Ipv4Addr::new(10, 77, 0, 1)),
                metric: 0,
                other: false,
            })
        );
        // Default route -> no destination attribute.
        let m = RouteMessageBuilder::<Ipv4Addr>::new()
            .table_id(151_820)
            .kind(RouteType::Unreachable)
            .build();
        let r = route_of(&m, &names).unwrap();
        assert_eq!(r.dst, "0.0.0.0/0".parse().unwrap());
        assert_eq!(r.kind, RouteKind::Unreachable);
        let m = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::new(192, 168, 10, 0), 24)
            .gateway(Ipv4Addr::new(10, 77, 0, 2))
            .build();
        let r = route_of(&m, &names).unwrap();
        assert!(r.other);
        assert_eq!(r.table, 254);
    }

    #[test]
    fn keys_become_bytes() {
        assert_eq!(*key_bytes(&STANDARD.encode([9u8; 32])).unwrap(), [9u8; 32]);
        assert!(key_bytes("nope").is_err());
        assert!(key_bytes(&STANDARD.encode([9u8; 31])).is_err());
    }
}
