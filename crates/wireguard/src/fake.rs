//! CPE double for tests; no production code uses it.
//!
//! [`FakeDevice`]: TR-181 tree with `Device.WireGuard.` + `Device.IP.Interface.`.
//! Acts like the firmware variants the device planner ([`crate::device`]) must handle.
//! Firmware may make tunnel interface + IP interface of a new tunnel
//! (at once, or at commit: [`FakeDevice::derive`]), and may make the tunnel key itself.
//! Keeps true values, secrets incl.; reads return what a client sees.

use std::collections::{BTreeMap, BTreeSet};

use crate::device::{Param, Tree};
use crate::keys::{generate_keypair, public_from_private};

const WG_ROOT: &str = "Device.WireGuard.";
const PEER_TABLE: &str = "Device.WireGuard.Peer.";
const TUNNEL_TABLE: &str = "Device.WireGuard.Tunnel.";
const IP_TABLE: &str = "Device.IP.Interface.";

/// Fake firmware behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FakeOptions {
    /// Firmware makes Tunnel.{t}.Interface.1 on Tunnel Add.
    pub tunnel_interface_made: bool,
    /// (b): Tunnel Add -> firmware makes an IP.Interface: IPv4Address.1,
    /// LowerLayers "Device.WireGuard.Tunnel.{t}.Interface.1." (trailing dot).
    /// Add in Device.IP.Interface. refused.
    /// Else (a): Add in Device.IP.Interface. works, nothing made automatically.
    pub firmware_ip_interface: bool,
    /// Key mode device: Tunnel.Enable becomes true + no PrivateKey set -> device makes a key.
    pub makes_key: bool,
    /// Has Device.WireGuard. at all.
    pub supported: bool,
    /// Tunnel.{t}.PrivateKey set to "" -> new key pair. false -> device keeps its key.
    pub regenerates_key: bool,
    /// With `firmware_ip_interface`: Tunnel Add makes no IP.Interface;
    /// firmware makes it later, at commit ([`FakeDevice::derive`]).
    pub ip_interface_later: bool,
    /// LowerLayers of the firmware-made IP.Interface = "" (found by Name only).
    pub ip_lower_layers_empty: bool,
}

/// Why the fake refused a request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FakeError {
    /// No such parameter, object or table.
    #[error("{0} does not exist on this device")]
    NotFound(String),
    /// Read-only parameter, or table the client may not add to.
    #[error("{0} is not writable on this device")]
    NotWritable(String),
    #[error("this device does not support Device.WireGuard.")]
    Unsupported,
}

/// One parameter + its true value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FakeParam {
    value: String,
    writable: bool,
    /// Reads return "".
    secured: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeDevice {
    opts: FakeOptions,
    params: BTreeMap<String, FakeParam>,
    /// Firmware-made IP.Interface instance -> its Tunnel instance.
    firmware_made: BTreeMap<u32, u32>,
}

/// Type `read` reports for a parameter.
fn xsd_type_of(path: &str) -> &'static str {
    let name = path.rsplit('.').next().unwrap_or(path);
    if name == "Enable" {
        "boolean"
    } else if name == "EndpointPort" {
        // -1 = unset.
        "int"
    } else if matches!(
        name,
        "ListenPort" | "PersistentKeepalive" | "MaxMTUSize" | "LastHandshakeTime"
    ) || name.ends_with("NumberOfEntries")
    {
        "unsignedInt"
    } else {
        "string"
    }
}

/// Instance numbers of `table` (ends with '.') in `params`.
fn instances_of(params: &BTreeMap<String, FakeParam>, table: &str) -> BTreeSet<u32> {
    params
        .keys()
        .filter_map(|k| k.strip_prefix(table))
        .filter_map(|rest| rest.split_once('.'))
        .filter(|(num, _)| !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()))
        .filter_map(|(num, _)| num.parse().ok())
        .collect()
}

impl FakeDevice {
    /// Device fresh from the factory.
    pub fn new(opts: FakeOptions) -> Self {
        let mut dev = Self {
            opts,
            params: BTreeMap::new(),
            firmware_made: BTreeMap::new(),
        };
        if opts.supported {
            dev.put("Device.WireGuard.TunnelNumberOfEntries", "0", false);
            dev.put("Device.WireGuard.PeerNumberOfEntries", "0", false);
        }
        let lan = "Device.IP.Interface.1.";
        for (name, value) in [
            ("Alias", "cpe-lan"),
            ("Enable", "true"),
            ("Name", "br-lan"),
            ("LowerLayers", "Device.Ethernet.Link.1"),
            ("MaxMTUSize", "1500"),
            ("IPv4Address.1.Alias", "cpe-lan-v4"),
            ("IPv4Address.1.Enable", "true"),
            ("IPv4Address.1.IPAddress", "192.168.1.1"),
            ("IPv4Address.1.SubnetMask", "255.255.255.0"),
        ] {
            dev.put(&format!("{lan}{name}"), value, name != "Name");
        }
        dev
    }

    fn put(&mut self, path: &str, value: &str, writable: bool) {
        self.params.insert(
            path.to_owned(),
            FakeParam {
                value: value.to_owned(),
                writable,
                secured: false,
            },
        );
    }

    /// Put `<inst>Alias`. Unset alias ("") -> reads `cpe-{n}`, `n` = instance number.
    fn put_alias(&mut self, inst: &str, alias: &str) {
        let alias = if alias.is_empty() {
            let n = inst
                .trim_end_matches('.')
                .rsplit('.')
                .next()
                .unwrap_or_default();
            format!("cpe-{n}")
        } else {
            alias.to_owned()
        };
        self.put(&format!("{inst}Alias"), &alias, true);
    }

    fn put_secret(&mut self, path: &str) {
        self.params.insert(
            path.to_owned(),
            FakeParam {
                value: String::new(),
                writable: true,
                secured: true,
            },
        );
    }

    /// `path` under `Device.WireGuard.` + device without it -> true.
    fn unsupported(&self, path: &str) -> bool {
        !self.opts.supported && path.starts_with(WG_ROOT)
    }

    fn exists(&self, object: &str) -> bool {
        self.params.keys().any(|k| k.starts_with(object))
    }

    /// Update NumberOfEntries counters.
    fn recount(&mut self) {
        if self.opts.supported {
            for (table, counter) in [
                (TUNNEL_TABLE, "Device.WireGuard.TunnelNumberOfEntries"),
                (PEER_TABLE, "Device.WireGuard.PeerNumberOfEntries"),
            ] {
                let n = instances_of(&self.params, table).len();
                self.put(counter, &n.to_string(), false);
            }
        }
        for t in instances_of(&self.params, TUNNEL_TABLE) {
            let n = instances_of(&self.params, &format!("{TUNNEL_TABLE}{t}.Interface.")).len();
            self.put(
                &format!("{TUNNEL_TABLE}{t}.InterfaceNumberOfEntries"),
                &n.to_string(),
                false,
            );
        }
    }

    /// Values as a client reads them (secured PrivateKey/PresharedKey -> ""), each leaf
    /// under `prefix` (ends with '.'). Nothing under it -> Err(NotFound).
    pub fn read(&self, prefix: &str) -> Result<Tree, FakeError> {
        if self.unsupported(prefix) {
            return Err(FakeError::Unsupported);
        }
        let tree: Tree = self
            .params
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, p)| {
                (
                    k.clone(),
                    Param {
                        value: if p.secured {
                            String::new()
                        } else {
                            p.value.clone()
                        },
                        writable: Some(p.writable),
                        xsd_type: Some(xsd_type_of(k).to_owned()),
                    },
                )
            })
            .collect();
        if tree.is_empty() {
            return Err(FakeError::NotFound(prefix.to_owned()));
        }
        Ok(tree)
    }

    fn next_instance(&self, table: &str) -> u32 {
        instances_of(&self.params, table)
            .last()
            .map_or(1, |n| n.saturating_add(1))
    }

    /// Add an instance (next free number) + its Alias -> instance path ("...{n}.").
    pub fn add(&mut self, table: &str, alias: &str) -> Result<String, FakeError> {
        if self.unsupported(table) {
            return Err(FakeError::Unsupported);
        }
        let n = self.next_instance(table);
        let inst = format!("{table}{n}.");
        if table == PEER_TABLE {
            self.add_peer(&inst, alias);
        } else if table == TUNNEL_TABLE {
            self.add_tunnel(n, alias);
        } else if table == IP_TABLE {
            if self.opts.firmware_ip_interface {
                return Err(FakeError::NotWritable(table.to_owned()));
            }
            self.add_ip_interface(&inst, alias);
        } else if let Some(t) = table
            .strip_prefix(TUNNEL_TABLE)
            .and_then(|r| r.strip_suffix(".Interface."))
            .filter(|t| self.exists(&format!("{TUNNEL_TABLE}{t}.")))
            .and_then(|t| t.parse::<u32>().ok())
        {
            self.add_tunnel_interface(t, n, alias);
        } else if table
            .strip_prefix(IP_TABLE)
            .and_then(|r| r.strip_suffix(".IPv4Address."))
            .is_some_and(|x| {
                x.bytes().all(|b| b.is_ascii_digit()) && self.exists(&format!("{IP_TABLE}{x}."))
            })
        {
            self.add_ipv4_address(&inst, alias);
        } else {
            return Err(FakeError::NotFound(table.to_owned()));
        }
        self.recount();
        Ok(inst)
    }

    fn add_peer(&mut self, inst: &str, alias: &str) {
        self.put_alias(inst, alias);
        for (name, value, writable) in [
            ("Enable", "false", true),
            ("PublicKey", "", true),
            ("AllowedIPs", "", true),
            ("EndpointAddress", "", true),
            // -1 = unset.
            ("EndpointPort", "-1", true),
            ("PersistentKeepalive", "0", true),
            // s since last handshake; 0 = never.
            ("LastHandshakeTime", "0", false),
        ] {
            self.put(&format!("{inst}{name}"), value, writable);
        }
        self.put_secret(&format!("{inst}PresharedKey"));
    }

    fn add_tunnel(&mut self, t: u32, alias: &str) {
        let inst = format!("{TUNNEL_TABLE}{t}.");
        self.put_alias(&inst, alias);
        for (name, value, writable) in [
            ("Enable", "false", true),
            ("Status", "Down", false),
            ("PublicKey", "", false),
            ("ListenPort", "0", true),
            ("PeerReferences", "", true),
            ("InterfaceNumberOfEntries", "0", false),
        ] {
            self.put(&format!("{inst}{name}"), value, writable);
        }
        self.put_secret(&format!("{inst}PrivateKey"));
        if self.opts.tunnel_interface_made {
            self.add_tunnel_interface(t, 1, "");
        }
        if self.opts.firmware_ip_interface && !self.opts.ip_interface_later {
            self.make_ip_interface(t);
        }
    }

    /// Firmware IP.Interface for Tunnel `t`: IPv4Address.1, Name of Tunnel.{t}.Interface.1,
    /// LowerLayers -> it (trailing dot) unless `ip_lower_layers_empty`.
    fn make_ip_interface(&mut self, t: u32) {
        let tif = format!("{TUNNEL_TABLE}{t}.Interface.1.");
        let x = self.next_instance(IP_TABLE);
        let ip = format!("{IP_TABLE}{x}.");
        self.add_ip_interface(&ip, "");
        let lower = if self.opts.ip_lower_layers_empty {
            String::new()
        } else {
            tif.clone()
        };
        self.put(&format!("{ip}LowerLayers"), &lower, true);
        let name = self
            .value(&format!("{tif}Name"))
            .unwrap_or_default()
            .to_owned();
        self.put(&format!("{ip}Name"), &name, false);
        self.add_ipv4_address(&format!("{ip}IPv4Address.1."), "");
        self.firmware_made.insert(x, t);
    }

    /// Commit (`ip_interface_later`): make the IP.Interface of each Tunnel without a
    /// firmware-made one. Idempotent.
    /// No-op without `ip_interface_later` or `firmware_ip_interface`.
    pub fn derive(&mut self) {
        if !(self.opts.firmware_ip_interface && self.opts.ip_interface_later) {
            return;
        }
        let made: BTreeSet<u32> = self.firmware_made.values().copied().collect();
        for t in instances_of(&self.params, TUNNEL_TABLE) {
            if !made.contains(&t) {
                self.make_ip_interface(t);
            }
        }
    }

    fn add_tunnel_interface(&mut self, t: u32, k: u32, alias: &str) {
        let inst = format!("{TUNNEL_TABLE}{t}.Interface.{k}.");
        self.put_alias(&inst, alias);
        self.put(&format!("{inst}Enable"), "false", true);
        self.put(&format!("{inst}Name"), &format!("wg{t}"), false);
        self.put(&format!("{inst}LowerLayers"), "", true);
    }

    /// IP.Interface as a client Add makes it (Name "").
    fn add_ip_interface(&mut self, inst: &str, alias: &str) {
        self.put_alias(inst, alias);
        self.put(&format!("{inst}Enable"), "false", true);
        self.put(&format!("{inst}Name"), "", false);
        self.put(&format!("{inst}LowerLayers"), "", true);
        self.put(&format!("{inst}MaxMTUSize"), "1500", true);
    }

    fn add_ipv4_address(&mut self, inst: &str, alias: &str) {
        self.put_alias(inst, alias);
        self.put(&format!("{inst}Enable"), "false", true);
        self.put(&format!("{inst}IPAddress"), "", true);
        self.put(&format!("{inst}SubnetMask"), "", true);
    }

    /// Set all values or none (atomic). Read-only param -> NotWritable, unknown path -> NotFound.
    ///
    /// `Tunnel.{t}.PrivateKey` set -> `PublicKey` = its public key ("" if not a valid key).
    /// Set to "" -> new key pair with `regenerates_key`, else no change.
    /// `makes_key` + `Tunnel.{t}.Enable` becomes "true" with no PrivateKey set -> new key pair.
    pub fn set(&mut self, values: &[(String, String)]) -> Result<(), FakeError> {
        for (path, _) in values {
            if self.unsupported(path) {
                return Err(FakeError::Unsupported);
            }
            match self.params.get(path) {
                None => return Err(FakeError::NotFound(path.clone())),
                Some(p) if !p.writable => return Err(FakeError::NotWritable(path.clone())),
                Some(_) => {}
            }
        }
        let tunnels_enabled_before: BTreeSet<u32> = self.enabled_tunnels();
        for (path, value) in values {
            let tunnel_key = path
                .strip_prefix(TUNNEL_TABLE)
                .and_then(|r| r.strip_suffix(".PrivateKey"))
                .filter(|i| i.bytes().all(|b| b.is_ascii_digit()));
            if let Some(inst) = tunnel_key
                && value.is_empty()
            {
                if self.opts.regenerates_key
                    && let Ok(pair) = generate_keypair()
                {
                    if let Some(p) = self.params.get_mut(path) {
                        p.value.clone_from(&pair.private);
                    }
                    self.put(
                        &format!("{TUNNEL_TABLE}{inst}.PublicKey"),
                        &pair.public,
                        false,
                    );
                }
                continue;
            }
            if let Some(p) = self.params.get_mut(path) {
                p.value.clone_from(value);
            }
            if let Some(inst) = tunnel_key {
                let public = public_from_private(value).unwrap_or_default();
                self.put(&format!("{TUNNEL_TABLE}{inst}.PublicKey"), &public, false);
            }
        }
        if self.opts.makes_key {
            for t in self.enabled_tunnels().difference(&tunnels_enabled_before) {
                let private = format!("{TUNNEL_TABLE}{t}.PrivateKey");
                if self.value(&private) == Some("")
                    && let Ok(pair) = generate_keypair()
                {
                    if let Some(p) = self.params.get_mut(&private) {
                        p.value.clone_from(&pair.private);
                    }
                    self.put(&format!("{TUNNEL_TABLE}{t}.PublicKey"), &pair.public, false);
                }
            }
        }
        Ok(())
    }

    fn enabled_tunnels(&self) -> BTreeSet<u32> {
        instances_of(&self.params, TUNNEL_TABLE)
            .into_iter()
            .filter(|t| {
                self.value(&format!("{TUNNEL_TABLE}{t}.Enable"))
                    .is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1")
            })
            .collect()
    }

    /// Delete an instance (path ends with '.') + all under it.
    /// Tunnel delete -> also its firmware-made IP interface.
    pub fn delete(&mut self, object: &str) -> Result<(), FakeError> {
        if self.unsupported(object) {
            return Err(FakeError::Unsupported);
        }
        if !object.ends_with('.') || !self.exists(object) {
            return Err(FakeError::NotFound(object.to_owned()));
        }
        self.params.retain(|k, _| !k.starts_with(object));
        if let Some(t) = object
            .strip_prefix(TUNNEL_TABLE)
            .and_then(|r| r.strip_suffix('.'))
            .and_then(|t| t.parse::<u32>().ok())
        {
            let made: Vec<u32> = self
                .firmware_made
                .iter()
                .filter(|(_, tunnel)| **tunnel == t)
                .map(|(x, _)| *x)
                .collect();
            for x in made {
                self.firmware_made.remove(&x);
                let ip = format!("{IP_TABLE}{x}.");
                self.params.retain(|k, _| !k.starts_with(&ip));
            }
        }
        if let Some(x) = object
            .strip_prefix(IP_TABLE)
            .and_then(|r| r.strip_suffix('.'))
            .and_then(|x| x.parse::<u32>().ok())
        {
            self.firmware_made.remove(&x);
        }
        self.recount();
        Ok(())
    }

    /// True value (tests only), secrets incl.
    pub fn value(&self, path: &str) -> Option<&str> {
        self.params.get(path).map(|p| p.value.as_str())
    }

    /// True `PresharedKey` of the Peer with Alias `alias` (tests only; client reads "").
    /// "" = none set; `None` = no such Peer.
    pub fn preshared_key(&self, alias: &str) -> Option<&str> {
        instances_of(&self.params, PEER_TABLE)
            .into_iter()
            .find(|p| self.value(&format!("{PEER_TABLE}{p}.Alias")) == Some(alias))
            .and_then(|p| self.value(&format!("{PEER_TABLE}{p}.PresharedKey")))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn opts() -> FakeOptions {
        FakeOptions {
            tunnel_interface_made: true,
            firmware_ip_interface: true,
            makes_key: true,
            supported: true,
            regenerates_key: false,
            ip_interface_later: false,
            ip_lower_layers_empty: false,
        }
    }

    #[test]
    fn firmware_makes_rows_with_a_tunnel_and_removes_them_with_it() {
        let mut dev = FakeDevice::new(opts());
        assert_eq!(
            dev.add(TUNNEL_TABLE, "a").unwrap(),
            "Device.WireGuard.Tunnel.1."
        );
        assert_eq!(
            dev.value("Device.IP.Interface.2.LowerLayers"),
            Some("Device.WireGuard.Tunnel.1.Interface.1.")
        );
        assert_eq!(
            dev.value("Device.WireGuard.Tunnel.1.Interface.1.Name"),
            Some("wg1")
        );
        assert_eq!(
            dev.value("Device.WireGuard.Tunnel.1.InterfaceNumberOfEntries"),
            Some("1")
        );
        assert_eq!(
            dev.value("Device.WireGuard.TunnelNumberOfEntries"),
            Some("1")
        );
        assert_eq!(
            dev.add(IP_TABLE, "x"),
            Err(FakeError::NotWritable(IP_TABLE.to_owned()))
        );
        dev.delete("Device.WireGuard.Tunnel.1.").unwrap();
        assert_eq!(dev.value("Device.IP.Interface.2.Enable"), None);
        assert_eq!(dev.value("Device.IP.Interface.1.Alias"), Some("cpe-lan"));
        assert_eq!(
            dev.value("Device.WireGuard.TunnelNumberOfEntries"),
            Some("0")
        );
    }

    #[test]
    fn secrets_read_empty_and_keys_follow() {
        let mut dev = FakeDevice::new(FakeOptions {
            makes_key: false,
            ..opts()
        });
        let t = dev.add(TUNNEL_TABLE, "a").unwrap();
        let pair = generate_keypair().unwrap();
        let private = format!("{t}PrivateKey");
        dev.set(&[(private.clone(), pair.private.to_string())])
            .unwrap();
        assert_eq!(
            dev.value(&format!("{t}PublicKey")),
            Some(pair.public.as_str())
        );
        let read = dev.read(&t).unwrap();
        assert_eq!(read[&private].value, "");
        assert_eq!(read[&private].writable, Some(true));
        assert_eq!(read[&format!("{t}PublicKey")].value, pair.public);
        assert_eq!(read[&format!("{t}PublicKey")].writable, Some(false));
        assert_eq!(
            read[&format!("{t}Enable")].xsd_type.as_deref(),
            Some("boolean")
        );
        assert_eq!(
            read[&format!("{t}ListenPort")].xsd_type.as_deref(),
            Some("unsignedInt")
        );
    }

    #[test]
    fn a_preshared_key_is_kept_but_reads_empty() {
        let mut dev = FakeDevice::new(opts());
        let peer = dev.add(PEER_TABLE, "a").unwrap();
        let path = format!("{peer}PresharedKey");
        assert_eq!(dev.preshared_key("a"), Some(""));
        assert_eq!(dev.preshared_key("b"), None);
        dev.set(&[(path.clone(), "invented-psk".to_owned())])
            .unwrap();
        assert_eq!(dev.preshared_key("a"), Some("invented-psk"));
        let read = dev.read(&peer).unwrap();
        assert_eq!(read[&path].value, "");
        assert_eq!(read[&path].writable, Some(true));
        dev.set(&[(path.clone(), String::new())]).unwrap();
        assert_eq!(dev.preshared_key("a"), Some(""));
    }

    #[test]
    fn the_device_makes_its_key_once_enabled() {
        let mut dev = FakeDevice::new(opts());
        let t = dev.add(TUNNEL_TABLE, "a").unwrap();
        assert_eq!(dev.value(&format!("{t}PublicKey")), Some(""));
        dev.set(&[(format!("{t}Enable"), "true".to_owned())])
            .unwrap();
        let public = dev.value(&format!("{t}PublicKey")).unwrap().to_owned();
        assert_eq!(
            public_from_private(dev.value(&format!("{t}PrivateKey")).unwrap()).unwrap(),
            public
        );
        // 2nd enable -> no new key.
        dev.set(&[(format!("{t}Enable"), "false".to_owned())])
            .unwrap();
        dev.set(&[(format!("{t}Enable"), "true".to_owned())])
            .unwrap();
        assert_eq!(dev.value(&format!("{t}PublicKey")), Some(public.as_str()));
    }

    #[test]
    fn an_empty_private_key_makes_a_new_pair_only_when_the_firmware_does() {
        for regenerates_key in [true, false] {
            let mut dev = FakeDevice::new(FakeOptions {
                regenerates_key,
                ..opts()
            });
            let t = dev.add(TUNNEL_TABLE, "a").unwrap();
            dev.set(&[(format!("{t}Enable"), "true".to_owned())])
                .unwrap();
            let old = dev.value(&format!("{t}PublicKey")).unwrap().to_owned();
            let old_private = dev.value(&format!("{t}PrivateKey")).unwrap().to_owned();
            dev.set(&[(format!("{t}PrivateKey"), String::new())])
                .unwrap();
            let new = dev.value(&format!("{t}PublicKey")).unwrap().to_owned();
            let new_private = dev.value(&format!("{t}PrivateKey")).unwrap();
            if regenerates_key {
                assert_ne!(new, old);
                assert_eq!(public_from_private(new_private).unwrap(), new);
            } else {
                assert_eq!(new, old);
                assert_eq!(new_private, old_private);
            }
        }
    }

    #[test]
    fn sets_are_atomic() {
        let mut dev = FakeDevice::new(opts());
        let p = dev.add(PEER_TABLE, "a").unwrap();
        let err = dev
            .set(&[
                (format!("{p}EndpointPort"), "51820".to_owned()),
                (format!("{p}LastHandshakeTime"), "x".to_owned()),
            ])
            .unwrap_err();
        assert_eq!(err, FakeError::NotWritable(format!("{p}LastHandshakeTime")));
        assert_eq!(dev.value(&format!("{p}EndpointPort")), Some("-1"));
        assert_eq!(
            dev.set(&[(format!("{p}Nope"), "1".to_owned())]),
            Err(FakeError::NotFound(format!("{p}Nope")))
        );
        assert!(err.to_string().contains("not writable"));
    }

    #[test]
    fn the_ip_interface_can_come_with_the_commit() {
        let mut dev = FakeDevice::new(FakeOptions {
            ip_interface_later: true,
            ..opts()
        });
        let t = dev.add(TUNNEL_TABLE, "a").unwrap();
        assert_eq!(dev.value("Device.IP.Interface.2.Enable"), None);
        dev.derive();
        dev.derive();
        assert_eq!(
            dev.value("Device.IP.Interface.2.LowerLayers"),
            Some("Device.WireGuard.Tunnel.1.Interface.1.")
        );
        assert_eq!(dev.value("Device.IP.Interface.2.Name"), Some("wg1"));
        assert_eq!(
            dev.value("Device.IP.Interface.2.IPv4Address.1.Alias"),
            Some("cpe-1")
        );
        assert_eq!(dev.value("Device.IP.Interface.3.Enable"), None);
        assert_eq!(
            dev.add(IP_TABLE, "x"),
            Err(FakeError::NotWritable(IP_TABLE.to_owned()))
        );
        dev.delete(&t).unwrap();
        assert_eq!(dev.value("Device.IP.Interface.2.Enable"), None);
        // Tunnel gone -> nothing to derive.
        dev.derive();
        assert_eq!(dev.value("Device.IP.Interface.2.Enable"), None);

        // No option -> row comes with the Add, derive adds nothing.
        let mut dev = FakeDevice::new(opts());
        dev.add(TUNNEL_TABLE, "a").unwrap();
        let before = dev.read(IP_TABLE).unwrap();
        dev.derive();
        assert_eq!(dev.read(IP_TABLE).unwrap(), before);
    }

    #[test]
    fn the_firmware_row_may_have_empty_lower_layers() {
        let mut dev = FakeDevice::new(FakeOptions {
            ip_lower_layers_empty: true,
            ..opts()
        });
        dev.add(TUNNEL_TABLE, "a").unwrap();
        assert_eq!(dev.value("Device.IP.Interface.2.LowerLayers"), Some(""));
        assert_eq!(dev.value("Device.IP.Interface.2.Name"), Some("wg1"));
    }

    #[test]
    fn names_and_unset_aliases() {
        let mut dev = FakeDevice::new(FakeOptions {
            firmware_ip_interface: false,
            ..opts()
        });
        let read = dev.read(IP_TABLE).unwrap();
        let lan = &read["Device.IP.Interface.1.Name"];
        assert_eq!(lan.value, "br-lan");
        assert_eq!(lan.writable, Some(false));
        assert_eq!(dev.value("Device.IP.Interface.1.Alias"), Some("cpe-lan"));
        assert_eq!(dev.add(IP_TABLE, "").unwrap(), "Device.IP.Interface.2.");
        assert_eq!(dev.value("Device.IP.Interface.2.Name"), Some(""));
        assert_eq!(dev.value("Device.IP.Interface.2.Alias"), Some("cpe-2"));
        dev.add(IP_TABLE, "mine").unwrap();
        assert_eq!(dev.value("Device.IP.Interface.3.Alias"), Some("mine"));
        dev.add(PEER_TABLE, "").unwrap();
        dev.add(PEER_TABLE, "").unwrap();
        assert_eq!(dev.value("Device.WireGuard.Peer.2.Alias"), Some("cpe-2"));
        let t = dev.add(TUNNEL_TABLE, "").unwrap();
        assert_eq!(dev.value(&format!("{t}Alias")), Some("cpe-1"));
        assert_eq!(dev.value(&format!("{t}Interface.1.Alias")), Some("cpe-1"));
        assert_eq!(dev.value(&format!("{t}Interface.1.Name")), Some("wg1"));
        // Set Alias -> reads as set.
        dev.set(&[(format!("{t}Alias"), "ours".to_owned())])
            .unwrap();
        assert_eq!(dev.value(&format!("{t}Alias")), Some("ours"));
    }

    #[test]
    fn peer_port_and_handshake_types() {
        let mut dev = FakeDevice::new(opts());
        let p = dev.add(PEER_TABLE, "a").unwrap();
        let read = dev.read(&p).unwrap();
        let port = &read[&format!("{p}EndpointPort")];
        assert_eq!(port.value, "-1");
        assert_eq!(port.xsd_type.as_deref(), Some("int"));
        let handshake = &read[&format!("{p}LastHandshakeTime")];
        assert_eq!(handshake.value, "0");
        assert_eq!(handshake.xsd_type.as_deref(), Some("unsignedInt"));
        assert_eq!(handshake.writable, Some(false));
    }

    #[test]
    fn unsupported_devices_have_no_wireguard() {
        let mut dev = FakeDevice::new(FakeOptions {
            supported: false,
            ..opts()
        });
        assert_eq!(dev.read(WG_ROOT), Err(FakeError::Unsupported));
        assert_eq!(dev.add(PEER_TABLE, "a"), Err(FakeError::Unsupported));
        assert!(dev.read(IP_TABLE).is_ok());
        assert_eq!(
            dev.read("Device.Nothing."),
            Err(FakeError::NotFound("Device.Nothing.".to_owned()))
        );
    }
}
