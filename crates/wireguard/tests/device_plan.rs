//! Device planner vs fake CPE, driven like the CWMP + USP callers.

#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use dhonomos_wireguard::fake::{FakeDevice, FakeError, FakeOptions};
use dhonomos_wireguard::{
    DesiredTunnel, KeyMode, Outcome, Param, PlanInput, Step, Tree, alias_of, desired_hash,
    generate_keypair, plan,
};
use uuid::Uuid;

const MAX_STEPS: usize = 40;
/// Max waits for a firmware-made IP interface.
const WAIT_LIMIT: usize = 2;

/// Caller side: its snapshot of one device.
struct Driver {
    dev: FakeDevice,
    snap: Tree,
    /// Waits for firmware-made IP interface, per network, kept across runs.
    waits: BTreeMap<Uuid, usize>,
    /// Firmware makes the IP interface (`FakeDevice::derive`) at this wait. None -> never.
    derive_at_wait: Option<usize>,
    /// Networks managed by another record of this device (`PlanInput::kept`).
    kept: BTreeSet<Uuid>,
}

#[derive(Debug)]
struct Run {
    /// All steps except the last (`Done`).
    steps: Vec<Step>,
    outcomes: Vec<Outcome>,
}

impl Run {
    fn kinds(&self) -> Vec<&'static str> {
        self.steps
            .iter()
            .map(|s| match s {
                Step::Read { .. } => "read",
                Step::Add { .. } => "add",
                Step::Set { .. } => "set",
                Step::SetPrivateKey { .. } => "key",
                Step::RegenerateKey { .. } => "regenerate",
                Step::Delete { .. } => "delete",
                Step::WaitForFirmware { .. } => "wait",
                Step::Done { .. } => "done",
            })
            .collect()
    }

    fn adds(&self) -> Vec<&str> {
        self.steps
            .iter()
            .filter_map(|s| match s {
                Step::Add { table, .. } => Some(table.as_str()),
                _ => None,
            })
            .collect()
    }

    fn set_paths(&self) -> Vec<Vec<&str>> {
        self.steps
            .iter()
            .filter_map(|s| match s {
                Step::Set { values, .. } => Some(values.iter().map(|v| v.path.as_str()).collect()),
                _ => None,
            })
            .collect()
    }
}

fn drop_under(snap: &mut Tree, prefix: &str) {
    snap.retain(|k, _| !k.starts_with(prefix));
}

impl Driver {
    fn new(opts: FakeOptions) -> Self {
        Self {
            dev: FakeDevice::new(opts),
            snap: Tree::new(),
            waits: BTreeMap::new(),
            derive_at_wait: None,
            kept: BTreeSet::new(),
        }
    }

    /// Networks with `WAIT_LIMIT` waits done.
    fn ip_wait_over(&self) -> BTreeSet<Uuid> {
        self.waits
            .iter()
            .filter(|(_, c)| **c >= WAIT_LIMIT)
            .map(|(n, _)| *n)
            .collect()
    }

    /// Replace snapshot under `path` with a fresh read. false -> device has nothing there.
    fn refresh(&mut self, path: &str) -> bool {
        drop_under(&mut self.snap, path);
        match self.dev.read(path) {
            Ok(tree) => {
                self.snap.extend(tree);
                true
            }
            Err(FakeError::Unsupported | FakeError::NotFound(_)) => false,
            Err(e) => panic!("read {path}: {e}"),
        }
    }

    /// One run with a fresh `read` set, until `Done`.
    /// Keys stored like the real caller: public key of own key pair + key read from device.
    /// `rotate_key` cleared after the rotation step is sent.
    fn run(&mut self, desired: &mut [DesiredTunnel]) -> Run {
        let mut read = BTreeSet::new();
        let mut steps = Vec::new();
        for _ in 0..MAX_STEPS {
            let ip_wait_over = self.ip_wait_over();
            let step = plan(&PlanInput {
                desired,
                tree: &self.snap,
                read: &read,
                ip_wait_over: &ip_wait_over,
                kept: &self.kept,
            });
            match &step {
                Step::Read { paths } => {
                    for path in paths {
                        if !self.refresh(path) {
                            assert_eq!(path, "Device.WireGuard.", "nothing at {path}");
                        }
                        read.insert(path.clone());
                    }
                }
                Step::Add {
                    table,
                    alias,
                    then_read,
                    ..
                } => {
                    let inst = self.dev.add(table, alias).unwrap();
                    assert!(self.refresh(&inst));
                    for path in then_read {
                        self.refresh(path);
                    }
                }
                Step::Set { values, .. } => {
                    let pairs: Vec<(String, String)> = values
                        .iter()
                        .map(|v| (v.path.clone(), v.value.clone()))
                        .collect();
                    self.dev.set(&pairs).unwrap();
                    for v in values {
                        self.snap
                            .entry(v.path.clone())
                            .and_modify(|p| p.value.clone_from(&v.value))
                            .or_insert_with(|| Param {
                                value: v.value.clone(),
                                writable: Some(true),
                                xsd_type: Some(v.xsd_type.clone()),
                            });
                    }
                }
                Step::SetPrivateKey { tunnel, network_id } => {
                    let pair = generate_keypair().unwrap();
                    let path = format!("{tunnel}PrivateKey");
                    self.dev
                        .set(&[(path.clone(), pair.private.to_string())])
                        .unwrap();
                    self.refresh(tunnel);
                    assert_eq!(self.snap[&path].value, "");
                    let d = member(desired, *network_id);
                    d.member_public_key = Some(pair.public);
                    d.rotate_key = false;
                }
                Step::RegenerateKey { tunnel, network_id } => {
                    self.dev
                        .set(&[(format!("{tunnel}PrivateKey"), String::new())])
                        .unwrap();
                    self.refresh(tunnel);
                    member(desired, *network_id).rotate_key = false;
                }
                Step::Delete { object } => {
                    self.dev.delete(object).unwrap();
                    drop_under(&mut self.snap, object);
                }
                Step::WaitForFirmware { table, network_id } => {
                    let c = self.waits.entry(*network_id).or_default();
                    *c += 1;
                    if self.derive_at_wait == Some(*c) {
                        self.dev.derive();
                    }
                    self.refresh(table);
                }
                Step::Done { outcomes } => {
                    for o in outcomes {
                        if let Outcome::Applied {
                            network_id,
                            device_public_key,
                            ..
                        } = o
                        {
                            self.waits.remove(network_id);
                            if let Some(key) = device_public_key {
                                member(desired, *network_id).member_public_key = Some(key.clone());
                            }
                        }
                    }
                    return Run {
                        steps,
                        outcomes: outcomes.clone(),
                    };
                }
            }
            steps.push(step);
        }
        panic!("no convergence after {MAX_STEPS} steps: {steps:#?}");
    }

    /// Instance of `table` with Alias = `alias` on the device.
    fn instance(&self, table: &str, alias: &str) -> Option<String> {
        let tree = self.dev.read(table).ok()?;
        tree.iter()
            .find(|(k, p)| {
                k.ends_with(".Alias")
                    && p.value == alias
                    && k[table.len()..].matches('.').count() == 1
            })
            .map(|(k, _)| k.trim_end_matches("Alias").to_owned())
    }

    fn value(&self, path: &str) -> &str {
        self.dev.value(path).unwrap_or_else(|| panic!("no {path}"))
    }

    /// Check real device values (not the snapshot) vs `d`.
    fn assert_configured(&self, d: &DesiredTunnel) {
        let alias = alias_of(d.network_id);
        let peer = self.instance("Device.WireGuard.Peer.", &alias).unwrap();
        let tunnel = self.instance("Device.WireGuard.Tunnel.", &alias).unwrap();
        assert_eq!(
            self.value(&format!("{peer}PublicKey")),
            d.hub_public_key.as_deref().unwrap()
        );
        assert_eq!(
            self.value(&format!("{peer}EndpointAddress")),
            d.endpoint_host
        );
        assert_eq!(
            self.value(&format!("{peer}EndpointPort")),
            d.endpoint_port.to_string()
        );
        assert_eq!(
            self.value(&format!("{peer}PersistentKeepalive")),
            d.persistent_keepalive.to_string()
        );
        let mut prefixes = d.allowed_ips.clone();
        prefixes.sort();
        prefixes.dedup();
        let joined: Vec<String> = prefixes.iter().map(ToString::to_string).collect();
        assert_eq!(self.value(&format!("{peer}AllowedIPs")), joined.join(","));
        assert_eq!(self.value(&format!("{peer}Enable")), "true");
        assert_eq!(self.value(&format!("{tunnel}ListenPort")), "0");
        assert_eq!(
            self.value(&format!("{tunnel}PeerReferences")),
            peer.trim_end_matches('.')
        );
        assert_eq!(self.value(&format!("{tunnel}Enable")), "true");
        let tif = format!("{tunnel}Interface.1");
        assert_eq!(self.value(&format!("{tif}.Enable")), "true");
        // IP interface above tunnel interface: by LowerLayers, else by Name.
        let ip_tree = self.dev.read("Device.IP.Interface.").unwrap();
        let name = self.value(&format!("{tif}.Name"));
        let lower = ip_tree
            .iter()
            .find(|(k, p)| k.ends_with(".LowerLayers") && p.value.trim_end_matches('.') == tif)
            .or_else(|| {
                ip_tree
                    .iter()
                    .find(|(k, p)| k.ends_with(".Name") && !name.is_empty() && p.value == name)
            })
            .map(|(k, _)| k.rsplit_once('.').unwrap().0.to_owned() + ".")
            .unwrap_or_else(|| panic!("no IP interface above {tif}"));
        assert_eq!(self.value(&format!("{lower}MaxMTUSize")), d.mtu.to_string());
        assert_eq!(self.value(&format!("{lower}Enable")), "true");
        let v4 = format!("{lower}IPv4Address.1.");
        assert_eq!(self.value(&format!("{v4}IPAddress")), d.address.to_string());
        assert_eq!(self.value(&format!("{v4}SubnetMask")), "255.255.255.0");
        assert_eq!(self.value(&format!("{v4}Enable")), "true");
    }
}

fn member(desired: &mut [DesiredTunnel], id: Uuid) -> &mut DesiredTunnel {
    desired.iter_mut().find(|d| d.network_id == id).unwrap()
}

fn net(n: u8) -> Uuid {
    Uuid::from_bytes([n; 16])
}

fn desired(n: u8, key_mode: KeyMode) -> DesiredTunnel {
    DesiredTunnel {
        network_id: net(n),
        hub_public_key: Some(generate_keypair().unwrap().public),
        endpoint_host: "hub.example.net".to_owned(),
        endpoint_port: 51819 + u16::from(n),
        persistent_keepalive: 25,
        allowed_ips: vec![
            format!("192.168.{}.0/24", 100 + n).parse().unwrap(),
            format!("10.{n}.0.0/24").parse().unwrap(),
        ],
        address: Ipv4Addr::new(10, n, 0, 2),
        prefix: format!("10.{n}.0.0/24").parse().unwrap(),
        mtu: 1420,
        key_mode,
        member_public_key: None,
        rotate_key: false,
        preshared_key: None,
        send_preshared_key: false,
    }
}

/// (b): firmware makes tunnel interface + IP interface, device makes its key.
fn firmware_b() -> FakeOptions {
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

/// (a): firmware makes nothing.
fn firmware_a() -> FakeOptions {
    FakeOptions {
        tunnel_interface_made: false,
        firmware_ip_interface: false,
        makes_key: true,
        supported: true,
        regenerates_key: false,
        ip_interface_later: false,
        ip_lower_layers_empty: false,
    }
}

fn applied(run: &Run) -> (String, Option<String>) {
    match run.outcomes.as_slice() {
        [
            Outcome::Applied {
                desired_hash,
                device_public_key,
                ..
            },
        ] => (desired_hash.clone(), device_public_key.clone()),
        other => panic!("not applied: {other:?}"),
    }
}

fn blocked(reason: &str, n: u8) -> Vec<Outcome> {
    vec![Outcome::Blocked {
        network_id: net(n),
        reason: reason.to_owned(),
    }]
}

#[test]
fn firmware_made_ip_interface_and_device_key() {
    let mut drv = Driver::new(firmware_b());
    let lan = drv.dev.read("Device.IP.Interface.1.").unwrap();
    let mut want = vec![desired(1, KeyMode::Device)];
    let run = drv.run(&mut want);
    assert_eq!(
        run.adds(),
        ["Device.WireGuard.Peer.", "Device.WireGuard.Tunnel."]
    );
    assert_eq!(run.kinds(), ["read", "add", "add", "set", "read"]);
    match &run.steps[2] {
        Step::Add { then_read, .. } => assert_eq!(then_read, &["Device.IP.Interface."]),
        other => panic!("{other:?}"),
    }
    match &run.steps[1] {
        Step::Add { then_read, .. } => assert!(then_read.is_empty()),
        other => panic!("{other:?}"),
    }
    // Firmware made Device.IP.Interface.2, found by LowerLayers -> LowerLayers not set again.
    let sets = run.set_paths();
    assert!(
        !sets[0].iter().any(|p| p.ends_with("LowerLayers")),
        "{sets:?}"
    );
    assert!(sets[0].iter().rev().take(5).all(|p| p.ends_with(".Enable")));
    let (hash, key) = applied(&run);
    assert_eq!(hash, desired_hash(&want[0]));
    let device_key = drv.value("Device.WireGuard.Tunnel.1.PublicKey").to_owned();
    assert!(!device_key.is_empty());
    assert_eq!(key.as_deref(), Some(device_key.as_str()));
    drv.assert_configured(&want[0]);
    assert_eq!(drv.dev.read("Device.IP.Interface.1.").unwrap(), lan);

    // 2nd run: read only, nothing to do.
    let again = drv.run(&mut want);
    assert_eq!(again.kinds(), ["read"]);
    assert_eq!(applied(&again), (hash, None));
    assert_eq!(drv.dev.read("Device.IP.Interface.1.").unwrap(), lan);
}

#[test]
fn dhonomos_made_ip_interface() {
    let mut drv = Driver::new(firmware_a());
    let lan = drv.dev.read("Device.IP.Interface.1.").unwrap();
    let mut want = vec![desired(1, KeyMode::Device)];
    let run = drv.run(&mut want);
    assert_eq!(
        run.adds(),
        [
            "Device.WireGuard.Peer.",
            "Device.WireGuard.Tunnel.",
            "Device.WireGuard.Tunnel.1.Interface.",
            "Device.IP.Interface.",
            "Device.IP.Interface.2.IPv4Address.",
        ]
    );
    // No firmware IP interface -> WAIT_LIMIT waits, then own Add.
    assert_eq!(
        run.kinds(),
        [
            "read", "add", "add", "add", "wait", "wait", "add", "add", "set", "read"
        ]
    );
    assert_eq!(
        run.steps[4],
        Step::WaitForFirmware {
            table: "Device.IP.Interface.".to_owned(),
            network_id: net(1),
        }
    );
    assert!(drv.waits.is_empty());
    let sets = run.set_paths();
    assert_eq!(sets.len(), 1);
    assert!(sets[0].contains(&"Device.IP.Interface.2.LowerLayers"));
    assert_eq!(
        drv.value("Device.IP.Interface.2.LowerLayers"),
        "Device.WireGuard.Tunnel.1.Interface.1"
    );
    assert_eq!(drv.value("Device.IP.Interface.2.Alias"), alias_of(net(1)));
    applied(&run);
    drv.assert_configured(&want[0]);
    assert_eq!(drv.dev.read("Device.IP.Interface.1.").unwrap(), lan);
    assert_eq!(drv.run(&mut want).kinds(), ["read"]);
}

#[test]
fn server_key_mode() {
    let opts = FakeOptions {
        makes_key: false,
        ..firmware_b()
    };
    let mut drv = Driver::new(opts);
    let mut want = vec![desired(1, KeyMode::Server)];
    let run = drv.run(&mut want);
    assert_eq!(run.kinds(), ["read", "add", "add", "key", "set"]);
    let member_key = want[0].member_public_key.clone().unwrap();
    assert_eq!(drv.value("Device.WireGuard.Tunnel.1.PublicKey"), member_key);
    assert_eq!(applied(&run).1, None);
    drv.assert_configured(&want[0]);
    let again = drv.run(&mut want);
    assert_eq!(again.kinds(), ["read"]);
    assert_eq!(applied(&again).1, None);

    // Factory reset: fresh device, Dhonomos still knows the member key.
    // New Tunnel PublicKey = "" until a PrivateKey is set -> rule 6 sees a device that hides
    // it -> no key set, tunnel has no key.
    // Known gap: stage 6 handles key rotation + factory reset.
    drv.dev = FakeDevice::new(opts);
    let reset = drv.run(&mut want);
    assert_eq!(reset.kinds(), ["read", "add", "add", "set"]);
    applied(&reset);
    assert_eq!(drv.value("Device.WireGuard.Tunnel.1.PrivateKey"), "");
    assert_eq!(drv.value("Device.WireGuard.Tunnel.1.PublicKey"), "");
    assert_eq!(
        want[0].member_public_key.as_deref(),
        Some(member_key.as_str())
    );
}

#[test]
fn device_key_rotation() {
    let mut drv = Driver::new(FakeOptions {
        regenerates_key: true,
        ..firmware_b()
    });
    let mut want = vec![desired(1, KeyMode::Device)];
    applied(&drv.run(&mut want));
    let old = want[0].member_public_key.clone().unwrap();

    want[0].rotate_key = true;
    let run = drv.run(&mut want);
    assert_eq!(run.kinds(), ["read", "regenerate"]);
    assert_eq!(
        run.steps[1],
        Step::RegenerateKey {
            tunnel: "Device.WireGuard.Tunnel.1.".to_owned(),
            network_id: net(1),
        }
    );
    assert!(!want[0].rotate_key);
    let new = drv.value("Device.WireGuard.Tunnel.1.PublicKey").to_owned();
    assert!(!new.is_empty());
    assert_ne!(new, old);
    let (hash, key) = applied(&run);
    assert_eq!(hash, desired_hash(&want[0]));
    assert_eq!(key.as_deref(), Some(new.as_str()));
    assert_eq!(want[0].member_public_key.as_deref(), Some(new.as_str()));
    drv.assert_configured(&want[0]);
    assert_eq!(drv.run(&mut want).kinds(), ["read"]);
}

#[test]
fn server_key_rotation_sets_a_key_although_the_member_key_matches() {
    let mut drv = Driver::new(FakeOptions {
        makes_key: false,
        ..firmware_b()
    });
    let mut want = vec![desired(1, KeyMode::Server)];
    applied(&drv.run(&mut want));
    let old = want[0].member_public_key.clone().unwrap();
    assert_eq!(drv.value("Device.WireGuard.Tunnel.1.PublicKey"), old);

    want[0].rotate_key = true;
    let run = drv.run(&mut want);
    assert_eq!(run.kinds(), ["read", "key"]);
    assert!(!want[0].rotate_key);
    let new = want[0].member_public_key.clone().unwrap();
    assert_ne!(new, old);
    assert_eq!(drv.value("Device.WireGuard.Tunnel.1.PublicKey"), new);
    assert_eq!(applied(&run).1, None);
    assert_eq!(drv.run(&mut want).kinds(), ["read"]);
}

#[test]
fn device_that_keeps_its_key_on_rotation() {
    let mut drv = Driver::new(firmware_b());
    let mut want = vec![desired(1, KeyMode::Device)];
    applied(&drv.run(&mut want));
    let old = want[0].member_public_key.clone().unwrap();

    want[0].rotate_key = true;
    let run = drv.run(&mut want);
    assert_eq!(run.kinds(), ["read", "regenerate"]);
    assert_eq!(drv.value("Device.WireGuard.Tunnel.1.PublicKey"), old);
    assert_ne!(drv.value("Device.WireGuard.Tunnel.1.PrivateKey"), "");
    // Applied without a new key -> caller turns it into blocked.
    let (hash, key) = applied(&run);
    assert_eq!(hash, desired_hash(&want[0]));
    assert_eq!(key, None);
}

#[test]
fn device_key_mode_without_a_key_blocks() {
    let mut drv = Driver::new(FakeOptions {
        makes_key: false,
        ..firmware_b()
    });
    let mut want = vec![desired(1, KeyMode::Device)];
    let run = drv.run(&mut want);
    assert_eq!(run.kinds(), ["read", "add", "add", "set", "read"]);
    assert_eq!(
        run.steps.last(),
        Some(&Step::Read {
            paths: vec!["Device.WireGuard.Tunnel.1.".to_owned()]
        })
    );
    assert_eq!(run.outcomes, blocked("the device did not make a key", 1));
}

#[test]
fn no_hub_key_blocks_before_anything() {
    let mut drv = Driver::new(firmware_b());
    let mut want = vec![desired(1, KeyMode::Device)];
    want[0].hub_public_key = None;
    let run = drv.run(&mut want);
    assert_eq!(
        run.steps,
        [Step::Read {
            paths: vec![
                "Device.WireGuard.".to_owned(),
                "Device.IP.Interface.".to_owned()
            ]
        }]
    );
    assert_eq!(
        run.outcomes,
        blocked("the hub has not reported its public key yet", 1)
    );
}

#[test]
fn unsupported_device() {
    let mut drv = Driver::new(FakeOptions {
        supported: false,
        ..firmware_b()
    });
    let mut want = vec![desired(1, KeyMode::Device)];
    let run = drv.run(&mut want);
    assert_eq!(run.kinds(), ["read"]);
    assert_eq!(run.outcomes, [Outcome::Unsupported { network_id: net(1) }]);
}

#[test]
fn drift_is_repaired_with_one_set() {
    let mut drv = Driver::new(firmware_b());
    let mut want = vec![desired(1, KeyMode::Device)];
    drv.run(&mut want);
    drv.dev
        .set(&[
            (
                "Device.WireGuard.Peer.1.AllowedIPs".to_owned(),
                "0.0.0.0/0".to_owned(),
            ),
            (
                "Device.WireGuard.Peer.1.EndpointPort".to_owned(),
                "1".to_owned(),
            ),
        ])
        .unwrap();
    let run = drv.run(&mut want);
    assert_eq!(run.kinds(), ["read", "set"]);
    match &run.steps[1] {
        Step::Set { values, network_id } => {
            assert_eq!(*network_id, net(1));
            let got: Vec<(&str, &str, &str)> = values
                .iter()
                .map(|v| (v.path.as_str(), v.value.as_str(), v.xsd_type.as_str()))
                .collect();
            assert_eq!(
                got,
                [
                    ("Device.WireGuard.Peer.1.EndpointPort", "51820", "int"),
                    (
                        "Device.WireGuard.Peer.1.AllowedIPs",
                        "10.1.0.0/24,192.168.101.0/24",
                        "string"
                    ),
                ]
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(applied(&run).1, None);
    drv.assert_configured(&want[0]);
}

#[test]
fn desired_changes_are_one_set() {
    let mut drv = Driver::new(firmware_b());
    let mut want = vec![desired(1, KeyMode::Device)];
    let (before, _) = applied(&drv.run(&mut want));
    want[0]
        .allowed_ips
        .push("192.168.200.0/24".parse().unwrap());
    want[0].mtu = 1380;
    let run = drv.run(&mut want);
    assert_eq!(run.kinds(), ["read", "set"]);
    assert_eq!(
        run.set_paths(),
        [[
            "Device.WireGuard.Peer.1.AllowedIPs",
            "Device.IP.Interface.2.MaxMTUSize"
        ]]
    );
    let (after, _) = applied(&run);
    assert_ne!(before, after);
    assert_eq!(after, desired_hash(&want[0]));
    drv.assert_configured(&want[0]);
}

#[test]
fn two_networks_then_one_dropped() {
    let mut drv = Driver::new(firmware_a());
    let mut want = vec![desired(1, KeyMode::Device), desired(2, KeyMode::Device)];
    let run = drv.run(&mut want);
    assert_eq!(run.outcomes.len(), 2);
    for (o, n) in run.outcomes.iter().zip([1, 2]) {
        match o {
            Outcome::Applied { network_id, .. } => assert_eq!(*network_id, net(n)),
            other => panic!("{other:?}"),
        }
    }
    drv.assert_configured(&want[0]);
    drv.assert_configured(&want[1]);
    let a2 = alias_of(net(2));
    let peer2 = drv.instance("Device.WireGuard.Peer.", &a2).unwrap();
    let tunnel2 = drv.instance("Device.WireGuard.Tunnel.", &a2).unwrap();
    let ip2 = drv.instance("Device.IP.Interface.", &a2).unwrap();
    let rows2 = [
        drv.dev.read(&peer2).unwrap(),
        drv.dev.read(&tunnel2).unwrap(),
        drv.dev.read(&ip2).unwrap(),
    ];
    let a1 = alias_of(net(1));
    let peer1 = drv.instance("Device.WireGuard.Peer.", &a1).unwrap();
    let tunnel1 = drv.instance("Device.WireGuard.Tunnel.", &a1).unwrap();
    let ip1 = drv.instance("Device.IP.Interface.", &a1).unwrap();

    let mut only_two = vec![want[1].clone()];
    let run = drv.run(&mut only_two);
    assert_eq!(
        run.steps[1..],
        [
            Step::Delete { object: tunnel1 },
            Step::Delete { object: peer1 },
            Step::Delete { object: ip1 },
        ]
    );
    assert_eq!(run.kinds(), ["read", "delete", "delete", "delete"]);
    assert_eq!(applied(&run).1, None);
    assert_eq!(drv.instance("Device.WireGuard.Peer.", &a1), None);
    assert_eq!(
        [
            drv.dev.read(&peer2).unwrap(),
            drv.dev.read(&tunnel2).unwrap(),
            drv.dev.read(&ip2).unwrap(),
        ],
        rows2
    );
    assert_eq!(drv.value("Device.WireGuard.TunnelNumberOfEntries"), "1");

    // Nothing desired -> rest deleted too, then nothing to do.
    let run = drv.run(&mut []);
    assert_eq!(run.kinds(), ["read", "delete", "delete", "delete"]);
    assert!(run.outcomes.is_empty());
    assert_eq!(drv.value("Device.WireGuard.PeerNumberOfEntries"), "0");
    assert_eq!(drv.value("Device.IP.Interface.1.Alias"), "cpe-lan");
}

#[test]
fn rows_of_kept_networks_are_not_deleted() {
    let mut drv = Driver::new(firmware_a());
    let mut want = vec![
        desired(1, KeyMode::Device),
        desired(2, KeyMode::Device),
        desired(3, KeyMode::Device),
    ];
    drv.run(&mut want);
    let a1 = alias_of(net(1));
    let a2 = alias_of(net(2));
    let peer2 = drv.instance("Device.WireGuard.Peer.", &a2).unwrap();
    let tunnel2 = drv.instance("Device.WireGuard.Tunnel.", &a2).unwrap();
    let ip2 = drv.instance("Device.IP.Interface.", &a2).unwrap();
    let rows2 = [
        drv.dev.read(&peer2).unwrap(),
        drv.dev.read(&tunnel2).unwrap(),
        drv.dev.read(&ip2).unwrap(),
    ];
    let peer3 = drv
        .instance("Device.WireGuard.Peer.", &alias_of(net(3)))
        .unwrap();
    let tunnel3 = drv
        .instance("Device.WireGuard.Tunnel.", &alias_of(net(3)))
        .unwrap();
    let ip3 = drv
        .instance("Device.IP.Interface.", &alias_of(net(3)))
        .unwrap();

    // Network 1 still desired, network 2 managed by the twin record, network 3 wanted by none
    // -> only rows of network 3 deleted.
    drv.kept = BTreeSet::from([net(2)]);
    let mut only_one = vec![want[0].clone()];
    let run = drv.run(&mut only_one);
    assert_eq!(
        run.steps[1..],
        [
            Step::Delete { object: tunnel3 },
            Step::Delete { object: peer3 },
            Step::Delete { object: ip3 },
        ]
    );
    assert_eq!(applied(&run).1, None);
    drv.assert_configured(&want[0]);
    assert!(drv.instance("Device.WireGuard.Peer.", &a1).is_some());
    assert_eq!(
        [
            drv.dev.read(&peer2).unwrap(),
            drv.dev.read(&tunnel2).unwrap(),
            drv.dev.read(&ip2).unwrap(),
        ],
        rows2
    );

    // Nothing desired -> rows of network 1 deleted, network 2 kept; then nothing to do.
    let run = drv.run(&mut []);
    assert_eq!(run.kinds(), ["read", "delete", "delete", "delete"]);
    assert!(run.outcomes.is_empty());
    let run = drv.run(&mut []);
    assert_eq!(run.kinds(), ["read"]);
    assert_eq!(drv.instance("Device.WireGuard.Peer.", &a1), None);
    assert_eq!(
        [
            drv.dev.read(&peer2).unwrap(),
            drv.dev.read(&tunnel2).unwrap(),
            drv.dev.read(&ip2).unwrap(),
        ],
        rows2
    );
}

#[test]
fn read_only_value_that_must_change_blocks() {
    let mut drv = Driver::new(firmware_b());
    let mut want = vec![desired(1, KeyMode::Device)];
    drv.run(&mut want);
    // Device reports EndpointPort read-only + new port desired.
    let path = "Device.WireGuard.Peer.1.EndpointPort";
    drv.snap.get_mut(path).unwrap().writable = Some(false);
    want[0].endpoint_port = 40000;
    let read = BTreeSet::from([
        "Device.WireGuard.".to_owned(),
        "Device.IP.Interface.".to_owned(),
    ]);
    let step = plan(&PlanInput {
        desired: &want,
        tree: &drv.snap,
        read: &read,
        ip_wait_over: &BTreeSet::new(),
        kept: &BTreeSet::new(),
    });
    assert_eq!(
        step,
        Step::Done {
            outcomes: blocked(&format!("{path} is not writable on this device"), 1)
        }
    );
    // Port unchanged -> read-only does not matter.
    want[0].endpoint_port = 51820;
    let step = plan(&PlanInput {
        desired: &want,
        tree: &drv.snap,
        read: &read,
        ip_wait_over: &BTreeSet::new(),
        kept: &BTreeSet::new(),
    });
    assert!(
        matches!(&step, Step::Done { outcomes } if matches!(outcomes[..], [Outcome::Applied { .. }])),
        "{step:?}"
    );
}

#[test]
fn nothing_desired_and_nothing_there_needs_no_read() {
    let drv = Driver::new(firmware_b());
    assert_eq!(
        plan(&PlanInput {
            desired: &[],
            tree: &drv.snap,
            read: &BTreeSet::new(),
            ip_wait_over: &BTreeSet::new(),
            kept: &BTreeSet::new(),
        }),
        Step::Done {
            outcomes: Vec::new()
        }
    );
    let mut drv = drv;
    let run = drv.run(&mut []);
    assert!(run.steps.is_empty());
    assert!(run.outcomes.is_empty());
}

#[test]
fn rows_of_others_are_never_touched() {
    let mut drv = Driver::new(firmware_a());
    drv.dev
        .add("Device.WireGuard.Peer.", "operator-peer")
        .unwrap();
    drv.dev.add("Device.WireGuard.Tunnel.", "").unwrap();
    // Our alias prefix, but not the exact form.
    drv.dev
        .add("Device.IP.Interface.", "dhonomos-wg-notours")
        .unwrap();
    let before = (
        drv.dev.read("Device.WireGuard.").unwrap(),
        drv.dev.read("Device.IP.Interface.").unwrap(),
    );
    // Snapshot of an earlier run has WireGuard rows -> planner reads.
    assert!(drv.refresh("Device.WireGuard."));
    let run = drv.run(&mut []);
    assert_eq!(run.kinds(), ["read"]);
    assert!(run.outcomes.is_empty());
    assert_eq!(
        (
            drv.dev.read("Device.WireGuard.").unwrap(),
            drv.dev.read("Device.IP.Interface.").unwrap(),
        ),
        before
    );
}

/// LS500X: firmware makes the IP interface (by Name, LowerLayers "") after the request
/// that added the tunnel is committed.
fn ls500x() -> FakeOptions {
    FakeOptions {
        ip_interface_later: true,
        ..firmware_b()
    }
}

#[test]
fn ip_interface_found_by_name_when_lower_layers_is_empty() {
    let mut drv = Driver::new(FakeOptions {
        ip_lower_layers_empty: true,
        ..firmware_b()
    });
    let mut want = vec![desired(1, KeyMode::Device)];
    let run = drv.run(&mut want);
    assert_eq!(
        run.adds(),
        ["Device.WireGuard.Peer.", "Device.WireGuard.Tunnel."]
    );
    assert_eq!(run.kinds(), ["read", "add", "add", "set", "read"]);
    let sets = run.set_paths();
    assert!(
        !sets.iter().flatten().any(|p| p.ends_with("LowerLayers")),
        "{sets:?}"
    );
    assert!(sets[0].contains(&"Device.IP.Interface.2.MaxMTUSize"));
    assert!(sets[0].contains(&"Device.IP.Interface.2.IPv4Address.1.IPAddress"));
    assert_eq!(drv.value("Device.IP.Interface.2.LowerLayers"), "");
    applied(&run);
    drv.assert_configured(&want[0]);
    assert_eq!(drv.run(&mut want).kinds(), ["read"]);
}

#[test]
fn firmware_that_makes_the_ip_interface_later_is_waited_for() {
    for lower_layers_empty in [false, true] {
        let mut drv = Driver::new(FakeOptions {
            ip_lower_layers_empty: lower_layers_empty,
            ..ls500x()
        });
        drv.derive_at_wait = Some(1);
        let mut want = vec![desired(1, KeyMode::Device)];
        let run = drv.run(&mut want);
        assert_eq!(run.kinds(), ["read", "add", "add", "wait", "set", "read"]);
        assert_eq!(
            run.adds(),
            ["Device.WireGuard.Peer.", "Device.WireGuard.Tunnel."]
        );
        let sets = run.set_paths();
        assert!(
            !sets.iter().flatten().any(|p| p.ends_with("LowerLayers")),
            "{sets:?}"
        );
        assert!(sets[0].contains(&"Device.IP.Interface.2.MaxMTUSize"));
        applied(&run);
        drv.assert_configured(&want[0]);
        assert!(drv.waits.is_empty());
        assert_eq!(drv.run(&mut want).kinds(), ["read"]);
    }
}

#[test]
fn firmware_that_never_makes_the_ip_interface_and_refuses_the_add() {
    let mut drv = Driver::new(ls500x());
    let want = vec![desired(1, KeyMode::Device)];
    let mut read = BTreeSet::new();
    // Drive by hand up to the Add in Device.IP.Interface. -> fake refuses it.
    let mut kinds = Vec::new();
    loop {
        let over = drv.ip_wait_over();
        let step = plan(&PlanInput {
            desired: &want,
            tree: &drv.snap,
            read: &read,
            ip_wait_over: &over,
            kept: &BTreeSet::new(),
        });
        match &step {
            Step::Read { paths } => {
                for p in paths {
                    drv.refresh(p);
                    read.insert(p.clone());
                }
                kinds.push("read");
            }
            Step::Add {
                table,
                alias,
                then_read,
                ..
            } if table != "Device.IP.Interface." => {
                let inst = drv.dev.add(table, alias).unwrap();
                drv.refresh(&inst);
                for p in then_read {
                    drv.refresh(p);
                }
                kinds.push("add");
            }
            Step::Add { table, alias, .. } => {
                assert_eq!(
                    drv.dev.add(table, alias),
                    Err(FakeError::NotWritable("Device.IP.Interface.".to_owned()))
                );
                kinds.push("add ip");
                break;
            }
            Step::WaitForFirmware { table, network_id } => {
                *drv.waits.entry(*network_id).or_default() += 1;
                drv.refresh(table);
                kinds.push("wait");
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(kinds, ["read", "add", "add", "wait", "wait", "add ip"]);
}
