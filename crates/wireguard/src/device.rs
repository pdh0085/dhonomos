//! Converging planner for a device member (ADR-110, stage 4): next step so that the CPE's
//! TR-181 `Device.WireGuard.` (+ IP layer above it) = desired.
//!
//! Pure: desired tunnels + current parameter snapshot -> next single [`Step`].
//! Caller runs it (CWMP RPC or USP message), updates the snapshot, calls again until
//! [`Step::Done`].
//!
//! Our rows: Alias `dhonomos-wg-<network id as 32 lowercase hex>` ([`alias_of`]).
//! `A(n)` below = alias of network `n`.
//! Instances of table `T` (ends with `.`) = distinct decimal `i` with a snapshot key that
//! starts with `T` + `i` + `.`, ascending numeric order.
//! Alias of an instance = value of `<instance>Alias`.
//!
//! Rules, in order:
//!
//! - **R0, reads.** No desired tunnel + no key under `Device.WireGuard.` -> done, no read.
//!   Else, while `Device.WireGuard.` not in `read` -> read it (also `Device.IP.Interface.`
//!   when there are desired tunnels and it is not read either).
//!   Read, but snapshot still empty under it -> every desired network
//!   [`Outcome::Unsupported`].
//! - **R1, stale rows.** Rows with one of our aliases for a network not desired and not kept
//!   ([`PlanInput::kept`]: another record of the same physical device manages its rows)
//!   -> deleted, one per step: Tunnel instances, then Peer instances, then
//!   `Device.IP.Interface.` instances. Rows with any other alias (or none) + rows of a kept
//!   network: never touched.
//! - **R2, per desired network in input order.** Outcome for one network does not stop the
//!   others. First network that needs a step -> that step. Outcome for every network
//!   -> [`Step::Done`].
//!   1. No hub public key -> blocked.
//!   2. Peer `p`: `Device.WireGuard.Peer.` instance with Alias `A(n)`, else add one.
//!   3. Tunnel `t`: `Device.WireGuard.Tunnel.` instance with Alias `A(n)`, else add one
//!      (`then_read` = `Device.IP.Interface.`: firmware may make the IP interface of a new
//!      tunnel).
//!   4. Tunnel interface `k`: `Tunnel.{t}.Interface.` instance with Alias `A(n)`, else the
//!      lowest-numbered one, else add one.
//!   5. Key rotation (`rotate_key`): server key mode -> set a private key
//!      ([`Step::SetPrivateKey`]); device key mode -> device makes a new key
//!      ([`Step::RegenerateKey`]).
//!   6. Server key mode: no member key, or non-empty `Tunnel.{t}.PublicKey` != member key
//!      -> set a private key. (Empty `PublicKey` + member key = device that hides it.)
//!      After each private key it sets -> caller reads the tunnel again -> snapshot shows
//!      the device's new `PublicKey` (or "").
//!
//!      Rules 5 + 6 need the Tunnel only -> before the IP layer -> a run that ends at a wait
//!      for the firmware (rule 7) has already set the key of a tunnel it just added.
//!   7. IP interface `x`: `Device.IP.Interface.` instance whose `LowerLayers` lists
//!      `Device.WireGuard.Tunnel.{t}.Interface.{k}` (entries trimmed, one trailing `.`
//!      ignored); else the lowest-numbered one with `Name` equal to
//!      `Tunnel.{t}.Interface.{k}.Name` (both non-empty, exact compare: firmware that
//!      leaves `LowerLayers` empty); else the one with Alias `A(n)`; else, while `n` not in
//!      `ip_wait_over` -> wait for the firmware to make it ([`Step::WaitForFirmware`]:
//!      firmware may make the IP interface of a new tunnel only some time after the commit
//!      of the request that added the tunnel); else add one.
//!   8. IPv4 address `a`: `IP.Interface.{x}.IPv4Address.` instance with Alias `A(n)`, else
//!      the lowest-numbered one, else add one.
//!   9. Values (list + compare rules: [`plan`]): every differing desired value -> one
//!      request, `Enable`s last. Differing value the snapshot reports not writable
//!      -> network blocked. Pre-shared key (`Peer.{p}.PresharedKey`) = secured value, reads
//!      as "", no compare -> in the request exactly when
//!      [`DesiredTunnel::send_preshared_key`] (the key, or "" for none). Device without that
//!      parameter + key wanted -> network blocked.
//!   10. Device key mode: empty `Tunnel.{t}.PublicKey` -> read once more
//!       (`Device.WireGuard.Tunnel.{t}.`), then network blocked.
//!   11. Applied.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::net::Ipv4Addr;

use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::keys::key_from_text;
use crate::prefix::Ipv4Prefix;

/// Start of every alias Dhonomos gives a row.
pub const ALIAS_PREFIX: &str = "dhonomos-wg-";

const WG_ROOT: &str = "Device.WireGuard.";
const PEER_TABLE: &str = "Device.WireGuard.Peer.";
const TUNNEL_TABLE: &str = "Device.WireGuard.Tunnel.";
const IP_TABLE: &str = "Device.IP.Interface.";

/// `dhonomos-wg-<32 hex>`.
pub fn alias_of(network_id: Uuid) -> String {
    format!("{ALIAS_PREFIX}{}", network_id.simple())
}

/// Network of one of our aliases (exact form only), else None.
pub fn network_of_alias(alias: &str) -> Option<Uuid> {
    let hex = alias.strip_prefix(ALIAS_PREFIX)?;
    if hex.len() != 32 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    Uuid::try_parse(hex).ok()
}

/// Who makes the device's key pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMode {
    /// CPE makes its key -> Dhonomos reads `Tunnel.PublicKey`.
    Device,
    /// Dhonomos makes the key pair -> sets `Tunnel.PrivateKey`.
    Server,
}

/// Desired state of one network membership of the device. `Debug` hides the pre-shared key.
#[derive(Clone, PartialEq, Eq)]
pub struct DesiredTunnel {
    pub network_id: Uuid,
    /// None until the hub process reported it.
    pub hub_public_key: Option<String>,
    /// Hub host name or address.
    pub endpoint_host: String,
    /// Hub port of the network.
    pub endpoint_port: u16,
    /// Keepalive interval, s (0 = off).
    pub persistent_keepalive: u16,
    /// Tunnel prefix + site prefixes of the other members.
    /// Any order -> compared as a set, written sorted ascending.
    pub allowed_ips: Vec<Ipv4Prefix>,
    /// Tunnel address of the member.
    pub address: Ipv4Addr,
    /// Tunnel prefix -> subnet mask.
    pub prefix: Ipv4Prefix,
    pub mtu: u16,
    pub key_mode: KeyMode,
    /// Member public key Dhonomos knows. Server mode: the one it made; device mode: last read.
    /// Not in `desired_hash`.
    pub member_public_key: Option<String>,
    /// New key wanted in this run. Caller: set from the member's request, clear after the
    /// rotation step. Not in `desired_hash`.
    pub rotate_key: bool,
    /// Pre-shared key, 32 bytes base64; `None` = none. Secret.
    pub preshared_key: Option<Zeroizing<String>>,
    /// Give the device the pre-shared key (or "" for none) in this run.
    /// Secured value reads as "" -> planner cannot tell if the device has it -> caller decides.
    /// Server runs send it while not set yet in the run, when the run added the network's
    /// Peer row, member not `applied`, or member's applied hash != this [`desired_hash`]
    /// (a run that ended before the values, e.g. at a wait for the firmware, may have stored
    /// the hash already). Not in `desired_hash`.
    pub send_preshared_key: bool,
}

impl fmt::Debug for DesiredTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DesiredTunnel")
            .field("network_id", &self.network_id)
            .field("hub_public_key", &self.hub_public_key)
            .field("endpoint_host", &self.endpoint_host)
            .field("endpoint_port", &self.endpoint_port)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("allowed_ips", &self.allowed_ips)
            .field("address", &self.address)
            .field("prefix", &self.prefix)
            .field("mtu", &self.mtu)
            .field("key_mode", &self.key_mode)
            .field("member_public_key", &self.member_public_key)
            .field("rotate_key", &self.rotate_key)
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| REDACTED),
            )
            .field("send_preshared_key", &self.send_preshared_key)
            .finish()
    }
}

/// `Debug` text for a secret.
const REDACTED: &str = "********";

/// Append `name=<byte length>:<text>\n`.
fn render_text(out: &mut String, name: &str, text: &str) {
    // Write to a String never fails.
    let _ = writeln!(out, "{name}={}:{text}", text.len());
}

/// First 16 bytes of SHA-256 of `data`, as 32 lowercase hex chars.
fn hex16(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut hex = String::with_capacity(32);
    for b in digest.iter().take(16) {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Hex SHA-256 (first 16 bytes, 32 lowercase hex chars) of a canonical rendering of every
/// field except `member_public_key`, `rotate_key`, `send_preshared_key`.
///
/// Rendering: UTF-8 text, one line per field, each ends with `\n`, this order:
///
/// ```text
/// dhonomos-wg-desired-v2
/// network_id=<hyphenated lowercase UUID>
/// hub_public_key=none                      (or hub_public_key=<byte length>:<key>)
/// endpoint_host=<byte length>:<host>
/// endpoint_port=<decimal>
/// persistent_keepalive=<decimal>
/// allowed_ips=<prefixes a.b.c.d/len, deduplicated, sorted ascending, joined with ",">
/// address=<a.b.c.d>
/// prefix=<a.b.c.d/len>
/// mtu=<decimal>
/// key_mode=device                          (or key_mode=server)
/// preshared_key=none                       (or preshared_key=<32 lowercase hex>)
/// ```
///
/// Prefixes sort by network address, then length. Pre-shared key never in the rendering:
/// its line = first 16 bytes of SHA-256 of the key's 32 bytes (of the text bytes when not a
/// key), as 32 lowercase hex chars.
///
/// Stored value (member's applied hash) -> never change the rendering of a version.
/// `v1` = same without the `preshared_key` line -> every hash stored under it != its `v2`
/// hash -> each member configured once more after the upgrade.
pub fn desired_hash(d: &DesiredTunnel) -> String {
    let mut out = String::from("dhonomos-wg-desired-v2\n");
    let _ = writeln!(out, "network_id={}", d.network_id.hyphenated());
    match &d.hub_public_key {
        Some(key) => render_text(&mut out, "hub_public_key", key),
        None => out.push_str("hub_public_key=none\n"),
    }
    render_text(&mut out, "endpoint_host", &d.endpoint_host);
    let _ = writeln!(out, "endpoint_port={}", d.endpoint_port);
    let _ = writeln!(out, "persistent_keepalive={}", d.persistent_keepalive);
    let _ = writeln!(out, "allowed_ips={}", allowed_ips_text(&d.allowed_ips));
    let _ = writeln!(out, "address={}", d.address);
    let _ = writeln!(out, "prefix={}", d.prefix);
    let _ = writeln!(out, "mtu={}", d.mtu);
    out.push_str(match d.key_mode {
        KeyMode::Device => "key_mode=device\n",
        KeyMode::Server => "key_mode=server\n",
    });
    match &d.preshared_key {
        Some(key) => {
            let digest = match key_from_text(key) {
                Ok(bytes) => hex16(&bytes[..]),
                Err(_) => hex16(key.as_bytes()),
            };
            let _ = writeln!(out, "preshared_key={digest}");
        }
        None => out.push_str("preshared_key=none\n"),
    }
    hex16(out.as_bytes())
}

/// Prefixes deduplicated, sorted ascending, joined with ",".
fn allowed_ips_text(prefixes: &[Ipv4Prefix]) -> String {
    prefixes
        .iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// One snapshot parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    /// Value as read (secured parameters read as "").
    pub value: String,
    /// Writable as the device reported it; None = not reported.
    pub writable: Option<bool>,
    /// Type the device reported; None = not reported.
    pub xsd_type: Option<String>,
}

/// Snapshot: full parameter path -> parameter (leaf parameters only).
pub type Tree = BTreeMap<String, Param>;

/// One value to set. `Debug` hides the value of a secret.
#[derive(Clone, PartialEq, Eq)]
pub struct SetParam {
    /// Full parameter path.
    pub path: String,
    pub value: String,
    /// Type to send (device's reported type when known).
    pub xsd_type: String,
    /// Secret (pre-shared key) -> caller seals it in the task, redacts it after the task ends.
    pub secret: bool,
}

impl fmt::Debug for SetParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = if self.secret {
            REDACTED
        } else {
            self.value.as_str()
        };
        f.debug_struct("SetParam")
            .field("path", &self.path)
            .field("value", &value)
            .field("xsd_type", &self.xsd_type)
            .field("secret", &self.secret)
            .finish()
    }
}

/// Next action of the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Read these object paths (each ends with '.').
    /// Read OK -> caller adds each to `read` + refreshes the snapshot under it.
    Read {
        /// Object paths.
        paths: Vec<String>,
    },
    /// Firmware expected to make a row in `table` (now always "Device.IP.Interface.") for the
    /// network's new tunnel, some time after the commit of the request that added the tunnel.
    /// Caller reads `table` again later (replaces snapshot under it; not added to `read`) and
    /// plans again. Stops waiting -> puts the network in [`PlanInput::ip_wait_over`]
    /// -> planner adds the row itself.
    WaitForFirmware {
        table: String,
        /// Network it is for.
        network_id: Uuid,
    },
    /// Create an instance in `table` (ends with '.', e.g. "Device.WireGuard.Peer.") with
    /// `alias`. Caller must then make the new instance (with its Alias) appear in the
    /// snapshot (reads the instance), then read every path in `then_read`, replacing the
    /// snapshot under each (not added to `read`).
    Add {
        table: String,
        /// Alias of the new instance.
        alias: String,
        network_id: Uuid,
        /// Object paths (end with '.') where firmware may make rows because of this Add:
        /// `["Device.IP.Interface."]` for an Add in `Device.WireGuard.Tunnel.`, else empty.
        /// (Firmware that makes the row only later -> [`Step::WaitForFirmware`].)
        then_read: Vec<String>,
    },
    /// Set these values in one request (order kept: every `...Enable` last).
    /// Value marked `secret` -> sealed in the task, redacted after the task ends.
    Set {
        values: Vec<SetParam>,
        network_id: Uuid,
    },
    /// Server key mode: make a key pair, set `<tunnel>PrivateKey` (secret) to its private
    /// key, store its public key as member key, then read `<tunnel>` (replaces snapshot under
    /// it) before planning again. `tunnel` = instance path, ends with '.', e.g.
    /// "Device.WireGuard.Tunnel.2.".
    SetPrivateKey {
        tunnel: String,
        /// Network it is for.
        network_id: Uuid,
    },
    /// Device key mode, key rotation: caller sets `<tunnel>PrivateKey` to "" (not a secret;
    /// firmware then makes a new key pair), then reads `<tunnel>` (replaces snapshot under it)
    /// before planning again. `tunnel` = instance path, ends with '.'.
    RegenerateKey {
        tunnel: String,
        /// Network it is for.
        network_id: Uuid,
    },
    /// Delete an instance (path ends with '.').
    Delete {
        /// Instance path.
        object: String,
    },
    /// Nothing left to do.
    Done {
        /// One per desired network, input order.
        outcomes: Vec<Outcome>,
    },
}

/// End state of one desired network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Configured as desired.
    Applied {
        network_id: Uuid,
        /// [`desired_hash`] of what was applied.
        desired_hash: String,
        /// Device key mode: key read from the device when != `member_public_key`
        /// -> caller stores it. Else None.
        device_public_key: Option<String>,
    },
    /// Cannot go on for this network.
    Blocked {
        network_id: Uuid,
        /// Why, in English.
        reason: String,
    },
    /// Device has no `Device.WireGuard.` at all (after reading it).
    Unsupported {
        /// The network.
        network_id: Uuid,
    },
}

/// Planner input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanInput<'a> {
    /// Desired network memberships of the device.
    pub desired: &'a [DesiredTunnel],
    /// Current snapshot.
    pub tree: &'a Tree,
    /// Object paths already read in this run (see read rules).
    pub read: &'a BTreeSet<String>,
    /// Networks where the caller stopped waiting for firmware to make the IP interface
    /// ([`Step::WaitForFirmware`]) -> rule 7 adds it.
    pub ip_wait_over: &'a BTreeSet<Uuid>,
    /// Networks whose rows another record of the same physical device manages
    /// (CPE with CWMP + USP = 2 devices) -> R1 leaves their rows alone.
    pub kept: &'a BTreeSet<Uuid>,
}

/// Instance numbers of `table` (ends with '.'), ascending.
fn instances(tree: &Tree, table: &str) -> Vec<u32> {
    let mut found = BTreeSet::new();
    for key in tree
        .range::<str, _>((std::ops::Bound::Included(table), std::ops::Bound::Unbounded))
        .map(|(k, _)| k)
        .take_while(|k| k.starts_with(table))
    {
        let rest = &key[table.len()..];
        if let Some((num, _)) = rest.split_once('.')
            && !num.is_empty()
            && num.bytes().all(|b| b.is_ascii_digit())
            && let Ok(n) = num.parse::<u32>()
        {
            found.insert(n);
        }
    }
    found.into_iter().collect()
}

fn value<'t>(tree: &'t Tree, path: &str) -> Option<&'t str> {
    tree.get(path).map(|p| p.value.as_str())
}

fn by_alias(tree: &Tree, table: &str, alias: &str) -> Option<u32> {
    instances(tree, table)
        .into_iter()
        .find(|i| value(tree, &format!("{table}{i}.Alias")) == Some(alias))
}

/// Instance of `table` with Alias `alias`, else the lowest-numbered one.
fn by_alias_or_first(tree: &Tree, table: &str, alias: &str) -> Option<u32> {
    by_alias(tree, table, alias).or_else(|| instances(tree, table).first().copied())
}

fn has_under(tree: &Tree, prefix: &str) -> bool {
    tree.range::<str, _>((
        std::ops::Bound::Included(prefix),
        std::ops::Bound::Unbounded,
    ))
    .next()
    .is_some_and(|(k, _)| k.starts_with(prefix))
}

/// Compare rule: desired value vs device value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Compare {
    /// "true"/"1" or "false"/"0", case-insensitive.
    Boolean,
    /// Numeric.
    UnsignedInt,
    /// Set of prefixes; bare address = /32.
    Prefixes,
    /// Set of object references, each without trailing '.'.
    References,
    /// ASCII case-insensitive.
    Host,
    Exact,
    /// Never same: secured value reads as "".
    Secured,
}

impl Compare {
    /// Default xsd type for this rule.
    fn xsd_type(self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::UnsignedInt => "unsignedInt",
            _ => "string",
        }
    }
}

/// Boolean as TR-106 writes it.
fn parse_bool(s: &str) -> Option<bool> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("true") || s == "1" {
        Some(true)
    } else if s.eq_ignore_ascii_case("false") || s == "0" {
        Some(false)
    } else {
        None
    }
}

/// Comma-separated prefix list; None when an entry does not parse.
fn parse_prefixes(s: &str) -> Option<BTreeSet<Ipv4Prefix>> {
    if s.trim().is_empty() {
        return Some(BTreeSet::new());
    }
    s.split(',')
        .map(|entry| {
            let entry = entry.trim();
            if entry.contains('/') {
                entry.parse::<Ipv4Prefix>().ok()
            } else {
                entry
                    .parse::<Ipv4Addr>()
                    .ok()
                    .and_then(|a| Ipv4Prefix::new(a, 32))
            }
        })
        .collect()
}

/// Comma-separated reference list as a set: entries trimmed, one trailing '.' dropped,
/// empty entries ignored.
fn parse_references(s: &str) -> BTreeSet<&str> {
    s.split(',')
        .map(|e| {
            let e = e.trim();
            e.strip_suffix('.').unwrap_or(e)
        })
        .filter(|e| !e.is_empty())
        .collect()
}

/// Device value `have` = desired `want` under `cmp`?
fn same(cmp: Compare, want: &str, have: &str) -> bool {
    match cmp {
        Compare::Boolean => {
            parse_bool(want).is_some_and(|w| parse_bool(have).is_some_and(|h| h == w))
        }
        Compare::UnsignedInt => want
            .trim()
            .parse::<u64>()
            .is_ok_and(|w| have.trim().parse::<u64>().is_ok_and(|h| h == w)),
        Compare::Prefixes => {
            parse_prefixes(want).is_some_and(|w| parse_prefixes(have).is_some_and(|h| h == w))
        }
        Compare::References => parse_references(want) == parse_references(have),
        Compare::Host => want.eq_ignore_ascii_case(have),
        Compare::Exact => want == have,
        Compare::Secured => false,
    }
}

/// Dotted subnet mask of `prefix`.
fn subnet_mask(prefix: Ipv4Prefix) -> Ipv4Addr {
    let len = u32::from(prefix.prefix_len());
    Ipv4Addr::from(u32::MAX.checked_shl(32 - len).unwrap_or(0))
}

/// R2 decision for one network.
enum Next {
    Step(Step),
    Outcome(Outcome),
}

/// Next step (rules: module header).
///
/// Values of rule 9, in order (all paths absolute):
///
/// - `Device.WireGuard.Peer.{p}.PublicKey` = hub key, `.EndpointAddress` = endpoint host
///   (ASCII case-insensitive compare), `.EndpointPort` + `.PersistentKeepalive`
///   (unsignedInt), `.AllowedIPs` = prefixes sorted, joined with "," (compared as a set of
///   prefixes; bare address counts as /32; unparsable list differs);
/// - `Device.WireGuard.Tunnel.{t}.ListenPort` = 0 (unsignedInt), `.PeerReferences` =
///   `Device.WireGuard.Peer.{p}` (compared as a set of references without trailing '.');
/// - only when `x` found by Alias (not by `LowerLayers` or `Name`):
///   `Device.IP.Interface.{x}.LowerLayers` = `Device.WireGuard.Tunnel.{t}.Interface.{k}`
///   (compared like `PeerReferences`);
/// - `Device.IP.Interface.{x}.MaxMTUSize` = MTU (unsignedInt);
/// - `Device.IP.Interface.{x}.IPv4Address.{a}.IPAddress` = address, `.SubnetMask` = dotted
///   mask of the tunnel prefix;
/// - only with `send_preshared_key`: `Device.WireGuard.Peer.{p}.PresharedKey` = pre-shared
///   key, or "" for none (type `string`, marked `secret` when not empty; never compared
///   -> always in the request). Path not in snapshot -> wanted key blocks the network,
///   "" left out;
/// - last, `true` (boolean, "true"/"1" and "false"/"0" case-insensitive) for
///   `Peer.{p}.Enable`, `Tunnel.{t}.Interface.{k}.Enable`, `Tunnel.{t}.Enable`,
///   `IP.Interface.{x}.IPv4Address.{a}.Enable` and `IP.Interface.{x}.Enable`.
///
/// Anything else: exact compare. Value differs when the snapshot lacks the path or the
/// values are not the same. Device's reported type, when present -> `xsd_type` sent.
pub fn plan(input: &PlanInput<'_>) -> Step {
    let PlanInput {
        desired,
        tree,
        read,
        ip_wait_over,
        kept,
    } = *input;

    // R0.
    let has_wg = has_under(tree, WG_ROOT);
    if desired.is_empty() && !has_wg {
        return Step::Done {
            outcomes: Vec::new(),
        };
    }
    if !read.contains(WG_ROOT) {
        let mut paths = vec![WG_ROOT.to_owned()];
        if !desired.is_empty() && !read.contains(IP_TABLE) {
            paths.push(IP_TABLE.to_owned());
        }
        return Step::Read { paths };
    }
    if !has_wg {
        return Step::Done {
            outcomes: desired
                .iter()
                .map(|d| Outcome::Unsupported {
                    network_id: d.network_id,
                })
                .collect(),
        };
    }

    // R1.
    let wanted: BTreeSet<Uuid> = desired.iter().map(|d| d.network_id).collect();
    for table in [TUNNEL_TABLE, PEER_TABLE, IP_TABLE] {
        for i in instances(tree, table) {
            let stale = value(tree, &format!("{table}{i}.Alias"))
                .and_then(network_of_alias)
                .is_some_and(|n| !wanted.contains(&n) && !kept.contains(&n));
            if stale {
                return Step::Delete {
                    object: format!("{table}{i}."),
                };
            }
        }
    }

    // R2.
    let mut outcomes = Vec::with_capacity(desired.len());
    for d in desired {
        match plan_one(d, tree, read, ip_wait_over.contains(&d.network_id)) {
            Next::Step(step) => return step,
            Next::Outcome(outcome) => outcomes.push(outcome),
        }
    }
    Step::Done { outcomes }
}

/// R2 for one network. `wait_over` = network in `ip_wait_over`.
fn plan_one(d: &DesiredTunnel, tree: &Tree, read: &BTreeSet<String>, wait_over: bool) -> Next {
    let n = d.network_id;
    let alias = alias_of(n);
    let add = |table: String| {
        let then_read = if table == TUNNEL_TABLE {
            vec![IP_TABLE.to_owned()]
        } else {
            Vec::new()
        };
        Next::Step(Step::Add {
            table,
            alias: alias.clone(),
            network_id: n,
            then_read,
        })
    };

    // 1.
    let Some(hub_key) = &d.hub_public_key else {
        return Next::Outcome(Outcome::Blocked {
            network_id: n,
            reason: "the hub has not reported its public key yet".to_owned(),
        });
    };
    // 2.
    let Some(p) = by_alias(tree, PEER_TABLE, &alias) else {
        return add(PEER_TABLE.to_owned());
    };
    // 3.
    let Some(t) = by_alias(tree, TUNNEL_TABLE, &alias) else {
        return add(TUNNEL_TABLE.to_owned());
    };
    let tunnel = format!("{TUNNEL_TABLE}{t}.");
    // 4.
    let tif_table = format!("{tunnel}Interface.");
    let Some(k) = by_alias_or_first(tree, &tif_table, &alias) else {
        return add(tif_table);
    };
    let tif = format!("{tif_table}{k}");
    // 5.
    if d.rotate_key {
        return Next::Step(match d.key_mode {
            KeyMode::Server => Step::SetPrivateKey {
                tunnel,
                network_id: n,
            },
            KeyMode::Device => Step::RegenerateKey {
                tunnel,
                network_id: n,
            },
        });
    }
    // 6.
    let pk = value(tree, &format!("{tunnel}PublicKey")).unwrap_or("");
    if d.key_mode == KeyMode::Server {
        let refresh = match &d.member_public_key {
            None => true,
            Some(member) => !pk.is_empty() && pk != member,
        };
        if refresh {
            return Next::Step(Step::SetPrivateKey {
                tunnel,
                network_id: n,
            });
        }
    }
    // 7.
    let by_lower = instances(tree, IP_TABLE).into_iter().find(|x| {
        value(tree, &format!("{IP_TABLE}{x}.LowerLayers"))
            .is_some_and(|ll| parse_references(ll).contains(tif.as_str()))
    });
    let by_name = || {
        let name = value(tree, &format!("{tif}.Name")).filter(|n| !n.is_empty())?;
        instances(tree, IP_TABLE)
            .into_iter()
            .find(|x| value(tree, &format!("{IP_TABLE}{x}.Name")) == Some(name))
    };
    let (x, x_by_alias) = match by_lower.or_else(by_name) {
        Some(x) => (x, false),
        None => match by_alias(tree, IP_TABLE, &alias) {
            Some(x) => (x, true),
            None if !wait_over => {
                return Next::Step(Step::WaitForFirmware {
                    table: IP_TABLE.to_owned(),
                    network_id: n,
                });
            }
            None => return add(IP_TABLE.to_owned()),
        },
    };
    let ip = format!("{IP_TABLE}{x}.");
    // 8.
    let v4_table = format!("{ip}IPv4Address.");
    let Some(a) = by_alias_or_first(tree, &v4_table, &alias) else {
        return add(v4_table);
    };
    let v4 = format!("{v4_table}{a}.");
    // 9.
    let peer = format!("{PEER_TABLE}{p}.");
    let mut wanted: Vec<(String, String, Compare)> = vec![
        (format!("{peer}PublicKey"), hub_key.clone(), Compare::Exact),
        (
            format!("{peer}EndpointAddress"),
            d.endpoint_host.clone(),
            Compare::Host,
        ),
        (
            format!("{peer}EndpointPort"),
            d.endpoint_port.to_string(),
            Compare::UnsignedInt,
        ),
        (
            format!("{peer}PersistentKeepalive"),
            d.persistent_keepalive.to_string(),
            Compare::UnsignedInt,
        ),
        (
            format!("{peer}AllowedIPs"),
            allowed_ips_text(&d.allowed_ips),
            Compare::Prefixes,
        ),
        (
            format!("{tunnel}ListenPort"),
            "0".to_owned(),
            Compare::UnsignedInt,
        ),
        (
            format!("{tunnel}PeerReferences"),
            format!("{PEER_TABLE}{p}"),
            Compare::References,
        ),
    ];
    if x_by_alias {
        wanted.push((format!("{ip}LowerLayers"), tif.clone(), Compare::References));
    }
    wanted.extend([
        (
            format!("{ip}MaxMTUSize"),
            d.mtu.to_string(),
            Compare::UnsignedInt,
        ),
        (
            format!("{v4}IPAddress"),
            d.address.to_string(),
            Compare::Exact,
        ),
        (
            format!("{v4}SubnetMask"),
            subnet_mask(d.prefix).to_string(),
            Compare::Exact,
        ),
    ]);
    let psk_path = format!("{peer}PresharedKey");
    if d.send_preshared_key {
        let psk = d.preshared_key.as_deref().map_or("", String::as_str);
        if tree.contains_key(&psk_path) {
            wanted.push((psk_path, psk.to_owned(), Compare::Secured));
        } else if !psk.is_empty() {
            return Next::Outcome(Outcome::Blocked {
                network_id: n,
                reason: format!("the device has no {psk_path}"),
            });
        }
    }
    for enable in [
        format!("{peer}Enable"),
        format!("{tif}.Enable"),
        format!("{tunnel}Enable"),
        format!("{v4}Enable"),
        format!("{ip}Enable"),
    ] {
        wanted.push((enable, "true".to_owned(), Compare::Boolean));
    }
    let mut values = Vec::new();
    for (path, want, cmp) in wanted {
        let have = tree.get(&path);
        if have.is_some_and(|h| same(cmp, &want, &h.value)) {
            continue;
        }
        if have.is_some_and(|h| h.writable == Some(false)) {
            return Next::Outcome(Outcome::Blocked {
                network_id: n,
                reason: format!("{path} is not writable on this device"),
            });
        }
        let xsd_type = match cmp {
            Compare::Secured => cmp.xsd_type().to_owned(),
            _ => have
                .and_then(|h| h.xsd_type.clone())
                .unwrap_or_else(|| cmp.xsd_type().to_owned()),
        };
        let secret = cmp == Compare::Secured && !want.is_empty();
        values.push(SetParam {
            path,
            value: want,
            xsd_type,
            secret,
        });
    }
    if !values.is_empty() {
        return Next::Step(Step::Set {
            values,
            network_id: n,
        });
    }
    // 10.
    if d.key_mode == KeyMode::Device && pk.is_empty() {
        if !read.contains(&tunnel) {
            return Next::Step(Step::Read {
                paths: vec![tunnel],
            });
        }
        return Next::Outcome(Outcome::Blocked {
            network_id: n,
            reason: "the device did not make a key".to_owned(),
        });
    }
    // 11.
    let device_public_key = (d.key_mode == KeyMode::Device
        && d.member_public_key.as_deref() != Some(pk))
    .then(|| pk.to_owned());
    Next::Outcome(Outcome::Applied {
        network_id: n,
        desired_hash: desired_hash(d),
        device_public_key,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn aliases_round_trip_and_are_strict() {
        let id = Uuid::parse_str("0123abcd-4567-89ef-0123-456789abcdef").unwrap();
        let alias = alias_of(id);
        assert_eq!(alias, "dhonomos-wg-0123abcd456789ef0123456789abcdef");
        assert_eq!(network_of_alias(&alias), Some(id));
        for bad in [
            "",
            "dhonomos-wg-",
            "dhonomos-wg-0123ABCD456789ef0123456789abcdef",
            "dhonomos-wg-0123abcd-4567-89ef-0123-456789abcdef",
            "dhonomos-wg-0123abcd456789ef0123456789abcde",
            "dhonomos-wg-0123abcd456789ef0123456789abcdef0",
            "dhonomos-wg-0123abcd456789ef0123456789abcdeg",
            "Dhonomos-wg-0123abcd456789ef0123456789abcdef",
            " dhonomos-wg-0123abcd456789ef0123456789abcdef",
            "cpe-lan",
        ] {
            assert_eq!(network_of_alias(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn booleans_compare_loosely() {
        for have in ["true", "TRUE", "1", " True "] {
            assert!(same(Compare::Boolean, "true", have), "{have}");
        }
        for have in ["false", "0", "", "yes", "2"] {
            assert!(!same(Compare::Boolean, "true", have), "{have}");
        }
        assert!(same(Compare::Boolean, "false", "False"));
    }

    #[test]
    fn numbers_compare_numerically() {
        assert!(same(Compare::UnsignedInt, "25", "25"));
        assert!(same(Compare::UnsignedInt, "25", "025"));
        assert!(!same(Compare::UnsignedInt, "25", "26"));
        assert!(!same(Compare::UnsignedInt, "25", ""));
        assert!(!same(Compare::UnsignedInt, "25", "-25"));
    }

    #[test]
    fn prefix_lists_compare_as_sets() {
        let want = "10.77.0.0/24,192.168.2.0/24";
        assert!(same(Compare::Prefixes, want, want));
        assert!(same(
            Compare::Prefixes,
            want,
            "192.168.2.0/24, 10.77.0.0/24"
        ));
        assert!(same(
            Compare::Prefixes,
            "10.77.0.0/24,10.0.0.5/32",
            "10.0.0.5,10.77.0.0/24"
        ));
        assert!(same(Compare::Prefixes, "", ""));
        assert!(!same(Compare::Prefixes, want, "10.77.0.0/24"));
        assert!(!same(Compare::Prefixes, want, ""));
        // Host bits set, garbage, empty entry -> unparsable -> differs.
        assert!(!same(
            Compare::Prefixes,
            want,
            "10.77.0.1/24,192.168.2.0/24"
        ));
        assert!(!same(
            Compare::Prefixes,
            want,
            "10.77.0.0/24,192.168.2.0/24,x"
        ));
        assert!(!same(
            Compare::Prefixes,
            want,
            "10.77.0.0/24,,192.168.2.0/24"
        ));
    }

    #[test]
    fn references_ignore_one_trailing_dot_and_order() {
        let want = "Device.WireGuard.Peer.1";
        assert!(same(Compare::References, want, "Device.WireGuard.Peer.1."));
        assert!(same(Compare::References, want, " Device.WireGuard.Peer.1 "));
        assert!(!same(
            Compare::References,
            want,
            "Device.WireGuard.Peer.1.."
        ));
        assert!(!same(Compare::References, want, "Device.WireGuard.Peer.10"));
        assert!(!same(
            Compare::References,
            want,
            "Device.WireGuard.Peer.1,Device.WireGuard.Peer.2"
        ));
        assert!(same(
            Compare::References,
            "Device.WireGuard.Peer.2,Device.WireGuard.Peer.1",
            "Device.WireGuard.Peer.1.,Device.WireGuard.Peer.2."
        ));
        assert!(!same(Compare::References, want, ""));
    }

    #[test]
    fn hosts_ignore_ascii_case_and_the_rest_is_exact() {
        assert!(same(Compare::Host, "hub.example.net", "HUB.Example.NET"));
        assert!(!same(Compare::Host, "hub.example.net", "hub.example.net."));
        assert!(same(Compare::Exact, "Key=", "Key="));
        assert!(!same(Compare::Exact, "Key=", "key="));
        assert!(!same(Compare::Exact, "10.77.0.2", " 10.77.0.2"));
    }

    #[test]
    fn subnet_masks() {
        for (prefix, mask) in [
            ("10.77.0.0/24", "255.255.255.0"),
            ("10.0.0.0/16", "255.255.0.0"),
            ("10.77.0.8/29", "255.255.255.248"),
            ("0.0.0.0/0", "0.0.0.0"),
            ("10.0.0.1/32", "255.255.255.255"),
        ] {
            assert_eq!(subnet_mask(prefix.parse().unwrap()).to_string(), mask);
        }
    }

    #[test]
    fn instances_are_numeric_and_distinct() {
        let mut tree = Tree::new();
        for key in [
            "Device.IP.Interface.10.Enable",
            "Device.IP.Interface.2.Enable",
            "Device.IP.Interface.2.IPv4Address.1.Enable",
            "Device.IP.InterfaceNumberOfEntries",
            "Device.IP.Interface.x.Enable",
        ] {
            tree.insert(
                key.to_owned(),
                Param {
                    value: String::new(),
                    writable: None,
                    xsd_type: None,
                },
            );
        }
        assert_eq!(instances(&tree, "Device.IP.Interface."), vec![2, 10]);
        assert_eq!(
            instances(&tree, "Device.IP.Interface.2.IPv4Address."),
            vec![1]
        );
        assert!(instances(&tree, "Device.WireGuard.Peer.").is_empty());
    }

    fn sample() -> DesiredTunnel {
        DesiredTunnel {
            network_id: Uuid::parse_str("0123abcd-4567-89ef-0123-456789abcdef").unwrap(),
            hub_public_key: Some("HUBhubHUBhubHUBhubHUBhubHUBhubHUBhubHUBhub0=".to_owned()),
            endpoint_host: "hub.example.net".to_owned(),
            endpoint_port: 51820,
            persistent_keepalive: 25,
            allowed_ips: vec![
                "192.168.2.0/24".parse().unwrap(),
                "10.77.0.0/24".parse().unwrap(),
            ],
            address: Ipv4Addr::new(10, 77, 0, 2),
            prefix: "10.77.0.0/24".parse().unwrap(),
            mtu: 1420,
            key_mode: KeyMode::Device,
            member_public_key: None,
            rotate_key: false,
            preshared_key: None,
            send_preshared_key: false,
        }
    }

    /// Invented pre-shared key: 32 bytes of 0x50.
    const PSK: &str = "UFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFA=";

    fn p(value: &str) -> Param {
        Param {
            value: value.to_owned(),
            writable: Some(true),
            xsd_type: None,
        }
    }

    /// Peer 1 + Tunnel 1 of the sample network (tunnel interface Name `tif_name`), LAN row
    /// (Name "br-lan") as IP.Interface.1, `ip` (instance, Alias, Name, LowerLayers) as more
    /// IP.Interface rows, each with IPv4Address.1.
    fn tree_with(tif_name: &str, ip: &[(u32, &str, &str, &str)]) -> Tree {
        let alias = alias_of(sample().network_id);
        let mut tree = Tree::new();
        tree.insert("Device.WireGuard.Peer.1.Alias".to_owned(), p(&alias));
        tree.insert("Device.WireGuard.Tunnel.1.Alias".to_owned(), p(&alias));
        tree.insert(
            "Device.WireGuard.Tunnel.1.Interface.1.Name".to_owned(),
            p(tif_name),
        );
        let lan = (1, "cpe-lan", "br-lan", "Device.Ethernet.Link.1");
        for &(x, a, name, lower) in std::iter::once(&lan).chain(ip) {
            let row = format!("Device.IP.Interface.{x}.");
            tree.insert(format!("{row}Alias"), p(a));
            tree.insert(format!("{row}Name"), p(name));
            tree.insert(format!("{row}LowerLayers"), p(lower));
            tree.insert(format!("{row}IPv4Address.1.Alias"), p(""));
        }
        tree
    }

    /// Step for the sample on `tree`, everything read.
    fn step_on(tree: &Tree, wait_over: bool) -> Step {
        let read = BTreeSet::from([WG_ROOT.to_owned(), IP_TABLE.to_owned()]);
        let over: BTreeSet<Uuid> = if wait_over {
            BTreeSet::from([sample().network_id])
        } else {
            BTreeSet::new()
        };
        plan(&PlanInput {
            desired: &[sample()],
            tree,
            read: &read,
            ip_wait_over: &over,
            kept: &BTreeSet::new(),
        })
    }

    /// IP interface the Set of `step` configures + whether it sets its LowerLayers.
    fn ip_of(step: &Step) -> (u32, bool) {
        let Step::Set { values, .. } = step else {
            panic!("{step:?}");
        };
        let mtu = values
            .iter()
            .find_map(|v| {
                v.path
                    .strip_prefix(IP_TABLE)?
                    .strip_suffix(".MaxMTUSize")?
                    .parse()
                    .ok()
            })
            .unwrap();
        let lower = values.iter().any(|v| v.path.ends_with("LowerLayers"));
        (mtu, lower)
    }

    #[test]
    fn the_ip_interface_by_lower_layers_then_name_then_alias() {
        let alias = alias_of(sample().network_id);
        let tif = "Device.WireGuard.Tunnel.1.Interface.1";
        let by_lower = (4, "cpe-4", "other", tif);
        let by_name = (3, "cpe-3", "wg1", "");
        let by_name_too = (5, "cpe-5", "wg1", "");
        let by_alias = (2, alias.as_str(), "", "");
        let tree = tree_with("wg1", &[by_alias, by_name, by_lower, by_name_too]);
        assert_eq!(ip_of(&step_on(&tree, false)), (4, false));
        // Trailing dot (older LS500X images write it).
        let tree = tree_with(
            "wg1",
            &[
                by_alias,
                by_name,
                (
                    4,
                    "cpe-4",
                    "other",
                    "Device.WireGuard.Tunnel.1.Interface.1.",
                ),
            ],
        );
        assert_eq!(ip_of(&step_on(&tree, false)), (4, false));
        // Lowest-numbered row with the name.
        let tree = tree_with("wg1", &[by_alias, by_name_too, by_name]);
        assert_eq!(ip_of(&step_on(&tree, false)), (3, false));
        let tree = tree_with("wg1", &[by_alias]);
        assert_eq!(ip_of(&step_on(&tree, true)), (2, true));
        assert_eq!(ip_of(&step_on(&tree, false)), (2, true));
    }

    #[test]
    fn names_match_only_when_equal_and_not_empty() {
        let wait = Step::WaitForFirmware {
            table: IP_TABLE.to_owned(),
            network_id: sample().network_id,
        };
        // Client-added row (Name "") + tunnel interface without Name + LAN row
        // -> none picked.
        let tree = tree_with("", &[(2, "cpe-2", "", "")]);
        assert_eq!(step_on(&tree, false), wait);
        let tree = tree_with("wg1", &[(2, "cpe-2", "", ""), (3, "cpe-3", "WG1", "")]);
        assert_eq!(step_on(&tree, false), wait);
        let tree = tree_with("br-lan", &[]);
        assert_eq!(ip_of(&step_on(&tree, false)), (1, false));
    }

    #[test]
    fn no_ip_interface_waits_for_the_firmware_until_told_not_to() {
        let tree = tree_with("wg1", &[(2, "cpe-2", "", "")]);
        assert_eq!(
            step_on(&tree, false),
            Step::WaitForFirmware {
                table: IP_TABLE.to_owned(),
                network_id: sample().network_id,
            }
        );
        assert_eq!(
            step_on(&tree, true),
            Step::Add {
                table: IP_TABLE.to_owned(),
                alias: alias_of(sample().network_id),
                network_id: sample().network_id,
                then_read: Vec::new(),
            }
        );
    }

    #[test]
    fn desired_hash_is_stable() {
        // Rendering of the sample (see `desired_hash`), checked with `sha256sum`:
        // "dhonomos-wg-desired-v2\nnetwork_id=0123abcd-4567-89ef-0123-456789abcdef\n
        // hub_public_key=44:HUBhub...hub0=\nendpoint_host=15:hub.example.net\n
        // endpoint_port=51820\npersistent_keepalive=25\n
        // allowed_ips=10.77.0.0/24,192.168.2.0/24\naddress=10.77.0.2\nprefix=10.77.0.0/24\n
        // mtu=1420\nkey_mode=device\npreshared_key=none\n".
        // v1 (same without last line, "v1") -> ad4518f3462c130264d241b08715c8ec.
        assert_eq!(desired_hash(&sample()), "87ad509dc4f1d9f1cc4c4bf48ba15a30");
        // With PSK: last line "preshared_key=b37361a0be8af8905de1f4384e701365"
        // = first 16 bytes of SHA-256 of the 32 bytes of 0x50.
        let mut d = sample();
        d.preshared_key = Some(Zeroizing::new(PSK.to_owned()));
        assert_eq!(desired_hash(&d), "93cf306d550891698541e65828316921");
    }

    #[test]
    fn desired_hash_ignores_the_member_key_and_prefix_order() {
        let base = desired_hash(&sample());
        let mut d = sample();
        d.member_public_key = Some("anything".to_owned());
        d.rotate_key = true;
        d.send_preshared_key = true;
        d.allowed_ips.reverse();
        d.allowed_ips.push("10.77.0.0/24".parse().unwrap());
        assert_eq!(desired_hash(&d), base);
        assert_eq!(base.len(), 32);
        assert!(
            base.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn desired_hash_sees_every_other_field() {
        let base = desired_hash(&sample());
        let changes: Vec<fn(&mut DesiredTunnel)> = vec![
            |d| d.network_id = Uuid::nil(),
            |d| d.hub_public_key = None,
            |d| d.hub_public_key = Some(String::new()),
            |d| d.endpoint_host = "hub2.example.net".to_owned(),
            |d| d.endpoint_port = 51821,
            |d| d.persistent_keepalive = 0,
            |d| d.allowed_ips.pop().map(drop).unwrap_or(()),
            |d| d.address = Ipv4Addr::new(10, 77, 0, 3),
            |d| d.prefix = "10.77.0.0/23".parse().unwrap(),
            |d| d.mtu = 1400,
            |d| d.key_mode = KeyMode::Server,
            |d| d.preshared_key = Some(Zeroizing::new(PSK.to_owned())),
            |d| {
                d.preshared_key = Some(Zeroizing::new(
                    "UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=".to_owned(),
                ));
            },
        ];
        let mut seen = BTreeSet::from([base]);
        for change in changes {
            let mut d = sample();
            change(&mut d);
            assert!(seen.insert(desired_hash(&d)), "{d:?}");
        }
    }

    /// Snapshot with everything of the sample in place + as desired;
    /// `Peer.1.PresharedKey` (reads "") when `psk_param`.
    fn converged(psk_param: bool) -> Tree {
        let mut tree = tree_with("wg1", &[(2, "cpe-2", "wg1", "")]);
        let d = sample();
        for (path, value) in [
            (
                "Device.WireGuard.Peer.1.PublicKey",
                d.hub_public_key.clone().unwrap(),
            ),
            (
                "Device.WireGuard.Peer.1.EndpointAddress",
                d.endpoint_host.clone(),
            ),
            ("Device.WireGuard.Peer.1.EndpointPort", "51820".to_owned()),
            (
                "Device.WireGuard.Peer.1.PersistentKeepalive",
                "25".to_owned(),
            ),
            (
                "Device.WireGuard.Peer.1.AllowedIPs",
                "10.77.0.0/24,192.168.2.0/24".to_owned(),
            ),
            ("Device.WireGuard.Peer.1.Enable", "true".to_owned()),
            ("Device.WireGuard.Tunnel.1.ListenPort", "0".to_owned()),
            (
                "Device.WireGuard.Tunnel.1.PeerReferences",
                "Device.WireGuard.Peer.1".to_owned(),
            ),
            ("Device.WireGuard.Tunnel.1.PublicKey", "DEVdev".to_owned()),
            ("Device.WireGuard.Tunnel.1.Enable", "true".to_owned()),
            (
                "Device.WireGuard.Tunnel.1.Interface.1.Enable",
                "true".to_owned(),
            ),
            ("Device.IP.Interface.2.MaxMTUSize", "1420".to_owned()),
            ("Device.IP.Interface.2.Enable", "true".to_owned()),
            (
                "Device.IP.Interface.2.IPv4Address.1.IPAddress",
                "10.77.0.2".to_owned(),
            ),
            (
                "Device.IP.Interface.2.IPv4Address.1.SubnetMask",
                "255.255.255.0".to_owned(),
            ),
            (
                "Device.IP.Interface.2.IPv4Address.1.Enable",
                "true".to_owned(),
            ),
        ] {
            tree.insert(path.to_owned(), p(&value));
        }
        if psk_param {
            tree.insert(
                "Device.WireGuard.Peer.1.PresharedKey".to_owned(),
                Param {
                    value: String::new(),
                    writable: Some(true),
                    xsd_type: Some("hexBinary".to_owned()),
                },
            );
        }
        tree
    }

    /// Step for `d` on `tree`, everything read.
    fn step_for(d: &DesiredTunnel, tree: &Tree) -> Step {
        let read = BTreeSet::from([WG_ROOT.to_owned(), IP_TABLE.to_owned()]);
        plan(&PlanInput {
            desired: std::slice::from_ref(d),
            tree,
            read: &read,
            ip_wait_over: &BTreeSet::new(),
            kept: &BTreeSet::new(),
        })
    }

    #[test]
    fn the_preshared_key_is_sent_only_when_asked() {
        let tree = converged(true);
        let mut d = sample();
        d.member_public_key = Some("DEVdev".to_owned());
        d.preshared_key = Some(Zeroizing::new(PSK.to_owned()));
        // Not asked -> nothing to do, whatever the key.
        assert!(
            matches!(step_for(&d, &tree), Step::Done { ref outcomes } if matches!(outcomes[..], [Outcome::Applied { .. }])),
            "{:?}",
            step_for(&d, &tree)
        );
        // Asked -> key alone, secret, type string, before the Enables.
        d.send_preshared_key = true;
        let step = step_for(&d, &tree);
        assert_eq!(
            step,
            Step::Set {
                values: vec![SetParam {
                    path: "Device.WireGuard.Peer.1.PresharedKey".to_owned(),
                    value: PSK.to_owned(),
                    xsd_type: "string".to_owned(),
                    secret: true,
                }],
                network_id: sample().network_id,
            }
        );
        let shown = format!("{step:?} {d:?}");
        assert!(!shown.contains(PSK), "{shown}");
        assert!(shown.contains("value: \"********\""), "{shown}");
        // Other values differ too -> key still before the Enables.
        let mut off = tree.clone();
        off.insert("Device.WireGuard.Peer.1.Enable".to_owned(), p("false"));
        off.insert("Device.WireGuard.Peer.1.EndpointPort".to_owned(), p("1"));
        let Step::Set { values, .. } = step_for(&d, &off) else {
            panic!();
        };
        let paths: Vec<&str> = values.iter().map(|v| v.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "Device.WireGuard.Peer.1.EndpointPort",
                "Device.WireGuard.Peer.1.PresharedKey",
                "Device.WireGuard.Peer.1.Enable",
            ]
        );
        assert_eq!(
            values.iter().map(|v| v.secret).collect::<Vec<_>>(),
            [false, true, false]
        );
        // No key wanted -> "" clears it, not a secret.
        d.preshared_key = None;
        let Step::Set { values, .. } = step_for(&d, &tree) else {
            panic!();
        };
        assert_eq!(
            values,
            [SetParam {
                path: "Device.WireGuard.Peer.1.PresharedKey".to_owned(),
                value: String::new(),
                xsd_type: "string".to_owned(),
                secret: false,
            }]
        );
    }

    #[test]
    fn a_device_without_the_preshared_key_parameter() {
        let tree = converged(false);
        let mut d = sample();
        d.member_public_key = Some("DEVdev".to_owned());
        d.send_preshared_key = true;
        // No key wanted -> nothing to clear.
        assert!(matches!(
            step_for(&d, &tree),
            Step::Done { ref outcomes } if matches!(outcomes[..], [Outcome::Applied { .. }])
        ));
        // Key wanted -> blocked.
        d.preshared_key = Some(Zeroizing::new(PSK.to_owned()));
        assert_eq!(
            step_for(&d, &tree),
            Step::Done {
                outcomes: vec![Outcome::Blocked {
                    network_id: sample().network_id,
                    reason: "the device has no Device.WireGuard.Peer.1.PresharedKey".to_owned(),
                }],
            }
        );
        // Not sent in this run -> planner does not look.
        d.send_preshared_key = false;
        assert!(matches!(
            step_for(&d, &tree),
            Step::Done { ref outcomes } if matches!(outcomes[..], [Outcome::Applied { .. }])
        ));
        // Read-only one -> blocks like any other value.
        let mut ro = converged(true);
        ro.get_mut("Device.WireGuard.Peer.1.PresharedKey")
            .unwrap()
            .writable = Some(false);
        d.send_preshared_key = true;
        assert_eq!(
            step_for(&d, &ro),
            Step::Done {
                outcomes: vec![Outcome::Blocked {
                    network_id: sample().network_id,
                    reason: "Device.WireGuard.Peer.1.PresharedKey is not writable on this device"
                        .to_owned(),
                }],
            }
        );
    }
}
