//! WireGuard planning (ADR-110, docs/design/13-wireguard.md): overlay network math, no I/O.
//!
//! - [`prefix`]: IPv4 prefixes, tunnel prefix from address pool, member addresses,
//!   checks of LAN prefixes behind a device (site prefixes).
//! - [`keys`]: Curve25519 key pairs + pre-shared keys, WireGuard base64 form.
//! - [`hub`]: messages between server and hub process (`dhonomos-wg-hub`): desired state,
//!   hub public key, peer status, hub interface names.
//! - [`health`]: member tunnel states (connected, idle, stale, never, unknown) +
//!   thresholds, shared by server and web UI.
//! - [`client_config`]: wg-quick config file of a client member + its file name.
//! - [`device`]: converging planner for CPE TR-181 `Device.WireGuard.` + IP interface
//!   above it, one step at a time.
//! - [`fake`]: CPE double for tests; no production use.
//!
//! DB keeps state + takes locks; this crate only decides what fits.

pub mod client_config;
pub mod device;
pub mod fake;
pub mod health;
pub mod hub;
pub mod keys;
pub mod prefix;

pub use client_config::{ClientConfig, config_file_name, render_client_config};
pub use device::{
    ALIAS_PREFIX, DesiredTunnel, KeyMode, Outcome, Param, PlanInput, SetParam, Step, Tree,
    alias_of, desired_hash, network_of_alias, plan,
};
pub use health::{CONNECTED_SECS, HUB_SILENT_SECS, STALE_SECS, TunnelState};
pub use hub::{
    HUB_TOKEN_PREFIX, HubNetwork, HubPeer, HubState, MAX_STATUS_PEERS, MAX_WAIT_SECS, PeerStatus,
    PublicKeyReport, StatusAccepted, StatusReport, interface_name, parse_interface_name,
};
pub use keys::{
    KEY_LEN, KeyError, KeyPair, generate_keypair, generate_preshared_key, key_from_text, key_text,
    public_from_private, validate_key,
};
pub use prefix::{
    DEFAULT_LISTEN_PORT, DEFAULT_NETWORK_LEN, Ipv4Prefix, MAX_SITE_PREFIXES, NETWORK_MAX_LEN,
    NETWORK_MIN_LEN, NetworkPrefixError, POOL_MAX_LEN, POOL_MIN_LEN, ParsePrefixError,
    SITE_MIN_LEN, SitePrefixError, UsedAddress, addresses_in_use, allocate_member_address,
    allocate_network_prefix, check_network_prefix, check_pool, check_site_prefixes, hub_address,
    lowest_free_port,
};
