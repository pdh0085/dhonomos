//! WireGuard hubs, networks, members + site prefixes (ADR-110, docs/design/13-wireguard.md).
//!
//! Stage 1 = data only; no talk to a hub or a device.
//! Math (free prefix or address, site prefix collisions) -> `dhonomos_wireguard`.
//! This module -> locks that keep those answers true + row writes:
//!
//! - tenant's networks: created under row lock on the tenant -> prefixes do not overlap;
//!   lock mode does not block FK checks of other writers
//! - addresses + site prefixes of a network: changed under row lock on the network
//! - unique indexes = last defence -> mapped to the same refusals
//!
//! No private key stored. Public keys only (ADR-110 Q7).

use std::collections::HashMap;
use std::net::Ipv4Addr;

use dhonomos_wireguard::{
    CONNECTED_SECS, HUB_SILENT_SECS, Ipv4Prefix, NetworkPrefixError, STALE_SECS, SitePrefixError,
    TunnelState, UsedAddress, addresses_in_use, alias_of, allocate_member_address,
    allocate_network_prefix, check_network_prefix, check_site_prefixes, lowest_free_port,
};
use sqlx::PgConnection;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::scope::scope_param;
use crate::{DeviceScope, Result, Store, StoreError};

/// Hub = WireGuard endpoint managed by Dhonomos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgHub {
    pub id: Uuid,
    /// Unique per tenant.
    pub name: String,
    /// Host name or address members dial.
    pub endpoint_host: String,
    /// Set after the hub process made its key pair (stage 2).
    pub public_key: Option<String>,
    /// Network count on this hub.
    pub networks: i64,
    /// First chars of the hub token, if issued. Never the token.
    pub token_prefix: Option<String>,
    pub token_created_at: Option<OffsetDateTime>,
    /// Last call of the hub process to the server.
    pub last_seen_at: Option<OffsetDateTime>,
    pub last_seen_ip: Option<String>,
    /// Hub process version, from its `User-Agent`.
    pub hub_version: Option<String>,
    /// Grows on each change of a network, member or site prefix of the hub.
    pub state_revision: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Overlay network + its hub + counts of members visible to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgNetwork {
    pub id: Uuid,
    pub hub_id: Uuid,
    pub hub_name: String,
    pub hub_endpoint_host: String,
    /// `None` until the hub has a key.
    pub hub_public_key: Option<String>,
    /// Unique per tenant.
    pub name: String,
    /// Tunnel prefix. Hub address = first host.
    pub ipv4_prefix: Ipv4Prefix,
    /// Hub UDP port for this network.
    pub listen_port: i32,
    pub mtu: i32,
    /// Keepalive seconds for members (0 = none).
    pub persistent_keepalive: i32,
    /// Not revoked, visible to the caller.
    pub device_members: i64,
    /// Not revoked, visible to the caller.
    pub client_members: i64,
    /// Visible to the caller.
    pub revoked_members: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// LAN prefix behind a device member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgSitePrefix {
    pub prefix: Ipv4Prefix,
    /// Free text for operators.
    pub description: String,
}

/// Member of a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgMember {
    pub id: Uuid,
    pub network_id: Uuid,
    /// `device` or `client`.
    pub kind: String,
    /// The CPE (device members only).
    pub device_id: Option<Uuid>,
    /// Client owner. `None` -> server client made by an admin, or owner gone.
    pub user_id: Option<Uuid>,
    pub name: String,
    /// `None` -> device member, key not known yet.
    pub public_key: Option<String>,
    /// Device members: `device` (CPE makes the key) or `server` (Dhonomos makes + sends it,
    /// keeps nothing).
    pub key_mode: Option<String>,
    pub preshared_key_enabled: bool,
    /// Tunnel address.
    pub address: Ipv4Addr,
    /// LAN prefixes behind it (device members), by prefix.
    pub site_prefixes: Vec<WgSitePrefix>,
    /// Last hub report about it, if any.
    pub hub_status: Option<WgPeerStatus>,
    /// Device members: result of the last run on the CPE (`pending`, `applied`, `blocked`,
    /// `unsupported`, `error`). `None` for clients.
    pub device_state: Option<String>,
    /// Reason for `blocked` + `error`.
    pub device_detail: Option<String>,
    /// Last time a run on the CPE recorded a state.
    pub device_checked_at: Option<OffsetDateTime>,
    /// Desired state (`dhonomos_wireguard::desired_hash`) of the last run on the CPE.
    pub device_applied_hash: Option<String>,
    /// Device members: key rotation asked at. Cleared after a run applied a new key.
    pub rotate_requested_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
    pub revoked_reason: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Live device member of a device or its twin (other record of the same CPE).
/// For the WireGuard view of the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgDeviceMember {
    pub member: WgMember,
    pub network_name: String,
    /// `None` -> member of the device itself; else (twin ID, twin protocol `cwmp` or `usp`).
    pub via_twin: Option<(Uuid, String)>,
    /// Tunnel report of the record that owns the member (device or twin).
    /// `None` -> its snapshot has no Tunnel with the network alias.
    pub device_side: Option<WgDeviceSide>,
}

/// Device report on its tunnel of a network, from stored parameters
/// (`Device.WireGuard.Tunnel` + `Peer` rows with `Alias` = network alias).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgDeviceSide {
    /// `Tunnel.{t}.Status` (`Enabled`, `Disabled`, ...).
    pub tunnel_status: Option<String>,
    /// `Tunnel.{t}.Interface.1.Status` (`Up`, `Down`, ...).
    pub interface_status: Option<String>,
    /// `Peer.{p}.LastHandshakeTime`: seconds since last handshake, at read time; 0 = never.
    pub last_handshake_secs: Option<u64>,
    /// `Tunnel.{t}.Stats.BytesSent`.
    pub bytes_sent: Option<u64>,
    /// `Tunnel.{t}.Stats.BytesReceived`.
    pub bytes_received: Option<u64>,
    /// Newest `updated_at` of the parameters used.
    pub read_at: OffsetDateTime,
}

/// Member count per tunnel state ([`dhonomos_wireguard::TunnelState`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WgStateCounts {
    /// Handshake within the connected threshold.
    pub connected: i64,
    /// Handshake between connected + stale threshold.
    pub idle: i64,
    /// Handshake older than the stale threshold.
    pub stale: i64,
    /// No handshake, or no report about the member.
    pub never: i64,
    /// Hub of the member is silent.
    pub unknown: i64,
}

impl WgStateCounts {
    pub fn total(&self) -> i64 {
        self.connected + self.idle + self.stale + self.never + self.unknown
    }

    fn add(&mut self, state: TunnelState, n: i64) {
        *match state {
            TunnelState::Connected => &mut self.connected,
            TunnelState::Idle => &mut self.idle,
            TunnelState::Stale => &mut self.stale,
            TunnelState::Never => &mut self.never,
            TunnelState::Unknown => &mut self.unknown,
        } += n;
    }
}

/// Tunnel states of one network's live members visible to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgNetworkHealth {
    /// Network ID.
    pub id: Uuid,
    pub name: String,
    pub hub_id: Uuid,
    pub hub_name: String,
    pub device: WgStateCounts,
    pub client: WgStateCounts,
}

/// Tunnel states of a tenant's live members visible to the caller: total + per network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WgHealthSummary {
    /// Device members, all networks.
    pub device: WgStateCounts,
    /// Client members, all networks.
    pub client: WgStateCounts,
    /// Every network of the tenant, by name (zero counts when none visible).
    pub networks: Vec<WgNetworkHealth>,
}

/// Last hub report about a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgPeerStatus {
    /// `ip:port` the hub last saw it at.
    pub endpoint: Option<String>,
    /// `None` = never.
    pub latest_handshake: Option<OffsetDateTime>,
    /// Bytes the hub received from it.
    pub rx_bytes: i64,
    /// Bytes the hub sent to it.
    pub tx_bytes: i64,
    pub reported_at: OffsetDateTime,
}

/// Members a caller sees (design 13 sec. 6, Q6): device members with device in the caller's
/// device scope + own client members (admin: all).
#[derive(Debug, Clone, Copy)]
pub struct WgVisibility<'a> {
    /// Sees every client member (admins).
    pub all_clients: bool,
    /// Sees client members owned by this account.
    pub user_id: Option<Uuid>,
    /// Sees device members with a matching device; `None` = every device.
    pub scope: Option<&'a DeviceScope>,
}

/// Tunnel prefix source of a new network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgPrefixChoice {
    /// Lowest free block of this length in the pool.
    Auto {
        len: u8,
        /// Server address pool.
        pool: Ipv4Prefix,
    },
    Explicit(Ipv4Prefix),
}

/// Network to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewWgNetwork {
    pub hub_id: Uuid,
    /// Unique per tenant.
    pub name: String,
    pub prefix: WgPrefixChoice,
    /// Hub UDP port; `None` -> lowest free from 51820.
    pub listen_port: Option<u16>,
    pub mtu: i32,
    /// Keepalive, seconds.
    pub persistent_keepalive: i32,
}

/// Network changes; `None` fields stay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WgNetworkPatch {
    pub name: Option<String>,
    /// New tunnel prefix. Refused while the network has live members.
    pub ipv4_prefix: Option<Ipv4Prefix>,
    pub listen_port: Option<u16>,
    pub mtu: Option<i32>,
    pub persistent_keepalive: Option<i32>,
}

/// Kind of member to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewWgMemberKind {
    /// CPE. Key not known yet: stage 1 makes or sends no key
    /// (stage 4 sets `public_key` after the device reports it, or after the server sent one).
    Device {
        device_id: Uuid,
        /// `device` or `server`.
        key_mode: String,
    },
    /// Operator PC or server.
    Client {
        /// Owner; `None` = server client.
        user_id: Option<Uuid>,
        public_key: String,
    },
}

/// PSK sealed with the server secrets key: `(ciphertext, nonce)`. Store never sees the key.
pub type WgSealedPsk = (Vec<u8>, Vec<u8>);

/// Member to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewWgMember {
    /// Chosen by the caller: PSK is sealed bound to it before the member exists.
    pub id: Uuid,
    pub name: String,
    pub kind: NewWgMemberKind,
    /// LAN prefixes behind it (devices only).
    pub site_prefixes: Vec<WgSitePrefix>,
    /// PSK sealed for `id`; `None` = no PSK (`preshared_key_enabled` false).
    pub psk: Option<WgSealedPsk>,
}

/// Sealed PSK of a member, as read by rotation of the secrets key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedWgPsk {
    pub member_id: Uuid,
    /// Ciphertext + tag.
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Client member revoked after a change of its owner's account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedClient {
    pub id: Uuid,
    pub network_id: Uuid,
    pub name: String,
    /// `user disabled`, `user deleted`, `role changed` or `scope changed`.
    pub reason: String,
}

/// Refused WireGuard change. API maps each to a status code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WgRefusal {
    #[error("hub not found")]
    HubNotFound,
    #[error("network not found")]
    NetworkNotFound,
    #[error("member not found")]
    MemberNotFound,
    #[error("device not found")]
    DeviceNotFound,
    #[error("a hub named {0:?} exists")]
    HubNameTaken(String),
    #[error("a network named {0:?} exists")]
    NetworkNameTaken(String),
    #[error("port {0} is used by another network on this hub")]
    PortTaken(u16),
    #[error("every port from 51820 up is used on this hub")]
    NoFreePort,
    #[error("the hub still has networks; delete or move them first")]
    HubHasNetworks,
    #[error(
        "the network has members that are not revoked; revoke or delete them before changing its prefix"
    )]
    NetworkHasMembers,
    /// Tunnel prefix refused.
    #[error("{0}")]
    NetworkPrefix(NetworkPrefixError),
    /// Site prefixes refused.
    #[error("{0}")]
    SitePrefix(SitePrefixError),
    /// Every host taken (or still in the reuse delay).
    #[error("no free address is left in {0}")]
    NetworkFull(Ipv4Prefix),
    #[error("the device is a member of this network already")]
    DeviceAlreadyMember,
    /// Twin of the device (other record, CWMP or USP: see [`Store::wg_twin_networks`])
    /// is a member already.
    #[error(
        "the same device is a member of this network already through its other record (CWMP or USP)"
    )]
    DeviceTwinIsMember,
    /// Another live member has this key.
    #[error("another member of this network has this public key")]
    KeyInUse,
    /// Revoked member -> no change.
    #[error("the member is revoked")]
    MemberRevoked,
    /// Client owner is not an account of the tenant.
    #[error("user_id does not name an account")]
    OwnerNotFound,
    /// Client owner may not have clients (ADR-110 Q6).
    #[error(
        "the account cannot own client members: it is disabled, below the operator role or has a device scope"
    )]
    OwnerCannotOwnClients,
    #[error("only client members can be re-keyed here")]
    NotAClient,
    #[error("only device members' keys are rotated here; re-key a client instead")]
    NotADevice,
}

/// Outer = storage error, inner = refusal.
pub type WgResult<T> = Result<std::result::Result<T, WgRefusal>>;

fn decode_error(e: impl std::error::Error + Send + Sync + 'static) -> StoreError {
    StoreError::Database(sqlx::Error::Decode(Box::new(e)))
}

fn prefix_of(s: &str) -> Result<Ipv4Prefix> {
    s.parse().map_err(decode_error)
}

fn address_of(s: &str) -> Result<Ipv4Addr> {
    s.parse().map_err(decode_error)
}

/// Name of the unique constraint or index `e` violated, if a unique violation.
fn violated(e: &sqlx::Error) -> Option<&str> {
    match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => d.constraint(),
        _ => None,
    }
}

struct HubRow {
    id: Uuid,
    name: String,
    endpoint_host: String,
    public_key: Option<String>,
    networks: i64,
    token_prefix: Option<String>,
    token_created_at: Option<OffsetDateTime>,
    last_seen_at: Option<OffsetDateTime>,
    last_seen_ip: Option<String>,
    hub_version: Option<String>,
    state_revision: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl From<HubRow> for WgHub {
    fn from(r: HubRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            endpoint_host: r.endpoint_host,
            public_key: r.public_key,
            networks: r.networks,
            token_prefix: r.token_prefix,
            token_created_at: r.token_created_at,
            last_seen_at: r.last_seen_at,
            last_seen_ip: r.last_seen_ip,
            hub_version: r.hub_version,
            state_revision: r.state_revision,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

struct NetworkRow {
    id: Uuid,
    hub_id: Uuid,
    hub_name: String,
    hub_endpoint_host: String,
    hub_public_key: Option<String>,
    name: String,
    ipv4_prefix: String,
    listen_port: i32,
    mtu: i32,
    persistent_keepalive: i32,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl NetworkRow {
    fn into_network(self, counts: (i64, i64, i64)) -> Result<WgNetwork> {
        Ok(WgNetwork {
            id: self.id,
            hub_id: self.hub_id,
            hub_name: self.hub_name,
            hub_endpoint_host: self.hub_endpoint_host,
            hub_public_key: self.hub_public_key,
            name: self.name,
            ipv4_prefix: prefix_of(&self.ipv4_prefix)?,
            listen_port: self.listen_port,
            mtu: self.mtu,
            persistent_keepalive: self.persistent_keepalive,
            device_members: counts.0,
            client_members: counts.1,
            revoked_members: counts.2,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

struct MemberRow {
    id: Uuid,
    network_id: Uuid,
    kind: String,
    device_id: Option<Uuid>,
    user_id: Option<Uuid>,
    name: String,
    public_key: Option<String>,
    key_mode: Option<String>,
    preshared_key_enabled: bool,
    address: String,
    revoked_at: Option<OffsetDateTime>,
    revoked_reason: Option<String>,
    device_state: Option<String>,
    device_detail: Option<String>,
    device_checked_at: Option<OffsetDateTime>,
    device_applied_hash: Option<String>,
    rotate_requested_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

/// Members of `rows` + their site prefixes + last hub report.
async fn with_prefixes(db: &mut PgConnection, rows: Vec<MemberRow>) -> Result<Vec<WgMember>> {
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let mut by_member: HashMap<Uuid, Vec<WgSitePrefix>> = HashMap::new();
    for p in sqlx::query!(
        r#"
        SELECT member_id, prefix::text AS "prefix!", description
        FROM wg_site_prefixes WHERE member_id = ANY($1) ORDER BY prefix
        "#,
        &ids
    )
    .fetch_all(&mut *db)
    .await?
    {
        by_member
            .entry(p.member_id)
            .or_default()
            .push(WgSitePrefix {
                prefix: prefix_of(&p.prefix)?,
                description: p.description,
            });
    }
    let mut status: HashMap<Uuid, WgPeerStatus> = sqlx::query!(
        r#"
        SELECT member_id, endpoint, latest_handshake, rx_bytes, tx_bytes, reported_at
        FROM wg_peer_status WHERE member_id = ANY($1)
        "#,
        &ids
    )
    .fetch_all(&mut *db)
    .await?
    .into_iter()
    .map(|r| {
        (
            r.member_id,
            WgPeerStatus {
                endpoint: r.endpoint,
                latest_handshake: r.latest_handshake,
                rx_bytes: r.rx_bytes,
                tx_bytes: r.tx_bytes,
                reported_at: r.reported_at,
            },
        )
    })
    .collect();
    rows.into_iter()
        .map(|r| {
            Ok(WgMember {
                site_prefixes: by_member.remove(&r.id).unwrap_or_default(),
                hub_status: status.remove(&r.id),
                id: r.id,
                network_id: r.network_id,
                kind: r.kind,
                device_id: r.device_id,
                user_id: r.user_id,
                name: r.name,
                public_key: r.public_key,
                key_mode: r.key_mode,
                preshared_key_enabled: r.preshared_key_enabled,
                address: address_of(&r.address)?,
                revoked_at: r.revoked_at,
                revoked_reason: r.revoked_reason,
                device_state: r.device_state,
                device_detail: r.device_detail,
                device_checked_at: r.device_checked_at,
                device_applied_hash: r.device_applied_hash,
                rotate_requested_at: r.rotate_requested_at,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
        })
        .collect()
}

/// Stored parameters read by [`device_side_of`] (regex on the path).
const DEVICE_SIDE_PATHS: &str = r"^Device\.WireGuard\.(Tunnel|Peer)\.[0-9]+\.(Alias|Status|Interface\.1\.Status|Stats\.BytesSent|Stats\.BytesReceived|LastHandshakeTime)$";

/// Stored parameter: path, value (`None` = not read yet), stored at.
type StoredValue = (String, Option<String>, OffsetDateTime);

/// Tunnel of `network_id` from device parameters `params`: Tunnel + Peer with `Alias` =
/// network alias (lowest instance if several) + known values below them.
/// `None` -> no Tunnel has the alias.
pub(crate) fn device_side_of(params: &[StoredValue], network_id: Uuid) -> Option<WgDeviceSide> {
    let alias = alias_of(network_id);
    let instance = |table: &str| {
        params
            .iter()
            .filter(|(_, v, _)| v.as_deref() == Some(alias.as_str()))
            .filter_map(|(path, _, _)| {
                let i = path.strip_prefix(table)?.strip_suffix(".Alias")?;
                i.parse::<u32>().ok()
            })
            .min()
            .map(|i| format!("{table}{i}."))
    };
    let tunnel = instance("Device.WireGuard.Tunnel.")?;
    let peer = instance("Device.WireGuard.Peer.");
    let mut read_at: Option<OffsetDateTime> = None;
    let mut value = |path: String| {
        let (_, v, at) = params.iter().find(|(p, _, _)| *p == path)?;
        let v = v.as_deref()?.trim().to_owned();
        read_at = read_at.max(Some(*at));
        Some(v)
    };
    let number = |v: Option<String>| v.and_then(|v| v.parse::<u64>().ok());
    value(format!("{tunnel}Alias"));
    let tunnel_status = value(format!("{tunnel}Status"));
    let interface_status = value(format!("{tunnel}Interface.1.Status"));
    let bytes_sent = number(value(format!("{tunnel}Stats.BytesSent")));
    let bytes_received = number(value(format!("{tunnel}Stats.BytesReceived")));
    let last_handshake_secs = peer.and_then(|peer| {
        value(format!("{peer}Alias"));
        number(value(format!("{peer}LastHandshakeTime")))
    });
    Some(WgDeviceSide {
        tunnel_status,
        interface_status,
        last_handshake_secs,
        bytes_sent,
        bytes_received,
        read_at: read_at?,
    })
}

/// One member by ID in the tenant, with site prefixes.
pub(crate) async fn member_in(
    db: &mut PgConnection,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<WgMember>> {
    let row = sqlx::query_as!(
        MemberRow,
        r#"
        SELECT m.id, m.network_id, m.kind, m.device_id, m.user_id, m.name, m.public_key,
               m.key_mode, m.preshared_key_enabled, host(m.address) AS "address!",
               m.revoked_at, m.revoked_reason, m.device_state, m.device_detail,
               m.device_checked_at, m.device_applied_hash, m.rotate_requested_at,
               m.created_at, m.updated_at
        FROM wg_members m JOIN wg_networks n ON n.id = m.network_id
        WHERE m.id = $1 AND n.tenant_id = $2
        "#,
        id,
        tenant_id
    )
    .fetch_optional(&mut *db)
    .await?;
    match row {
        Some(r) => Ok(with_prefixes(db, vec![r]).await?.pop()),
        None => Ok(None),
    }
}

/// Tunnel prefixes of the tenant's networks, except `except`.
async fn taken_prefixes(
    db: &mut PgConnection,
    tenant_id: Uuid,
    except: Option<Uuid>,
) -> Result<Vec<Ipv4Prefix>> {
    sqlx::query_scalar!(
        r#"
        SELECT ipv4_prefix::text AS "prefix!" FROM wg_networks
        WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id <> $2)
        "#,
        tenant_id,
        except
    )
    .fetch_all(&mut *db)
    .await?
    .iter()
    .map(|p| prefix_of(p))
    .collect()
}

/// Serialises all that decides where a tenant's tunnel prefixes lie.
/// `FOR NO KEY UPDATE` conflicts with itself, not with key-share locks of FKs to the tenant
/// -> other writes of the tenant go on.
async fn lock_tenant(db: &mut PgConnection, tenant_id: Uuid) -> Result<()> {
    sqlx::query!(
        "SELECT id FROM tenants WHERE id = $1 FOR NO KEY UPDATE",
        tenant_id
    )
    .fetch_optional(&mut *db)
    .await?;
    Ok(())
}

/// Lock a tenant's network -> its tunnel prefix; `None` if not the tenant's.
async fn lock_network(
    db: &mut PgConnection,
    tenant_id: Uuid,
    network_id: Uuid,
) -> Result<Option<Ipv4Prefix>> {
    sqlx::query_scalar!(
        r#"
        SELECT ipv4_prefix::text AS "prefix!" FROM wg_networks
        WHERE id = $1 AND tenant_id = $2 FOR NO KEY UPDATE
        "#,
        network_id,
        tenant_id
    )
    .fetch_optional(&mut *db)
    .await?
    .map(|p| prefix_of(&p))
    .transpose()
}

/// Site prefixes of the network's live members, except those of `except`.
async fn others_site_prefixes(
    db: &mut PgConnection,
    network_id: Uuid,
    except: Uuid,
) -> Result<Vec<Ipv4Prefix>> {
    sqlx::query_scalar!(
        r#"
        SELECT sp.prefix::text AS "prefix!"
        FROM wg_site_prefixes sp JOIN wg_members m ON m.id = sp.member_id
        WHERE m.network_id = $1 AND m.revoked_at IS NULL AND m.id <> $2
        "#,
        network_id,
        except
    )
    .fetch_all(&mut *db)
    .await?
    .iter()
    .map(|p| prefix_of(p))
    .collect()
}

/// Revoke the account's live client members, for `reason`.
pub(crate) async fn revoke_clients_of_user(
    db: &mut PgConnection,
    user_id: Uuid,
    reason: &str,
) -> Result<Vec<RevokedClient>> {
    // Revision triggers lock the hub of each changed member. Clients may span hubs +
    // another tx may bump an overlapping set -> lock hubs in id order first, no deadlock.
    sqlx::query!(
        r#"
        SELECT h.id FROM wg_hubs h
        WHERE h.id IN (SELECT n.hub_id FROM wg_members m JOIN wg_networks n ON n.id = m.network_id
                       WHERE m.user_id = $1 AND m.kind = 'client' AND m.revoked_at IS NULL)
        ORDER BY h.id FOR NO KEY UPDATE
        "#,
        user_id
    )
    .fetch_all(&mut *db)
    .await?;
    Ok(sqlx::query!(
        r#"
        UPDATE wg_members SET revoked_at = now(), revoked_reason = $2, updated_at = now()
        WHERE user_id = $1 AND kind = 'client' AND revoked_at IS NULL
        RETURNING id, network_id, name
        "#,
        user_id,
        reason
    )
    .fetch_all(&mut *db)
    .await?
    .into_iter()
    .map(|r| RevokedClient {
        id: r.id,
        network_id: r.network_id,
        name: r.name,
        reason: reason.to_owned(),
    })
    .collect())
}

impl Store {
    /// Tenant's hubs, by name.
    pub async fn list_wg_hubs(&self, tenant_id: Uuid) -> Result<Vec<WgHub>> {
        Ok(sqlx::query_as!(
            HubRow,
            r#"
            SELECT h.id, h.name, h.endpoint_host, h.public_key, h.created_at, h.updated_at,
                   (SELECT count(*) FROM wg_networks n WHERE n.hub_id = h.id) AS "networks!",
                   h.token_prefix, h.token_created_at, h.last_seen_at,
                   host(h.last_seen_ip) AS last_seen_ip, h.hub_version, h.state_revision
            FROM wg_hubs h WHERE h.tenant_id = $1 ORDER BY h.name
            "#,
            tenant_id
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
    }

    pub async fn get_wg_hub(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<WgHub>> {
        Ok(sqlx::query_as!(
            HubRow,
            r#"
            SELECT h.id, h.name, h.endpoint_host, h.public_key, h.created_at, h.updated_at,
                   (SELECT count(*) FROM wg_networks n WHERE n.hub_id = h.id) AS "networks!",
                   h.token_prefix, h.token_created_at, h.last_seen_at,
                   host(h.last_seen_ip) AS last_seen_ip, h.hub_version, h.state_revision
            FROM wg_hubs h WHERE h.tenant_id = $1 AND h.id = $2
            "#,
            tenant_id,
            id
        )
        .fetch_optional(&self.pool)
        .await?
        .map(Into::into))
    }

    pub async fn create_wg_hub(
        &self,
        tenant_id: Uuid,
        name: &str,
        endpoint_host: &str,
    ) -> WgResult<WgHub> {
        let id = Uuid::now_v7();
        let done = sqlx::query!(
            "INSERT INTO wg_hubs (id, tenant_id, name, endpoint_host) VALUES ($1, $2, $3, $4)",
            id,
            tenant_id,
            name,
            endpoint_host
        )
        .execute(&self.pool)
        .await;
        match done {
            Ok(_) => {}
            Err(e) if violated(&e) == Some("wg_hubs_tenant_id_name_key") => {
                return Ok(Err(WgRefusal::HubNameTaken(name.to_owned())));
            }
            Err(e) => return Err(e.into()),
        }
        Ok(self
            .get_wg_hub(tenant_id, id)
            .await?
            .ok_or(WgRefusal::HubNotFound))
    }

    /// Rename a hub or move its endpoint; `None` fields stay.
    pub async fn update_wg_hub(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        name: Option<&str>,
        endpoint_host: Option<&str>,
    ) -> WgResult<WgHub> {
        let done = sqlx::query!(
            r#"
            UPDATE wg_hubs SET name = COALESCE($3, name),
                endpoint_host = COALESCE($4, endpoint_host), updated_at = now()
            WHERE id = $1 AND tenant_id = $2
            "#,
            id,
            tenant_id,
            name,
            endpoint_host
        )
        .execute(&self.pool)
        .await;
        match done {
            Ok(done) if done.rows_affected() == 0 => return Ok(Err(WgRefusal::HubNotFound)),
            Ok(_) => {}
            Err(e) if violated(&e) == Some("wg_hubs_tenant_id_name_key") => {
                return Ok(Err(WgRefusal::HubNameTaken(
                    name.unwrap_or_default().to_owned(),
                )));
            }
            Err(e) => return Err(e.into()),
        }
        Ok(self
            .get_wg_hub(tenant_id, id)
            .await?
            .ok_or(WgRefusal::HubNotFound))
    }

    /// Delete a hub without networks.
    pub async fn delete_wg_hub(&self, tenant_id: Uuid, id: Uuid) -> WgResult<()> {
        let done = sqlx::query!(
            "DELETE FROM wg_hubs WHERE id = $1 AND tenant_id = $2",
            id,
            tenant_id
        )
        .execute(&self.pool)
        .await;
        match done {
            Ok(done) if done.rows_affected() == 0 => Ok(Err(WgRefusal::HubNotFound)),
            Ok(_) => Ok(Ok(())),
            // Network created on it meanwhile.
            Err(sqlx::Error::Database(d)) if d.is_foreign_key_violation() => {
                Ok(Err(WgRefusal::HubHasNetworks))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Tenant's networks by name + counts of members visible to the caller.
    pub async fn list_wg_networks(
        &self,
        tenant_id: Uuid,
        vis: &WgVisibility<'_>,
    ) -> Result<Vec<WgNetwork>> {
        let rows = sqlx::query_as!(
            NetworkRow,
            r#"
            SELECT n.id, n.hub_id, h.name AS hub_name, h.endpoint_host AS hub_endpoint_host,
                   h.public_key AS hub_public_key, n.name, n.ipv4_prefix::text AS "ipv4_prefix!",
                   n.listen_port, n.mtu, n.persistent_keepalive, n.created_at, n.updated_at
            FROM wg_networks n JOIN wg_hubs h ON h.id = n.hub_id
            WHERE n.tenant_id = $1 ORDER BY n.name
            "#,
            tenant_id
        )
        .fetch_all(&self.pool)
        .await?;
        let counts = self.member_counts(tenant_id, None, vis).await?;
        rows.into_iter()
            .map(|r| {
                let c = counts.get(&r.id).copied().unwrap_or_default();
                r.into_network(c)
            })
            .collect()
    }

    /// Tenant's network + counts of members visible to the caller.
    pub async fn get_wg_network(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        vis: &WgVisibility<'_>,
    ) -> Result<Option<WgNetwork>> {
        let Some(row) = sqlx::query_as!(
            NetworkRow,
            r#"
            SELECT n.id, n.hub_id, h.name AS hub_name, h.endpoint_host AS hub_endpoint_host,
                   h.public_key AS hub_public_key, n.name, n.ipv4_prefix::text AS "ipv4_prefix!",
                   n.listen_port, n.mtu, n.persistent_keepalive, n.created_at, n.updated_at
            FROM wg_networks n JOIN wg_hubs h ON h.id = n.hub_id
            WHERE n.tenant_id = $1 AND n.id = $2
            "#,
            tenant_id,
            id
        )
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };
        let counts = self.member_counts(tenant_id, Some(id), vis).await?;
        let c = counts.get(&id).copied().unwrap_or_default();
        row.into_network(c).map(Some)
    }

    /// Tunnel states ([`TunnelState`]) of the tenant's live members visible to the caller:
    /// per network (all, by name) + total. Clock = DB `now()`.
    pub async fn wg_health_summary(
        &self,
        tenant_id: Uuid,
        vis: &WgVisibility<'_>,
    ) -> Result<WgHealthSummary> {
        let rows = sqlx::query!(
            r#"
            SELECT n.id, n.name, n.hub_id, h.name AS hub_name, m.kind AS "kind?",
                   CASE
                       WHEN h.last_seen_at IS NULL
                            OR h.last_seen_at < now() - make_interval(secs => $5::int8) THEN 'unknown'
                       WHEN s.latest_handshake IS NULL THEN 'never'
                       WHEN s.latest_handshake > now() - make_interval(secs => $6::int8) THEN 'connected'
                       WHEN s.latest_handshake >= now() - make_interval(secs => $7::int8) THEN 'idle'
                       ELSE 'stale'
                   END AS "state!",
                   count(m.id) AS "n!"
            FROM wg_networks n JOIN wg_hubs h ON h.id = n.hub_id
            LEFT JOIN wg_members m ON m.network_id = n.id AND m.revoked_at IS NULL
                AND ((m.kind = 'client' AND ($2 OR m.user_id = $3))
                     OR (m.kind = 'device' AND EXISTS (
                         SELECT 1 FROM devices d
                         WHERE d.id = m.device_id AND d.tenant_id = $1 AND device_in_scope(d, $4))))
            LEFT JOIN wg_peer_status s ON s.member_id = m.id
            WHERE n.tenant_id = $1
            GROUP BY n.id, n.name, n.hub_id, h.name, 5, 6
            ORDER BY n.name, n.id
            "#,
            tenant_id,
            vis.all_clients,
            vis.user_id,
            scope_param(vis.scope),
            HUB_SILENT_SECS,
            CONNECTED_SECS,
            STALE_SECS
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = WgHealthSummary::default();
        for r in rows {
            if out.networks.last().is_none_or(|n| n.id != r.id) {
                out.networks.push(WgNetworkHealth {
                    id: r.id,
                    name: r.name,
                    hub_id: r.hub_id,
                    hub_name: r.hub_name,
                    device: WgStateCounts::default(),
                    client: WgStateCounts::default(),
                });
            }
            let Some(state) = TunnelState::parse(&r.state) else {
                continue;
            };
            let Some(net) = out.networks.last_mut() else {
                continue;
            };
            // No visible member -> left-join row of the network, counted 0.
            match r.kind.as_deref() {
                Some("device") => {
                    net.device.add(state, r.n);
                    out.device.add(state, r.n);
                }
                Some("client") => {
                    net.client.add(state, r.n);
                    out.client.add(state, r.n);
                }
                _ => {}
            }
        }
        Ok(out)
    }

    /// Per network: `(device members, client members, revoked members)` visible to the caller.
    async fn member_counts(
        &self,
        tenant_id: Uuid,
        network_id: Option<Uuid>,
        vis: &WgVisibility<'_>,
    ) -> Result<HashMap<Uuid, (i64, i64, i64)>> {
        Ok(sqlx::query!(
            r#"
            SELECT m.network_id,
                   count(*) FILTER (WHERE m.kind = 'device' AND m.revoked_at IS NULL) AS "devices!",
                   count(*) FILTER (WHERE m.kind = 'client' AND m.revoked_at IS NULL) AS "clients!",
                   count(*) FILTER (WHERE m.revoked_at IS NOT NULL) AS "revoked!"
            FROM wg_members m JOIN wg_networks n ON n.id = m.network_id
            WHERE n.tenant_id = $1 AND ($2::uuid IS NULL OR m.network_id = $2)
              AND ((m.kind = 'client' AND ($3 OR m.user_id = $4))
                   OR (m.kind = 'device' AND EXISTS (
                       SELECT 1 FROM devices d
                       WHERE d.id = m.device_id AND d.tenant_id = $1 AND device_in_scope(d, $5))))
            GROUP BY m.network_id
            "#,
            tenant_id,
            network_id,
            vis.all_clients,
            vis.user_id,
            scope_param(vis.scope)
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| (r.network_id, (r.devices, r.clients, r.revoked)))
        .collect())
    }

    /// Create a network on a hub of the tenant. Prefix: from the pool, or checked.
    /// Port: given one, or lowest free from 51820.
    pub async fn create_wg_network(
        &self,
        tenant_id: Uuid,
        new: &NewWgNetwork,
    ) -> WgResult<WgNetwork> {
        let mut tx = self.pool.begin().await?;
        lock_tenant(&mut tx, tenant_id).await?;
        let hub = sqlx::query_scalar!(
            "SELECT id FROM wg_hubs WHERE id = $1 AND tenant_id = $2",
            new.hub_id,
            tenant_id
        )
        .fetch_optional(&mut *tx)
        .await?;
        if hub.is_none() {
            return Ok(Err(WgRefusal::HubNotFound));
        }
        let taken = taken_prefixes(&mut tx, tenant_id, None).await?;
        let prefix = match new.prefix {
            WgPrefixChoice::Auto { len, pool } => allocate_network_prefix(pool, len, &taken),
            WgPrefixChoice::Explicit(p) => check_network_prefix(p, &taken).map(|()| p),
        };
        let prefix = match prefix {
            Ok(p) => p,
            Err(e) => return Ok(Err(WgRefusal::NetworkPrefix(e))),
        };
        let used: Vec<u16> = sqlx::query_scalar!(
            "SELECT listen_port FROM wg_networks WHERE hub_id = $1",
            new.hub_id
        )
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .filter_map(|p| u16::try_from(p).ok())
        .collect();
        let port = match new.listen_port {
            Some(p) if used.contains(&p) => return Ok(Err(WgRefusal::PortTaken(p))),
            Some(p) => p,
            None => match lowest_free_port(&used) {
                Some(p) => p,
                None => return Ok(Err(WgRefusal::NoFreePort)),
            },
        };
        let id = Uuid::now_v7();
        let done = sqlx::query!(
            r#"
            INSERT INTO wg_networks (id, tenant_id, hub_id, name, ipv4_prefix, listen_port, mtu,
                                     persistent_keepalive)
            VALUES ($1, $2, $3, $4, $5::text::cidr, $6, $7, $8)
            "#,
            id,
            tenant_id,
            new.hub_id,
            new.name,
            prefix.to_string(),
            i32::from(port),
            new.mtu,
            new.persistent_keepalive
        )
        .execute(&mut *tx)
        .await;
        match done {
            Ok(_) => {}
            Err(e) => {
                // Hub deleted meanwhile.
                if matches!(&e, sqlx::Error::Database(d) if d.is_foreign_key_violation()) {
                    return Ok(Err(WgRefusal::HubNotFound));
                }
                return match violated(&e) {
                    Some("wg_networks_tenant_id_name_key") => {
                        Ok(Err(WgRefusal::NetworkNameTaken(new.name.clone())))
                    }
                    Some("wg_networks_hub_id_listen_port_key") => {
                        Ok(Err(WgRefusal::PortTaken(port)))
                    }
                    _ => Err(e.into()),
                };
            }
        }
        tx.commit().await?;
        let vis = WgVisibility {
            all_clients: true,
            user_id: None,
            scope: None,
        };
        Ok(self
            .get_wg_network(tenant_id, id, &vis)
            .await?
            .ok_or(WgRefusal::NetworkNotFound))
    }

    /// Change a network. New tunnel prefix -> needs no live members (each would need new
    /// config) + no overlap with other networks of the tenant.
    pub async fn update_wg_network(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        patch: &WgNetworkPatch,
    ) -> WgResult<WgNetwork> {
        let mut tx = self.pool.begin().await?;
        lock_tenant(&mut tx, tenant_id).await?;
        let Some(current) = lock_network(&mut tx, tenant_id, id).await? else {
            return Ok(Err(WgRefusal::NetworkNotFound));
        };
        if let Some(prefix) = patch.ipv4_prefix.filter(|p| *p != current) {
            let live = sqlx::query_scalar!(
                r#"SELECT count(*) AS "n!" FROM wg_members WHERE network_id = $1 AND revoked_at IS NULL"#,
                id
            )
            .fetch_one(&mut *tx)
            .await?;
            if live > 0 {
                return Ok(Err(WgRefusal::NetworkHasMembers));
            }
            let taken = taken_prefixes(&mut tx, tenant_id, Some(id)).await?;
            if let Err(e) = check_network_prefix(prefix, &taken) {
                return Ok(Err(WgRefusal::NetworkPrefix(e)));
            }
        }
        let done = sqlx::query!(
            r#"
            UPDATE wg_networks SET name = COALESCE($3, name),
                ipv4_prefix = COALESCE($4::text::cidr, ipv4_prefix),
                listen_port = COALESCE($5, listen_port), mtu = COALESCE($6, mtu),
                persistent_keepalive = COALESCE($7, persistent_keepalive), updated_at = now()
            WHERE id = $1 AND tenant_id = $2
            "#,
            id,
            tenant_id,
            patch.name,
            patch.ipv4_prefix.map(|p| p.to_string()),
            patch.listen_port.map(i32::from),
            patch.mtu,
            patch.persistent_keepalive
        )
        .execute(&mut *tx)
        .await;
        if let Err(e) = done {
            return match violated(&e) {
                Some("wg_networks_tenant_id_name_key") => Ok(Err(WgRefusal::NetworkNameTaken(
                    patch.name.clone().unwrap_or_default(),
                ))),
                Some("wg_networks_hub_id_listen_port_key") => Ok(Err(WgRefusal::PortTaken(
                    patch.listen_port.unwrap_or_default(),
                ))),
                _ => Err(e.into()),
            };
        }
        tx.commit().await?;
        let vis = WgVisibility {
            all_clients: true,
            user_id: None,
            scope: None,
        };
        Ok(self
            .get_wg_network(tenant_id, id, &vis)
            .await?
            .ok_or(WgRefusal::NetworkNotFound))
    }

    /// Delete a network + its members + their site prefixes -> count of live members gone.
    pub async fn delete_wg_network(&self, tenant_id: Uuid, id: Uuid) -> WgResult<i64> {
        let mut tx = self.pool.begin().await?;
        let Some(_) = lock_network(&mut tx, tenant_id, id).await? else {
            return Ok(Err(WgRefusal::NetworkNotFound));
        };
        let live = sqlx::query_scalar!(
            r#"SELECT count(*) AS "n!" FROM wg_members WHERE network_id = $1 AND revoked_at IS NULL"#,
            id
        )
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query!(
            "DELETE FROM wg_networks WHERE id = $1 AND tenant_id = $2",
            id,
            tenant_id
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Ok(live))
    }

    /// Page of a network's members visible to the caller, by address, + total count.
    /// `None` -> network not the tenant's.
    pub async fn list_wg_members(
        &self,
        tenant_id: Uuid,
        network_id: Uuid,
        vis: &WgVisibility<'_>,
        include_revoked: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Option<(Vec<WgMember>, i64)>> {
        let mut conn = self.pool.acquire().await?;
        let exists = sqlx::query_scalar!(
            "SELECT id FROM wg_networks WHERE id = $1 AND tenant_id = $2",
            network_id,
            tenant_id
        )
        .fetch_optional(&mut *conn)
        .await?;
        if exists.is_none() {
            return Ok(None);
        }
        let scope = scope_param(vis.scope);
        let total = sqlx::query_scalar!(
            r#"
            SELECT count(*) AS "n!" FROM wg_members m
            WHERE m.network_id = $1 AND ($2 OR m.revoked_at IS NULL)
              AND ((m.kind = 'client' AND ($3 OR m.user_id = $4))
                   OR (m.kind = 'device' AND EXISTS (
                       SELECT 1 FROM devices d
                       WHERE d.id = m.device_id AND d.tenant_id = $6 AND device_in_scope(d, $5))))
            "#,
            network_id,
            include_revoked,
            vis.all_clients,
            vis.user_id,
            scope,
            tenant_id
        )
        .fetch_one(&mut *conn)
        .await?;
        let rows = sqlx::query_as!(
            MemberRow,
            r#"
            SELECT m.id, m.network_id, m.kind, m.device_id, m.user_id, m.name, m.public_key,
                   m.key_mode, m.preshared_key_enabled, host(m.address) AS "address!",
                   m.revoked_at, m.revoked_reason, m.device_state, m.device_detail,
                   m.device_checked_at, m.device_applied_hash, m.rotate_requested_at,
               m.created_at, m.updated_at
            FROM wg_members m
            WHERE m.network_id = $1 AND ($2 OR m.revoked_at IS NULL)
              AND ((m.kind = 'client' AND ($3 OR m.user_id = $4))
                   OR (m.kind = 'device' AND EXISTS (
                       SELECT 1 FROM devices d
                       WHERE d.id = m.device_id AND d.tenant_id = $6 AND device_in_scope(d, $5))))
            ORDER BY m.address, m.created_at, m.id
            LIMIT $7 OFFSET $8
            "#,
            network_id,
            include_revoked,
            vis.all_clients,
            vis.user_id,
            scope,
            tenant_id,
            limit,
            offset
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(Some((with_prefixes(&mut conn, rows).await?, total)))
    }

    /// Member visible to the caller.
    pub async fn get_wg_member(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        vis: &WgVisibility<'_>,
    ) -> Result<Option<WgMember>> {
        let mut conn = self.pool.acquire().await?;
        let Some(row) = sqlx::query_as!(
            MemberRow,
            r#"
            SELECT m.id, m.network_id, m.kind, m.device_id, m.user_id, m.name, m.public_key,
                   m.key_mode, m.preshared_key_enabled, host(m.address) AS "address!",
                   m.revoked_at, m.revoked_reason, m.device_state, m.device_detail,
                   m.device_checked_at, m.device_applied_hash, m.rotate_requested_at,
               m.created_at, m.updated_at
            FROM wg_members m JOIN wg_networks n ON n.id = m.network_id
            WHERE m.id = $1 AND n.tenant_id = $2
              AND ((m.kind = 'client' AND ($3 OR m.user_id = $4))
                   OR (m.kind = 'device' AND EXISTS (
                       SELECT 1 FROM devices d
                       WHERE d.id = m.device_id AND d.tenant_id = $2 AND device_in_scope(d, $5))))
            "#,
            id,
            tenant_id,
            vis.all_clients,
            vis.user_id,
            scope_param(vis.scope)
        )
        .fetch_optional(&mut *conn)
        .await?
        else {
            return Ok(None);
        };
        Ok(with_prefixes(&mut conn, vec![row]).await?.pop())
    }

    /// Live device members of a device + its twins (other record of the same CPE: same
    /// tenant, equal non-empty OUI + serial number), device visible to the caller.
    /// Each with network name + tunnel report from stored parameters of the owning record.
    /// Order: network name, then member ID.
    pub async fn list_wg_device_members(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        vis: &WgVisibility<'_>,
    ) -> Result<Vec<WgDeviceMember>> {
        let mut conn = self.pool.acquire().await?;
        let rows = sqlx::query!(
            r#"
            SELECT m.id, m.network_id, m.kind, m.device_id, m.user_id, m.name, m.public_key,
                   m.key_mode, m.preshared_key_enabled, host(m.address) AS "address!",
                   m.revoked_at, m.revoked_reason, m.device_state, m.device_detail,
                   m.device_checked_at, m.device_applied_hash, m.rotate_requested_at,
                   m.created_at, m.updated_at, n.name AS network_name, t.id AS owner_id,
                   t.protocol AS owner_protocol
            FROM devices d
            JOIN devices t ON t.tenant_id = d.tenant_id
                AND (t.id = d.id
                     OR (t.oui = d.oui AND t.serial_number = d.serial_number
                         AND d.oui <> '' AND d.serial_number <> ''))
            JOIN wg_members m ON m.device_id = t.id
            JOIN wg_networks n ON n.id = m.network_id AND n.tenant_id = d.tenant_id
            WHERE d.id = $2 AND d.tenant_id = $1
              AND m.kind = 'device' AND m.revoked_at IS NULL
              AND device_in_scope(t, $3)
            ORDER BY n.name, m.id
            "#,
            tenant_id,
            device_id,
            scope_param(vis.scope)
        )
        .fetch_all(&mut *conn)
        .await?;
        let mut owners: Vec<Uuid> = rows.iter().map(|r| r.owner_id).collect();
        owners.sort_unstable();
        owners.dedup();
        // Member configured via its owning record -> that snapshot = device report.
        let mut params: HashMap<Uuid, Vec<StoredValue>> = HashMap::new();
        for p in sqlx::query!(
            r#"
            SELECT device_id, path, value, updated_at FROM device_params
            WHERE device_id = ANY($1) AND path LIKE 'Device.WireGuard.%' AND path ~ $2
            "#,
            &owners,
            DEVICE_SIDE_PATHS
        )
        .fetch_all(&mut *conn)
        .await?
        {
            params
                .entry(p.device_id)
                .or_default()
                .push((p.path, p.value, p.updated_at));
        }
        let mut extra = Vec::with_capacity(rows.len());
        let mut members = Vec::with_capacity(rows.len());
        for r in rows {
            let device_side = params
                .get(&r.owner_id)
                .and_then(|p| device_side_of(p, r.network_id));
            extra.push((
                r.network_name,
                (r.owner_id != device_id).then_some((r.owner_id, r.owner_protocol)),
                device_side,
            ));
            members.push(MemberRow {
                id: r.id,
                network_id: r.network_id,
                kind: r.kind,
                device_id: r.device_id,
                user_id: r.user_id,
                name: r.name,
                public_key: r.public_key,
                key_mode: r.key_mode,
                preshared_key_enabled: r.preshared_key_enabled,
                address: r.address,
                revoked_at: r.revoked_at,
                revoked_reason: r.revoked_reason,
                device_state: r.device_state,
                device_detail: r.device_detail,
                device_checked_at: r.device_checked_at,
                device_applied_hash: r.device_applied_hash,
                rotate_requested_at: r.rotate_requested_at,
                created_at: r.created_at,
                updated_at: r.updated_at,
            });
        }
        Ok(with_prefixes(&mut conn, members)
            .await?
            .into_iter()
            .zip(extra)
            .map(
                |(member, (network_name, via_twin, device_side))| WgDeviceMember {
                    member,
                    network_name,
                    via_twin,
                    device_side,
                },
            )
            .collect())
    }

    /// Add a member to a network. Address = lowest free host: not network, broadcast or
    /// hub `.1`; not of a live member or one revoked less than `reuse_delay` ago.
    /// Concurrent requests -> never the same address: network row lock + unique index.
    ///
    /// Device members: stored without key, `device_state` = `pending`.
    /// CPE provisioning (stage 4) fills in `public_key`.
    pub async fn create_wg_member(
        &self,
        tenant_id: Uuid,
        network_id: Uuid,
        new: &NewWgMember,
        reuse_delay: Duration,
    ) -> WgResult<WgMember> {
        let mut tx = self.pool.begin().await?;
        let Some(network) = lock_network(&mut tx, tenant_id, network_id).await? else {
            return Ok(Err(WgRefusal::NetworkNotFound));
        };
        let id = new.id;
        let (kind, device_id, user_id, public_key, key_mode) = match &new.kind {
            NewWgMemberKind::Device {
                device_id,
                key_mode,
            } => {
                let known = sqlx::query_scalar!(
                    "SELECT id FROM devices WHERE id = $1 AND tenant_id = $2",
                    device_id,
                    tenant_id
                )
                .fetch_optional(&mut *tx)
                .await?;
                if known.is_none() {
                    return Ok(Err(WgRefusal::DeviceNotFound));
                }
                let member = sqlx::query_scalar!(
                    r#"
                    SELECT EXISTS (SELECT 1 FROM wg_members
                                   WHERE network_id = $1 AND device_id = $2 AND revoked_at IS NULL)
                    AS "e!"
                    "#,
                    network_id,
                    device_id
                )
                .fetch_one(&mut *tx)
                .await?;
                if member {
                    return Ok(Err(WgRefusal::DeviceAlreadyMember));
                }
                let twin = sqlx::query_scalar!(
                    r#"
                    SELECT EXISTS (
                        SELECT 1 FROM devices d
                        JOIN devices t ON t.tenant_id = d.tenant_id AND t.id <> d.id
                            AND t.oui = d.oui AND t.serial_number = d.serial_number
                        JOIN wg_members m ON m.device_id = t.id
                        WHERE d.id = $2 AND d.oui <> '' AND d.serial_number <> ''
                          AND m.network_id = $1 AND m.kind = 'device' AND m.revoked_at IS NULL)
                    AS "e!"
                    "#,
                    network_id,
                    device_id
                )
                .fetch_one(&mut *tx)
                .await?;
                if twin {
                    return Ok(Err(WgRefusal::DeviceTwinIsMember));
                }
                (
                    "device",
                    Some(*device_id),
                    None,
                    None,
                    Some(key_mode.as_str()),
                )
            }
            NewWgMemberKind::Client {
                user_id,
                public_key,
            } => {
                if let Some(uid) = user_id {
                    // API checked the owner already. Share lock closes the race with an
                    // account change that revokes its clients: change waits until the member
                    // exists (then revokes it too), or this read sees the change.
                    let owner = sqlx::query!(
                        r#"
                        SELECT role, disabled, scope IS NOT NULL AS "scoped!"
                        FROM users WHERE id = $1 AND tenant_id = $2 FOR SHARE
                        "#,
                        uid,
                        tenant_id
                    )
                    .fetch_optional(&mut *tx)
                    .await?;
                    let Some(owner) = owner else {
                        return Ok(Err(WgRefusal::OwnerNotFound));
                    };
                    if owner.disabled
                        || !matches!(owner.role.as_str(), "admin" | "operator")
                        || owner.scoped
                    {
                        return Ok(Err(WgRefusal::OwnerCannotOwnClients));
                    }
                }
                ("client", None, *user_id, Some(public_key.as_str()), None)
            }
        };
        if !new.site_prefixes.is_empty() {
            let own: Vec<Ipv4Prefix> = new.site_prefixes.iter().map(|p| p.prefix).collect();
            let others = others_site_prefixes(&mut tx, network_id, id).await?;
            if let Err(e) = check_site_prefixes(network, &own, &others) {
                return Ok(Err(WgRefusal::SitePrefix(e)));
            }
        }
        let now = sqlx::query_scalar!(r#"SELECT now() AS "now!""#)
            .fetch_one(&mut *tx)
            .await?;
        let rows = sqlx::query!(
            r#"SELECT host(address) AS "address!", revoked_at FROM wg_members WHERE network_id = $1"#,
            network_id
        )
        .fetch_all(&mut *tx)
        .await?;
        let mut held = Vec::with_capacity(rows.len());
        for r in rows {
            // Address of an earlier tunnel prefix -> not a host of this one, holds nothing.
            let address = address_of(&r.address)?;
            if network.contains_addr(address) {
                held.push(UsedAddress {
                    address,
                    revoked_at: r.revoked_at,
                });
            }
        }
        let in_use = addresses_in_use(&held, now, reuse_delay);
        let Some(address) = allocate_member_address(network, &in_use) else {
            return Ok(Err(WgRefusal::NetworkFull(network)));
        };
        let done = sqlx::query!(
            r#"
            INSERT INTO wg_members (id, network_id, kind, device_id, user_id, name, public_key,
                                    key_mode, preshared_key_enabled, address, device_state,
                                    psk_ciphertext, psk_nonce)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::text::inet,
                    CASE WHEN $3 = 'device' THEN 'pending' END, $11, $12)
            "#,
            id,
            network_id,
            kind,
            device_id,
            user_id,
            new.name,
            public_key,
            key_mode,
            new.psk.is_some(),
            address.to_string(),
            new.psk.as_ref().map(|(ct, _)| ct.as_slice()),
            new.psk.as_ref().map(|(_, nonce)| nonce.as_slice())
        )
        .execute(&mut *tx)
        .await;
        if let Err(e) = done {
            return match violated(&e) {
                Some("wg_members_live_key") => Ok(Err(WgRefusal::KeyInUse)),
                Some("wg_members_live_device") => Ok(Err(WgRefusal::DeviceAlreadyMember)),
                _ => Err(e.into()),
            };
        }
        for p in &new.site_prefixes {
            sqlx::query!(
                r#"
                INSERT INTO wg_site_prefixes (id, member_id, prefix, description)
                VALUES ($1, $2, $3::text::cidr, $4)
                "#,
                Uuid::now_v7(),
                id,
                p.prefix.to_string(),
                p.description
            )
            .execute(&mut *tx)
            .await?;
        }
        let member = member_in(&mut tx, tenant_id, id).await?;
        tx.commit().await?;
        Ok(member.ok_or(WgRefusal::MemberNotFound))
    }

    /// Rename a member, replace its site prefixes (all, atomic, checked against other
    /// members of the network) and/or set its PSK (`Some(Some)` = this sealed key,
    /// `Some(None)` = none; `preshared_key_enabled` follows). Revoked member -> no change.
    pub async fn update_wg_member(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        name: Option<&str>,
        site_prefixes: Option<&[WgSitePrefix]>,
        psk: Option<Option<(&[u8], &[u8])>>,
    ) -> WgResult<WgMember> {
        let mut tx = self.pool.begin().await?;
        let Some(found) = sqlx::query!(
            "SELECT m.network_id, m.revoked_at FROM wg_members m JOIN wg_networks n ON n.id = m.network_id WHERE m.id = $1 AND n.tenant_id = $2",
            id,
            tenant_id
        )
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(Err(WgRefusal::MemberNotFound));
        };
        let Some(network) = lock_network(&mut tx, tenant_id, found.network_id).await? else {
            return Ok(Err(WgRefusal::MemberNotFound));
        };
        // Re-read under the lock: revocation may have come meanwhile.
        let revoked = sqlx::query_scalar!(
            "SELECT revoked_at FROM wg_members WHERE id = $1 FOR NO KEY UPDATE",
            id
        )
        .fetch_optional(&mut *tx)
        .await?;
        match revoked {
            None => return Ok(Err(WgRefusal::MemberNotFound)),
            Some(Some(_)) => return Ok(Err(WgRefusal::MemberRevoked)),
            Some(None) => {}
        }
        if let Some(list) = site_prefixes {
            let own: Vec<Ipv4Prefix> = list.iter().map(|p| p.prefix).collect();
            let others = others_site_prefixes(&mut tx, found.network_id, id).await?;
            if let Err(e) = check_site_prefixes(network, &own, &others) {
                return Ok(Err(WgRefusal::SitePrefix(e)));
            }
            sqlx::query!("DELETE FROM wg_site_prefixes WHERE member_id = $1", id)
                .execute(&mut *tx)
                .await?;
            for p in list {
                sqlx::query!(
                    r#"
                    INSERT INTO wg_site_prefixes (id, member_id, prefix, description)
                    VALUES ($1, $2, $3::text::cidr, $4)
                    "#,
                    Uuid::now_v7(),
                    id,
                    p.prefix.to_string(),
                    p.description
                )
                .execute(&mut *tx)
                .await?;
            }
        }
        sqlx::query!(
            "UPDATE wg_members SET name = COALESCE($2, name), updated_at = now() WHERE id = $1",
            id,
            name
        )
        .execute(&mut *tx)
        .await?;
        if let Some(psk) = psk {
            sqlx::query!(
                r#"
                UPDATE wg_members SET preshared_key_enabled = $2, psk_ciphertext = $3,
                    psk_nonce = $4
                WHERE id = $1
                "#,
                id,
                psk.is_some(),
                psk.map(|(ct, _)| ct),
                psk.map(|(_, nonce)| nonce)
            )
            .execute(&mut *tx)
            .await?;
        }
        let member = member_in(&mut tx, tenant_id, id).await?;
        tx.commit().await?;
        Ok(member.ok_or(WgRefusal::MemberNotFound))
    }

    /// Revoke a member (row kept). Already revoked -> no change, first reason kept.
    /// Returns member + whether this call revoked it.
    pub async fn revoke_wg_member(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        reason: Option<&str>,
    ) -> WgResult<(WgMember, bool)> {
        let mut tx = self.pool.begin().await?;
        let done = sqlx::query!(
            r#"
            UPDATE wg_members m SET revoked_at = now(), revoked_reason = $3, updated_at = now()
            FROM wg_networks n
            WHERE m.id = $1 AND n.id = m.network_id AND n.tenant_id = $2 AND m.revoked_at IS NULL
            "#,
            id,
            tenant_id,
            reason
        )
        .execute(&mut *tx)
        .await?;
        let member = member_in(&mut tx, tenant_id, id).await?;
        tx.commit().await?;
        Ok(member
            .map(|m| (m, done.rows_affected() == 1))
            .ok_or(WgRefusal::MemberNotFound))
    }

    /// Site prefixes of the network's live members, ascending, no duplicates
    /// -> what a client member reaches besides the tunnel prefix (Q6).
    pub async fn wg_network_site_prefixes(&self, network_id: Uuid) -> Result<Vec<Ipv4Prefix>> {
        sqlx::query_scalar!(
            r#"
            SELECT s.prefix::text AS "prefix!" FROM (
                SELECT DISTINCT sp.prefix
                FROM wg_site_prefixes sp JOIN wg_members m ON m.id = sp.member_id
                WHERE m.network_id = $1 AND m.revoked_at IS NULL
            ) s ORDER BY s.prefix
            "#,
            network_id
        )
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(|p| prefix_of(p))
        .collect()
    }

    /// New public key for a client member; with `psk` also a new sealed PSK if enabled
    /// (client without PSK stays without). Last hub report dropped: it was about the old key.
    /// Revision triggers -> hub drops the old key.
    pub async fn rekey_wg_client(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        public_key: &str,
        psk: Option<(&[u8], &[u8])>,
    ) -> WgResult<WgMember> {
        let mut tx = self.pool.begin().await?;
        let Some(found) = sqlx::query!(
            r#"
            SELECT m.kind, m.revoked_at FROM wg_members m JOIN wg_networks n ON n.id = m.network_id
            WHERE m.id = $1 AND n.tenant_id = $2 FOR NO KEY UPDATE OF m
            "#,
            id,
            tenant_id
        )
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(Err(WgRefusal::MemberNotFound));
        };
        if found.revoked_at.is_some() {
            return Ok(Err(WgRefusal::MemberRevoked));
        }
        if found.kind != "client" {
            return Ok(Err(WgRefusal::NotAClient));
        }
        let done = sqlx::query!(
            r#"
            UPDATE wg_members SET public_key = $2, updated_at = now(),
                psk_ciphertext = CASE WHEN preshared_key_enabled AND $3::bytea IS NOT NULL
                                      THEN $3 ELSE psk_ciphertext END,
                psk_nonce = CASE WHEN preshared_key_enabled AND $3::bytea IS NOT NULL
                                 THEN $4 ELSE psk_nonce END
            WHERE id = $1
            "#,
            id,
            public_key,
            psk.map(|(ct, _)| ct),
            psk.map(|(_, nonce)| nonce)
        )
        .execute(&mut *tx)
        .await;
        if let Err(e) = done {
            return match violated(&e) {
                Some("wg_members_live_key") => Ok(Err(WgRefusal::KeyInUse)),
                _ => Err(e.into()),
            };
        }
        sqlx::query!("DELETE FROM wg_peer_status WHERE member_id = $1", id)
            .execute(&mut *tx)
            .await?;
        let member = member_in(&mut tx, tenant_id, id).await?;
        tx.commit().await?;
        Ok(member.ok_or(WgRefusal::MemberNotFound))
    }

    /// Sealed PSK of a tenant's member; `None` -> no such member, or no PSK.
    pub async fn wg_member_psk(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<WgSealedPsk>> {
        let row = sqlx::query!(
            r#"
            SELECT m.psk_ciphertext, m.psk_nonce
            FROM wg_members m JOIN wg_networks n ON n.id = m.network_id
            WHERE m.id = $1 AND n.tenant_id = $2
            "#,
            id,
            tenant_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.psk_ciphertext.zip(r.psk_nonce)))
    }

    /// Max `limit` sealed PSKs of all tenants, by member ID after `after`
    /// -> input of secrets-key rotation (sealed again).
    pub async fn wg_psks_page(&self, after: Option<Uuid>, limit: i64) -> Result<Vec<SealedWgPsk>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, psk_ciphertext AS "ciphertext!", psk_nonce AS "nonce!"
            FROM wg_members
            WHERE psk_ciphertext IS NOT NULL AND ($1::uuid IS NULL OR id > $1)
            ORDER BY id LIMIT $2
            "#,
            after,
            limit
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| SealedWgPsk {
                member_id: r.id,
                ciphertext: r.ciphertext,
                nonce: r.nonce,
            })
            .collect())
    }

    /// Replace a sealed PSK with the same key sealed again, unless changed meanwhile.
    /// Returns whether replaced. `updated_at` stays.
    pub async fn rewrap_wg_psk(
        &self,
        old: &SealedWgPsk,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<bool> {
        let done = sqlx::query!(
            r#"
            UPDATE wg_members SET psk_ciphertext = $3, psk_nonce = $4
            WHERE id = $1 AND psk_ciphertext = $2
            "#,
            old.member_id,
            old.ciphertext,
            ciphertext,
            nonce
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Delete a member + its site prefixes for good (revoke keeps the row).
    pub async fn delete_wg_member(&self, tenant_id: Uuid, id: Uuid) -> WgResult<()> {
        let done = sqlx::query!(
            r#"
            DELETE FROM wg_members m USING wg_networks n
            WHERE m.id = $1 AND n.id = m.network_id AND n.tenant_id = $2
            "#,
            id,
            tenant_id
        )
        .execute(&self.pool)
        .await?;
        Ok(if done.rows_affected() == 1 {
            Ok(())
        } else {
            Err(WgRefusal::MemberNotFound)
        })
    }
}
