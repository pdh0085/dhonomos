//! WireGuard management (ADR-110, docs/design/13-wireguard.md): hubs, overlay networks,
//! members + LAN prefixes behind device members. Stored + served here.
//! Hub process gets its part via [`crate::wg_hub`], with a hub token issued here.
//! CPE of a device member -> configured by core (`dhonomos_core` `WgRunner`);
//! member shows progress (`device_status`).
//!
//! | Who | May |
//! |---|---|
//! | operator, admin | read hubs, networks and the members they may see |
//! | admin | create, change and delete hubs and networks; issue and revoke hub tokens; delete members |
//! | operator | add a device member for a device inside the account's device scope; change and revoke the device members they see |
//! | operator without a device scope | add a client member for themselves; list, change, re-key and revoke their own clients and fetch their configuration files |
//! | admin | also add a client for another account, or a server client that belongs to none; see, re-key and revoke every client |
//!
//! Client member -> reaches the whole network (Q6): tunnel prefix + site prefixes of every
//! live device member.
//! Request (creation or re-key) without `public_key` -> key pair made here.
//! Private key, wg-quick config file with it + its QR code: in that one response only,
//! never stored, logged or audited. Config can be fetched again later, without private key.
//! Account disabled, deleted, below operator role or gets a device scope -> its clients
//! revoked in the same transaction (store does it).
//!
//! Devices woken when their WireGuard config should change:
//! - hub: endpoint or public key
//! - network: tunnel prefix, port, MTU or keepalive
//! - device member added (has site prefixes -> whole network, it routes to them), revoked or
//!   deleted (whole network + the member's own device)
//! - site prefixes of a member
//!
//! CWMP devices concerned -> CR in background, max 100 per change, 8 at a time;
//! others apply it at their next periodic Inform.
//! USP Agents: no wake, reconciled while connected.
//! Names, clients, new hubs or networks -> wake nobody.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use dhonomos_store::{
    NewWgMember, NewWgMemberKind, NewWgNetwork, RevokedClient, WgDeviceMember, WgDeviceSide,
    WgHealthSummary, WgHub, WgMember, WgNetwork, WgNetworkPatch, WgPrefixChoice, WgRefusal,
    WgSitePrefix, WgStateCounts, WgVisibility,
};
use dhonomos_wireguard::{
    CONNECTED_SECS, ClientConfig, DEFAULT_NETWORK_LEN, HUB_SILENT_SECS, HUB_TOKEN_PREFIX,
    Ipv4Prefix, KeyPair, MAX_SITE_PREFIXES, NETWORK_MAX_LEN, NETWORK_MIN_LEN, STALE_SECS,
    check_pool, config_file_name, generate_keypair, generate_preshared_key, hub_address, key_text,
    render_client_config, validate_key,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::auth::{Principal, Role, present, random_token, sha256};
use crate::{ApiError, AppState, Page, audit, device_of, not_found, ts};

/// Max hub, network or member name, in chars.
const MAX_NAME: usize = 64;
/// Max site prefix description, in chars.
const MAX_DESCRIPTION: usize = 200;
/// Max revoke reason, in chars.
const MAX_REASON: usize = 200;
const DEFAULT_MTU: i64 = 1420;
const DEFAULT_KEEPALIVE: i64 = 25;

/// Server WireGuard settings (ADR-110).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireguardConfig {
    /// IPv4 range for the tunnel prefixes of networks (`--wg-address-pool`).
    pub address_pool: Ipv4Prefix,
    /// Address of a revoked member -> no reuse for this long (`--wg-address-reuse-delay-hours`).
    pub address_reuse_delay: Duration,
}

impl Default for WireguardConfig {
    fn default() -> Self {
        Self {
            address_pool: Ipv4Prefix::new(std::net::Ipv4Addr::new(10, 77, 0, 0), 16)
                .unwrap_or_else(|| unreachable!("10.77.0.0/16 is canonical")),
            address_reuse_delay: Duration::from_secs(24 * 3600),
        }
    }
}

impl WireguardConfig {
    /// Settings with a checked address pool.
    pub fn new(address_pool: Ipv4Prefix, reuse_delay_hours: u64) -> Result<Self, String> {
        check_pool(address_pool).map_err(|e| format!("--wg-address-pool {address_pool}: {e}"))?;
        Ok(Self {
            address_pool,
            address_reuse_delay: Duration::from_secs(reuse_delay_hours.saturating_mul(3600)),
        })
    }
}

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/wireguard/summary", get(summary))
        .route("/wireguard/hubs", get(list_hubs).post(create_hub))
        .route(
            "/wireguard/hubs/{id}",
            get(get_hub).patch(update_hub).delete(delete_hub),
        )
        .route(
            "/wireguard/hubs/{id}/token",
            post(issue_hub_token).delete(revoke_hub_token),
        )
        .route(
            "/wireguard/networks",
            get(list_networks).post(create_network),
        )
        .route(
            "/wireguard/networks/{id}",
            get(get_network)
                .patch(update_network)
                .delete(delete_network),
        )
        .route(
            "/wireguard/networks/{id}/members",
            get(list_members).post(create_member),
        )
        .route(
            "/wireguard/members/{id}",
            get(get_member).patch(update_member).delete(delete_member),
        )
        .route("/wireguard/members/{id}/revoke", post(revoke_member))
        .route("/wireguard/members/{id}/config", get(member_config))
        .route("/wireguard/members/{id}/rekey", post(rekey_member))
        .route(
            "/wireguard/members/{id}/rotate-key",
            post(rotate_member_key),
        )
        .route(
            "/wireguard/networks/{id}/rotate-keys",
            post(rotate_network_keys),
        )
        .route("/devices/{id}/wireguard", get(device_members))
}

pub(crate) fn unprocessable(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg.into())
}

fn forbidden(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::FORBIDDEN, msg.into())
}

/// Store refusal -> API answer.
fn refusal(r: WgRefusal) -> ApiError {
    let status = match &r {
        WgRefusal::HubNotFound
        | WgRefusal::NetworkNotFound
        | WgRefusal::MemberNotFound
        | WgRefusal::DeviceNotFound => StatusCode::NOT_FOUND,
        WgRefusal::OwnerNotFound
        | WgRefusal::OwnerCannotOwnClients
        | WgRefusal::NotAClient
        | WgRefusal::NotADevice => StatusCode::UNPROCESSABLE_ENTITY,
        WgRefusal::NetworkPrefix(e) if !e.is_conflict() => StatusCode::UNPROCESSABLE_ENTITY,
        WgRefusal::SitePrefix(e) if !e.is_conflict() => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::CONFLICT,
    };
    ApiError(status, r.to_string())
}

/// What the caller may see of members (design 13 sec. 6, Q6).
fn visibility(caller: &Principal) -> WgVisibility<'_> {
    WgVisibility {
        all_clients: caller.role() >= Role::Admin,
        user_id: caller.user_id(),
        scope: caller.scope(),
    }
}

/// All visible: for admin bookkeeping, e.g. the answer to a change they just made.
const EVERYTHING: WgVisibility<'static> = WgVisibility {
    all_clients: true,
    user_id: None,
    scope: None,
};

/// Name: 1-64 chars, no control chars.
fn clean_name(what: &str, name: &str) -> Result<String, ApiError> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > MAX_NAME || n.chars().any(char::is_control) {
        return Err(unprocessable(format!(
            "{what} must be 1-{MAX_NAME} characters without control characters"
        )));
    }
    Ok(n.to_owned())
}

/// Host name or IP address, no scheme, port or brackets.
fn clean_endpoint_host(host: &str) -> Result<String, ApiError> {
    let h = host.trim();
    let bad = || {
        unprocessable(
            "endpoint_host must be a host name or an IP address (no scheme, port or brackets)",
        )
    };
    if h.is_empty() || h.len() > 253 {
        return Err(bad());
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return if ip.is_unspecified() || ip.is_multicast() {
            Err(bad())
        } else {
            Ok(h.to_owned())
        };
    }
    let labels: Vec<&str> = h.split('.').collect();
    let label_ok = |l: &&str| {
        (1..=63).contains(&l.len())
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    // Numeric last label -> "999.1.1.1" would be a host name; it is a mistyped address.
    let numeric_tld = labels
        .last()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    if !labels.iter().all(label_ok) || numeric_tld {
        return Err(bad());
    }
    Ok(h.to_ascii_lowercase())
}

/// Whole number in `low..=high`.
fn in_range(what: &str, n: i64, low: i64, high: i64) -> Result<i32, ApiError> {
    i32::try_from(n)
        .ok()
        .filter(|n| (low..=high).contains(&i64::from(*n)))
        .ok_or_else(|| unprocessable(format!("{what} must be between {low} and {high}")))
}

fn prefix_of(what: &str, s: &str) -> Result<Ipv4Prefix, ApiError> {
    s.trim()
        .parse()
        .map_err(|e: dhonomos_wireguard::ParsePrefixError| unprocessable(format!("{what}: {e}")))
}

// --- JSON ---------------------------------------------------------------------------------

pub(crate) fn hub_json(h: &WgHub) -> Value {
    json!({
        "id": h.id,
        "name": h.name,
        "endpoint_host": h.endpoint_host,
        "public_key": h.public_key,
        "networks": h.networks,
        "token_prefix": h.token_prefix,
        "token_created_at": h.token_created_at.map(ts),
        "last_seen_at": h.last_seen_at.map(ts),
        "last_seen_ip": h.last_seen_ip,
        "version": h.hub_version,
        "state_revision": h.state_revision,
        "created_at": ts(h.created_at),
        "updated_at": ts(h.updated_at),
    })
}

pub(crate) fn network_json(n: &WgNetwork) -> Value {
    json!({
        "id": n.id,
        "hub": {
            "id": n.hub_id,
            "name": n.hub_name,
            "endpoint_host": n.hub_endpoint_host,
            "public_key": n.hub_public_key,
        },
        "name": n.name,
        "ipv4_prefix": n.ipv4_prefix.to_string(),
        "hub_address": hub_address(n.ipv4_prefix).to_string(),
        "listen_port": n.listen_port,
        "mtu": n.mtu,
        "persistent_keepalive": n.persistent_keepalive,
        "members": {
            "device": n.device_members,
            "client": n.client_members,
            "revoked": n.revoked_members,
        },
        "created_at": ts(n.created_at),
        "updated_at": ts(n.updated_at),
    })
}

pub(crate) fn member_json(m: &WgMember) -> Value {
    // Applied hash stays internal: only tells the server when to configure again.
    let device_status = m
        .device_state
        .as_ref()
        .filter(|_| m.kind == "device")
        .map(|state| {
            json!({
                "state": state,
                "detail": m.device_detail,
                "checked_at": m.device_checked_at.map(ts),
            })
        });
    json!({
        "id": m.id,
        "network_id": m.network_id,
        "kind": m.kind,
        "name": m.name,
        "device_id": m.device_id,
        "user_id": m.user_id,
        "public_key": m.public_key,
        "key_mode": m.key_mode,
        "preshared_key_enabled": m.preshared_key_enabled,
        "address": m.address.to_string(),
        "site_prefixes": m.site_prefixes.iter().map(|p| json!({
            "prefix": p.prefix.to_string(),
            "description": p.description,
        })).collect::<Vec<_>>(),
        "revoked_at": m.revoked_at.map(ts),
        "revoked_reason": m.revoked_reason,
        "hub_status": m.hub_status.as_ref().map(|st| json!({
            "endpoint": st.endpoint,
            "latest_handshake": st.latest_handshake.map(ts),
            "rx_bytes": st.rx_bytes,
            "tx_bytes": st.tx_bytes,
            "reported_at": ts(st.reported_at),
        })),
        "device_status": device_status,
        "rotate_requested_at": m.rotate_requested_at.map(ts),
        "created_at": ts(m.created_at),
        "updated_at": ts(m.updated_at),
    })
}

/// Tunnel report of the device.
fn device_side_json(d: &WgDeviceSide) -> Value {
    json!({
        "tunnel_status": d.tunnel_status,
        "interface_status": d.interface_status,
        "last_handshake_secs": d.last_handshake_secs,
        "bytes_sent": d.bytes_sent,
        "bytes_received": d.bytes_received,
        "read_at": ts(d.read_at),
    })
}

/// Device member in the WireGuard view of a device: member, network name, twin it belongs
/// to (null for the device's own) + report of the record that owns it.
pub(crate) fn device_member_json(dm: &WgDeviceMember) -> Value {
    let mut v = member_json(&dm.member);
    v["network_name"] = json!(dm.network_name);
    v["via_twin"] = match &dm.via_twin {
        Some((device_id, protocol)) => json!({ "device_id": device_id, "protocol": protocol }),
        None => Value::Null,
    };
    v["device_side"] = dm
        .device_side
        .as_ref()
        .map_or(Value::Null, device_side_json);
    v
}

fn state_counts_json(c: &WgStateCounts) -> Value {
    json!({
        "total": c.total(),
        "connected": c.connected,
        "idle": c.idle,
        "stale": c.stale,
        "never": c.never,
        "unknown": c.unknown,
    })
}

/// Tunnel health summary + thresholds of the states.
pub(crate) fn summary_json(sum: &WgHealthSummary) -> Value {
    json!({
        "thresholds": {
            "connected_secs": CONNECTED_SECS,
            "stale_secs": STALE_SECS,
            "hub_silent_secs": HUB_SILENT_SECS,
        },
        "totals": {
            "device": state_counts_json(&sum.device),
            "client": state_counts_json(&sum.client),
        },
        "networks": sum.networks.iter().map(|n| json!({
            "id": n.id,
            "name": n.name,
            "hub_id": n.hub_id,
            "hub_name": n.hub_name,
            "device": state_counts_json(&n.device),
            "client": state_counts_json(&n.client),
        })).collect::<Vec<_>>(),
    })
}

/// Client key pair made here -> all secrets, shown in that one response only.
pub(crate) struct MadeKey {
    pub(crate) private_key: Zeroizing<String>,
    /// wg-quick config file, incl. private key.
    pub(crate) config: Zeroizing<String>,
    /// File name to save `config` as.
    pub(crate) config_filename: String,
    /// `config` as QR code (SVG).
    pub(crate) qr_svg: Zeroizing<String>,
}

/// Answer of creation, re-key or change: member + (client, key pair made here) private key,
/// config file, QR code + pre-shared key made for the request (each null otherwise).
/// Only time these exist outside this function.
pub(crate) fn member_created_json(
    m: &WgMember,
    made: Option<&MadeKey>,
    preshared_key: Option<&str>,
) -> Value {
    let mut v = member_json(m);
    v["private_key"] = json!(made.map(|k| k.private_key.as_str()));
    v["config"] = json!(made.map(|k| k.config.as_str()));
    v["config_filename"] = json!(made.map(|k| k.config_filename.as_str()));
    v["qr_svg"] = json!(made.map(|k| k.qr_svg.as_str()));
    v["preshared_key"] = json!(preshared_key);
    v
}

/// Pre-shared key made for a member: text form (shown once) + sealed for the member (stored).
struct MadePsk {
    text: Zeroizing<String>,
    sealed: (Vec<u8>, Vec<u8>),
}

/// New pre-shared key for `member`, sealed with the secrets key.
/// No secrets key -> 422; system cannot make or seal one -> 500.
fn new_psk(s: &AppState, member: Uuid) -> Result<MadePsk, ApiError> {
    let Some(secrets) = s.config.secrets.as_deref() else {
        return Err(unprocessable(
            "a pre-shared key needs the server's secrets key (--secrets-key)",
        ));
    };
    let failed = |what: &str| {
        tracing::error!(what, "making a WireGuard pre-shared key failed");
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not make a pre-shared key".into(),
        )
    };
    let bytes = generate_preshared_key().map_err(|_| failed("random"))?;
    let sealed = secrets
        .seal_wg_psk(member, &bytes[..])
        .map_err(|_| failed("seal"))?;
    Ok(MadePsk {
        text: key_text(&bytes),
        sealed,
    })
}

/// Answer of `GET /wireguard/members/{id}/config`.
pub(crate) fn client_config_json(config: &str, config_filename: &str) -> Value {
    json!({ "config": config, "config_filename": config_filename })
}

/// 500 for a value the DB CHECKs keep in range.
fn out_of_range(what: &str) -> ApiError {
    tracing::error!(what, "a stored WireGuard value is out of range");
    ApiError(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("the stored {what} is out of range"),
    )
}

/// Hub public key, needed by a config file. 409 until the hub process reported it.
fn hub_key(network: &WgNetwork) -> Result<&str, ApiError> {
    network.hub_public_key.as_deref().ok_or_else(|| {
        ApiError(
            StatusCode::CONFLICT,
            "the hub has not reported its public key yet: start dhonomos-wg-hub on it first".into(),
        )
    })
}

/// wg-quick config + file name of a client member.
/// Client reaches the whole network (Q6): tunnel prefix, then site prefixes of live members
/// by prefix.
async fn client_config(
    s: &AppState,
    network: &WgNetwork,
    member: &WgMember,
    private_key: Option<&str>,
    preshared_key: Option<&str>,
) -> Result<(Zeroizing<String>, String), ApiError> {
    let hub_public_key = hub_key(network)?;
    let mut allowed_ips = vec![network.ipv4_prefix];
    allowed_ips.extend(s.store.wg_network_site_prefixes(network.id).await?);
    let config = render_client_config(&ClientConfig {
        network_name: &network.name,
        member_name: &member.name,
        private_key,
        address: member.address,
        mtu: u16::try_from(network.mtu).map_err(|_| out_of_range("mtu"))?,
        hub_public_key,
        preshared_key,
        preshared_key_enabled: member.preshared_key_enabled,
        endpoint_host: &network.hub_endpoint_host,
        listen_port: u16::try_from(network.listen_port).map_err(|_| out_of_range("listen_port"))?,
        allowed_ips: &allowed_ips,
        persistent_keepalive: u16::try_from(network.persistent_keepalive)
            .map_err(|_| out_of_range("persistent_keepalive"))?,
    });
    Ok((Zeroizing::new(config), config_file_name(&network.name)))
}

/// Secrets of a key pair made here for `member`: private key, config file with it (+ the
/// pre-shared key made for the same request), that file as QR code.
async fn made_key(
    s: &AppState,
    network: &WgNetwork,
    member: &WgMember,
    pair: KeyPair,
    preshared_key: Option<&str>,
) -> Result<MadeKey, ApiError> {
    let (config, config_filename) = client_config(
        s,
        network,
        member,
        Some(pair.private.as_str()),
        preshared_key,
    )
    .await?;
    // QR code: max ~2,300 chars at this error correction. Config ~300 + max 20 per site
    // prefix in the network -> over 100 site prefixes to reach it; realistic networks far below.
    // Error answered + logged without the config.
    let qr_svg = crate::totp::qr_svg(&config).map_err(|_| {
        tracing::error!("a WireGuard client configuration is too long for a QR code");
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the configuration is too long for a QR code".into(),
        )
    })?;
    Ok(MadeKey {
        private_key: pair.private,
        config,
        config_filename,
        qr_svg: Zeroizing::new(qr_svg),
    })
}

/// New key pair. System cannot make one -> 500.
fn new_keypair() -> Result<KeyPair, ApiError> {
    generate_keypair().map_err(|e| {
        tracing::error!(error = %e, "making a WireGuard key pair failed");
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not make a key pair".into(),
        )
    })
}

/// Audit records for client members revoked by a change of the owner account.
pub(crate) async fn audit_revoked_clients(s: &AppState, revoked: &[RevokedClient]) {
    for r in revoked {
        audit(
            s,
            "wireguard.member.revoke",
            "wg_member",
            r.id,
            json!({ "network": r.network_id, "name": r.name, "reason": r.reason,
                    "automatic": true }),
        )
        .await;
    }
}

// --- waking devices -----------------------------------------------------------------------

/// Max devices one change wakes; others apply it at their next periodic Inform.
const WAKE_LIMIT: usize = 100;
/// Max CRs of one change in flight at once.
const WAKE_CONCURRENCY: usize = 8;

/// Devices to wake: ascending, each once, max [`WAKE_LIMIT`]; + count left out.
fn wake_selection(mut devices: Vec<Uuid>) -> (Vec<Uuid>, usize) {
    devices.sort_unstable();
    devices.dedup();
    let skipped = devices.len().saturating_sub(WAKE_LIMIT);
    devices.truncate(WAKE_LIMIT);
    (devices, skipped)
}

/// CR to `devices` in background -> they apply a WireGuard config change now, not at next
/// periodic Inform. Response does not wait; 1 log line when all done. No waker -> nothing.
fn wake_devices(s: &Arc<AppState>, devices: Vec<Uuid>, why: &'static str) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use dhonomos_core::WakeOutcome;
    use futures_util::StreamExt as _;

    let Some(waker) = s.config.waker.clone() else {
        return;
    };
    if devices.is_empty() {
        return;
    }
    let (devices, skipped) = wake_selection(devices);
    if skipped > 0 {
        tracing::info!(
            why,
            skipped,
            limit = WAKE_LIMIT,
            "too many devices to wake for one WireGuard change: the others apply it at their next periodic Inform"
        );
    }
    tokio::spawn(async move {
        let total = devices.len();
        let (sent, no_url, failed, other) = (
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
        );
        futures_util::stream::iter(devices)
            .for_each_concurrent(WAKE_CONCURRENCY, |device| {
                let (waker, sent, no_url, failed, other) =
                    (&waker, &sent, &no_url, &failed, &other);
                async move {
                    let counter = match waker.wake(device).await {
                        WakeOutcome::Sent | WakeOutcome::SentUdp | WakeOutcome::SentXmpp => sent,
                        WakeOutcome::NoUrl => no_url,
                        WakeOutcome::Failed(_) => failed,
                        WakeOutcome::UspSending | WakeOutcome::UspOffline => other,
                    };
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            })
            .await;
        tracing::info!(
            why,
            devices = total,
            sent = sent.into_inner(),
            no_url = no_url.into_inner(),
            failed = failed.into_inner(),
            other = other.into_inner(),
            "woke devices after a WireGuard change"
        );
    });
}

/// The device, if one of the tenant's CWMP devices (USP Agents need no wake).
async fn cwmp_device(s: &AppState, device: Option<Uuid>) -> Option<Uuid> {
    let id = device?;
    match s.store.get_device(id).await {
        Ok(d) => d
            .filter(|d| d.tenant_id == s.config.tenant_id && d.protocol == "cwmp")
            .map(|d| d.id),
        Err(e) => {
            tracing::warn!(error = %e, device = %id, "looking up a device to wake failed");
            None
        }
    }
}

/// Wake CWMP devices of the live device members of `networks` + `also` (a device that just
/// left one of them). Failed lookup -> logged, not answered: change is stored, devices apply
/// it at next periodic Inform.
async fn wake_networks(
    s: &Arc<AppState>,
    networks: &[Uuid],
    also: Option<Uuid>,
    why: &'static str,
) {
    if s.config.waker.is_none() {
        return;
    }
    let mut devices = match s
        .store
        .wg_cwmp_devices_of_networks(s.config.tenant_id, networks)
        .await
    {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, why, "looking up the devices to wake failed");
            Vec::new()
        }
    };
    devices.extend(also);
    wake_devices(s, devices, why);
}

/// Wake CWMP devices of the live device members of all networks of a hub.
pub(crate) async fn wake_hub(s: &Arc<AppState>, hub_id: Uuid, why: &'static str) {
    if s.config.waker.is_none() {
        return;
    }
    let networks: Vec<Uuid> = match s
        .store
        .list_wg_networks(s.config.tenant_id, &EVERYTHING)
        .await
    {
        Ok(list) => list
            .into_iter()
            .filter(|n| n.hub_id == hub_id)
            .map(|n| n.id)
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, why, "looking up the networks of the hub failed");
            return;
        }
    };
    if !networks.is_empty() {
        wake_networks(s, &networks, None, why).await;
    }
}

// --- summary ------------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/wireguard/summary",
    tag = "wireguard",
    operation_id = "wg_summary",
    summary = "WireGuard tunnel health",
    description = "How many live members are in each tunnel state, in all and per network (every network, by name), as of the database's clock. A member is `connected` with a handshake within `connected_secs`, `idle` up to `stale_secs`, `stale` older, `never` without a handshake or a report about it, and `unknown` when its hub has not reported for more than `hub_silent_secs` (this wins). Counts cover the members the caller may see: device members inside the caller's device scope, and the caller's own clients (all of them for an admin).",
    responses(
        (status = 200, description = "The summary", body = crate::schemas::WgSummary),
    ),
)]
async fn summary(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
) -> Result<Json<Value>, ApiError> {
    let sum = s
        .store
        .wg_health_summary(s.config.tenant_id, &visibility(&caller))
        .await?;
    Ok(Json(summary_json(&sum)))
}

// --- hubs ---------------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/wireguard/hubs",
    tag = "wireguard",
    operation_id = "list_wg_hubs",
    summary = "WireGuard hubs",
    responses(
        (status = 200, description = "The hubs by name", body = crate::schemas::WgHubList),
    ),
)]
async fn list_hubs(State(s): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let hubs = s.store.list_wg_hubs(s.config.tenant_id).await?;
    Ok(Json(
        json!({ "items": hubs.iter().map(hub_json).collect::<Vec<_>>() }),
    ))
}

/// Body of `POST /wireguard/hubs`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct NewHub {
    /// 1-64 characters; unique.
    name: String,
    /// Host name or IP address members dial (no scheme or port).
    endpoint_host: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/wireguard/hubs",
    tag = "wireguard",
    operation_id = "create_wg_hub",
    summary = "Add a hub",
    description = "A hub is a WireGuard endpoint Dhonomos manages. Its public key stays null until the hub process reports it.",
    request_body = NewHub,
    responses(
        (status = 201, description = "The hub", body = crate::schemas::WgHub),
        (status = 409, description = "The name is taken"),
        (status = 422, description = "Invalid body, name or endpoint host"),
    ),
)]
async fn create_hub(
    State(s): State<Arc<AppState>>,
    body: Result<Json<NewHub>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    let name = clean_name("name", &req.name)?;
    let host = clean_endpoint_host(&req.endpoint_host)?;
    let hub = s
        .store
        .create_wg_hub(s.config.tenant_id, &name, &host)
        .await?
        .map_err(refusal)?;
    audit(
        &s,
        "wireguard.hub.create",
        "wg_hub",
        hub.id,
        json!({ "name": hub.name, "endpoint_host": hub.endpoint_host }),
    )
    .await;
    Ok((StatusCode::CREATED, Json(hub_json(&hub))))
}

async fn hub_of(s: &AppState, id: Uuid) -> Result<WgHub, ApiError> {
    s.store
        .get_wg_hub(s.config.tenant_id, id)
        .await?
        .ok_or_else(|| not_found("hub"))
}

#[utoipa::path(
    get,
    path = "/api/v1/wireguard/hubs/{id}",
    tag = "wireguard",
    operation_id = "get_wg_hub",
    summary = "A hub",
    params(("id" = Uuid, Path, description = "Hub ID")),
    responses(
        (status = 200, description = "The hub", body = crate::schemas::WgHub),
        (status = 404, description = "Unknown hub"),
    ),
)]
async fn get_hub(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(hub_json(&hub_of(&s, id).await?)))
}

/// Body of `PATCH /wireguard/hubs/{id}`; fields left out stay.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct HubChange {
    /// 1-64 characters; unique.
    #[serde(default)]
    name: Option<String>,
    /// Host name or IP address members dial.
    #[serde(default)]
    endpoint_host: Option<String>,
}

#[utoipa::path(
    patch,
    path = "/api/v1/wireguard/hubs/{id}",
    tag = "wireguard",
    operation_id = "update_wg_hub",
    summary = "Rename a hub or change its endpoint",
    description = "Devices are configured again with a new `endpoint_host`: the CWMP devices of the hub's networks are woken with a connection request (at most 100 per change; the others at their next periodic Inform), and USP Agents are reconciled while connected.",
    params(("id" = Uuid, Path, description = "Hub ID")),
    request_body = HubChange,
    responses(
        (status = 200, description = "The hub", body = crate::schemas::WgHub),
        (status = 404, description = "Unknown hub"),
        (status = 409, description = "The name is taken"),
        (status = 422, description = "Invalid body, name or endpoint host"),
    ),
)]
async fn update_hub(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    body: Result<Json<HubChange>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    let name = req
        .name
        .as_deref()
        .map(|n| clean_name("name", n))
        .transpose()?;
    let host = req
        .endpoint_host
        .as_deref()
        .map(clean_endpoint_host)
        .transpose()?;
    let before = match host {
        Some(_) => Some(hub_of(&s, id).await?.endpoint_host),
        None => None,
    };
    let hub = s
        .store
        .update_wg_hub(s.config.tenant_id, id, name.as_deref(), host.as_deref())
        .await?
        .map_err(refusal)?;
    audit(
        &s,
        "wireguard.hub.update",
        "wg_hub",
        id,
        json!({ "name": name, "endpoint_host": host }),
    )
    .await;
    if before.is_some_and(|b| b != hub.endpoint_host) {
        wake_hub(&s, id, "hub endpoint changed").await;
    }
    Ok(Json(hub_json(&hub)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/wireguard/hubs/{id}",
    tag = "wireguard",
    operation_id = "delete_wg_hub",
    summary = "Delete a hub",
    params(("id" = Uuid, Path, description = "Hub ID")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Unknown hub"),
        (status = 409, description = "The hub still has networks"),
    ),
)]
async fn delete_hub(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let hub = hub_of(&s, id).await?;
    s.store
        .delete_wg_hub(s.config.tenant_id, id)
        .await?
        .map_err(refusal)?;
    audit(
        &s,
        "wireguard.hub.delete",
        "wg_hub",
        id,
        json!({ "name": hub.name }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Chars of a hub token kept to recognise it (`dwh_` + 8).
const HUB_TOKEN_SHOWN: usize = 12;

#[utoipa::path(
    post,
    path = "/api/v1/wireguard/hubs/{id}/token",
    tag = "wireguard",
    operation_id = "issue_wg_hub_token",
    summary = "Issue a hub token",
    description = "The hub process (`dhonomos-wg-hub`) authenticates with this token (`Authorization: Bearer dwh_...`). It is shown only in this response: the server keeps its SHA-256 and the first 12 characters (`token_prefix`). Issuing a token again replaces the old one at once.",
    params(("id" = Uuid, Path, description = "Hub ID")),
    responses(
        (status = 201, description = "The token, shown once, and the hub", body = crate::schemas::WgHubToken),
        (status = 404, description = "Unknown hub"),
    ),
)]
async fn issue_hub_token(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let token = format!("{HUB_TOKEN_PREFIX}{}", random_token()?);
    let prefix: String = token.chars().take(HUB_TOKEN_SHOWN).collect();
    let replaced = s
        .store
        .set_wg_hub_token(s.config.tenant_id, id, &sha256(&token), &prefix)
        .await?
        .ok_or_else(|| not_found("hub"))?;
    // Token itself never in an audit record.
    audit(
        &s,
        "wireguard.hub.token",
        "wg_hub",
        id,
        json!({ "token_prefix": prefix, "replaced": replaced }),
    )
    .await;
    let hub = hub_of(&s, id).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "token": token, "token_prefix": prefix, "hub": hub_json(&hub) })),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/wireguard/hubs/{id}/token",
    tag = "wireguard",
    operation_id = "revoke_wg_hub_token",
    summary = "Revoke a hub token",
    description = "The hub process can no longer call the server until a new token is issued. Revoking when there is no token is not an error.",
    params(("id" = Uuid, Path, description = "Hub ID")),
    responses(
        (status = 204, description = "Revoked"),
        (status = 404, description = "Unknown hub"),
    ),
)]
async fn revoke_hub_token(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    if !s.store.clear_wg_hub_token(s.config.tenant_id, id).await? {
        return Err(not_found("hub"));
    }
    audit(&s, "wireguard.hub.token_revoke", "wg_hub", id, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

// --- networks -----------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/wireguard/networks",
    tag = "wireguard",
    operation_id = "list_wg_networks",
    summary = "WireGuard networks",
    description = "Member counts cover the members the caller may see: device members inside the caller's device scope, and the caller's own clients (all of them for an admin).",
    responses(
        (status = 200, description = "The networks by name", body = crate::schemas::WgNetworkList),
    ),
)]
async fn list_networks(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
) -> Result<Json<Value>, ApiError> {
    let networks = s
        .store
        .list_wg_networks(s.config.tenant_id, &visibility(&caller))
        .await?;
    Ok(Json(
        json!({ "items": networks.iter().map(network_json).collect::<Vec<_>>() }),
    ))
}

async fn network_of(s: &AppState, caller: &Principal, id: Uuid) -> Result<WgNetwork, ApiError> {
    s.store
        .get_wg_network(s.config.tenant_id, id, &visibility(caller))
        .await?
        .ok_or_else(|| not_found("network"))
}

/// Body of `POST /wireguard/networks`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct NewNetwork {
    /// Hub the network runs on.
    hub_id: Uuid,
    /// 1-64 characters; unique.
    name: String,
    /// Tunnel prefix size taken from the address pool, 16-29 (default 24): lowest free block
    /// overlapping no other network. Not with `ipv4_prefix`.
    #[serde(default)]
    prefix_len: Option<i64>,
    /// Tunnel prefix, e.g. `10.77.4.0/24` (network address, length 16-29). May lie outside
    /// the address pool; must overlap no other network. Not with `prefix_len`.
    #[serde(default)]
    ipv4_prefix: Option<String>,
    /// Hub UDP port for this network, 1-65535 (default: lowest free one from 51820 on the hub).
    #[serde(default)]
    listen_port: Option<i64>,
    /// Tunnel MTU, 1280-1500 (default 1420).
    #[serde(default)]
    mtu: Option<i64>,
    /// Keepalive seconds members send, 0-65535 (default 25; 0 turns it off).
    #[serde(default)]
    persistent_keepalive: Option<i64>,
}

#[utoipa::path(
    post,
    path = "/api/v1/wireguard/networks",
    tag = "wireguard",
    operation_id = "create_wg_network",
    summary = "Add a network",
    description = "A network is one overlay: a tunnel prefix and a hub interface. The hub takes the first host of the prefix (`hub_address`) and members get the lowest free host after it. Without `ipv4_prefix` the prefix is cut from the server's address pool (`--wg-address-pool`, default 10.77.0.0/16).",
    request_body = NewNetwork,
    responses(
        (status = 201, description = "The network", body = crate::schemas::WgNetwork),
        (status = 404, description = "Unknown hub"),
        (status = 409, description = "The name or hub port is taken, the prefix overlaps another network, or the address pool has no free block of that size"),
        (status = 422, description = "Invalid body or value"),
    ),
)]
async fn create_network(
    State(s): State<Arc<AppState>>,
    body: Result<Json<NewNetwork>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    let name = clean_name("name", &req.name)?;
    let prefix = match (req.prefix_len, &req.ipv4_prefix) {
        (Some(_), Some(_)) => {
            return Err(unprocessable(
                "give either prefix_len or ipv4_prefix, not both",
            ));
        }
        (_, Some(p)) => WgPrefixChoice::Explicit(prefix_of("ipv4_prefix", p)?),
        (len, None) => {
            let len = in_range(
                "prefix_len",
                len.unwrap_or(i64::from(DEFAULT_NETWORK_LEN)),
                i64::from(NETWORK_MIN_LEN),
                i64::from(NETWORK_MAX_LEN),
            )?;
            WgPrefixChoice::Auto {
                len: u8::try_from(len).unwrap_or(DEFAULT_NETWORK_LEN),
                pool: s.config.wireguard.get().address_pool,
            }
        }
    };
    let new = NewWgNetwork {
        hub_id: req.hub_id,
        name,
        prefix,
        listen_port: req
            .listen_port
            .map(|p| in_range("listen_port", p, 1, 65535))
            .transpose()?
            .and_then(|p| u16::try_from(p).ok()),
        mtu: in_range("mtu", req.mtu.unwrap_or(DEFAULT_MTU), 1280, 1500)?,
        persistent_keepalive: in_range(
            "persistent_keepalive",
            req.persistent_keepalive.unwrap_or(DEFAULT_KEEPALIVE),
            0,
            65535,
        )?,
    };
    let network = s
        .store
        .create_wg_network(s.config.tenant_id, &new)
        .await?
        .map_err(refusal)?;
    audit(
        &s,
        "wireguard.network.create",
        "wg_network",
        network.id,
        json!({ "name": network.name, "hub": network.hub_id,
                "ipv4_prefix": network.ipv4_prefix.to_string(),
                "listen_port": network.listen_port, "mtu": network.mtu,
                "persistent_keepalive": network.persistent_keepalive }),
    )
    .await;
    Ok((StatusCode::CREATED, Json(network_json(&network))))
}

#[utoipa::path(
    get,
    path = "/api/v1/wireguard/networks/{id}",
    tag = "wireguard",
    operation_id = "get_wg_network",
    summary = "A network",
    params(("id" = Uuid, Path, description = "Network ID")),
    responses(
        (status = 200, description = "The network with its hub and member counts", body = crate::schemas::WgNetwork),
        (status = 404, description = "Unknown network"),
    ),
)]
async fn get_network(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(network_json(&network_of(&s, &caller, id).await?)))
}

/// Body of `PATCH /wireguard/networks/{id}`; fields left out stay.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct NetworkChange {
    /// 1-64 characters; unique.
    #[serde(default)]
    name: Option<String>,
    /// New tunnel prefix (network address, length 16-29). 409 while the network has members
    /// not revoked: all would need new configuration.
    #[serde(default)]
    ipv4_prefix: Option<String>,
    /// Hub UDP port, 1-65535.
    #[serde(default)]
    listen_port: Option<i64>,
    /// Tunnel MTU, 1280-1500.
    #[serde(default)]
    mtu: Option<i64>,
    /// Keepalive seconds, 0-65535.
    #[serde(default)]
    persistent_keepalive: Option<i64>,
}

#[utoipa::path(
    patch,
    path = "/api/v1/wireguard/networks/{id}",
    tag = "wireguard",
    operation_id = "update_wg_network",
    summary = "Change a network",
    description = "Devices are configured again when the tunnel prefix, port, MTU or keepalive change: the network's CWMP devices are woken with a connection request (at most 100 per change; the others at their next periodic Inform), and USP Agents are reconciled while connected. A new name wakes nobody.",
    params(("id" = Uuid, Path, description = "Network ID")),
    request_body = NetworkChange,
    responses(
        (status = 200, description = "The network", body = crate::schemas::WgNetwork),
        (status = 404, description = "Unknown network"),
        (status = 409, description = "The name or port is taken; the new prefix overlaps another network; or the network has members that are not revoked and a new prefix was asked for"),
        (status = 422, description = "Invalid body or value"),
    ),
)]
async fn update_network(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    body: Result<Json<NetworkChange>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    let patch = WgNetworkPatch {
        name: req
            .name
            .as_deref()
            .map(|n| clean_name("name", n))
            .transpose()?,
        ipv4_prefix: req
            .ipv4_prefix
            .as_deref()
            .map(|p| prefix_of("ipv4_prefix", p))
            .transpose()?,
        listen_port: req
            .listen_port
            .map(|p| in_range("listen_port", p, 1, 65535))
            .transpose()?
            .and_then(|p| u16::try_from(p).ok()),
        mtu: req
            .mtu
            .map(|m| in_range("mtu", m, 1280, 1500))
            .transpose()?,
        persistent_keepalive: req
            .persistent_keepalive
            .map(|k| in_range("persistent_keepalive", k, 0, 65535))
            .transpose()?,
    };
    let before = s
        .store
        .get_wg_network(s.config.tenant_id, id, &EVERYTHING)
        .await?
        .ok_or_else(|| not_found("network"))?;
    let after = s
        .store
        .update_wg_network(s.config.tenant_id, id, &patch)
        .await?
        .map_err(refusal)?;
    audit(
        &s,
        "wireguard.network.update",
        "wg_network",
        id,
        json!({ "name": patch.name,
                "ipv4_prefix": patch.ipv4_prefix.map(|p| p.to_string()),
                "listen_port": patch.listen_port, "mtu": patch.mtu,
                "persistent_keepalive": patch.persistent_keepalive }),
    )
    .await;
    // New name -> no device config change.
    let configured = |n: &WgNetwork| (n.ipv4_prefix, n.listen_port, n.mtu, n.persistent_keepalive);
    if configured(&before) != configured(&after) {
        wake_networks(&s, &[id], None, "network changed").await;
    }
    // Admin may change the network -> sees all its members in the counts.
    let network = s
        .store
        .get_wg_network(s.config.tenant_id, id, &EVERYTHING)
        .await?
        .ok_or_else(|| not_found("network"))?;
    Ok(Json(network_json(&network)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/wireguard/networks/{id}",
    tag = "wireguard",
    operation_id = "delete_wg_network",
    summary = "Delete a network",
    description = "Its members and their site prefixes are deleted with it (their rows, revoked ones too); the audit record says how many live members went. Devices are woken so that they remove it: the CWMP devices of its live device members get a connection request (at most 100; the others at their next periodic Inform), and USP Agents are reconciled while connected.",
    params(("id" = Uuid, Path, description = "Network ID")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Unknown network"),
    ),
)]
async fn delete_network(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let network = s
        .store
        .get_wg_network(s.config.tenant_id, id, &EVERYTHING)
        .await?
        .ok_or_else(|| not_found("network"))?;
    // Read before members are deleted: these devices must remove the network.
    let devices = if s.config.waker.is_some() {
        s.store
            .wg_cwmp_devices_of_networks(s.config.tenant_id, &[id])
            .await?
    } else {
        Vec::new()
    };
    let removed = s
        .store
        .delete_wg_network(s.config.tenant_id, id)
        .await?
        .map_err(refusal)?;
    audit(
        &s,
        "wireguard.network.delete",
        "wg_network",
        id,
        json!({ "name": network.name, "ipv4_prefix": network.ipv4_prefix.to_string(),
                "members_removed": removed }),
    )
    .await;
    wake_devices(&s, devices, "network deleted");
    Ok(StatusCode::NO_CONTENT)
}

// --- members ------------------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct MemberQuery {
    /// Also list revoked members (default true).
    #[serde(default = "crate::yes")]
    include_revoked: bool,
    /// Page size, 1-1000 (default 100).
    #[serde(default = "crate::default_limit")]
    limit: i64,
    /// Members to skip.
    #[serde(default)]
    offset: i64,
}

#[utoipa::path(
    get,
    path = "/api/v1/wireguard/networks/{id}/members",
    tag = "wireguard",
    operation_id = "list_wg_members",
    summary = "The members of a network",
    description = "By address. Device members are listed when their device is inside the caller's device scope; client members when they are the caller's own (an admin sees all). Revoked members keep their rows.",
    params(("id" = Uuid, Path, description = "Network ID"), MemberQuery),
    responses(
        (status = 200, description = "One page", body = crate::schemas::WgMemberPage),
        (status = 404, description = "Unknown network"),
    ),
)]
async fn list_members(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
    Path(id): Path<Uuid>,
    Query(q): Query<MemberQuery>,
) -> Result<Json<Value>, ApiError> {
    let (limit, offset) = Page {
        limit: q.limit,
        offset: q.offset,
    }
    .clamp();
    let (members, total) = s
        .store
        .list_wg_members(
            s.config.tenant_id,
            id,
            &visibility(&caller),
            q.include_revoked,
            limit,
            offset,
        )
        .await?
        .ok_or_else(|| not_found("network"))?;
    Ok(Json(json!({
        "items": members.iter().map(member_json).collect::<Vec<_>>(),
        "total": total,
        "limit": limit,
        "offset": offset,
    })))
}

#[utoipa::path(
    get,
    path = "/api/v1/devices/{id}/wireguard",
    tag = "wireguard",
    operation_id = "list_wg_device_members",
    summary = "The WireGuard memberships of a device",
    description = "The live device members of the device and of its twin (the other record, CWMP or USP, of the same CPE: equal non-empty OUI and serial number), by network name. A twin outside the caller's device scope is left out. `device_side` is what the record that owns the member (the device, or the twin for `via_twin` items) last reported about the network's tunnel, from its stored parameters; queue a `get_parameter_values` task for `Device.WireGuard.` on that record to read it again.",
    params(("id" = Uuid, Path, description = "Device ID")),
    responses(
        (status = 200, description = "The memberships", body = crate::schemas::WgDeviceMemberList),
        (status = 404, description = "Unknown device"),
    ),
)]
async fn device_members(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    device_of(&s, id).await?;
    let members = s
        .store
        .list_wg_device_members(s.config.tenant_id, id, &visibility(&caller))
        .await?;
    Ok(Json(json!({
        "items": members.iter().map(device_member_json).collect::<Vec<_>>(),
    })))
}

async fn member_of(s: &AppState, caller: &Principal, id: Uuid) -> Result<WgMember, ApiError> {
    s.store
        .get_wg_member(s.config.tenant_id, id, &visibility(caller))
        .await?
        .ok_or_else(|| not_found("member"))
}

/// Member kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
enum MemberKind {
    /// A CPE, configured over TR-181.
    Device,
    /// Operator PC or server, gets a configuration file.
    Client,
}

/// LAN prefix behind a device member.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct SitePrefixIn {
    /// E.g. `192.168.10.0/24`: network address, length 8-32; not `0.0.0.0/0`; must not
    /// overlap the network's tunnel prefix or a site prefix of another member of the network.
    prefix: String,
    /// What it is (up to 200 characters).
    #[serde(default)]
    description: String,
}

/// Parse + check the site prefixes of a request.
fn site_prefixes(list: &[SitePrefixIn]) -> Result<Vec<WgSitePrefix>, ApiError> {
    if list.len() > MAX_SITE_PREFIXES {
        return Err(unprocessable(format!(
            "a member has at most {MAX_SITE_PREFIXES} site prefixes"
        )));
    }
    list.iter()
        .map(|p| {
            let description = p.description.trim();
            if description.chars().count() > MAX_DESCRIPTION
                || description.chars().any(char::is_control)
            {
                return Err(unprocessable(format!(
                    "a site prefix description is at most {MAX_DESCRIPTION} characters without control characters"
                )));
            }
            Ok(WgSitePrefix {
                prefix: prefix_of("site prefix", &p.prefix)?,
                description: description.to_owned(),
            })
        })
        .collect()
}

fn site_prefixes_json(list: &[WgSitePrefix]) -> Value {
    json!(
        list.iter()
            .map(|p| p.prefix.to_string())
            .collect::<Vec<_>>()
    )
}

/// Body of `POST /wireguard/networks/{id}/members`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct NewMember {
    /// `device` or `client`.
    kind: MemberKind,
    /// 1-64 characters. Devices default to their serial number or endpoint ID.
    #[serde(default)]
    name: Option<String>,
    /// Device members: the device; must be inside the caller's device scope.
    #[serde(default)]
    device_id: Option<Uuid>,
    /// Device members: where the key pair is made: `device` (on the CPE; default) or `server`
    /// (Dhonomos makes it, sends the private key once, keeps only the public key).
    /// Public key null until the CPE is configured.
    #[serde(default)]
    key_mode: Option<String>,
    /// Use a pre-shared key (default false): made here, stored sealed with the server's
    /// secrets key (422 without `--secrets-key`), returned once as `preshared_key` (also in
    /// a client's `config` when its key pair is made here).
    #[serde(default)]
    preshared_key_enabled: Option<bool>,
    /// Device members: the LAN prefixes behind the device.
    #[serde(default)]
    site_prefixes: Option<Vec<SitePrefixIn>>,
    /// Client members: account that owns the client. Omitted: the caller's own account.
    /// `null`: server client, no account (admins only). Another account: admins only; that
    /// account must be enabled, operator or admin, without a device scope.
    #[serde(default, deserialize_with = "present")]
    #[schema(value_type = Option<Uuid>)]
    user_id: Option<Option<Uuid>>,
    /// Client members: the client's public key (44 chars of base64). Omitted: key pair made,
    /// private key + configuration file + its QR code returned once.
    #[serde(default)]
    public_key: Option<String>,
}

/// Why `user` cannot own client members; `None` if it can (ADR-110 Q6).
fn cannot_own_clients(u: &dhonomos_store::User) -> Option<&'static str> {
    if u.disabled {
        Some("that account is disabled")
    } else if !matches!(u.role.as_str(), "admin" | "operator") {
        Some("clients need an operator or admin account")
    } else if u.scope.is_some() {
        Some("clients need an account without a device scope")
    } else {
        None
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/wireguard/networks/{id}/members",
    tag = "wireguard",
    operation_id = "create_wg_member",
    summary = "Add a member to a network",
    description = "The member gets the lowest free host of the network's tunnel prefix (not the first, which is the hub's, nor an address revoked less than `--wg-address-reuse-delay-hours` ago).\n\n**Device members** need the admin role or an operator whose device scope contains the device. The device is configured automatically; `device_status` tells how far it got. A CWMP device is woken with a connection request to be configured now, and when the member has site prefixes the network's other CWMP devices are too (they route to them; at most 100 per change, the others at their next periodic Inform). USP Agents are reconciled while connected.\n\n**Client members** reach the whole network. An operator without a device scope may add one for their own account; an account with a device scope cannot (403). Admins may add one for another account or, with `user_id: null`, a server client. Without `public_key`, a key pair is made here: the response carries `private_key`, the wg-quick configuration file holding it (`config`, saved as `config_filename`) and that file as a QR code (`qr_svg`) for the WireGuard apps. They are shown only in this response, and stored, logged and audited nowhere; this needs the hub to have reported its public key (409 before). `GET /wireguard/members/{id}/config` gives the configuration again, without the private key. The client is revoked automatically when its account is disabled, deleted, falls below the operator role or gets a device scope.\n\n**Pre-shared keys** (both kinds): with `preshared_key_enabled: true` a pre-shared key is made here and stored sealed with the server's secrets key (422 without `--secrets-key`), because the hub and the device need it again. The response carries it once as `preshared_key` (and in a made client `config`); no other call returns it. A device member's CPE is given it, and the hub uses it for the peer.",
    params(("id" = Uuid, Path, description = "Network ID")),
    request_body = NewMember,
    responses(
        (status = 201, description = "The member; for a client whose key pair was made here, with its private key", body = crate::schemas::WgMemberCreated),
        (status = 403, description = "The caller may not add this member: a scoped account adding a client, a non-admin adding a client for another account or a server client"),
        (status = 404, description = "Unknown network, or a device that does not exist or is outside the caller's scope"),
        (status = 409, description = "The device is a member already, the public key is in use, no address is left, the site prefixes overlap those of the network or its members, or a key pair was to be made and the hub has not reported its public key yet"),
        (status = 422, description = "Invalid body or value, or a pre-shared key without `--secrets-key`"),
    ),
)]
async fn create_member(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
    Path(network_id): Path<Uuid>,
    body: Result<Json<NewMember>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    let network = network_of(&s, &caller, network_id).await?;
    let name = req
        .name
        .as_deref()
        .map(|n| clean_name("name", n))
        .transpose()?;
    let mut pair = None;
    // CWMP device of a device member -> wake after add.
    let mut cwmp = None;
    let id = Uuid::now_v7();
    let psk = match req.preshared_key_enabled {
        Some(true) => Some(new_psk(&s, id)?),
        _ => None,
    };
    let (name, kind) = match req.kind {
        MemberKind::Device => {
            if req.public_key.is_some() || req.user_id.is_some() {
                return Err(unprocessable(
                    "public_key and user_id are for client members: a device member gets its key from the device",
                ));
            }
            let device_id = req
                .device_id
                .ok_or_else(|| unprocessable("device_id is required for a device member"))?;
            let key_mode = req.key_mode.as_deref().unwrap_or("device");
            if !matches!(key_mode, "device" | "server") {
                return Err(unprocessable("key_mode must be device or server"));
            }
            // Device must be inside the caller's scope (else 404).
            let device = device_of(&s, device_id).await?;
            cwmp = (device.protocol == "cwmp").then_some(device.id);
            let name = match name {
                Some(n) => n,
                None => clean_name(
                    "name",
                    device
                        .serial_number
                        .as_deref()
                        .or(device.endpoint_id.as_deref())
                        .unwrap_or(&device.id.to_string()),
                )?,
            };
            (
                name,
                NewWgMemberKind::Device {
                    device_id,
                    key_mode: key_mode.to_owned(),
                },
            )
        }
        MemberKind::Client => {
            if req.device_id.is_some() || req.key_mode.is_some() || req.site_prefixes.is_some() {
                return Err(unprocessable(
                    "device_id, key_mode and site_prefixes are for device members",
                ));
            }
            let name = name.ok_or_else(|| unprocessable("name is required for a client member"))?;
            let owner = client_owner(&s, &caller, req.user_id).await?;
            let public_key = match req.public_key.as_deref() {
                Some(k) => {
                    validate_key(k).map_err(|e| unprocessable(format!("public_key: {e}")))?;
                    k.to_owned()
                }
                None => {
                    // Returned config file needs the hub key.
                    hub_key(&network)?;
                    let made = new_keypair()?;
                    let public = made.public.clone();
                    pair = Some(made);
                    public
                }
            };
            (
                name,
                NewWgMemberKind::Client {
                    user_id: owner,
                    public_key,
                },
            )
        }
    };
    let prefixes = match (&kind, &req.site_prefixes) {
        (NewWgMemberKind::Device { .. }, Some(list)) => site_prefixes(list)?,
        _ => Vec::new(),
    };
    let new = NewWgMember {
        id,
        name,
        kind,
        site_prefixes: prefixes,
        psk: psk.as_ref().map(|p| p.sealed.clone()),
    };
    let delay = time::Duration::try_from(s.config.wireguard.get().address_reuse_delay)
        .unwrap_or(time::Duration::MAX);
    let member = s
        .store
        .create_wg_member(s.config.tenant_id, network.id, &new, delay)
        .await?
        .map_err(refusal)?;
    // Never in an audit record: private key, pre-shared key, configuration.
    audit(
        &s,
        "wireguard.member.create",
        "wg_member",
        member.id,
        json!({ "network": network.id, "kind": member.kind, "name": member.name,
                "address": member.address.to_string(), "device_id": member.device_id,
                "user_id": member.user_id, "public_key": member.public_key,
                "key_mode": member.key_mode,
                "key_pair_made": pair.is_some(),
                "preshared_key": psk.as_ref().map(|_| "made"),
                "site_prefixes": site_prefixes_json(&member.site_prefixes) }),
    )
    .await;
    if member.kind == "device" {
        if member.site_prefixes.is_empty() {
            wake_devices(&s, cwmp.into_iter().collect(), "device member added");
        } else {
            // Others route to its site prefixes -> wake whole network.
            wake_networks(&s, &[network.id], cwmp, "device member added").await;
        }
    }
    let psk_text = psk.as_ref().map(|p| p.text.as_str());
    let made = match pair {
        Some(pair) => Some(made_key(&s, &network, &member, pair, psk_text).await?),
        None => None,
    };
    Ok((
        StatusCode::CREATED,
        Json(member_created_json(&member, made.as_ref(), psk_text)),
    ))
}

/// Owner of the client member the caller asks for (inner `None` = server client).
/// Checks first: caller may make it + owner can have clients.
async fn client_owner(
    s: &AppState,
    caller: &Principal,
    asked: Option<Option<Uuid>>,
) -> Result<Option<Uuid>, ApiError> {
    let admin = caller.role() >= Role::Admin;
    let owner = match asked {
        None => Some(caller.user_id().ok_or_else(|| {
            unprocessable(
                "this caller has no account of its own: give user_id (an account) or null (a server client)",
            )
        })?),
        Some(owner) => owner,
    };
    let Some(owner) = owner else {
        if !admin {
            return Err(forbidden(
                "only admins can add a client that belongs to no account",
            ));
        }
        return Ok(None);
    };
    let own = caller.user_id() == Some(owner);
    if !own && !admin {
        return Err(forbidden(
            "only admins can add a client for another account",
        ));
    }
    if own && caller.scope().is_some() {
        return Err(forbidden(
            "accounts with a device scope cannot add client members",
        ));
    }
    let user = s
        .store
        .get_user(owner)
        .await?
        .filter(|u| u.tenant_id == s.config.tenant_id)
        .ok_or_else(|| unprocessable("user_id does not name an account"))?;
    if let Some(why) = cannot_own_clients(&user) {
        return Err(unprocessable(format!("user_id: {why}")));
    }
    Ok(Some(owner))
}

#[utoipa::path(
    get,
    path = "/api/v1/wireguard/members/{id}",
    tag = "wireguard",
    operation_id = "get_wg_member",
    summary = "A member",
    description = "A private key is never shown here: it exists only in the response that created or re-keyed the client.",
    params(("id" = Uuid, Path, description = "Member ID")),
    responses(
        (status = 200, description = "The member", body = crate::schemas::WgMember),
        (status = 404, description = "Unknown member, a device member outside the caller's device scope, or a client that is not the caller's"),
    ),
)]
async fn get_member(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(member_json(&member_of(&s, &caller, id).await?)))
}

/// Body of `PATCH /wireguard/members/{id}`; fields left out stay.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct MemberChange {
    /// 1-64 characters.
    #[serde(default)]
    name: Option<String>,
    /// Device members: all LAN prefixes behind the device (replace the current ones, atomic).
    #[serde(default)]
    site_prefixes: Option<Vec<SitePrefixIn>>,
    /// `true`: new pre-shared key made (replaces the current one), stored sealed (422 without
    /// `--secrets-key`), returned once as `preshared_key`. `false`: pre-shared key removed.
    #[serde(default)]
    preshared_key_enabled: Option<bool>,
}

#[utoipa::path(
    patch,
    path = "/api/v1/wireguard/members/{id}",
    tag = "wireguard",
    operation_id = "update_wg_member",
    summary = "Rename a member, replace its site prefixes or its pre-shared key",
    description = "The site prefixes are checked together: none may overlap another of the list, the network's tunnel prefix, or a site prefix of another member of the network that is not revoked. A revoked member cannot be changed.\n\n`preshared_key_enabled: true` makes a new pre-shared key (it replaces the one the member has); the response carries it as `preshared_key`, shown only there. `false` removes it. The hub takes the change at once; a client must put the new key in its configuration, a device member's CPE is configured again.\n\nDevices are woken when the site prefixes change (the prefixes, not their descriptions): the network's CWMP devices get a connection request (at most 100 per change; the others at their next periodic Inform), and USP Agents are reconciled while connected. When a device member's pre-shared key changes, its own CWMP device gets one.",
    params(("id" = Uuid, Path, description = "Member ID")),
    request_body = MemberChange,
    responses(
        (status = 200, description = "The member; `preshared_key` when one was made, the other secrets null", body = crate::schemas::WgMemberCreated),
        (status = 404, description = "Unknown member, or not one the caller may see"),
        (status = 409, description = "The member is revoked, or the site prefixes overlap those of the network or its members"),
        (status = 422, description = "Invalid body or value, site prefixes for a client member, or a pre-shared key without `--secrets-key`"),
    ),
)]
async fn update_member(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
    Path(id): Path<Uuid>,
    body: Result<Json<MemberChange>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(req) = body.map_err(|e| unprocessable(e.body_text()))?;
    let current = member_of(&s, &caller, id).await?;
    let name = req
        .name
        .as_deref()
        .map(|n| clean_name("name", n))
        .transpose()?;
    if req.site_prefixes.is_some() && current.kind != "device" {
        return Err(unprocessable("site prefixes are for device members"));
    }
    let prefixes = req
        .site_prefixes
        .as_deref()
        .map(site_prefixes)
        .transpose()?;
    let psk = match req.preshared_key_enabled {
        Some(true) => Some(new_psk(&s, id)?),
        _ => None,
    };
    let psk_change = match req.preshared_key_enabled {
        Some(true) => Some(
            psk.as_ref()
                .map(|p| (p.sealed.0.as_slice(), p.sealed.1.as_slice())),
        ),
        Some(false) => Some(None),
        None => None,
    };
    let member = s
        .store
        .update_wg_member(
            s.config.tenant_id,
            id,
            name.as_deref(),
            prefixes.as_deref(),
            psk_change,
        )
        .await?
        .map_err(refusal)?;
    let psk_audit = match (req.preshared_key_enabled, current.preshared_key_enabled) {
        (Some(true), false) => Some("made"),
        (Some(true), true) => Some("replaced"),
        (Some(false), true) => Some("cleared"),
        _ => None,
    };
    let prefix_set = |m: &WgMember| -> std::collections::BTreeSet<Ipv4Prefix> {
        m.site_prefixes.iter().map(|p| p.prefix).collect()
    };
    let prefixes_changed = prefix_set(&current) != prefix_set(&member);
    audit(
        &s,
        "wireguard.member.update",
        "wg_member",
        id,
        json!({ "network": member.network_id, "name": name,
                "site_prefixes": prefixes.as_deref().map(site_prefixes_json),
                "preshared_key": psk_audit }),
    )
    .await;
    if prefixes_changed {
        wake_networks(&s, &[member.network_id], None, "site prefixes changed").await;
    } else if psk_audit.is_some()
        && member.kind == "device"
        && let Some(device) = cwmp_device(&s, member.device_id).await
    {
        wake_devices(&s, vec![device], "pre-shared key changed");
    }
    Ok(Json(member_created_json(
        &member,
        None,
        psk.as_ref().map(|p| p.text.as_str()),
    )))
}

/// Body of `POST /wireguard/members/{id}/revoke` (optional).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct Revoke {
    /// Why (up to 200 characters).
    #[serde(default)]
    reason: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/wireguard/members/{id}/revoke",
    tag = "wireguard",
    operation_id = "revoke_wg_member",
    summary = "Revoke a member",
    description = "The row stays for the audit trail; the member leaves the hub and the device configuration on their next reconcile. Revoking a revoked member changes nothing (the first reason and time stay). The address is given to another member only after `--wg-address-reuse-delay-hours`.\n\nDevices are woken when a device member is revoked: its own device (to remove the network) and the network's CWMP devices get a connection request (at most 100 per change; the others at their next periodic Inform). USP Agents are reconciled while connected.",
    params(("id" = Uuid, Path, description = "Member ID")),
    request_body(content = Option<Revoke>, description = "Optional: why"),
    responses(
        (status = 200, description = "The revoked member", body = crate::schemas::WgMember),
        (status = 404, description = "Unknown member, or not one the caller may see"),
        (status = 422, description = "Invalid body"),
    ),
)]
async fn revoke_member(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
    Path(id): Path<Uuid>,
    body: Result<Option<Json<Revoke>>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let reason = body
        .map_err(|e| unprocessable(e.body_text()))?
        .and_then(|Json(r)| r.reason)
        .map(|r| r.trim().to_owned())
        .filter(|r| !r.is_empty());
    if let Some(r) = &reason
        && (r.chars().count() > MAX_REASON || r.chars().any(char::is_control))
    {
        return Err(unprocessable(format!(
            "reason is at most {MAX_REASON} characters without control characters"
        )));
    }
    let current = member_of(&s, &caller, id).await?;
    let own = match current.kind.as_str() {
        "device" => cwmp_device(&s, current.device_id).await,
        _ => None,
    };
    let (member, revoked_now) = s
        .store
        .revoke_wg_member(s.config.tenant_id, id, reason.as_deref())
        .await?
        .map_err(refusal)?;
    if revoked_now {
        audit(
            &s,
            "wireguard.member.revoke",
            "wg_member",
            id,
            json!({ "network": member.network_id, "name": member.name, "reason": reason,
                    "automatic": false }),
        )
        .await;
        if member.kind == "device" {
            wake_networks(&s, &[member.network_id], own, "device member revoked").await;
        }
    }
    Ok(Json(member_json(&member)))
}

/// `Ok` if the member is a live client, else error with why not.
fn live_client(m: &WgMember) -> Result<(), ApiError> {
    if m.kind != "client" {
        return Err(unprocessable(
            "device members are configured over TR-181, not with a configuration file",
        ));
    }
    if m.revoked_at.is_some() {
        return Err(refusal(WgRefusal::MemberRevoked));
    }
    Ok(())
}

#[utoipa::path(
    get,
    path = "/api/v1/wireguard/members/{id}/config",
    tag = "wireguard",
    operation_id = "get_wg_member_config",
    summary = "A client's configuration file",
    description = "The wg-quick configuration of a client member: its address, the hub as the peer, and as `AllowedIPs` the tunnel prefix and the site prefixes of every live member of the network. Dhonomos does not keep private keys, so the `PrivateKey` line is a comment to fill in; the configuration with the key and its QR code are only in the response that created or re-keyed the client. The pre-shared key of a member that has one is not shown here either: its `PresharedKey` line is a comment, and the key is only in the response that made it.",
    params(("id" = Uuid, Path, description = "Member ID")),
    responses(
        (status = 200, description = "The configuration without the private key", body = crate::schemas::WgClientConfig),
        (status = 404, description = "Unknown member, or not one the caller may see"),
        (status = 409, description = "The member is revoked, or the hub has not reported its public key yet"),
        (status = 422, description = "A device member: those are configured over TR-181"),
    ),
)]
async fn member_config(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let member = member_of(&s, &caller, id).await?;
    live_client(&member)?;
    let network = network_of(&s, &caller, member.network_id).await?;
    let (config, filename) = client_config(&s, &network, &member, None, None).await?;
    Ok(Json(client_config_json(&config, &filename)))
}

/// Body of `POST /wireguard/members/{id}/rekey` (optional).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct Rekey {
    /// The client's new public key (44 chars of base64). Omitted: key pair made, private
    /// key + configuration file + its QR code returned once.
    #[serde(default)]
    public_key: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/wireguard/members/{id}/rekey",
    tag = "wireguard",
    operation_id = "rekey_wg_member",
    summary = "Give a client a new key",
    description = "Replaces a client member's public key; its address and name stay. The old key stops working as soon as the hub applies the change (about a second when `dhonomos-wg-hub` runs). Without a body or `public_key`, a key pair is made here: the response carries `private_key`, the configuration file holding it (`config`, saved as `config_filename`) and its QR code (`qr_svg`), shown only in this response and stored, logged and audited nowhere; this needs the hub to have reported its public key. With `public_key` those four are null.\n\nA client with a pre-shared key gets a new one too (422 without `--secrets-key`): `preshared_key` in the response, and in `config` when the key pair was made here.",
    params(("id" = Uuid, Path, description = "Member ID")),
    request_body(content = Option<Rekey>, description = "Optional: the new public key"),
    responses(
        (status = 200, description = "The member; with its private key, configuration and QR code when the key pair was made here", body = crate::schemas::WgMemberCreated),
        (status = 404, description = "Unknown member, or not one the caller may see"),
        (status = 409, description = "The member is revoked, the key is used by another member of the network, or a key pair was to be made and the hub has not reported its public key yet"),
        (status = 422, description = "Invalid body or key, a device member, or a client with a pre-shared key without `--secrets-key`"),
    ),
)]
async fn rekey_member(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
    Path(id): Path<Uuid>,
    body: Result<Option<Json<Rekey>>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let given = body
        .map_err(|e| unprocessable(e.body_text()))?
        .and_then(|Json(r)| r.public_key);
    if let Some(k) = &given {
        validate_key(k).map_err(|e| unprocessable(format!("public_key: {e}")))?;
    }
    let current = member_of(&s, &caller, id).await?;
    live_client(&current)?;
    let network = network_of(&s, &caller, current.network_id).await?;
    let psk = if current.preshared_key_enabled {
        Some(new_psk(&s, id)?)
    } else {
        None
    };
    let (public_key, pair) = match given {
        Some(k) => (k, None),
        None => {
            // Check before any change: answer must carry a usable configuration.
            hub_key(&network)?;
            let pair = new_keypair()?;
            (pair.public.clone(), Some(pair))
        }
    };
    let member = s
        .store
        .rekey_wg_client(
            s.config.tenant_id,
            id,
            &public_key,
            psk.as_ref()
                .map(|p| (p.sealed.0.as_slice(), p.sealed.1.as_slice())),
        )
        .await?
        .map_err(refusal)?;
    // Pre-shared key turned off meanwhile -> not replaced.
    let psk = psk.filter(|_| member.preshared_key_enabled);
    // Never in an audit record: private key, pre-shared key, configuration.
    audit(
        &s,
        "wireguard.member.rekey",
        "wg_member",
        id,
        json!({ "network": member.network_id, "name": member.name,
                "old_public_key": current.public_key, "public_key": member.public_key,
                "key_pair_made": pair.is_some(),
                "preshared_key": psk.as_ref().map(|_| "replaced") }),
    )
    .await;
    let psk_text = psk.as_ref().map(|p| p.text.as_str());
    let made = match pair {
        Some(pair) => Some(made_key(&s, &network, &member, pair, psk_text).await?),
        None => None,
    };
    Ok(Json(member_created_json(&member, made.as_ref(), psk_text)))
}

#[utoipa::path(
    post,
    path = "/api/v1/wireguard/members/{id}/rotate-key",
    tag = "wireguard",
    operation_id = "rotate_wg_member_key",
    summary = "Give a device member a new key",
    description = "Asks for a device member's key to be replaced; the member goes back to `pending` and `rotate_requested_at` is set. At the device's next run Dhonomos makes the CPE use a new key and the hub swaps it directly: in server key mode Dhonomos makes a new key pair and sends the private key (kept nowhere); in device key mode it sets the tunnel's `PrivateKey` to the empty string, which makes the firmware make a new key pair, and reads the new public key. The new public key becomes the member's, and the hub drops the old peer and adds the new one, so the tunnel is down for a few seconds. A member with a pre-shared key gets a new one with the new key (made by the run, stored sealed, sent to the CPE and the hub). The request stays until the key really changed: a device that keeps its key leaves the member `blocked` and is tried again later (or at once after another request).\n\nA CWMP device gets a connection request so that this happens now; a USP Agent is reconciled while connected.",
    params(("id" = Uuid, Path, description = "Member ID")),
    responses(
        (status = 202, description = "Requested: the member", body = crate::schemas::WgMember),
        (status = 404, description = "Unknown member, or not one the caller may see"),
        (status = 409, description = "The member is revoked"),
        (status = 422, description = "A client member: re-key it instead"),
    ),
)]
async fn rotate_member_key(
    State(s): State<Arc<AppState>>,
    Extension(caller): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let current = member_of(&s, &caller, id).await?;
    let member = s
        .store
        .request_wg_key_rotation(s.config.tenant_id, id)
        .await?
        .map_err(refusal)?;
    audit(
        &s,
        "wireguard.member.rotate_key",
        "wg_member",
        id,
        json!({ "network": member.network_id, "name": member.name,
                "public_key": current.public_key }),
    )
    .await;
    if let Some(device) = cwmp_device(&s, member.device_id).await {
        wake_devices(&s, vec![device], "device key rotation requested");
    }
    Ok((StatusCode::ACCEPTED, Json(member_json(&member))))
}

#[utoipa::path(
    post,
    path = "/api/v1/wireguard/networks/{id}/rotate-keys",
    tag = "wireguard",
    operation_id = "rotate_wg_network_keys",
    summary = "Give every device member of a network a new key",
    description = "Asks for a new key for every live device member of the network, as `POST /wireguard/members/{id}/rotate-key` does for one (a direct swap at each device's next run, a few seconds without the tunnel; device key mode uses the empty-`PrivateKey` regeneration the firmware supports; each request stays until that member's key changed). Clients are left alone. The network's CWMP devices get a connection request (at most 100; the others at their next periodic Inform); USP Agents are reconciled while connected.",
    params(("id" = Uuid, Path, description = "Network ID")),
    responses(
        (status = 202, description = "Requested: how many members", body = crate::schemas::WgKeyRotations),
        (status = 404, description = "Unknown network"),
    ),
)]
async fn rotate_network_keys(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let requested = s
        .store
        .request_wg_network_key_rotation(s.config.tenant_id, id)
        .await?
        .map_err(refusal)?;
    audit(
        &s,
        "wireguard.network.rotate_keys",
        "wg_network",
        id,
        json!({ "members": requested }),
    )
    .await;
    if requested > 0 {
        wake_networks(&s, &[id], None, "device key rotation requested").await;
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "requested": requested })),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/wireguard/members/{id}",
    tag = "wireguard",
    operation_id = "delete_wg_member",
    summary = "Delete a member for good",
    description = "Unlike revoking, this removes the row and its site prefixes.\n\nDevices are woken when a device member is deleted: its own device (to remove the network) and the network's CWMP devices get a connection request (at most 100 per change; the others at their next periodic Inform). USP Agents are reconciled while connected.",
    params(("id" = Uuid, Path, description = "Member ID")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Unknown member"),
    ),
)]
async fn delete_member(
    State(s): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let member = s
        .store
        .get_wg_member(s.config.tenant_id, id, &EVERYTHING)
        .await?
        .ok_or_else(|| not_found("member"))?;
    let own = match member.kind.as_str() {
        "device" => cwmp_device(&s, member.device_id).await,
        _ => None,
    };
    s.store
        .delete_wg_member(s.config.tenant_id, id)
        .await?
        .map_err(refusal)?;
    audit(
        &s,
        "wireguard.member.delete",
        "wg_member",
        id,
        json!({ "network": member.network_id, "kind": member.kind, "name": member.name,
                "address": member.address.to_string(),
                "was_revoked": member.revoked_at.is_some() }),
    )
    .await;
    if member.kind == "device" {
        wake_networks(&s, &[member.network_id], own, "device member deleted").await;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn endpoint_hosts() {
        for ok in [
            "hub.example.org",
            "hub1",
            "Hub-1.Example.ORG",
            "203.0.113.7",
            "2001:db8::1",
            "a.b.c.d.e.f",
        ] {
            assert!(clean_endpoint_host(ok).is_ok(), "{ok}");
        }
        assert_eq!(
            clean_endpoint_host(" Hub.Example.org ").unwrap(),
            "hub.example.org"
        );
        // Addresses keep their form.
        assert_eq!(clean_endpoint_host("2001:db8::1").unwrap(), "2001:db8::1");
        for bad in [
            "",
            " ",
            "https://hub.example.org",
            "hub.example.org:51820",
            "[2001:db8::1]",
            "203.0.113.7:51820",
            "999.1.1.1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "-hub.example.org",
            "hub-.example.org",
            "hub..example.org",
            "hub.example.org.",
            "hub example.org",
            "hub_1.example.org",
            &"a".repeat(64),
            &format!("{}.org", "a.".repeat(130)),
        ] {
            assert!(clean_endpoint_host(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn names_are_trimmed_and_limited() {
        assert_eq!(clean_name("name", "  lab ").unwrap(), "lab");
        assert!(clean_name("name", "").is_err());
        assert!(clean_name("name", "   ").is_err());
        assert!(clean_name("name", "a\nb").is_err());
        assert!(clean_name("name", &"x".repeat(65)).is_err());
        assert!(clean_name("name", &"x".repeat(64)).is_ok());
        assert!(clean_name("name", &"é".repeat(64)).is_ok());
    }

    #[test]
    fn numbers_are_range_checked() {
        assert_eq!(in_range("mtu", 1420, 1280, 1500).unwrap(), 1420);
        assert!(in_range("mtu", 1279, 1280, 1500).is_err());
        assert!(in_range("mtu", 1501, 1280, 1500).is_err());
        assert!(in_range("port", i64::MAX, 1, 65535).is_err());
        assert!(in_range("port", -1, 1, 65535).is_err());
        assert_eq!(in_range("keepalive", 0, 0, 65535).unwrap(), 0);
    }

    #[test]
    fn devices_to_wake_are_sorted_distinct_and_limited() {
        let ids: Vec<Uuid> = (0..WAKE_LIMIT as u128 + 20).map(Uuid::from_u128).collect();
        let (few, skipped) = wake_selection(vec![ids[2], ids[0], ids[2], ids[1], ids[0]]);
        assert_eq!(few, [ids[0], ids[1], ids[2]]);
        assert_eq!(skipped, 0);
        assert_eq!(wake_selection(Vec::new()), (Vec::new(), 0));
        // Duplicates not counted against the limit; lowest IDs kept.
        let mut many: Vec<Uuid> = ids.iter().rev().copied().collect();
        many.extend_from_slice(&ids[..50]);
        let (kept, skipped) = wake_selection(many);
        assert_eq!(kept, ids[..WAKE_LIMIT]);
        assert_eq!(skipped, 20);
        let (kept, skipped) = wake_selection(ids[..WAKE_LIMIT].to_vec());
        assert_eq!((kept.len(), skipped), (WAKE_LIMIT, 0));
    }

    #[test]
    fn the_default_pool_is_valid() {
        let c = WireguardConfig::default();
        assert_eq!(c.address_pool.to_string(), "10.77.0.0/16");
        assert_eq!(c.address_reuse_delay, Duration::from_secs(86400));
        assert!(check_pool(c.address_pool).is_ok());
        assert_eq!(
            WireguardConfig::new(c.address_pool, 1)
                .unwrap()
                .address_reuse_delay,
            Duration::from_secs(3600)
        );
        assert!(WireguardConfig::new("127.0.0.0/8".parse().unwrap(), 24).is_err());
        assert!(WireguardConfig::new("10.0.0.0/30".parse().unwrap(), 24).is_err());
    }
}
