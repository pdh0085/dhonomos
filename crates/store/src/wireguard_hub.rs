//! Hub process (`dhonomos-wg-hub`, ADR-110 stage 2): reads + writes via the server.
//! Token, desired state + revision, public key, peer status.
//!
//! Revision (`wg_hubs.state_revision`) kept by triggers (migrations 0032, 0034, 0036).
//! Bump on: any change of a network or site prefix of the hub, any change of a member
//! field the hub state uses (network, kind, key, address, revocation, PSK).
//! Nothing here bumps it: own hub calls (last seen, status reports, public key) != state.

use std::collections::HashMap;
use std::net::IpAddr;

use dhonomos_wireguard::{
    HubNetwork, HubPeer, HubState, Ipv4Prefix, PeerStatus, hub_address, interface_name,
};
use uuid::Uuid;

use crate::wireguard::WgSealedPsk;
use crate::{Result, Store, StoreError};

/// Hub of a hub token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgHubAuth {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
}

/// Member with status stored by a hub report + the stored values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgReportedPeer {
    pub member_id: Uuid,
    /// `None` = client.
    pub device_id: Option<Uuid>,
    pub network_id: Uuid,
    /// Latest handshake reported (`None` = never).
    pub latest_handshake: Option<time::OffsetDateTime>,
    /// Bytes from the peer, as reported.
    pub rx_bytes: i64,
    /// Bytes to the peer, as reported.
    pub tx_bytes: i64,
}

/// Result of [`Store::report_wg_peer_status`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WgPeerReport {
    /// Entries stored.
    pub accepted: usize,
    pub ignored: usize,
    /// Members with stored status, one per accepted entry.
    pub peers: Vec<WgReportedPeer>,
}

fn decode_error(msg: String) -> StoreError {
    StoreError::Database(sqlx::Error::Decode(msg.into()))
}

fn prefix_of(s: &str) -> Result<Ipv4Prefix> {
    s.parse()
        .map_err(|e: dhonomos_wireguard::ParsePrefixError| decode_error(e.to_string()))
}

fn u16_of(what: &str, n: i32) -> Result<u16> {
    u16::try_from(n).map_err(|_| decode_error(format!("{what} {n} is out of range")))
}

impl Store {
    /// New token for a hub of the tenant (SHA-256 + display prefix), old one replaced at once.
    /// `None`: no such hub. `Some(replaced)`: hub had a token.
    pub async fn set_wg_hub_token(
        &self,
        tenant_id: Uuid,
        hub_id: Uuid,
        hash: &[u8],
        prefix: &str,
    ) -> Result<Option<bool>> {
        Ok(sqlx::query_scalar!(
            r#"
            WITH old AS (
                SELECT id, token_hash IS NOT NULL AS had FROM wg_hubs
                WHERE id = $1 AND tenant_id = $2 FOR UPDATE
            )
            UPDATE wg_hubs h SET token_hash = $3, token_prefix = $4, token_created_at = now()
            FROM old WHERE h.id = old.id
            RETURNING old.had AS "had!"
            "#,
            hub_id,
            tenant_id,
            hash,
            prefix
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Remove the token of a hub of the tenant. false: no such hub (hub without token = ok).
    pub async fn clear_wg_hub_token(&self, tenant_id: Uuid, hub_id: Uuid) -> Result<bool> {
        let done = sqlx::query!(
            r#"
            UPDATE wg_hubs SET token_hash = NULL, token_prefix = NULL, token_created_at = NULL
            WHERE id = $1 AND tenant_id = $2
            "#,
            hub_id,
            tenant_id
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Hub whose token has this SHA-256.
    pub async fn wg_hub_by_token(&self, hash: &[u8]) -> Result<Option<WgHubAuth>> {
        Ok(sqlx::query_as!(
            WgHubAuth,
            "SELECT id, tenant_id, name FROM wg_hubs WHERE token_hash = $1",
            hash
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Record a hub process call: time, source (`None`: not known to the server), version
    /// (`None` clears it). No change of `updated_at` or revision.
    pub async fn touch_wg_hub(
        &self,
        id: Uuid,
        ip: Option<IpAddr>,
        version: Option<&str>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE wg_hubs SET last_seen_at = now(), last_seen_ip = $2::text::inet,
                hub_version = $3
            WHERE id = $1
            "#,
            id,
            ip.map(|ip| ip.to_string()),
            version
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// State revision of the hub; `None`: no such hub.
    pub async fn wg_hub_revision(&self, id: Uuid) -> Result<Option<i64>> {
        Ok(
            sqlx::query_scalar!("SELECT state_revision FROM wg_hubs WHERE id = $1", id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Full run state of the hub, one snapshot. `None`: no such hub.
    ///
    /// Networks by listen port; in each, live members with a public key, by address.
    /// Peer allowed IPs = own `/32`, then site prefixes ascending.
    /// Left out: revoked members + device members with key not known yet.
    /// Every peer `preshared_key` = `None` here: see [`Store::wg_hub_state_sealed`].
    pub async fn wg_hub_state(&self, id: Uuid) -> Result<Option<HubState>> {
        Ok(self.wg_hub_state_sealed(id).await?.map(|(state, _)| state))
    }

    /// [`Store::wg_hub_state`] + sealed PSKs of its peers by member ID, same snapshot
    /// (only peers with one). Caller opens them -> fills each peer `preshared_key`.
    pub async fn wg_hub_state_sealed(
        &self,
        id: Uuid,
    ) -> Result<Option<(HubState, HashMap<Uuid, WgSealedPsk>)>> {
        let mut tx = self.pool.begin().await?;
        // One snapshot for all reads below -> revision matches what they see.
        sqlx::query!("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        let Some(revision) =
            sqlx::query_scalar!("SELECT state_revision FROM wg_hubs WHERE id = $1", id)
                .fetch_optional(&mut *tx)
                .await?
        else {
            return Ok(None);
        };
        let networks = sqlx::query!(
            r#"
            SELECT id, name, ipv4_prefix::text AS "prefix!", listen_port, mtu
            FROM wg_networks WHERE hub_id = $1 ORDER BY listen_port
            "#,
            id
        )
        .fetch_all(&mut *tx)
        .await?;
        let members = sqlx::query!(
            r#"
            SELECT m.id, m.network_id, m.kind, m.public_key AS "public_key!",
                   host(m.address) AS "address!", m.psk_ciphertext, m.psk_nonce
            FROM wg_members m JOIN wg_networks n ON n.id = m.network_id
            WHERE n.hub_id = $1 AND m.revoked_at IS NULL AND m.public_key IS NOT NULL
            ORDER BY m.address
            "#,
            id
        )
        .fetch_all(&mut *tx)
        .await?;
        let site_prefixes = sqlx::query!(
            r#"
            SELECT sp.member_id, sp.prefix::text AS "prefix!"
            FROM wg_site_prefixes sp JOIN wg_members m ON m.id = sp.member_id
            JOIN wg_networks n ON n.id = m.network_id
            WHERE n.hub_id = $1 AND m.revoked_at IS NULL AND m.public_key IS NOT NULL
            ORDER BY sp.prefix
            "#,
            id
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        let mut behind: HashMap<Uuid, Vec<Ipv4Prefix>> = HashMap::new();
        for p in site_prefixes {
            behind
                .entry(p.member_id)
                .or_default()
                .push(prefix_of(&p.prefix)?);
        }
        let mut peers: HashMap<Uuid, Vec<HubPeer>> = HashMap::new();
        let mut psks: HashMap<Uuid, WgSealedPsk> = HashMap::new();
        for m in members {
            if let Some(sealed) = m.psk_ciphertext.zip(m.psk_nonce) {
                psks.insert(m.id, sealed);
            }
            let address: std::net::Ipv4Addr = m
                .address
                .parse()
                .map_err(|_| decode_error(format!("{} is not an IPv4 address", m.address)))?;
            let own = Ipv4Prefix::new(address, 32)
                .ok_or_else(|| decode_error(format!("{address}/32 is not a prefix")))?;
            let mut allowed_ips = vec![own];
            allowed_ips.extend(behind.remove(&m.id).unwrap_or_default());
            peers.entry(m.network_id).or_default().push(HubPeer {
                member_id: m.id,
                kind: m.kind,
                public_key: m.public_key,
                allowed_ips,
                preshared_key: None,
            });
        }
        let networks = networks
            .into_iter()
            .map(|n| {
                let prefix = prefix_of(&n.prefix)?;
                let listen_port = u16_of("listen_port", n.listen_port)?;
                Ok(HubNetwork {
                    interface: interface_name(listen_port),
                    listen_port,
                    address: hub_address(prefix),
                    prefix,
                    mtu: u16_of("mtu", n.mtu)?,
                    peers: peers.remove(&n.id).unwrap_or_default(),
                    id: n.id,
                    name: n.name,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some((
            HubState {
                hub_id: id,
                revision,
                networks,
            },
            psks,
        )))
    }

    /// Set the hub public key, return the previous one (outer `None`: no such hub).
    /// Row (+ `updated_at`) changes only when the key differs.
    pub async fn set_wg_hub_public_key(
        &self,
        id: Uuid,
        key: &str,
    ) -> Result<Option<Option<String>>> {
        let mut tx = self.pool.begin().await?;
        let Some(previous) = sqlx::query_scalar!(
            "SELECT public_key FROM wg_hubs WHERE id = $1 FOR NO KEY UPDATE",
            id
        )
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(None);
        };
        if previous.as_deref() != Some(key) {
            sqlx::query!(
                "UPDATE wg_hubs SET public_key = $2, updated_at = now() WHERE id = $1",
                id,
                key
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(Some(previous))
    }

    /// Store a hub report on its peers: each entry for a live member of a hub network
    /// (by network + public key) overwrites the status of that member.
    ///
    /// Returns accepted + ignored counts, accepted members with stored values.
    /// Ignored: unknown keys, revoked members, networks of other hubs, repeats
    /// (last entry per network + key counts).
    /// Caller checked: byte counts fit in `i64`.
    pub async fn report_wg_peer_status(
        &self,
        hub_id: Uuid,
        peers: &[PeerStatus],
    ) -> Result<WgPeerReport> {
        // ON CONFLICT cannot touch one row twice in a statement -> one entry per peer, the last.
        let mut last: HashMap<(Uuid, &str), usize> = HashMap::new();
        for (i, p) in peers.iter().enumerate() {
            last.insert((p.network_id, p.public_key.as_str()), i);
        }
        let mut kept: Vec<usize> = last.into_values().collect();
        kept.sort_unstable();
        let n = kept.len();
        let mut network_ids = Vec::with_capacity(n);
        let mut keys = Vec::with_capacity(n);
        let mut endpoints = Vec::with_capacity(n);
        let mut handshakes = Vec::with_capacity(n);
        let mut rx = Vec::with_capacity(n);
        let mut tx = Vec::with_capacity(n);
        for i in kept {
            let p = &peers[i];
            network_ids.push(p.network_id);
            keys.push(p.public_key.clone());
            endpoints.push(p.endpoint.clone());
            handshakes.push(p.latest_handshake.unwrap_or(0));
            rx.push(i64::try_from(p.rx_bytes).unwrap_or(i64::MAX));
            tx.push(i64::try_from(p.tx_bytes).unwrap_or(i64::MAX));
        }
        let rows = sqlx::query!(
            r#"
            WITH up AS (
                INSERT INTO wg_peer_status (member_id, endpoint, latest_handshake, rx_bytes,
                                            tx_bytes, reported_at)
                SELECT m.id, u.endpoint,
                       CASE WHEN u.handshake > 0 THEN to_timestamp(u.handshake) END,
                       u.rx, u.tx, now()
                FROM UNNEST($1::uuid[], $2::text[], $3::text[], $4::bigint[], $5::bigint[],
                            $6::bigint[]) AS u(network_id, public_key, endpoint, handshake, rx,
                                               tx)
                JOIN wg_members m ON m.network_id = u.network_id AND m.public_key = u.public_key
                                 AND m.revoked_at IS NULL
                JOIN wg_networks n ON n.id = m.network_id AND n.hub_id = $7
                ON CONFLICT (member_id) DO UPDATE SET endpoint = EXCLUDED.endpoint,
                    latest_handshake = EXCLUDED.latest_handshake, rx_bytes = EXCLUDED.rx_bytes,
                    tx_bytes = EXCLUDED.tx_bytes, reported_at = EXCLUDED.reported_at
                RETURNING member_id, latest_handshake, rx_bytes, tx_bytes
            )
            SELECT up.member_id AS "member_id!", m.device_id AS "device_id?",
                   m.network_id AS "network_id!", up.latest_handshake AS "latest_handshake?",
                   up.rx_bytes AS "rx_bytes!", up.tx_bytes AS "tx_bytes!"
            FROM up JOIN wg_members m ON m.id = up.member_id
            "#,
            &network_ids,
            &keys,
            &endpoints as &[Option<String>],
            &handshakes,
            &rx,
            &tx,
            hub_id
        )
        .fetch_all(&self.pool)
        .await?;
        let peers_out: Vec<WgReportedPeer> = rows
            .into_iter()
            .map(|r| WgReportedPeer {
                member_id: r.member_id,
                device_id: r.device_id,
                network_id: r.network_id,
                latest_handshake: r.latest_handshake,
                rx_bytes: r.rx_bytes,
                tx_bytes: r.tx_bytes,
            })
            .collect();
        let accepted = peers_out.len();
        Ok(WgPeerReport {
            accepted,
            ignored: peers.len().saturating_sub(accepted),
            peers: peers_out,
        })
    }
}
