//! CPE provisioning of device members (ADR-110 stage 4): reads + writes.
//! Live memberships of a device + all the planner needs, last run state per member,
//! member key (made by the device or sent by the server).
//!
//! Run state (`device_*` columns, migration 0034) -> no hub revision bump.
//! Member key -> bump (hub must take a new key + drop one the device does not have).

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;

use dhonomos_wireguard::Ipv4Prefix;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::wireguard::{WgMember, WgRefusal, WgResult, WgSealedPsk, member_in};
use crate::{Result, Store, StoreError};

/// One live network membership of a device, input of the CPE provisioning plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgDeviceMembership {
    pub member_id: Uuid,
    pub network_id: Uuid,
    /// `device` or `server`.
    pub key_mode: String,
    /// `None` = not known yet.
    pub public_key: Option<String>,
    /// Tunnel address.
    pub address: Ipv4Addr,
    /// Tunnel prefix of the network.
    pub prefix: Ipv4Prefix,
    /// Hub UDP port of the network.
    pub listen_port: u16,
    pub mtu: u16,
    /// Keepalive in s (0 = none).
    pub persistent_keepalive: u16,
    /// Host the device dials.
    pub hub_endpoint_host: String,
    /// `None` until the hub process reports it.
    pub hub_public_key: Option<String>,
    /// Site prefixes of the other live members of the network, ascending, no duplicates.
    pub other_site_prefixes: Vec<Ipv4Prefix>,
    /// Result of the last run (see migration 0034).
    pub device_state: String,
    /// Reason for `blocked` + `error`.
    pub device_detail: Option<String>,
    /// Last time a run recorded a state.
    pub device_checked_at: Option<OffsetDateTime>,
    /// Desired state (hash) of the last run.
    pub device_applied_hash: Option<String>,
    /// Time of the key rotation request (see migration 0035).
    pub rotate_requested_at: Option<OffsetDateTime>,
    /// Sealed PSK `(ciphertext, nonce)` (see migration 0036). `None` = no PSK.
    pub psk: Option<WgSealedPsk>,
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

/// Name of the violated unique constraint/index, if `e` is a unique violation.
fn violated(e: &sqlx::Error) -> Option<&str> {
    match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => d.constraint(),
        _ => None,
    }
}

impl Store {
    /// Live device members of a device of the tenant, by network ID, one snapshot.
    pub async fn wg_device_memberships(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
    ) -> Result<Vec<WgDeviceMembership>> {
        Ok(self
            .wg_device_memberships_for(tenant_id, &[device_id])
            .await?
            .remove(&device_id)
            .unwrap_or_default())
    }

    /// [`Store::wg_device_memberships`] of many devices of the tenant at once, one snapshot.
    ///
    /// Only devices with >= 1 live device member, each with its members by network ID.
    pub async fn wg_device_memberships_for(
        &self,
        tenant_id: Uuid,
        device_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Vec<WgDeviceMembership>>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query!("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        let rows = sqlx::query!(
            r#"
            SELECT m.id, m.network_id, m.device_id AS "device_id!", m.key_mode AS "key_mode!",
                   m.public_key, host(m.address) AS "address!", n.ipv4_prefix::text AS "prefix!",
                   n.listen_port, n.mtu, n.persistent_keepalive,
                   h.endpoint_host, h.public_key AS hub_public_key,
                   m.device_state AS "device_state!", m.device_detail, m.device_checked_at,
                   m.device_applied_hash, m.rotate_requested_at, m.psk_ciphertext, m.psk_nonce
            FROM wg_members m JOIN wg_networks n ON n.id = m.network_id
            JOIN wg_hubs h ON h.id = n.hub_id
            WHERE n.tenant_id = $1 AND m.device_id = ANY($2) AND m.kind = 'device'
              AND m.revoked_at IS NULL
            ORDER BY m.device_id, n.id
            "#,
            tenant_id,
            device_ids
        )
        .fetch_all(&mut *tx)
        .await?;
        let mut networks: Vec<Uuid> = rows.iter().map(|r| r.network_id).collect();
        networks.sort_unstable();
        networks.dedup();
        // Site prefixes of all live members of these networks + member device (None = client).
        // Prefixes of a member's own device are not "other".
        let prefixes = sqlx::query!(
            r#"
            SELECT m.network_id, m.device_id, sp.prefix::text AS "prefix!"
            FROM wg_site_prefixes sp JOIN wg_members m ON m.id = sp.member_id
            WHERE m.network_id = ANY($1) AND m.revoked_at IS NULL
            "#,
            &networks
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        let mut site: Vec<(Uuid, Option<Uuid>, Ipv4Prefix)> = Vec::with_capacity(prefixes.len());
        for p in prefixes {
            site.push((p.network_id, p.device_id, prefix_of(&p.prefix)?));
        }
        let mut out: HashMap<Uuid, Vec<WgDeviceMembership>> = HashMap::new();
        for r in rows {
            let behind: BTreeSet<Ipv4Prefix> = site
                .iter()
                .filter(|(network, device, _)| {
                    *network == r.network_id && *device != Some(r.device_id)
                })
                .map(|(_, _, prefix)| *prefix)
                .collect();
            let m = WgDeviceMembership {
                member_id: r.id,
                network_id: r.network_id,
                key_mode: r.key_mode,
                public_key: r.public_key,
                address: r
                    .address
                    .parse()
                    .map_err(|_| decode_error(format!("{} is not an IPv4 address", r.address)))?,
                prefix: prefix_of(&r.prefix)?,
                listen_port: u16_of("listen_port", r.listen_port)?,
                mtu: u16_of("mtu", r.mtu)?,
                persistent_keepalive: u16_of("persistent_keepalive", r.persistent_keepalive)?,
                hub_endpoint_host: r.endpoint_host,
                hub_public_key: r.hub_public_key,
                other_site_prefixes: behind.into_iter().collect(),
                device_state: r.device_state,
                device_detail: r.device_detail,
                device_checked_at: r.device_checked_at,
                device_applied_hash: r.device_applied_hash,
                rotate_requested_at: r.rotate_requested_at,
                psk: r.psk_ciphertext.zip(r.psk_nonce),
            };
            out.entry(r.device_id).or_default().push(m);
        }
        Ok(out)
    }

    /// CWMP devices (`devices.protocol = 'cwmp'`) of the tenant's live device members in
    /// `network_ids`, ascending, each once -> devices to wake when an input of their
    /// WireGuard config changes. USP Agents left out: reconciled while connected, no wake.
    pub async fn wg_cwmp_devices_of_networks(
        &self,
        tenant_id: Uuid,
        network_ids: &[Uuid],
    ) -> Result<Vec<Uuid>> {
        Ok(sqlx::query_scalar!(
            r#"
            SELECT DISTINCT d.id
            FROM wg_members m JOIN wg_networks n ON n.id = m.network_id
            JOIN devices d ON d.id = m.device_id
            WHERE n.tenant_id = $1 AND d.tenant_id = $1 AND m.network_id = ANY($2)
              AND m.kind = 'device' AND m.revoked_at IS NULL AND d.protocol = 'cwmp'
            ORDER BY d.id
            "#,
            tenant_id,
            network_ids
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Networks of the tenant with a live device member of a twin of `device_id`, ascending.
    ///
    /// Twin = other device of the same tenant, equal `oui` + equal `serial_number`, both
    /// non-null and non-empty, any protocol.
    /// Why: one CPE with CWMP + USP = two devices -> rows of these networks on the CPE
    /// belong to the twin's provisioning.
    pub async fn wg_twin_networks(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
    ) -> Result<BTreeSet<Uuid>> {
        let rows = sqlx::query_scalar!(
            r#"
            SELECT DISTINCT m.network_id
            FROM devices d
            JOIN devices t ON t.tenant_id = d.tenant_id AND t.id <> d.id
                AND t.oui = d.oui AND t.serial_number = d.serial_number
            JOIN wg_members m ON m.device_id = t.id
            JOIN wg_networks n ON n.id = m.network_id
            WHERE d.id = $2 AND d.tenant_id = $1 AND n.tenant_id = $1
              AND d.oui <> '' AND d.serial_number <> ''
              AND m.kind = 'device' AND m.revoked_at IS NULL
            "#,
            tenant_id,
            device_id
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().collect())
    }

    /// Devices among `device_ids` with stale WireGuard rows, ascending, each once.
    ///
    /// Stale row = alias `dhonomos-wg-<network>` (exact form) under `Device.WireGuard.` or
    /// `Device.IP.Interface.` in the snapshot, for a network where neither the device nor a
    /// twin (see [`Store::wg_twin_networks`]) has a live device member.
    /// Cause: device maybe left the network -> rows no record of the CPE manages any more.
    pub async fn wg_stale_devices(&self, device_ids: &[Uuid]) -> Result<Vec<Uuid>> {
        let rows = sqlx::query!(
            r#"
            SELECT device_id, value AS "value!" FROM device_params
            WHERE device_id = ANY($1)
              AND (path LIKE 'Device.WireGuard.%' OR path LIKE 'Device.IP.Interface.%')
              AND path LIKE '%.Alias' AND value LIKE 'dhonomos-wg-%'
            "#,
            device_ids
        )
        .fetch_all(&self.pool)
        .await?;
        // Networks where the device or a twin is a live device member.
        let managed: BTreeSet<(Uuid, Uuid)> = sqlx::query!(
            r#"
            SELECT d.id AS device_id, m.network_id
            FROM devices d
            JOIN devices t ON t.tenant_id = d.tenant_id
                AND (t.id = d.id
                     OR (t.oui = d.oui AND t.serial_number = d.serial_number
                         AND d.oui <> '' AND d.serial_number <> ''))
            JOIN wg_members m ON m.device_id = t.id
            JOIN wg_networks n ON n.id = m.network_id AND n.tenant_id = d.tenant_id
            WHERE d.id = ANY($1) AND m.kind = 'device' AND m.revoked_at IS NULL
            "#,
            device_ids
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| (r.device_id, r.network_id))
        .collect();
        let mut out: Vec<Uuid> = rows
            .into_iter()
            .filter(|r| {
                dhonomos_wireguard::network_of_alias(&r.value)
                    .is_some_and(|n| !managed.contains(&(r.device_id, n)))
            })
            .map(|r| r.device_id)
            .collect();
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    /// Record the result of a run on the CPE for a device member: `state`, `detail`, checked
    /// now. `applied_hash` `None` -> stored hash kept. No hub revision change.
    pub async fn set_wg_member_device_state(
        &self,
        member_id: Uuid,
        state: &str,
        detail: Option<&str>,
        applied_hash: Option<&str>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE wg_members SET device_state = $2, device_detail = $3,
                device_checked_at = now(),
                device_applied_hash = COALESCE($4, device_applied_hash)
            WHERE id = $1 AND kind = 'device'
            "#,
            member_id,
            state,
            detail,
            applied_hash
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Set the public key of a live device member (read from the device, or public half of
    /// the key pair the server sent).
    ///
    /// Key changed -> last hub report on the member dropped (it was about the old key).
    /// `MemberNotFound`: no live device member. `KeyInUse`: other live member of the network
    /// has this key.
    pub async fn set_wg_device_member_key(
        &self,
        member_id: Uuid,
        public_key: &str,
    ) -> WgResult<()> {
        let mut tx = self.pool.begin().await?;
        let Some(previous) = sqlx::query_scalar!(
            r#"
            SELECT public_key FROM wg_members
            WHERE id = $1 AND kind = 'device' AND revoked_at IS NULL FOR NO KEY UPDATE
            "#,
            member_id
        )
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(Err(WgRefusal::MemberNotFound));
        };
        if previous.as_deref() == Some(public_key) {
            return Ok(Ok(()));
        }
        let done = sqlx::query!(
            "UPDATE wg_members SET public_key = $2, updated_at = now() WHERE id = $1",
            member_id,
            public_key
        )
        .execute(&mut *tx)
        .await;
        if let Err(e) = done {
            return match violated(&e) {
                Some("wg_members_live_key") => Ok(Err(WgRefusal::KeyInUse)),
                _ => Err(e.into()),
            };
        }
        sqlx::query!("DELETE FROM wg_peer_status WHERE member_id = $1", member_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Ok(()))
    }

    /// Ask for a new key of a live device member of the tenant -> next run makes the CPE use
    /// one (see migration 0035). Member -> back to `pending`.
    /// `MemberNotFound`, `MemberRevoked`, `NotADevice` (a client).
    pub async fn request_wg_key_rotation(
        &self,
        tenant_id: Uuid,
        member_id: Uuid,
    ) -> WgResult<WgMember> {
        let mut tx = self.pool.begin().await?;
        let Some(found) = sqlx::query!(
            r#"
            SELECT m.kind, m.revoked_at FROM wg_members m JOIN wg_networks n ON n.id = m.network_id
            WHERE m.id = $1 AND n.tenant_id = $2 FOR NO KEY UPDATE OF m
            "#,
            member_id,
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
        if found.kind != "device" {
            return Ok(Err(WgRefusal::NotADevice));
        }
        sqlx::query!(
            r#"
            UPDATE wg_members SET rotate_requested_at = now(), device_state = 'pending',
                device_detail = NULL
            WHERE id = $1
            "#,
            member_id
        )
        .execute(&mut *tx)
        .await?;
        let member = member_in(&mut tx, tenant_id, member_id).await?;
        tx.commit().await?;
        Ok(member.ok_or(WgRefusal::MemberNotFound))
    }

    /// [`Store::request_wg_key_rotation`] for every live device member of a network of the
    /// tenant. Returns count asked; `NetworkNotFound`.
    pub async fn request_wg_network_key_rotation(
        &self,
        tenant_id: Uuid,
        network_id: Uuid,
    ) -> WgResult<i64> {
        let mut tx = self.pool.begin().await?;
        let exists = sqlx::query_scalar!(
            "SELECT id FROM wg_networks WHERE id = $1 AND tenant_id = $2",
            network_id,
            tenant_id
        )
        .fetch_optional(&mut *tx)
        .await?;
        if exists.is_none() {
            return Ok(Err(WgRefusal::NetworkNotFound));
        }
        let done = sqlx::query!(
            r#"
            UPDATE wg_members SET rotate_requested_at = now(), device_state = 'pending',
                device_detail = NULL
            WHERE network_id = $1 AND kind = 'device' AND revoked_at IS NULL
            "#,
            network_id
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Ok(i64::try_from(done.rows_affected()).unwrap_or(i64::MAX)))
    }

    /// Replace the sealed PSK of a live member that has one (key rotation -> new PSK).
    /// Hub revision bumped. Returns replaced; false: member gone, revoked or no PSK (any more).
    pub async fn replace_wg_member_psk(
        &self,
        member_id: Uuid,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<bool> {
        let done = sqlx::query!(
            r#"
            UPDATE wg_members SET psk_ciphertext = $2, psk_nonce = $3, updated_at = now()
            WHERE id = $1 AND preshared_key_enabled AND revoked_at IS NULL
            "#,
            member_id,
            ciphertext,
            nonce
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Clear the key rotation request of a member: a run applied it with a new key.
    pub async fn clear_wg_key_rotation(&self, member_id: Uuid) -> Result<()> {
        sqlx::query!(
            "UPDATE wg_members SET rotate_requested_at = NULL WHERE id = $1",
            member_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Forget the public key of a live device member.
    ///
    /// Why: server made a key pair for the device, but the device may not have taken the
    /// private key. -> hub drops the peer (revision bumped), next run sends a new key.
    pub async fn clear_wg_device_member_key(&self, member_id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let done = sqlx::query!(
            r#"
            UPDATE wg_members SET public_key = NULL, updated_at = now()
            WHERE id = $1 AND kind = 'device' AND revoked_at IS NULL AND public_key IS NOT NULL
            "#,
            member_id
        )
        .execute(&mut *tx)
        .await?;
        if done.rows_affected() == 1 {
            sqlx::query!("DELETE FROM wg_peer_status WHERE member_id = $1", member_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
