//! Store side of the WireGuard hub process (ADR-110 stage 2). Throwaway PostgreSQL.
//! Covers: hub tokens, state revision (kept by triggers), hub state, peer status.
//! Stage 1 fixes: client owners, revocation.
//! Stage 3: site prefixes a client reaches, client re-key.
#![allow(clippy::unwrap_used)]

use std::net::IpAddr;

use dhonomos_store::{
    CwmpIdentity, DEFAULT_TENANT, InformUpdate, NewWgMember, NewWgMemberKind, NewWgNetwork, Store,
    WgMember, WgNetwork, WgNetworkPatch, WgPeerReport, WgPrefixChoice, WgRefusal, WgReportedPeer,
    WgSitePrefix, WgVisibility,
};
use dhonomos_wireguard::{Ipv4Prefix, PeerStatus};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use time::Duration;
use uuid::Uuid;

async fn setup() -> (ContainerAsync<Postgres>, Store) {
    let container = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let store = Store::connect(&url, 8).await.unwrap();
    store.migrate().await.unwrap();
    (container, store)
}

fn p(s: &str) -> Ipv4Prefix {
    s.parse().unwrap()
}

const ALL: WgVisibility<'static> = WgVisibility {
    all_clients: true,
    user_id: None,
    scope: None,
};

const DAY: Duration = Duration::hours(24);

async fn hub(store: &Store, name: &str) -> Uuid {
    store
        .create_wg_hub(DEFAULT_TENANT, name, "hub.example.org")
        .await
        .unwrap()
        .unwrap()
        .id
}

async fn network(store: &Store, hub_id: Uuid, name: &str, port: Option<u16>) -> WgNetwork {
    store
        .create_wg_network(
            DEFAULT_TENANT,
            &NewWgNetwork {
                hub_id,
                name: name.into(),
                prefix: WgPrefixChoice::Auto {
                    len: 24,
                    pool: p("10.77.0.0/16"),
                },
                listen_port: port,
                mtu: 1420,
                persistent_keepalive: 25,
            },
        )
        .await
        .unwrap()
        .unwrap()
}

async fn device(store: &Store, serial: &str) -> Uuid {
    store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: "202BC1".into(),
                product_class: "LS500X".into(),
                serial_number: serial.into(),
            },
            &InformUpdate::default(),
        )
        .await
        .unwrap()
        .id
}

fn device_member(device_id: Uuid, name: &str, prefixes: &[&str]) -> NewWgMember {
    NewWgMember {
        id: Uuid::now_v7(),
        psk: None,
        name: name.into(),
        kind: NewWgMemberKind::Device {
            device_id,
            key_mode: "device".into(),
        },
        site_prefixes: prefixes
            .iter()
            .map(|s| WgSitePrefix {
                prefix: p(s),
                description: String::new(),
            })
            .collect(),
    }
}

/// Distinct 44-char key per `n`.
fn key(n: u8) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([n.wrapping_add(1); 32])
}

fn client(user_id: Option<Uuid>, name: &str, public_key: String) -> NewWgMember {
    NewWgMember {
        id: Uuid::now_v7(),
        psk: None,
        name: name.into(),
        kind: NewWgMemberKind::Client {
            user_id,
            public_key,
        },
        site_prefixes: Vec::new(),
    }
}

async fn add(store: &Store, network: &WgNetwork, new: &NewWgMember) -> WgMember {
    store
        .create_wg_member(DEFAULT_TENANT, network.id, new, DAY)
        .await
        .unwrap()
        .unwrap()
}

async fn rev(store: &Store, hub_id: Uuid) -> i64 {
    store.wg_hub_revision(hub_id).await.unwrap().unwrap()
}

/// Device member key via raw SQL, as stage 4 sets it.
async fn set_key(store: &Store, member_id: Uuid, key: &str) {
    sqlx::query("UPDATE wg_members SET public_key = $2 WHERE id = $1")
        .bind(member_id)
        .bind(key)
        .execute(store.pool())
        .await
        .unwrap();
}

fn peer(network_id: Uuid, key: String, rx: u64) -> PeerStatus {
    PeerStatus {
        network_id,
        public_key: key,
        endpoint: Some("198.51.100.7:40000".into()),
        latest_handshake: Some(1_760_000_000),
        rx_bytes: rx,
        tx_bytes: rx * 2,
    }
}

#[tokio::test]
async fn hub_tokens_are_set_replaced_and_cleared() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let first = [1u8; 32];
    let second = [2u8; 32];

    assert_eq!(
        store
            .set_wg_hub_token(DEFAULT_TENANT, h, &first, "dwh_aaaaaaaa")
            .await
            .unwrap(),
        Some(false)
    );
    let found = store.wg_hub_by_token(&first).await.unwrap().unwrap();
    assert_eq!((found.id, found.tenant_id), (h, DEFAULT_TENANT));
    assert_eq!(found.name, "lab");
    let shown = store.get_wg_hub(DEFAULT_TENANT, h).await.unwrap().unwrap();
    assert_eq!(shown.token_prefix.as_deref(), Some("dwh_aaaaaaaa"));
    assert!(shown.token_created_at.is_some());

    // New token -> old one invalid at once.
    assert_eq!(
        store
            .set_wg_hub_token(DEFAULT_TENANT, h, &second, "dwh_bbbbbbbb")
            .await
            .unwrap(),
        Some(true)
    );
    assert!(store.wg_hub_by_token(&first).await.unwrap().is_none());
    assert_eq!(store.wg_hub_by_token(&second).await.unwrap().unwrap().id, h);

    assert!(store.clear_wg_hub_token(DEFAULT_TENANT, h).await.unwrap());
    assert!(store.wg_hub_by_token(&second).await.unwrap().is_none());
    let shown = store.get_wg_hub(DEFAULT_TENANT, h).await.unwrap().unwrap();
    assert_eq!((shown.token_prefix, shown.token_created_at), (None, None));
    // Clear x2 -> ok.
    assert!(store.clear_wg_hub_token(DEFAULT_TENANT, h).await.unwrap());

    // Unknown hub, hub of another tenant.
    let other = Uuid::now_v7();
    assert_eq!(
        store
            .set_wg_hub_token(DEFAULT_TENANT, other, &first, "dwh_x")
            .await
            .unwrap(),
        None
    );
    assert!(
        !store
            .clear_wg_hub_token(DEFAULT_TENANT, other)
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .set_wg_hub_token(Uuid::now_v7(), h, &first, "dwh_x")
            .await
            .unwrap(),
        None
    );

    // DB refuses: hash without prefix + time, hash of other size.
    let half = sqlx::query("UPDATE wg_hubs SET token_hash = $2 WHERE id = $1")
        .bind(h)
        .bind(first.to_vec())
        .execute(store.pool())
        .await;
    assert!(half.is_err());
    let short = sqlx::query(
        "UPDATE wg_hubs SET token_hash = $2, token_prefix = 'dwh_', token_created_at = now() WHERE id = $1",
    )
    .bind(h)
    .bind(vec![1u8; 16])
    .execute(store.pool())
    .await;
    assert!(short.is_err());
}

#[tokio::test]
async fn the_revision_follows_every_change_of_the_hubs_state() {
    let (_c, store) = setup().await;
    let x = hub(&store, "x").await;
    let y = hub(&store, "y").await;
    let y0 = rev(&store, y).await;

    let r = rev(&store, x).await;
    assert_eq!(r, 1);
    let net = network(&store, x, "n", None).await;
    assert_eq!(rev(&store, x).await, r + 1);
    let r = rev(&store, x).await;
    store
        .update_wg_network(
            DEFAULT_TENANT,
            net.id,
            &WgNetworkPatch {
                mtu: Some(1400),
                ..WgNetworkPatch::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rev(&store, x).await, r + 1);

    let r = rev(&store, x).await;
    let c = add(&store, &net, &client(None, "srv", key(1))).await;
    assert_eq!(rev(&store, x).await, r + 1);
    let d1 = device(&store, "D1").await;
    let r = rev(&store, x).await;
    let dm = add(
        &store,
        &net,
        &device_member(d1, "d1", &["192.168.10.0/24", "192.168.11.0/24"]),
    )
    .await;
    assert!(rev(&store, x).await > r);
    let r = rev(&store, x).await;
    store
        .update_wg_member(
            DEFAULT_TENANT,
            dm.id,
            None,
            Some(&[WgSitePrefix {
                prefix: p("192.168.12.0/24"),
                description: String::new(),
            }]),
            None,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(rev(&store, x).await > r);
    let r = rev(&store, x).await;
    store
        .update_wg_member(DEFAULT_TENANT, dm.id, Some("renamed"), None, None)
        .await
        .unwrap()
        .unwrap();
    // Member name not in hub state (migration 0034).
    assert_eq!(rev(&store, x).await, r);
    let r = rev(&store, x).await;
    set_key(&store, dm.id, &key(2)).await;
    assert_eq!(rev(&store, x).await, r + 1);

    let r = rev(&store, x).await;
    let (_, now) = store
        .revoke_wg_member(DEFAULT_TENANT, c.id, Some("gone"))
        .await
        .unwrap()
        .unwrap();
    assert!(now);
    assert_eq!(rev(&store, x).await, r + 1);
    // Revoke again -> no row change, no bump.
    let (_, now) = store
        .revoke_wg_member(DEFAULT_TENANT, c.id, None)
        .await
        .unwrap()
        .unwrap();
    assert!(!now);
    assert_eq!(rev(&store, x).await, r + 1);

    // Delete member with site prefixes -> 1 bump.
    // Its prefixes go along + find no member -> no 2nd bump.
    let r = rev(&store, x).await;
    store
        .delete_wg_member(DEFAULT_TENANT, dm.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rev(&store, x).await, r + 1);

    // Delete device -> its member goes too -> 1 bump.
    let d2 = device(&store, "D2").await;
    add(&store, &net, &device_member(d2, "d2", &["192.168.20.0/24"])).await;
    let r = rev(&store, x).await;
    sqlx::query("DELETE FROM devices WHERE id = $1")
        .bind(d2)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(rev(&store, x).await, r + 1);

    // Calls of the hub itself -> no bump.
    let k = add(&store, &net, &client(None, "srv2", key(3))).await;
    let r = rev(&store, x).await;
    store
        .touch_wg_hub(x, Some("203.0.113.5".parse().unwrap()), Some("0.1.0"))
        .await
        .unwrap();
    store
        .report_wg_peer_status(x, &[peer(net.id, key(3), 10)])
        .await
        .unwrap();
    store.set_wg_hub_public_key(x, &key(9)).await.unwrap();
    assert_eq!(rev(&store, x).await, r);
    let shown = store.get_wg_hub(DEFAULT_TENANT, x).await.unwrap().unwrap();
    assert_eq!(shown.state_revision, r);
    assert!(
        store
            .get_wg_member(DEFAULT_TENANT, k.id, &ALL)
            .await
            .unwrap()
            .unwrap()
            .hub_status
            .is_some()
    );

    // Delete network with members -> 1 bump.
    let r = rev(&store, x).await;
    store
        .delete_wg_network(DEFAULT_TENANT, net.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rev(&store, x).await, r + 1);

    // Other hub untouched.
    assert_eq!(rev(&store, y).await, y0);
}

#[tokio::test]
async fn the_hub_state_holds_live_keyed_members_by_port_and_address() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let other_hub = hub(&store, "other").await;
    let high = network(&store, h, "high", Some(51821)).await;
    let low = network(&store, h, "low", Some(51820)).await;
    network(&store, other_hub, "elsewhere", Some(51820)).await;

    let c1 = add(&store, &low, &client(None, "c1", key(1))).await;
    let revoked = add(&store, &low, &client(None, "gone", key(2))).await;
    store
        .revoke_wg_member(DEFAULT_TENANT, revoked.id, None)
        .await
        .unwrap()
        .unwrap();
    let d1 = device(&store, "D1").await;
    let keyless = add(&store, &low, &device_member(d1, "keyless", &[])).await;
    let d2 = device(&store, "D2").await;
    let dm = add(
        &store,
        &low,
        &device_member(
            d2,
            "d2",
            &["192.168.20.0/24", "172.16.0.0/16", "192.168.3.0/24"],
        ),
    )
    .await;
    set_key(&store, dm.id, &key(3)).await;
    let c2 = add(&store, &high, &client(None, "c2", key(4))).await;

    let state = store.wg_hub_state(h).await.unwrap().unwrap();
    assert_eq!(state.hub_id, h);
    assert_eq!(state.revision, rev(&store, h).await);
    let ports: Vec<u16> = state.networks.iter().map(|n| n.listen_port).collect();
    assert_eq!(ports, [51820, 51821]);

    let n = &state.networks[0];
    assert_eq!(n.id, low.id);
    assert_eq!(n.name, "low");
    assert_eq!(n.interface, "dwg51820");
    assert_eq!(n.prefix, low.ipv4_prefix);
    assert_eq!(n.address, dhonomos_wireguard::hub_address(low.ipv4_prefix));
    assert_eq!(n.mtu, 1420);
    let ids: Vec<Uuid> = n.peers.iter().map(|p| p.member_id).collect();
    // By address: c1 first, device later.
    // Left out: keyless member (in between), revoked client.
    assert_eq!(ids, [c1.id, dm.id]);
    assert!(!ids.contains(&revoked.id) && !ids.contains(&keyless.id));
    assert_eq!(n.peers[0].kind, "client");
    assert_eq!(n.peers[0].public_key, key(1));
    assert_eq!(
        n.peers[0].allowed_ips,
        [Ipv4Prefix::new(c1.address, 32).unwrap()]
    );
    assert_eq!(n.peers[1].kind, "device");
    assert_eq!(
        n.peers[1].allowed_ips,
        [
            Ipv4Prefix::new(dm.address, 32).unwrap(),
            p("172.16.0.0/16"),
            p("192.168.3.0/24"),
            p("192.168.20.0/24"),
        ]
    );

    let n = &state.networks[1];
    assert_eq!(n.interface, "dwg51821");
    assert_eq!(n.peers.len(), 1);
    assert_eq!(n.peers[0].member_id, c2.id);

    assert!(store.wg_hub_state(Uuid::now_v7()).await.unwrap().is_none());
    assert!(
        store
            .wg_hub_revision(Uuid::now_v7())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn peer_status_is_kept_for_live_members_of_the_hubs_networks() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let other_hub = hub(&store, "other").await;
    let net = network(&store, h, "n", None).await;
    let elsewhere = network(&store, other_hub, "e", None).await;
    let a = add(&store, &net, &client(None, "a", key(1))).await;
    let revoked = add(&store, &net, &client(None, "r", key(2))).await;
    store
        .revoke_wg_member(DEFAULT_TENANT, revoked.id, None)
        .await
        .unwrap()
        .unwrap();
    let foreign = add(&store, &elsewhere, &client(None, "f", key(3))).await;

    let report = [
        peer(net.id, key(1), 1),
        peer(net.id, key(7), 1),       // unknown key
        peer(net.id, key(2), 1),       // revoked
        peer(elsewhere.id, key(3), 1), // network of another hub
        peer(net.id, key(3), 1),       // key known, other network
        peer(net.id, key(1), 500),     // repeat -> last one counts
    ];
    let done = store.report_wg_peer_status(h, &report).await.unwrap();
    assert_eq!((done.accepted, done.ignored), (1, 5));
    let s = store
        .get_wg_member(DEFAULT_TENANT, a.id, &ALL)
        .await
        .unwrap()
        .unwrap()
        .hub_status
        .unwrap();
    assert_eq!(s.endpoint.as_deref(), Some("198.51.100.7:40000"));
    assert_eq!(s.rx_bytes, 500);
    assert_eq!(s.tx_bytes, 1000);
    assert_eq!(s.latest_handshake.unwrap().unix_timestamp(), 1_760_000_000);
    for id in [revoked.id, foreign.id] {
        let m = store
            .get_wg_member(DEFAULT_TENANT, id, &ALL)
            .await
            .unwrap()
            .unwrap();
        assert!(m.hub_status.is_none());
    }

    // Later report overwrites. Handshake 0 = none.
    let mut again = peer(net.id, key(1), 9);
    again.latest_handshake = Some(0);
    again.endpoint = None;
    let done = store.report_wg_peer_status(h, &[again]).await.unwrap();
    assert_eq!((done.accepted, done.ignored), (1, 0));
    let s2 = store
        .get_wg_member(DEFAULT_TENANT, a.id, &ALL)
        .await
        .unwrap()
        .unwrap()
        .hub_status
        .unwrap();
    assert_eq!((s2.rx_bytes, s2.tx_bytes), (9, 18));
    assert_eq!((s2.endpoint, s2.latest_handshake), (None, None));
    assert!(s2.reported_at >= s.reported_at);
    // Member list -> shows it too.
    let (listed, _) = store
        .list_wg_members(DEFAULT_TENANT, net.id, &ALL, true, 100, 0)
        .await
        .unwrap()
        .unwrap();
    assert!(
        listed
            .iter()
            .find(|m| m.id == a.id)
            .unwrap()
            .hub_status
            .is_some()
    );

    // Delete member -> status gone too.
    store
        .delete_wg_member(DEFAULT_TENANT, a.id)
        .await
        .unwrap()
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM wg_peer_status")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(left, 0);
    assert_eq!(
        store.report_wg_peer_status(h, &[]).await.unwrap(),
        WgPeerReport::default()
    );
}

/// Report result = stored members only.
///
/// Device member -> with device. Client -> without. Ignored entries -> absent.
#[tokio::test]
async fn a_peer_status_report_returns_the_members_it_stored() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n", None).await;
    let d = device(&store, "D1").await;
    let dm = add(&store, &net, &device_member(d, "d1", &[])).await;
    set_key(&store, dm.id, &key(1)).await;
    let c = add(&store, &net, &client(None, "c", key(2))).await;

    let mut never = peer(net.id, key(2), 7);
    never.latest_handshake = None;
    let report = [
        peer(net.id, key(1), 100),
        never,
        peer(net.id, key(9), 1), // unknown key
    ];
    let mut done = store.report_wg_peer_status(h, &report).await.unwrap();
    assert_eq!((done.accepted, done.ignored), (2, 1));
    done.peers.sort_by_key(|p| p.device_id.is_none());
    assert_eq!(
        done.peers,
        [
            WgReportedPeer {
                member_id: dm.id,
                device_id: Some(d),
                network_id: net.id,
                latest_handshake: Some(
                    time::OffsetDateTime::from_unix_timestamp(1_760_000_000).unwrap()
                ),
                rx_bytes: 100,
                tx_bytes: 200,
            },
            WgReportedPeer {
                member_id: c.id,
                device_id: None,
                network_id: net.id,
                latest_handshake: None,
                rx_bytes: 7,
                tx_bytes: 14,
            },
        ]
    );
}

#[tokio::test]
async fn the_hub_records_when_it_was_seen_and_its_public_key() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let before = store.get_wg_hub(DEFAULT_TENANT, h).await.unwrap().unwrap();
    assert_eq!(before.last_seen_at, None);

    let ip: IpAddr = "2001:db8::7".parse().unwrap();
    store
        .touch_wg_hub(h, Some(ip), Some("0.1.0"))
        .await
        .unwrap();
    let seen = store.get_wg_hub(DEFAULT_TENANT, h).await.unwrap().unwrap();
    assert!(seen.last_seen_at.is_some());
    assert_eq!(seen.last_seen_ip.as_deref(), Some("2001:db8::7"));
    assert_eq!(seen.hub_version.as_deref(), Some("0.1.0"));
    assert_eq!(seen.updated_at, before.updated_at);
    store
        .touch_wg_hub(h, Some("203.0.113.5".parse().unwrap()), None)
        .await
        .unwrap();
    let seen = store.get_wg_hub(DEFAULT_TENANT, h).await.unwrap().unwrap();
    assert_eq!(seen.last_seen_ip.as_deref(), Some("203.0.113.5"));
    assert_eq!(seen.hub_version, None);
    store.touch_wg_hub(h, None, None).await.unwrap();
    let seen = store.get_wg_hub(DEFAULT_TENANT, h).await.unwrap().unwrap();
    assert_eq!(seen.last_seen_ip, None);

    assert_eq!(
        store.set_wg_hub_public_key(h, &key(1)).await.unwrap(),
        Some(None)
    );
    let keyed = store.get_wg_hub(DEFAULT_TENANT, h).await.unwrap().unwrap();
    assert_eq!(keyed.public_key, Some(key(1)));
    assert!(keyed.updated_at > before.updated_at);
    // Same key again -> no change.
    assert_eq!(
        store.set_wg_hub_public_key(h, &key(1)).await.unwrap(),
        Some(Some(key(1)))
    );
    let same = store.get_wg_hub(DEFAULT_TENANT, h).await.unwrap().unwrap();
    assert_eq!(same.updated_at, keyed.updated_at);
    assert_eq!(
        store.set_wg_hub_public_key(h, &key(2)).await.unwrap(),
        Some(Some(key(1)))
    );
    assert_eq!(
        store
            .set_wg_hub_public_key(Uuid::now_v7(), &key(2))
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn a_client_needs_an_owner_that_can_own_clients_when_it_is_stored() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n", None).await;
    let refused = |owner: Option<Uuid>, n: u8| {
        let store = store.clone();
        let net = net.clone();
        async move {
            store
                .create_wg_member(DEFAULT_TENANT, net.id, &client(owner, "c", key(n)), DAY)
                .await
                .unwrap()
                .err()
        }
    };

    // Owner disabled after the API check, before the store call.
    let op = store
        .create_user(DEFAULT_TENANT, "op", "x", "operator")
        .await
        .unwrap();
    sqlx::query("UPDATE users SET disabled = true WHERE id = $1")
        .bind(op)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        refused(Some(op), 1).await,
        Some(WgRefusal::OwnerCannotOwnClients)
    );

    assert_eq!(
        refused(Some(Uuid::now_v7()), 2).await,
        Some(WgRefusal::OwnerNotFound)
    );

    let scoped = store
        .create_user(DEFAULT_TENANT, "scoped", "x", "operator")
        .await
        .unwrap();
    sqlx::query(r#"UPDATE users SET scope = '{"tags": ["lab"]}'::jsonb WHERE id = $1"#)
        .bind(scoped)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        refused(Some(scoped), 3).await,
        Some(WgRefusal::OwnerCannotOwnClients)
    );

    let viewer = store
        .create_user(DEFAULT_TENANT, "viewer", "x", "viewer")
        .await
        .unwrap();
    assert_eq!(
        refused(Some(viewer), 4).await,
        Some(WgRefusal::OwnerCannotOwnClients)
    );

    // Valid owner + server client -> ok.
    let ok = store
        .create_user(DEFAULT_TENANT, "ok", "x", "operator")
        .await
        .unwrap();
    assert_eq!(refused(Some(ok), 5).await, None);
    assert_eq!(refused(None, 6).await, None);
}

#[tokio::test]
async fn revoking_an_accounts_clients_on_two_hubs_bumps_both() {
    let (_c, store) = setup().await;
    let x = hub(&store, "x").await;
    let y = hub(&store, "y").await;
    let nx = network(&store, x, "nx", None).await;
    let ny = network(&store, y, "ny", None).await;
    let user = store
        .create_user(DEFAULT_TENANT, "op", "x", "operator")
        .await
        .unwrap();
    add(&store, &nx, &client(Some(user), "a", key(1))).await;
    add(&store, &ny, &client(Some(user), "b", key(2))).await;
    let (rx, ry) = (rev(&store, x).await, rev(&store, y).await);

    let done = store
        .update_user(user, None, Some(true), None, None)
        .await
        .unwrap();
    assert_eq!(done.revoked_clients.len(), 2);
    assert_eq!(rev(&store, x).await, rx + 1);
    assert_eq!(rev(&store, y).await, ry + 1);
}

#[tokio::test]
async fn deleting_an_account_waits_for_a_client_being_added_and_revokes_it() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n", None).await;
    let user = store
        .create_user(DEFAULT_TENANT, "op", "x", "operator")
        .await
        .unwrap();

    // Other tx holds the owner row, as `create_wg_member` does.
    let mut held = store.pool().begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR SHARE")
        .bind(user)
        .fetch_one(&mut *held)
        .await
        .unwrap();
    let deleting = {
        let store = store.clone();
        tokio::spawn(async move { store.delete_user(user).await.unwrap() })
    };
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !deleting.is_finished(),
        "delete_user did not wait for the owner lock"
    );

    let member = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO wg_members (id, network_id, kind, user_id, name, public_key, address)
        VALUES ($1, $2, 'client', $3, 'late', $4, '10.77.0.2/32')
        "#,
    )
    .bind(member)
    .bind(net.id)
    .bind(user)
    .bind(key(1))
    .execute(&mut *held)
    .await
    .unwrap();
    held.commit().await.unwrap();

    let done = deleting.await.unwrap();
    assert!(done.found);
    assert_eq!(
        done.revoked_clients
            .iter()
            .map(|r| (r.id, r.reason.as_str()))
            .collect::<Vec<_>>(),
        [(member, "user deleted")]
    );
    let m = store
        .get_wg_member(DEFAULT_TENANT, member, &ALL)
        .await
        .unwrap()
        .unwrap();
    assert!(m.revoked_at.is_some());
    assert_eq!(m.revoked_reason.as_deref(), Some("user deleted"));
    assert_eq!(m.user_id, None);
}

#[tokio::test]
async fn a_networks_site_prefixes_are_those_of_its_live_members_in_order() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n", None).await;
    let other = network(&store, h, "o", None).await;
    let empty = network(&store, h, "e", None).await;
    let (d1, d2, d3, d4) = (
        device(&store, "S1").await,
        device(&store, "S2").await,
        device(&store, "S3").await,
        device(&store, "S4").await,
    );
    add(
        &store,
        &net,
        &device_member(d1, "a", &["192.168.20.0/24", "172.16.0.0/16"]),
    )
    .await;
    add(&store, &net, &device_member(d2, "b", &["192.168.10.0/24"])).await;
    let revoked = add(&store, &net, &device_member(d3, "r", &["10.200.0.0/24"])).await;
    store
        .revoke_wg_member(DEFAULT_TENANT, revoked.id, None)
        .await
        .unwrap()
        .unwrap();
    add(
        &store,
        &other,
        &device_member(d4, "x", &["192.168.30.0/24"]),
    )
    .await;
    add(&store, &net, &client(None, "pc", key(1))).await;

    assert_eq!(
        store.wg_network_site_prefixes(net.id).await.unwrap(),
        vec![
            p("172.16.0.0/16"),
            p("192.168.10.0/24"),
            p("192.168.20.0/24")
        ]
    );
    assert_eq!(
        store.wg_network_site_prefixes(other.id).await.unwrap(),
        vec![p("192.168.30.0/24")]
    );
    assert!(
        store
            .wg_network_site_prefixes(empty.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_client_is_rekeyed_and_the_hub_forgets_the_old_key() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n", None).await;
    let pc = add(&store, &net, &client(None, "pc", key(1))).await;
    let other = add(&store, &net, &client(None, "other", key(2))).await;
    let done = store
        .report_wg_peer_status(h, &[peer(net.id, key(1), 1)])
        .await
        .unwrap();
    assert_eq!((done.accepted, done.ignored), (1, 0));

    let before = rev(&store, h).await;
    let m = store
        .rekey_wg_client(DEFAULT_TENANT, pc.id, &key(3), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(m.public_key.as_deref(), Some(key(3).as_str()));
    assert_eq!((m.address, m.name.as_str()), (pc.address, "pc"));
    assert!(m.hub_status.is_none(), "the status was about the old key");
    assert!(m.updated_at >= pc.updated_at);
    assert!(rev(&store, h).await > before);
    let status: i64 =
        sqlx::query_scalar("SELECT count(*) FROM wg_peer_status WHERE member_id = $1")
            .bind(pc.id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(status, 0);
    let keys: Vec<String> = store
        .wg_hub_state(h)
        .await
        .unwrap()
        .unwrap()
        .networks
        .iter()
        .flat_map(|n| n.peers.iter().map(|p| p.public_key.clone()))
        .collect();
    assert!(
        keys.contains(&key(3)) && !keys.contains(&key(1)),
        "{keys:?}"
    );

    // Key of another live member -> refused, no change.
    assert_eq!(
        store
            .rekey_wg_client(DEFAULT_TENANT, pc.id, &key(2), None)
            .await
            .unwrap(),
        Err(WgRefusal::KeyInUse)
    );
    let still = store
        .get_wg_member(DEFAULT_TENANT, pc.id, &ALL)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still.public_key.as_deref(), Some(key(3).as_str()));

    // Device -> not re-keyed here. Revoked member -> never.
    let d = device(&store, "S1").await;
    let dm = add(&store, &net, &device_member(d, "dev", &[])).await;
    assert_eq!(
        store
            .rekey_wg_client(DEFAULT_TENANT, dm.id, &key(4), None)
            .await
            .unwrap(),
        Err(WgRefusal::NotAClient)
    );
    store
        .revoke_wg_member(DEFAULT_TENANT, other.id, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .rekey_wg_client(DEFAULT_TENANT, other.id, &key(5), None)
            .await
            .unwrap(),
        Err(WgRefusal::MemberRevoked)
    );
    // Key of revoked member -> free again.
    store
        .rekey_wg_client(DEFAULT_TENANT, pc.id, &key(2), None)
        .await
        .unwrap()
        .unwrap();

    // Other tenant -> member not found. Unknown ID -> not found.
    let tenant = Uuid::now_v7();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, 'other')")
        .bind(tenant)
        .execute(store.pool())
        .await
        .unwrap();
    for (t, id) in [(tenant, pc.id), (DEFAULT_TENANT, Uuid::now_v7())] {
        assert_eq!(
            store.rekey_wg_client(t, id, &key(6), None).await.unwrap(),
            Err(WgRefusal::MemberNotFound)
        );
    }
    let unchanged = store
        .get_wg_member(DEFAULT_TENANT, pc.id, &ALL)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.public_key.as_deref(), Some(key(2).as_str()));
}

/// Invented sealed bytes. Store never opens them.
fn sealed(n: u8) -> (Vec<u8>, Vec<u8>) {
    (vec![n; 48], vec![n; 12])
}

#[tokio::test]
async fn preshared_keys_are_stored_sealed_and_bump_the_revision() {
    let (_c, store) = setup().await;
    let h = hub(&store, "psk").await;
    let net = network(&store, h, "n", None).await;

    // Create with sealed PSK -> enabled + in hub state of the same snapshot.
    let mut new = client(None, "pc", key(1));
    new.psk = Some(sealed(1));
    let pc = add(&store, &net, &new).await;
    assert_eq!(pc.id, new.id, "the caller chooses the ID");
    assert!(pc.preshared_key_enabled);
    assert_eq!(
        store.wg_member_psk(DEFAULT_TENANT, pc.id).await.unwrap(),
        Some(sealed(1))
    );
    assert_eq!(
        store.wg_member_psk(Uuid::now_v7(), pc.id).await.unwrap(),
        None,
        "another tenant"
    );
    let (state, psks) = store.wg_hub_state_sealed(h).await.unwrap().unwrap();
    assert_eq!(psks.get(&pc.id), Some(&sealed(1)));
    assert_eq!(state.networks[0].peers[0].preshared_key, None);

    // No PSK -> not enabled, nothing stored.
    let other = add(&store, &net, &client(None, "pc2", key(2))).await;
    assert!(!other.preshared_key_enabled);
    assert_eq!(
        store.wg_member_psk(DEFAULT_TENANT, other.id).await.unwrap(),
        None
    );

    // Replace, then clear -> bump each time.
    let r = rev(&store, h).await;
    let m = store
        .update_wg_member(
            DEFAULT_TENANT,
            other.id,
            None,
            None,
            Some(Some((&[2; 48], &[2; 12]))),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(m.preshared_key_enabled);
    assert!(rev(&store, h).await > r);
    let r = rev(&store, h).await;
    let m = store
        .update_wg_member(DEFAULT_TENANT, other.id, None, None, Some(None))
        .await
        .unwrap()
        .unwrap();
    assert!(!m.preshared_key_enabled);
    assert_eq!(
        store.wg_member_psk(DEFAULT_TENANT, other.id).await.unwrap(),
        None
    );
    assert!(rev(&store, h).await > r);
    // PSK left out -> kept, no bump.
    let r = rev(&store, h).await;
    let m = store
        .update_wg_member(DEFAULT_TENANT, pc.id, Some("renamed"), None, None)
        .await
        .unwrap()
        .unwrap();
    assert!(m.preshared_key_enabled);
    assert_eq!(rev(&store, h).await, r);

    // Device member: run state -> no bump. PSK -> bump.
    let d = device(&store, "PSK1").await;
    let mut dnew = device_member(d, "d", &[]);
    dnew.psk = Some(sealed(3));
    let dm = add(&store, &net, &dnew).await;
    assert!(dm.preshared_key_enabled);
    let r = rev(&store, h).await;
    store
        .set_wg_member_device_state(dm.id, "applied", None, Some("hash"))
        .await
        .unwrap();
    assert_eq!(rev(&store, h).await, r);
    assert!(
        store
            .replace_wg_member_psk(dm.id, &[4; 48], &[4; 12])
            .await
            .unwrap()
    );
    assert!(rev(&store, h).await > r);
    let m = &store
        .wg_device_memberships(DEFAULT_TENANT, d)
        .await
        .unwrap()[0];
    assert_eq!(m.psk, Some(sealed(4)));
    // Member without PSK -> false.
    assert!(
        !store
            .replace_wg_member_psk(other.id, &[5; 48], &[5; 12])
            .await
            .unwrap()
    );

    // Client re-key -> replaces PSK only when it has one.
    store
        .rekey_wg_client(DEFAULT_TENANT, pc.id, &key(5), Some((&[6; 48], &[6; 12])))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store.wg_member_psk(DEFAULT_TENANT, pc.id).await.unwrap(),
        Some(sealed(6))
    );
    store
        .rekey_wg_client(DEFAULT_TENANT, pc.id, &key(7), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store.wg_member_psk(DEFAULT_TENANT, pc.id).await.unwrap(),
        Some(sealed(6)),
        "no new key given: the old one stays"
    );
    let m = store
        .rekey_wg_client(
            DEFAULT_TENANT,
            other.id,
            &key(8),
            Some((&[7; 48], &[7; 12])),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        !m.preshared_key_enabled,
        "a client without one stays without"
    );

    // DB check: flag + PSK always together.
    for (enabled, ct, nonce) in [
        (true, None, None),
        (false, Some(vec![1u8; 48]), Some(vec![1u8; 12])),
        (true, Some(vec![1u8; 48]), None),
    ] {
        let bad = sqlx::query(
            "UPDATE wg_members SET preshared_key_enabled = $2, psk_ciphertext = $3, psk_nonce = $4 WHERE id = $1",
        )
        .bind(other.id)
        .bind(enabled)
        .bind(ct)
        .bind(nonce)
        .execute(store.pool())
        .await;
        assert!(bad.is_err(), "{enabled}");
    }

    // Secrets key rotation: read PSKs page by page.
    // Replace a PSK only if unchanged meanwhile.
    let mut all = Vec::new();
    let mut after = None;
    loop {
        let page = store.wg_psks_page(after, 1).await.unwrap();
        let Some(last) = page.last() else { break };
        after = Some(last.member_id);
        all.extend(page);
    }
    let mut ids: Vec<Uuid> = all.iter().map(|p| p.member_id).collect();
    ids.sort();
    let mut want = vec![pc.id, dm.id];
    want.sort();
    assert_eq!(ids, want);
    let old = all.iter().find(|p| p.member_id == pc.id).unwrap().clone();
    let r = rev(&store, h).await;
    assert!(store.rewrap_wg_psk(&old, &[9; 48], &[9; 12]).await.unwrap());
    assert!(!store.rewrap_wg_psk(&old, &[8; 48], &[8; 12]).await.unwrap());
    assert_eq!(
        store.wg_member_psk(DEFAULT_TENANT, pc.id).await.unwrap(),
        Some(sealed(9))
    );
    assert!(rev(&store, h).await > r, "the hub fetches the state again");
}
