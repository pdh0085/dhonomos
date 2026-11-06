//! Store side of CPE provisioning of device members (ADR-110 stage 4). Throwaway PostgreSQL.
//! Covers: device state columns, memberships of a device, member keys,
//! redaction of task secret values, member changes that bump the hub revision.
#![allow(clippy::unwrap_used)]

use dhonomos_store::{
    CwmpIdentity, DEFAULT_TENANT, DeviceFilter, DeviceInfo, DeviceScope, InformUpdate, NewTask,
    NewWgMember, NewWgMemberKind, NewWgNetwork, Store, WgMember, WgNetwork, WgPrefixChoice,
    WgRefusal, WgSitePrefix, WgVisibility,
};
use dhonomos_wireguard::Ipv4Prefix;
use serde_json::json;
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

async fn network(store: &Store, hub_id: Uuid, name: &str) -> WgNetwork {
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
                listen_port: None,
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

fn device_member(device_id: Uuid, key_mode: &str, prefixes: &[&str]) -> NewWgMember {
    NewWgMember {
        id: Uuid::now_v7(),
        psk: None,
        name: "cpe".into(),
        kind: NewWgMemberKind::Device {
            device_id,
            key_mode: key_mode.into(),
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

async fn add(store: &Store, network: &WgNetwork, new: &NewWgMember) -> WgMember {
    store
        .create_wg_member(DEFAULT_TENANT, network.id, new, DAY)
        .await
        .unwrap()
        .unwrap()
}

async fn member(store: &Store, id: Uuid) -> WgMember {
    store
        .get_wg_member(DEFAULT_TENANT, id, &ALL)
        .await
        .unwrap()
        .unwrap()
}

async fn rev(store: &Store, hub_id: Uuid) -> i64 {
    store.wg_hub_revision(hub_id).await.unwrap().unwrap()
}

#[tokio::test]
async fn device_members_start_pending_and_clients_have_no_state() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n").await;
    let d = device(&store, "SN1").await;
    let m = add(&store, &net, &device_member(d, "device", &[])).await;
    assert_eq!(m.device_state.as_deref(), Some("pending"));
    assert_eq!(m.device_detail, None);
    assert_eq!(m.device_checked_at, None);
    assert_eq!(m.device_applied_hash, None);
    let client = add(
        &store,
        &net,
        &NewWgMember {
            id: Uuid::now_v7(),
            psk: None,
            name: "pc".into(),
            kind: NewWgMemberKind::Client {
                user_id: None,
                public_key: key(1),
            },
            site_prefixes: Vec::new(),
        },
    )
    .await;
    assert_eq!(client.device_state, None);
    // List -> same columns.
    let (listed, _) = store
        .list_wg_members(DEFAULT_TENANT, net.id, &ALL, false, 10, 0)
        .await
        .unwrap()
        .unwrap();
    let states: Vec<Option<&str>> = listed.iter().map(|m| m.device_state.as_deref()).collect();
    assert_eq!(states, [Some("pending"), None]);
}

#[tokio::test]
async fn memberships_carry_what_the_planner_needs() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let n1 = network(&store, h, "one").await;
    let n2 = network(&store, h, "two").await;
    let a = device(&store, "A").await;
    let b = device(&store, "B").await;
    let c = device(&store, "C").await;
    let ma1 = add(
        &store,
        &n1,
        &device_member(a, "server", &["192.168.10.0/24"]),
    )
    .await;
    let ma2 = add(&store, &n2, &device_member(a, "device", &[])).await;
    add(
        &store,
        &n1,
        &device_member(b, "device", &["192.168.30.0/24", "192.168.20.0/24"]),
    )
    .await;
    let mc = add(
        &store,
        &n1,
        &device_member(c, "device", &["192.168.40.0/24"]),
    )
    .await;
    store
        .revoke_wg_member(DEFAULT_TENANT, mc.id, None)
        .await
        .unwrap()
        .unwrap();

    let got = store
        .wg_device_memberships(DEFAULT_TENANT, a)
        .await
        .unwrap();
    assert_eq!(got.len(), 2);
    let mut want_order = vec![n1.id, n2.id];
    want_order.sort();
    assert_eq!(
        got.iter().map(|m| m.network_id).collect::<Vec<_>>(),
        want_order,
        "by network ID"
    );
    let one = got.iter().find(|m| m.network_id == n1.id).unwrap();
    assert_eq!(one.member_id, ma1.id);
    assert_eq!(one.key_mode, "server");
    assert_eq!(one.public_key, None);
    assert_eq!(one.address, ma1.address);
    assert_eq!(one.prefix, n1.ipv4_prefix);
    assert_eq!(i32::from(one.listen_port), n1.listen_port);
    assert_eq!(one.mtu, 1420);
    assert_eq!(one.persistent_keepalive, 25);
    assert_eq!(one.hub_endpoint_host, "hub.example.org");
    assert_eq!(one.hub_public_key, None, "not reported yet");
    // Prefixes of the others, sorted. Without A's own + revoked member's.
    assert_eq!(
        one.other_site_prefixes,
        [p("192.168.20.0/24"), p("192.168.30.0/24")]
    );
    assert_eq!(one.device_state, "pending");
    let two = got.iter().find(|m| m.network_id == n2.id).unwrap();
    assert_eq!(two.member_id, ma2.id);
    assert!(two.other_site_prefixes.is_empty());

    store.set_wg_hub_public_key(h, &key(9)).await.unwrap();
    let got = store
        .wg_device_memberships(DEFAULT_TENANT, a)
        .await
        .unwrap();
    assert!(got.iter().all(|m| m.hub_public_key == Some(key(9))));
    // Revoked member, device of other tenant -> none.
    assert!(
        store
            .wg_device_memberships(DEFAULT_TENANT, c)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .wg_device_memberships(Uuid::now_v7(), a)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn device_state_is_recorded_and_the_hash_kept_unless_given() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n").await;
    let d = device(&store, "SN1").await;
    let m = add(&store, &net, &device_member(d, "device", &[])).await;
    store
        .set_wg_member_device_state(m.id, "applied", None, Some("aa"))
        .await
        .unwrap();
    let got = member(&store, m.id).await;
    assert_eq!(got.device_state.as_deref(), Some("applied"));
    assert_eq!(got.device_applied_hash.as_deref(), Some("aa"));
    let first = got.device_checked_at.unwrap();
    store
        .set_wg_member_device_state(m.id, "error", Some("9002 Internal error"), None)
        .await
        .unwrap();
    let got = member(&store, m.id).await;
    assert_eq!(got.device_state.as_deref(), Some("error"));
    assert_eq!(got.device_detail.as_deref(), Some("9002 Internal error"));
    assert_eq!(got.device_applied_hash.as_deref(), Some("aa"), "kept");
    assert!(got.device_checked_at.unwrap() >= first);
    // Unknown state -> DB refuses.
    assert!(
        store
            .set_wg_member_device_state(m.id, "done", None, None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn device_member_keys_are_set_and_cleared() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n").await;
    let a = device(&store, "A").await;
    let b = device(&store, "B").await;
    let ma = add(&store, &net, &device_member(a, "device", &[])).await;
    let mb = add(&store, &net, &device_member(b, "server", &[])).await;
    store
        .set_wg_device_member_key(ma.id, &key(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(member(&store, ma.id).await.public_key, Some(key(1)));
    // Same key again -> ok. Key of another live member -> refused.
    store
        .set_wg_device_member_key(ma.id, &key(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .set_wg_device_member_key(mb.id, &key(1))
            .await
            .unwrap(),
        Err(WgRefusal::KeyInUse)
    );
    assert_eq!(member(&store, mb.id).await.public_key, None);

    store.clear_wg_device_member_key(ma.id).await.unwrap();
    assert_eq!(member(&store, ma.id).await.public_key, None);
    store
        .set_wg_device_member_key(mb.id, &key(1))
        .await
        .unwrap()
        .unwrap();

    // Revoked members + clients -> untouched.
    store
        .revoke_wg_member(DEFAULT_TENANT, mb.id, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .set_wg_device_member_key(mb.id, &key(2))
            .await
            .unwrap(),
        Err(WgRefusal::MemberNotFound)
    );
    store.clear_wg_device_member_key(mb.id).await.unwrap();
    assert_eq!(member(&store, mb.id).await.public_key, Some(key(1)));
    let client = add(
        &store,
        &net,
        &NewWgMember {
            id: Uuid::now_v7(),
            psk: None,
            name: "pc".into(),
            kind: NewWgMemberKind::Client {
                user_id: None,
                public_key: key(3),
            },
            site_prefixes: Vec::new(),
        },
    )
    .await;
    assert_eq!(
        store
            .set_wg_device_member_key(client.id, &key(4))
            .await
            .unwrap(),
        Err(WgRefusal::MemberNotFound)
    );
    store.clear_wg_device_member_key(client.id).await.unwrap();
    assert_eq!(member(&store, client.id).await.public_key, Some(key(3)));
}

#[tokio::test]
async fn only_changes_the_hub_sees_bump_its_revision() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n").await;
    let d = device(&store, "SN1").await;
    let m = add(&store, &net, &device_member(d, "server", &[])).await;
    let r = rev(&store, h).await;
    store
        .set_wg_member_device_state(m.id, "applied", None, Some("aa"))
        .await
        .unwrap();
    store
        .set_wg_member_device_state(m.id, "error", Some("x"), Some("bb"))
        .await
        .unwrap();
    assert_eq!(rev(&store, h).await, r, "the device state is not the hub's");
    store
        .set_wg_device_member_key(m.id, &key(1))
        .await
        .unwrap()
        .unwrap();
    let r1 = rev(&store, h).await;
    assert!(r1 > r, "a key is");
    store.clear_wg_device_member_key(m.id).await.unwrap();
    let r2 = rev(&store, h).await;
    assert!(r2 > r1, "so is forgetting it");
    store
        .revoke_wg_member(DEFAULT_TENANT, m.id, None)
        .await
        .unwrap()
        .unwrap();
    assert!(rev(&store, h).await > r2, "and a revocation");
}

#[tokio::test]
async fn secret_values_of_a_task_are_redacted() {
    let (_c, store) = setup().await;
    let d = device(&store, "SN1").await;
    let payload = json!({
        "values": [
            { "name": "Device.WireGuard.Tunnel.1.PrivateKey", "value": "enc:v1:abc", "type": "string", "secret": true },
            { "name": "Device.WireGuard.Tunnel.1.Enable", "value": "true", "type": "boolean" },
        ]
    });
    let (id, _) = store
        .enqueue_task(&NewTask::new(
            DEFAULT_TENANT,
            d,
            "set_parameter_values",
            payload,
        ))
        .await
        .unwrap();
    store.fail_task(id, "9002 Internal error").await.unwrap();
    let want = json!({
        "values": [
            { "name": "Device.WireGuard.Tunnel.1.PrivateKey", "value": "********", "type": "string", "secret": true },
            { "name": "Device.WireGuard.Tunnel.1.Enable", "value": "true", "type": "boolean" },
        ]
    });
    store.redact_task_secret_values(id).await.unwrap();
    assert_eq!(store.get_task(id).await.unwrap().unwrap().payload, want);
    store.redact_task_secret_values(id).await.unwrap();
    assert_eq!(
        store.get_task(id).await.unwrap().unwrap().payload,
        want,
        "idempotent"
    );
    // No `values`, or empty -> payload unchanged.
    for payload in [json!({ "names": ["Device."] }), json!({ "values": [] })] {
        let (id, _) = store
            .enqueue_task(&NewTask::new(
                DEFAULT_TENANT,
                d,
                "get_parameter_values",
                payload.clone(),
            ))
            .await
            .unwrap();
        store.redact_task_secret_values(id).await.unwrap();
        assert_eq!(store.get_task(id).await.unwrap().unwrap().payload, payload);
    }
}

#[tokio::test]
async fn cwmp_devices_of_networks_are_the_live_cwmp_device_members() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let n1 = network(&store, h, "one").await;
    let n2 = network(&store, h, "two").await;
    let n3 = network(&store, h, "three").await;
    let a = device(&store, "A").await;
    let b = device(&store, "B").await;
    let c = device(&store, "C").await;
    let usp = store
        .upsert_usp_device(DEFAULT_TENANT, "os::agent", None)
        .await
        .unwrap()
        .id;
    add(&store, &n1, &device_member(a, "device", &[])).await;
    add(&store, &n2, &device_member(a, "device", &[])).await;
    add(
        &store,
        &n1,
        &device_member(b, "device", &["192.168.10.0/24"]),
    )
    .await;
    add(&store, &n1, &device_member(usp, "device", &[])).await;
    let revoked = add(&store, &n2, &device_member(c, "device", &[])).await;
    store
        .revoke_wg_member(DEFAULT_TENANT, revoked.id, None)
        .await
        .unwrap()
        .unwrap();
    add(&store, &n3, &device_member(c, "server", &[])).await;
    add(
        &store,
        &n1,
        &NewWgMember {
            id: Uuid::now_v7(),
            psk: None,
            name: "pc".into(),
            kind: NewWgMemberKind::Client {
                user_id: None,
                public_key: key(1),
            },
            site_prefixes: Vec::new(),
        },
    )
    .await;

    let mut want = vec![a, b];
    want.sort();
    // A in both networks -> listed once.
    // Left out: USP Agent, revoked member, client, C (network not asked for).
    assert_eq!(
        store
            .wg_cwmp_devices_of_networks(DEFAULT_TENANT, &[n1.id, n2.id])
            .await
            .unwrap(),
        want
    );
    assert_eq!(
        store
            .wg_cwmp_devices_of_networks(DEFAULT_TENANT, &[n2.id])
            .await
            .unwrap(),
        [a]
    );
    assert!(
        store
            .wg_cwmp_devices_of_networks(DEFAULT_TENANT, &[])
            .await
            .unwrap()
            .is_empty()
    );

    // Tenant isolation: network of other tenant not found, both ways.
    let other = Uuid::now_v7();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, 'other')")
        .bind(other)
        .execute(store.pool())
        .await
        .unwrap();
    let oh = store
        .create_wg_hub(other, "lab", "hub.example.org")
        .await
        .unwrap()
        .unwrap()
        .id;
    let on = store
        .create_wg_network(
            other,
            &NewWgNetwork {
                hub_id: oh,
                name: "one".into(),
                prefix: WgPrefixChoice::Auto {
                    len: 24,
                    pool: p("10.77.0.0/16"),
                },
                listen_port: None,
                mtu: 1420,
                persistent_keepalive: 25,
            },
        )
        .await
        .unwrap()
        .unwrap();
    let od = store
        .upsert_cwmp_device(
            other,
            &CwmpIdentity {
                oui: "202BC1".into(),
                product_class: "LS500X".into(),
                serial_number: "A".into(),
            },
            &InformUpdate::default(),
        )
        .await
        .unwrap()
        .id;
    store
        .create_wg_member(other, on.id, &device_member(od, "device", &[]), DAY)
        .await
        .unwrap()
        .unwrap();
    assert!(
        store
            .wg_cwmp_devices_of_networks(DEFAULT_TENANT, &[on.id])
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .wg_cwmp_devices_of_networks(other, &[on.id, n1.id])
            .await
            .unwrap(),
        [od]
    );
}

#[tokio::test]
async fn key_rotation_is_requested_per_member_and_per_network_and_cleared() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n").await;
    let d1 = device(&store, "SN1").await;
    let d2 = device(&store, "SN2").await;
    let d3 = device(&store, "SN3").await;
    let m1 = add(&store, &net, &device_member(d1, "device", &[])).await;
    let m2 = add(&store, &net, &device_member(d2, "server", &[])).await;
    let gone = add(&store, &net, &device_member(d3, "device", &[])).await;
    store
        .revoke_wg_member(DEFAULT_TENANT, gone.id, None)
        .await
        .unwrap()
        .unwrap();
    let client = add(
        &store,
        &net,
        &NewWgMember {
            id: Uuid::now_v7(),
            psk: None,
            name: "pc".into(),
            kind: NewWgMemberKind::Client {
                user_id: None,
                public_key: key(9),
            },
            site_prefixes: Vec::new(),
        },
    )
    .await;
    assert_eq!(m1.rotate_requested_at, None);
    store
        .set_wg_device_member_key(m1.id, &key(1))
        .await
        .unwrap()
        .unwrap();
    store
        .set_wg_member_device_state(m1.id, "blocked", Some("x"), Some("aa"))
        .await
        .unwrap();
    let r = rev(&store, h).await;

    // One member -> requested + pending again. Key + hub untouched.
    let asked = store
        .request_wg_key_rotation(DEFAULT_TENANT, m1.id)
        .await
        .unwrap()
        .unwrap();
    assert!(asked.rotate_requested_at.is_some());
    assert_eq!(asked.device_state.as_deref(), Some("pending"));
    assert_eq!(asked.device_detail, None);
    assert_eq!(asked.device_applied_hash.as_deref(), Some("aa"));
    assert_eq!(asked.public_key, Some(key(1)));
    assert_eq!(member(&store, m1.id).await, asked);
    assert_eq!(rev(&store, h).await, r, "a request is not the hub's");
    let ms = store
        .wg_device_memberships(DEFAULT_TENANT, d1)
        .await
        .unwrap();
    assert_eq!(ms[0].rotate_requested_at, asked.rotate_requested_at);

    for (id, refusal) in [
        (Uuid::now_v7(), WgRefusal::MemberNotFound),
        (gone.id, WgRefusal::MemberRevoked),
        (client.id, WgRefusal::NotADevice),
    ] {
        assert_eq!(
            store
                .request_wg_key_rotation(DEFAULT_TENANT, id)
                .await
                .unwrap(),
            Err(refusal)
        );
    }
    assert_eq!(
        WgRefusal::NotADevice.to_string(),
        "only device members' keys are rotated here; re-key a client instead"
    );
    assert_eq!(member(&store, client.id).await.rotate_requested_at, None);
    let other = Uuid::now_v7();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, 'other')")
        .bind(other)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        store.request_wg_key_rotation(other, m2.id).await.unwrap(),
        Err(WgRefusal::MemberNotFound)
    );

    // Whole network -> every live device member. Not revoked, not client.
    assert_eq!(
        store
            .request_wg_network_key_rotation(DEFAULT_TENANT, net.id)
            .await
            .unwrap(),
        Ok(2)
    );
    assert!(member(&store, m2.id).await.rotate_requested_at.is_some());
    assert_eq!(member(&store, gone.id).await.rotate_requested_at, None);
    assert_eq!(member(&store, client.id).await.rotate_requested_at, None);
    for id in [net.id, Uuid::now_v7()] {
        let tenant = if id == net.id { other } else { DEFAULT_TENANT };
        assert_eq!(
            store
                .request_wg_network_key_rotation(tenant, id)
                .await
                .unwrap(),
            Err(WgRefusal::NetworkNotFound)
        );
    }

    // Clear -> other members + hub revision unchanged.
    store.clear_wg_key_rotation(m1.id).await.unwrap();
    assert_eq!(member(&store, m1.id).await.rotate_requested_at, None);
    assert!(member(&store, m2.id).await.rotate_requested_at.is_some());
    assert_eq!(rev(&store, h).await, r);

    // Client never has a rotate request -> DB refuses.
    let refused = sqlx::query("UPDATE wg_members SET rotate_requested_at = now() WHERE id = $1")
        .bind(client.id)
        .execute(store.pool())
        .await
        .unwrap_err();
    assert!(
        refused.to_string().contains("wg_members_rotate_device"),
        "{refused}"
    );
}

async fn cwmp_device(store: &Store, oui: &str, serial: &str) -> Uuid {
    store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: oui.into(),
                product_class: "LS500X".into(),
                serial_number: serial.into(),
            },
            &InformUpdate::default(),
        )
        .await
        .unwrap()
        .id
}

/// USP Agent. `None` OUI/serial -> never reported.
async fn usp_device(
    store: &Store,
    endpoint_id: &str,
    oui: Option<&str>,
    serial: Option<&str>,
) -> Uuid {
    let id = store
        .upsert_usp_device(DEFAULT_TENANT, endpoint_id, None)
        .await
        .unwrap()
        .id;
    store
        .update_device_info(
            id,
            &DeviceInfo {
                oui: oui.map(Into::into),
                serial_number: serial.map(Into::into),
                ..DeviceInfo::default()
            },
        )
        .await
        .unwrap();
    id
}

async fn try_add(
    store: &Store,
    network: &WgNetwork,
    device_id: Uuid,
) -> Result<WgMember, WgRefusal> {
    store
        .create_wg_member(
            DEFAULT_TENANT,
            network.id,
            &device_member(device_id, "device", &[]),
            DAY,
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn a_twin_of_a_member_cannot_join_the_same_network() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let n = network(&store, h, "n").await;
    let m = network(&store, h, "m").await;
    let cwmp = cwmp_device(&store, "B01408", "B01408123456").await;
    let usp = usp_device(
        &store,
        "os::B01408-B01408123456",
        Some("B01408"),
        Some("B01408123456"),
    )
    .await;
    let member = add(&store, &n, &device_member(cwmp, "device", &[])).await;
    assert_eq!(
        try_add(&store, &n, usp).await.unwrap_err(),
        WgRefusal::DeviceTwinIsMember
    );
    assert_eq!(
        WgRefusal::DeviceTwinIsMember.to_string(),
        "the same device is a member of this network already through its other record (CWMP or USP)"
    );
    // Other network -> ok.
    try_add(&store, &m, usp).await.unwrap();

    // Not twins: other OUI, other serial.
    let other_oui = usp_device(&store, "os::1", Some("B01409"), Some("B01408123456")).await;
    try_add(&store, &n, other_oui).await.unwrap();
    let other_serial = usp_device(&store, "os::2", Some("B01408"), Some("B01408123457")).await;
    try_add(&store, &n, other_serial).await.unwrap();
    // Not twins: empty OUI or serial on both rows, or not reported.
    let no_oui = cwmp_device(&store, "", "S1").await;
    add(&store, &n, &device_member(no_oui, "device", &[])).await;
    let no_oui_too = usp_device(&store, "os::3", Some(""), Some("S1")).await;
    try_add(&store, &n, no_oui_too).await.unwrap();
    let no_serial = cwmp_device(&store, "B01408", "").await;
    add(&store, &n, &device_member(no_serial, "device", &[])).await;
    let no_serial_too = usp_device(&store, "os::4", Some("B01408"), Some("")).await;
    try_add(&store, &n, no_serial_too).await.unwrap();
    let unreported = usp_device(&store, "os::5", None, Some("S2")).await;
    add(&store, &n, &device_member(unreported, "device", &[])).await;
    let unreported_too = usp_device(&store, "os::6", None, Some("S2")).await;
    try_add(&store, &n, unreported_too).await.unwrap();

    // Twin membership revoked -> device may join.
    store
        .revoke_wg_member(DEFAULT_TENANT, member.id, None)
        .await
        .unwrap()
        .unwrap();
    try_add(&store, &n, usp).await.unwrap();
}

#[tokio::test]
async fn twin_networks_are_the_live_device_memberships_of_the_other_record() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let n = network(&store, h, "n").await;
    let m = network(&store, h, "m").await;
    let gone = network(&store, h, "gone").await;
    let cwmp = cwmp_device(&store, "B01408", "B01408123456").await;
    let usp = usp_device(
        &store,
        "os::B01408-B01408123456",
        Some("B01408"),
        Some("B01408123456"),
    )
    .await;
    let unrelated = cwmp_device(&store, "B01408", "B01408123457").await;
    add(&store, &n, &device_member(cwmp, "device", &[])).await;
    let revoked = add(&store, &gone, &device_member(cwmp, "device", &[])).await;
    store
        .revoke_wg_member(DEFAULT_TENANT, revoked.id, None)
        .await
        .unwrap()
        .unwrap();
    add(&store, &m, &device_member(usp, "device", &[])).await;
    add(&store, &m, &device_member(unrelated, "device", &[])).await;

    let twin = |id| store.wg_twin_networks(DEFAULT_TENANT, id);
    assert_eq!(twin(usp).await.unwrap(), [n.id].into());
    assert_eq!(twin(cwmp).await.unwrap(), [m.id].into());
    assert!(twin(unrelated).await.unwrap().is_empty());
    // Other tenant -> device not seen.
    assert!(
        store
            .wg_twin_networks(Uuid::now_v7(), usp)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn stale_devices_leave_out_rows_of_their_own_and_their_twins_networks() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let n = network(&store, h, "n").await;
    let own = network(&store, h, "own").await;
    let nobody = network(&store, h, "nobody").await;
    let cwmp = cwmp_device(&store, "B01408", "B01408123456").await;
    let usp = usp_device(
        &store,
        "os::B01408-B01408123456",
        Some("B01408"),
        Some("B01408123456"),
    )
    .await;
    let unrelated = usp_device(&store, "os::other", Some("B01408"), Some("X")).await;
    add(&store, &n, &device_member(cwmp, "device", &[])).await;
    add(&store, &own, &device_member(usp, "device", &[])).await;
    let alias = |net: &WgNetwork| dhonomos_wireguard::alias_of(net.id);
    let param = |device: Uuid, path: &str, value: String| {
        let store = &store;
        let path = path.to_owned();
        async move {
            sqlx::query("INSERT INTO device_params (device_id, path, value) VALUES ($1, $2, $3)")
                .bind(device)
                .bind(path)
                .bind(value)
                .execute(store.pool())
                .await
                .unwrap();
        }
    };
    param(usp, "Device.WireGuard.Peer.1.Alias", alias(&n)).await;
    param(usp, "Device.WireGuard.Tunnel.1.Alias", alias(&n)).await;
    param(usp, "Device.IP.Interface.3.Alias", alias(&own)).await;
    param(unrelated, "Device.WireGuard.Peer.1.Alias", alias(&n)).await;
    let ids = [usp, unrelated, cwmp];
    // USP record: rows of twin's + own network -> not stale.
    // Unrelated Agent: in no network -> stale.
    assert_eq!(store.wg_stale_devices(&ids).await.unwrap(), [unrelated]);

    // 1 alias of a network neither twin is in -> stale.
    param(usp, "Device.WireGuard.Peer.2.Alias", alias(&nobody)).await;
    let mut want = vec![usp, unrelated];
    want.sort_unstable();
    assert_eq!(store.wg_stale_devices(&ids).await.unwrap(), want);
}

#[tokio::test]
async fn device_members_of_a_device_and_its_twin_with_network_names() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let beta = network(&store, h, "beta").await;
    let alpha = network(&store, h, "alpha").await;
    let gone = network(&store, h, "gone").await;
    let cwmp = cwmp_device(&store, "B01408", "B01408123456").await;
    let usp = usp_device(
        &store,
        "os::B01408-B01408123456",
        Some("B01408"),
        Some("B01408123456"),
    )
    .await;
    let unrelated = cwmp_device(&store, "B01408", "B01408123457").await;
    let own = add(
        &store,
        &beta,
        &device_member(cwmp, "device", &["192.168.10.0/24"]),
    )
    .await;
    let twin = add(&store, &alpha, &device_member(usp, "server", &[])).await;
    add(&store, &gone, &device_member(unrelated, "device", &[])).await;
    let revoked = add(&store, &gone, &device_member(cwmp, "device", &[])).await;
    store
        .revoke_wg_member(DEFAULT_TENANT, revoked.id, None)
        .await
        .unwrap()
        .unwrap();

    let list = store
        .list_wg_device_members(DEFAULT_TENANT, cwmp, &ALL)
        .await
        .unwrap();
    // By network name -> twin's alpha before own beta.
    // Left out: revoked member, member of unrelated device.
    assert_eq!(list.len(), 2, "{list:?}");
    assert_eq!(list[0].member, member(&store, twin.id).await);
    assert_eq!(list[0].network_name, "alpha");
    assert_eq!(list[0].via_twin, Some((usp, "usp".to_owned())));
    assert_eq!(list[1].member, member(&store, own.id).await);
    assert_eq!(list[1].member.site_prefixes.len(), 1);
    assert_eq!(list[1].network_name, "beta");
    assert_eq!(list[1].via_twin, None);
    // Same from the twin side.
    let list = store
        .list_wg_device_members(DEFAULT_TENANT, usp, &ALL)
        .await
        .unwrap();
    assert_eq!(
        list.iter()
            .map(|d| (d.member.id, d.via_twin.clone()))
            .collect::<Vec<_>>(),
        [(twin.id, None), (own.id, Some((cwmp, "cwmp".to_owned())))]
    );

    // Twin outside caller scope -> left out.
    let scope = DeviceScope {
        protocol: Some("cwmp".into()),
        ..DeviceScope::default()
    };
    let scoped = WgVisibility {
        all_clients: false,
        user_id: None,
        scope: Some(&scope),
    };
    let list = store
        .list_wg_device_members(DEFAULT_TENANT, cwmp, &scoped)
        .await
        .unwrap();
    assert_eq!(
        list.iter().map(|d| d.member.id).collect::<Vec<_>>(),
        [own.id]
    );
    // Other tenant -> nothing.
    assert!(
        store
            .list_wg_device_members(Uuid::now_v7(), cwmp, &ALL)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Device member = stale-handshake hit, unless a case changes it.
///
/// Applied, created 1 h ago, hub seen now, last handshake 30 min ago.
async fn stale_member(
    store: &Store,
    hub_id: Uuid,
    network: &WgNetwork,
    serial: &str,
) -> (Uuid, Uuid) {
    let d = device(store, serial).await;
    let m = add(store, network, &device_member(d, "device", &[])).await;
    sqlx::query(
        "UPDATE wg_members SET device_state = 'applied', created_at = now() - interval '1 hour' WHERE id = $1",
    )
    .bind(m.id)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query("UPDATE wg_hubs SET last_seen_at = now() WHERE id = $1")
        .bind(hub_id)
        .execute(store.pool())
        .await
        .unwrap();
    handshake(store, m.id, Some("30 minutes")).await;
    (d, m.id)
}

/// Hub report of a member: handshake `ago` ago, `None` = never.
async fn handshake(store: &Store, member_id: Uuid, ago: Option<&str>) {
    sqlx::query(
        r#"
        INSERT INTO wg_peer_status (member_id, latest_handshake, rx_bytes, tx_bytes, reported_at)
        VALUES ($1, now() - $2::text::interval, 0, 0, now())
        ON CONFLICT (member_id) DO UPDATE SET latest_handshake = EXCLUDED.latest_handshake
        "#,
    )
    .bind(member_id)
    .bind(ago)
    .execute(store.pool())
    .await
    .unwrap();
}

async fn stale(store: &Store, filter: &DeviceFilter) -> Vec<(Uuid, f64)> {
    store
        .wg_handshake_stale_devices(DEFAULT_TENANT, filter, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|h| (h.device_id, h.value))
        .collect()
}

#[tokio::test]
async fn a_stale_handshake_is_a_hit_and_its_minutes_the_value() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let n = network(&store, h, "n").await;
    let (d, _) = stale_member(&store, h, &n, "SN1").await;
    let hits = stale(&store, &DeviceFilter::default()).await;
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].0, d);
    assert!((hits[0].1 - 30.0).abs() < 1.0, "{hits:?}");
}

#[tokio::test]
async fn a_fresh_handshake_is_no_hit() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let n = network(&store, h, "n").await;
    let (_, m) = stale_member(&store, h, &n, "SN1").await;
    handshake(&store, m, Some("1 minute")).await;
    assert!(stale(&store, &DeviceFilter::default()).await.is_empty());
}

#[tokio::test]
async fn never_a_handshake_is_a_hit_once_past_the_grace() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let n = network(&store, h, "n").await;
    let (d, m) = stale_member(&store, h, &n, "SN1").await;
    handshake(&store, m, None).await;
    let hits = stale(&store, &DeviceFilter::default()).await;
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].0, d);
    // Minutes since member creation.
    assert!((hits[0].1 - 60.0).abs() < 1.0, "{hits:?}");
    // No report row -> same.
    sqlx::query("DELETE FROM wg_peer_status WHERE member_id = $1")
        .bind(m)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(stale(&store, &DeviceFilter::default()).await.len(), 1);
    // Member younger than grace -> no hit.
    sqlx::query("UPDATE wg_members SET created_at = now() - interval '5 minutes' WHERE id = $1")
        .bind(m)
        .execute(store.pool())
        .await
        .unwrap();
    assert!(stale(&store, &DeviceFilter::default()).await.is_empty());
}

#[tokio::test]
async fn a_member_not_applied_is_no_hit() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let n = network(&store, h, "n").await;
    let (_, m) = stale_member(&store, h, &n, "SN1").await;
    sqlx::query("UPDATE wg_members SET device_state = 'error' WHERE id = $1")
        .bind(m)
        .execute(store.pool())
        .await
        .unwrap();
    assert!(stale(&store, &DeviceFilter::default()).await.is_empty());
}

#[tokio::test]
async fn a_revoked_member_is_no_hit() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let n = network(&store, h, "n").await;
    let (_, m) = stale_member(&store, h, &n, "SN1").await;
    store
        .revoke_wg_member(DEFAULT_TENANT, m, None)
        .await
        .unwrap()
        .unwrap();
    // Revoke drops peer status. Stale row left anyway -> still no hit.
    handshake(&store, m, Some("30 minutes")).await;
    assert!(stale(&store, &DeviceFilter::default()).await.is_empty());
}

#[tokio::test]
async fn members_of_a_hub_not_reporting_are_no_hits() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let n = network(&store, h, "n").await;
    stale_member(&store, h, &n, "SN1").await;
    sqlx::query("UPDATE wg_hubs SET last_seen_at = now() - interval '6 minutes' WHERE id = $1")
        .bind(h)
        .execute(store.pool())
        .await
        .unwrap();
    assert!(stale(&store, &DeviceFilter::default()).await.is_empty());
}

#[tokio::test]
async fn stale_handshakes_follow_the_device_filter() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let n = network(&store, h, "n").await;
    let (d, _) = stale_member(&store, h, &n, "SN1").await;
    let filter = |product_class: &str| DeviceFilter {
        product_class: Some(product_class.into()),
        ..DeviceFilter::default()
    };
    // `device` -> product class LS500X.
    assert_eq!(
        stale(&store, &filter("LS500X"))
            .await
            .into_iter()
            .map(|h| h.0)
            .collect::<Vec<_>>(),
        [d]
    );
    assert!(stale(&store, &filter("Other")).await.is_empty());
}

// --- tunnel health: summary, device filter fields, device side ----------------------------

/// Last hub call: `ago` ago, `None` = never.
async fn hub_seen(store: &Store, hub_id: Uuid, ago: Option<&str>) {
    sqlx::query("UPDATE wg_hubs SET last_seen_at = now() - $2::text::interval WHERE id = $1")
        .bind(hub_id)
        .bind(ago)
        .execute(store.pool())
        .await
        .unwrap();
}

/// Server client (no owner) of `network`.
async fn server_client(store: &Store, network: &WgNetwork, n: u8) -> WgMember {
    add(
        store,
        network,
        &NewWgMember {
            id: Uuid::now_v7(),
            psk: None,
            name: format!("client-{n}"),
            kind: NewWgMemberKind::Client {
                user_id: None,
                public_key: key(n),
            },
            site_prefixes: Vec::new(),
        },
    )
    .await
}

#[tokio::test]
async fn the_health_summary_counts_live_visible_members_per_state() {
    use dhonomos_store::WgStateCounts;
    let (_c, store) = setup().await;
    let up = hub(&store, "up").await;
    let silent = hub(&store, "silent").await;
    hub_seen(&store, up, Some("10 seconds")).await;
    hub_seen(&store, silent, Some("6 minutes")).await;
    let beta = network(&store, up, "beta").await;
    let alpha = network(&store, up, "alpha").await;
    let quiet = network(&store, silent, "quiet").await;
    let empty = network(&store, up, "empty").await;

    let member = |net: &WgNetwork, serial: &'static str, ago: Option<&'static str>| {
        let store = &store;
        let net = net.clone();
        async move {
            let d = device(store, serial).await;
            let m = add(store, &net, &device_member(d, "device", &[])).await;
            if let Some(ago) = ago {
                handshake(store, m.id, if ago == "never" { None } else { Some(ago) }).await;
            }
            m
        }
    };
    member(&beta, "B1", Some("1 minute")).await;
    member(&beta, "B2", Some("5 minutes")).await;
    member(&beta, "B3", Some("20 minutes")).await;
    member(&beta, "B4", Some("never")).await;
    // No report -> never.
    member(&beta, "B5", None).await;
    let revoked = member(&beta, "B6", Some("1 minute")).await;
    store
        .revoke_wg_member(DEFAULT_TENANT, revoked.id, None)
        .await
        .unwrap()
        .unwrap();
    member(&alpha, "A1", Some("1 minute")).await;
    // Silent hub -> unknown, whatever the last report.
    member(&quiet, "Q1", Some("1 minute")).await;
    member(&quiet, "Q2", Some("never")).await;
    let client = server_client(&store, &alpha, 1).await;
    handshake(&store, client.id, Some("2 minutes")).await;

    let sum = store.wg_health_summary(DEFAULT_TENANT, &ALL).await.unwrap();
    let names: Vec<&str> = sum.networks.iter().map(|n| n.name.as_str()).collect();
    assert_eq!(names, ["alpha", "beta", "empty", "quiet"]);
    let by = |name: &str| sum.networks.iter().find(|n| n.name == name).unwrap();
    assert_eq!(
        by("beta").device,
        WgStateCounts {
            connected: 1,
            idle: 1,
            stale: 1,
            never: 2,
            unknown: 0
        }
    );
    assert_eq!(by("beta").client, WgStateCounts::default());
    assert_eq!(by("beta").hub_id, up);
    assert_eq!(by("beta").hub_name, "up");
    assert_eq!(by("alpha").device.connected, 1);
    assert_eq!(by("alpha").client.connected, 1);
    assert_eq!(by("quiet").device.unknown, 2);
    assert_eq!(by("quiet").device.total(), 2);
    assert_eq!(by("empty").device.total() + by("empty").client.total(), 0);
    assert_eq!(by("empty").id, empty.id);
    assert_eq!(
        sum.device,
        WgStateCounts {
            connected: 2,
            idle: 1,
            stale: 1,
            never: 2,
            unknown: 2
        }
    );
    assert_eq!(sum.client.total(), 1);

    // Hub never called -> silent too.
    hub_seen(&store, up, None).await;
    let sum = store.wg_health_summary(DEFAULT_TENANT, &ALL).await.unwrap();
    assert_eq!(sum.device.unknown, 8);
    hub_seen(&store, up, Some("10 seconds")).await;

    // Operator with device scope -> only devices in scope, no server client.
    // All networks still listed.
    let scope = DeviceScope {
        protocol: Some("usp".into()),
        ..DeviceScope::default()
    };
    let scoped = WgVisibility {
        all_clients: false,
        user_id: Some(Uuid::now_v7()),
        scope: Some(&scope),
    };
    let sum = store
        .wg_health_summary(DEFAULT_TENANT, &scoped)
        .await
        .unwrap();
    assert_eq!(sum.networks.len(), 4);
    assert_eq!(sum.device.total(), 0);
    assert_eq!(sum.client.total(), 0);
    // No scope, not admin -> every device member, still no server client.
    let operator = WgVisibility {
        all_clients: false,
        user_id: Some(Uuid::now_v7()),
        scope: None,
    };
    let sum = store
        .wg_health_summary(DEFAULT_TENANT, &operator)
        .await
        .unwrap();
    assert_eq!(sum.device.total(), 8);
    assert_eq!(sum.client.total(), 0);
    // Other tenant -> no networks.
    assert!(
        store
            .wg_health_summary(Uuid::now_v7(), &ALL)
            .await
            .unwrap()
            .networks
            .is_empty()
    );
}

#[tokio::test]
async fn wireguard_filter_fields_look_at_live_device_members() {
    use dhonomos_store::{DeviceSearch, FilterExpr};
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let n = network(&store, h, "n").await;
    let other = network(&store, h, "other").await;
    // A fresh, B stale, C never, D no report, E revoked (fresh), F no member,
    // G 1 fresh + 1 stale member.
    let mut members = Vec::new();
    for (serial, ago) in [
        ("A", Some("1 minute")),
        ("B", Some("20 minutes")),
        ("C", None),
        ("E", Some("1 minute")),
        ("G", Some("1 minute")),
    ] {
        let d = device(&store, serial).await;
        let m = add(&store, &n, &device_member(d, "device", &[])).await;
        handshake(&store, m.id, ago).await;
        members.push((serial, d, m.id));
    }
    let d = device(&store, "D").await;
    add(&store, &n, &device_member(d, "device", &[])).await;
    device(&store, "F").await;
    let (_, g, _) = members[4];
    let m = add(&store, &other, &device_member(g, "device", &[])).await;
    handshake(&store, m.id, Some("20 minutes")).await;
    store
        .revoke_wg_member(DEFAULT_TENANT, members[3].2, None)
        .await
        .unwrap()
        .unwrap();
    // Row left by revoked member -> not counted.
    handshake(&store, members[3].2, Some("1 minute")).await;

    let found = |expr: &'static str| {
        let store = store.clone();
        async move {
            let search = DeviceSearch {
                filter: Some(FilterExpr::parse(expr).unwrap_or_else(|e| panic!("{expr}: {e}"))),
                ..DeviceSearch::default()
            };
            let (devices, _) = store
                .search_devices(DEFAULT_TENANT, &search, 100, 0)
                .await
                .unwrap();
            let mut serials: Vec<String> = devices
                .into_iter()
                .filter_map(|d| d.serial_number)
                .collect();
            serials.sort_unstable();
            serials.join("")
        }
    };
    assert_eq!(found("wg_member = true").await, "ABCDG");
    assert_eq!(found("wg_member = false").await, "EF");
    assert_eq!(found("wg_handshake < 3m").await, "AG");
    assert_eq!(found("wg_handshake <= 3m").await, "AG");
    // Older or never. Device that is no member != "old".
    assert_eq!(found("wg_handshake > 15m").await, "BCDG");
    assert_eq!(found("wg_handshake >= 15m").await, "BCDG");
    assert_eq!(found("wg_handshake exists").await, "ABG");
    assert_eq!(
        found("wg_member = true and not wg_handshake exists").await,
        "CD"
    );
    assert_eq!(found("not wg_handshake < 3m").await, "BCDEF");
    // Unlike last_contact: there never = old.
    assert_eq!(found("last_contact > 15m").await, "");
}

/// Device parameter with `updated_at` = now - `ago`.
async fn stored(store: &Store, device: Uuid, path: &str, value: Option<&str>, ago: &str) {
    sqlx::query(
        r#"
        INSERT INTO device_params (device_id, path, value, updated_at)
        VALUES ($1, $2, $3, now() - $4::text::interval)
        "#,
    )
    .bind(device)
    .bind(path)
    .bind(value)
    .bind(ago)
    .execute(store.pool())
    .await
    .unwrap();
}

#[tokio::test]
async fn the_device_side_comes_from_the_owning_records_parameters() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let full = network(&store, h, "full").await;
    let partial = network(&store, h, "partial").await;
    let missing = network(&store, h, "missing").await;
    let twin_net = network(&store, h, "twin").await;
    let cwmp = cwmp_device(&store, "B01408", "B01408123456").await;
    let usp = usp_device(
        &store,
        "os::B01408-B01408123456",
        Some("B01408"),
        Some("B01408123456"),
    )
    .await;
    for net in [&full, &partial, &missing] {
        add(&store, net, &device_member(cwmp, "device", &[])).await;
    }
    add(&store, &twin_net, &device_member(usp, "device", &[])).await;
    let alias = |net: &WgNetwork| dhonomos_wireguard::alias_of(net.id);
    let t = "Device.WireGuard.Tunnel.";
    let p = "Device.WireGuard.Peer.";

    // "full": LS500X values, Tunnel 2 + Peer 3.
    // Not read: Tunnel of another network, Tunnel with the alias but higher instance number.
    let a = alias(&full);
    let unrelated = dhonomos_wireguard::alias_of(Uuid::now_v7());
    stored(
        &store,
        cwmp,
        &format!("{t}1.Alias"),
        Some(&unrelated),
        "1 hour",
    )
    .await;
    stored(
        &store,
        cwmp,
        &format!("{t}1.Status"),
        Some("Disabled"),
        "1 hour",
    )
    .await;
    stored(&store, cwmp, &format!("{t}2.Alias"), Some(&a), "10 minutes").await;
    stored(
        &store,
        cwmp,
        &format!("{t}2.Status"),
        Some("Enabled"),
        "10 minutes",
    )
    .await;
    stored(
        &store,
        cwmp,
        &format!("{t}2.Interface.1.Status"),
        Some("Up"),
        "10 minutes",
    )
    .await;
    stored(
        &store,
        cwmp,
        &format!("{t}2.Stats.BytesSent"),
        Some("123456"),
        "2 minutes",
    )
    .await;
    stored(
        &store,
        cwmp,
        &format!("{t}2.Stats.BytesReceived"),
        Some(" 654321 "),
        "2 minutes",
    )
    .await;
    stored(&store, cwmp, &format!("{t}10.Alias"), Some(&a), "1 minute").await;
    stored(
        &store,
        cwmp,
        &format!("{t}10.Status"),
        Some("Disabled"),
        "1 minute",
    )
    .await;
    stored(&store, cwmp, &format!("{p}3.Alias"), Some(&a), "10 minutes").await;
    stored(
        &store,
        cwmp,
        &format!("{p}3.LastHandshakeTime"),
        Some("42"),
        "10 minutes",
    )
    .await;
    // "partial": Tunnel with only alias + unreadable counter.
    // Peer with handshake never read (null value).
    let b = alias(&partial);
    stored(&store, cwmp, &format!("{t}4.Alias"), Some(&b), "30 minutes").await;
    stored(
        &store,
        cwmp,
        &format!("{t}4.Stats.BytesSent"),
        Some("lots"),
        "30 minutes",
    )
    .await;
    stored(&store, cwmp, &format!("{p}5.Alias"), Some(&b), "5 minutes").await;
    stored(
        &store,
        cwmp,
        &format!("{p}5.LastHandshakeTime"),
        None,
        "1 minute",
    )
    .await;
    // "missing": Peer only, no Tunnel.
    stored(
        &store,
        cwmp,
        &format!("{p}6.Alias"),
        Some(&alias(&missing)),
        "5 minutes",
    )
    .await;
    // Twin network: rows on the twin + decoys on this record.
    let c = alias(&twin_net);
    stored(&store, usp, &format!("{t}1.Alias"), Some(&c), "3 minutes").await;
    stored(
        &store,
        usp,
        &format!("{t}1.Status"),
        Some("Enabled"),
        "3 minutes",
    )
    .await;
    stored(&store, usp, &format!("{p}1.Alias"), Some(&c), "3 minutes").await;
    stored(
        &store,
        usp,
        &format!("{p}1.LastHandshakeTime"),
        Some("0"),
        "3 minutes",
    )
    .await;
    stored(&store, cwmp, &format!("{t}7.Alias"), Some(&c), "1 minute").await;
    stored(
        &store,
        cwmp,
        &format!("{t}7.Status"),
        Some("Disabled"),
        "1 minute",
    )
    .await;

    let list = store
        .list_wg_device_members(DEFAULT_TENANT, cwmp, &ALL)
        .await
        .unwrap();
    let side = |name: &str| {
        list.iter()
            .find(|d| d.network_name == name)
            .unwrap()
            .device_side
            .clone()
    };
    let now = time::OffsetDateTime::now_utc();
    let ago = |at: time::OffsetDateTime| (now - at).whole_seconds();

    let s = side("full").unwrap();
    assert_eq!(s.tunnel_status.as_deref(), Some("Enabled"));
    assert_eq!(s.interface_status.as_deref(), Some("Up"));
    assert_eq!(s.last_handshake_secs, Some(42));
    assert_eq!(s.bytes_sent, Some(123_456));
    assert_eq!(s.bytes_received, Some(654_321));
    // `read_at` = newest used value -> counters, 2 min ago.
    assert!((115..=125).contains(&ago(s.read_at)), "{}", ago(s.read_at));

    let s = side("partial").unwrap();
    assert_eq!(s.tunnel_status, None);
    assert_eq!(s.interface_status, None);
    assert_eq!(s.bytes_sent, None);
    assert_eq!(s.bytes_received, None);
    assert_eq!(s.last_handshake_secs, None);
    // Peer alias (5 min) newer than Tunnel's. Null value not used.
    assert!((295..=305).contains(&ago(s.read_at)), "{}", ago(s.read_at));

    assert_eq!(side("missing"), None);

    // Twin member -> rows of the twin, not decoys of this record.
    let s = side("twin").unwrap();
    assert_eq!(s.tunnel_status.as_deref(), Some("Enabled"));
    assert_eq!(s.last_handshake_secs, Some(0));
    assert!((175..=185).contains(&ago(s.read_at)), "{}", ago(s.read_at));
}
