//! WireGuard hubs, networks, members + site prefixes, throwaway PostgreSQL container
//! (ADR-110, docs/design/13-wireguard.md).
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

use dhonomos_store::{
    CwmpIdentity, DEFAULT_TENANT, DeviceScope, InformUpdate, NewWgMember, NewWgMemberKind,
    NewWgNetwork, Store, WgMember, WgNetwork, WgNetworkPatch, WgPrefixChoice, WgRefusal,
    WgSitePrefix, WgVisibility,
};
use dhonomos_wireguard::{Ipv4Prefix, NetworkPrefixError, SitePrefixError};
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

fn pool() -> Ipv4Prefix {
    p("10.77.0.0/16")
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

fn auto(hub_id: Uuid, name: &str, len: u8) -> NewWgNetwork {
    NewWgNetwork {
        hub_id,
        name: name.into(),
        prefix: WgPrefixChoice::Auto { len, pool: pool() },
        listen_port: None,
        mtu: 1420,
        persistent_keepalive: 25,
    }
}

async fn network(store: &Store, hub_id: Uuid, name: &str, len: u8) -> WgNetwork {
    store
        .create_wg_network(DEFAULT_TENANT, &auto(hub_id, name, len))
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
                description: format!("lan {s}"),
            })
            .collect(),
    }
}

/// Distinct 44-char key per number.
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

async fn refused(store: &Store, network: &WgNetwork, new: &NewWgMember) -> WgRefusal {
    store
        .create_wg_member(DEFAULT_TENANT, network.id, new, DAY)
        .await
        .unwrap()
        .unwrap_err()
}

#[tokio::test]
async fn networks_take_prefixes_ports_and_refuse_overlaps() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;

    let a = network(&store, h, "a", 24).await;
    assert_eq!(a.ipv4_prefix, p("10.77.0.0/24"));
    assert_eq!(
        (a.listen_port, a.mtu, a.persistent_keepalive),
        (51820, 1420, 25)
    );
    // Second network -> next block + next port on the same hub.
    let b = network(&store, h, "b", 24).await;
    assert_eq!((b.ipv4_prefix, b.listen_port), (p("10.77.1.0/24"), 51821));
    // Other size -> aligned to itself.
    let c = network(&store, h, "c", 25).await;
    assert_eq!(c.ipv4_prefix, p("10.77.2.0/25"));
    // Network on another hub -> first port again, but shares the tenant prefixes.
    let h2 = hub(&store, "lab2").await;
    let d = network(&store, h2, "d", 24).await;
    assert_eq!((d.ipv4_prefix, d.listen_port), (p("10.77.3.0/24"), 51820));

    // Explicit prefix: may be outside the pool, must not overlap another network.
    let explicit = |prefix: &str, name: &str| NewWgNetwork {
        prefix: WgPrefixChoice::Explicit(p(prefix)),
        ..auto(h, name, 24)
    };
    let e = store
        .create_wg_network(DEFAULT_TENANT, &explicit("192.168.200.0/24", "e"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(e.ipv4_prefix, p("192.168.200.0/24"));
    for (prefix, other) in [
        ("10.77.0.0/24", "10.77.0.0/24"),
        ("10.77.0.0/16", "10.77.0.0/24"),
        ("10.77.1.128/25", "10.77.1.0/24"),
        ("192.168.200.0/23", "192.168.200.0/24"),
    ] {
        let err = store
            .create_wg_network(DEFAULT_TENANT, &explicit(prefix, "x"))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(
            err,
            WgRefusal::NetworkPrefix(NetworkPrefixError::Overlaps {
                prefix: p(prefix),
                other: p(other)
            }),
            "{prefix}"
        );
    }
    // Taken name, taken port.
    let err = store
        .create_wg_network(DEFAULT_TENANT, &explicit("192.168.201.0/24", "a"))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err, WgRefusal::NetworkNameTaken("a".into()));
    let err = store
        .create_wg_network(
            DEFAULT_TENANT,
            &NewWgNetwork {
                listen_port: Some(51821),
                ..explicit("192.168.201.0/24", "f")
            },
        )
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err, WgRefusal::PortTaken(51821));
    // Free explicit port -> used; default then skips taken ports.
    let g = store
        .create_wg_network(
            DEFAULT_TENANT,
            &NewWgNetwork {
                listen_port: Some(51830),
                ..explicit("192.168.201.0/24", "g")
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(g.listen_port, 51830);
    // Refusals -> nothing created.
    let names: Vec<_> = store
        .list_wg_networks(DEFAULT_TENANT, &ALL)
        .await
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .collect();
    assert_eq!(names, ["a", "b", "c", "d", "e", "g"]);

    // Hub that does not exist.
    let err = store
        .create_wg_network(DEFAULT_TENANT, &auto(Uuid::now_v7(), "z", 24))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err, WgRefusal::HubNotFound);
}

#[tokio::test]
async fn the_address_pool_runs_out() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let small = |name: &str| NewWgNetwork {
        prefix: WgPrefixChoice::Auto {
            len: 25,
            pool: p("10.99.0.0/24"),
        },
        ..auto(h, name, 25)
    };
    for (name, want) in [("a", "10.99.0.0/25"), ("b", "10.99.0.128/25")] {
        let n = store
            .create_wg_network(DEFAULT_TENANT, &small(name))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n.ipv4_prefix, p(want));
    }
    let err = store
        .create_wg_network(DEFAULT_TENANT, &small("c"))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(
        err,
        WgRefusal::NetworkPrefix(NetworkPrefixError::Exhausted {
            len: 25,
            pool: p("10.99.0.0/24")
        })
    );
    // Network deleted -> its block free.
    let a = store.list_wg_networks(DEFAULT_TENANT, &ALL).await.unwrap()[0].id;
    assert_eq!(
        store.delete_wg_network(DEFAULT_TENANT, a).await.unwrap(),
        Ok(0)
    );
    let n = store
        .create_wg_network(DEFAULT_TENANT, &small("c"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n.ipv4_prefix, p("10.99.0.0/25"));
}

#[tokio::test]
async fn concurrent_creations_get_distinct_prefixes_and_addresses() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    // 8 networks at once.
    let mut tasks = Vec::new();
    for i in 0..8 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store
                .create_wg_network(DEFAULT_TENANT, &auto(h, &format!("n{i}"), 24))
                .await
                .unwrap()
                .unwrap()
        }));
    }
    let mut networks = Vec::new();
    for t in tasks {
        networks.push(t.await.unwrap());
    }
    let prefixes: BTreeSet<_> = networks.iter().map(|n| n.ipv4_prefix.to_string()).collect();
    let ports: BTreeSet<_> = networks.iter().map(|n| n.listen_port).collect();
    assert_eq!(prefixes.len(), 8, "{prefixes:?}");
    assert_eq!(ports.len(), 8, "{ports:?}");
    assert_eq!(
        prefixes.iter().next().map(String::as_str),
        Some("10.77.0.0/24")
    );
    assert_eq!(
        prefixes.iter().last().map(String::as_str),
        Some("10.77.7.0/24")
    );

    // 20 members at once in one network (first prefix; which task got it varies).
    let net = networks
        .iter()
        .find(|n| n.ipv4_prefix.to_string() == "10.77.0.0/24")
        .unwrap();
    let mut tasks = Vec::new();
    for i in 0..20u8 {
        let (store, id) = (store.clone(), net.id);
        tasks.push(tokio::spawn(async move {
            store
                .create_wg_member(
                    DEFAULT_TENANT,
                    id,
                    &client(None, &format!("c{i}"), key(i)),
                    DAY,
                )
                .await
                .unwrap()
                .unwrap()
        }));
    }
    let mut addresses = BTreeSet::new();
    for t in tasks {
        addresses.insert(t.await.unwrap().address);
    }
    let want: BTreeSet<_> = (2..22u8)
        .map(|i| std::net::Ipv4Addr::new(10, 77, 0, i))
        .collect();
    assert_eq!(addresses, want, "no address twice, none skipped");
}

#[tokio::test]
async fn members_get_hosts_not_the_hub_and_wait_out_the_reuse_delay() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n", 24).await;
    let d1 = device(&store, "SN1").await;
    let d2 = device(&store, "SN2").await;

    let m1 = add(&store, &net, &device_member(d1, "first", &[])).await;
    assert_eq!(m1.address.to_string(), "10.77.0.2", "the hub has .1");
    assert_eq!(
        (
            m1.kind.as_str(),
            m1.key_mode.as_deref(),
            m1.public_key.as_deref()
        ),
        ("device", Some("device"), None),
        "no key is made or sent in stage 1"
    );
    let m2 = add(&store, &net, &client(None, "second", key(1))).await;
    assert_eq!(m2.address.to_string(), "10.77.0.3");
    let m3 = add(&store, &net, &device_member(d2, "third", &[])).await;
    assert_eq!(m3.address.to_string(), "10.77.0.4");

    // Revoked address -> not given out within the delay; next member skips it.
    let (revoked, changed) = store
        .revoke_wg_member(DEFAULT_TENANT, m2.id, Some("lost laptop"))
        .await
        .unwrap()
        .unwrap();
    assert!(changed && revoked.revoked_at.is_some());
    assert_eq!(revoked.revoked_reason.as_deref(), Some("lost laptop"));
    let m4 = add(&store, &net, &client(None, "fourth", key(2))).await;
    assert_eq!(m4.address.to_string(), "10.77.0.5");
    // No delay -> free at once; lowest free host wins.
    let m5 = store
        .create_wg_member(
            DEFAULT_TENANT,
            net.id,
            &client(None, "fifth", key(3)),
            Duration::ZERO,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(m5.address.to_string(), "10.77.0.3");
    // Revoked row stays, with old address. Order: address, then age.
    let (all, total) = store
        .list_wg_members(DEFAULT_TENANT, net.id, &ALL, true, 100, 0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(total, 5);
    assert_eq!(
        all.iter()
            .map(|m| (m.address.to_string(), m.revoked_at.is_some()))
            .collect::<Vec<_>>(),
        [
            ("10.77.0.2".to_owned(), false),
            ("10.77.0.3".to_owned(), true),
            ("10.77.0.3".to_owned(), false),
            ("10.77.0.4".to_owned(), false),
            ("10.77.0.5".to_owned(), false),
        ]
    );
    let counts = store
        .get_wg_network(DEFAULT_TENANT, net.id, &ALL)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            counts.device_members,
            counts.client_members,
            counts.revoked_members
        ),
        (2, 2, 1)
    );
    let (page, total) = store
        .list_wg_members(DEFAULT_TENANT, net.id, &ALL, false, 2, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((page.len(), total), (2, 4), "revoked rows hidden, paged");
    assert_eq!(page[0].address.to_string(), "10.77.0.3");

    // Revoke again -> no change, first reason kept.
    let (again, changed) = store
        .revoke_wg_member(DEFAULT_TENANT, m2.id, Some("other"))
        .await
        .unwrap()
        .unwrap();
    assert!(!changed);
    assert_eq!(again.revoked_reason.as_deref(), Some("lost laptop"));
    assert_eq!(again.revoked_at, revoked.revoked_at);
    assert_eq!(
        store
            .revoke_wg_member(DEFAULT_TENANT, Uuid::now_v7(), None)
            .await
            .unwrap()
            .unwrap_err(),
        WgRefusal::MemberNotFound
    );
}

#[tokio::test]
async fn a_small_network_fills_up_without_the_broadcast_address() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "tiny", 29).await;
    let mut got = Vec::new();
    for i in 0..5u8 {
        got.push(
            add(&store, &net, &client(None, &format!("c{i}"), key(i)))
                .await
                .address
                .to_string(),
        );
    }
    // 10.77.0.0/29: .0 network, .1 hub, .2-.6 members, .7 broadcast.
    assert_eq!(
        got,
        [
            "10.77.0.2",
            "10.77.0.3",
            "10.77.0.4",
            "10.77.0.5",
            "10.77.0.6"
        ]
    );
    assert_eq!(
        refused(&store, &net, &client(None, "extra", key(9))).await,
        WgRefusal::NetworkFull(p("10.77.0.0/29"))
    );
}

#[tokio::test]
async fn live_members_are_unique_by_device_and_key_but_revoked_ones_do_not_count() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n", 24).await;
    let other = network(&store, h, "o", 24).await;
    let d = device(&store, "SN1").await;

    let first = add(&store, &net, &device_member(d, "cpe", &[])).await;
    assert_eq!(
        refused(&store, &net, &device_member(d, "again", &[])).await,
        WgRefusal::DeviceAlreadyMember
    );
    // Other network -> other membership.
    add(&store, &other, &device_member(d, "cpe", &[])).await;
    // Not a device of this tenant.
    assert_eq!(
        refused(&store, &net, &device_member(Uuid::now_v7(), "ghost", &[])).await,
        WgRefusal::DeviceNotFound
    );
    // Revoked -> device can join again, new row.
    store
        .revoke_wg_member(DEFAULT_TENANT, first.id, None)
        .await
        .unwrap()
        .unwrap();
    let second = add(&store, &net, &device_member(d, "cpe", &[])).await;
    assert_ne!(second.id, first.id);

    add(&store, &net, &client(None, "pc", key(1))).await;
    assert_eq!(
        refused(&store, &net, &client(None, "dup", key(1))).await,
        WgRefusal::KeyInUse
    );
    // Same key in another network -> fine; new key too.
    add(&store, &other, &client(None, "pc", key(1))).await;
    let c2 = add(&store, &net, &client(None, "pc2", key(2))).await;
    store
        .revoke_wg_member(DEFAULT_TENANT, c2.id, None)
        .await
        .unwrap()
        .unwrap();
    add(&store, &net, &client(None, "pc2 again", key(2))).await;

    // Revoked member -> no change.
    assert_eq!(
        store
            .update_wg_member(DEFAULT_TENANT, c2.id, Some("x"), None, None)
            .await
            .unwrap()
            .unwrap_err(),
        WgRefusal::MemberRevoked
    );
}

#[tokio::test]
async fn site_prefixes_are_checked_across_the_members_of_a_network() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n", 24).await;
    let other = network(&store, h, "o", 24).await;
    let (d1, d2, d3) = (
        device(&store, "SN1").await,
        device(&store, "SN2").await,
        device(&store, "SN3").await,
    );

    let m1 = add(
        &store,
        &net,
        &device_member(d1, "one", &["192.168.10.0/24", "172.20.0.0/16"]),
    )
    .await;
    assert_eq!(
        m1.site_prefixes
            .iter()
            .map(|s| s.prefix.to_string())
            .collect::<Vec<_>>(),
        ["172.20.0.0/16", "192.168.10.0/24"],
        "by prefix"
    );
    assert_eq!(m1.site_prefixes[1].description, "lan 192.168.10.0/24");

    // Other member of the same network: no overlapping prefix...
    for (prefix, conflict) in [
        ("192.168.10.0/24", "192.168.10.0/24"),
        ("192.168.10.128/25", "192.168.10.0/24"),
        ("172.20.5.0/24", "172.20.0.0/16"),
        ("172.16.0.0/12", "172.20.0.0/16"),
    ] {
        let err = refused(&store, &net, &device_member(d2, "two", &[prefix])).await;
        assert_eq!(
            err,
            WgRefusal::SitePrefix(SitePrefixError::OverlapsMember {
                prefix: p(prefix),
                other: p(conflict)
            }),
            "{prefix}"
        );
    }
    // ...nor one overlapping the tunnel prefix.
    assert_eq!(
        refused(&store, &net, &device_member(d2, "two", &["10.77.0.0/16"])).await,
        WgRefusal::SitePrefix(SitePrefixError::OverlapsNetwork {
            prefix: p("10.77.0.0/16"),
            network: p("10.77.0.0/24")
        })
    );
    // Refused members -> nothing kept, not even the member row.
    let (all, _) = store
        .list_wg_members(DEFAULT_TENANT, net.id, &ALL, true, 100, 0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(all.len(), 1);
    // Other network -> own space.
    add(
        &store,
        &other,
        &device_member(d2, "two", &["192.168.10.0/24"]),
    )
    .await;
    // Free prefix -> fine.
    let m3 = add(
        &store,
        &net,
        &device_member(d3, "three", &["192.168.30.0/24"]),
    )
    .await;

    // Replaced list -> checked against the others; refusal keeps the old list.
    let err = store
        .update_wg_member(
            DEFAULT_TENANT,
            m3.id,
            Some("renamed"),
            Some(&[
                WgSitePrefix {
                    prefix: p("192.168.40.0/24"),
                    description: String::new(),
                },
                WgSitePrefix {
                    prefix: p("172.20.1.0/24"),
                    description: String::new(),
                },
            ]),
            None,
        )
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        err,
        WgRefusal::SitePrefix(SitePrefixError::OverlapsMember { .. })
    ));
    let kept = store
        .get_wg_member(DEFAULT_TENANT, m3.id, &ALL)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kept.name, "three", "the name did not change either");
    assert_eq!(kept.site_prefixes.len(), 1);
    assert_eq!(kept.site_prefixes[0].prefix, p("192.168.30.0/24"));
    // Own prefixes of a member -> no collision with themselves.
    let updated = store
        .update_wg_member(
            DEFAULT_TENANT,
            m3.id,
            None,
            Some(&[WgSitePrefix {
                prefix: p("192.168.30.0/25"),
                description: "half".into(),
            }]),
            None,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.name, "three");
    assert_eq!(updated.site_prefixes[0].description, "half");
    // Empty list -> clears them; none given -> keeps them.
    let cleared = store
        .update_wg_member(DEFAULT_TENANT, m3.id, None, Some(&[]), None)
        .await
        .unwrap()
        .unwrap();
    assert!(cleared.site_prefixes.is_empty());

    // Revoked member -> its prefixes free again.
    store
        .revoke_wg_member(DEFAULT_TENANT, m1.id, None)
        .await
        .unwrap()
        .unwrap();
    add(
        &store,
        &net,
        &device_member(d2, "two", &["192.168.10.0/24"]),
    )
    .await;
}

#[tokio::test]
async fn the_prefix_of_a_network_with_live_members_cannot_change() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n", 24).await;
    let _other = network(&store, h, "o", 24).await;
    let member = add(&store, &net, &client(None, "pc", key(1))).await;
    let to = |prefix: &str| WgNetworkPatch {
        ipv4_prefix: Some(p(prefix)),
        ..WgNetworkPatch::default()
    };

    let err = store
        .update_wg_network(DEFAULT_TENANT, net.id, &to("10.88.0.0/24"))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err, WgRefusal::NetworkHasMembers);
    // Current prefix named -> no change.
    store
        .update_wg_network(DEFAULT_TENANT, net.id, &to("10.77.0.0/24"))
        .await
        .unwrap()
        .unwrap();
    // Other fields change freely.
    let n = store
        .update_wg_network(
            DEFAULT_TENANT,
            net.id,
            &WgNetworkPatch {
                name: Some("renamed".into()),
                mtu: Some(1412),
                persistent_keepalive: Some(0),
                listen_port: Some(51900),
                ..WgNetworkPatch::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            n.name.as_str(),
            n.mtu,
            n.persistent_keepalive,
            n.listen_port,
            n.ipv4_prefix
        ),
        ("renamed", 1412, 0, 51900, p("10.77.0.0/24"))
    );
    // All members revoked -> prefix change allowed. Must still avoid other networks.
    store
        .revoke_wg_member(DEFAULT_TENANT, member.id, None)
        .await
        .unwrap()
        .unwrap();
    let err = store
        .update_wg_network(DEFAULT_TENANT, net.id, &to("10.77.1.0/24"))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        err,
        WgRefusal::NetworkPrefix(NetworkPrefixError::Overlaps { .. })
    ));
    let n = store
        .update_wg_network(DEFAULT_TENANT, net.id, &to("10.88.0.0/24"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n.ipv4_prefix, p("10.88.0.0/24"));
    // Revoked rows keep old address; new members start at .2 of the new prefix,
    // whatever old rows hold.
    let fresh = add(&store, &n, &client(None, "pc2", key(2))).await;
    assert_eq!(fresh.address.to_string(), "10.88.0.2");
    // Name + port unique.
    let err = store
        .update_wg_network(
            DEFAULT_TENANT,
            net.id,
            &WgNetworkPatch {
                name: Some("o".into()),
                ..WgNetworkPatch::default()
            },
        )
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err, WgRefusal::NetworkNameTaken("o".into()));
    let err = store
        .update_wg_network(
            DEFAULT_TENANT,
            net.id,
            &WgNetworkPatch {
                listen_port: Some(51821),
                ..WgNetworkPatch::default()
            },
        )
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err, WgRefusal::PortTaken(51821));
}

#[tokio::test]
async fn hubs_with_networks_stay_and_deleting_a_network_takes_its_members() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    assert_eq!(
        store
            .create_wg_hub(DEFAULT_TENANT, "lab", "other.example.org")
            .await
            .unwrap()
            .unwrap_err(),
        WgRefusal::HubNameTaken("lab".into())
    );
    let net = network(&store, h, "n", 24).await;
    let d = device(&store, "SN1").await;
    add(&store, &net, &device_member(d, "cpe", &["192.168.1.0/24"])).await;
    add(&store, &net, &client(None, "pc", key(1))).await;

    assert_eq!(
        store.delete_wg_hub(DEFAULT_TENANT, h).await.unwrap(),
        Err(WgRefusal::HubHasNetworks)
    );
    assert_eq!(
        store
            .get_wg_hub(DEFAULT_TENANT, h)
            .await
            .unwrap()
            .unwrap()
            .networks,
        1
    );
    // Hub rename + move.
    let moved = store
        .update_wg_hub(DEFAULT_TENANT, h, Some("renamed"), Some("203.0.113.9"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (moved.name.as_str(), moved.endpoint_host.as_str()),
        ("renamed", "203.0.113.9")
    );
    assert_eq!(
        store
            .update_wg_hub(DEFAULT_TENANT, Uuid::now_v7(), Some("x"), None)
            .await
            .unwrap(),
        Err(WgRefusal::HubNotFound)
    );

    // 2 live members deleted with the network, site prefixes too.
    assert_eq!(
        store
            .delete_wg_network(DEFAULT_TENANT, net.id)
            .await
            .unwrap(),
        Ok(2)
    );
    assert_eq!(sqlx_count(&store, "wg_members").await, 0);
    assert_eq!(sqlx_count(&store, "wg_site_prefixes").await, 0);
    assert_eq!(
        store
            .delete_wg_network(DEFAULT_TENANT, net.id)
            .await
            .unwrap(),
        Err(WgRefusal::NetworkNotFound)
    );
    assert_eq!(
        store.delete_wg_hub(DEFAULT_TENANT, h).await.unwrap(),
        Ok(())
    );
    assert_eq!(
        store.delete_wg_hub(DEFAULT_TENANT, h).await.unwrap(),
        Err(WgRefusal::HubNotFound)
    );
}

async fn sqlx_count(store: &Store, table: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(store.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn tenants_cannot_see_each_others_wireguard_data() {
    let (_c, store) = setup().await;
    let other = Uuid::now_v7();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, 'other')")
        .bind(other)
        .execute(store.pool())
        .await
        .unwrap();
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n", 24).await;
    let member = add(&store, &net, &client(None, "pc", key(1))).await;

    // Same names + same prefix free in the other tenant.
    let oh = store
        .create_wg_hub(other, "lab", "hub.example.org")
        .await
        .unwrap()
        .unwrap();
    let onet = store
        .create_wg_network(other, &auto(oh.id, "n", 24))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        onet.ipv4_prefix, net.ipv4_prefix,
        "tenants have their own pool"
    );
    assert_eq!(onet.listen_port, 51820);

    // Data of the first tenant: not visible, not changeable in the second.
    assert_eq!(store.list_wg_hubs(other).await.unwrap().len(), 1);
    assert!(store.get_wg_hub(other, h).await.unwrap().is_none());
    assert!(
        store
            .get_wg_network(other, net.id, &ALL)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_wg_member(other, member.id, &ALL)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .list_wg_members(other, net.id, &ALL, true, 10, 0)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .update_wg_hub(other, h, Some("x"), None)
            .await
            .unwrap(),
        Err(WgRefusal::HubNotFound)
    );
    assert_eq!(
        store
            .update_wg_network(other, net.id, &WgNetworkPatch::default())
            .await
            .unwrap(),
        Err(WgRefusal::NetworkNotFound)
    );
    assert_eq!(
        store
            .revoke_wg_member(other, member.id, None)
            .await
            .unwrap(),
        Err(WgRefusal::MemberNotFound)
    );
    assert_eq!(
        store.delete_wg_member(other, member.id).await.unwrap(),
        Err(WgRefusal::MemberNotFound)
    );
    assert_eq!(
        store.delete_wg_network(other, net.id).await.unwrap(),
        Err(WgRefusal::NetworkNotFound)
    );
    assert_eq!(
        store.delete_wg_hub(other, h).await.unwrap(),
        Err(WgRefusal::HubNotFound)
    );
    // Network: not on a hub of another tenant, not with its device.
    assert_eq!(
        store
            .create_wg_network(other, &auto(h, "x", 24))
            .await
            .unwrap()
            .unwrap_err(),
        WgRefusal::HubNotFound
    );
    let d = device(&store, "SN1").await;
    assert_eq!(
        store
            .create_wg_member(other, onet.id, &device_member(d, "cpe", &[]), DAY)
            .await
            .unwrap()
            .unwrap_err(),
        WgRefusal::DeviceNotFound
    );
    // Data of the first tenant all still there.
    assert!(
        store
            .get_wg_member(DEFAULT_TENANT, member.id, &ALL)
            .await
            .unwrap()
            .is_some()
    );
}

/// Names of network members the caller may see.
/// Also checks: member counts of the network follow the same rule.
async fn visible_names(store: &Store, network_id: Uuid, vis: WgVisibility<'_>) -> Vec<String> {
    let (items, total) = store
        .list_wg_members(DEFAULT_TENANT, network_id, &vis, true, 100, 0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(items.len() as i64, total);
    let counted = store
        .get_wg_network(DEFAULT_TENANT, network_id, &vis)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        counted.device_members + counted.client_members,
        total,
        "the counts follow the same rule"
    );
    items.into_iter().map(|m| m.name).collect()
}

async fn sees(store: &Store, id: Uuid, vis: WgVisibility<'_>) -> bool {
    store
        .get_wg_member(DEFAULT_TENANT, id, &vis)
        .await
        .unwrap()
        .is_some()
}

#[tokio::test]
async fn members_are_seen_by_device_scope_and_by_owner() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n", 24).await;
    let (east, west) = (device(&store, "EAST").await, device(&store, "WEST").await);
    store
        .update_device(DEFAULT_TENANT, east, Some(&["east".to_owned()]), None)
        .await
        .unwrap();
    store
        .update_device(DEFAULT_TENANT, west, Some(&["west".to_owned()]), None)
        .await
        .unwrap();
    let alice = store
        .create_user(DEFAULT_TENANT, "alice", "x", "operator")
        .await
        .unwrap();
    let bob = store
        .create_user(DEFAULT_TENANT, "bob", "x", "operator")
        .await
        .unwrap();
    let m_east = add(&store, &net, &device_member(east, "east", &[])).await;
    let m_west = add(&store, &net, &device_member(west, "west", &[])).await;
    let c_alice = add(&store, &net, &client(Some(alice), "alice-pc", key(1))).await;
    let c_bob = add(&store, &net, &client(Some(bob), "bob-pc", key(2))).await;
    let c_server = add(&store, &net, &client(None, "server", key(3))).await;

    let east_scope = DeviceScope {
        tags: vec!["east".into()],
        ..DeviceScope::default()
    };
    // Admin -> sees all.
    assert_eq!(visible_names(&store, net.id, ALL).await.len(), 5);
    // Unscoped operator -> all devices, own clients only.
    let mine = visible_names(
        &store,
        net.id,
        WgVisibility {
            all_clients: false,
            user_id: Some(alice),
            scope: None,
        },
    )
    .await;
    assert_eq!(mine, ["east", "west", "alice-pc"]);
    // Scoped operator -> devices in scope; clients only own ones.
    let scoped = visible_names(
        &store,
        net.id,
        WgVisibility {
            all_clients: false,
            user_id: Some(bob),
            scope: Some(&east_scope),
        },
    )
    .await;
    assert_eq!(scoped, ["east", "bob-pc"]);
    // Account = nobody (token without account) -> no clients unless admin.
    let nobody = visible_names(
        &store,
        net.id,
        WgVisibility {
            all_clients: false,
            user_id: None,
            scope: Some(&east_scope),
        },
    )
    .await;
    assert_eq!(nobody, ["east"]);

    // Single members -> same rule.
    let scoped_bob = WgVisibility {
        all_clients: false,
        user_id: Some(bob),
        scope: Some(&east_scope),
    };
    assert!(sees(&store, m_east.id, scoped_bob).await);
    assert!(
        !sees(&store, m_west.id, scoped_bob).await,
        "outside the scope"
    );
    assert!(sees(&store, c_bob.id, scoped_bob).await);
    assert!(
        !sees(&store, c_alice.id, scoped_bob).await,
        "someone else's"
    );
    assert!(
        !sees(&store, c_server.id, scoped_bob).await,
        "a server client is an admin's"
    );
    assert!(sees(&store, c_server.id, ALL).await);

    // Device deleted -> its membership too.
    assert!(
        store
            .delete_device(DEFAULT_TENANT, east, None)
            .await
            .unwrap()
            .is_some()
    );
    assert!(!sees(&store, m_east.id, ALL).await);
}

#[tokio::test]
async fn an_account_that_cannot_own_clients_loses_them_in_the_same_transaction() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n", 24).await;
    let other_net = network(&store, h, "o", 24).await;
    let hash = "x";
    let mk = |name: &'static str, role: &'static str| {
        let store = store.clone();
        async move {
            store
                .create_user(DEFAULT_TENANT, name, hash, role)
                .await
                .unwrap()
        }
    };
    let (disabled, deleted, demoted, scoped, safe, promoted) = (
        mk("disabled", "operator").await,
        mk("deleted", "operator").await,
        mk("demoted", "admin").await,
        mk("scoped", "operator").await,
        mk("safe", "operator").await,
        mk("promoted", "operator").await,
    );
    let mut ids = std::collections::HashMap::new();
    for (i, (name, user)) in [
        ("disabled", disabled),
        ("deleted", deleted),
        ("demoted", demoted),
        ("scoped", scoped),
        ("safe", safe),
        ("promoted", promoted),
    ]
    .into_iter()
    .enumerate()
    {
        // 1 client in each of 2 networks.
        let a = add(&store, &net, &client(Some(user), name, key(i as u8 * 2))).await;
        let b = add(
            &store,
            &other_net,
            &client(Some(user), name, key(i as u8 * 2 + 1)),
        )
        .await;
        ids.insert(name, (user, a.id, b.id));
    }
    let revoked = |name: &'static str| {
        let store = store.clone();
        let (_, a, b) = ids[name];
        async move {
            let mut out = Vec::new();
            for id in [a, b] {
                let m = store
                    .get_wg_member(DEFAULT_TENANT, id, &ALL)
                    .await
                    .unwrap()
                    .unwrap();
                out.push((m.revoked_at.is_some(), m.revoked_reason, m.user_id));
            }
            out
        }
    };

    // Disable.
    let done = store
        .update_user(disabled, None, Some(true), None, None)
        .await
        .unwrap();
    assert!(done.found);
    assert_eq!(done.revoked_clients.len(), 2);
    assert!(
        done.revoked_clients
            .iter()
            .all(|r| r.reason == "user disabled")
    );
    assert_eq!(
        revoked("disabled").await,
        [
            (true, Some("user disabled".to_owned()), Some(disabled)),
            (true, Some("user disabled".to_owned()), Some(disabled))
        ]
    );
    // Role below operator.
    let done = store
        .update_user(demoted, Some("viewer"), None, None, None)
        .await
        .unwrap();
    assert_eq!(done.revoked_clients.len(), 2);
    assert_eq!(
        revoked("demoted").await[0].1.as_deref(),
        Some("role changed")
    );
    // Role that may still own clients -> keeps them; same for enable or password.
    for (role, disabled_now) in [
        (Some("admin"), None),
        (Some("operator"), Some(false)),
        (None, None),
    ] {
        let done = store
            .update_user(promoted, role, disabled_now, Some("newhash"), None)
            .await
            .unwrap();
        assert!(done.found && done.revoked_clients.is_empty());
    }
    assert!(!revoked("promoted").await[0].0);
    // Device scope.
    let scope = DeviceScope {
        tags: vec!["east".into()],
        ..DeviceScope::default()
    };
    let done = store.set_user_scope(scoped, Some(&scope)).await.unwrap();
    assert_eq!(done.revoked_clients.len(), 2);
    assert_eq!(
        revoked("scoped").await[1].1.as_deref(),
        Some("scope changed")
    );
    // Scope cleared -> nothing revoked.
    let done = store.set_user_scope(safe, None).await.unwrap();
    assert!(done.found && done.revoked_clients.is_empty());
    assert!(!revoked("safe").await[0].0);
    // Delete -> revoked first, rows stay without owner.
    let done = store.delete_user(deleted).await.unwrap();
    assert!(done.found);
    assert_eq!(done.revoked_clients.len(), 2);
    assert_eq!(
        revoked("deleted").await,
        [
            (true, Some("user deleted".to_owned()), None),
            (true, Some("user deleted".to_owned()), None)
        ],
        "revoked, and no longer pointing at anyone"
    );
    // Revoked clients -> not revoked x2, first reason kept.
    let again = store
        .update_user(disabled, Some("viewer"), None, None, None)
        .await
        .unwrap();
    assert!(again.revoked_clients.is_empty());
    assert_eq!(
        revoked("disabled").await[0].1.as_deref(),
        Some("user disabled")
    );
    // Unknown accounts.
    let ghost = Uuid::now_v7();
    assert!(
        !store
            .update_user(ghost, None, Some(true), None, None)
            .await
            .unwrap()
            .found
    );
    assert!(
        !store
            .set_user_scope(ghost, Some(&scope))
            .await
            .unwrap()
            .found
    );
    assert!(!store.delete_user(ghost).await.unwrap().found);
    // Untouched one -> still has both.
    assert_eq!(revoked("safe").await.iter().filter(|r| r.0).count(), 0);
}

#[tokio::test]
async fn the_database_refuses_what_the_server_should_never_write() {
    let (_c, store) = setup().await;
    let h = hub(&store, "lab").await;
    let net = network(&store, h, "n", 24).await;
    let d = device(&store, "SN1").await;
    let member = add(&store, &net, &device_member(d, "cpe", &[])).await;
    let run = |sql: String| {
        let store = store.clone();
        async move {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(store.pool())
                .await
                .is_err()
        }
    };
    // Client needs a key; device needs a device + key mode; client has no device;
    // only clients have owners.
    let net_id = net.id;
    // Each row: own address + device not yet a member -> only the rule under test can refuse.
    let d2 = device(&store, "SN2").await;
    let next = std::cell::Cell::new(100u8);
    let insert = |cols: &str, vals: &str| {
        next.set(next.get() + 1);
        run(format!(
            "INSERT INTO wg_members (id, network_id, name, address, {cols}) VALUES ('{}', '{net_id}', 'x', '10.77.0.{}', {vals})",
            Uuid::now_v7(),
            next.get()
        ))
    };
    // Statements below valid except for the one thing each tests.
    // Well-formed one -> goes in (removed again).
    assert!(
        !insert("kind, public_key", &format!("'client', '{}'", key(1))).await,
        "control: a plain client row is accepted"
    );
    assert!(
        !insert(
            "kind, device_id, key_mode, device_state",
            &format!("'device', '{d2}', 'server', 'pending'")
        )
        .await,
        "control: so is a plain device row"
    );
    assert!(
        !run(format!(
            "UPDATE wg_networks SET mtu = 1400, listen_port = 51999, persistent_keepalive = 0 WHERE id = '{net_id}'"
        ))
        .await,
        "control: valid network numbers"
    );
    run(format!(
        "DELETE FROM wg_members WHERE network_id = '{net_id}' AND name = 'x'"
    ))
    .await;
    assert!(insert("kind", "'client'").await, "no key");
    assert!(
        insert("kind, public_key", "'client', 'short'").await,
        "bad key length"
    );
    assert!(
        insert(
            "kind, public_key, key_mode",
            &format!("'client', '{}', 'device'", key(1))
        )
        .await,
        "clients have no key mode"
    );
    assert!(insert("kind", "'device'").await, "no device");
    assert!(
        insert(
            "kind, device_id, key_mode",
            &format!("'device', '{d2}', 'server'")
        )
        .await,
        "a device member has a device state"
    );
    assert!(
        insert(
            "kind, public_key, device_state",
            &format!("'client', '{}', 'pending'", key(1))
        )
        .await,
        "clients have no device state"
    );
    assert!(
        insert(
            "kind, device_id, key_mode, device_state",
            &format!("'device', '{d2}', 'server', 'done'")
        )
        .await,
        "unknown device state"
    );
    assert!(insert("kind", "'router'").await, "unknown kind");
    assert!(
        insert(
            "kind, device_id, key_mode",
            &format!("'device', '{d2}', 'cloud'")
        )
        .await,
        "unknown key mode"
    );
    assert!(
        insert(
            "kind, device_id, key_mode, user_id",
            &format!(
                "'device', '{}', 'device', '{}'",
                Uuid::now_v7(),
                Uuid::now_v7()
            )
        )
        .await,
        "no such device"
    );
    // Address = single IPv4 host.
    assert!(
        run(format!(
            "UPDATE wg_members SET address = '10.77.0.0/24' WHERE id = '{}'",
            member.id
        ))
        .await
    );
    assert!(
        run(format!(
            "UPDATE wg_members SET address = 'fd00::2' WHERE id = '{}'",
            member.id
        ))
        .await
    );
    assert!(
        run(format!(
            "UPDATE wg_members SET revoked_reason = 'x' WHERE id = '{}'",
            member.id
        ))
        .await,
        "a reason without a revocation"
    );
    // Networks: IPv4, canonical, 16-29, sane numbers.
    for (col, val) in [
        ("ipv4_prefix", "'10.77.0.1/24'"),
        ("ipv4_prefix", "'10.77.0.0/30'"),
        ("ipv4_prefix", "'10.0.0.0/15'"),
        ("ipv4_prefix", "'fd00::/64'"),
        ("mtu", "1279"),
        ("mtu", "1501"),
        ("listen_port", "0"),
        ("listen_port", "65536"),
        ("persistent_keepalive", "-1"),
        ("persistent_keepalive", "65536"),
    ] {
        assert!(
            run(format!(
                "UPDATE wg_networks SET {col} = {val} WHERE id = '{net_id}'"
            ))
            .await,
            "{col} = {val}"
        );
    }
    // Hub keys = 44 chars.
    assert!(
        run(format!(
            "UPDATE wg_hubs SET public_key = 'short' WHERE id = '{h}'"
        ))
        .await
    );
    assert!(
        !run(format!(
            "UPDATE wg_hubs SET public_key = '{}' WHERE id = '{h}'",
            key(5)
        ))
        .await
    );
}
