//! Certificates of USP Agents, on a throwaway PostgreSQL container.
#![allow(clippy::unwrap_used)]

use dhonomos_store::{CwmpIdentity, DEFAULT_TENANT, InformUpdate, Store};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

async fn setup() -> (ContainerAsync<Postgres>, Store) {
    let container = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let store = Store::connect(&url, 4).await.unwrap();
    store.migrate().await.unwrap();
    (container, store)
}

async fn issue(store: &Store, device: Uuid, serial: &str, days: i64) -> Uuid {
    store
        .record_certificate(
            DEFAULT_TENANT,
            device,
            serial,
            &format!("fp-{serial}"),
            OffsetDateTime::now_utc() + Duration::days(days),
            true,
            None,
        )
        .await
        .unwrap()
}

/// EndpointIDs that must prove themselves with a certificate = USP devices with a
/// non-revoked certificate, any age.
#[tokio::test]
async fn certificate_bound_endpoints_are_those_with_an_unrevoked_certificate() {
    let (_c, store) = setup().await;
    let usp = |eid: &'static str| {
        let store = store.clone();
        async move {
            store
                .upsert_usp_device(DEFAULT_TENANT, eid, None)
                .await
                .unwrap()
                .id
        }
    };
    let alice = usp("os::alice").await;
    let bob = usp("os::bob").await;
    let _carol = usp("os::carol").await;
    let cwmp = store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: "202BC1".into(),
                product_class: "BM632w".into(),
                serial_number: "SN1".into(),
            },
            &InformUpdate::default(),
        )
        .await
        .unwrap()
        .id;

    assert!(
        store
            .certificate_bound_endpoints(DEFAULT_TENANT)
            .await
            .unwrap()
            .is_empty()
    );

    // Alice: 2 (renewed), Bob: 1 expired, Carol: none.
    // CWMP device with a certificate -> no EndpointID to bind.
    let old = issue(&store, alice, "a1", 30).await;
    issue(&store, alice, "a2", 365).await;
    issue(&store, bob, "b1", -1).await;
    issue(&store, cwmp, "c1", 30).await;
    let mut bound = store
        .certificate_bound_endpoints(DEFAULT_TENANT)
        .await
        .unwrap();
    bound.sort();
    assert_eq!(bound, ["os::alice", "os::bob"]);

    // Revoke 1 of Alice's -> still bound. Revoke her last, or Bob's -> released.
    store
        .revoke_certificate(alice, old, Some("op"), None)
        .await
        .unwrap();
    let certs = store.device_certificates(alice).await.unwrap();
    assert_eq!(
        store
            .certificate_bound_endpoints(DEFAULT_TENANT)
            .await
            .unwrap()
            .len(),
        2
    );
    for c in certs.iter().filter(|c| c.revoked_at.is_none()) {
        store
            .revoke_certificate(alice, c.id, Some("op"), Some("stolen"))
            .await
            .unwrap();
    }
    let bobs = store.device_certificates(bob).await.unwrap();
    store
        .revoke_certificate(bob, bobs[0].id, None, None)
        .await
        .unwrap();
    assert!(
        store
            .certificate_bound_endpoints(DEFAULT_TENANT)
            .await
            .unwrap()
            .is_empty()
    );
    // Certificates of another tenant: not ours.
    assert!(
        store
            .certificate_bound_endpoints(Uuid::now_v7())
            .await
            .unwrap()
            .is_empty()
    );
}

/// Bundle targets: found by ID or EndpointID within the tenant.
/// Bulk record -> all together, as generated-key certificates, EndpointID bound.
#[tokio::test]
async fn bundle_targets_are_found_and_recorded_together() {
    let (_c, store) = setup().await;
    let alice = store
        .preregister_usp_device(DEFAULT_TENANT, "os::alice", &[])
        .await
        .unwrap()
        .id;
    let bob = store
        .upsert_usp_device(DEFAULT_TENANT, "os::bob", None)
        .await
        .unwrap()
        .id;
    let cwmp = store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: "202BC1".into(),
                product_class: "BM632w".into(),
                serial_number: "SN1".into(),
            },
            &InformUpdate::default(),
        )
        .await
        .unwrap()
        .id;

    let found = store
        .certificate_targets(
            DEFAULT_TENANT,
            &[alice, cwmp, Uuid::now_v7()],
            &["os::bob".into(), "os::nobody".into(), "os::alice".into()],
        )
        .await
        .unwrap();
    let mut by_id: Vec<_> = found.iter().map(|t| (t.id, t.protocol.as_str())).collect();
    by_id.sort();
    let mut expected = vec![(alice, "usp"), (bob, "usp"), (cwmp, "cwmp")];
    expected.sort();
    assert_eq!(by_id, expected, "alice once, though named twice");
    assert!(found.iter().all(|t| t.status == "active"));
    assert!(
        store
            .certificate_targets(Uuid::now_v7(), &[alice], &["os::bob".into()])
            .await
            .unwrap()
            .is_empty(),
        "another tenant's devices are not ours"
    );
    assert!(
        store
            .certificate_targets(DEFAULT_TENANT, &[], &[])
            .await
            .unwrap()
            .is_empty()
    );

    let soon = OffsetDateTime::now_utc() + Duration::days(30);
    let cert = |device: Uuid, serial: &str| dhonomos_store::NewCertificate {
        device_id: device,
        serial: serial.into(),
        fingerprint: format!("fp-{serial}"),
        not_after: soon,
    };
    store
        .record_certificates(
            DEFAULT_TENANT,
            Some("op"),
            &[cert(alice, "s1"), cert(bob, "s2")],
        )
        .await
        .unwrap();
    for (device, serial) in [(alice, "s1"), (bob, "s2")] {
        let recorded = store.device_certificates(device).await.unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].serial, serial);
        assert_eq!(recorded[0].fingerprint, format!("fp-{serial}"));
        assert!(!recorded[0].from_csr);
        assert_eq!(recorded[0].issued_by.as_deref(), Some("op"));
    }
    let mut bound = store
        .certificate_bound_endpoints(DEFAULT_TENANT)
        .await
        .unwrap();
    bound.sort();
    assert_eq!(bound, ["os::alice", "os::bob"]);

    // All or none: 1 clashing serial -> whole batch fails.
    let clash = store
        .record_certificates(DEFAULT_TENANT, None, &[cert(alice, "s3"), cert(bob, "s2")])
        .await;
    assert!(clash.is_err());
    assert_eq!(store.device_certificates(alice).await.unwrap().len(), 1);
    // Empty batch -> ok.
    store
        .record_certificates(DEFAULT_TENANT, None, &[])
        .await
        .unwrap();
}

/// Batch pre-registration, 1 statement: new devices get the tags, existing ones returned
/// as they are. Lookup changes nothing.
#[tokio::test]
async fn devices_are_preregistered_in_batches() {
    let (_c, store) = setup().await;
    let old = store
        .preregister_usp_device(DEFAULT_TENANT, "os::old", &["kept".into()])
        .await
        .unwrap()
        .id;
    let eids: Vec<String> = ["os::new-1", "os::old", "os::new-2"]
        .map(String::from)
        .into();
    let tags = vec!["lab".to_owned()];

    let found = store.find_usp_devices(DEFAULT_TENANT, &eids).await.unwrap();
    assert_eq!(found.len(), 1, "a lookup finds what exists");
    assert_eq!(
        (found["os::old"].id, found["os::old"].created),
        (old, false)
    );
    assert!(
        store
            .find_usp_devices(Uuid::now_v7(), &eids)
            .await
            .unwrap()
            .is_empty(),
        "another tenant has none of them"
    );

    let made = store
        .preregister_usp_devices(DEFAULT_TENANT, &eids, &tags)
        .await
        .unwrap();
    assert_eq!(made.len(), 3);
    assert_eq!((made["os::old"].id, made["os::old"].created), (old, false));
    assert!(made["os::new-1"].created && made["os::new-2"].created);
    assert_ne!(made["os::new-1"].id, made["os::new-2"].id);
    for (eid, expected) in [
        ("os::new-1", &tags[..]),
        ("os::old", &["kept".to_owned()][..]),
    ] {
        let d = store.get_device(made[eid].id).await.unwrap().unwrap();
        assert_eq!((d.protocol.as_str(), d.status.as_str()), ("usp", "active"));
        assert_eq!(d.tags, expected, "{eid}");
    }
    // Again -> nothing new.
    let again = store
        .preregister_usp_devices(DEFAULT_TENANT, &eids, &tags)
        .await
        .unwrap();
    assert!(again.values().all(|k| !k.created));
    assert_eq!(again["os::new-1"].id, made["os::new-1"].id);
    assert!(
        store
            .preregister_usp_devices(DEFAULT_TENANT, &[], &tags)
            .await
            .unwrap()
            .is_empty()
    );

    // CWMP devices, by identity (product class is part of it).
    let id = |class: &str, serial: &str| CwmpIdentity {
        oui: "00AA00".into(),
        product_class: class.into(),
        serial_number: serial.into(),
    };
    let existing = store
        .preregister_cwmp_device(DEFAULT_TENANT, &id("Box", "S1"), &["kept".into()])
        .await
        .unwrap();
    let wanted = [id("Box", "S1"), id("", "S1"), id("Box", "S2")];
    let found = store
        .find_cwmp_devices(DEFAULT_TENANT, &wanted)
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[&wanted[0]].id, existing.id);
    let made = store
        .preregister_cwmp_devices(DEFAULT_TENANT, &wanted, &tags)
        .await
        .unwrap();
    assert_eq!(made.len(), 3);
    assert_eq!(
        (made[&wanted[0]].id, made[&wanted[0]].created),
        (existing.id, false)
    );
    assert!(made[&wanted[1]].created && made[&wanted[2]].created);
    let d = store
        .get_device(made[&wanted[1]].id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (d.protocol.as_str(), d.product_class.as_str(), d.tags),
        ("cwmp", "", tags.clone())
    );
}

/// Certificates recorded with the Agents they are for: Agents registered with own tags,
/// same transaction. Agent registered in the meantime -> certificate goes to that device.
#[tokio::test]
async fn certificates_are_recorded_with_the_agents_they_register() {
    let (_c, store) = setup().await;
    let soon = OffsetDateTime::now_utc() + Duration::days(30);
    let cert = |device: Uuid, serial: &str| dhonomos_store::NewCertificate {
        device_id: device,
        serial: serial.into(),
        fingerprint: format!("fp-{serial}"),
        not_after: soon,
    };
    let agent = |eid: &str, tags: &[&str]| dhonomos_store::NewUspDevice {
        id: Uuid::now_v7(),
        endpoint_id: eid.into(),
        tags: tags.iter().map(|t| (*t).to_owned()).collect(),
    };
    let existing = store
        .preregister_usp_device(DEFAULT_TENANT, "os::existing", &[])
        .await
        .unwrap()
        .id;
    let (a, b, raced) = (
        agent("os::new-a", &["x", "y"]),
        agent("os::new-b", &[]),
        agent("os::raced", &["lost"]),
    );
    // Agent `raced`: registered by someone else before the record.
    let winner = store
        .preregister_usp_device(DEFAULT_TENANT, "os::raced", &["won".into()])
        .await
        .unwrap()
        .id;
    store
        .record_certificates_creating(
            DEFAULT_TENANT,
            Some("op"),
            &[a.clone(), b.clone(), raced.clone()],
            &[
                cert(a.id, "s1"),
                cert(b.id, "s2"),
                cert(raced.id, "s3"),
                cert(existing, "s4"),
            ],
        )
        .await
        .unwrap();
    for (eid, tags) in [("os::new-a", vec!["x", "y"]), ("os::new-b", vec![])] {
        let id = store
            .find_usp_device(DEFAULT_TENANT, eid)
            .await
            .unwrap()
            .unwrap();
        let d = store.get_device(id).await.unwrap().unwrap();
        assert_eq!(d.tags, tags, "{eid}");
        assert_eq!(
            store.device_certificates(id).await.unwrap().len(),
            1,
            "{eid}"
        );
    }
    assert_eq!(store.device_certificates(existing).await.unwrap().len(), 1);
    let certs = store.device_certificates(winner).await.unwrap();
    assert_eq!(
        certs.len(),
        1,
        "the certificate follows the device that exists"
    );
    assert_eq!(
        store.get_device(winner).await.unwrap().unwrap().tags,
        ["won"],
        "that device keeps its tags"
    );
    assert!(
        store.get_device(raced.id).await.unwrap().is_none(),
        "the ID that lost is not used"
    );
    let mut bound = store
        .certificate_bound_endpoints(DEFAULT_TENANT)
        .await
        .unwrap();
    bound.sort();
    assert_eq!(
        bound,
        ["os::existing", "os::new-a", "os::new-b", "os::raced"]
    );

    // All or none: clashing serial number -> no Agent registered either.
    let late = agent("os::late", &[]);
    let clash = store
        .record_certificates_creating(
            DEFAULT_TENANT,
            None,
            std::slice::from_ref(&late),
            &[cert(late.id, "s1")],
        )
        .await;
    assert!(clash.is_err());
    assert!(
        store
            .find_usp_device(DEFAULT_TENANT, "os::late")
            .await
            .unwrap()
            .is_none(),
        "nothing was registered"
    );
}

/// Raw certificate row of a fingerprint (device, endpoint, revocation).
async fn row(
    store: &Store,
    fingerprint: &str,
) -> (Option<Uuid>, Option<String>, Option<String>, Option<String>) {
    sqlx::query_as(
        "SELECT device_id, endpoint_id, revoked_by, revoke_reason FROM usp_certificates
         WHERE fingerprint = $1",
    )
    .bind(fingerprint)
    .fetch_one(store.pool())
    .await
    .unwrap()
}

/// Issued certificates stay valid after device delete -> delete revokes them first + keeps
/// the rows (device NULL, EndpointID kept) -> still in the revoked set the MTPs enforce.
/// Other devices keep their certificates.
#[tokio::test]
async fn deleting_a_device_revokes_its_certificates_and_keeps_the_rows() {
    let (_c, store) = setup().await;
    let usp = |eid: &'static str| {
        let store = store.clone();
        async move {
            store
                .upsert_usp_device(DEFAULT_TENANT, eid, None)
                .await
                .unwrap()
                .id
        }
    };
    let alice = usp("os::alice").await;
    let bob = usp("os::bob").await;
    let cwmp = store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: "202BC1".into(),
                product_class: "BM632w".into(),
                serial_number: "SN1".into(),
            },
            &InformUpdate::default(),
        )
        .await
        .unwrap()
        .id;

    // Alice: live, renewed, revoked before, expired. Bob + CWMP device: 1 each.
    let first = issue(&store, alice, "a1", 30).await;
    issue(&store, alice, "a2", 365).await;
    issue(&store, alice, "a3", 90).await;
    issue(&store, alice, "a4", -2).await;
    issue(&store, bob, "b1", 365).await;
    issue(&store, cwmp, "c1", 365).await;
    store
        .revoke_certificate(alice, first, Some("earlier"), Some("lost"))
        .await
        .unwrap();
    let revoked_before = store.revoked_fingerprints(DEFAULT_TENANT).await.unwrap();
    assert_eq!(revoked_before, ["fp-a1"]);

    // Delete in another tenant, or of an unknown device -> no change.
    assert!(
        store
            .delete_device(Uuid::now_v7(), alice, Some("op"))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .delete_device(DEFAULT_TENANT, Uuid::now_v7(), Some("op"))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(store.device_certificates(alice).await.unwrap().len(), 4);

    let deleted = store
        .delete_device(DEFAULT_TENANT, alice, Some("op"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        deleted.certificates_revoked, 3,
        "the live ones and the expired one, not the one revoked before"
    );
    assert!(store.get_device(alice).await.unwrap().is_none());
    assert!(store.device_certificates(alice).await.unwrap().is_empty());

    // Rows survive without device. Ones revoked now: reason + who.
    for fp in ["fp-a2", "fp-a3", "fp-a4"] {
        let (device, endpoint, by, reason) = row(&store, fp).await;
        assert_eq!(device, None, "{fp}");
        assert_eq!(endpoint.as_deref(), Some("os::alice"), "{fp}");
        assert_eq!(by.as_deref(), Some("op"), "{fp}");
        assert_eq!(reason.as_deref(), Some("device deleted"), "{fp}");
    }
    let (device, endpoint, by, reason) = row(&store, "fp-a1").await;
    assert_eq!(
        (
            device,
            endpoint.as_deref(),
            by.as_deref(),
            reason.as_deref()
        ),
        (None, Some("os::alice"), Some("earlier"), Some("lost")),
        "an earlier revocation stands"
    );

    // All unexpired certificates of the deleted device -> revoked set (expired one fails the
    // TLS handshake anyway). Bob + CWMP device untouched.
    let mut revoked = store.revoked_fingerprints(DEFAULT_TENANT).await.unwrap();
    revoked.sort();
    assert_eq!(revoked, ["fp-a1", "fp-a2", "fp-a3"]);
    assert_eq!(
        store
            .certificate_bound_endpoints(DEFAULT_TENANT)
            .await
            .unwrap(),
        ["os::bob"],
        "Alice's EndpointID is not bound by revoked certificates"
    );
    // Listings skip rows with no device or revoked; still work.
    let expiring = store
        .expiring_certificates(DEFAULT_TENANT, 400, None, 100)
        .await
        .unwrap();
    let mut serials: Vec<_> = expiring.iter().map(|c| c.serial.as_str()).collect();
    serials.sort();
    assert_eq!(serials, ["b1", "c1"]);
    assert_eq!(store.device_certificates(bob).await.unwrap().len(), 1);
    assert!(
        store.device_certificates(bob).await.unwrap()[0]
            .revoked_at
            .is_none()
    );

    // Certificates of the deleted device: still found + revoked by fingerprint.
    let found = store
        .revoke_fingerprint(DEFAULT_TENANT, "fp-a2", None, Some("other"), Some("again"))
        .await
        .unwrap();
    assert!(found.known);
    assert_eq!(found.device_id, None);
    assert_eq!(found.serial.as_deref(), Some("a2"));
    assert_eq!(
        found.revoked_by.as_deref(),
        Some("op"),
        "the first revocation stands"
    );

    // Other devices delete as before: CWMP device (1 certificate), Carol (none).
    let none = store
        .delete_device(DEFAULT_TENANT, cwmp, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(none.certificates_revoked, 1);
    let carol = usp("os::carol").await;
    let none = store
        .delete_device(DEFAULT_TENANT, carol, Some("op"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(none.certificates_revoked, 0);
}

/// Certificate with record gone -> revoke by fingerprint.
/// Unknown -> new revoked record (MTPs refuse it). Known -> normal revoke. Again -> no change.
#[tokio::test]
async fn certificates_are_revoked_by_fingerprint() {
    let (_c, store) = setup().await;
    let alice = store
        .upsert_usp_device(DEFAULT_TENANT, "os::alice", None)
        .await
        .unwrap()
        .id;
    issue(&store, alice, "a1", 365).await;
    assert_eq!(
        store
            .certificate_bound_endpoints(DEFAULT_TENANT)
            .await
            .unwrap(),
        ["os::alice"]
    );

    // Unknown -> recorded as revoked, no device, serial number or expiry.
    let lost = "ab".repeat(32);
    let r = store
        .revoke_fingerprint(
            DEFAULT_TENANT,
            &lost,
            Some("os::lost"),
            Some("op"),
            Some("record lost"),
        )
        .await
        .unwrap();
    assert!(!r.known);
    assert_eq!(r.fingerprint, lost);
    assert_eq!(
        (r.device_id, r.serial.as_deref(), r.not_after),
        (None, None, None)
    );
    assert_eq!(r.endpoint_id.as_deref(), Some("os::lost"));
    assert_eq!(
        (r.revoked_by.as_deref(), r.revoke_reason.as_deref()),
        (Some("op"), Some("record lost"))
    );
    assert_eq!(
        store.revoked_fingerprints(DEFAULT_TENANT).await.unwrap(),
        [lost.as_str()],
        "an unknown expiry keeps it in the revoked set"
    );
    assert_eq!(
        store
            .certificate_bound_endpoints(DEFAULT_TENANT)
            .await
            .unwrap(),
        ["os::alice"],
        "a revoked record binds no EndpointID"
    );
    assert!(
        store
            .expiring_certificates(DEFAULT_TENANT, 3650, None, 100)
            .await
            .unwrap()
            .iter()
            .all(|c| c.serial == "a1")
    );

    // Again, other user + other reason -> first revocation stands.
    // Missing EndpointID filled in, existing one not replaced.
    let again = store
        .revoke_fingerprint(
            DEFAULT_TENANT,
            &lost,
            Some("os::other"),
            Some("second"),
            Some("later"),
        )
        .await
        .unwrap();
    assert!(again.known);
    assert_eq!(again.id, r.id);
    assert_eq!(again.revoked_at, r.revoked_at);
    assert_eq!(
        (again.revoked_by.as_deref(), again.revoke_reason.as_deref()),
        (Some("op"), Some("record lost"))
    );
    assert_eq!(again.endpoint_id.as_deref(), Some("os::lost"));
    assert_eq!(
        store
            .revoked_fingerprints(DEFAULT_TENANT)
            .await
            .unwrap()
            .len(),
        1
    );
    let bare = "cd".repeat(32);
    store
        .revoke_fingerprint(DEFAULT_TENANT, &bare, None, None, None)
        .await
        .unwrap();
    let filled = store
        .revoke_fingerprint(DEFAULT_TENANT, &bare, Some("os::late"), None, None)
        .await
        .unwrap();
    assert_eq!(filled.endpoint_id.as_deref(), Some("os::late"));

    // Known -> revoked like any other certificate of the device, EndpointID released.
    let known = store
        .revoke_fingerprint(DEFAULT_TENANT, "fp-a1", None, Some("op"), Some("stolen"))
        .await
        .unwrap();
    assert!(known.known);
    assert_eq!(known.device_id, Some(alice));
    assert_eq!(known.serial.as_deref(), Some("a1"));
    assert_eq!(known.endpoint_id.as_deref(), Some("os::alice"));
    let certs = store.device_certificates(alice).await.unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].revoked_by.as_deref(), Some("op"));
    assert_eq!(certs[0].revoke_reason.as_deref(), Some("stolen"));
    assert!(
        store
            .certificate_bound_endpoints(DEFAULT_TENANT)
            .await
            .unwrap()
            .is_empty()
    );
    let mut revoked = store.revoked_fingerprints(DEFAULT_TENANT).await.unwrap();
    revoked.sort();
    assert_eq!(revoked, [lost.as_str(), bare.as_str(), "fp-a1"]);

    // Same fingerprint in another tenant = another certificate.
    let other = Uuid::now_v7();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, 'other')")
        .bind(other)
        .execute(store.pool())
        .await
        .unwrap();
    let theirs = store
        .revoke_fingerprint(other, &lost, None, None, None)
        .await
        .unwrap();
    assert!(!theirs.known);
    assert_ne!(theirs.id, r.id);
    assert_eq!(
        store.revoked_fingerprints(other).await.unwrap(),
        [lost.as_str()]
    );
}

/// Row with a device needs serial number + expiry. Only rows revoked by fingerprint may
/// lack them.
#[tokio::test]
async fn certificates_of_devices_need_a_serial_and_an_expiry() {
    let (_c, store) = setup().await;
    let alice = store
        .upsert_usp_device(DEFAULT_TENANT, "os::alice", None)
        .await
        .unwrap()
        .id;
    let insert = |serial: Option<&'static str>, expiry: Option<OffsetDateTime>| {
        let store = store.clone();
        async move {
            sqlx::query(
                "INSERT INTO usp_certificates (id, tenant_id, device_id, serial, fingerprint,
                                               not_after, from_csr)
                 VALUES ($1, $2, $3, $4, $5, $6, false)",
            )
            .bind(Uuid::now_v7())
            .bind(DEFAULT_TENANT)
            .bind(alice)
            .bind(serial)
            .bind(format!("fp-{serial:?}-{expiry:?}"))
            .bind(expiry)
            .execute(store.pool())
            .await
        }
    };
    let soon = Some(OffsetDateTime::now_utc() + Duration::days(1));
    assert!(insert(None, soon).await.is_err());
    assert!(insert(Some("s1"), None).await.is_err());
    assert!(insert(Some("s1"), soon).await.is_ok());
}

/// Certificates recorded before EndpointID was on the row -> migration fills it from the
/// device. Device delete no longer takes them along.
#[tokio::test]
async fn existing_certificates_get_their_endpoint_id_when_migrated() {
    let container = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let store = Store::connect(&url, 4).await.unwrap();
    let migrator = sqlx::migrate!("./migrations");
    migrator.run_to(25, store.pool()).await.unwrap();

    let alice = store
        .upsert_usp_device(DEFAULT_TENANT, "os::alice", None)
        .await
        .unwrap()
        .id;
    let cwmp = store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: "202BC1".into(),
                product_class: "BM632w".into(),
                serial_number: "SN1".into(),
            },
            &InformUpdate::default(),
        )
        .await
        .unwrap()
        .id;
    for (device, serial) in [(alice, "a1"), (cwmp, "c1")] {
        sqlx::query(
            "INSERT INTO usp_certificates (id, tenant_id, device_id, serial, fingerprint,
                                           not_after, from_csr)
             VALUES ($1, $2, $3, $4, $5, now() + interval '30 days', true)",
        )
        .bind(Uuid::now_v7())
        .bind(DEFAULT_TENANT)
        .bind(device)
        .bind(serial)
        .bind(format!("fp-{serial}"))
        .execute(store.pool())
        .await
        .unwrap();
    }

    store.migrate().await.unwrap();
    assert_eq!(
        row(&store, "fp-a1").await,
        (Some(alice), Some("os::alice".to_owned()), None, None)
    );
    assert_eq!(row(&store, "fp-c1").await, (Some(cwmp), None, None, None));
    assert_eq!(
        store
            .certificate_bound_endpoints(DEFAULT_TENANT)
            .await
            .unwrap(),
        ["os::alice"]
    );

    // DB itself keeps the row when the device goes (even if not revoked).
    sqlx::query("DELETE FROM devices WHERE id = $1")
        .bind(alice)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        row(&store, "fp-a1").await,
        (None, Some("os::alice".to_owned()), None, None)
    );
    assert_eq!(
        store
            .certificate_bound_endpoints(DEFAULT_TENANT)
            .await
            .unwrap(),
        ["os::alice"],
        "an unrevoked certificate still binds its EndpointID"
    );
}
