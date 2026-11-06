//! Secrets key rotation (ADR-082), PostgreSQL container.
#![allow(clippy::unwrap_used)]

use base64::Engine as _;
use dhonomos_core::SecretBox;
use dhonomos_core::secrets::{job_context, rewrap_secrets, task_context};
use dhonomos_store::{
    CwmpIdentity, DEFAULT_TENANT, InformUpdate, NewJob, NewTask, SealedCredential, Store,
};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use serde_json::json;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use uuid::Uuid;

/// Seal as before the AAD -> nothing bound to the ciphertext.
fn legacy_seal(key: u8, plain: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[key; 32]).unwrap());
    let nonce = [5u8; NONCE_LEN];
    let mut data = plain.to_vec();
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut data)
        .unwrap();
    (data, nonce.to_vec())
}

/// `enc:v1:` payload value, old format.
fn legacy_v1(key: u8, plain: &str) -> String {
    let (ct, nonce) = legacy_seal(key, plain.as_bytes());
    let mut blob = nonce;
    blob.extend(ct);
    format!(
        "enc:v1:{}",
        base64::engine::general_purpose::STANDARD.encode(blob)
    )
}

#[tokio::test]
async fn old_secrets_are_rewrapped_under_the_new_key() {
    let c = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let port = c.get_host_port_ipv4(5432).await.unwrap();
    let store = Store::connect(
        &format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres"),
        4,
    )
    .await
    .unwrap();
    store.migrate().await.unwrap();
    let device = store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: "A".into(),
                product_class: "B".into(),
                serial_number: "C".into(),
            },
            &InformUpdate::default(),
        )
        .await
        .unwrap()
        .id;
    let b64 = |b: u8| base64::engine::general_purpose::STANDARD.encode([b; 32]);
    let old = SecretBox::from_base64(&b64(1), "k1").unwrap();

    // Old key: credential, pending task, finished task, job.
    // Also legacy ones (no AAD) under the key current after rotation.
    let (ct, nonce) = old.seal_credential(device, b"cr-password").unwrap();
    store
        .put_credential(&SealedCredential {
            device_id: device,
            kind: "connection_request".into(),
            username: "acs".into(),
            ciphertext: ct,
            nonce,
            key_id: "k1".into(),
        })
        .await
        .unwrap();
    let (ct, nonce) = legacy_seal(2, b"acs-password");
    store
        .put_credential(&SealedCredential {
            device_id: device,
            kind: "acs_auth".into(),
            username: "cpe".into(),
            ciphertext: ct,
            nonce,
            key_id: "k2".into(),
        })
        .await
        .unwrap();
    let sealed = |id: Uuid, pw: &str| {
        let mut p = json!({ "url": "http://fw", "username": "u", "password": pw });
        old.encrypt_fields(&mut p, &task_context(id)).unwrap();
        p
    };
    let queue = async |id: Uuid, payload: serde_json::Value| {
        store
            .enqueue_task_with_id(
                id,
                &NewTask::new(DEFAULT_TENANT, device, "download", payload),
            )
            .await
            .unwrap()
            .0
    };
    let pending_id = Uuid::now_v7();
    let pending = queue(pending_id, sealed(pending_id, "a")).await;
    let finished_id = Uuid::now_v7();
    let finished = queue(finished_id, sealed(finished_id, "b")).await;
    store.cancel_task(finished).await.unwrap();
    let legacy = queue(
        Uuid::now_v7(),
        json!({ "url": "http://fw", "username": "u", "password": legacy_v1(2, "d") }),
    )
    .await;
    let job_id = Uuid::now_v7();
    let mut job_payload = json!({ "url": "http://fw", "username": "u", "password": "c" });
    old.encrypt_fields(&mut job_payload, &job_context(job_id))
        .unwrap();
    let job = store
        .create_job_with_id(
            job_id,
            &NewJob {
                tenant_id: DEFAULT_TENANT,
                name: "fw".into(),
                target: Default::default(),
                task_kind: "download".into(),
                task_payload: job_payload,
                policy: json!({}),
                created_by: None,
            },
        )
        .await
        .unwrap();

    let rotating = SecretBox::from_base64(&b64(2), "k2")
        .unwrap()
        .with_old_keys(&[b64(1)])
        .unwrap();
    let done = rewrap_secrets(&store, &rotating).await.unwrap();
    assert_eq!(
        (done.credentials, done.payloads, done.unreadable),
        (2, 3, 0),
        "{done:?}"
    );
    // Nothing left -> 2nd run changes nothing.
    assert_eq!(
        rewrap_secrets(&store, &rotating).await.unwrap(),
        Default::default()
    );

    // New key alone -> opens all that is still needed.
    let new_only = SecretBox::from_base64(&b64(2), "k2").unwrap();
    let cred = store
        .get_credential(device, "connection_request")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cred.key_id, "k2");
    assert_eq!(
        new_only
            .open_credential(device, &cred.ciphertext, &cred.nonce)
            .unwrap(),
        b"cr-password"
    );
    // Now bound to its device -> no use for another device's row.
    assert!(
        new_only
            .open_credential(Uuid::now_v7(), &cred.ciphertext, &cred.nonce)
            .is_err()
    );
    // Credential from before the AAD -> current form too.
    let acs = store
        .get_credential(device, "acs_auth")
        .await
        .unwrap()
        .unwrap();
    assert!(new_only.credential_is_current(device, &acs.ciphertext, &acs.nonce));
    assert_eq!(
        new_only
            .open_credential(device, &acs.ciphertext, &acs.nonce)
            .unwrap(),
        b"acs-password"
    );
    let mut p = store.get_task(pending).await.unwrap().unwrap().payload;
    new_only
        .decrypt_fields(&mut p, &task_context(pending))
        .unwrap();
    assert_eq!(p["password"], "a");
    // Same ciphertext -> no open as another task's.
    let mut p = store.get_task(pending).await.unwrap().unwrap().payload;
    assert!(
        new_only
            .decrypt_fields(&mut p, &task_context(Uuid::now_v7()))
            .is_err()
    );
    // enc:v1: -> enc:v2: (+ bound to its task).
    let mut l = store.get_task(legacy).await.unwrap().unwrap().payload;
    assert!(l["password"].as_str().unwrap().starts_with("enc:v2:"));
    new_only
        .decrypt_fields(&mut l, &task_context(legacy))
        .unwrap();
    assert_eq!(l["password"], "d");
    let mut j = store.get_job(job).await.unwrap().unwrap().task_payload;
    new_only.decrypt_fields(&mut j, &job_context(job)).unwrap();
    assert_eq!(j["password"], "c");
    // Finished tasks left alone (never decrypted again).
    let mut f = store.get_task(finished).await.unwrap().unwrap().payload;
    assert!(
        new_only
            .decrypt_fields(&mut f, &task_context(finished))
            .is_err()
    );

    // Secret no configured key opens -> reported, not destroyed.
    let stranger = SecretBox::from_base64(&b64(9), "k9").unwrap();
    let report = rewrap_secrets(&store, &stranger).await.unwrap();
    assert_eq!(
        (report.credentials, report.unreadable),
        (0, 5),
        "{report:?}"
    );
}

/// Operator TOTP secrets (ADR-100), active + waiting for 1st code -> new key too.
/// Still bound to their account.
#[tokio::test]
async fn totp_secrets_are_rewrapped_under_the_new_key() {
    let c = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let port = c.get_host_port_ipv4(5432).await.unwrap();
    let store = Store::connect(
        &format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres"),
        4,
    )
    .await
    .unwrap();
    store.migrate().await.unwrap();
    let b64 = |b: u8| base64::engine::general_purpose::STANDARD.encode([b; 32]);
    let old = SecretBox::from_base64(&b64(1), "k1").unwrap();

    // Accounts: in use, waiting for 1st code, both (new device).
    let mut users = Vec::new();
    for name in ["in-use", "waiting", "both"] {
        users.push(
            store
                .create_user(DEFAULT_TENANT, name, "!sso", "viewer")
                .await
                .unwrap(),
        );
    }
    let (in_use, waiting, both) = (users[0], users[1], users[2]);
    let sealed = |user: Uuid, secret: &[u8]| old.seal_totp(user, secret).unwrap();
    let set_pending = async |user: Uuid, secret: &[u8]| {
        let (ct, nonce) = sealed(user, secret);
        store
            .set_pending_totp(user, &ct, &nonce, "k1")
            .await
            .unwrap();
        ct
    };
    for (user, secret) in [
        (in_use, &b"in-use-secret-0000000"[..]),
        (both, &b"both-active-00000000"[..]),
    ] {
        let ct = set_pending(user, secret).await;
        assert!(store.enable_totp(user, &ct, 5, &[], None).await.unwrap());
    }
    set_pending(waiting, b"waiting-secret-00000").await;
    set_pending(both, b"both-pending-0000000").await;

    let rotating = SecretBox::from_base64(&b64(2), "k2")
        .unwrap()
        .with_old_keys(&[b64(1)])
        .unwrap();
    let done = rewrap_secrets(&store, &rotating).await.unwrap();
    assert_eq!((done.totp, done.unreadable), (4, 0), "{done:?}");
    assert_eq!(
        rewrap_secrets(&store, &rotating).await.unwrap(),
        Default::default(),
        "nothing is left under the old key"
    );

    // New key alone opens all, each only for its own account.
    let new_only = SecretBox::from_base64(&b64(2), "k2").unwrap();
    let active = store.active_totp(in_use).await.unwrap().unwrap();
    assert_eq!(
        new_only
            .open_totp(in_use, &active.ciphertext, &active.nonce)
            .unwrap(),
        b"in-use-secret-0000000"
    );
    assert!(
        new_only
            .open_totp(both, &active.ciphertext, &active.nonce)
            .is_err()
    );
    assert_eq!(active.last_step, Some(5), "the replay guard is kept");
    let pending = store.pending_totp(waiting, 3600).await.unwrap().unwrap();
    assert_eq!(
        new_only
            .open_totp(waiting, &pending.ciphertext, &pending.nonce)
            .unwrap(),
        b"waiting-secret-00000"
    );
    let active = store.active_totp(both).await.unwrap().unwrap();
    let pending = store.pending_totp(both, 3600).await.unwrap().unwrap();
    assert_eq!(
        new_only
            .open_totp(both, &active.ciphertext, &active.nonce)
            .unwrap(),
        b"both-active-00000000"
    );
    assert_eq!(
        new_only
            .open_totp(both, &pending.ciphertext, &pending.nonce)
            .unwrap(),
        b"both-pending-0000000"
    );

    // Secret no configured key opens -> reported, not destroyed.
    let stranger = SecretBox::from_base64(&b64(9), "k9").unwrap();
    let report = rewrap_secrets(&store, &stranger).await.unwrap();
    assert_eq!((report.totp, report.unreadable), (0, 4), "{report:?}");
}

/// WireGuard PSKs (ADR-110) -> new key too, still bound to their member.
/// Hub state revision follows.
#[tokio::test]
async fn wireguard_preshared_keys_are_rewrapped_under_the_new_key() {
    let c = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let port = c.get_host_port_ipv4(5432).await.unwrap();
    let store = Store::connect(
        &format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres"),
        4,
    )
    .await
    .unwrap();
    store.migrate().await.unwrap();
    let b64 = |b: u8| base64::engine::general_purpose::STANDARD.encode([b; 32]);
    let old = SecretBox::from_base64(&b64(1), "k1").unwrap();
    let hub = store
        .create_wg_hub(DEFAULT_TENANT, "lab", "hub.example.org")
        .await
        .unwrap()
        .unwrap()
        .id;
    let network = store
        .create_wg_network(
            DEFAULT_TENANT,
            &dhonomos_store::NewWgNetwork {
                hub_id: hub,
                name: "n".into(),
                prefix: dhonomos_store::WgPrefixChoice::Explicit("10.77.0.0/24".parse().unwrap()),
                listen_port: None,
                mtu: 1420,
                persistent_keepalive: 25,
            },
        )
        .await
        .unwrap()
        .unwrap()
        .id;
    let mut members = Vec::new();
    for n in 1..=2u8 {
        let id = Uuid::now_v7();
        let psk = [n + 10; 32];
        store
            .create_wg_member(
                DEFAULT_TENANT,
                network,
                &dhonomos_store::NewWgMember {
                    id,
                    name: format!("pc{n}"),
                    kind: dhonomos_store::NewWgMemberKind::Client {
                        user_id: None,
                        public_key: b64(n + 100),
                    },
                    site_prefixes: Vec::new(),
                    psk: Some(old.seal_wg_psk(id, &psk).unwrap()),
                },
                time::Duration::hours(24),
            )
            .await
            .unwrap()
            .unwrap();
        members.push((id, psk));
    }

    let rotating = SecretBox::from_base64(&b64(2), "k2")
        .unwrap()
        .with_old_keys(&[b64(1)])
        .unwrap();
    let before = store.wg_hub_revision(hub).await.unwrap().unwrap();
    let done = rewrap_secrets(&store, &rotating).await.unwrap();
    assert_eq!((done.wg_psks, done.unreadable), (2, 0), "{done:?}");
    assert!(store.wg_hub_revision(hub).await.unwrap().unwrap() > before);
    assert_eq!(
        rewrap_secrets(&store, &rotating).await.unwrap(),
        Default::default(),
        "nothing is left under the old key"
    );
    let new_only = SecretBox::from_base64(&b64(2), "k2").unwrap();
    for (id, psk) in &members {
        let (ct, nonce) = store
            .wg_member_psk(DEFAULT_TENANT, *id)
            .await
            .unwrap()
            .unwrap();
        assert!(new_only.wg_psk_is_current(*id, &ct, &nonce));
        assert_eq!(
            new_only.open_wg_psk(*id, &ct, &nonce).unwrap().as_slice(),
            psk
        );
        assert!(new_only.open_wg_psk(Uuid::now_v7(), &ct, &nonce).is_err());
    }
    // PSK no configured key opens -> reported, not destroyed.
    let stranger = SecretBox::from_base64(&b64(9), "k9").unwrap();
    let report = rewrap_secrets(&store, &stranger).await.unwrap();
    assert_eq!((report.wg_psks, report.unreadable), (0, 2), "{report:?}");
}
