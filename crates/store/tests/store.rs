//! Integration tests, throwaway PostgreSQL container (testcontainers).
#![allow(clippy::unwrap_used)]

use dhonomos_store::{
    CwmpIdentity, DEFAULT_TENANT, InformUpdate, NewTask, ParamUpdate, Store, TaskState,
};
use serde_json::json;
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

fn ident(serial: &str) -> CwmpIdentity {
    CwmpIdentity {
        oui: "202BC1".into(),
        product_class: "BM632w".into(),
        serial_number: serial.into(),
    }
}

async fn device(store: &Store, serial: &str) -> Uuid {
    store
        .upsert_cwmp_device(DEFAULT_TENANT, &ident(serial), &InformUpdate::default())
        .await
        .unwrap()
        .id
}

#[tokio::test]
async fn device_upsert_keeps_known_fields() {
    let (_c, store) = setup().await;
    let first = InformUpdate {
        manufacturer: Some("Huawei".into()),
        software_version: Some("V1".into()),
        connection_request_url: Some("http://[2001:db8::1]:7547/".into()),
        remote_addr: Some("2001:db8::1".parse().unwrap()),
        booted: true,
        ..InformUpdate::default()
    };
    let a = store
        .upsert_cwmp_device(DEFAULT_TENANT, &ident("SN1"), &first)
        .await
        .unwrap();
    assert!(a.created);

    let second = InformUpdate {
        software_version: Some("V2".into()),
        ..InformUpdate::default()
    };
    let b = store
        .upsert_cwmp_device(DEFAULT_TENANT, &ident("SN1"), &second)
        .await
        .unwrap();
    assert_eq!((b.id, b.created), (a.id, false));

    let d = store.get_device(a.id).await.unwrap().unwrap();
    assert_eq!(d.software_version.as_deref(), Some("V2"));
    assert_eq!(
        d.manufacturer.as_deref(),
        Some("Huawei"),
        "None keeps the stored value"
    );
    assert_eq!(d.last_remote_addr.as_deref(), Some("2001:db8::1"));
    assert!(d.last_boot_at.is_some() && d.last_contact_at.is_some());
    assert_eq!(d.protocol, "cwmp");

    assert_eq!(
        store
            .find_cwmp_device(DEFAULT_TENANT, &ident("SN1"))
            .await
            .unwrap(),
        Some(a.id)
    );
    assert_eq!(
        store
            .list_devices(DEFAULT_TENANT, 10, 0)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn tenants_are_isolated() {
    let (_c, store) = setup().await;
    let other = Uuid::now_v7();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, 'other')")
        .bind(other)
        .execute(store.pool())
        .await
        .unwrap();
    let a = device(&store, "SN1").await;
    let b = store
        .upsert_cwmp_device(other, &ident("SN1"), &InformUpdate::default())
        .await
        .unwrap();
    assert!(b.created);
    assert_ne!(a, b.id);
}

#[tokio::test]
async fn params_merge_and_prefix_queries() {
    let (_c, store) = setup().await;
    let d = device(&store, "SN1").await;
    let p = |path: &str, value: Option<&str>, writable: Option<bool>| ParamUpdate {
        path: path.into(),
        value: value.map(Into::into),
        xsd_type: value.map(|_| "string".into()),
        writable,
    };
    store
        .upsert_params(
            d,
            &[
                p("Device.DeviceInfo.SoftwareVersion", Some("V1"), None),
                p("Device.DeviceInfo.SerialNumber", Some("SN1"), None),
                p("Device.ManagementServer.URL", Some("http://acs"), None),
            ],
        )
        .await
        .unwrap();
    // GPN: writability only -> value must stay.
    store
        .upsert_params(
            d,
            &[p("Device.DeviceInfo.SoftwareVersion", None, Some(false))],
        )
        .await
        .unwrap();

    let info = store.get_params(d, "Device.DeviceInfo.").await.unwrap();
    assert_eq!(info.len(), 2);
    let sw = info
        .iter()
        .find(|x| x.path.ends_with("SoftwareVersion"))
        .unwrap();
    assert_eq!(
        (sw.value.as_deref(), sw.writable),
        (Some("V1"), Some(false))
    );
    assert_eq!(store.get_params(d, "").await.unwrap().len(), 3);
    // Literal prefix match: '_', '%' not wildcards.
    assert!(
        store
            .get_params(d, "Device.Device_nfo")
            .await
            .unwrap()
            .is_empty()
    );

    assert_eq!(
        store
            .delete_params_under(d, "Device.DeviceInfo.")
            .await
            .unwrap(),
        2
    );
    assert_eq!(store.upsert_params(d, &[]).await.unwrap().stored, 0);
}

/// ADR-111: paths under an object (never own row, never values) + exact delete.
#[tokio::test]
async fn param_paths_under_and_exact_delete() {
    let (_c, store) = setup().await;
    let (d, other) = (device(&store, "SN1").await, device(&store, "SN2").await);
    let rows: Vec<ParamUpdate> = [
        "Device.Ethernet.",
        "Device.Ethernet.Interface.1.Name",
        "Device.Ethernet.Interface.2.",
        "Device.Ethernet.Interface.2.Name",
        "Device.EthernetX.Name",
        "Device.DeviceInfo.UpTime",
    ]
    .iter()
    .map(|path| ParamUpdate {
        path: (*path).into(),
        value: (!path.ends_with('.')).then(|| "v".into()),
        ..ParamUpdate::default()
    })
    .collect();
    store.upsert_params(d, &rows).await.unwrap();
    store.upsert_params(other, &rows).await.unwrap();

    let mut under = store
        .param_paths_under(d, "Device.Ethernet.")
        .await
        .unwrap();
    under.sort();
    assert_eq!(
        under,
        [
            "Device.Ethernet.Interface.1.Name",
            "Device.Ethernet.Interface.2.",
            "Device.Ethernet.Interface.2.Name",
        ]
    );

    let gone = [
        "Device.Ethernet.Interface.2.".to_owned(),
        "Device.Ethernet.Interface.2.Name".to_owned(),
        "Device.Ethernet.Interface.9.Name".to_owned(),
    ];
    assert_eq!(store.delete_params_exact(d, &gone).await.unwrap(), 2);
    assert_eq!(store.delete_params_exact(d, &[]).await.unwrap(), 0);
    let left: Vec<String> = store
        .get_params(d, "")
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.path)
        .collect();
    assert_eq!(
        left,
        [
            "Device.DeviceInfo.UpTime",
            "Device.Ethernet.",
            "Device.Ethernet.Interface.1.Name",
            "Device.EthernetX.Name",
        ]
    );
    // Rows of the other device untouched.
    assert_eq!(store.get_params(other, "").await.unwrap().len(), 6);
}

#[tokio::test]
async fn param_prefix_presence_is_per_device_and_literal() {
    let (_c, store) = setup().await;
    let (a, b) = (device(&store, "SN1").await, device(&store, "SN2").await);
    store
        .upsert_params(
            a,
            &[ParamUpdate {
                path: "Device.DeviceInfo.FirmwareImage.1.Version".into(),
                value: Some("V1".into()),
                ..ParamUpdate::default()
            }],
        )
        .await
        .unwrap();
    let images = "Device.DeviceInfo.FirmwareImage.";
    assert!(store.has_param_prefix(a, images).await.unwrap());
    assert!(
        !store.has_param_prefix(b, images).await.unwrap(),
        "another device's rows do not count"
    );
    assert!(
        !store
            .has_param_prefix(a, "Device.DeviceInfo.FirmwareImage.2.")
            .await
            .unwrap()
    );
    // '_', '%' not wildcards.
    assert!(
        !store
            .has_param_prefix(a, "Device.Device_nfo.")
            .await
            .unwrap()
    );
    assert!(!store.has_param_prefix(a, "%").await.unwrap());
}

#[tokio::test]
async fn open_reads_are_those_that_run_or_will_run_now() {
    let (_c, store) = setup().await;
    let d = device(&store, "SN1").await;
    let other = device(&store, "SN2").await;
    let read = |device: Uuid, names: &[&str], key: &str| NewTask {
        idempotency_key: Some(key.into()),
        ..NewTask::new(
            DEFAULT_TENANT,
            device,
            "get_parameter_values",
            json!({ "names": names }),
        )
    };
    assert!(!store.has_open_read_of(d, "Device.").await.unwrap());

    // Pending -> open read for its own name.
    // Not for: other name, other device, other task kind.
    store
        .enqueue_task(&read(d, &["Device.", "Device.Other."], "full"))
        .await
        .unwrap();
    assert!(store.has_open_read_of(d, "Device.").await.unwrap());
    assert!(store.has_open_read_of(d, "Device.Other.").await.unwrap());
    assert!(
        !store
            .has_open_read_of(d, "Device.DeviceInfo.")
            .await
            .unwrap()
    );
    assert!(!store.has_open_read_of(other, "Device.").await.unwrap());
    store
        .enqueue_task(&NewTask::new(
            DEFAULT_TENANT,
            other,
            "set_parameter_values",
            json!({ "names": ["Device."] }),
        ))
        .await
        .unwrap();
    assert!(!store.has_open_read_of(other, "Device.").await.unwrap());

    // Running -> counts; done -> not.
    let task = store.next_task(d).await.unwrap().unwrap();
    assert!(store.has_open_read_of(d, "Device.").await.unwrap());
    store
        .complete_task(d, task.id, Ok(json!({})))
        .await
        .unwrap();
    assert!(!store.has_open_read_of(d, "Device.").await.unwrap());

    // Postponed to later -> no run now.
    let later = NewTask {
        not_before: Some(OffsetDateTime::now_utc() + Duration::hours(1)),
        ..read(d, &["Device."], "later")
    };
    store.enqueue_task(&later).await.unwrap();
    assert!(!store.has_open_read_of(d, "Device.").await.unwrap());
}

#[tokio::test]
async fn task_queue_order_retry_and_idempotency() {
    let (_c, store) = setup().await;
    let d = device(&store, "SN1").await;
    let mk = |kind: &str| NewTask::new(DEFAULT_TENANT, d, kind, json!({}));

    let (low, _) = store.enqueue_task(&mk("low")).await.unwrap();
    let high = NewTask {
        priority: 10,
        max_attempts: 2,
        ..mk("high")
    };
    let (high_id, _) = store.enqueue_task(&high).await.unwrap();

    let keyed = NewTask {
        idempotency_key: Some("k1".into()),
        ..mk("keyed")
    };
    let (k1, created1) = store.enqueue_task(&keyed).await.unwrap();
    let (k2, created2) = store.enqueue_task(&keyed).await.unwrap();
    assert!(created1 && !created2);
    assert_eq!(k1, k2);

    // Highest priority first.
    let t = store.next_task(d).await.unwrap().unwrap();
    assert_eq!(
        (t.id, t.state, t.attempts),
        (high_id, TaskState::Running, 1)
    );
    // Fail + attempts left -> back to pending.
    assert_eq!(
        store
            .complete_task(d, t.id, Err("9002 Internal error".into()))
            .await
            .unwrap(),
        TaskState::Pending
    );
    let t = store.next_task(d).await.unwrap().unwrap();
    assert_eq!((t.id, t.attempts), (high_id, 2));
    assert_eq!(
        store
            .complete_task(d, t.id, Err("again".into()))
            .await
            .unwrap(),
        TaskState::Failed
    );

    // Then creation order.
    let t = store.next_task(d).await.unwrap().unwrap();
    assert_eq!(t.id, low);
    assert_eq!(
        store
            .complete_task(d, t.id, Ok(json!({"status": 0})))
            .await
            .unwrap(),
        TaskState::Succeeded
    );
    let done = store.get_task(low).await.unwrap().unwrap();
    assert_eq!(done.result, Some(json!({"status": 0})));

    // Session aborted -> running task back to pending.
    let t = store.next_task(d).await.unwrap().unwrap();
    assert_eq!(t.id, k1);
    assert_eq!(store.requeue_running(d).await.unwrap(), 1);
    assert!(store.cancel_task(k1).await.unwrap());
    assert!(store.next_task(d).await.unwrap().is_none());
    assert_eq!(store.list_tasks(d, 10).await.unwrap().len(), 3);
}

#[tokio::test]
async fn permanent_failures_skip_retries() {
    let (_c, store) = setup().await;
    let d = device(&store, "SN1").await;
    let (id, _) = store
        .enqueue_task(&NewTask::new(DEFAULT_TENANT, d, "reboot", json!({})))
        .await
        .unwrap();
    store.next_task(d).await.unwrap().unwrap();
    assert!(
        store
            .fail_task(id, "9000 Method not supported")
            .await
            .unwrap()
    );
    let t = store.get_task(id).await.unwrap().unwrap();
    assert_eq!((t.state, t.attempts), (TaskState::Failed, 1));
    assert!(
        !store.fail_task(id, "again").await.unwrap(),
        "only running tasks"
    );
}

#[tokio::test]
async fn stale_waiting_tasks_fail() {
    let (_c, store) = setup().await;
    let d = device(&store, "SN1").await;
    let (id, _) = store
        .enqueue_task(&NewTask::new(DEFAULT_TENANT, d, "download", json!({})))
        .await
        .unwrap();
    store.next_task(d).await.unwrap().unwrap();
    store
        .mark_task_waiting(id, &json!({"status": 1}))
        .await
        .unwrap();
    assert_eq!(
        store.fail_stale_waiting(Duration::hours(1)).await.unwrap(),
        0
    );
    assert_eq!(
        store
            .fail_stale_waiting(Duration::seconds(-1))
            .await
            .unwrap(),
        1
    );
    let t = store.get_task(id).await.unwrap().unwrap();
    assert_eq!(t.state, TaskState::Failed);
    assert!(t.error.unwrap().contains("TransferComplete"));
}

#[tokio::test]
async fn aborted_sessions_count_as_attempts() {
    let (_c, store) = setup().await;
    let d = device(&store, "SN1").await;
    let t = NewTask {
        max_attempts: 2,
        ..NewTask::new(DEFAULT_TENANT, d, "gpv", json!({}))
    };
    let (id, _) = store.enqueue_task(&t).await.unwrap();
    for expected in [TaskState::Pending, TaskState::Failed] {
        store.next_task(d).await.unwrap().unwrap();
        store.requeue_running(d).await.unwrap();
        let task = store.get_task(id).await.unwrap().unwrap();
        assert_eq!(task.state, expected);
        assert!(task.error.unwrap().contains("session aborted"));
    }
    assert!(store.next_task(d).await.unwrap().is_none());
}

#[tokio::test]
async fn task_time_limits() {
    let (_c, store) = setup().await;
    let d = device(&store, "SN1").await;
    let now = OffsetDateTime::now_utc();
    let expired = NewTask {
        expires_at: Some(now - Duration::minutes(1)),
        ..NewTask::new(DEFAULT_TENANT, d, "expired", json!({}))
    };
    let later = NewTask {
        not_before: Some(now + Duration::hours(1)),
        ..NewTask::new(DEFAULT_TENANT, d, "later", json!({}))
    };
    let (e, _) = store.enqueue_task(&expired).await.unwrap();
    store.enqueue_task(&later).await.unwrap();
    assert!(store.next_task(d).await.unwrap().is_none());
    assert_eq!(
        store.get_task(e).await.unwrap().unwrap().state,
        TaskState::Expired
    );
}

#[tokio::test]
async fn concurrent_sessions_take_distinct_tasks() {
    let (_c, store) = setup().await;
    let d = device(&store, "SN1").await;
    for i in 0..10 {
        store
            .enqueue_task(&NewTask::new(DEFAULT_TENANT, d, format!("t{i}"), json!({})))
            .await
            .unwrap();
    }
    let mut handles = Vec::new();
    for _ in 0..10 {
        let s = store.clone();
        handles.push(tokio::spawn(async move {
            s.next_task(d).await.unwrap().map(|t| t.id)
        }));
    }
    let mut ids = Vec::new();
    for h in handles {
        ids.extend(h.await.unwrap());
    }
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 10, "every task taken exactly once");
}

#[tokio::test]
async fn events_are_recorded() {
    let (_c, store) = setup().await;
    let d = device(&store, "SN1").await;
    store
        .record_event(
            DEFAULT_TENANT,
            Some(d),
            "inform",
            &json!({"events": ["1 BOOT"]}),
        )
        .await
        .unwrap();
    store
        .record_event(DEFAULT_TENANT, Some(d), "transfer_complete", &json!({}))
        .await
        .unwrap();
    let ev = store.list_events(d, 10).await.unwrap();
    assert_eq!(ev.len(), 2);
    assert_eq!(ev[0].kind, "transfer_complete");
}

#[tokio::test]
async fn usp_preregistration_and_broker_credentials() {
    let (_c, store) = setup().await;
    let eid = "os::012345-AABBCCDDEEFF";
    let first = store
        .preregister_usp_device(DEFAULT_TENANT, eid, &["lab".into()])
        .await
        .unwrap();
    assert!(first.created);
    assert_eq!(first.status, "active");
    let again = store
        .preregister_usp_device(DEFAULT_TENANT, eid, &[])
        .await
        .unwrap();
    assert_eq!((again.id, again.created), (first.id, false));
    // First Agent connect -> finds the preregistered row.
    let connected = store
        .upsert_usp_device(DEFAULT_TENANT, eid, None)
        .await
        .unwrap();
    assert_eq!((connected.id, connected.created), (first.id, false));

    store
        .put_credential(&dhonomos_store::SealedCredential {
            device_id: first.id,
            kind: "mqtt".into(),
            username: eid.into(),
            ciphertext: vec![1, 2, 3],
            nonce: vec![0; 12],
            key_id: "k1".into(),
        })
        .await
        .unwrap();
    assert_eq!(
        store.list_credentials(first.id).await.unwrap(),
        vec![("mqtt".to_owned(), eid.to_owned())]
    );
}

#[tokio::test]
async fn metric_partitions_and_retention() {
    let (_c, store) = setup().await;
    let dev = device(&store, "M1").await;
    let today = OffsetDateTime::now_utc().date();
    let created = store
        .ensure_metric_partitions(today - Duration::days(3), today)
        .await
        .unwrap();
    assert_eq!(created, 4);
    assert_eq!(
        store
            .ensure_metric_partitions(today - Duration::days(3), today)
            .await
            .unwrap(),
        4,
        "IF NOT EXISTS: counted, not failed"
    );
    let ids = store.metric_ids(&["Device.X".into()]).await.unwrap();
    let x = ids["Device.X"];
    let now = OffsetDateTime::now_utc();
    store
        .insert_samples(dev, &[(x, now - Duration::days(3), 1.0), (x, now, 2.0)])
        .await
        .unwrap();
    let all = store
        .metric_series(
            dev,
            "Device.X",
            now - Duration::days(4),
            now + Duration::hours(1),
            86_400 * 7,
        )
        .await
        .unwrap();
    assert_eq!(all.iter().map(|b| b.count).sum::<i64>(), 2);
    // Keep last 2 days -> sample of 3 days ago dropped with its partition.
    let dropped = store
        .drop_metric_partitions_before(today - Duration::days(1))
        .await
        .unwrap();
    assert_eq!(dropped, 2);
    let left = store
        .metric_series(
            dev,
            "Device.X",
            now - Duration::days(4),
            now + Duration::hours(1),
            86_400 * 7,
        )
        .await
        .unwrap();
    assert_eq!(left.iter().map(|b| b.count).sum::<i64>(), 1);
    // Outside any partition -> PostgreSQL rejects (ingest layer filters these).
    assert!(
        store
            .insert_samples(dev, &[(x, now - Duration::days(30), 0.0)])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn metric_rollups_keep_series_queryable() {
    let (_c, store) = setup().await;
    let dev = device(&store, "R1").await;
    let today = OffsetDateTime::now_utc().date();
    store
        .ensure_metric_partitions(today - Duration::days(3), today)
        .await
        .unwrap();
    let x = store.metric_ids(&["Device.R".into()]).await.unwrap()["Device.R"];
    let old_day = (today - Duration::days(3)).midnight().assume_utc();
    let now = OffsetDateTime::now_utc();
    store
        .insert_samples(
            dev,
            &[
                (x, old_day + Duration::minutes(5), 1.0),
                (x, old_day + Duration::minutes(10), 3.0),
                (x, now, 10.0),
            ],
        )
        .await
        .unwrap();
    let series = |from: OffsetDateTime| {
        let store = store.clone();
        async move {
            store
                .metric_series(dev, "Device.R", from, now + Duration::hours(1), 86_400 * 10)
                .await
                .unwrap()
        }
    };
    let before = series(old_day).await;
    // Compact all before yesterday -> old day partition = one array row.
    assert_eq!(
        store
            .rollup_metric_partitions_before(today - Duration::days(1))
            .await
            .unwrap(),
        2,
        "days -3 and -2"
    );
    let after = series(old_day).await;
    assert_eq!(before, after, "same answer from raw and compacted data");
    assert_eq!(after.iter().map(|b| b.count).sum::<i64>(), 3);
    assert_eq!(after[0].min, 1.0);
    // Range inside a compacted day -> only its samples.
    let narrow = store
        .metric_series(
            dev,
            "Device.R",
            old_day + Duration::minutes(8),
            old_day + Duration::hours(1),
            3600,
        )
        .await
        .unwrap();
    assert_eq!((narrow.len(), narrow[0].avg), (1, 3.0));
    // Retention -> deletes compacted days.
    assert_eq!(store.delete_rollups_before(today).await.unwrap(), 1);
    assert_eq!(
        series(old_day).await.iter().map(|b| b.count).sum::<i64>(),
        1
    );
}

#[tokio::test]
async fn retention_deletes_old_rows_only() {
    let (_c, store) = setup().await;
    let dev = device(&store, "RET1").await;
    for _ in 0..3 {
        store
            .record_event(DEFAULT_TENANT, Some(dev), "inform", &json!({}))
            .await
            .unwrap();
    }
    let (t, _) = store
        .enqueue_task(&NewTask::new(DEFAULT_TENANT, dev, "reboot", json!({})))
        .await
        .unwrap();
    let running = store.next_task(dev).await.unwrap().unwrap();
    store
        .complete_task(dev, running.id, Ok(json!({})))
        .await
        .unwrap();
    let (once, _) = store
        .enqueue_task(&NewTask {
            idempotency_key: Some(format!("preset-once:p:0:{dev}")),
            ..NewTask::new(DEFAULT_TENANT, dev, "reboot", json!({}))
        })
        .await
        .unwrap();
    let running = store.next_task(dev).await.unwrap().unwrap();
    store
        .complete_task(dev, running.id, Ok(json!({})))
        .await
        .unwrap();
    // Nothing old enough yet.
    let past = OffsetDateTime::now_utc() - Duration::days(1);
    let p = store.apply_retention(past, past, past).await.unwrap();
    assert_eq!((p.events, p.tasks), (0, 0));
    // Cutoff "tomorrow" -> all old.
    let future = OffsetDateTime::now_utc() + Duration::days(1);
    let p = store.apply_retention(future, future, future).await.unwrap();
    assert_eq!((p.events, p.tasks), (3, 1));
    assert!(store.get_task(t).await.unwrap().is_none());
    assert!(
        store.get_task(once).await.unwrap().is_some(),
        "once-preset record kept"
    );
    assert!(store.list_events(dev, 10).await.unwrap().is_empty());
}

/// SQL rule (`device_in_scope`, searches) = Rust rule (`DeviceScope::matches`, one device).
#[tokio::test]
async fn device_scopes_agree_in_sql_and_rust() {
    use dhonomos_store::{DeviceScope, DeviceSearch};
    let (_c, store) = setup().await;
    let mut ids = Vec::new();
    for (serial, tags, attrs) in [
        (
            "A",
            vec!["east"],
            json!({ "region": "busan", "plan": "gold" }),
        ),
        ("B", vec!["east", "vip"], json!({ "region": "ulsan" })),
        ("C", vec![], json!({ "region": "busan" })),
        ("D", vec!["west"], json!({})),
    ] {
        let id = device(&store, serial).await;
        let tags: Vec<String> = tags.into_iter().map(Into::into).collect();
        store
            .update_device(DEFAULT_TENANT, id, Some(&tags), Some(&attrs))
            .await
            .unwrap();
        ids.push(id);
    }
    let usp = store
        .preregister_usp_device(DEFAULT_TENANT, "proto::agent-1", &["east".to_owned()])
        .await
        .unwrap()
        .id;
    ids.push(usp);
    let scopes = [
        json!({ "tags": ["east"] }),
        json!({ "tags": ["east", "vip"] }),
        json!({ "attributes": { "region": "busan" } }),
        json!({ "tags": ["east"], "attributes": { "region": "busan" } }),
        json!({ "protocol": "usp" }),
        json!({ "protocol": "cwmp", "tags": ["east"] }),
        json!({ "oui": "202BC1" }),
        json!({ "oui": "000000" }),
        json!({ "product_class": "BM632w", "attributes": { "plan": "gold" } }),
        json!({ "attributes": { "region": "seoul" } }),
    ];
    for scope in scopes {
        let scope: DeviceScope = serde_json::from_value(scope).unwrap();
        let search = DeviceSearch {
            scope: Some(scope.clone()),
            ..DeviceSearch::default()
        };
        let (found, total) = store
            .search_devices(DEFAULT_TENANT, &search, 100, 0)
            .await
            .unwrap();
        let mut sql: Vec<Uuid> = found.iter().map(|d| d.id).collect();
        sql.sort();
        let mut rust = Vec::new();
        for id in &ids {
            let d = store.get_device(*id).await.unwrap().unwrap();
            if scope.matches(&d) {
                rust.push(d.id);
            }
        }
        rust.sort();
        assert_eq!(sql, rust, "{scope:?}");
        assert_eq!(total as usize, rust.len());
    }
    let (_, all) = store
        .search_devices(DEFAULT_TENANT, &DeviceSearch::default(), 100, 0)
        .await
        .unwrap();
    assert_eq!(all, 5, "no scope: every device");
}

/// Device list filter values (UI-01): distinct values + counts, no empty ones.
/// Each facet ignores its own filter. Also: exact OUI + model filters.
#[tokio::test]
async fn device_facets_and_exact_filters() {
    use dhonomos_store::{DeviceInfo, DeviceSearch, FacetValue};
    let (_c, store) = setup().await;
    for (serial, oui, class, model, manufacturer) in [
        ("A", "00AA01", "R1", Some("M1"), Some("Acme")),
        ("B", "00AA01", "R1", Some("M1"), Some("Acme")),
        ("C", "00AA01", "R2", Some(""), Some("")),
        ("D", "00BB02", "R2", Some("M2"), Some("Beta")),
        ("E", "00CC03", "R3", None, None),
    ] {
        let identity = CwmpIdentity {
            oui: oui.into(),
            product_class: class.into(),
            serial_number: serial.into(),
        };
        let update = InformUpdate {
            model_name: model.map(Into::into),
            manufacturer: manufacturer.map(Into::into),
            ..InformUpdate::default()
        };
        store
            .upsert_cwmp_device(DEFAULT_TENANT, &identity, &update)
            .await
            .unwrap();
    }
    // USP Agent -> no product class.
    let usp = store
        .upsert_usp_device(DEFAULT_TENANT, "os::00DD04-X", None)
        .await
        .unwrap()
        .id;
    store
        .update_device_info(
            usp,
            &DeviceInfo {
                oui: Some("00DD04".into()),
                model_name: Some("M3".into()),
                manufacturer: Some("Delta".into()),
                ..DeviceInfo::default()
            },
        )
        .await
        .unwrap();

    let v = |value: &str, count: i64, manufacturer: Option<&str>| FacetValue {
        value: value.into(),
        count,
        manufacturer: manufacturer.map(Into::into),
    };
    let all = store
        .device_facets(DEFAULT_TENANT, &DeviceSearch::default())
        .await
        .unwrap();
    assert_eq!(
        all.oui,
        [
            v("00AA01", 3, Some("Acme")),
            v("00BB02", 1, Some("Beta")),
            v("00CC03", 1, None),
            v("00DD04", 1, Some("Delta")),
        ]
    );
    assert_eq!(
        all.product_class,
        [v("R1", 2, None), v("R2", 2, None), v("R3", 1, None)]
    );
    assert_eq!(
        all.model_name,
        [v("M1", 2, None), v("M2", 1, None), v("M3", 1, None)]
    );

    // OUI selected -> narrows other facets; all OUIs still offered.
    let by_oui = DeviceSearch {
        oui: Some("00AA01".into()),
        ..DeviceSearch::default()
    };
    let narrowed = store.device_facets(DEFAULT_TENANT, &by_oui).await.unwrap();
    assert_eq!(narrowed.oui, all.oui);
    assert_eq!(narrowed.product_class, [v("R1", 2, None), v("R2", 1, None)]);
    assert_eq!(narrowed.model_name, [v("M1", 2, None)]);

    // Same for product class, with protocol filter.
    let by_class = DeviceSearch {
        product_class: Some("R2".into()),
        protocol: Some("cwmp".into()),
        ..DeviceSearch::default()
    };
    let narrowed = store
        .device_facets(DEFAULT_TENANT, &by_class)
        .await
        .unwrap();
    assert_eq!(
        narrowed.product_class,
        [v("R1", 2, None), v("R2", 2, None), v("R3", 1, None)]
    );
    assert_eq!(
        narrowed.oui,
        [v("00AA01", 1, None), v("00BB02", 1, Some("Beta"))]
    );
    assert_eq!(narrowed.model_name, [v("M2", 1, None)]);

    let serials = |search: DeviceSearch| {
        let store = store.clone();
        async move {
            let (devices, total) = store
                .search_devices(DEFAULT_TENANT, &search, 100, 0)
                .await
                .unwrap();
            assert_eq!(total as usize, devices.len());
            let mut serials: Vec<String> = devices
                .into_iter()
                .map(|d| d.serial_number.unwrap_or_else(|| "usp".into()))
                .collect();
            serials.sort_unstable();
            serials.join(",")
        }
    };
    assert_eq!(serials(by_oui).await, "A,B,C");
    assert_eq!(
        serials(DeviceSearch {
            model_name: Some("M1".into()),
            ..DeviceSearch::default()
        })
        .await,
        "A,B"
    );
    assert_eq!(
        serials(DeviceSearch {
            oui: Some("00DD04".into()),
            model_name: Some("M3".into()),
            ..DeviceSearch::default()
        })
        .await,
        "usp"
    );
}

/// Each state change -> one step in the task trace.
#[tokio::test]
async fn task_trace_records_each_step() {
    let (_c, store) = setup().await;
    let d = device(&store, "SN1").await;
    let task = NewTask {
        created_by: Some("preset:wifi".into()),
        ..NewTask::new(DEFAULT_TENANT, d, "reboot", json!({}))
    };
    let (id, _) = store.enqueue_task(&task).await.unwrap();
    store.next_task(d).await.unwrap().unwrap();
    store
        .complete_task(d, id, Err("9002 Internal error".into()))
        .await
        .unwrap();
    store.next_task(d).await.unwrap().unwrap();
    store
        .mark_task_waiting(id, &json!({ "status": 1 }))
        .await
        .unwrap();
    store
        .complete_task(d, id, Ok(json!({ "status": 0 })))
        .await
        .unwrap();
    let (other, _) = store
        .enqueue_task(&NewTask::new(
            DEFAULT_TENANT,
            d,
            "reboot",
            json!({ "x": 1 }),
        ))
        .await
        .unwrap();
    store.cancel_task(other).await.unwrap();

    let steps = |t: &dhonomos_store::Task| -> Vec<(String, i64, Option<String>)> {
        t.trace
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                OffsetDateTime::parse(
                    s["at"].as_str().unwrap(),
                    &time::format_description::well_known::Rfc3339,
                )
                .unwrap();
                (
                    s["step"].as_str().unwrap().to_owned(),
                    s["attempt"].as_i64().unwrap(),
                    s["detail"].as_str().map(str::to_owned),
                )
            })
            .collect()
    };
    let t = store.get_task(id).await.unwrap().unwrap();
    let s =
        |step: &str, n: i64, detail: Option<&str>| (step.to_owned(), n, detail.map(str::to_owned));
    assert_eq!(
        steps(&t),
        vec![
            s("queued", 0, Some("preset:wifi")),
            s("dispatched", 1, None),
            s("retry", 1, Some("9002 Internal error")),
            s("dispatched", 2, None),
            s("waiting", 2, Some("waiting for the completion report")),
            s("succeeded", 2, None),
        ]
    );
    let c = store.get_task(other).await.unwrap().unwrap();
    assert_eq!(
        steps(&c),
        vec![s("queued", 0, None), s("cancelled", 0, None)]
    );
}

#[tokio::test]
async fn filter_expressions_select_devices() {
    use dhonomos_store::{DeviceSearch, FilterExpr};
    let (_c, store) = setup().await;
    let mut ids = std::collections::HashMap::new();
    for (serial, tags, attrs, uptime) in [
        (
            "A",
            vec!["east"],
            json!({ "region": "busan", "plan": "gold" }),
            Some("100"),
        ),
        (
            "B",
            vec!["east", "vip"],
            json!({ "region": "ulsan" }),
            Some("5000"),
        ),
        ("C", vec![], json!({ "region": "busan" }), None),
        ("D", vec!["west"], json!({}), Some("not a number")),
    ] {
        let id = device(&store, serial).await;
        let tags: Vec<String> = tags.into_iter().map(Into::into).collect();
        store
            .update_device(DEFAULT_TENANT, id, Some(&tags), Some(&attrs))
            .await
            .unwrap();
        if let Some(v) = uptime {
            store
                .upsert_params(
                    id,
                    &[ParamUpdate {
                        path: "Device.DeviceInfo.UpTime".into(),
                        value: Some(v.into()),
                        ..ParamUpdate::default()
                    }],
                )
                .await
                .unwrap();
        }
        ids.insert(id, serial);
    }
    let found = |expr: &str| {
        let store = store.clone();
        let ids = ids.clone();
        let filter = FilterExpr::parse(expr).unwrap_or_else(|e| panic!("{expr}: {e}"));
        async move {
            let search = DeviceSearch {
                filter: Some(filter),
                ..DeviceSearch::default()
            };
            let (devices, total) = store
                .search_devices(DEFAULT_TENANT, &search, 100, 0)
                .await
                .unwrap();
            assert_eq!(total as usize, devices.len());
            let mut names: Vec<&str> = devices.iter().map(|d| ids[&d.id]).collect();
            names.sort_unstable();
            names.join("")
        }
    };
    assert_eq!(found("tag = east").await, "AB");
    assert_eq!(found("tag = east and not tag = vip").await, "A");
    assert_eq!(found("attr.region = busan or tag = west").await, "ACD");
    assert_eq!(found("attr.plan exists").await, "A");
    assert_eq!(found("not attr.plan exists").await, "BCD");
    assert_eq!(found("attr.region ~ SAN").await, "ABC");
    assert_eq!(found("attr.region !~ usa").await, "BD");
    assert_eq!(
        found(r#"param."Device.DeviceInfo.UpTime" > 1000"#).await,
        "B"
    );
    assert_eq!(found("param.Device.DeviceInfo.UpTime <= 1000").await, "A");
    assert_eq!(found("param.Device.DeviceInfo.UpTime exists").await, "ABD");
    assert_eq!(
        found("serial = A or (oui = 202BC1 and serial ~ d)").await,
        "AD"
    );
    assert_eq!(found("serial != A and product_class = BM632w").await, "BCD");
    // All devices upserted now -> just in touch.
    assert_eq!(found("last_contact < 1h").await, "ABCD");
    assert_eq!(found("last_contact > 1d").await, "");
    assert_eq!(
        found("last_boot > 1d").await,
        "ABCD",
        "never booted counts as long ago"
    );
}

/// Reachability in device rows: filter fields `xmpp_connected` + `udp_cr`,
/// UDP CR address, last wake.
#[tokio::test]
async fn reachability_fields_and_filters() {
    use dhonomos_store::{DeviceSearch, FilterExpr};
    let (_c, store) = setup().await;
    let a = device(&store, "A").await;
    let b = device(&store, "B").await;
    let c = device(&store, "C").await;

    // Nothing known yet.
    let d = store.get_device(a).await.unwrap().unwrap();
    assert_eq!(d.udp_cr_address, None);
    assert_eq!(d.udp_cr_seen_at, None);
    assert_eq!(d.last_wake_at, None);
    assert_eq!(d.last_wake_method, None);
    assert_eq!(d.last_wake_outcome, None);

    // A: XMPP session. A + B: UDP address known.
    store
        .set_xmpp_connected(a, OffsetDateTime::now_utc())
        .await
        .unwrap();
    for id in [a, b] {
        assert!(
            store
                .set_udp_cr_address(DEFAULT_TENANT, id, "198.51.100.7:50000")
                .await
                .unwrap()
        );
    }
    let d = store.get_device(b).await.unwrap().unwrap();
    assert_eq!(d.udp_cr_address.as_deref(), Some("198.51.100.7:50000"));
    assert!(d.udp_cr_seen_at.is_some());

    let found = |expr: &'static str| {
        let store = store.clone();
        async move {
            let search = DeviceSearch {
                filter: Some(FilterExpr::parse(expr).unwrap_or_else(|e| panic!("{expr}: {e}"))),
                ..DeviceSearch::default()
            };
            let (devices, total) = store
                .search_devices(DEFAULT_TENANT, &search, 100, 0)
                .await
                .unwrap();
            assert_eq!(total as usize, devices.len());
            let mut serials: Vec<String> = devices
                .into_iter()
                .filter_map(|d| d.serial_number)
                .collect();
            serials.sort_unstable();
            serials.join("")
        }
    };
    assert_eq!(found("xmpp_connected = true").await, "A");
    assert_eq!(found("xmpp_connected exists").await, "A");
    assert_eq!(found("xmpp_connected = false").await, "BC");
    assert_eq!(found("xmpp_connected != true").await, "BC");
    assert_eq!(found("not xmpp_connected = true").await, "BC");
    assert_eq!(found("udp_cr = true").await, "AB");
    assert_eq!(found("udp_cr = false").await, "C");
    assert_eq!(found("xmpp_connected = true and udp_cr = true").await, "A");
    assert_eq!(found("xmpp_connected = false and udp_cr = true").await, "B");
    assert_eq!(found("xmpp_connected = true or udp_cr = false").await, "AC");
    // Session ends.
    store.clear_all_xmpp_connected().await.unwrap();
    assert_eq!(found("xmpp_connected = true").await, "");

    // Last wake: one row per device, latest attempt wins; nothing sent -> no method.
    assert!(
        store
            .record_wake(a, Some("xmpp"), "sent over XMPP")
            .await
            .unwrap()
    );
    let d = store.get_device(a).await.unwrap().unwrap();
    assert!(d.last_wake_at.is_some());
    assert_eq!(d.last_wake_method.as_deref(), Some("xmpp"));
    assert_eq!(d.last_wake_outcome.as_deref(), Some("sent over XMPP"));
    assert!(
        store
            .record_wake(a, None, "failed: connection refused")
            .await
            .unwrap()
    );
    let d = store.get_device(a).await.unwrap().unwrap();
    assert_eq!(d.last_wake_method, None);
    assert_eq!(
        d.last_wake_outcome.as_deref(),
        Some("failed: connection refused")
    );
    assert_eq!(
        store.get_device(c).await.unwrap().unwrap().last_wake_at,
        None,
        "other devices are untouched"
    );
    assert!(
        !store
            .record_wake(Uuid::now_v7(), None, "sent")
            .await
            .unwrap(),
        "no such device"
    );
}

#[tokio::test]
async fn connected_usp_agents_are_touched_and_addressed() {
    let (_c, store) = setup().await;
    let a = store
        .upsert_usp_device(DEFAULT_TENANT, "os::00AA00-A", None)
        .await
        .unwrap()
        .id;
    let b = store
        .upsert_usp_device(DEFAULT_TENANT, "os::00AA00-B", None)
        .await
        .unwrap()
        .id;
    let contact = async |id| store.get_device(id).await.unwrap().unwrap().last_contact_at;
    let before = contact(b).await.unwrap();
    // Only listed Agents touched, to the given instant (not now).
    let heard = before + Duration::minutes(5);
    assert_eq!(
        store
            .touch_usp_devices(DEFAULT_TENANT, &[("os::00AA00-A".to_owned(), heard)])
            .await
            .unwrap(),
        1
    );
    // Column keeps microseconds.
    let at = |t: OffsetDateTime| t.replace_nanosecond(t.microsecond() * 1000).unwrap();
    assert_eq!(contact(a).await, Some(at(heard)));
    assert_eq!(contact(b).await, Some(before));
    // Contact never moves back; unchanged -> no write.
    let heard_a = ("os::00AA00-A".to_owned(), heard);
    let earlier = ("os::00AA00-A".to_owned(), heard - Duration::minutes(1));
    for stale in [earlier, heard_a.clone()] {
        assert_eq!(
            store
                .touch_usp_devices(DEFAULT_TENANT, &[stale])
                .await
                .unwrap(),
            0
        );
    }
    assert_eq!(contact(a).await, Some(at(heard)));
    // Several Agents at once, each to own instant; unknown one ignored.
    let later = heard + Duration::minutes(1);
    let batch = [
        heard_a.0.clone(),
        "os::00AA00-B".to_owned(),
        "os::00AA00-NONE".to_owned(),
    ]
    .into_iter()
    .zip([later, later + Duration::seconds(1), later])
    .collect::<Vec<_>>();
    assert_eq!(
        store
            .touch_usp_devices(DEFAULT_TENANT, &batch)
            .await
            .unwrap(),
        2
    );
    assert_eq!(contact(a).await, Some(at(later)));
    assert_eq!(contact(b).await, Some(at(later + Duration::seconds(1))));
    assert_eq!(
        store.touch_usp_devices(DEFAULT_TENANT, &[]).await.unwrap(),
        0
    );
    store
        .set_usp_remote_addr(
            a,
            "::ffff:10.20.30.243"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .to_canonical(),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .get_device(a)
            .await
            .unwrap()
            .unwrap()
            .last_remote_addr
            .as_deref(),
        Some("10.20.30.243")
    );
}

#[tokio::test]
async fn supported_models_are_replaced_deleted_and_removed_with_the_device() {
    let (_c, store) = setup().await;
    let a = device(&store, "SM1").await;
    let b = device(&store, "SM2").await;
    let first = json!({ "objects": [{ "path": "Device." }] });
    let second = json!({ "objects": [{ "path": "Device." }, { "path": "Device.IP." }] });

    // First stored model wins. Replace keeps the row -> linked devices see the new one.
    let id = store
        .put_supported_model("fp", "usp", &first)
        .await
        .unwrap();
    assert_eq!(
        store
            .put_supported_model("fp", "usp", &second)
            .await
            .unwrap(),
        id
    );
    assert!(store.device_supported_model(a).await.unwrap().is_none());
    store.link_supported_model(a, id).await.unwrap();
    store.link_supported_model(b, id).await.unwrap();
    assert_eq!(
        store
            .device_supported_model(a)
            .await
            .unwrap()
            .unwrap()
            .model,
        first
    );
    assert_eq!(
        store
            .replace_supported_model("fp", "usp", &second)
            .await
            .unwrap(),
        id
    );
    for d in [a, b] {
        assert_eq!(
            store
                .device_supported_model(d)
                .await
                .unwrap()
                .unwrap()
                .model,
            second
        );
    }

    // Model deleted -> devices without model.
    assert!(store.delete_supported_model("fp").await.unwrap());
    assert!(!store.delete_supported_model("fp").await.unwrap());
    assert_eq!(store.supported_model_id("fp").await.unwrap(), None);
    assert!(store.device_supported_model(a).await.unwrap().is_none());

    // Model of one device -> deleted with the device.
    let own = dhonomos_store::device_fingerprint(a);
    let id = store
        .replace_supported_model(&own, "usp", &first)
        .await
        .unwrap();
    store.link_supported_model(a, id).await.unwrap();
    assert_eq!(store.supported_model_id(&own).await.unwrap(), Some(id));
    assert!(
        store
            .delete_device(DEFAULT_TENANT, a, None)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(store.supported_model_id(&own).await.unwrap(), None);
}

fn sealed(
    device_id: Uuid,
    kind: &str,
    username: &str,
    secret: u8,
) -> dhonomos_store::SealedCredential {
    dhonomos_store::SealedCredential {
        device_id,
        kind: kind.into(),
        username: username.into(),
        ciphertext: vec![secret; 4],
        nonce: vec![secret; 12],
        key_id: "k1".into(),
    }
}

/// L-1: device reports outcome by task ID -> ID alone must not pick the task.
#[tokio::test]
async fn a_device_cannot_complete_another_devices_task() {
    let (_c, store) = setup().await;
    let (a, b) = (device(&store, "A").await, device(&store, "B").await);
    let (task, _) = store
        .enqueue_task(&NewTask::new(DEFAULT_TENANT, a, "download", json!({})))
        .await
        .unwrap();
    store.next_task(a).await.unwrap().unwrap();
    assert_eq!(
        store.get_task(task).await.unwrap().unwrap().state,
        TaskState::Running
    );

    // B names task of A -> no change.
    store
        .complete_task(b, task, Ok(json!({ "forged": true })))
        .await
        .unwrap();
    let t = store.get_task(task).await.unwrap().unwrap();
    assert_eq!((t.state, t.result), (TaskState::Running, None));
    store
        .complete_task(b, task, Err("forged failure".into()))
        .await
        .unwrap();
    let t = store.get_task(task).await.unwrap().unwrap();
    assert_eq!((t.state, t.error), (TaskState::Running, None));

    // Owner can.
    assert_eq!(
        store
            .complete_task(a, task, Ok(json!({ "status": 0 })))
            .await
            .unwrap(),
        TaskState::Succeeded
    );
}

/// M-4: provisioning from a CWMP session never replaces a pending credential.
/// Operator writes (admin API) do.
#[tokio::test]
async fn pending_credentials_are_only_stored_when_absent() {
    let (_c, store) = setup().await;
    let d = device(&store, "P1").await;
    assert!(
        store
            .put_pending_credential(&sealed(d, "acs_auth_pending", "acs-one", 1))
            .await
            .unwrap()
    );
    assert!(
        !store
            .put_pending_credential(&sealed(d, "acs_auth_pending", "acs-two", 2))
            .await
            .unwrap(),
        "the second one is refused"
    );
    let kept = store
        .get_credential(d, "acs_auth_pending")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((kept.username.as_str(), kept.ciphertext[0]), ("acs-one", 1));

    // Operator replaces it on purpose.
    store
        .put_credential(&sealed(d, "acs_auth_pending", "acs-three", 3))
        .await
        .unwrap();
    let kept = store
        .get_credential(d, "acs_auth_pending")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kept.username, "acs-three");
}

/// Provisioning with refused credential -> deletes exactly that one.
/// Not another kind, not a credential that took its place.
#[tokio::test]
async fn a_credential_is_deleted_only_with_its_nonce() {
    let (_c, store) = setup().await;
    let d = device(&store, "N1").await;
    store
        .put_credential(&sealed(d, "xmpp_pending", "one", 1))
        .await
        .unwrap();
    store
        .put_credential(&sealed(d, "xmpp", "active", 9))
        .await
        .unwrap();
    assert!(
        !store
            .delete_credential_with_nonce(d, "xmpp_pending", &[2; 12])
            .await
            .unwrap(),
        "another credential's nonce"
    );
    assert!(
        !store
            .delete_credential_with_nonce(d, "acs_auth_pending", &[1; 12])
            .await
            .unwrap(),
        "another kind"
    );
    assert!(
        store
            .delete_credential_with_nonce(d, "xmpp_pending", &[1; 12])
            .await
            .unwrap()
    );
    let kinds: Vec<String> = store
        .list_credentials(d)
        .await
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert_eq!(kinds, ["xmpp"], "the active one stays");
}

/// Failed tasks found by idempotency key + last error.
/// Not found: other states, keys of other tenants.
#[tokio::test]
async fn failed_tasks_are_found_by_key() {
    let (_c, store) = setup().await;
    let d = device(&store, "F1").await;
    let task = |key: &str| NewTask {
        idempotency_key: Some(key.into()),
        ..NewTask::new(DEFAULT_TENANT, d, "get_parameter_values", json!({}))
    };
    for key in ["failed", "done", "waiting"] {
        store.enqueue_task(&task(key)).await.unwrap();
    }
    // Queue order: "failed" first, then "done".
    let failed = store.next_task(d).await.unwrap().unwrap();
    store
        .fail_task(failed.id, "9003 Invalid arguments")
        .await
        .unwrap();
    let done = store.next_task(d).await.unwrap().unwrap();
    store
        .complete_task(d, done.id, Ok(json!({})))
        .await
        .unwrap();
    let keys: Vec<String> = ["failed", "done", "waiting", "unknown"]
        .into_iter()
        .map(String::from)
        .collect();
    let found = store
        .failed_tasks_by_key(DEFAULT_TENANT, &keys)
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, "9003 Invalid arguments");
    assert!(OffsetDateTime::now_utc() - found[0].1 < Duration::minutes(1));
    assert!(
        store
            .failed_tasks_by_key(Uuid::from_u128(77), &keys)
            .await
            .unwrap()
            .is_empty()
    );
}

/// ADR-104: XMPP logins of a device -> active first, only active devices of the tenant,
/// deleted together. Session start time -> cleared only by that session.
#[tokio::test]
async fn xmpp_logins_and_session_times() {
    let (_c, store) = setup().await;
    let (d, other) = (device(&store, "X1").await, device(&store, "X2").await);
    for (device, kind, tag) in [
        (d, "xmpp_pending", 1),
        (d, "xmpp", 2),
        (other, "xmpp", 3),
        (d, "acs_auth", 4),
    ] {
        store
            .put_credential(&sealed(device, kind, &device.to_string(), tag))
            .await
            .unwrap();
    }
    let kinds = |found: Vec<dhonomos_store::SealedCredential>| -> Vec<String> {
        found.into_iter().map(|c| c.kind).collect()
    };
    assert_eq!(
        kinds(
            store
                .find_xmpp_credentials(DEFAULT_TENANT, d)
                .await
                .unwrap()
        ),
        ["xmpp", "xmpp_pending"],
        "the active one first, and no other kind"
    );
    assert!(
        store
            .find_xmpp_credentials(Uuid::now_v7(), d)
            .await
            .unwrap()
            .is_empty(),
        "another tenant"
    );
    store
        .set_device_status(DEFAULT_TENANT, d, "quarantined")
        .await
        .unwrap();
    assert!(
        store
            .find_xmpp_credentials(DEFAULT_TENANT, d)
            .await
            .unwrap()
            .is_empty(),
        "only active devices log in"
    );
    store
        .set_device_status(DEFAULT_TENANT, d, "active")
        .await
        .unwrap();

    // Pending -> becomes the login.
    assert!(
        store
            .promote_credential(d, "xmpp_pending", "xmpp")
            .await
            .unwrap()
    );
    assert_eq!(
        kinds(
            store
                .find_xmpp_credentials(DEFAULT_TENANT, d)
                .await
                .unwrap()
        ),
        ["xmpp"]
    );
    store
        .put_credential(&sealed(d, "xmpp_pending", &d.to_string(), 5))
        .await
        .unwrap();
    assert!(store.delete_credential(d, "xmpp").await.unwrap());
    assert!(
        store
            .find_xmpp_credentials(DEFAULT_TENANT, d)
            .await
            .unwrap()
            .is_empty(),
        "the login and the one being provisioned go together"
    );
    assert!(
        store.get_credential(d, "acs_auth").await.unwrap().is_some(),
        "other kinds stay"
    );

    // Session times, microsecond precision = DB.
    let at = |micros: i64| {
        time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1000).unwrap()
    };
    assert!(
        store
            .set_xmpp_connected(d, at(1_700_000_000_000_001))
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .get_device(d)
            .await
            .unwrap()
            .unwrap()
            .xmpp_connected_at,
        Some(at(1_700_000_000_000_001))
    );
    // Newer session replaced it -> end of older one changes nothing.
    assert!(
        store
            .set_xmpp_connected(d, at(1_700_000_000_000_002))
            .await
            .unwrap()
    );
    assert!(
        !store
            .clear_xmpp_connected(d, at(1_700_000_000_000_001))
            .await
            .unwrap()
    );
    assert!(
        store
            .get_device(d)
            .await
            .unwrap()
            .unwrap()
            .xmpp_connected_at
            .is_some()
    );
    assert!(
        store
            .clear_xmpp_connected(d, at(1_700_000_000_000_002))
            .await
            .unwrap()
    );
    assert!(
        store
            .get_device(d)
            .await
            .unwrap()
            .unwrap()
            .xmpp_connected_at
            .is_none()
    );
    assert!(
        !store
            .set_xmpp_connected(Uuid::now_v7(), at(1))
            .await
            .unwrap(),
        "no such device"
    );

    // Startup -> all cleared.
    store
        .set_xmpp_connected(d, at(1_700_000_000_000_003))
        .await
        .unwrap();
    store
        .set_xmpp_connected(other, at(1_700_000_000_000_004))
        .await
        .unwrap();
    assert_eq!(store.clear_all_xmpp_connected().await.unwrap(), 2);
    assert_eq!(store.clear_all_xmpp_connected().await.unwrap(), 0);
}

/// Rollout: new credential next to current -> CPE may use either.
#[tokio::test]
async fn acs_credentials_are_found_active_first_and_deleted_with_their_pending_one() {
    let (_c, store) = setup().await;
    let (d, other) = (device(&store, "F1").await, device(&store, "F2").await);
    store
        .put_credential(&sealed(d, "acs_auth", "acs-same", 1))
        .await
        .unwrap();
    store
        .put_credential(&sealed(d, "acs_auth_pending", "acs-same", 2))
        .await
        .unwrap();
    store
        .put_credential(&sealed(other, "acs_auth", "acs-other", 3))
        .await
        .unwrap();
    let found = store
        .find_acs_credentials(DEFAULT_TENANT, "acs-same")
        .await
        .unwrap();
    let kinds: Vec<_> = found
        .iter()
        .map(|c| (c.kind.as_str(), c.device_id))
        .collect();
    assert_eq!(kinds, [("acs_auth", d), ("acs_auth_pending", d)]);
    assert!(
        store
            .find_acs_credentials(DEFAULT_TENANT, "acs-unknown")
            .await
            .unwrap()
            .is_empty()
    );

    // Credential deleted -> provisioning reset: pending counterpart goes too.
    // Other kinds + other devices stay.
    store
        .put_credential(&sealed(d, "connection_request", "cr", 4))
        .await
        .unwrap();
    assert!(store.delete_credential(d, "acs_auth").await.unwrap());
    assert_eq!(
        store.list_credentials(d).await.unwrap(),
        vec![("connection_request".to_owned(), "cr".to_owned())]
    );
    assert_eq!(store.list_credentials(other).await.unwrap().len(), 1);
    assert!(!store.delete_credential(d, "acs_auth").await.unwrap());
    // Only pending one left (stuck provisioning) -> deleted too.
    store
        .put_credential(&sealed(d, "connection_request_pending", "cr2", 5))
        .await
        .unwrap();
    assert!(
        store
            .delete_credential(d, "connection_request")
            .await
            .unwrap()
    );
    assert!(store.list_credentials(d).await.unwrap().is_empty());
}

/// L-5: max `max_total` parameters per device; known ones stay current.
#[tokio::test]
async fn capped_upserts_keep_a_device_to_its_limit() {
    let (_c, store) = setup().await;
    let d = device(&store, "CAP1").await;
    let other = device(&store, "CAP2").await;
    let p = |path: String, value: &str| ParamUpdate {
        path,
        value: Some(value.into()),
        xsd_type: Some("string".into()),
        writable: None,
    };
    let batch = |range: std::ops::Range<usize>, value: &str| -> Vec<ParamUpdate> {
        range.map(|i| p(format!("Device.X.{i}.V"), value)).collect()
    };

    // Within limit -> all stored.
    let done = store
        .upsert_params_capped(d, &batch(0..6, "a"), 10)
        .await
        .unwrap();
    assert_eq!((done.stored, done.dropped), (6, 0));
    // Over limit: known ones updated, new ones fill the rest of the room, others dropped.
    let mut more = batch(4..9, "b");
    more.extend(batch(20..23, "b"));
    let done = store.upsert_params_capped(d, &more, 10).await.unwrap();
    // 2 known (4, 5), 6 new (6, 7, 8, 20, 21, 22), room for 4.
    assert_eq!((done.stored, done.dropped), (2 + 4, 2), "{done:?}");
    let all = store.get_params(d, "").await.unwrap();
    assert_eq!(all.len(), 10);
    let value = |path: &str| {
        all.iter()
            .find(|x| x.path == path)
            .and_then(|x| x.value.clone())
    };
    assert_eq!(
        value("Device.X.5.V").as_deref(),
        Some("b"),
        "known: updated"
    );
    assert_eq!(
        value("Device.X.8.V").as_deref(),
        Some("b"),
        "new, there was room"
    );
    assert_eq!(
        value("Device.X.20.V").as_deref(),
        Some("b"),
        "the last one with room"
    );
    assert_eq!(value("Device.X.21.V"), None, "new, no room");
    // At limit -> only updates.
    let done = store
        .upsert_params_capped(
            d,
            &[p("Device.X.0.V".into(), "c"), p("Device.Y".into(), "c")],
            10,
        )
        .await
        .unwrap();
    assert_eq!((done.stored, done.dropped), (1, 1));
    // Same path x2 in one message -> fine, last entry wins.
    let done = store
        .upsert_params_capped(
            other,
            &[p("Device.Z".into(), "first"), p("Device.Z".into(), "last")],
            10,
        )
        .await
        .unwrap();
    assert_eq!((done.stored, done.dropped), (1, 0));
    assert_eq!(
        store.get_params(other, "Device.Z").await.unwrap()[0]
            .value
            .as_deref(),
        Some("last")
    );
    // Limit per device.
    assert_eq!(store.get_params(other, "").await.unwrap().len(), 1);
    assert_eq!(
        store.upsert_params_capped(d, &[], 10).await.unwrap(),
        dhonomos_store::CappedUpsert::default()
    );
}

fn text_param(path: &str, value: &str) -> ParamUpdate {
    ParamUpdate {
        path: path.into(),
        value: Some(value.into()),
        xsd_type: Some("string".into()),
        writable: None,
    }
}

const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n";
const HANGUL: &str = "";

/// `len` pseudo-random chars of `alphabet` (empty -> all Hangul syllables).
fn noise(len: usize, seed: u64, alphabet: &str) -> String {
    let chars: Vec<char> = alphabet.chars().collect();
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let n = (x >> 11) as usize;
            if chars.is_empty() {
                char::from_u32(0xAC00 + (n % 11_172) as u32).unwrap()
            } else {
                chars[n % chars.len()]
            }
        })
        .collect()
}

/// Btree index row ~2.7 KB -> index on the whole value refused longer values
/// (certificate, `DeviceInfo.DeviceLog` up to 32 KiB) -> their batch lost.
/// Now: stored, read back whole, found by every filter kind.
#[tokio::test]
async fn long_parameter_values_are_stored_and_searchable() {
    use dhonomos_store::{DeviceSearch, FilterExpr};
    let (_c, store) = setup().await;
    let migrated: Vec<String> = sqlx::query_scalar(
        "SELECT indexname FROM pg_indexes WHERE tablename = 'device_params' ORDER BY indexname",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(
        migrated,
        ["device_params_path_value_prefix", "device_params_pkey"],
        "the index on the whole value is gone"
    );

    let d = device(&store, "LONG1").await;
    let other = device(&store, "LONG2").await;
    // 32 KiB log text with needle in the middle, a certificate, 33 KB Hangul (3 bytes/char).
    // Text = noise: PostgreSQL compresses before indexing -> repeated text fits an index row.
    let log = format!(
        "{}needle-in-the-log{}",
        noise(16_000, 1, ALNUM),
        noise(16_800, 2, ALNUM)
    );
    assert!(log.len() >= 32 * 1024, "{}", log.len());
    let korean = noise(11_000, 3, HANGUL);
    let pem = format!("-----BEGIN CERTIFICATE-----\n{}", noise(10_000, 4, ALNUM));
    // 2 values, differ only after the first 256 chars (= part in the index).
    let head = "h".repeat(300);
    let (v1, v2) = (format!("{head}-one"), format!("{head}-two"));
    let batch = vec![
        text_param("Device.DeviceInfo.DeviceLog", &log),
        text_param("Device.Security.Certificate.1.PEM", &pem),
        text_param("Device.X_Korean", &korean),
        text_param("Device.X_Head", &v1),
        text_param("Device.DeviceInfo.UpTime", "100"),
    ];
    let done = store.upsert_params(d, &batch).await.unwrap();
    assert_eq!((done.stored, done.rejected.len()), (5, 0), "{done:?}");
    let done = store
        .upsert_params(other, &[text_param("Device.X_Head", &v2)])
        .await
        .unwrap();
    assert_eq!(done.stored, 1);
    // Old index -> could not hold these values.
    let old = sqlx::query("CREATE INDEX old_style ON device_params (path, value)")
        .execute(store.pool())
        .await;
    assert!(
        old.is_err(),
        "the values must be too long for an index on the whole value"
    );

    // Read back whole, also after a change (log changes on every read).
    let value = async |path: &str| {
        store.get_params(d, path).await.unwrap()[0]
            .value
            .clone()
            .unwrap()
    };
    assert_eq!(value("Device.DeviceInfo.DeviceLog").await, log);
    assert_eq!(value("Device.Security.Certificate.1.PEM").await, pem);
    assert_eq!(value("Device.X_Korean").await, korean);
    let newer = format!("{log}kernel: one more line\n");
    store
        .upsert_params(d, &[text_param("Device.DeviceInfo.DeviceLog", &newer)])
        .await
        .unwrap();
    assert_eq!(value("Device.DeviceInfo.DeviceLog").await, newer);

    let found = |expr: String| {
        let store = store.clone();
        async move {
            let filter = FilterExpr::parse(&expr).unwrap_or_else(|e| panic!("{expr}: {e}"));
            let search = DeviceSearch {
                filter: Some(filter),
                ..DeviceSearch::default()
            };
            let (devices, _) = store
                .search_devices(DEFAULT_TENANT, &search, 100, 0)
                .await
                .unwrap();
            let mut ids: Vec<Uuid> = devices.iter().map(|d| d.id).collect();
            ids.sort_unstable();
            ids
        }
    };
    let only = |id: Uuid| vec![id];
    // Pattern search + `exists` on the long value.
    assert_eq!(
        found("param.Device.DeviceInfo.DeviceLog ~ needle-in-the-log".into()).await,
        only(d)
    );
    assert!(
        found("param.Device.DeviceInfo.DeviceLog ~ not-in-it".into())
            .await
            .is_empty()
    );
    assert_eq!(
        found("param.Device.DeviceInfo.DeviceLog exists".into()).await,
        only(d)
    );
    assert_eq!(
        found("param.Device.Security.Certificate.1.PEM ~ BEGIN".into()).await,
        only(d)
    );
    // Equality on long value (filter text max 2000 chars -> value too):
    // prefix index narrows, whole value decides.
    assert_eq!(
        found(format!(r#"param.Device.X_Head = "{v1}""#)).await,
        only(d)
    );
    assert_eq!(
        found(format!(r#"param.Device.X_Head = "{v2}""#)).await,
        only(other)
    );
    assert!(
        found(format!(r#"param.Device.X_Head = "{head}""#))
            .await
            .is_empty(),
        "a prefix is not the value"
    );
    assert!(
        found(format!(r#"param.Device.X_Head = "{head}-thr""#))
            .await
            .is_empty()
    );
    let mut both = vec![d, other];
    both.sort_unstable();
    assert_eq!(
        found(format!(r#"param.Device.X_Head != "{head}-x""#)).await,
        both
    );
    // Filter on a normal parameter -> not affected.
    assert_eq!(
        found("param.Device.DeviceInfo.UpTime = 100".into()).await,
        only(d)
    );
    assert!(
        found("param.Device.DeviceInfo.UpTime = 10".into())
            .await
            .is_empty()
    );
    assert_eq!(
        found("param.Device.DeviceInfo.UpTime > 50".into()).await,
        only(d)
    );
}

/// Value PostgreSQL cannot hold (NUL char) must not lose the rest of its batch:
/// others stored, offender reported.
#[tokio::test]
async fn a_refused_parameter_does_not_lose_its_batch() {
    let (_c, store) = setup().await;
    let d = device(&store, "BAD1").await;
    let mut batch: Vec<ParamUpdate> = (0..40)
        .map(|i| text_param(&format!("Device.X.{i}.V"), "ok"))
        .collect();
    batch[7].value = Some("nul\0inside".into());
    batch[31].value = Some("\0".into());
    let done = store.upsert_params(d, &batch).await.unwrap();
    assert_eq!(done.stored, 38, "{done:?}");
    let rejected: Vec<&str> = done.rejected.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(rejected, ["Device.X.7.V", "Device.X.31.V"]);
    assert!(
        done.rejected.iter().all(|r| !r.error.contains("inside")),
        "the message must not carry the value: {done:?}"
    );
    let stored = store.get_params(d, "Device.X.").await.unwrap();
    assert_eq!(stored.len(), 38);
    assert!(stored.iter().all(|p| p.value.as_deref() == Some("ok")));

    // Same for device reports, with per-device limit.
    let other = device(&store, "BAD2").await;
    let mut batch: Vec<ParamUpdate> = (0..10)
        .map(|i| text_param(&format!("Device.Y.{i}"), "ok"))
        .collect();
    batch[3].value = Some("a\0b".into());
    let done = store.upsert_params_capped(other, &batch, 8).await.unwrap();
    // Room for 8; 1 of them refused.
    assert_eq!(
        (done.stored, done.dropped, done.rejected.len()),
        (7, 2, 1),
        "{done:?}"
    );
    assert_eq!(done.rejected[0].path, "Device.Y.3");
    assert_eq!(store.get_params(other, "").await.unwrap().len(), 7);
}

#[tokio::test]
async fn migration_0030_scrubs_the_stun_password_that_earlier_versions_stored() {
    let (_c, store) = setup().await;
    let d = device(&store, "STUN1").await;
    let text = |path: &str, value: Option<&str>| ParamUpdate {
        value: value.map(Into::into),
        ..text_param(path, "")
    };
    store
        .upsert_params(
            d,
            &[
                text("Device.ManagementServer.STUNPassword", Some("pw-1")),
                text(
                    "InternetGatewayDevice.ManagementServer.STUNPassword",
                    Some("pw-2"),
                ),
                text("Device.ManagementServer.STUNUsername", Some("user")),
                text("Device.Other.STUNPassword", Some("not-ours")),
                text("Device.ManagementServer.X_VENDOR.STUNPassword", None),
            ],
        )
        .await
        .unwrap();

    // STUN setups in every state + look-alike tasks that are not.
    let spv = |password: serde_json::Value| {
        json!({ "values": [
            { "name": "Device.ManagementServer.STUNEnable", "value": "true", "type": "boolean" },
            { "name": "Device.ManagementServer.STUNPassword", "value": password, "type": "string" },
            { "name": "Device.ManagementServer.STUNUsername", "value": "user" },
        ]})
    };
    let mut ids = std::collections::HashMap::new();
    for (key, created_by, kind, state, payload) in [
        (
            "done",
            "system:stun",
            "set_parameter_values",
            "succeeded",
            spv(json!("pw-1")),
        ),
        (
            "failed",
            "system:stun",
            "set_parameter_values",
            "failed",
            spv(json!("pw-1")),
        ),
        (
            "pending",
            "system:stun",
            "set_parameter_values",
            "pending",
            spv(json!("pw-1")),
        ),
        (
            "running",
            "system:stun",
            "set_parameter_values",
            "running",
            spv(json!("pw-1")),
        ),
        (
            "sealed",
            "system:stun",
            "set_parameter_values",
            "pending",
            {
                let mut p = spv(json!("enc:v2:AAAA"));
                p["values"][1]["secret"] = json!(true);
                p
            },
        ),
        (
            "operator",
            "api",
            "set_parameter_values",
            "succeeded",
            spv(json!("typed")),
        ),
        (
            "attributes",
            "system:stun",
            "set_parameter_attributes",
            "succeeded",
            json!({ "changes": [{ "name": "Device.ManagementServer.UDPConnectionRequestAddress",
                                  "notification": 2 }] }),
        ),
    ] {
        let task = NewTask {
            idempotency_key: Some(key.into()),
            created_by: Some(created_by.into()),
            ..NewTask::new(DEFAULT_TENANT, d, kind, payload)
        };
        let (id, _) = store.enqueue_task(&task).await.unwrap();
        sqlx::query("UPDATE tasks SET state = $2 WHERE id = $1")
            .bind(id)
            .bind(state)
            .execute(store.pool())
            .await
            .unwrap();
        ids.insert(key, id);
    }

    // Inform with the password + one without.
    let change = |path: &str, old: &str, new: &str| json!({ "path": path, "old": old, "new": new });
    for changes in [
        json!([
            change("Device.ManagementServer.STUNUsername", "a", "b"),
            change("Device.ManagementServer.STUNPassword", "pw-1", ""),
        ]),
        json!([change("Device.DeviceInfo.UpTime", "1", "2")]),
    ] {
        store
            .record_event(
                DEFAULT_TENANT,
                Some(d),
                "parameter_change",
                &json!({ "source": "cwmp-value-change", "changes": changes }),
            )
            .await
            .unwrap();
    }

    let scrub = include_str!("../migrations/0030_redact_stun_password.sql");
    let snapshot = async |store: &Store| {
        let params: Vec<_> = store
            .get_params(d, "")
            .await
            .unwrap()
            .into_iter()
            .map(|p| (p.path, p.value))
            .collect();
        let mut tasks = Vec::new();
        for id in ids.values() {
            tasks.push((*id, store.get_task(*id).await.unwrap().unwrap().payload));
        }
        tasks.sort_by_key(|(id, _)| *id);
        let events: Vec<_> = store
            .list_events(d, 10)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.detail)
            .collect();
        (params, tasks, events)
    };
    sqlx::raw_sql(scrub).execute(store.pool()).await.unwrap();
    let (params, tasks, events) = snapshot(&store).await;

    let value = |path: &str| {
        params
            .iter()
            .find(|(p, _)| p == path)
            .unwrap_or_else(|| panic!("{path}"))
            .1
            .clone()
    };
    assert_eq!(
        value("Device.ManagementServer.STUNPassword").as_deref(),
        Some("")
    );
    assert_eq!(
        value("InternetGatewayDevice.ManagementServer.STUNPassword").as_deref(),
        Some("")
    );
    assert_eq!(
        value("Device.ManagementServer.STUNUsername").as_deref(),
        Some("user")
    );
    assert_eq!(
        value("Device.Other.STUNPassword").as_deref(),
        Some("not-ours")
    );
    assert_eq!(value("Device.ManagementServer.X_VENDOR.STUNPassword"), None);

    let password = |key: &str| {
        let payload = &tasks.iter().find(|(id, _)| *id == ids[key]).unwrap().1;
        let entry = &payload["values"][1];
        assert_eq!(entry["name"], "Device.ManagementServer.STUNPassword");
        // Other values unchanged.
        assert_eq!(payload["values"][0]["value"], "true");
        assert_eq!(
            payload["values"][2],
            json!({ "name": "Device.ManagementServer.STUNUsername", "value": "user" })
        );
        (entry["value"].clone(), entry["secret"].clone())
    };
    // Finished -> value gone. Queued or running -> kept, as a secret.
    assert_eq!(password("done"), (json!("********"), json!(true)));
    assert_eq!(password("failed"), (json!("********"), json!(true)));
    assert_eq!(password("pending"), (json!("pw-1"), json!(true)));
    assert_eq!(password("running"), (json!("pw-1"), json!(true)));
    assert_eq!(password("sealed"), (json!("enc:v2:AAAA"), json!(true)));
    // Not an ACS STUN setup.
    assert_eq!(
        password("operator"),
        (json!("typed"), serde_json::Value::Null)
    );
    let attributes = &tasks
        .iter()
        .find(|(id, _)| *id == ids["attributes"])
        .unwrap()
        .1;
    assert_eq!(attributes["changes"][0]["notification"], 2);

    let stun_event = events
        .iter()
        .find(|e| e["changes"].as_array().is_some_and(|c| c.len() == 2))
        .unwrap();
    assert_eq!(stun_event["source"], "cwmp-value-change");
    assert_eq!(
        stun_event["changes"][0],
        change("Device.ManagementServer.STUNUsername", "a", "b")
    );
    assert_eq!(
        stun_event["changes"][1],
        change("Device.ManagementServer.STUNPassword", "********", "")
    );
    assert!(
        events
            .iter()
            .any(|e| e["changes"][0]["path"] == "Device.DeviceInfo.UpTime")
    );

    // Nothing left to change -> second run changes nothing.
    sqlx::raw_sql(scrub).execute(store.pool()).await.unwrap();
    assert_eq!(snapshot(&store).await, (params, tasks, events));
}

#[tokio::test]
async fn migration_0033_scrubs_the_secrets_usp_sets_stored() {
    const KEY: &str = "Device.WiFi.AccessPoint.1.Security.KeyPassphrase";
    const SSID: &str = "Device.WiFi.SSID.1.SSID";
    const RADIUS: &str = "Device.WiFi.AccessPoint.1.Security.RadiusSecret";
    const UNREAD: &str = "Device.WiFi.AccessPoint.2.Security.KeyPassphrase";
    let (_c, store) = setup().await;
    let d = device(&store, "USPSECRET1").await;
    // Same parameter on a device with no secret set.
    let other = device(&store, "USPSECRET2").await;
    let text = |path: &str, value: Option<&str>| ParamUpdate {
        value: value.map(Into::into),
        ..text_param(path, "")
    };
    store
        .upsert_params(
            d,
            &[
                text(KEY, Some("leaked-1")),
                text(SSID, Some("home")),
                text(RADIUS, Some("")),
                text(UNREAD, None),
            ],
        )
        .await
        .unwrap();
    store
        .upsert_params(other, &[text(KEY, Some("not-set-here"))])
        .await
        .unwrap();

    // Finished Set with a secret (plain text: no server key) + normal value,
    // queued one with sealed secret, Set with no secret.
    for (key, state, payload) in [
        (
            "done",
            "succeeded",
            json!({ "values": [
                { "name": KEY, "value": "leaked-1", "secret": true },
                { "name": SSID, "value": "home" },
            ]}),
        ),
        (
            "sealed",
            "pending",
            json!({ "values": [
                { "name": RADIUS, "value": "enc:v2:AAAA", "secret": true },
                { "name": UNREAD, "value": "enc:v2:BBBB", "secret": true },
            ]}),
        ),
        (
            "plain",
            "succeeded",
            json!({ "values": [{ "name": SSID, "value": "home", "secret": false }]}),
        ),
    ] {
        let task = NewTask {
            idempotency_key: Some(key.into()),
            ..NewTask::new(DEFAULT_TENANT, d, "set_parameter_values", payload)
        };
        let (id, _) = store.enqueue_task(&task).await.unwrap();
        sqlx::query("UPDATE tasks SET state = $2 WHERE id = $1")
            .bind(id)
            .bind(state)
            .execute(store.pool())
            .await
            .unwrap();
    }

    // ValueChange with leaked value kept as `old` + same on the other device.
    let change = |path: &str, old: &str, new: &str| json!({ "path": path, "old": old, "new": new });
    for device in [d, other] {
        store
            .record_event(
                DEFAULT_TENANT,
                Some(device),
                "parameter_change",
                &json!({ "source": "usp-value-change", "subscription": "s",
                         "changes": [change(KEY, "leaked-1", "leaked-2")] }),
            )
            .await
            .unwrap();
    }
    store
        .record_event(
            DEFAULT_TENANT,
            Some(d),
            "parameter_change",
            &json!({ "source": "usp-value-change", "subscription": "s",
                     "changes": [change(SSID, "home", "work")] }),
        )
        .await
        .unwrap();

    let scrub = include_str!("../migrations/0033_redact_usp_secret_params.sql");
    let snapshot = async |store: &Store| {
        let mut params = Vec::new();
        for device in [d, other] {
            params.extend(
                store
                    .get_params(device, "")
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|p| (device, p.path, p.value)),
            );
        }
        let mut events = Vec::new();
        for device in [d, other] {
            events.extend(
                store
                    .list_events(device, 10)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|e| (device, e.detail)),
            );
        }
        (params, events)
    };
    sqlx::raw_sql(scrub).execute(store.pool()).await.unwrap();
    let (params, events) = snapshot(&store).await;

    let value = |device: uuid::Uuid, path: &str| {
        params
            .iter()
            .find(|(dev, p, _)| *dev == device && p == path)
            .unwrap_or_else(|| panic!("{path}"))
            .2
            .clone()
    };
    assert_eq!(value(d, KEY).as_deref(), Some(""));
    assert_eq!(value(d, SSID).as_deref(), Some("home"));
    assert_eq!(value(d, RADIUS).as_deref(), Some(""));
    assert_eq!(value(d, UNREAD), None);
    assert_eq!(value(other, KEY).as_deref(), Some("not-set-here"));

    let changes = |device: uuid::Uuid, path: &str| {
        events
            .iter()
            .find(|(dev, e)| *dev == device && e["changes"][0]["path"] == path)
            .unwrap_or_else(|| panic!("{path}"))
            .1
            .clone()
    };
    let masked = changes(d, KEY);
    assert_eq!(masked["source"], "usp-value-change");
    assert_eq!(masked["subscription"], "s");
    assert_eq!(
        masked["changes"],
        json!([change(KEY, "********", "********")])
    );
    assert_eq!(
        changes(d, SSID)["changes"],
        json!([change(SSID, "home", "work")])
    );
    assert_eq!(
        changes(other, KEY)["changes"],
        json!([change(KEY, "leaked-1", "leaked-2")])
    );

    // Nothing left to change -> second run changes nothing.
    sqlx::raw_sql(scrub).execute(store.pool()).await.unwrap();
    assert_eq!(snapshot(&store).await, (params, events));
}

#[tokio::test]
async fn runtime_settings_are_set_reset_and_recorded() {
    use dhonomos_store::RUNTIME_SETTINGS_REVISION as KIND;
    let (_c, store) = setup().await;
    let t = DEFAULT_TENANT;
    assert!(store.runtime_settings(t).await.unwrap().is_empty());
    assert_eq!(store.config_revision(t, KIND).await.unwrap(), 0);

    let old = store
        .set_runtime_setting(t, "session_hours", &json!("8"), Some("alice"))
        .await
        .unwrap();
    assert_eq!(old, None);
    assert_eq!(store.config_revision(t, KIND).await.unwrap(), 1);
    let old = store
        .set_runtime_setting(t, "session_hours", &json!("4"), Some("bob"))
        .await
        .unwrap();
    assert_eq!(old, Some(json!("8")));
    store
        .set_runtime_setting(t, "webhook_url", &json!(["https://a", "https://b"]), None)
        .await
        .unwrap();
    assert_eq!(store.config_revision(t, KIND).await.unwrap(), 3);
    let all = store.runtime_settings(t).await.unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all["session_hours"], json!("4"));
    assert_eq!(all["webhook_url"], json!(["https://a", "https://b"]));

    let old = store
        .reset_runtime_setting(t, "session_hours", Some("carol"))
        .await
        .unwrap();
    assert_eq!(old, Some(json!("4")));
    assert_eq!(store.config_revision(t, KIND).await.unwrap(), 4);
    assert!(
        !store
            .runtime_settings(t)
            .await
            .unwrap()
            .contains_key("session_hours")
    );
    // Nothing stored -> no change, no record.
    assert_eq!(
        store
            .reset_runtime_setting(t, "session_hours", Some("carol"))
            .await
            .unwrap(),
        None
    );
    assert_eq!(store.config_revision(t, KIND).await.unwrap(), 4);

    let history = store
        .runtime_setting_history(t, "session_hours", 50)
        .await
        .unwrap();
    let h: Vec<_> = history
        .iter()
        .map(|c| (c.old.clone(), c.new.clone(), c.actor.clone()))
        .collect();
    assert_eq!(
        h,
        [
            (Some(json!("4")), None, Some("carol".to_owned())),
            (Some(json!("8")), Some(json!("4")), Some("bob".to_owned())),
            (None, Some(json!("8")), Some("alice".to_owned())),
        ]
    );
    let limited = store
        .runtime_setting_history(t, "session_hours", 1)
        .await
        .unwrap();
    assert_eq!(limited.len(), 1);
    assert_eq!(limited[0].new, None);
    assert_eq!(
        store
            .runtime_setting_history(t, "webhook_url", 50)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn alarm_rules_are_stored_with_their_history() {
    use dhonomos_store::ALARM_RULES_REVISION as KIND;
    let (_c, store) = setup().await;
    let t = DEFAULT_TENANT;
    assert!(store.alarm_rule_set(t).await.unwrap().is_none());
    assert!(
        store
            .alarm_rule_set_history(t, 20)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.config_revision(t, KIND).await.unwrap(), 0);

    let old = store
        .set_alarm_rule_set(t, "alarms: []", Some("alice"))
        .await
        .unwrap();
    assert_eq!(old, None);
    assert_eq!(store.config_revision(t, KIND).await.unwrap(), 1);
    let old = store
        .set_alarm_rule_set(t, "alarms: [{ name: a }]", Some("bob"))
        .await
        .unwrap();
    assert_eq!(old.as_deref(), Some("alarms: []"));
    assert_eq!(store.config_revision(t, KIND).await.unwrap(), 2);
    // Other kinds not bumped.
    assert_eq!(
        store
            .config_revision(t, dhonomos_store::RUNTIME_SETTINGS_REVISION)
            .await
            .unwrap(),
        0
    );

    let now = store.alarm_rule_set(t).await.unwrap().unwrap();
    assert_eq!(
        (now.yaml.as_str(), now.updated_by.as_deref()),
        ("alarms: [{ name: a }]", Some("bob"))
    );
    let history = store.alarm_rule_set_history(t, 20).await.unwrap();
    let got: Vec<_> = history
        .iter()
        .map(|v| (v.yaml.as_deref(), v.actor.as_deref()))
        .collect();
    assert_eq!(
        got,
        [
            (Some("alarms: [{ name: a }]"), Some("bob")),
            (Some("alarms: []"), Some("alice")),
        ]
    );
    assert_eq!(store.alarm_rule_set_history(t, 1).await.unwrap().len(), 1);
}
