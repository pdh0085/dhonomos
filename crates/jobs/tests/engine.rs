//! Job engine vs PostgreSQL: stages, gates, auto pause, verification, expiry.
#![allow(clippy::unwrap_used)]

use std::time::Duration;

use dhonomos_jobs::{Engine, Policy, Verify};
use dhonomos_store::{CwmpIdentity, DEFAULT_TENANT, DeviceFilter, InformUpdate, NewJob, Store};
use serde_json::json;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use uuid::Uuid;

async fn setup(devices: usize) -> (ContainerAsync<Postgres>, Store, Vec<Uuid>) {
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
    let mut ids = Vec::new();
    for i in 0..devices {
        let d = store
            .upsert_cwmp_device(
                DEFAULT_TENANT,
                &CwmpIdentity {
                    oui: "00AA00".into(),
                    product_class: "Box".into(),
                    serial_number: format!("SN{i:03}"),
                },
                &InformUpdate {
                    software_version: Some("1.0".into()),
                    ..InformUpdate::default()
                },
            )
            .await
            .unwrap();
        ids.push(d.id);
    }
    (c, store, ids)
}

async fn job(store: &Store, policy: Policy) -> Uuid {
    let id = store
        .create_job(&NewJob {
            tenant_id: DEFAULT_TENANT,
            name: "test".into(),
            target: DeviceFilter {
                oui: Some("00AA00".into()),
                ..DeviceFilter::default()
            },
            task_kind: "reboot".into(),
            task_payload: json!({}),
            policy: serde_json::to_value(policy).unwrap(),
            created_by: None,
        })
        .await
        .unwrap();
    store
        .start_job(
            id,
            &DeviceFilter {
                oui: Some("00AA00".into()),
                ..DeviceFilter::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    id
}

/// Run the pending task of each dispatched member. `fail(i)` -> member `i` fails.
async fn run_tasks(store: &Store, job: Uuid, fail: impl Fn(usize) -> bool) -> usize {
    let members = store
        .list_job_members(job, Some("dispatched"), 1000, 0)
        .await
        .unwrap();
    let mut n = 0;
    for (i, m) in members.iter().enumerate() {
        if let Some(t) = store.next_task(m.device_id).await.unwrap() {
            let outcome = if fail(i) {
                Err("9002 Internal error".into())
            } else {
                Ok(json!({}))
            };
            store
                .complete_task(m.device_id, t.id, outcome)
                .await
                .unwrap();
            n += 1;
        }
    }
    n
}

async fn state(store: &Store, job: Uuid) -> (String, i32, Option<String>) {
    let j = store.get_job(job).await.unwrap().unwrap();
    (j.state, j.stage, j.reason)
}

fn quick(policy: Policy) -> Policy {
    Policy {
        task: dhonomos_jobs::TaskOptions {
            max_attempts: 1,
            ..Default::default()
        },
        ..policy
    }
}

#[tokio::test]
async fn canary_then_rest_with_limits() {
    let (_c, store, _) = setup(20).await;
    let engine = Engine::new(store.clone(), None, Duration::from_secs(1));
    let id = job(
        &store,
        quick(Policy {
            stages: vec![10.0, 100.0],
            batch_size: 5,
            max_in_flight: 8,
            gate_success_rate: Some(100.0),
            ..Policy::default()
        }),
    )
    .await;
    engine.tick_job(id).await.unwrap();
    let c = store.job_counts(id, 20).await.unwrap();
    assert_eq!(c.total("dispatched"), 2, "canary = 10% of 20");
    engine.tick_job(id).await.unwrap();
    assert_eq!(
        store.job_counts(id, 20).await.unwrap().total("dispatched"),
        2,
        "stage limit holds"
    );

    assert_eq!(run_tasks(&store, id, |_| false).await, 2);
    engine.tick_job(id).await.unwrap(); // settle + advance
    assert_eq!(state(&store, id).await.1, 1, "gate passed, next stage");
    engine.tick_job(id).await.unwrap();
    assert_eq!(
        store.job_counts(id, 20).await.unwrap().total("dispatched"),
        5,
        "batch size"
    );
    engine.tick_job(id).await.unwrap();
    assert_eq!(
        store.job_counts(id, 20).await.unwrap().total("dispatched"),
        8,
        "in-flight cap"
    );

    for _ in 0..10 {
        run_tasks(&store, id, |_| false).await;
        engine.tick_job(id).await.unwrap();
    }
    let (s, _, _) = state(&store, id).await;
    assert_eq!(s, "completed");
    assert_eq!(
        store.job_counts(id, 20).await.unwrap().total("succeeded"),
        20
    );
}

#[tokio::test]
async fn failures_pause_the_job_and_cancel_stops_it() {
    let (_c, store, _) = setup(20).await;
    let engine = Engine::new(store.clone(), None, Duration::from_secs(1));
    let id = job(
        &store,
        quick(Policy {
            stages: vec![50.0, 100.0],
            batch_size: 10,
            abort_failure_rate: Some(30.0),
            min_samples: 4,
            ..Policy::default()
        }),
    )
    .await;
    engine.tick_job(id).await.unwrap();
    run_tasks(&store, id, |i| i % 2 == 0).await; // 50% fail
    engine.tick_job(id).await.unwrap();
    let (s, _, reason) = state(&store, id).await;
    assert_eq!(s, "paused");
    assert!(reason.unwrap().contains("failure rate 50.0%"));

    // Cancel -> queued members + pending tasks cancelled.
    store
        .transition_job(id, &["paused"], "cancelled", Some("by test"), None)
        .await
        .unwrap();
    store.cancel_job_members(id).await.unwrap();
    let c = store.job_counts(id, 20).await.unwrap();
    assert_eq!(c.total("cancelled"), 10);
    assert_eq!(c.total("queued"), 0);
    engine.tick_job(id).await.unwrap();
    assert_eq!(
        state(&store, id).await.0,
        "cancelled",
        "not driven any more"
    );
}

#[tokio::test]
async fn gates_wait_for_approval() {
    let (_c, store, _) = setup(10).await;
    let engine = Engine::new(store.clone(), None, Duration::from_secs(1));
    let id = job(
        &store,
        quick(Policy {
            stages: vec![20.0, 100.0],
            auto_advance: false,
            ..Policy::default()
        }),
    )
    .await;
    engine.tick_job(id).await.unwrap();
    run_tasks(&store, id, |_| false).await;
    engine.tick_job(id).await.unwrap();
    let (s, stage, reason) = state(&store, id).await;
    assert_eq!((s.as_str(), stage), ("paused", 0));
    assert!(reason.unwrap().contains("approve"));
    // Approve = next stage.
    store
        .transition_job(id, &["paused"], "running", None, Some(1))
        .await
        .unwrap();
    engine.tick_job(id).await.unwrap();
    assert_eq!(
        store.job_counts(id, 10).await.unwrap().total("dispatched"),
        8
    );
}

#[tokio::test]
async fn firmware_verification_and_expiry() {
    let (_c, store, ids) = setup(3).await;
    let engine = Engine::new(store.clone(), None, Duration::from_secs(1));
    let id = job(
        &store,
        Policy {
            verify: Some(Verify {
                software_version: "2.0".into(),
                within_seconds: 1,
            }),
            task: dhonomos_jobs::TaskOptions {
                max_attempts: 1,
                expires_in_seconds: Some(1),
                priority: 0,
            },
            ..Policy::default()
        },
    )
    .await;
    engine.tick_job(id).await.unwrap();
    let members = store.list_job_members(id, None, 10, 0).await.unwrap();
    let order: Vec<Uuid> = members.iter().map(|m| m.device_id).collect();
    // First 2 run the task; 3rd never connects.
    for d in &order[..2] {
        let t = store.next_task(*d).await.unwrap().unwrap();
        store.complete_task(*d, t.id, Ok(json!({}))).await.unwrap();
    }
    engine.tick_job(id).await.unwrap();
    assert_eq!(store.job_counts(id, 3).await.unwrap().total("verifying"), 2);
    // Only 1st comes back with new firmware.
    let serial = ids.iter().position(|i| *i == order[0]).unwrap();
    store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: "00AA00".into(),
                product_class: "Box".into(),
                serial_number: format!("SN{serial:03}"),
            },
            &InformUpdate {
                software_version: Some("2.0".into()),
                ..InformUpdate::default()
            },
        )
        .await
        .unwrap();
    engine.tick_job(id).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    engine.tick_job(id).await.unwrap();
    let members = store.list_job_members(id, None, 10, 0).await.unwrap();
    let by = |d: Uuid| members.iter().find(|m| m.device_id == d).unwrap().clone();
    assert_eq!(by(order[0]).state, "succeeded");
    assert_eq!(by(order[1]).state, "failed");
    assert!(by(order[1]).error.unwrap().contains("software version 2.0"));
    assert_eq!(by(order[2]).state, "failed");
    assert!(by(order[2]).error.unwrap().contains("expired"));
    engine.tick_job(id).await.unwrap();
    assert_eq!(state(&store, id).await.0, "completed");
}

#[tokio::test]
async fn paused_jobs_still_record_results() {
    let (_c, store, _) = setup(4).await;
    let engine = Engine::new(store.clone(), None, Duration::from_secs(1));
    let id = job(&store, quick(Policy::default())).await;
    engine.tick_job(id).await.unwrap();
    store
        .transition_job(id, &["running"], "paused", Some("test"), None)
        .await
        .unwrap();
    assert_eq!(store.jobs_to_settle().await.unwrap(), vec![id]);
    run_tasks(&store, id, |_| false).await;
    engine.settle(id).await.unwrap();
    assert_eq!(store.job_counts(id, 4).await.unwrap().total("succeeded"), 4);
    assert!(store.jobs_to_settle().await.unwrap().is_empty());
}
