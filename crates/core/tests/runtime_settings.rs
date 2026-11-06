//! Runtime settings -> every process. Watchers on one DB follow a change from anywhere:
//! within their poll interval, at once when woken.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dhonomos_store::{DEFAULT_TENANT, Store};
use serde_json::{Value, json};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tokio::sync::Notify;

type Seen = Arc<Mutex<Vec<BTreeMap<String, Value>>>>;

/// Watcher as in each process; records the values it gets.
fn watcher(store: &Store, every: Duration, seen_rev: Option<i64>) -> (Seen, Arc<Notify>) {
    let seen: Seen = Arc::default();
    let wake = Arc::new(Notify::new());
    let record = seen.clone();
    tokio::spawn(dhonomos_core::runtime_settings::watch(
        store.clone(),
        DEFAULT_TENANT,
        every,
        wake.clone(),
        seen_rev,
        move |values| record.lock().unwrap().push(values),
    ));
    (seen, wake)
}

async fn until(seen: &Seen, n: usize, within: Duration) -> Vec<BTreeMap<String, Value>> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let now = seen.lock().unwrap().clone();
        if now.len() >= n {
            return now;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "only {} of {n} changes seen",
            now.len()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn every_watcher_follows_a_change() {
    let pg = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let url = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        pg.get_host_port_ipv4(5432).await.unwrap()
    );
    let a = Store::connect(&url, 2).await.unwrap();
    a.migrate().await.unwrap();
    // 2 processes -> own pool each.
    let b = Store::connect(&url, 2).await.unwrap();
    let every = Duration::from_millis(300);
    // Start after startup load (revision 0 seen) -> nothing to apply yet.
    let (seen_a, wake_a) = watcher(&a, Duration::from_secs(3600), Some(0));
    let (seen_b, _) = watcher(&b, every, Some(0));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(seen_a.lock().unwrap().is_empty());
    assert!(seen_b.lock().unwrap().is_empty());

    // Change via `a` (its API wakes its own watcher) -> `b` follows within its poll.
    a.set_runtime_setting(DEFAULT_TENANT, "api_rate_limit", &json!("7"), Some("admin"))
        .await
        .unwrap();
    wake_a.notify_one();
    let got = until(&seen_a, 1, Duration::from_secs(2)).await;
    assert_eq!(got[0]["api_rate_limit"], json!("7"));
    let got = until(&seen_b, 1, every * 3).await;
    assert_eq!(got[0]["api_rate_limit"], json!("7"));

    // Reset -> reaches both too. No change -> no call.
    b.reset_runtime_setting(DEFAULT_TENANT, "api_rate_limit", None)
        .await
        .unwrap();
    let got = until(&seen_b, 2, every * 3).await;
    assert!(got[1].is_empty());
    wake_a.notify_one();
    until(&seen_a, 2, Duration::from_secs(2)).await;
    tokio::time::sleep(every * 2).await;
    assert_eq!(seen_b.lock().unwrap().len(), 2);

    // No revision seen -> 1st check applies the stored values.
    let (seen_c, _) = watcher(&b, every, None);
    let got = until(&seen_c, 1, every * 3).await;
    assert!(got[0].is_empty());
}
