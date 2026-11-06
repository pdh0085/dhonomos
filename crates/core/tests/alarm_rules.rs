//! Alarm rules stored from the web -> every process.
//! Watchers on one DB -> follow a change from anywhere within poll interval; at once when woken.
//! Rules that fail to load -> running ones kept.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use dhonomos_core::Shared;
use dhonomos_core::alarms::{AlarmRules, watch_stored};
use dhonomos_store::{DEFAULT_TENANT, Store};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tokio::sync::Notify;

/// Watcher like the one of each process.
fn watcher(store: &Store, every: Duration) -> (Shared<AlarmRules>, Arc<Notify>) {
    let rules = Shared::new(AlarmRules::default());
    let wake = Arc::new(Notify::new());
    tokio::spawn(watch_stored(
        store.clone(),
        DEFAULT_TENANT,
        rules.clone(),
        every,
        wake.clone(),
        Some(0),
    ));
    (rules, wake)
}

async fn until(rules: &Shared<AlarmRules>, name: &str, within: Duration) {
    let deadline = tokio::time::Instant::now() + within;
    while !rules.get().contains(name) {
        assert!(tokio::time::Instant::now() < deadline, "{name} not seen");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn one_rule(name: &str) -> String {
    format!("alarms: [{{ name: {name}, severity: major, when: {{ offline_minutes: 5 }} }}]")
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
    let (rules_a, wake_a) = watcher(&a, Duration::from_secs(3600));
    let (rules_b, _) = watcher(&b, every);

    // Stored via `a` (its API wakes its own watcher) -> `b` follows within its poll.
    a.set_alarm_rule_set(DEFAULT_TENANT, &one_rule("first"), Some("admin"))
        .await
        .unwrap();
    wake_a.notify_one();
    until(&rules_a, "first", Duration::from_secs(2)).await;
    until(&rules_b, "first", every * 3).await;

    // Stored rules that fail to load (not via the API) -> running ones kept.
    b.set_alarm_rule_set(DEFAULT_TENANT, "alarms: [{ name: broken }]", None)
        .await
        .unwrap();
    wake_a.notify_one();
    tokio::time::sleep(every * 3).await;
    assert!(rules_a.get().contains("first"));
    assert!(rules_b.get().contains("first"));

    // Next valid change -> applied.
    b.set_alarm_rule_set(DEFAULT_TENANT, &one_rule("second"), None)
        .await
        .unwrap();
    until(&rules_b, "second", every * 3).await;
    assert!(!rules_b.get().contains("first"));
    wake_a.notify_one();
    until(&rules_a, "second", Duration::from_secs(2)).await;
}
