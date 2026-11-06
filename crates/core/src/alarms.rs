//! Alarms (CO-07): YAML rules, evaluated 1/min -> alarms raised + cleared in the store,
//! webhook notifications.
//!
//! Rules from `--alarms` file if given (reload on SIGHUP, read-only from the web).
//! Else in DB, edited from the web by admins (runtime settings, stage 4).
//! Every process follows a DB change within seconds ([`watch_stored`]). Format:
//!
//! ```yaml
//! alarms:
//!   - name: offline-1h
//!     severity: major
//!     devices: { product_class: Box }        # optional, as in jobs
//!     when: { offline_minutes: 60 }
//!   - name: wifi-noise
//!     severity: minor
//!     when: { metric: Device.WiFi.Radio.1.Stats.Noise, above: -70 }
//!   - name: boot-storm
//!     severity: warning
//!     when: { event: inform, detail: { events: ["1 BOOT"] }, count: 5, within_minutes: 60 }
//!   - name: wg-handshake
//!     severity: major
//!     when: { wg_handshake_minutes: 10 }
//! # More than this many alarms of one rule raised (or cleared) in one evaluation are
//! # notified as a single `alarm.storm` webhook (default 50, 0: never group).
//! storm_threshold: 50
//! ```
//!
//! Alarm under a silence (maintenance window) -> recorded, not notified; same for its clear.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dhonomos_store::{Alarm, DeviceFilter, RuleHit, Store};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// What raises the alarm.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Condition {
    /// No contact for this long.
    Offline {
        /// Minutes since last contact.
        offline_minutes: i64,
    },
    /// WireGuard device member applied on the CPE + its hub reporting -> no handshake from it
    /// for this long (or never, once the member is that old).
    WgHandshake {
        /// Minutes since latest handshake.
        wg_handshake_minutes: i64,
    },
    /// Latest value of a time series crosses a threshold.
    Metric {
        /// Parameter path of the series.
        metric: String,
        /// Raise above this value.
        #[serde(default)]
        above: Option<f64>,
        /// Raise below this value.
        #[serde(default)]
        below: Option<f64>,
    },
    /// Repeated events.
    Event {
        /// Event kind, e.g. `inform`, `transfer_complete`.
        event: String,
        /// Event detail must contain this JSON (e.g. `{events: ["1 BOOT"]}`).
        #[serde(default)]
        detail: Option<Value>,
        /// At least this many events within `within_minutes`.
        count: i64,
        within_minutes: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlarmRule {
    /// Unique.
    pub name: String,
    /// `critical`, `major`, `minor` or `warning`.
    pub severity: String,
    /// Devices of the rule (default: all active devices).
    #[serde(default)]
    pub devices: DeviceFilter,
    pub when: Condition,
}

const DEFAULT_STORM_THRESHOLD: usize = 50;

/// Max alarms in full in a storm webhook.
const STORM_SAMPLE: usize = 20;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    alarms: Vec<AlarmRule>,
    #[serde(default)]
    storm_threshold: Option<usize>,
}

/// Validated rule set. Serialized like the rule file (`alarms`, `storm_threshold`).
#[derive(Debug, Clone, Serialize)]
pub struct AlarmRules {
    #[serde(rename = "alarms")]
    rules: Vec<AlarmRule>,
    storm_threshold: usize,
}

impl Default for AlarmRules {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            storm_threshold: DEFAULT_STORM_THRESHOLD,
        }
    }
}

impl AlarmRules {
    /// Parse + validate a rule file.
    pub fn from_yaml(text: &str) -> Result<Self, String> {
        let file: RuleFile =
            serde_saphyr::from_str(text).map_err(|e| format!("invalid alarm rules: {e}"))?;
        let mut names = std::collections::HashSet::new();
        for r in &file.alarms {
            let bad = |why: &str| Err(format!("alarm rule {:?}: {why}", r.name));
            if r.name.trim().is_empty() || !names.insert(r.name.clone()) {
                return bad("names must be non-empty and unique");
            }
            if r.devices.expression.is_some() {
                return bad(
                    "devices take the fixed conditions; filter expressions are for searches and jobs",
                );
            }
            if !matches!(
                r.severity.as_str(),
                "critical" | "major" | "minor" | "warning"
            ) {
                return bad("severity must be critical, major, minor or warning");
            }
            match &r.when {
                Condition::Offline { offline_minutes } if *offline_minutes < 1 => {
                    return bad("offline_minutes must be at least 1");
                }
                Condition::WgHandshake {
                    wg_handshake_minutes,
                } if *wg_handshake_minutes < 3 => {
                    return bad(
                        "wg_handshake_minutes must be at least 3 (a live WireGuard session renews its handshake about every 2 minutes)",
                    );
                }
                Condition::Metric {
                    above: None,
                    below: None,
                    ..
                } => {
                    return bad("a metric rule needs above or below");
                }
                Condition::Event {
                    count,
                    within_minutes,
                    ..
                } if *count < 1 || *within_minutes < 1 => {
                    return bad("count and within_minutes must be at least 1");
                }
                _ => {}
            }
        }
        Ok(Self {
            rules: file.alarms,
            storm_threshold: file.storm_threshold.unwrap_or(DEFAULT_STORM_THRESHOLD),
        })
    }

    pub fn contains(&self, name: &str) -> bool {
        self.rules.iter().any(|r| r.name == name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &AlarmRule> {
        self.rules.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Start rules of a process from the DB (`yaml`: stored rules, if any).
    ///
    /// None stored -> no rules.
    /// Stored rules fail to load -> logged, no rules -> server still starts.
    /// Next evaluation then clears the active alarms of every rule.
    pub fn from_stored(yaml: Option<&str>) -> Self {
        let Some(yaml) = yaml else {
            info!("no alarm rules stored; starting with none");
            return Self::default();
        };
        match Self::from_yaml(yaml) {
            Ok(rules) => {
                info!(
                    rules = rules.rules.len(),
                    "alarm rules loaded from the database"
                );
                rules
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "the stored alarm rules are invalid; starting with no rules (fix them from the web). Active alarms of rules not in the set will be cleared"
                );
                Self::default()
            }
        }
    }
}

/// Keep `rules` in step with the alarm rules in the DB (server without `--alarms`).
///
/// Revision != `seen` (check every `every`, or at once on `wake` after a change via the
/// API of this process) -> load, validate, replace `rules`.
/// Load fails or none stored -> running rules kept. Replace would clear the alarms of
/// every rule missing from the new set.
pub async fn watch_stored(
    store: Store,
    tenant_id: Uuid,
    rules: crate::Shared<AlarmRules>,
    every: Duration,
    wake: Arc<tokio::sync::Notify>,
    seen: Option<i64>,
) {
    let load = {
        let store = store.clone();
        move || {
            let store = store.clone();
            async move { store.alarm_rule_set(tenant_id).await }
        }
    };
    crate::runtime_settings::watch_revision(
        &store,
        tenant_id,
        dhonomos_store::ALARM_RULES_REVISION,
        "alarm rules",
        every,
        wake,
        seen,
        load,
        |rev, stored: Option<dhonomos_store::StoredAlarmRules>| {
            let Some(stored) = stored else {
                warn!(
                    revision = rev,
                    "no alarm rules stored; keeping the running ones"
                );
                return;
            };
            match AlarmRules::from_yaml(&stored.yaml) {
                Ok(r) => {
                    info!(
                        revision = rev,
                        rules = r.rules.len(),
                        "alarm rules loaded from the database"
                    );
                    rules.replace(r);
                }
                Err(e) => tracing::error!(
                    revision = rev,
                    error = %e,
                    "the stored alarm rules are invalid; keeping the running ones"
                ),
            }
        },
    )
    .await;
}

/// JSON form of an alarm (API + webhooks).
pub fn alarm_json(a: &Alarm) -> Value {
    let ts = |t: time::OffsetDateTime| t.format(&Rfc3339).unwrap_or_default();
    json!({
        "id": a.id,
        "device_id": a.device_id,
        "rule": a.rule,
        "severity": a.severity,
        "state": a.state,
        "message": a.message,
        "detail": a.detail,
        "raised_at": ts(a.raised_at),
        "cleared_at": a.cleared_at.map(ts),
        "acked_at": a.acked_at.map(ts),
        "acked_by": a.acked_by,
        "silenced_by": a.silenced_by,
    })
}

fn message(rule: &AlarmRule, hit: &RuleHit) -> String {
    match &rule.when {
        Condition::Offline { .. } => format!("No contact for {:.0} minutes", hit.value),
        Condition::WgHandshake { .. } => {
            format!("No WireGuard handshake for {:.0} minutes", hit.value)
        }
        Condition::Metric {
            metric,
            above,
            below,
        } => match (above, below) {
            (Some(a), _) if hit.value > *a => format!("{metric} = {} (above {a})", hit.value),
            (_, Some(b)) => format!("{metric} = {} (below {b})", hit.value),
            _ => format!("{metric} = {}", hit.value),
        },
        Condition::Event {
            event,
            within_minutes,
            ..
        } => {
            format!("{} {event} events in {within_minutes} minutes", hit.value)
        }
    }
}

/// Webhook targets. Payload signed with HMAC-SHA256 in `X-Dhonomos-Signature`.
#[derive(Debug, Clone, Default)]
pub struct Webhooks {
    /// URLs (http or https).
    pub urls: Vec<String>,
    /// Signing secret (empty -> unsigned).
    pub secret: String,
}

/// E-mail notifications (NB-07).
#[derive(Debug, Clone)]
pub struct AlarmEmail {
    /// Server, sender, recipients.
    pub smtp: crate::mail::SmtpConfig,
    /// Min severity to send (`critical` > `major` > `minor` > `warning`).
    pub min_severity: String,
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "major" => 3,
        "minor" => 2,
        "warning" => 1,
        _ => 0,
    }
}

/// Periodic rule evaluation.
#[derive(Debug, Clone)]
pub struct AlarmEngine {
    store: Store,
    tenant_id: Uuid,
    rules: crate::Shared<AlarmRules>,
    /// Replaceable while running (runtime settings); secret is not.
    webhook_urls: crate::Shared<Vec<String>>,
    webhook_secret: Arc<str>,
    /// Replaceable while running (runtime settings). `None` -> no e-mail.
    email: crate::Shared<Option<Arc<AlarmEmail>>>,
}

impl AlarmEngine {
    /// Engine for one tenant. [`crate::Shared`] rules -> reload while running.
    pub fn new(
        store: Store,
        tenant_id: Uuid,
        rules: impl Into<crate::Shared<AlarmRules>>,
        webhooks: Webhooks,
    ) -> Self {
        Self {
            store,
            tenant_id,
            rules: rules.into(),
            webhook_urls: crate::Shared::new(webhooks.urls),
            webhook_secret: webhooks.secret.into(),
            email: crate::Shared::new(None),
        }
    }

    /// Also notify by e-mail.
    pub fn with_email(self, email: AlarmEmail) -> Self {
        self.email.replace(Some(Arc::new(email)));
        self
    }

    /// Webhook URLs, replaceable while running.
    pub fn webhook_urls(&self) -> crate::Shared<Vec<String>> {
        self.webhook_urls.clone()
    }

    /// E-mail settings, replaceable while running (`None` -> off).
    pub fn email(&self) -> crate::Shared<Option<Arc<AlarmEmail>>> {
        self.email.clone()
    }

    /// Snapshot of the current rules.
    pub fn rules(&self) -> Arc<AlarmRules> {
        self.rules.get()
    }

    /// Devices of `hits` under a silence for `rule` -> silence ID.
    async fn silenced(
        &self,
        silences: &[dhonomos_store::Silence],
        rule: &str,
        hits: &[RuleHit],
    ) -> Result<HashMap<Uuid, Uuid>, dhonomos_store::StoreError> {
        let now = OffsetDateTime::now_utc();
        let mut out = HashMap::new();
        let ids: Vec<Uuid> = hits.iter().map(|h| h.device_id).collect();
        if ids.is_empty() {
            return Ok(out);
        }
        for s in silences.iter().filter(|s| s.applies_to(rule, now)) {
            for d in self
                .store
                .devices_in_filter(self.tenant_id, &s.devices, &ids)
                .await?
            {
                out.entry(d).or_insert(s.id);
            }
        }
        Ok(out)
    }

    /// Evaluate every rule once -> (raised, cleared).
    #[tracing::instrument(name = "alarms.evaluate", skip_all)]
    pub async fn evaluate(&self) -> Result<(usize, usize), dhonomos_store::StoreError> {
        let (mut raised, mut cleared, mut silenced_total) = (0, 0, 0);
        let silences = self.store.list_silences(self.tenant_id, false).await?;
        let rules = self.rules.get();
        // Rule removed by a reload -> never evaluated again -> clear its alarms.
        for gone in self.store.active_alarm_rules(self.tenant_id).await? {
            if !rules.contains(&gone) {
                let n = self
                    .store
                    .clear_alarms_except(self.tenant_id, &gone, &[])
                    .await?
                    .len();
                info!(rule = %gone, cleared = n, "alarms of a removed rule cleared");
                cleared += n;
            }
        }
        for rule in rules.iter() {
            let (mut rule_raised, mut rule_cleared) = (0, 0);
            let (mut notify_raised, mut notify_cleared) = (Vec::new(), Vec::new());
            let hits = match &rule.when {
                Condition::Offline { offline_minutes } => {
                    self.store
                        .offline_devices(self.tenant_id, &rule.devices, *offline_minutes)
                        .await?
                }
                Condition::WgHandshake {
                    wg_handshake_minutes,
                } => {
                    self.store
                        .wg_handshake_stale_devices(
                            self.tenant_id,
                            &rule.devices,
                            *wg_handshake_minutes,
                        )
                        .await?
                }
                Condition::Metric {
                    metric,
                    above,
                    below,
                } => {
                    self.store
                        .metric_breaches(self.tenant_id, &rule.devices, metric, *above, *below)
                        .await?
                }
                Condition::Event {
                    event,
                    detail,
                    count,
                    within_minutes,
                } => {
                    self.store
                        .event_bursts(
                            self.tenant_id,
                            &rule.devices,
                            event,
                            detail.as_ref().unwrap_or(&json!({})),
                            *count,
                            *within_minutes,
                        )
                        .await?
                }
            };
            let silenced = self.silenced(&silences, &rule.name, &hits).await?;
            for hit in &hits {
                let detail = json!({ "value": hit.value });
                if let Some(a) = self
                    .store
                    .raise_alarm(
                        self.tenant_id,
                        hit.device_id,
                        &rule.name,
                        &rule.severity,
                        &message(rule, hit),
                        &detail,
                        silenced.get(&hit.device_id).copied(),
                    )
                    .await?
                {
                    rule_raised += 1;
                    debug!(rule = %rule.name, device = %a.device_id, silenced = a.silenced_by.is_some(), "alarm raised");
                    if a.silenced_by.is_some() {
                        silenced_total += 1;
                    } else {
                        notify_raised.push(a);
                    }
                }
            }
            let matching: Vec<Uuid> = hits.iter().map(|h| h.device_id).collect();
            for a in self
                .store
                .clear_alarms_except(self.tenant_id, &rule.name, &matching)
                .await?
            {
                rule_cleared += 1;
                debug!(rule = %rule.name, device = %a.device_id, "alarm cleared");
                // Raised silent -> cleared silent.
                if a.silenced_by.is_none() {
                    notify_cleared.push(a);
                }
            }
            self.notify_all(rule, "raised", &notify_raised);
            self.notify_all(rule, "cleared", &notify_cleared);
            if rule_raised + rule_cleared > 0 {
                info!(rule = %rule.name, raised = rule_raised, cleared = rule_cleared, "alarms changed");
            }
            raised += rule_raised;
            cleared += rule_cleared;
        }
        metrics::counter!("dhonomos_alarms_raised_total").increment(raised as u64);
        metrics::counter!("dhonomos_alarms_cleared_total").increment(cleared as u64);
        metrics::counter!("dhonomos_alarms_silenced_total").increment(silenced_total as u64);
        Ok((raised, cleared))
    }

    /// One webhook per alarm. Count > storm threshold -> one `alarm.storm` webhook.
    /// Mass outage -> page once, not 10000x.
    fn notify_all(&self, rule: &AlarmRule, state: &str, alarms: &[Alarm]) {
        if alarms.is_empty() {
            return;
        }
        let threshold = self.rules.get().storm_threshold;
        self.email_all(rule, state, alarms, threshold);
        if self.webhook_urls.get().is_empty() {
            return;
        }
        if threshold > 0 && alarms.len() > threshold {
            info!(rule = %rule.name, state, count = alarms.len(), "alarm storm notified as one webhook");
            metrics::counter!("dhonomos_alarm_storms_total").increment(1);
            self.send(json!({
                "type": "alarm.storm",
                "rule": rule.name,
                "severity": rule.severity,
                "state": state,
                "count": alarms.len(),
                "alarms": alarms.iter().take(STORM_SAMPLE).map(alarm_json).collect::<Vec<_>>(),
            }));
            return;
        }
        for a in alarms {
            self.send(json!({ "type": format!("alarm.{state}"), "alarm": alarm_json(a) }));
        }
    }

    /// One e-mail per alarm. Count > storm threshold -> one summary.
    fn email_all(&self, rule: &AlarmRule, state: &str, alarms: &[Alarm], threshold: usize) {
        let Some(email) = self.email.get().as_ref().clone() else {
            return;
        };
        if severity_rank(&rule.severity) < severity_rank(&email.min_severity) {
            return;
        }
        let (store, rule, state, alarms) = (
            self.store.clone(),
            rule.clone(),
            state.to_owned(),
            alarms.to_vec(),
        );
        tokio::spawn(async move {
            let ids: Vec<Uuid> = alarms.iter().map(|a| a.device_id).collect();
            let labels = store.device_labels(&ids).await.unwrap_or_default();
            let label = |a: &Alarm| {
                labels
                    .get(&a.device_id)
                    .cloned()
                    .unwrap_or_else(|| a.device_id.to_string())
            };
            let ts = |t: OffsetDateTime| t.format(&Rfc3339).unwrap_or_default();
            let mut messages = Vec::new();
            if threshold > 0 && alarms.len() > threshold {
                let mut body = format!(
                    "{} alarms of rule {} ({}) {state}.\n\nFirst {}:\n",
                    alarms.len(),
                    rule.name,
                    rule.severity,
                    STORM_SAMPLE.min(alarms.len())
                );
                for a in alarms.iter().take(STORM_SAMPLE) {
                    body.push_str(&format!("  {}  {}\n", label(a), a.message));
                }
                messages.push((
                    format!(
                        "[Dhonomos] {} {}: {} alarms {state}",
                        rule.severity,
                        rule.name,
                        alarms.len()
                    ),
                    body,
                ));
            } else {
                for a in &alarms {
                    let when = if state == "cleared" {
                        a.cleared_at.map(ts).unwrap_or_default()
                    } else {
                        ts(a.raised_at)
                    };
                    messages.push((
                        format!(
                            "[Dhonomos] {} {} {state}: {}",
                            a.severity,
                            a.rule,
                            label(a)
                        ),
                        format!(
                            "Alarm {state}\n\nRule:     {} ({})\nDevice:   {} ({})\nMessage:  {}\nTime:     {when}\nAlarm ID: {}\n",
                            a.rule,
                            a.severity,
                            label(a),
                            a.device_id,
                            a.message,
                            a.id
                        ),
                    ));
                }
            }
            for (subject, body) in messages {
                let mut sent = false;
                for attempt in 0..3u32 {
                    if attempt > 0 {
                        tokio::time::sleep(Duration::from_secs(2u64.pow(attempt))).await;
                    }
                    match crate::mail::send(&email.smtp, &subject, &body).await {
                        Ok(()) => {
                            sent = true;
                            break;
                        }
                        Err(e) => debug!(attempt, error = %e, "alarm e-mail failed"),
                    }
                }
                let outcome = if sent { "sent" } else { "failed" };
                metrics::counter!("dhonomos_alarm_emails_total", "outcome" => outcome).increment(1);
                if !sent {
                    warn!(%subject, "alarm e-mail gave up after 3 attempts");
                }
            }
        });
    }

    fn send(&self, body: Value) {
        let body = body.to_string();
        for url in self.webhook_urls.get().iter() {
            let (url, body, secret) = (url.clone(), body.clone(), self.webhook_secret.clone());
            tokio::spawn(async move {
                for attempt in 0..3u32 {
                    if attempt > 0 {
                        tokio::time::sleep(Duration::from_secs(2u64.pow(attempt))).await;
                    }
                    match crate::webhook::post(&url, &body, &secret).await {
                        Ok(()) => {
                            metrics::counter!("dhonomos_webhooks_total", "outcome" => "sent")
                                .increment(1);
                            return;
                        }
                        Err(e) => {
                            debug!(webhook = %crate::webhook::redact_url(&url), attempt, error = %e, "webhook failed")
                        }
                    }
                }
                metrics::counter!("dhonomos_webhooks_total", "outcome" => "failed").increment(1);
                warn!(webhook = %crate::webhook::redact_url(&url), "webhook gave up after 3 attempts");
            });
        }
    }

    /// Evaluate every `interval` until `shutdown` resolves.
    /// Only the process with the DB lock evaluates; others stand by.
    pub async fn run(self, interval: Duration, shutdown: impl std::future::Future<Output = ()>) {
        tokio::pin!(shutdown);
        let mut tick = tokio::time::interval(interval);
        let mut lock: Option<dhonomos_store::LeaderLock> = None;
        loop {
            tokio::select! {
                () = &mut shutdown => return,
                _ = tick.tick() => {}
            }
            if let Some(l) = lock.as_mut()
                && !l.alive().await
            {
                warn!("alarm engine lost its database lock");
                lock = None;
            }
            if lock.is_none() {
                match self.store.try_alarm_engine_lock().await {
                    Ok(Some(l)) => {
                        info!("alarm engine active");
                        lock = Some(l);
                    }
                    Ok(None) => continue,
                    Err(e) => {
                        warn!(error = %e, "alarm engine lock");
                        continue;
                    }
                }
            }
            if let Err(e) = self.evaluate().await {
                warn!(error = %e, "alarm evaluation failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_rules_that_fail_to_load_are_none() {
        assert!(AlarmRules::from_stored(None).is_empty());
        assert!(AlarmRules::from_stored(Some("alarms: [{ name: x }]")).is_empty());
        assert!(AlarmRules::from_stored(Some("not: yaml: at all")).is_empty());
        let r = AlarmRules::from_stored(Some(
            "alarms: [{ name: a, severity: major, when: { offline_minutes: 5 } }]",
        ));
        assert!(r.contains("a"));
    }

    #[test]
    fn rule_files() {
        let r = AlarmRules::from_yaml(
            r#"
alarms:
  - name: offline
    severity: major
    when: { offline_minutes: 60 }
  - name: noise
    severity: minor
    devices: { product_class: Box }
    when: { metric: Device.WiFi.Radio.1.Stats.Noise, above: -70 }
  - name: boots
    severity: warning
    when: { event: inform, detail: { events: ["1 BOOT"] }, count: 5, within_minutes: 60 }
"#,
        );
        let r = r.unwrap_or_else(|e| panic!("{e}"));
        let kinds: Vec<_> = r.iter().map(|x| std::mem::discriminant(&x.when)).collect();
        assert_eq!(kinds.len(), 3);
        assert!(matches!(
            r.iter().nth(2).map(|x| &x.when),
            Some(Condition::Event { count: 5, .. })
        ));
        assert_eq!(r.storm_threshold, DEFAULT_STORM_THRESHOLD);
        assert!(r.contains("noise") && !r.contains("nope"));
        let r = AlarmRules::from_yaml(
            "storm_threshold: 0\nalarms: [{ name: a, severity: major, when: { offline_minutes: 5 } }]",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(r.storm_threshold, 0);
        for bad in [
            "alarms: [{ name: a, severity: loud, when: { offline_minutes: 5 } }]",
            "alarms: [{ name: a, severity: major, when: { metric: X } }]",
            "alarms: [{ name: a, severity: major, when: { offline_minutes: 0 } }]",
            "alarms: [{ name: a, severity: major, when: { offline_minutes: 5 } }, { name: a, severity: major, when: { offline_minutes: 5 } }]",
            "alarms: [{ name: a, severity: major, when: { nonsense: 1 } }]",
        ] {
            assert!(AlarmRules::from_yaml(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn wg_handshake_rules() {
        let r = AlarmRules::from_yaml(
            "alarms: [{ name: wg-handshake, severity: major, devices: { product_class: Box }, when: { wg_handshake_minutes: 10 } }]",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let rule = r.iter().next().unwrap_or_else(|| panic!("no rule"));
        assert_eq!(
            rule.when,
            Condition::WgHandshake {
                wg_handshake_minutes: 10
            }
        );
        assert_eq!(rule.devices.product_class.as_deref(), Some("Box"));
        let hit = RuleHit {
            device_id: Uuid::nil(),
            value: 12.4,
        };
        assert_eq!(message(rule, &hit), "No WireGuard handshake for 12 minutes");
        AlarmRules::from_yaml(
            "alarms: [{ name: a, severity: major, when: { wg_handshake_minutes: 3 } }]",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            AlarmRules::from_yaml(
                "alarms: [{ name: a, severity: major, when: { wg_handshake_minutes: 2 } }]",
            )
            .err()
            .as_deref(),
            Some(
                "alarm rule \"a\": wg_handshake_minutes must be at least 3 (a live WireGuard session renews its handshake about every 2 minutes)"
            )
        );
    }
}
