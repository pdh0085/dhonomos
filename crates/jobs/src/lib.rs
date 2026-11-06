//! Bulk job engine (CO-15) + firmware campaigns (FW-02/03).
//! Stages, limits, gates, auto stops on top of the task queue. Design: docs/design/05-bulk-jobs.md.

use std::sync::Arc;
use std::time::Duration;

use dhonomos_core::secrets::{has_encrypted_secret, job_context, task_context};
use dhonomos_core::{SecretBox, Waker};
use dhonomos_store::{Job, NewTask, Store};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Task options per member.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TaskOptions {
    /// Attempts per device.
    pub max_attempts: i32,
    /// Not run within this time -> task expires, member fails.
    pub expires_in_seconds: Option<i64>,
    pub priority: i16,
}

impl Default for TaskOptions {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            expires_in_seconds: Some(86_400),
            priority: 0,
        }
    }
}

/// Firmware campaigns: success also needs this software version reported by the device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verify {
    /// Expected `software_version`.
    pub software_version: String,
    /// Deadline after task success.
    #[serde(default = "Verify::default_within")]
    pub within_seconds: i64,
}

impl Verify {
    fn default_within() -> i64 {
        1800
    }
}

/// Daily time window for member dispatch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    /// `HH:MM`, inclusive.
    pub start: String,
    /// `HH:MM`, exclusive. Before `start` -> window spans midnight.
    pub end: String,
    /// Local time offset from UTC.
    #[serde(default)]
    pub utc_offset_minutes: i32,
}

fn minutes(hhmm: &str) -> Option<i32> {
    let (h, m) = hhmm.split_once(':')?;
    let (h, m): (i32, i32) = (h.parse().ok()?, m.parse().ok()?);
    ((0..24).contains(&h) && (0..60).contains(&m)).then_some(h * 60 + m)
}

impl Window {
    pub fn contains(&self, now: OffsetDateTime) -> bool {
        let (Some(start), Some(end)) = (minutes(&self.start), minutes(&self.end)) else {
            return false;
        };
        let local = now + time::Duration::minutes(i64::from(self.utc_offset_minutes));
        let t = i32::from(local.hour()) * 60 + i32::from(local.minute());
        if start <= end {
            (start..end).contains(&t)
        } else {
            t >= start || t < end
        }
    }
}

/// Job run rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    /// Cumulative percentages, ascending, last = 100 (e.g. `[1, 10, 100]`).
    pub stages: Vec<f64>,
    /// Max members with an unfinished task at a time.
    pub max_in_flight: u32,
    /// New members per tick.
    pub batch_size: u32,
    /// Dispatch only inside this window.
    pub window: Option<Window>,
    /// Stage failure rate above this % -> pause.
    pub abort_failure_rate: Option<f64>,
    /// Min finished members before the failure rate counts.
    pub min_samples: u32,
    /// Min success % of a finished stage to go on.
    pub gate_success_rate: Option<f64>,
    /// Gate passed -> next stage without approval.
    pub auto_advance: bool,
    pub task: TaskOptions,
    /// Firmware campaigns: version the device must report after the task.
    pub verify: Option<Verify>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            stages: vec![100.0],
            max_in_flight: 200,
            batch_size: 100,
            window: None,
            abort_failure_rate: None,
            min_samples: 10,
            gate_success_rate: None,
            auto_advance: true,
            task: TaskOptions::default(),
            verify: None,
        }
    }
}

impl Policy {
    /// Check the policy. Error message -> API caller.
    pub fn validate(&self) -> Result<(), String> {
        let stages_ok = !self.stages.is_empty()
            && self.stages.windows(2).all(|w| w[0] < w[1])
            && self.stages.iter().all(|s| *s > 0.0 && *s <= 100.0)
            && self.stages.last() == Some(&100.0);
        if !stages_ok {
            return Err("stages must be ascending percentages in (0, 100] ending at 100".into());
        }
        if self.max_in_flight == 0 || self.batch_size == 0 {
            return Err("max_in_flight and batch_size must be at least 1".into());
        }
        for (name, v) in [
            ("abort_failure_rate", self.abort_failure_rate),
            ("gate_success_rate", self.gate_success_rate),
        ] {
            if v.is_some_and(|v| !(0.0..=100.0).contains(&v)) {
                return Err(format!("{name} must be a percentage"));
            }
        }
        if let Some(w) = &self.window
            && (minutes(&w.start).is_none() || minutes(&w.end).is_none())
        {
            return Err("window start and end must be HH:MM".into());
        }
        if self.task.max_attempts < 1 {
            return Err("task.max_attempts must be at least 1".into());
        }
        if self.verify.as_ref().is_some_and(|v| v.within_seconds < 1) {
            return Err("verify.within_seconds must be positive".into());
        }
        Ok(())
    }

    /// Highest member rank in the stage.
    pub fn stage_limit(&self, stage: usize, total: i32) -> i32 {
        let pct = self.stages.get(stage).copied().unwrap_or(100.0);
        ((f64::from(total) * pct / 100.0).ceil() as i32).clamp(0, total)
    }
}

/// Drives running jobs.
#[derive(Debug, Clone)]
pub struct Engine {
    store: Store,
    waker: Option<Waker>,
    interval: Duration,
    secrets: Option<Arc<SecretBox>>,
}

impl Engine {
    /// Tick every `interval`. `waker` -> connection requests for dispatched members.
    pub fn new(store: Store, waker: Option<Waker>, interval: Duration) -> Self {
        Self {
            store,
            waker,
            interval,
            secrets: None,
        }
    }

    /// Open encrypted secrets of the job's task -> reseal per member task
    /// (secrets bound to the row they are stored in).
    /// Without it -> job with secrets pauses at dispatch.
    #[must_use]
    pub fn with_secrets(mut self, secrets: Arc<SecretBox>) -> Self {
        self.secrets = Some(secrets);
        self
    }

    /// Run until `shutdown` resolves.
    /// Only the process with the DB lock drives jobs; others wait.
    pub async fn run(self, shutdown: impl std::future::Future<Output = ()>) {
        tokio::pin!(shutdown);
        let mut lock: Option<dhonomos_store::LeaderLock> = None;
        let mut tick = tokio::time::interval(self.interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = &mut shutdown => return,
                _ = tick.tick() => {}
            }
            if let Some(l) = lock.as_mut()
                && !l.alive().await
            {
                warn!("job engine lost its database lock");
                lock = None;
            }
            if lock.is_none() {
                match self.store.try_job_engine_lock().await {
                    Ok(Some(conn)) => {
                        info!("job engine active");
                        lock = Some(conn);
                    }
                    Ok(None) => continue,
                    Err(e) => {
                        warn!(error = %e, "job engine lock");
                        continue;
                    }
                }
            }
            match self.store.jobs_to_settle().await {
                Ok(ids) => {
                    for id in ids {
                        if let Err(e) = self.settle(id).await {
                            warn!(job = %id, error = %e, "settling job members failed");
                        }
                    }
                }
                Err(e) => warn!(error = %e, "listing jobs to settle failed"),
            }
            match self.store.running_jobs().await {
                Ok(ids) => {
                    for id in ids {
                        if let Err(e) = self.tick_job(id).await {
                            warn!(job = %id, error = %e, "job tick failed");
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "listing running jobs failed");
                    // Lock connection maybe gone -> take it again.
                    lock = None;
                }
            }
        }
    }

    /// Record results of already dispatched members (paused or cancelled jobs).
    pub async fn settle(&self, id: Uuid) -> Result<(), dhonomos_store::StoreError> {
        let Some(job) = self.store.get_job(id).await? else {
            return Ok(());
        };
        let policy: Policy = serde_json::from_value(job.policy).unwrap_or_default();
        self.store
            .sync_job_members(
                id,
                policy.verify.as_ref().map(|v| v.software_version.as_str()),
                policy.verify.as_ref().map(|v| v.within_seconds),
            )
            .await
    }

    /// One tick of a running job: settle members -> stop or advance -> dispatch more.
    #[tracing::instrument(name = "jobs.tick", skip(self))]
    pub async fn tick_job(&self, id: Uuid) -> Result<(), dhonomos_store::StoreError> {
        let Some(job) = self.store.get_job(id).await? else {
            return Ok(());
        };
        if job.state != "running" {
            return Ok(());
        }
        let policy: Policy = match serde_json::from_value(job.policy.clone()) {
            Ok(p) => p,
            Err(e) => {
                self.pause(&job, &format!("invalid policy: {e}")).await?;
                return Ok(());
            }
        };
        self.store
            .sync_job_members(
                id,
                policy.verify.as_ref().map(|v| v.software_version.as_str()),
                policy.verify.as_ref().map(|v| v.within_seconds),
            )
            .await?;
        let stage = usize::try_from(job.stage).unwrap_or(0);
        let limit = policy.stage_limit(stage, job.total);
        let c = self.store.job_counts(id, limit).await?;

        let (ok, failed) = (c.in_stage("succeeded"), c.in_stage("failed"));
        if let Some(max) = policy.abort_failure_rate {
            let finished = ok + failed;
            let rate = percent(failed, finished);
            if finished >= i64::from(policy.min_samples) && rate > max {
                metrics::counter!("dhonomos_job_auto_pauses_total").increment(1);
                let reason = format!(
                    "failure rate {rate:.1}% exceeded {max}% in stage {} ({failed} of {finished} failed)",
                    stage + 1
                );
                self.pause(&job, &reason).await?;
                return Ok(());
            }
        }

        let finished_all = c.total("succeeded") + c.total("failed") + c.total("cancelled");
        if finished_all >= i64::from(job.total) {
            self.store
                .transition_job(id, &["running"], "completed", None, None)
                .await?;
            info!(job = %id, succeeded = c.total("succeeded"), failed = c.total("failed"), "job completed");
            return Ok(());
        }

        let open_in_stage =
            c.in_stage("queued") + c.in_stage("dispatched") + c.in_stage("verifying");
        if open_in_stage == 0 {
            // Stage done + more stages left (else job completed above).
            let rate = percent(ok, ok + failed);
            let gate_ok = policy.gate_success_rate.is_none_or(|g| rate >= g);
            if gate_ok && policy.auto_advance {
                self.store
                    .transition_job(id, &["running"], "running", None, Some(job.stage + 1))
                    .await?;
                info!(job = %id, stage = stage + 2, "job advanced to the next stage");
            } else {
                let reason = if gate_ok {
                    format!(
                        "stage {} complete ({rate:.1}% succeeded): approve to continue",
                        stage + 1
                    )
                } else {
                    format!(
                        "stage {} succeeded {rate:.1}%, below the {}% gate",
                        stage + 1,
                        policy.gate_success_rate.unwrap_or_default()
                    )
                };
                self.pause(&job, &reason).await?;
            }
            return Ok(());
        }

        if policy
            .window
            .as_ref()
            .is_some_and(|w| !w.contains(OffsetDateTime::now_utc()))
        {
            return Ok(());
        }
        let in_flight = c.total("dispatched") + c.total("verifying");
        let room = (i64::from(policy.max_in_flight) - in_flight).min(i64::from(policy.batch_size));
        if room <= 0 {
            return Ok(());
        }
        let members = self.store.next_job_members(id, limit, room).await?;
        self.dispatch(&job, &policy, &members).await
    }

    async fn dispatch(
        &self,
        job: &Job,
        policy: &Policy,
        members: &[Uuid],
    ) -> Result<(), dhonomos_store::StoreError> {
        let expires_at = policy
            .task
            .expires_in_seconds
            .map(|s| OffsetDateTime::now_utc() + time::Duration::seconds(s));
        let encrypted = has_encrypted_secret(&job.task_payload);
        let mut woken = Vec::new();
        let mut stuck = None;
        for &device in members {
            // Task secrets bound to the task -> pick its ID first.
            let task_id = Uuid::now_v7();
            let mut payload = job.task_payload.clone();
            if encrypted {
                let resealed = match &self.secrets {
                    Some(secrets) => secrets
                        .reseal_fields(&mut payload, &job_context(job.id), &task_context(task_id))
                        .map_err(|e| e.to_string()),
                    None => Err("the server has no --secrets-key".to_owned()),
                };
                if let Err(e) = resealed {
                    stuck = Some(format!("the job's secrets cannot be passed on: {e}"));
                    break;
                }
            }
            let task = NewTask {
                priority: policy.task.priority,
                max_attempts: policy.task.max_attempts,
                idempotency_key: Some(format!("job:{}:{device}", job.id)),
                expires_at,
                created_by: Some(format!("job:{}", job.id)),
                job_id: Some(job.id),
                ..NewTask::new(job.tenant_id, device, job.task_kind.clone(), payload)
            };
            let (task_id, _) = self.store.enqueue_task_with_id(task_id, &task).await?;
            self.store
                .mark_member_dispatched(job.id, device, task_id)
                .await?;
            woken.push(device);
        }
        metrics::counter!("dhonomos_job_dispatched_total").increment(woken.len() as u64);
        debug!(job = %job.id, dispatched = woken.len(), "members dispatched");
        if let Some(waker) = self.waker.clone() {
            tokio::spawn(async move {
                for device in woken {
                    waker.wake(device).await;
                }
            });
        }
        if let Some(reason) = stuck {
            self.pause(job, &reason).await?;
        }
        Ok(())
    }

    async fn pause(&self, job: &Job, reason: &str) -> Result<(), dhonomos_store::StoreError> {
        if self
            .store
            .transition_job(job.id, &["running"], "paused", Some(reason), None)
            .await?
        {
            warn!(job = %job.id, reason, "job paused");
        }
        Ok(())
    }
}

fn percent(part: i64, whole: i64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn stage_limits_round_up() {
        let p = Policy {
            stages: vec![1.0, 10.0, 100.0],
            ..Policy::default()
        };
        assert!(p.validate().is_ok());
        assert_eq!(
            (
                p.stage_limit(0, 10_000),
                p.stage_limit(1, 10_000),
                p.stage_limit(2, 10_000)
            ),
            (100, 1_000, 10_000)
        );
        assert_eq!(p.stage_limit(0, 7), 1, "a canary has at least one device");
        assert_eq!(p.stage_limit(0, 0), 0);
    }

    #[test]
    fn invalid_policies() {
        for stages in [
            vec![],
            vec![10.0],
            vec![50.0, 10.0, 100.0],
            vec![0.0, 100.0],
        ] {
            let p = Policy {
                stages,
                ..Policy::default()
            };
            assert!(p.validate().is_err());
        }
        let p: Result<Policy, _> = serde_json::from_value(serde_json::json!({ "stagez": [100] }));
        assert!(p.is_err(), "unknown fields are rejected");
        let p = Policy {
            window: Some(Window {
                start: "25:00".into(),
                end: "01:00".into(),
                utc_offset_minutes: 0,
            }),
            ..Policy::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn windows_may_span_midnight() {
        let at = |h: u8, m: u8| {
            OffsetDateTime::UNIX_EPOCH
                .replace_hour(h)
                .unwrap()
                .replace_minute(m)
                .unwrap()
        };
        let night = Window {
            start: "23:00".into(),
            end: "05:00".into(),
            utc_offset_minutes: 0,
        };
        assert!(night.contains(at(23, 30)) && night.contains(at(2, 0)));
        assert!(!night.contains(at(5, 0)) && !night.contains(at(12, 0)));
        // 01:00-05:00 KST is 16:00-20:00 UTC.
        let kst = Window {
            start: "01:00".into(),
            end: "05:00".into(),
            utc_offset_minutes: 540,
        };
        assert!(kst.contains(at(17, 0)) && !kst.contains(at(1, 0)));
    }
}
