//! Bulk jobs (CO-15): definitions, member snapshots, progress.
//! Engine: `dhonomos-jobs`; see docs/design/05-bulk-jobs.md.

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Device, Result, Store, StoreError};

/// Session-level advisory lock, held while its own connection lives.
/// Drop -> connection closed -> lock released.
#[derive(Debug)]
pub struct LeaderLock(Option<sqlx::PgConnection>);

impl LeaderLock {
    /// Lock still held? `false` after a connection break (e.g. DB restart)
    /// -> another process may take it.
    pub async fn alive(&mut self) -> bool {
        use sqlx::Connection as _;
        match self.0.as_mut() {
            Some(c) => c.ping().await.is_ok(),
            None => false,
        }
    }
}

/// Target devices of a job. Every set field must match.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceFilter {
    /// `cwmp` or `usp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Manufacturer OUI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oui: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_class: Option<String>,
    /// Any of these versions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub software_version: Vec<String>,
    /// All of these tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Only these devices.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_ids: Vec<Uuid>,
    /// Device status, default `active`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Exact attribute values (CO-13), e.g. `{plan: gold}`.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub attributes: std::collections::BTreeMap<String, String>,
    /// Filter expression (NB-01), must also match. Job targets only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
}

impl DeviceFilter {
    /// Attribute condition as JSON object for `attributes @> ...` (empty -> match all).
    pub fn attributes_json(&self) -> serde_json::Value {
        serde_json::json!(self.attributes)
    }

    fn status(&self) -> &str {
        self.status.as_deref().unwrap_or("active")
    }
}

#[derive(Debug, Clone)]
pub struct NewJob {
    pub tenant_id: Uuid,
    pub name: String,
    pub target: DeviceFilter,
    /// Task kind, run on each device.
    pub task_kind: String,
    pub task_payload: Json,
    /// Policy (stages, limits, gates) -> read by the engine.
    pub policy: Json,
    pub created_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Job {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    /// [`DeviceFilter`] as JSON.
    pub target: Json,
    pub task_kind: String,
    pub task_payload: Json,
    pub policy: Json,
    /// `draft`, `running`, `paused`, `completed` or `cancelled`.
    pub state: String,
    /// Current stage = index into policy stages.
    pub stage: i32,
    /// Why paused or stopped.
    pub reason: Option<String>,
    /// Member count.
    pub total: i32,
    pub created_by: Option<String>,
    pub created_at: OffsetDateTime,
    pub started_at: Option<OffsetDateTime>,
    pub finished_at: Option<OffsetDateTime>,
}

/// Member counts by state, overall + within current stage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobCounts {
    /// `(state, all members, members ranked within the stage)`.
    pub by_state: Vec<(String, i64, i64)>,
}

impl JobCounts {
    fn get(&self, state: &str) -> (i64, i64) {
        self.by_state
            .iter()
            .find(|(s, _, _)| s == state)
            .map_or((0, 0), |(_, a, b)| (*a, *b))
    }

    /// Members in `state`, all.
    pub fn total(&self, state: &str) -> i64 {
        self.get(state).0
    }

    /// Members in `state` within the stage.
    pub fn in_stage(&self, state: &str) -> i64 {
        self.get(state).1
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct JobMember {
    pub device_id: Uuid,
    /// Serial number or EndpointID.
    pub device_label: Option<String>,
    /// Dispatch order.
    pub rank: i32,
    pub state: String,
    pub task_id: Option<Uuid>,
    /// Failure reason.
    pub error: Option<String>,
    pub finished_at: Option<OffsetDateTime>,
}

impl Store {
    /// Create a job in `draft`.
    pub async fn create_job(&self, j: &NewJob) -> Result<Uuid> {
        self.create_job_with_id(Uuid::now_v7(), j).await
    }

    /// [`Store::create_job`] with caller-chosen job ID.
    /// Caller needs the ID before insert -> binds encrypted payload secrets to the job.
    pub async fn create_job_with_id(&self, id: Uuid, j: &NewJob) -> Result<Uuid> {
        let target = serde_json::to_value(&j.target).unwrap_or_default();
        sqlx::query!(
            r#"
            INSERT INTO jobs (id, tenant_id, name, target, task_kind, task_payload, policy, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            id,
            j.tenant_id,
            j.name,
            target,
            j.task_kind,
            j.task_payload,
            j.policy,
            j.created_by
        )
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn get_job(&self, id: Uuid) -> Result<Option<Job>> {
        Ok(sqlx::query_as!(
            Job,
            r#"
            SELECT id, tenant_id, name, target, task_kind, task_payload, policy, state,
                   stage, reason, total, created_by, created_at, started_at, finished_at
            FROM jobs WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Jobs of a tenant, newest first.
    pub async fn list_jobs(&self, tenant_id: Uuid, limit: i64) -> Result<Vec<Job>> {
        Ok(sqlx::query_as!(
            Job,
            r#"
            SELECT id, tenant_id, name, target, task_kind, task_payload, policy, state,
                   stage, reason, total, created_by, created_at, started_at, finished_at
            FROM jobs WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2
            "#,
            tenant_id,
            limit
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// `filter` with expression (if any) resolved to the device IDs it matches now
    /// -> fixed queries can use it.
    async fn resolve_expression<'f>(
        &self,
        tenant_id: Uuid,
        filter: &'f DeviceFilter,
    ) -> Result<std::borrow::Cow<'f, DeviceFilter>> {
        let Some(text) = &filter.expression else {
            return Ok(std::borrow::Cow::Borrowed(filter));
        };
        let expr = crate::FilterExpr::parse(text)
            .map_err(|e| StoreError::Database(sqlx::Error::Decode(Box::new(e))))?;
        let mut q = sqlx::QueryBuilder::new("SELECT d.id FROM devices d WHERE d.tenant_id = ");
        q.push_bind(tenant_id).push(" AND ");
        expr.push_sql(&mut q);
        let found: Vec<Uuid> = q.build_query_scalar().fetch_all(&self.pool).await?;
        let mut out = filter.clone();
        out.expression = None;
        out.device_ids = if filter.device_ids.is_empty() {
            found
        } else {
            let found: std::collections::HashSet<Uuid> = found.into_iter().collect();
            filter
                .device_ids
                .iter()
                .copied()
                .filter(|id| found.contains(id))
                .collect()
        };
        // Empty list = "any device" -> match nothing instead.
        if out.device_ids.is_empty() {
            out.device_ids.push(Uuid::nil());
        }
        Ok(std::borrow::Cow::Owned(out))
    }

    /// IDs of running jobs, oldest first.
    pub async fn running_jobs(&self) -> Result<Vec<Uuid>> {
        Ok(
            sqlx::query_scalar!("SELECT id FROM jobs WHERE state = 'running' ORDER BY created_at")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    /// Devices matching `filter` -> (count, first `limit`).
    pub async fn preview_devices(
        &self,
        tenant_id: Uuid,
        filter: &DeviceFilter,
        limit: i64,
    ) -> Result<(i64, Vec<Device>)> {
        let resolved = self.resolve_expression(tenant_id, filter).await?;
        let filter = resolved.as_ref();
        let count = sqlx::query_scalar!(
            r#"
            SELECT count(*) AS "n!" FROM devices d
            WHERE d.tenant_id = $1 AND d.status = $2
              AND ($3::text IS NULL OR d.protocol = $3)
              AND ($4::text IS NULL OR d.oui = $4)
              AND ($5::text IS NULL OR d.product_class = $5)
              AND (cardinality($6::text[]) = 0 OR d.software_version = ANY($6))
              AND d.tags @> $7::text[]
              AND (cardinality($8::uuid[]) = 0 OR d.id = ANY($8))
              AND d.attributes @> $9::jsonb
            "#,
            tenant_id,
            filter.status(),
            filter.protocol,
            filter.oui,
            filter.product_class,
            &filter.software_version,
            &filter.tags,
            &filter.device_ids,
            filter.attributes_json()
        )
        .fetch_one(&self.pool)
        .await?;
        let devices = sqlx::query_as!(
            Device,
            r#"
            SELECT id, tenant_id, protocol, oui, product_class, serial_number, endpoint_id,
                   manufacturer, model_name, software_version, hardware_version, data_model,
                   connection_request_url, cwmp_version, status, tags, first_seen_at,
                   last_contact_at, last_boot_at, host(last_remote_addr) AS last_remote_addr, attributes, usp_ws_url, xmpp_connected_at,
                   udp_cr_address, udp_cr_seen_at, last_wake_at, last_wake_method,
                   last_wake_outcome
            FROM devices d
            WHERE d.tenant_id = $1 AND d.status = $2
              AND ($3::text IS NULL OR d.protocol = $3)
              AND ($4::text IS NULL OR d.oui = $4)
              AND ($5::text IS NULL OR d.product_class = $5)
              AND (cardinality($6::text[]) = 0 OR d.software_version = ANY($6))
              AND d.tags @> $7::text[]
              AND (cardinality($8::uuid[]) = 0 OR d.id = ANY($8))
              AND d.attributes @> $10::jsonb
            ORDER BY d.id LIMIT $9
            "#,
            tenant_id,
            filter.status(),
            filter.protocol,
            filter.oui,
            filter.product_class,
            &filter.software_version,
            &filter.tags,
            &filter.device_ids,
            limit,
            filter.attributes_json()
        )
        .fetch_all(&self.pool)
        .await?;
        Ok((count, devices))
    }

    /// Start a draft job: snapshot matching devices in random order -> `running`.
    /// -> member count; `None` if job not a draft.
    pub async fn start_job(&self, id: Uuid, filter: &DeviceFilter) -> Result<Option<i32>> {
        let tenant = sqlx::query_scalar!("SELECT tenant_id FROM jobs WHERE id = $1", id)
            .fetch_optional(&self.pool)
            .await?;
        let resolved = match tenant {
            Some(t) => self.resolve_expression(t, filter).await?,
            None => std::borrow::Cow::Borrowed(filter),
        };
        let filter = resolved.as_ref();
        let mut tx = self.pool.begin().await?;
        let Some(tenant_id) = sqlx::query_scalar!(
            "SELECT tenant_id FROM jobs WHERE id = $1 AND state = 'draft' FOR UPDATE",
            id
        )
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(None);
        };
        let added = sqlx::query!(
            r#"
            INSERT INTO job_devices (job_id, device_id, rank)
            SELECT $1, d.id, row_number() OVER (ORDER BY random())
            FROM devices d
            WHERE d.tenant_id = $2 AND d.status = $3
              AND ($4::text IS NULL OR d.protocol = $4)
              AND ($5::text IS NULL OR d.oui = $5)
              AND ($6::text IS NULL OR d.product_class = $6)
              AND (cardinality($7::text[]) = 0 OR d.software_version = ANY($7))
              AND d.tags @> $8::text[]
              AND (cardinality($9::uuid[]) = 0 OR d.id = ANY($9))
              AND d.attributes @> $10::jsonb
            "#,
            id,
            tenant_id,
            filter.status(),
            filter.protocol,
            filter.oui,
            filter.product_class,
            &filter.software_version,
            &filter.tags,
            &filter.device_ids,
            filter.attributes_json()
        )
        .execute(&mut *tx)
        .await?
        .rows_affected();
        let total = i32::try_from(added).unwrap_or(i32::MAX);
        sqlx::query!(
            r#"
            UPDATE jobs SET state = 'running', total = $2, started_at = now(), updated_at = now()
            WHERE id = $1
            "#,
            id,
            total
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(total))
    }

    /// Move job from one of `from` to `to` (+ reason, optional stage).
    /// -> `true` if changed.
    pub async fn transition_job(
        &self,
        id: Uuid,
        from: &[&str],
        to: &str,
        reason: Option<&str>,
        stage: Option<i32>,
    ) -> Result<bool> {
        let from: Vec<String> = from.iter().map(|s| (*s).to_owned()).collect();
        let done = sqlx::query!(
            r#"
            UPDATE jobs SET state = $3, reason = $4, stage = COALESCE($5, stage),
                updated_at = now(),
                finished_at = CASE WHEN $3 IN ('completed', 'cancelled') THEN now() END
            WHERE id = $1 AND state = ANY($2)
            "#,
            id,
            &from,
            to,
            reason,
            stage
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Sync members with their tasks.
    ///
    /// Expire overdue pending tasks of the job.
    /// Task ended -> settle member. Success + `verify_version` set -> `verifying`,
    /// deadline `verify_seconds`.
    /// `verifying` -> settle against `verify_version`.
    pub async fn sync_job_members(
        &self,
        job_id: Uuid,
        verify_version: Option<&str>,
        verify_seconds: Option<i64>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE tasks SET state = 'expired', finished_at = now(),
                trace = trace || task_step('expired', attempts)
            WHERE job_id = $1 AND state = 'pending' AND expires_at < now()
            "#,
            job_id
        )
        .execute(&self.pool)
        .await?;
        let verify = verify_version.is_some();
        sqlx::query!(
            r#"
            UPDATE job_devices jd SET
                state = CASE
                    WHEN t.state = 'succeeded' AND $2 THEN 'verifying'
                    WHEN t.state = 'succeeded' THEN 'succeeded'
                    WHEN t.state = 'cancelled' THEN 'cancelled'
                    ELSE 'failed'
                END,
                verify_deadline = CASE WHEN t.state = 'succeeded' AND $2
                    THEN now() + make_interval(secs => $3::bigint) END,
                finished_at = CASE WHEN t.state = 'succeeded' AND $2 THEN NULL ELSE now() END,
                error = CASE WHEN t.state = 'expired' THEN 'task expired before the device ran it'
                    ELSE t.error END
            FROM tasks t
            WHERE jd.job_id = $1 AND jd.state = 'dispatched' AND t.id = jd.task_id
              AND t.state IN ('succeeded', 'failed', 'cancelled', 'expired')
            "#,
            job_id,
            verify,
            verify_seconds.unwrap_or(0)
        )
        .execute(&self.pool)
        .await?;
        if let Some(version) = verify_version {
            sqlx::query!(
                r#"
                UPDATE job_devices jd SET state = 'succeeded', finished_at = now()
                FROM devices d
                WHERE jd.job_id = $1 AND jd.state = 'verifying' AND d.id = jd.device_id
                  AND d.software_version = $2
                "#,
                job_id,
                version
            )
            .execute(&self.pool)
            .await?;
            sqlx::query!(
                r#"
                UPDATE job_devices SET state = 'failed', finished_at = now(),
                    error = 'the device did not report software version ' || $2 || ' in time'
                WHERE job_id = $1 AND state = 'verifying' AND verify_deadline < now()
                "#,
                job_id,
                version
            )
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// Member counts by state; "in stage" = `rank <= stage_limit`.
    pub async fn job_counts(&self, job_id: Uuid, stage_limit: i32) -> Result<JobCounts> {
        let rows = sqlx::query!(
            r#"
            SELECT state, count(*) AS "all!", count(*) FILTER (WHERE rank <= $2) AS "in_stage!"
            FROM job_devices WHERE job_id = $1 GROUP BY state
            "#,
            job_id,
            stage_limit
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(JobCounts {
            by_state: rows
                .into_iter()
                .map(|r| (r.state, r.all, r.in_stage))
                .collect(),
        })
    }

    /// Max `limit` queued members with `rank <= max_rank`, rank order.
    pub async fn next_job_members(
        &self,
        job_id: Uuid,
        max_rank: i32,
        limit: i64,
    ) -> Result<Vec<Uuid>> {
        Ok(sqlx::query_scalar!(
            r#"
            SELECT device_id FROM job_devices
            WHERE job_id = $1 AND state = 'queued' AND rank <= $2
            ORDER BY rank LIMIT $3
            "#,
            job_id,
            max_rank,
            limit
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Task of member queued -> `dispatched`.
    pub async fn mark_member_dispatched(
        &self,
        job_id: Uuid,
        device_id: Uuid,
        task_id: Uuid,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE job_devices SET state = 'dispatched', task_id = $3, dispatched_at = now()
            WHERE job_id = $1 AND device_id = $2 AND state = 'queued'
            "#,
            job_id,
            device_id,
            task_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Fail a member that could not be dispatched.
    pub async fn fail_member(&self, job_id: Uuid, device_id: Uuid, error: &str) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE job_devices SET state = 'failed', error = $3, finished_at = now()
            WHERE job_id = $1 AND device_id = $2 AND state IN ('queued', 'dispatched')
            "#,
            job_id,
            device_id,
            error
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Cancel what has not reached devices: queued members + pending tasks.
    pub async fn cancel_job_members(&self, job_id: Uuid) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE job_devices SET state = 'cancelled', finished_at = now()
            WHERE job_id = $1 AND state = 'queued'
            "#,
            job_id
        )
        .execute(&self.pool)
        .await?;
        sqlx::query!(
            r#"
            UPDATE tasks SET state = 'cancelled', finished_at = now(),
                trace = trace || task_step('cancelled', attempts, 'job cancelled')
            WHERE job_id = $1 AND state = 'pending'
            "#,
            job_id
        )
        .execute(&self.pool)
        .await?;
        sqlx::query!(
            r#"
            UPDATE job_devices jd SET state = 'cancelled', finished_at = now()
            FROM tasks t
            WHERE jd.job_id = $1 AND jd.state = 'dispatched' AND t.id = jd.task_id
              AND t.state = 'cancelled'
            "#,
            job_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Paused/cancelled jobs with members still waiting for a result (task already sent)
    /// -> outcomes still recorded.
    pub async fn jobs_to_settle(&self) -> Result<Vec<Uuid>> {
        Ok(sqlx::query_scalar!(
            r#"
            SELECT j.id FROM jobs j
            WHERE j.state IN ('paused', 'cancelled')
              AND EXISTS (SELECT 1 FROM job_devices jd
                          WHERE jd.job_id = j.id AND jd.state IN ('dispatched', 'verifying'))
            "#
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Members of a job, optional state filter, rank order.
    pub async fn list_job_members(
        &self,
        job_id: Uuid,
        state: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<JobMember>> {
        Ok(sqlx::query_as!(
            JobMember,
            r#"
            SELECT jd.device_id, COALESCE(d.serial_number, d.endpoint_id) AS device_label,
                   jd.rank, jd.state, jd.task_id, jd.error, jd.finished_at
            FROM job_devices jd JOIN devices d ON d.id = jd.device_id
            WHERE jd.job_id = $1 AND ($2::text IS NULL OR jd.state = $2)
            ORDER BY jd.rank LIMIT $3 OFFSET $4
            "#,
            job_id,
            state,
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Lock: one process drives jobs. `None` if another holds it.
    pub async fn try_job_engine_lock(&self) -> Result<Option<LeaderLock>> {
        self.try_leader_lock(7_368_201).await
    }

    /// Lock: one process evaluates alarms.
    pub async fn try_alarm_engine_lock(&self) -> Result<Option<LeaderLock>> {
        self.try_leader_lock(7_368_202).await
    }

    /// Lock: one process ships the audit log (ADR-083).
    pub async fn try_audit_export_lock(&self) -> Result<Option<LeaderLock>> {
        self.try_leader_lock(7_368_203).await
    }

    async fn try_leader_lock(&self, key: i64) -> Result<Option<LeaderLock>> {
        let mut conn = self.pool.acquire().await?;
        let got = sqlx::query_scalar!(r#"SELECT pg_try_advisory_lock($1) AS "got!""#, key)
            .fetch_one(&mut *conn)
            .await?;
        // Detached -> lock drop ends session + lock; no locked connection back in the pool.
        Ok(got.then(|| LeaderLock(Some(conn.detach()))))
    }
}
