//! Persistent task queue (CO-02).

use serde_json::Value as Json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Result, Store};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskState {
    /// Waiting to be sent.
    Pending,
    /// Taken by a session.
    Running,
    Succeeded,
    /// Gave up after `max_attempts`, or permanent error.
    Failed,
    /// Cancelled by an operator.
    Cancelled,
    /// `expires_at` passed before run.
    Expired,
}

impl TaskState {
    /// DB value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "running" => Self::Running,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            "expired" => Self::Expired,
            _ => Self::Pending,
        }
    }
}

/// Task to enqueue.
#[derive(Debug, Clone, PartialEq)]
pub struct NewTask {
    pub tenant_id: Uuid,
    /// Target device.
    pub device_id: Uuid,
    /// Kind, e.g. `get_parameter_values`.
    pub kind: String,
    /// Kind-specific arguments.
    pub payload: Json,
    /// Higher -> runs first.
    pub priority: i16,
    /// Attempts before giving up.
    pub max_attempts: i32,
    /// Same key twice -> first task returned.
    pub idempotency_key: Option<String>,
    /// No run before this time.
    pub not_before: Option<OffsetDateTime>,
    /// Not run by this time -> expired.
    pub expires_at: Option<OffsetDateTime>,
    pub created_by: Option<String>,
    /// Owning bulk job.
    pub job_id: Option<Uuid>,
}

impl NewTask {
    /// Priority 0, 3 attempts, no time limits.
    pub fn new(tenant_id: Uuid, device_id: Uuid, kind: impl Into<String>, payload: Json) -> Self {
        Self {
            tenant_id,
            device_id,
            kind: kind.into(),
            payload,
            priority: 0,
            max_attempts: 3,
            idempotency_key: None,
            not_before: None,
            expires_at: None,
            created_by: None,
            job_id: None,
        }
    }
}

/// Stored task.
#[derive(Debug, Clone, PartialEq)]
pub struct Task {
    pub id: Uuid,
    /// Target device.
    pub device_id: Uuid,
    pub kind: String,
    /// Kind-specific arguments.
    pub payload: Json,
    pub state: TaskState,
    /// Attempts so far, incl. the current one when running.
    pub attempts: i32,
    pub max_attempts: i32,
    /// Result of a successful run. Also the interim response while waiting
    /// ([`Store::mark_task_waiting`]).
    pub result: Option<Json>,
    /// Last error.
    pub error: Option<String>,
    pub created_at: OffsetDateTime,
    /// Higher -> runs first.
    pub priority: i16,
    /// Origin: `api`, `preset:<name>`, `job:<id>`, ...
    pub created_by: Option<String>,
    /// Owning bulk job.
    pub job_id: Option<Uuid>,
    /// History: `[{at, step, attempt, detail?}]`, oldest first.
    pub trace: Json,
}

struct TaskRow {
    id: Uuid,
    device_id: Uuid,
    kind: String,
    payload: Json,
    state: String,
    attempts: i32,
    max_attempts: i32,
    result: Option<Json>,
    error: Option<String>,
    created_at: OffsetDateTime,
    priority: i16,
    created_by: Option<String>,
    job_id: Option<Uuid>,
    trace: Json,
}

impl From<TaskRow> for Task {
    fn from(r: TaskRow) -> Self {
        Self {
            id: r.id,
            device_id: r.device_id,
            kind: r.kind,
            payload: r.payload,
            state: TaskState::parse(&r.state),
            attempts: r.attempts,
            max_attempts: r.max_attempts,
            result: r.result,
            error: r.error,
            created_at: r.created_at,
            priority: r.priority,
            created_by: r.created_by,
            job_id: r.job_id,
            trace: r.trace,
        }
    }
}

impl Store {
    /// Enqueue a task -> (ID, newly created).
    /// Earlier task with the same idempotency key -> its ID + `false`.
    pub async fn enqueue_task(&self, t: &NewTask) -> Result<(Uuid, bool)> {
        self.enqueue_task_with_id(Uuid::now_v7(), t).await
    }

    /// [`Store::enqueue_task`] with a caller-chosen task ID.
    /// Why: caller binds the encrypted secrets of the payload to the task ID before insert.
    /// Earlier task with the same idempotency key -> ID unused, secrets too.
    pub async fn enqueue_task_with_id(&self, id: Uuid, t: &NewTask) -> Result<(Uuid, bool)> {
        let inserted = sqlx::query_scalar!(
            r#"
            INSERT INTO tasks (id, tenant_id, device_id, kind, payload, priority, max_attempts,
                               idempotency_key, not_before, expires_at, created_by, job_id,
                               trace)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                    task_step('queued', 0, $11))
            ON CONFLICT (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
            RETURNING id
            "#,
            id,
            t.tenant_id,
            t.device_id,
            t.kind,
            t.payload,
            t.priority,
            t.max_attempts,
            t.idempotency_key,
            t.not_before,
            t.expires_at,
            t.created_by,
            t.job_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        if let Some(id) = inserted {
            return Ok((id, true));
        }
        let existing = sqlx::query_scalar!(
            "SELECT id FROM tasks WHERE tenant_id = $1 AND idempotency_key = $2",
            t.tenant_id,
            t.idempotency_key
        )
        .fetch_one(&self.pool)
        .await?;
        Ok((existing, false))
    }

    /// `keys` that already name a task of the tenant.
    pub async fn existing_idempotency_keys(
        &self,
        tenant_id: Uuid,
        keys: &[String],
    ) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar!(
            r#"
            SELECT idempotency_key AS "key!" FROM tasks
            WHERE tenant_id = $1 AND idempotency_key = ANY($2)
            "#,
            tenant_id,
            keys
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Device has a `get_parameter_values` task with `name` in its names
    /// (e.g. `Device.` = full read) that runs now or at next drain:
    /// running, or pending + not postponed.
    pub async fn has_open_read_of(&self, device_id: Uuid, name: &str) -> Result<bool> {
        Ok(sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM tasks
                WHERE device_id = $1 AND kind = 'get_parameter_values'
                  AND (state = 'running'
                       OR (state = 'pending' AND (not_before IS NULL OR not_before <= now())))
                  AND payload @> jsonb_build_object('names', jsonb_build_array($2::text))
            ) AS "found!"
            "#,
            device_id,
            name
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// Time until the earliest postponed task of the device is due
    /// = min future `not_before` of its pending, not expired tasks - now.
    /// No such task -> `None`.
    pub async fn next_due_in(&self, device_id: Uuid) -> Result<Option<std::time::Duration>> {
        let micros = sqlx::query_scalar!(
            r#"
            SELECT (EXTRACT(EPOCH FROM (min(not_before) - now())) * 1000000)::bigint AS "micros"
            FROM tasks
            WHERE device_id = $1 AND state = 'pending' AND not_before > now()
              AND (expires_at IS NULL OR expires_at > now())
            "#,
            device_id
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(micros.map(|us| std::time::Duration::from_micros(u64::try_from(us).unwrap_or(0))))
    }

    /// Take the next runnable task of a device -> running.
    /// Before: pending tasks past `expires_at` -> expired.
    pub async fn next_task(&self, device_id: Uuid) -> Result<Option<Task>> {
        sqlx::query!(
            r#"
            UPDATE tasks SET state = 'expired', finished_at = now(),
                trace = trace || task_step('expired', attempts)
            WHERE device_id = $1 AND state = 'pending' AND expires_at < now()
            "#,
            device_id
        )
        .execute(&self.pool)
        .await?;
        let row = sqlx::query_as!(
            TaskRow,
            r#"
            UPDATE tasks SET state = 'running', attempts = attempts + 1, started_at = now(),
                trace = trace || task_step('dispatched', attempts + 1)
            WHERE id = (
                SELECT id FROM tasks
                WHERE device_id = $1 AND state = 'pending'
                  AND (not_before IS NULL OR not_before <= now())
                ORDER BY priority DESC, created_at, id
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING id, device_id, kind, payload, state, attempts, max_attempts,
                      result, error, created_at, priority, created_by, job_id, trace
            "#,
            device_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Task::from))
    }

    /// Record the outcome of a running task of `device_id` -> new state.
    /// Failure -> `pending` again until `max_attempts`.
    /// Task not running or of another device -> unchanged, `Pending` returned.
    /// Device reports by task ID (CommandKey) -> ID alone must not select the task (L-1).
    pub async fn complete_task(
        &self,
        device_id: Uuid,
        id: Uuid,
        outcome: std::result::Result<Json, String>,
    ) -> Result<TaskState> {
        let (result, error) = match outcome {
            Ok(r) => (Some(r), None),
            Err(e) => (None, Some(e)),
        };
        let state = sqlx::query_scalar!(
            r#"
            UPDATE tasks SET
                state = CASE
                    WHEN $2::jsonb IS NOT NULL OR $3::text IS NULL THEN 'succeeded'
                    WHEN attempts < max_attempts THEN 'pending'
                    ELSE 'failed'
                END,
                result = $2, error = $3,
                finished_at = CASE
                    WHEN $3::text IS NULL OR attempts >= max_attempts THEN now()
                END,
                trace = trace || task_step(
                    CASE
                        WHEN $2::jsonb IS NOT NULL OR $3::text IS NULL THEN 'succeeded'
                        WHEN attempts < max_attempts THEN 'retry'
                        ELSE 'failed'
                    END,
                    attempts, $3)
            WHERE id = $1 AND device_id = $4 AND state = 'running'
            RETURNING state
            "#,
            id,
            result,
            error,
            device_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(state
            .as_deref()
            .map_or(TaskState::Pending, TaskState::parse))
    }

    /// Fail tasks waiting > `max_wait` for a completion report -> count.
    /// E.g. Download, TransferComplete never came.
    pub async fn fail_stale_waiting(&self, max_wait: time::Duration) -> Result<u64> {
        let cutoff = OffsetDateTime::now_utc() - max_wait;
        let done = sqlx::query!(
            r#"
            UPDATE tasks SET state = 'failed', finished_at = now(),
                error = 'no completion report from the device (e.g. TransferComplete)',
                trace = trace || task_step('failed', attempts,
                    'no completion report from the device (e.g. TransferComplete)')
            WHERE state = 'running' AND result IS NOT NULL AND started_at < $1
            "#,
            cutoff
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// Fail a running task, no more attempts.
    /// For permanent errors, e.g. fault 9000 Method not supported.
    pub async fn fail_task(&self, id: Uuid, error: &str) -> Result<bool> {
        let done = sqlx::query!(
            r#"
            UPDATE tasks SET state = 'failed', error = $2, finished_at = now(),
                trace = trace || task_step('failed', attempts, $2)
            WHERE id = $1 AND state = 'running'
            "#,
            id,
            error
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// (last error, finish time) of each failed task of the tenant with an idempotency key
    /// in `keys`, newest first. Other states + keys with no task -> absent.
    pub async fn failed_tasks_by_key(
        &self,
        tenant_id: Uuid,
        keys: &[String],
    ) -> Result<Vec<(String, OffsetDateTime)>> {
        let rows = sqlx::query!(
            r#"
            SELECT error AS "error!", COALESCE(finished_at, created_at) AS "finished_at!"
            FROM tasks
            WHERE tenant_id = $1 AND idempotency_key = ANY($2)
              AND state = 'failed' AND error IS NOT NULL
            ORDER BY finished_at DESC NULLS LAST, id DESC
            "#,
            tenant_id,
            keys
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| (r.error, r.finished_at)).collect())
    }

    /// Tasks left `running` by an aborted session -> `pending`,
    /// or `failed` when `max_attempts` used up (aborted session = 1 attempt).
    /// Tasks waiting for a completion report ([`Store::mark_task_waiting`]) stay running
    /// -> transfer in progress not started twice.
    pub async fn requeue_running(&self, device_id: Uuid) -> Result<u64> {
        let done = sqlx::query!(
            r#"
            UPDATE tasks SET
                state = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'pending' END,
                error = 'session aborted before the device answered',
                finished_at = CASE WHEN attempts >= max_attempts THEN now() END,
                trace = trace || task_step(
                    CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'retry' END,
                    attempts, 'session aborted before the device answered')
            WHERE device_id = $1 AND state = 'running' AND result IS NULL
            "#,
            device_id
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// Keep a running task open until a later report + store the interim response.
    /// E.g. Download answered with status 1 -> wait for TransferComplete.
    pub async fn mark_task_waiting(&self, id: Uuid, interim: &Json) -> Result<bool> {
        let done = sqlx::query!(
            r#"
            UPDATE tasks SET result = $2,
                trace = trace || task_step('waiting', attempts, 'waiting for the completion report')
            WHERE id = $1 AND state = 'running'
            "#,
            id,
            interim
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Oldest task of `kind` of the device that ran + now waits for a later report.
    pub async fn waiting_task(&self, device_id: Uuid, kind: &str) -> Result<Option<Task>> {
        let row = sqlx::query_as!(
            TaskRow,
            r#"
            SELECT id, device_id, kind, payload, state, attempts, max_attempts,
                   result, error, created_at, priority, created_by, job_id, trace
            FROM tasks
            WHERE device_id = $1 AND kind = $2 AND state = 'running' AND result IS NOT NULL
            ORDER BY started_at, id LIMIT 1
            "#,
            device_id,
            kind
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Task::from))
    }

    /// Latest succeeded task of `kind` of the device, payload contains `payload`.
    pub async fn latest_succeeded_task(
        &self,
        device_id: Uuid,
        kind: &str,
        payload: &Json,
    ) -> Result<Option<Task>> {
        let row = sqlx::query_as!(
            TaskRow,
            r#"
            SELECT id, device_id, kind, payload, state, attempts, max_attempts,
                   result, error, created_at, priority, created_by, job_id, trace
            FROM tasks
            WHERE device_id = $1 AND kind = $2 AND payload @> $3 AND state = 'succeeded'
            ORDER BY finished_at DESC NULLS LAST, id DESC LIMIT 1
            "#,
            device_id,
            kind,
            payload
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Task::from))
    }

    /// Cancel a pending task -> `true`. Other state -> `false`.
    pub async fn cancel_task(&self, id: Uuid) -> Result<bool> {
        let done = sqlx::query!(
            r#"
            UPDATE tasks SET state = 'cancelled', finished_at = now(),
                trace = trace || task_step('cancelled', attempts)
            WHERE id = $1 AND state = 'pending'
            "#,
            id
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Every secret value in the payload (`values[i].value`, `values[i].secret` = true)
    /// -> `********`, in any task state. Idempotent.
    /// For a secret that must not outlive its task, even sealed.
    pub async fn redact_task_secret_values(&self, id: Uuid) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE tasks SET payload = jsonb_set(payload, '{values}', COALESCE((
                SELECT jsonb_agg(CASE WHEN v.elem -> 'secret' = 'true'::jsonb
                                      THEN jsonb_set(v.elem, '{value}', '"********"'::jsonb)
                                      ELSE v.elem END
                                 ORDER BY v.idx)
                FROM jsonb_array_elements(payload -> 'values') WITH ORDINALITY AS v(elem, idx)
            ), '[]'::jsonb))
            WHERE id = $1 AND jsonb_typeof(payload -> 'values') = 'array'
            "#,
            id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_task(&self, id: Uuid) -> Result<Option<Task>> {
        let row = sqlx::query_as!(
            TaskRow,
            r#"
            SELECT id, device_id, kind, payload, state, attempts, max_attempts,
                   result, error, created_at, priority, created_by, job_id, trace
            FROM tasks WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Task::from))
    }

    /// Tasks of a device, newest first, max `limit`.
    pub async fn list_tasks(&self, device_id: Uuid, limit: i64) -> Result<Vec<Task>> {
        let rows = sqlx::query_as!(
            TaskRow,
            r#"
            SELECT id, device_id, kind, payload, state, attempts, max_attempts,
                   result, error, created_at, priority, created_by, job_id, trace
            FROM tasks WHERE device_id = $1
            ORDER BY created_at DESC, id DESC
            LIMIT $2
            "#,
            device_id,
            limit
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Task::from).collect())
    }
}
