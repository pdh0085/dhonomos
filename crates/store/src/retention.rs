//! Retention (OP-10): delete old rows -> tables stop growing.
//! Old events, finished tasks, cleared alarms (+ ended silences), expired sessions.

use time::OffsetDateTime;

use crate::{Result, Store};

/// Rows deleted by one [`Store::apply_retention`] run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Purged {
    pub events: u64,
    /// Finished tasks.
    pub tasks: u64,
    /// Cleared alarms.
    pub alarms: u64,
    /// Expired sessions.
    pub sessions: u64,
}

/// Rows per DELETE -> small locks + WAL bursts.
const BATCH: i64 = 10_000;

impl Store {
    /// Delete events before `events_before` + tasks finished before `tasks_before` (batches),
    /// alarms cleared before `alarms_before` (+ silences ended before it), expired sessions.
    pub async fn apply_retention(
        &self,
        events_before: OffsetDateTime,
        tasks_before: OffsetDateTime,
        alarms_before: OffsetDateTime,
    ) -> Result<Purged> {
        let mut p = Purged::default();
        loop {
            let n = sqlx::query!(
                r#"
                DELETE FROM events WHERE id IN (
                    SELECT id FROM events WHERE occurred_at < $1 LIMIT $2
                )
                "#,
                events_before,
                BATCH
            )
            .execute(&self.pool)
            .await?
            .rows_affected();
            p.events += n;
            if n < BATCH as u64 {
                break;
            }
        }
        loop {
            // Job members ref tasks by ID only + jobs keep own counts -> safe to delete.
            let n = sqlx::query!(
                r#"
                DELETE FROM tasks WHERE id IN (
                    SELECT id FROM tasks
                    WHERE state IN ('succeeded', 'failed', 'cancelled', 'expired')
                      AND finished_at < $1
                      -- `once` presets remember that they ran through their task.
                      AND (idempotency_key IS NULL OR idempotency_key NOT LIKE 'preset-once:%')
                    LIMIT $2
                )
                "#,
                tasks_before,
                BATCH
            )
            .execute(&self.pool)
            .await?
            .rows_affected();
            p.tasks += n;
            if n < BATCH as u64 {
                break;
            }
        }
        p.alarms = sqlx::query!(
            "DELETE FROM alarms WHERE state = 'cleared' AND cleared_at < $1",
            alarms_before
        )
        .execute(&self.pool)
        .await?
        .rows_affected();
        // Silences: same cutoff as the alarms they covered.
        sqlx::query!(
            "DELETE FROM alarm_silences WHERE ends_at < $1",
            alarms_before
        )
        .execute(&self.pool)
        .await?;
        p.sessions = self.delete_expired_sessions().await?;
        Ok(p)
    }
}
