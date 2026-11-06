//! Ops overview (UI-02): fleet, activity, queue, firmware.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::scope::scope_param;
use crate::{DeviceFilter, DeviceScope, Result, Store};

/// Fleet + activity figures of a tenant.
#[derive(Debug, Clone, PartialEq)]
pub struct Overview {
    pub active: i64,
    /// Active devices with contact in last (15 min, 1 h, 1 day).
    pub online: (i64, i64, i64),
    /// Devices by protocol, all statuses.
    pub by_protocol: Vec<(String, i64)>,
    pub by_status: Vec<(String, i64)>,
    /// Sessions/min over last hour (CWMP Informs + USP connects).
    pub sessions_per_minute: Vec<(OffsetDateTime, i64)>,
    /// Tasks by state: open + finished in last day.
    pub tasks: Vec<(String, i64)>,
    /// Running bulk jobs, whole target in scope.
    pub jobs_running: i64,
    /// Top 8 software versions of active devices.
    pub versions: Vec<(String, i64)>,
}

impl Store {
    /// Overview of tenant devices in `scope` (`None` = all).
    pub async fn overview(&self, tenant_id: Uuid, scope: Option<&DeviceScope>) -> Result<Overview> {
        let sp = scope_param(scope);
        let fleet = sqlx::query!(
            r#"
            SELECT count(*) AS "active!",
                   count(*) FILTER (WHERE last_contact_at > now() - interval '15 minutes') AS "m15!",
                   count(*) FILTER (WHERE last_contact_at > now() - interval '1 hour') AS "h1!",
                   count(*) FILTER (WHERE last_contact_at > now() - interval '1 day') AS "d1!"
            FROM devices d WHERE tenant_id = $1 AND status = 'active' AND device_in_scope(d, $2)
            "#,
            tenant_id,
            sp.clone()
        )
        .fetch_one(&self.pool)
        .await?;
        let by_protocol = sqlx::query!(
            r#"SELECT protocol, count(*) AS "n!" FROM devices d WHERE tenant_id = $1 AND device_in_scope(d, $2) GROUP BY 1 ORDER BY 1"#,
            tenant_id,
            sp.clone()
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| (r.protocol, r.n))
        .collect();
        let by_status = sqlx::query!(
            r#"SELECT status, count(*) AS "n!" FROM devices d WHERE tenant_id = $1 AND device_in_scope(d, $2) GROUP BY 1 ORDER BY 1"#,
            tenant_id,
            sp.clone()
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| (r.status, r.n))
        .collect();
        let sessions_per_minute = sqlx::query!(
            r#"
            SELECT date_trunc('minute', occurred_at) AS "minute!", count(*) AS "n!"
            FROM events
            WHERE tenant_id = $1 AND occurred_at > now() - interval '1 hour'
              AND kind IN ('inform', 'usp_connect')
              AND ($2::jsonb IS NULL OR device_id IN (
                  SELECT d.id FROM devices d WHERE d.tenant_id = $1 AND device_in_scope(d, $2)))
            GROUP BY 1 ORDER BY 1
            "#,
            tenant_id,
            sp.clone()
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| (r.minute, r.n))
        .collect();
        let tasks = sqlx::query!(
            r#"
            SELECT state, count(*) AS "n!" FROM tasks
            WHERE tenant_id = $1
              AND (state IN ('pending', 'running') OR finished_at > now() - interval '1 day')
              AND ($2::jsonb IS NULL OR device_id IN (
                  SELECT d.id FROM devices d WHERE d.tenant_id = $1 AND device_in_scope(d, $2)))
            GROUP BY 1 ORDER BY 1
            "#,
            tenant_id,
            sp.clone()
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| (r.state, r.n))
        .collect();
        // Job counts only if whole target in scope (= job list).
        let jobs_running = sqlx::query_scalar!(
            "SELECT target FROM jobs WHERE tenant_id = $1 AND state = 'running'",
            tenant_id
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .filter(|t| {
            scope.is_none_or(|s| {
                serde_json::from_value::<DeviceFilter>(t.clone()).is_ok_and(|f| s.covers(&f))
            })
        })
        .count() as i64;
        let versions = sqlx::query!(
            r#"
            SELECT software_version AS "version!", count(*) AS "n!" FROM devices d
            WHERE tenant_id = $1 AND status = 'active' AND software_version IS NOT NULL
              AND device_in_scope(d, $2)
            GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 8
            "#,
            tenant_id,
            sp
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| (r.version, r.n))
        .collect();
        Ok(Overview {
            active: fleet.active,
            online: (fleet.m15, fleet.h1, fleet.d1),
            by_protocol,
            by_status,
            sessions_per_minute,
            tasks,
            jobs_running,
            versions,
        })
    }
}
