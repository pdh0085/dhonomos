//! Device time series (DG-04/05): numeric samples, daily partitions (ADR-037).

use std::collections::HashMap;

use time::{Date, OffsetDateTime};
use uuid::Uuid;

use crate::{Result, Store};

/// Aggregated bucket of a series.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricBucket {
    /// Bucket start.
    pub ts: OffsetDateTime,
    pub avg: f64,
    pub min: f64,
    pub max: f64,
    /// Samples in bucket.
    pub count: i64,
}

/// Metric of a device.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceMetric {
    /// Parameter path.
    pub path: String,
    pub last_ts: OffsetDateTime,
    pub last_value: f64,
}

/// Day of a `metric_samples_YYYYMMDD` partition. Other names -> `None`.
fn partition_day(name: &str) -> Option<Date> {
    let d = name.strip_prefix("metric_samples_")?;
    if d.len() != 8 || !d.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (y, m, day) = (
        d[..4].parse().ok()?,
        d[4..6].parse::<u8>().ok()?,
        d[6..].parse().ok()?,
    );
    Date::from_calendar_date(y, time::Month::try_from(m).ok()?, day).ok()
}

fn partition_name(day: Date) -> String {
    format!(
        "metric_samples_{:04}{:02}{:02}",
        day.year(),
        u8::from(day.month()),
        day.day()
    )
}

impl Store {
    /// IDs of metric paths. Missing ones created.
    pub async fn metric_ids(&self, paths: &[String]) -> Result<HashMap<String, i32>> {
        sqlx::query!(
            "INSERT INTO metric_names (path) SELECT unnest($1::text[]) ON CONFLICT (path) DO NOTHING",
            paths
        )
        .execute(&self.pool)
        .await?;
        let rows = sqlx::query!(
            "SELECT id, path FROM metric_names WHERE path = ANY($1)",
            paths
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| (r.path, r.id)).collect())
    }

    /// Store samples of one device. Partitions of their days must exist.
    pub async fn insert_samples(
        &self,
        device_id: Uuid,
        samples: &[(i32, OffsetDateTime, f64)],
    ) -> Result<()> {
        if samples.is_empty() {
            return Ok(());
        }
        let ids: Vec<i32> = samples.iter().map(|s| s.0).collect();
        let ts: Vec<OffsetDateTime> = samples.iter().map(|s| s.1).collect();
        let values: Vec<f64> = samples.iter().map(|s| s.2).collect();
        let mut tx = self.pool.begin().await?;
        sqlx::query!(
            r#"
            INSERT INTO metric_samples (device_id, metric_id, ts, value)
            SELECT $1, * FROM unnest($2::int[], $3::timestamptz[], $4::float8[])
            "#,
            device_id,
            &ids,
            &ts,
            &values
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            r#"
            INSERT INTO device_metrics (device_id, metric_id, last_ts, last_value)
            SELECT DISTINCT ON (m) $1, m, t, v
            FROM unnest($2::int[], $3::timestamptz[], $4::float8[]) AS s(m, t, v)
            ORDER BY m, t DESC
            ON CONFLICT (device_id, metric_id) DO UPDATE
                SET last_ts = EXCLUDED.last_ts, last_value = EXCLUDED.last_value
                WHERE device_metrics.last_ts <= EXCLUDED.last_ts
            "#,
            device_id,
            &ids,
            &ts,
            &values
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Metrics of a device, by path.
    pub async fn device_metrics(&self, device_id: Uuid) -> Result<Vec<DeviceMetric>> {
        Ok(sqlx::query_as!(
            DeviceMetric,
            r#"
            SELECT n.path, dm.last_ts, dm.last_value
            FROM device_metrics dm JOIN metric_names n ON n.id = dm.metric_id
            WHERE dm.device_id = $1 ORDER BY n.path
            "#,
            device_id
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Series in `[from, to)`, buckets of `step_seconds`.
    pub async fn metric_series(
        &self,
        device_id: Uuid,
        path: &str,
        from: OffsetDateTime,
        to: OffsetDateTime,
        step_seconds: i64,
    ) -> Result<Vec<MetricBucket>> {
        // Recent days = raw rows; older days = compacted daily arrays.
        Ok(sqlx::query_as!(
            MetricBucket,
            r#"
            WITH m AS (SELECT id FROM metric_names WHERE path = $2),
            s AS (
                SELECT s.ts, s.value FROM metric_samples s, m
                WHERE s.device_id = $1 AND s.metric_id = m.id AND s.ts >= $3 AND s.ts < $4
                UNION ALL
                SELECT r.day::timestamp AT TIME ZONE 'UTC' + make_interval(secs => u.off), u.v
                FROM metric_rollups r, m, unnest(r.offsets, r.vals) AS u(off, v)
                WHERE r.device_id = $1 AND r.metric_id = m.id
                  AND r.day >= ($3 AT TIME ZONE 'UTC')::date AND r.day <= ($4 AT TIME ZONE 'UTC')::date
            )
            SELECT date_bin(make_interval(secs => $5::bigint), ts, $3) AS "ts!",
                   avg(value) AS "avg!", min(value) AS "min!", max(value) AS "max!",
                   count(*) AS "count!"
            FROM s WHERE ts >= $3 AND ts < $4
            GROUP BY 1 ORDER BY 1
            "#,
            device_id,
            path,
            from,
            to,
            step_seconds
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Create missing daily partitions for `from..=to` -> number of days covered.
    pub async fn ensure_metric_partitions(&self, from: Date, to: Date) -> Result<u32> {
        let mut created = 0;
        let mut day = from;
        while day <= to {
            let Some(next) = day.next_day() else { break };
            // Identifiers cannot be bound -> name built from a date only.
            let sql = format!(
                "CREATE TABLE IF NOT EXISTS {} PARTITION OF metric_samples \
                 FOR VALUES FROM ('{day}') TO ('{next}')",
                partition_name(day)
            );
            let done = sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(&self.pool)
                .await;
            match done {
                Ok(_) => created += 1,
                // Created concurrently by another process.
                Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("42P07") => {}
                Err(e) => return Err(e.into()),
            }
            day = next;
        }
        Ok(created)
    }

    /// Compact raw partitions of days before `raw_from` into `metric_rollups`, then drop them.
    /// -> days compacted.
    pub async fn rollup_metric_partitions_before(&self, raw_from: Date) -> Result<u32> {
        let mut done = 0;
        for name in self.metric_partitions().await? {
            let Some(day) = partition_day(&name).filter(|d| *d < raw_from) else {
                continue;
            };
            let mut tx = self.pool.begin().await?;
            // Name checked = metric_samples_YYYYMMDD.
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "INSERT INTO metric_rollups (device_id, metric_id, day, offsets, vals) \
                 SELECT device_id, metric_id, $1::date, \
                        array_agg(EXTRACT(EPOCH FROM ts - $1::date::timestamp AT TIME ZONE 'UTC')::int ORDER BY ts), \
                        array_agg(value ORDER BY ts) \
                 FROM {name} GROUP BY device_id, metric_id \
                 ON CONFLICT (device_id, metric_id, day) DO UPDATE \
                 SET offsets = metric_rollups.offsets || EXCLUDED.offsets, \
                     vals = metric_rollups.vals || EXCLUDED.vals"
            )))
            .bind(day)
            .execute(&mut *tx)
            .await?;
            sqlx::query(sqlx::AssertSqlSafe(format!("DROP TABLE {name}")))
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            done += 1;
        }
        Ok(done)
    }

    /// Delete compacted days before `keep_from` -> rows deleted.
    pub async fn delete_rollups_before(&self, keep_from: Date) -> Result<u64> {
        Ok(
            sqlx::query!("DELETE FROM metric_rollups WHERE day < $1", keep_from)
                .execute(&self.pool)
                .await?
                .rows_affected(),
        )
    }

    async fn metric_partitions(&self) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar!(
            r#"
            SELECT c.relname AS "name!" FROM pg_inherits i
            JOIN pg_class c ON c.oid = i.inhrelid
            JOIN pg_class p ON p.oid = i.inhparent
            WHERE p.relname = 'metric_samples'
            "#
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Drop daily partitions of days before `keep_from` -> how many.
    pub async fn drop_metric_partitions_before(&self, keep_from: Date) -> Result<u32> {
        let mut dropped = 0;
        for name in self.metric_partitions().await? {
            // Only metric_samples_YYYYMMDD names reach the SQL.
            if partition_day(&name).is_some_and(|d| d < keep_from) {
                sqlx::query(sqlx::AssertSqlSafe(format!("DROP TABLE IF EXISTS {name}")))
                    .execute(&self.pool)
                    .await?;
                dropped += 1;
            }
        }
        Ok(dropped)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn partition_days() {
        assert_eq!(
            super::partition_day("metric_samples_20261004"),
            Some(time::macros::date!(2026 - 10 - 04))
        );
        for bad in [
            "metric_samples_2026100",
            "metric_samples_2026x004",
            "other_20261004",
            "metric_samples_20261304",
        ] {
            assert_eq!(super::partition_day(bad), None, "{bad}");
        }
    }

    #[test]
    fn partition_names_sort_by_date() {
        let a = super::partition_name(time::macros::date!(2026 - 09 - 30));
        let b = super::partition_name(time::macros::date!(2026 - 10 - 01));
        assert_eq!(a, "metric_samples_20260930");
        assert!(a < b);
    }
}
