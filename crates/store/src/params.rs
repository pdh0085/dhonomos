//! Parameter snapshot (CO-03), one row per path (ADR-027).

use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Result, Store};

/// Parameter update. `None` field -> stored value kept.
/// e.g. GPN -> names + writability, no values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParamUpdate {
    /// Full parameter path.
    pub path: String,
    pub value: Option<String>,
    /// `xsi:type` local name.
    pub xsd_type: Option<String>,
    pub writable: Option<bool>,
}

/// Stored parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredParam {
    /// Full parameter path.
    pub path: String,
    /// Last known value.
    pub value: Option<String>,
    /// `xsi:type` local name.
    pub xsd_type: Option<String>,
    pub writable: Option<bool>,
    /// Last update time.
    pub updated_at: OffsetDateTime,
}

/// Parameter refused by DB, rest of its batch stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedParam {
    /// Full parameter path.
    pub path: String,
    /// DB message. Never contains the value.
    pub error: String,
}

/// Result of [`Store::upsert_params`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParamsWritten {
    /// Parameters written (insert or update).
    pub stored: u64,
    /// Params refused one by one by DB (value PostgreSQL cannot hold, e.g. NUL char).
    /// Rest of batch stored.
    pub rejected: Vec<RejectedParam>,
}

/// Result of [`Store::upsert_params_capped`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CappedUpsert {
    /// Parameters written (insert or update).
    pub stored: u64,
    /// New params left out: device at its limit.
    pub dropped: usize,
    /// Params refused one by one by DB, see [`ParamsWritten::rejected`].
    pub rejected: Vec<RejectedParam>,
}

/// SQLSTATE classes of errors from row data, not DB state:
/// data exception (22), integrity constraint violation (23),
/// program limit exceeded (54, e.g. index row too large).
/// Only these -> retry in smaller batches.
fn is_row_error(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|db| db.code())
        .is_some_and(|code| ["22", "23", "54"].iter().any(|c| code.starts_with(c)))
}

impl Store {
    /// Insert or update params, 1 statement if DB accepts all.
    /// Refused for row data -> split batch until only those rows left out
    /// -> [`ParamsWritten::rejected`]; rest stored.
    /// Other errors (connection lost, ...) -> call fails.
    pub async fn upsert_params(
        &self,
        device_id: Uuid,
        params: &[ParamUpdate],
    ) -> Result<ParamsWritten> {
        let refs: Vec<&ParamUpdate> = params.iter().collect();
        self.write_params(device_id, &refs).await
    }

    /// [`Store::upsert_params`] for device reports: max `max_total` params per device (L-5).
    /// Known params always updated; new ones stored while room,
    /// then counted in [`CappedUpsert::dropped`].
    /// Path listed twice -> last entry kept.
    pub async fn upsert_params_capped(
        &self,
        device_id: Uuid,
        params: &[ParamUpdate],
        max_total: usize,
    ) -> Result<CappedUpsert> {
        if params.is_empty() {
            return Ok(CappedUpsert::default());
        }
        // One entry per path (statement cannot change a row twice), last wins.
        let mut last: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::with_capacity(params.len());
        for (i, p) in params.iter().enumerate() {
            last.insert(p.path.as_str(), i);
        }
        let unique: Vec<&ParamUpdate> = params
            .iter()
            .enumerate()
            .filter(|(i, p)| last.get(p.path.as_str()) == Some(i))
            .map(|(_, p)| p)
            .collect();
        let total = sqlx::query_scalar!(
            r#"SELECT count(*) AS "n!" FROM device_params WHERE device_id = $1"#,
            device_id
        )
        .fetch_one(&self.pool)
        .await?;
        let room =
            usize::try_from(i64::try_from(max_total).unwrap_or(i64::MAX) - total).unwrap_or(0);
        if room >= unique.len() {
            // All paths new -> still fit.
            let done = self.write_params(device_id, &unique).await?;
            return Ok(CappedUpsert {
                stored: done.stored,
                dropped: 0,
                rejected: done.rejected,
            });
        }
        let paths: Vec<&str> = unique.iter().map(|p| p.path.as_str()).collect();
        let known: std::collections::HashSet<String> = sqlx::query_scalar!(
            "SELECT path FROM device_params WHERE device_id = $1 AND path = ANY($2)",
            device_id,
            &paths as &[&str]
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .collect();
        let mut room = room;
        let mut dropped = 0;
        let keep: Vec<&ParamUpdate> = unique
            .into_iter()
            .filter(|p| {
                if known.contains(&p.path) {
                    true
                } else if room > 0 {
                    room -= 1;
                    true
                } else {
                    dropped += 1;
                    false
                }
            })
            .collect();
        let done = self.write_params(device_id, &keep).await?;
        Ok(CappedUpsert {
            stored: done.stored,
            dropped,
            rejected: done.rejected,
        })
    }

    /// Write `params` as 1 statement; refused for data -> split in halves, repeat.
    /// Failed statement changes nothing -> halves retried independently.
    /// Single row still failing = culprit.
    async fn write_params(
        &self,
        device_id: Uuid,
        params: &[&ParamUpdate],
    ) -> Result<ParamsWritten> {
        let mut out = ParamsWritten::default();
        let mut pending = vec![params];
        while let Some(chunk) = pending.pop() {
            if chunk.is_empty() {
                continue;
            }
            match self.write_chunk(device_id, chunk).await {
                Ok(n) => out.stored += n,
                Err(e) if is_row_error(&e) => match chunk {
                    [one] => out.rejected.push(RejectedParam {
                        path: one.path.clone(),
                        error: e
                            .as_database_error()
                            .map_or_else(|| e.to_string(), |db| db.message().to_owned()),
                    }),
                    _ => {
                        let (head, tail) = chunk.split_at(chunk.len() / 2);
                        pending.push(tail);
                        pending.push(head);
                    }
                },
                Err(e) => return Err(e.into()),
            }
        }
        Ok(out)
    }

    async fn write_chunk(
        &self,
        device_id: Uuid,
        params: &[&ParamUpdate],
    ) -> std::result::Result<u64, sqlx::Error> {
        let paths: Vec<&str> = params.iter().map(|p| p.path.as_str()).collect();
        let values: Vec<Option<&str>> = params.iter().map(|p| p.value.as_deref()).collect();
        let types: Vec<Option<&str>> = params.iter().map(|p| p.xsd_type.as_deref()).collect();
        let writable: Vec<Option<bool>> = params.iter().map(|p| p.writable).collect();
        let done = sqlx::query!(
            r#"
            INSERT INTO device_params (device_id, path, value, xsd_type, writable)
            SELECT $1, u.path, u.value, u.xsd_type, u.writable
            FROM UNNEST($2::text[], $3::text[], $4::text[], $5::bool[])
                AS u (path, value, xsd_type, writable)
            ON CONFLICT (device_id, path) DO UPDATE SET
                value = COALESCE(EXCLUDED.value, device_params.value),
                xsd_type = COALESCE(EXCLUDED.xsd_type, device_params.xsd_type),
                writable = COALESCE(EXCLUDED.writable, device_params.writable),
                updated_at = now()
            "#,
            device_id,
            &paths as &[&str],
            &values as &[Option<&str>],
            &types as &[Option<&str>],
            &writable as &[Option<bool>],
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// Params with path starting with `prefix` (empty = all), sorted by path.
    pub async fn get_params(&self, device_id: Uuid, prefix: &str) -> Result<Vec<StoredParam>> {
        Ok(sqlx::query_as!(
            StoredParam,
            r#"
            SELECT path, value, xsd_type, writable, updated_at
            FROM device_params
            WHERE device_id = $1 AND starts_with(path, $2)
            ORDER BY path
            "#,
            device_id,
            prefix
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Any stored param with path starting with `prefix`?
    /// Stops at first match -> cheap on device with many params.
    pub async fn has_param_prefix(&self, device_id: Uuid, prefix: &str) -> Result<bool> {
        Ok(sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM device_params WHERE device_id = $1 AND starts_with(path, $2)
            ) AS "found!"
            "#,
            device_id,
            prefix
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// Stored rows of exactly these paths (unknown paths absent).
    pub async fn get_params_exact(
        &self,
        device_id: Uuid,
        paths: &[String],
    ) -> Result<Vec<StoredParam>> {
        Ok(sqlx::query_as!(
            StoredParam,
            r#"
            SELECT path, value, xsd_type, writable, updated_at
            FROM device_params
            WHERE device_id = $1 AND path = ANY($2)
            "#,
            device_id,
            paths
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Stored values of given paths (no row -> absent).
    pub async fn get_param_values(
        &self,
        device_id: Uuid,
        paths: &[String],
    ) -> Result<std::collections::HashMap<String, Option<String>>> {
        let rows = sqlx::query!(
            "SELECT path, value FROM device_params WHERE device_id = $1 AND path = ANY($2)",
            device_id,
            paths
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| (r.path, r.value)).collect())
    }

    /// Stored paths under `prefix`, without `prefix` itself, no particular order.
    /// No values: some values are large logs.
    pub async fn param_paths_under(&self, device_id: Uuid, prefix: &str) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar!(
            r#"
            SELECT path FROM device_params
            WHERE device_id = $1 AND starts_with(path, $2) AND path <> $2
            "#,
            device_id,
            prefix
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Remove exactly these paths (unknown ignored) -> count removed.
    pub async fn delete_params_exact(&self, device_id: Uuid, paths: &[String]) -> Result<u64> {
        if paths.is_empty() {
            return Ok(0);
        }
        let done = sqlx::query!(
            "DELETE FROM device_params WHERE device_id = $1 AND path = ANY($2)",
            device_id,
            paths
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// Remove params under object path (e.g. after DeleteObject).
    pub async fn delete_params_under(&self, device_id: Uuid, prefix: &str) -> Result<u64> {
        let done = sqlx::query!(
            "DELETE FROM device_params WHERE device_id = $1 AND starts_with(path, $2)",
            device_id,
            prefix
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }
}
