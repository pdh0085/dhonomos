//! Device time series (DG-04/05): BulkData report parsing + sample ingestion.
//!
//! BulkData JSON: `Report` array; each report = optional `CollectionTime` + values.
//! Values: flat `"Device.X.Y": value` pairs (NameValuePair)
//! or nested objects (ObjectHierarchy).
//! Only numbers (+ booleans as 0/1) -> samples.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use dhonomos_store::Store;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

/// One reported value.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub path: String,
    /// Collection time (no `CollectionTime` -> time of receipt).
    pub ts: OffsetDateTime,
    pub value: f64,
}

/// BulkData report not readable.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid BulkData report: {0}")]
pub struct ReportError(String);

fn number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        // Some agents send all values as strings.
        Value::String(s) => match s.as_str() {
            "true" => Some(1.0),
            "false" => Some(0.0),
            s => s.parse::<f64>().ok().filter(|f| f.is_finite()),
        },
        _ => None,
    }
}

fn collection_time(v: Option<&Value>, received: OffsetDateTime) -> OffsetDateTime {
    match v {
        Some(Value::Number(n)) => n
            .as_i64()
            .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
            .unwrap_or(received),
        Some(Value::String(s)) => OffsetDateTime::parse(s, &Rfc3339).unwrap_or(received),
        _ => received,
    }
}

fn flatten(prefix: &str, v: &Value, ts: OffsetDateTime, out: &mut Vec<Sample>) {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&path, child, ts, out);
            }
        }
        leaf => {
            if let Some(value) = number(leaf) {
                out.push(Sample {
                    path: prefix.to_owned(),
                    ts,
                    value,
                });
            }
        }
    }
}

/// Samples of a BulkData JSON report (either encoding).
/// No collection time -> stamped `received`.
pub fn parse_bulkdata_json(
    body: &[u8],
    received: OffsetDateTime,
) -> Result<Vec<Sample>, ReportError> {
    let doc: Value = serde_json::from_slice(body).map_err(|e| ReportError(e.to_string()))?;
    let reports = doc
        .get("Report")
        .and_then(Value::as_array)
        .ok_or_else(|| ReportError("no Report array".into()))?;
    let mut out = Vec::new();
    for report in reports {
        let Some(obj) = report.as_object() else {
            continue;
        };
        let ts = collection_time(obj.get("CollectionTime"), received);
        for (k, v) in obj {
            if k != "CollectionTime" {
                flatten(k, v, ts, &mut out);
            }
        }
    }
    Ok(out)
}

/// Store samples; metric name IDs cached in memory.
#[derive(Debug, Clone)]
pub struct MetricsIngest {
    store: Store,
    /// Shared by all clones -> [`MetricsIngest::set_retention`] reaches all.
    retention_days: Arc<AtomicI64>,
    raw_days: Arc<AtomicI64>,
    ids: Arc<Mutex<HashMap<String, i32>>>,
}

impl MetricsIngest {
    /// Keep `retention_days` of history (ADR-044).
    /// Last `raw_days` (incl. today) -> raw rows; older days -> compacted.
    /// Samples before the raw days or 1+ day in the future -> dropped.
    pub fn new(store: Store, retention_days: i64, raw_days: i64) -> Self {
        let ingest = Self {
            store,
            retention_days: Arc::default(),
            raw_days: Arc::default(),
            ids: Arc::default(),
        };
        ingest.set_retention(retention_days, raw_days);
        ingest
    }

    /// Change days kept (see [`MetricsIngest::new`]) for this ingest + all clones.
    /// Takes effect from next sample or maintenance run.
    pub fn set_retention(&self, retention_days: i64, raw_days: i64) {
        let retention_days = retention_days.max(1);
        self.retention_days.store(retention_days, Ordering::Relaxed);
        self.raw_days
            .store(raw_days.clamp(1, retention_days), Ordering::Relaxed);
    }

    /// (days kept, raw days), after clamping.
    pub fn retention(&self) -> (i64, i64) {
        (
            self.retention_days.load(Ordering::Relaxed),
            self.raw_days.load(Ordering::Relaxed),
        )
    }

    fn raw_from(&self) -> time::Date {
        OffsetDateTime::now_utc().date()
            - time::Duration::days(self.raw_days.load(Ordering::Relaxed) - 1)
    }

    /// Store samples of a device -> count kept.
    pub async fn ingest(
        &self,
        device: Uuid,
        samples: &[Sample],
    ) -> Result<usize, dhonomos_store::StoreError> {
        let now = OffsetDateTime::now_utc();
        let oldest = self.raw_from().midnight().assume_utc();
        let newest = now + time::Duration::days(1);
        let kept: Vec<&Sample> = samples
            .iter()
            .filter(|s| s.ts >= oldest && s.ts < newest && !s.path.is_empty())
            .collect();
        if kept.len() < samples.len() {
            metrics::counter!("dhonomos_metric_samples_dropped_total")
                .increment((samples.len() - kept.len()) as u64);
        }
        if kept.is_empty() {
            return Ok(0);
        }
        let missing: Vec<String> = {
            let ids = self
                .ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut m: Vec<String> = kept
                .iter()
                .filter(|s| !ids.contains_key(&s.path))
                .map(|s| s.path.clone())
                .collect();
            m.sort();
            m.dedup();
            m
        };
        if !missing.is_empty() {
            let found = self.store.metric_ids(&missing).await?;
            self.ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend(found);
        }
        let rows: Vec<(i32, OffsetDateTime, f64)> = {
            let ids = self
                .ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            kept.iter()
                .filter_map(|s| ids.get(&s.path).map(|id| (*id, s.ts, s.value)))
                .collect()
        };
        self.store.insert_samples(device, &rows).await?;
        metrics::counter!("dhonomos_metric_samples_total").increment(rows.len() as u64);
        Ok(rows.len())
    }

    /// Partition upkeep. Run at start + periodically.
    /// Raw partitions for raw days + 2 days ahead; older raw days -> compacted;
    /// compacted days past retention -> deleted.
    /// Returns (raw days covered, days compacted, compacted rows deleted).
    pub async fn maintain(&self) -> Result<(u32, u32, u64), dhonomos_store::StoreError> {
        let today = OffsetDateTime::now_utc().date();
        let raw_from = self.raw_from();
        let covered = self
            .store
            .ensure_metric_partitions(raw_from, today + time::Duration::days(2))
            .await?;
        let compacted = self.store.rollup_metric_partitions_before(raw_from).await?;
        let keep_from = today - time::Duration::days(self.retention_days.load(Ordering::Relaxed));
        let deleted = self.store.delete_rollups_before(keep_from).await?;
        Ok((covered, compacted, deleted))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn both_json_encodings() {
        let received = OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap();
        let pairs = br#"{"Report":[
            {"CollectionTime":1791000000,
             "Device.WiFi.Radio.1.Stats.Noise":-92,
             "Device.DeviceInfo.UpTime":"3600",
             "Device.DeviceInfo.SoftwareVersion":"1.0.0",
             "Device.WiFi.Radio.1.Enable":true}]}"#;
        let s = parse_bulkdata_json(pairs, received).unwrap();
        assert_eq!(s.len(), 3, "the version string is not a number: {s:?}");
        assert!(s.iter().all(|x| x.ts.unix_timestamp() == 1_791_000_000));
        assert!(
            s.iter()
                .any(|x| x.path == "Device.WiFi.Radio.1.Stats.Noise" && x.value == -92.0)
        );

        let tree = br#"{"Report":[
            {"CollectionTime":"2026-10-04T01:00:00Z",
             "Device":{"WiFi":{"Radio":{"1":{"Stats":{"BytesSent":12,"Noise":-90}}}}}},
            {"Device":{"DeviceInfo":{"UpTime":7200}}}]}"#;
        let s = parse_bulkdata_json(tree, received).unwrap();
        assert_eq!(s.len(), 3);
        assert!(
            s.iter()
                .any(|x| x.path == "Device.WiFi.Radio.1.Stats.BytesSent" && x.value == 12.0)
        );
        let uptime = s
            .iter()
            .find(|x| x.path == "Device.DeviceInfo.UpTime")
            .unwrap();
        assert_eq!(uptime.ts, received, "no CollectionTime: time of receipt");

        assert!(parse_bulkdata_json(b"{}", received).is_err());
        assert!(parse_bulkdata_json(b"not json", received).is_err());
    }
}
