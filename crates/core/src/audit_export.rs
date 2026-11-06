//! Audit log -> external sink (ADR-083) -> copy survives DB tampering.
//! One process (leader lock) posts new records in order, in batches, signed like alarm
//! webhooks. Position kept in DB.

use std::time::Duration;

use dhonomos_store::{AuditEntry, Store};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use tracing::{info, warn};
use uuid::Uuid;

/// Records per POST.
const BATCH: i64 = 500;
/// Pause when caught up.
const IDLE: Duration = Duration::from_secs(5);
/// Max wait after failures.
const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// Audit log target.
#[derive(Debug, Clone)]
pub struct AuditSink {
    /// Webhook URL (HTTP or HTTPS).
    pub url: String,
    /// HMAC secret for `X-Dhonomos-Signature` (empty -> unsigned).
    pub secret: String,
}

fn record_json(a: &AuditEntry) -> Value {
    json!({
        "id": a.id,
        "occurred_at": a.occurred_at.format(&Rfc3339).unwrap_or_default(),
        "actor": a.actor,
        "action": a.action,
        "target_type": a.target_type,
        "target_id": a.target_id,
        "detail": a.detail,
    })
}

/// Body of one POST: `{"source": "dhonomos", "tenant_id", "records": [...]}`.
pub fn batch_json(tenant_id: Uuid, records: &[AuditEntry]) -> Value {
    json!({
        "source": "dhonomos",
        "tenant_id": tenant_id,
        "records": records.iter().map(record_json).collect::<Vec<_>>(),
    })
}

/// Ship one batch -> records sent (0 = caught up).
pub async fn ship_once(store: &Store, tenant_id: Uuid, sink: &AuditSink) -> Result<usize, String> {
    let from = store
        .audit_export_position(tenant_id, &sink.url)
        .await
        .map_err(|e| e.to_string())?;
    let records = store
        .audit_after(tenant_id, from, BATCH)
        .await
        .map_err(|e| e.to_string())?;
    let Some(last) = records.last() else {
        return Ok(0);
    };
    let body = batch_json(tenant_id, &records).to_string();
    crate::webhook::post(&sink.url, &body, &sink.secret).await?;
    store
        .set_audit_export_position(tenant_id, &sink.url, last.id)
        .await
        .map_err(|e| e.to_string())?;
    metrics::counter!("dhonomos_audit_exported_total").increment(records.len() as u64);
    Ok(records.len())
}

/// Ship forever while this process holds the shipper lock.
pub async fn run(store: Store, tenant_id: Uuid, sink: AuditSink) {
    let mut lock: Option<dhonomos_store::LeaderLock> = None;
    let mut backoff = IDLE;
    loop {
        if let Some(l) = lock.as_mut()
            && !l.alive().await
        {
            warn!("audit shipper lost its lock");
            lock = None;
        }
        if lock.is_none() {
            match store.try_audit_export_lock().await {
                Ok(Some(l)) => {
                    info!(webhook = %crate::webhook::redact_url(&sink.url), "audit log shipping active");
                    lock = Some(l);
                }
                Ok(None) => {
                    tokio::time::sleep(IDLE).await;
                    continue;
                }
                Err(e) => {
                    warn!(error = %e, "audit shipper lock");
                    tokio::time::sleep(IDLE).await;
                    continue;
                }
            }
        }
        match ship_once(&store, tenant_id, &sink).await {
            // Full batch -> maybe more waiting.
            Ok(n) if n as i64 == BATCH => {
                backoff = IDLE;
                continue;
            }
            Ok(_) => backoff = IDLE,
            Err(e) => {
                metrics::counter!("dhonomos_audit_export_failures_total").increment(1);
                warn!(webhook = %crate::webhook::redact_url(&sink.url), error = %e, retry_in = ?backoff, "shipping the audit log failed");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        }
        if let (Ok(latest), Ok(pos)) = (
            store.latest_audit_id(tenant_id).await,
            store.audit_export_position(tenant_id, &sink.url).await,
        ) {
            metrics::gauge!("dhonomos_audit_export_lag").set((latest - pos).max(0) as f64);
        }
        tokio::time::sleep(IDLE).await;
    }
}
