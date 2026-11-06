//! Param writes that must not fail silently.
//! Row refused by DB or failed batch -> logged (no values) + counted in
//! `dhonomos_param_store_errors_total`.

use dhonomos_store::{ParamUpdate, ParamsWritten, RejectedParam, Store, StoreError};
use tracing::warn;
use uuid::Uuid;

/// Max chars of a device-sent path in a log line (enough to find it).
const LOGGED_PATH_CHARS: usize = 160;

/// Log + count params the DB refused one by one (rest of their batch stored).
/// `source` = part of the system that wrote them.
pub(crate) fn report_rejected(device: Uuid, source: &'static str, rejected: &[RejectedParam]) {
    let Some(first) = rejected.first() else {
        return;
    };
    metrics::counter!("dhonomos_param_store_errors_total", "source" => source, "kind" => "row")
        .increment(rejected.len() as u64);
    let path: String = first.path.chars().take(LOGGED_PATH_CHARS).collect();
    warn!(%device, source, count = rejected.len(), first_path = %path, error = %first.error,
        "storing parameters failed; the rest of the batch was stored");
}

/// Log + count a param write that failed as a whole (DB unavailable, ...).
/// `source` = part of the system that wrote it.
pub(crate) fn report_failure(device: Uuid, source: &'static str, error: &StoreError) {
    metrics::counter!("dhonomos_param_store_errors_total", "source" => source, "kind" => "batch")
        .increment(1);
    warn!(%device, source, %error, "storing parameters failed");
}

/// [`Store::upsert_params`] for callers that go on whatever happens to the params
/// (Agent answer acted on either way) -> outcome reported, not returned.
pub(crate) async fn upsert_reporting(
    store: &Store,
    device: Uuid,
    source: &'static str,
    params: &[ParamUpdate],
) {
    match store.upsert_params(device, params).await {
        Ok(ParamsWritten { rejected, .. }) => report_rejected(device, source, &rejected),
        Err(e) => report_failure(device, source, &e),
    }
}
