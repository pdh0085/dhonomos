//! Runtime settings (stages 2-3): server options an admin can change from the web at runtime.
//! Resolve order (server binary): own config, then values in DB, then defaults.
//! Also: watcher -> follows changes made by any process.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use dhonomos_store::{RUNTIME_SETTINGS_REVISION, Store};
use serde_json::Value;
use uuid::Uuid;

/// Effective value of each runtime option, typed as on the command line.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeSettings {
    /// Days of device events kept; 0 = forever.
    pub events_retention_days: i64,
    /// Days finished tasks kept; 0 = forever.
    pub tasks_retention_days: i64,
    /// Days cleared alarms kept; 0 = forever.
    pub alarms_retention_days: i64,
    /// Days of device time series kept.
    pub metrics_retention_days: i64,
    /// Last days of time series kept as raw rows.
    pub metrics_raw_days: i64,
    /// Alarm webhook URLs.
    pub webhook_url: Vec<String>,
    /// SMTP server for alarm e-mails.
    pub smtp_host: Option<String>,
    pub smtp_port: u16,
    /// SMTP transport security.
    pub smtp_security: crate::mail::Security,
    pub smtp_username: Option<String>,
    pub alarm_email_from: Option<String>,
    pub alarm_email_to: Vec<String>,
    /// Least severe alarm still e-mailed.
    pub alarm_email_min_severity: String,
    /// UI session lifetime, hours.
    pub session_hours: i64,
    /// Idle limit of a UI session, minutes; 0 or less = no idle limit.
    pub session_idle_minutes: i64,
    /// API requests/s per caller; 0 = no limit.
    pub api_rate_limit: u32,
    /// CWMP sessions per CPE per minute; 0 = no limit.
    pub cpe_session_limit: u32,
    /// Max parameters stored from one CPE message.
    pub cpe_max_params_per_message: usize,
    /// Max parameters stored per CPE.
    pub cpe_max_params_per_device: usize,
    /// Idle seconds -> CWMP session aborted.
    pub session_timeout: u64,
    /// Max upload size, bytes.
    pub files_max_bytes: u64,
    /// Bandwidth of all device downloads together, Mbit/s.
    pub files_total_mbps: Option<u64>,
    /// Bandwidth of each device download, Mbit/s.
    pub files_download_mbps: Option<u64>,
    /// Max device downloads at the same time.
    pub files_max_downloads: Option<usize>,
    /// Validity of a download link, hours.
    pub files_link_hours: u64,
    /// Wait for a USP response, seconds.
    pub usp_request_timeout: u64,
    /// Wait for a USP response to a read of the whole data model, seconds.
    pub usp_full_read_timeout: u64,
    /// Add the Controller's own subscriptions to every USP Agent.
    pub usp_auto_subscribe: bool,
    /// Seconds with nothing from a CPE -> its XMPP connection closed.
    /// `None` = 3 keep-alives + 30 s.
    pub xmpp_idle_timeout: Option<u64>,
    /// IPv4 range of WireGuard tunnel prefixes.
    pub wg_address_pool: dhonomos_wireguard::Ipv4Prefix,
    /// Rest time of a revoked WireGuard member address before reuse, hours.
    pub wg_address_reuse_delay_hours: u64,
}

/// Keep a process in step with the runtime settings in the DB.
/// Revision != last seen (check every `every`, or at once on `wake`) -> read all -> `on_change`.
/// `seen` = revision the caller already applied (`None` -> apply on 1st check).
pub async fn watch(
    store: Store,
    tenant_id: Uuid,
    every: Duration,
    wake: Arc<tokio::sync::Notify>,
    seen: Option<i64>,
    mut on_change: impl FnMut(BTreeMap<String, Value>) + Send,
) {
    let load = {
        let store = store.clone();
        move || {
            let store = store.clone();
            async move { store.runtime_settings(tenant_id).await }
        }
    };
    watch_revision(
        &store,
        tenant_id,
        RUNTIME_SETTINGS_REVISION,
        "runtime settings",
        every,
        wake,
        seen,
        load,
        |rev, values: BTreeMap<String, Value>| {
            tracing::info!(
                revision = rev,
                values = values.len(),
                "runtime settings loaded from the database"
            );
            on_change(values);
        },
    )
    .await;
}

/// Follow a config in the DB by its `config_revisions` counter `kind`.
/// Revision != `seen` (check every `every`, or at once on `wake`) -> `load` -> `on_change`
/// with the revision.
/// Load failed -> log (with `what`), retry at next check; running config stays.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn watch_revision<T, F>(
    store: &Store,
    tenant_id: Uuid,
    kind: &str,
    what: &str,
    every: Duration,
    wake: Arc<tokio::sync::Notify>,
    mut seen: Option<i64>,
    mut load: impl FnMut() -> F + Send,
    mut on_change: impl FnMut(i64, T) + Send,
) where
    F: Future<Output = Result<T, dhonomos_store::StoreError>> + Send,
{
    loop {
        match store.config_revision(tenant_id, kind).await {
            Ok(rev) if seen != Some(rev) => match load().await {
                Ok(value) => {
                    on_change(rev, value);
                    seen = Some(rev);
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    "loading {what} failed; keeping the running ones"
                ),
            },
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "checking the {what} revision failed"),
        }
        tokio::select! {
            () = tokio::time::sleep(every) => {}
            () = wake.notified() => {}
        }
    }
}
