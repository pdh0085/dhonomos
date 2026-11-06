//! WireGuard tunnel history: hub peer status reports (`POST /wg-hub/status`, every 30 s)
//! -> device time series, read via `GET /devices/{id}/metrics/series`.
//! Per device member + network (`<nid>` = network id, 32 lowercase hex digits):
//!
//! - `Dhonomos.WireGuard.<nid>.Connected`: 1 if tunnel `connected`, else 0
//!   ([`TunnelState`], report time = "now": hub reports -> not silent).
//! - `Dhonomos.WireGuard.<nid>.RxRate` + `.TxRate`: bit/s since the previous sample of the
//!   member. Left out on first sample, counter down (reset), or under 1 s passed.
//!
//! Member sampled max once per [`STEP`] (5 min), not per report.
//! Reason: 10,000s of devices x 1 sample set per 30 s report -> 10x rows, little more insight.
//! Connected flag change -> sample at once -> short outage not lost between 2 steps.
//! Last sample in memory only (restart -> start over, sample at next report).
//! Entries not updated for [`FORGET`] -> dropped -> revoked members not kept.
//! Clients (people's devices): no device record for samples -> no history.
//! Sampling needs the server's [`MetricsIngest`](dhonomos_core::MetricsIngest)
//! (`ApiConfig::metrics_ingest`).
//!
//! Sampling = own task, after the hub has its answer -> errors logged, never fail or slow
//! the report. Max 1 task at a time; report during a running task -> not sampled (members
//! stay due -> next report) -> slow DB cannot pile up tasks.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use dhonomos_core::Sample;
use dhonomos_store::WgReportedPeer;
use dhonomos_wireguard::TunnelState;
use futures_util::StreamExt as _;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::AppState;

/// Min time between 2 samples of a member, connected flag unchanged.
pub(crate) const STEP: Duration = Duration::seconds(300);
/// Entries not updated for this long -> dropped.
const FORGET: Duration = Duration::hours(24);
/// Interval of the old-entry check.
const PRUNE_EVERY: Duration = Duration::minutes(1);
/// Max devices stored in parallel.
const PARALLEL_INGESTS: usize = 8;

/// Last sample of a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LastSample {
    pub(crate) ts: OffsetDateTime,
    pub(crate) rx: i64,
    pub(crate) tx: i64,
    pub(crate) connected: bool,
}

/// Samples due for 1 member + what to keep after they are stored.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Due {
    pub(crate) member_id: Uuid,
    pub(crate) device_id: Uuid,
    pub(crate) samples: Vec<Sample>,
    pub(crate) next: LastSample,
}

/// Last sample per member. Bounded table, see module doc.
#[derive(Debug)]
pub(crate) struct TunnelHistory {
    inner: Mutex<Table>,
    /// Sampling task running.
    busy: Arc<AtomicBool>,
}

/// Held by the running sampling task; drop -> next one may run.
#[derive(Debug)]
pub(crate) struct Busy(Arc<AtomicBool>);

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Debug)]
struct Table {
    last: HashMap<Uuid, LastSample>,
    pruned_at: OffsetDateTime,
}

impl Default for TunnelHistory {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Table {
                last: HashMap::new(),
                pruned_at: OffsetDateTime::UNIX_EPOCH,
            }),
            busy: Arc::default(),
        }
    }
}

impl TunnelHistory {
    fn table(&self) -> std::sync::MutexGuard<'_, Table> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Right to sample; `None` while another task holds it.
    pub(crate) fn try_begin(&self) -> Option<Busy> {
        self.busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
            .then(|| Busy(self.busy.clone()))
    }

    /// Samples due at `now` for the members of a report.
    /// Also drops old entries, max once per [`PRUNE_EVERY`].
    pub(crate) fn due(&self, peers: &[WgReportedPeer], now: OffsetDateTime) -> Vec<Due> {
        let mut t = self.table();
        if now - t.pruned_at >= PRUNE_EVERY {
            t.last.retain(|_, l| now - l.ts < FORGET);
            t.pruned_at = now;
        }
        due(&t.last, peers, now)
    }

    /// Keep what was stored for a member.
    pub(crate) fn stored(&self, member_id: Uuid, next: LastSample) {
        self.table().last.insert(member_id, next);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.table().last.len()
    }
}

/// Metric path of `what` of a member in network `network_id`.
pub(crate) fn path(network_id: Uuid, what: &str) -> String {
    format!("Dhonomos.WireGuard.{}.{what}", network_id.simple())
}

/// Bit/s from `before` to `now` bytes over `secs`; `None` if counter went down.
fn rate(before: i64, now: i64, secs: f64) -> Option<f64> {
    (now >= before).then(|| (now - before) as f64 * 8.0 / secs)
}

/// Samples due at `now` for the device members in `peers`, given the last samples.
/// Due = no entry, or [`STEP`] passed since last sample, or connected flag changed.
pub(crate) fn due(
    last: &HashMap<Uuid, LastSample>,
    peers: &[WgReportedPeer],
    now: OffsetDateTime,
) -> Vec<Due> {
    let mut out = Vec::new();
    for p in peers {
        let Some(device_id) = p.device_id else {
            continue;
        };
        let age = p.latest_handshake.map(|h| (now - h).whole_seconds());
        let connected = TunnelState::of(age, Some(0)) == TunnelState::Connected;
        let prev = last.get(&p.member_id);
        if let Some(l) = prev
            && now - l.ts < STEP
            && l.connected == connected
        {
            continue;
        }
        let mut samples = vec![Sample {
            path: path(p.network_id, "Connected"),
            ts: now,
            value: if connected { 1.0 } else { 0.0 },
        }];
        if let Some(l) = prev {
            let secs = (now - l.ts).as_seconds_f64();
            if secs >= 1.0 {
                for (what, before, bytes) in
                    [("RxRate", l.rx, p.rx_bytes), ("TxRate", l.tx, p.tx_bytes)]
                {
                    if let Some(value) = rate(before, bytes, secs) {
                        samples.push(Sample {
                            path: path(p.network_id, what),
                            ts: now,
                            value,
                        });
                    }
                }
            }
        }
        out.push(Due {
            member_id: p.member_id,
            device_id,
            samples,
            next: LastSample {
                ts: now,
                rx: p.rx_bytes,
                tx: p.tx_bytes,
                connected,
            },
        });
    }
    out
}

/// Sample the members of a hub report in an own task.
/// Only if server keeps time series + no other sampling task runs.
pub(crate) fn spawn_record(s: &Arc<AppState>, peers: Vec<WgReportedPeer>) {
    if s.config.metrics_ingest.is_none() || peers.is_empty() {
        return;
    }
    let Some(busy) = s.wg_history.try_begin() else {
        tracing::debug!(
            peers = peers.len(),
            "WireGuard tunnel sampling still running; this report is not sampled"
        );
        return;
    };
    let s = s.clone();
    tokio::spawn(async move {
        let _busy = busy;
        record(&s, &peers).await;
    });
}

/// Sample the members of a hub report, if server keeps time series.
async fn record(s: &AppState, peers: &[WgReportedPeer]) {
    let Some(ingest) = &s.config.metrics_ingest else {
        return;
    };
    let now = OffsetDateTime::now_utc();
    let due = s.wg_history.due(peers, now);
    if due.is_empty() {
        return;
    }
    // 1 call per device -> samples of a device in several networks together.
    let mut per_device: HashMap<Uuid, Vec<Due>> = HashMap::new();
    for d in due {
        per_device.entry(d.device_id).or_default().push(d);
    }
    futures_util::stream::iter(per_device)
        .for_each_concurrent(PARALLEL_INGESTS, |(device, dues)| async move {
            let samples: Vec<Sample> = dues.iter().flat_map(|d| d.samples.clone()).collect();
            match ingest.ingest(device, &samples).await {
                Ok(_) => {
                    for d in dues {
                        s.wg_history.stored(d.member_id, d.next);
                    }
                }
                Err(e) => {
                    tracing::warn!(%device, error = %e, "could not store WireGuard tunnel samples");
                }
            }
        })
        .await;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn t(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(2_000_000_000 + secs).unwrap()
    }

    fn peer(
        member: Uuid,
        device: Option<Uuid>,
        handshake: Option<i64>,
        rx: i64,
        tx: i64,
    ) -> WgReportedPeer {
        WgReportedPeer {
            member_id: member,
            device_id: device,
            network_id: Uuid::from_u128(0xab),
            latest_handshake: handshake.map(t),
            rx_bytes: rx,
            tx_bytes: tx,
        }
    }

    fn values(d: &Due) -> Vec<(String, f64)> {
        d.samples
            .iter()
            .map(|s| (s.path.rsplit('.').next().unwrap().to_owned(), s.value))
            .collect()
    }

    /// Apply `due` result, as `record` does after ingest OK.
    fn store(last: &mut HashMap<Uuid, LastSample>, dues: &[Due]) {
        for d in dues {
            last.insert(d.member_id, d.next);
        }
    }

    #[test]
    fn one_sampling_task_at_a_time() {
        let h = TunnelHistory::default();
        let first = h.try_begin();
        assert!(first.is_some());
        // 2nd report during sampling -> nothing.
        assert!(h.try_begin().is_none());
        drop(first);
        assert!(h.try_begin().is_some());
    }

    #[test]
    fn paths_name_the_network_in_lowercase_hex() {
        assert_eq!(
            path(Uuid::from_u128(0xAB), "Connected"),
            "Dhonomos.WireGuard.000000000000000000000000000000ab.Connected"
        );
    }

    #[test]
    fn a_member_is_sampled_every_step_or_when_its_state_changes() {
        let (m, d) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let mut last = HashMap::new();

        // 1st report -> connected flag, no rates.
        let dues = due(&last, &[peer(m, Some(d), Some(-10), 1_000, 2_000)], t(0));
        assert_eq!(dues.len(), 1);
        assert_eq!(dues[0].device_id, d);
        assert_eq!(values(&dues[0]), [("Connected".to_owned(), 1.0)]);
        assert!(dues[0].samples.iter().all(|s| s.ts == t(0)));
        store(&mut last, &dues);

        // 30 s later, still connected -> nothing.
        let dues = due(&last, &[peer(m, Some(d), Some(20), 5_000, 6_000)], t(30));
        assert!(dues.is_empty());

        // Handshake older than connected window -> sample at once, with rates.
        let dues = due(&last, &[peer(m, Some(d), Some(20), 7_000, 8_000)], t(200));
        assert_eq!(
            values(&dues[0]),
            [
                ("Connected".to_owned(), 0.0),
                ("RxRate".to_owned(), 6_000.0 * 8.0 / 200.0),
                ("TxRate".to_owned(), 6_000.0 * 8.0 / 200.0),
            ]
        );
        store(&mut last, &dues);

        // Still not connected, under 1 step -> nothing.
        assert!(due(&last, &[peer(m, Some(d), Some(20), 9_000, 9_000)], t(400)).is_empty());

        // 1 step after last sample -> rates over deltas since then.
        let dues = due(
            &last,
            &[peer(m, Some(d), Some(20), 7_000 + 37_500, 8_000 + 75_000)],
            t(500),
        );
        assert_eq!(
            values(&dues[0]),
            [
                ("Connected".to_owned(), 0.0),
                ("RxRate".to_owned(), 1_000.0),
                ("TxRate".to_owned(), 2_000.0),
            ]
        );
        assert_eq!(
            dues[0].next,
            LastSample {
                ts: t(500),
                rx: 44_500,
                tx: 83_000,
                connected: false
            }
        );
    }

    #[test]
    fn a_counter_reset_has_no_rate() {
        let (m, d) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let mut last = HashMap::new();
        let first = due(&last, &[peer(m, Some(d), Some(0), 1_000, 2_000)], t(0));
        store(&mut last, &first);
        let dues = due(&last, &[peer(m, Some(d), Some(290), 10, 3_000)], t(300));
        assert_eq!(
            values(&dues[0]),
            [
                ("Connected".to_owned(), 1.0),
                ("TxRate".to_owned(), 1_000.0 * 8.0 / 300.0),
            ]
        );
        // Both reset -> only the flag.
        store(&mut last, &dues);
        let dues = due(&last, &[peer(m, Some(d), Some(590), 0, 0)], t(600));
        assert_eq!(values(&dues[0]), [("Connected".to_owned(), 1.0)]);
    }

    #[test]
    fn under_a_second_has_no_rate() {
        let (m, d) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let mut last = HashMap::new();
        last.insert(
            m,
            LastSample {
                ts: t(0) - Duration::milliseconds(500),
                rx: 0,
                tx: 0,
                connected: false,
            },
        );
        let dues = due(&last, &[peer(m, Some(d), Some(0), 10, 10)], t(0));
        assert_eq!(values(&dues[0]), [("Connected".to_owned(), 1.0)]);
    }

    #[test]
    fn clients_have_no_history() {
        let m = Uuid::from_u128(1);
        assert!(due(&HashMap::new(), &[peer(m, None, Some(0), 1, 1)], t(0)).is_empty());
    }

    #[test]
    fn a_never_seen_peer_is_not_connected() {
        let (m, d) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let dues = due(&HashMap::new(), &[peer(m, Some(d), None, 0, 0)], t(0));
        assert_eq!(values(&dues[0]), [("Connected".to_owned(), 0.0)]);
    }

    #[test]
    fn old_entries_are_dropped_at_most_once_a_minute() {
        let h = TunnelHistory::default();
        let next = |ts| LastSample {
            ts,
            rx: 0,
            tx: 0,
            connected: true,
        };
        h.stored(Uuid::from_u128(1), next(t(0)));
        h.stored(Uuid::from_u128(2), next(t(3_600)));
        // Check: nothing 1 day old yet.
        h.due(&[], t(0) + FORGET - Duration::seconds(30));
        assert_eq!(h.len(), 2);
        // 1st entry now 1 day old, but last check under 1 min ago.
        h.due(&[], t(0) + FORGET + Duration::seconds(10));
        assert_eq!(h.len(), 2);
        h.due(&[], t(0) + FORGET + Duration::seconds(30));
        assert_eq!(h.len(), 1);
    }
}
