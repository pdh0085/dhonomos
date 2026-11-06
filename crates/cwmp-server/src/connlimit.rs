//! Open-connection caps (CW-17): global + per source address.
//! IPv6: per /64, same as [`crate::guard::AuthGuard`].
//! Over either cap -> closed at accept, before any byte read or task spawn.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

use crate::guard::source;

/// Connection refusal cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Global cap reached.
    Total,
    /// Source address (or IPv6 /64) at its cap.
    PerSource,
}

impl Refused {
    /// `reason` label of `dhonomos_cwmp_rejected_total`.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Total => "connections_total",
            Self::PerSource => "connections_per_ip",
        }
    }
}

#[derive(Debug, Default)]
struct Counts {
    total: usize,
    per_source: HashMap<IpAddr, usize>,
}

/// Open-connection accounting.
#[derive(Debug)]
pub(crate) struct ConnLimiter {
    max_total: usize,
    max_per_source: usize,
    counts: Mutex<Counts>,
}

impl ConnLimiter {
    /// Cap 0 = unlimited.
    pub(crate) fn new(max_total: usize, max_per_source: usize) -> Arc<Self> {
        Arc::new(Self {
            max_total,
            max_per_source,
            counts: Mutex::default(),
        })
    }

    /// Admit 1 more connection from `ip`. Permit dropped -> slot free.
    pub(crate) fn acquire(self: &Arc<Self>, ip: IpAddr) -> Result<ConnPermit, Refused> {
        let key = source(ip);
        // Poisoned lock = only a panic mid-update of plain counters -> still usable.
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let from_source = counts.per_source.get(&key).copied().unwrap_or(0);
        if self.max_per_source != 0 && from_source >= self.max_per_source {
            return Err(Refused::PerSource);
        }
        if self.max_total != 0 && counts.total >= self.max_total {
            return Err(Refused::Total);
        }
        counts.total += 1;
        counts.per_source.insert(key, from_source + 1);
        drop(counts);
        metrics::gauge!("dhonomos_cwmp_connections").increment(1.0);
        Ok(ConnPermit {
            limiter: Arc::clone(self),
            key,
        })
    }

    /// Connections admitted now.
    pub(crate) fn open(&self) -> usize {
        self.counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .total
    }
}

/// One admitted connection.
#[derive(Debug)]
pub(crate) struct ConnPermit {
    limiter: Arc<ConnLimiter>,
    key: IpAddr,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        let mut counts = self
            .limiter
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        counts.total = counts.total.saturating_sub(1);
        if let Some(n) = counts.per_source.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                counts.per_source.remove(&self.key);
            }
        }
        drop(counts);
        metrics::gauge!("dhonomos_cwmp_connections").decrement(1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or_else(|_| panic!("{s}"))
    }

    #[test]
    fn per_source_cap_frees_slots_on_drop() {
        let l = ConnLimiter::new(0, 2);
        let a = l.acquire(ip("203.0.113.9"));
        let b = l.acquire(ip("203.0.113.9"));
        assert!(a.is_ok() && b.is_ok());
        assert_eq!(l.acquire(ip("203.0.113.9")).err(), Some(Refused::PerSource));
        assert!(l.acquire(ip("203.0.113.10")).is_ok(), "other sources fit");
        drop(a);
        assert!(
            l.acquire(ip("203.0.113.9")).is_ok(),
            "a freed slot is reusable"
        );
    }

    #[test]
    fn global_cap_and_unlimited() {
        let l = ConnLimiter::new(3, 0);
        let held: Vec<_> = (1..=3)
            .map(|i| l.acquire(ip(&format!("198.51.100.{i}"))))
            .collect();
        assert!(held.iter().all(Result::is_ok));
        assert_eq!(l.open(), 3);
        assert_eq!(l.acquire(ip("198.51.100.4")).err(), Some(Refused::Total));
        drop(held);
        assert_eq!(l.open(), 0);
        assert!(l.counts.lock().is_ok_and(|c| c.per_source.is_empty()));

        let unlimited = ConnLimiter::new(0, 0);
        let many: Vec<_> = (0..1000).map(|_| unlimited.acquire(ip("::1"))).collect();
        assert!(many.iter().all(Result::is_ok));
    }

    #[test]
    fn ipv6_counts_per_prefix_and_mapped_v4_as_v4() {
        let l = ConnLimiter::new(0, 1);
        let held = l.acquire(ip("2001:db8:1:2::1"));
        assert!(held.is_ok());
        assert_eq!(
            l.acquire(ip("2001:db8:1:2:abcd::9")).err(),
            Some(Refused::PerSource),
            "same /64"
        );
        assert!(l.acquire(ip("2001:db8:1:3::1")).is_ok(), "another /64");

        let v4 = l.acquire(ip("192.0.2.7"));
        assert!(v4.is_ok());
        assert_eq!(
            l.acquire(ip("::ffff:192.0.2.7")).err(),
            Some(Refused::PerSource),
            "an IPv4-mapped address is the same source"
        );
    }
}
