//! Sessions per CPE (threat model: CPE stuck in an Inform loop, ADR-084).
//! Token bucket per device. Session over the limit -> fault 8005 before the Inform is stored;
//! CPE retries later with its own backoff.
//! Key chosen by the caller. CWMP backend: per (username, client address, device identity),
//! only after identity checks -> claim of another identity cannot use up its sessions (L-3).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

/// Max entries before idle ones are dropped.
const PRUNE_AT: usize = 100_000;

/// Session limiter per device; one per process.
#[derive(Debug)]
pub struct SessionLimiter {
    /// Sessions/min, also the burst; 0 = no limit.
    per_minute: AtomicU32,
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

impl SessionLimiter {
    /// `per_minute` sessions per device per minute (burst = same); 0 = no limit.
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute: AtomicU32::new(per_minute),
            buckets: Mutex::default(),
        }
    }

    /// Change the limit at runtime (0 = off).
    /// Bucket fuller than the new limit -> cut down at its next session.
    pub fn set_per_minute(&self, per_minute: u32) {
        self.per_minute.store(per_minute, Ordering::Relaxed);
        if per_minute == 0
            && let Ok(mut buckets) = self.buckets.lock()
        {
            // Limit on again -> every device starts with a full bucket.
            buckets.clear();
        }
    }

    /// Current limit (0 = off).
    pub fn per_minute(&self) -> u32 {
        self.per_minute.load(Ordering::Relaxed)
    }

    /// Take a session for `device`; false = over the limit.
    pub fn allow(&self, device: &str) -> bool {
        self.allow_at(device, Instant::now())
    }

    fn allow_at(&self, device: &str, now: Instant) -> bool {
        let per_minute = self.per_minute();
        if per_minute == 0 {
            return true;
        }
        let per_minute = f64::from(per_minute);
        let Ok(mut buckets) = self.buckets.lock() else {
            return true;
        };
        let rate = per_minute / 60.0;
        if buckets.len() >= PRUNE_AT {
            // Full bucket = no info -> drop.
            let cap = per_minute;
            buckets.retain(|_, (tokens, at)| {
                *tokens + now.duration_since(*at).as_secs_f64() * rate < cap
            });
        }
        let (tokens, at) = buckets
            .entry(device.to_owned())
            .or_insert((per_minute, now));
        *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * rate).min(per_minute);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bursts_then_refills() {
        let l = SessionLimiter::new(3);
        let t0 = Instant::now();
        assert!((0..3).all(|_| l.allow_at("a", t0)));
        assert!(!l.allow_at("a", t0), "fourth in the same instant");
        assert!(l.allow_at("b", t0), "other devices are not affected");
        // 3/min -> 1 token per 20 s.
        assert!(!l.allow_at("a", t0 + Duration::from_secs(10)));
        assert!(l.allow_at("a", t0 + Duration::from_secs(31)));
        assert!(!l.allow_at("a", t0 + Duration::from_secs(32)));
    }

    #[test]
    fn the_limit_changes_while_running() {
        let l = SessionLimiter::new(0);
        let t0 = Instant::now();
        assert!((0..100).all(|_| l.allow_at("a", t0)), "0 is off");
        l.set_per_minute(2);
        assert!(l.allow_at("a", t0) && l.allow_at("a", t0));
        assert!(!l.allow_at("a", t0));
        // Raised -> bucket refills toward the new limit.
        l.set_per_minute(60);
        assert!(l.allow_at("a", t0 + Duration::from_secs(2)));
        // Lowered -> full bucket cut down to the new limit.
        l.set_per_minute(1);
        assert!(l.allow_at("b", t0));
        assert!(!l.allow_at("b", t0));
        l.set_per_minute(0);
        assert!((0..10).all(|_| l.allow_at("b", t0)));
    }
}
