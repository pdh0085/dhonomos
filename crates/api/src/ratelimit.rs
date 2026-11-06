//! Rate limit per caller (SE-03): token bucket per authenticated principal.
//! Auth failed -> bucket per client address.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Max buckets -> then idle (full) ones dropped.
const MAX_BUCKETS: usize = 10_000;

/// Token buckets: refill `rate`/s up to `burst`.
#[derive(Debug)]
pub(crate) struct RateLimiter {
    rate: Rate,
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

/// Rate + burst of a [`RateLimiter`].
#[derive(Debug)]
enum Rate {
    /// Requests/s, burst.
    Fixed(f64, f64),
    /// Current requests/s, burst = rate x this factor.
    Live(dhonomos_core::Shared<u32>, u32),
}

impl RateLimiter {
    /// `rate` requests/s, bursts of `burst`. `rate == 0` -> no limit.
    pub(crate) fn new(rate: u32, burst: u32) -> Self {
        Self {
            rate: Rate::Fixed(f64::from(rate), f64::from(burst.max(rate))),
            buckets: Mutex::default(),
        }
    }

    /// `rate` requests/s, read at each request (may change while running).
    /// Bursts of `factor` x rate. Rate 0 -> no limit.
    pub(crate) fn live(rate: dhonomos_core::Shared<u32>, factor: u32) -> Self {
        Self {
            rate: Rate::Live(rate, factor),
            buckets: Mutex::default(),
        }
    }

    fn rate(&self) -> (f64, f64) {
        match &self.rate {
            Rate::Fixed(rate, burst) => (*rate, *burst),
            Rate::Live(rate, factor) => {
                let rate = *rate.get();
                (
                    f64::from(rate),
                    f64::from(rate.saturating_mul(*factor).max(rate)),
                )
            }
        }
    }

    /// Take one token for `key`. None left -> `Err(time until the next token)`.
    pub(crate) fn check(&self, key: &str, now: Instant) -> Result<(), Duration> {
        let (rate, burst) = self.rate();
        if rate <= 0.0 {
            return Ok(());
        }
        let Ok(mut buckets) = self.buckets.lock() else {
            return Ok(());
        };
        if buckets.len() >= MAX_BUCKETS && !buckets.contains_key(key) {
            buckets.retain(|_, (tokens, at)| {
                *tokens + now.duration_since(*at).as_secs_f64() * rate < burst
            });
        }
        let (tokens, at) = buckets.entry(key.to_owned()).or_insert((burst, now));
        *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * rate).min(burst);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - *tokens) / rate))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_refill_per_key() {
        let l = RateLimiter::new(10, 20);
        let t0 = Instant::now();
        for _ in 0..20 {
            assert!(l.check("a", t0).is_ok());
        }
        let wait = l.check("a", t0).expect_err("burst used up");
        assert!(wait <= Duration::from_millis(100), "{wait:?}");
        assert!(
            l.check("b", t0).is_ok(),
            "other callers have their own bucket"
        );
        // 10/s -> after 0.5 s, 5 more.
        let t1 = t0 + Duration::from_millis(500);
        for _ in 0..5 {
            assert!(l.check("a", t1).is_ok());
        }
        assert!(l.check("a", t1).is_err());
        assert!(RateLimiter::new(0, 0).check("a", t0).is_ok(), "0 disables");
    }

    #[test]
    fn a_live_rate_changes_while_running() {
        let rate = dhonomos_core::Shared::new(0);
        let l = RateLimiter::live(rate.clone(), 4);
        let t0 = Instant::now();
        assert!((0..100).all(|_| l.check("a", t0).is_ok()), "0 is off");
        rate.replace(1);
        assert!((0..4).all(|_| l.check("a", t0).is_ok()), "a burst of four");
        assert!(l.check("a", t0).is_err(), "limited without a restart");
        rate.replace(100);
        assert!(l.check("a", t0 + Duration::from_millis(50)).is_ok());
        rate.replace(0);
        assert!(l.check("a", t0).is_ok(), "off again");
    }
}
