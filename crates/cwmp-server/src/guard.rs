//! Block sources with repeated CPE auth failures (CW-17).
//! `limit` failures within `window` from one address (IPv6: its /64) -> refused for `window`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// At this many tracked addresses -> drop expired entries.
const MAX_TRACKED: usize = 100_000;

#[derive(Debug, Clone, Copy)]
struct Record {
    failures: u32,
    since: Instant,
    blocked_until: Option<Instant>,
}

/// Failure counts + blocks per source.
#[derive(Debug)]
pub(crate) struct AuthGuard {
    limit: u32,
    window: Duration,
    records: Mutex<HashMap<IpAddr, Record>>,
}

/// Counting key: IPv4 (also IPv4-mapped) as is; IPv6 -> its /64 (one subscriber prefix).
pub(crate) fn source(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

impl AuthGuard {
    /// `limit == 0` -> no blocking.
    pub(crate) fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            records: Mutex::default(),
        }
    }

    /// True -> requests from `ip` refused now.
    pub(crate) fn blocked(&self, ip: IpAddr, now: Instant) -> bool {
        if self.limit == 0 {
            return false;
        }
        self.records
            .lock()
            .ok()
            .and_then(|r| r.get(&source(ip)).copied())
            .and_then(|r| r.blocked_until)
            .is_some_and(|until| now < until)
    }

    /// Count a failed auth. True -> this failure blocks the source.
    pub(crate) fn failed(&self, ip: IpAddr, now: Instant) -> bool {
        if self.limit == 0 {
            return false;
        }
        let Ok(mut records) = self.records.lock() else {
            return false;
        };
        if records.len() >= MAX_TRACKED {
            let window = self.window;
            records.retain(|_, r| {
                r.blocked_until.is_some_and(|u| now < u) || now.duration_since(r.since) < window
            });
        }
        let r = records.entry(source(ip)).or_insert(Record {
            failures: 0,
            since: now,
            blocked_until: None,
        });
        if r.blocked_until.is_some_and(|u| now >= u) || now.duration_since(r.since) >= self.window {
            *r = Record {
                failures: 0,
                since: now,
                blocked_until: None,
            };
        }
        r.failures += 1;
        if r.failures >= self.limit && r.blocked_until.is_none() {
            r.blocked_until = Some(now + self.window);
            return true;
        }
        false
    }

    /// Successful auth -> clear failures of the source. Active block stays.
    pub(crate) fn succeeded(&self, ip: IpAddr) {
        if self.limit == 0 {
            return;
        }
        if let Ok(mut records) = self.records.lock() {
            let key = source(ip);
            if records.get(&key).is_some_and(|r| r.blocked_until.is_none()) {
                records.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or_else(|_| panic!("{s}"))
    }

    #[test]
    fn blocks_after_repeated_failures_then_expires() {
        let g = AuthGuard::new(3, Duration::from_secs(600));
        let t0 = Instant::now();
        let a = ip("203.0.113.9");
        assert!(!g.failed(a, t0));
        assert!(!g.failed(a, t0));
        assert!(g.failed(a, t0), "third failure blocks");
        assert!(g.blocked(a, t0 + Duration::from_secs(1)));
        assert!(
            !g.blocked(ip("203.0.113.10"), t0),
            "other addresses unaffected"
        );
        g.succeeded(a);
        assert!(g.blocked(a, t0), "a success does not lift a block");
        assert!(
            !g.blocked(a, t0 + Duration::from_secs(601)),
            "blocks expire"
        );
        // Failures outside the window -> count starts over.
        let b = ip("198.51.100.1");
        g.failed(b, t0);
        g.failed(b, t0);
        assert!(!g.failed(b, t0 + Duration::from_secs(700)));
        // Success -> count cleared.
        let c = ip("198.51.100.2");
        g.failed(c, t0);
        g.failed(c, t0);
        g.succeeded(c);
        assert!(!g.failed(c, t0));
    }

    #[test]
    fn ipv6_counts_per_prefix() {
        let g = AuthGuard::new(2, Duration::from_secs(600));
        let t0 = Instant::now();
        g.failed(ip("2001:db8:1:2::1"), t0);
        assert!(g.failed(ip("2001:db8:1:2::ffff"), t0), "same /64");
        assert!(g.blocked(ip("2001:db8:1:2:abcd::1"), t0));
        assert!(!g.blocked(ip("2001:db8:1:3::1"), t0));
        assert!(
            !AuthGuard::new(0, Duration::from_secs(1)).failed(ip("::1"), t0),
            "0 disables"
        );
    }
}
