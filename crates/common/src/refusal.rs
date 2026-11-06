//! Log lines for refusals of the public listeners, with source address.
//!
//! Prometheus metrics -> how many, not who.
//! [`connection_refused!`](crate::connection_refused) +
//! [`request_refused!`](crate::request_refused) -> one `info` line: listener, remote, reason.
//!
//! ```text
//! connection refused listener=cwmp remote=203.0.113.9:51514 reason=tls_handshake error=...
//! request refused listener=cwmp remote=203.0.113.9:51514 reason=auth_failed username="admin"
//! ```
//!
//! Scan or password guessing -> same refusal 1000s of times.
//! One limiter per process -> each (listener, reason, source IP) logs once per [`WINDOW`].
//! Repeats counted -> next line of the key has `suppressed=N`.
//! No next line -> periodic sweep logs them as `refusals suppressed`.
//! Max [`MAX_KEYS`] keys; oldest dropped first.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

#[doc(hidden)]
pub use tracing;

/// Quiet time of a (listener, reason, source IP) key after its line.
pub const WINDOW: Duration = Duration::from_secs(600);

/// Max keys in the limiter.
pub const MAX_KEYS: usize = 4096;

/// Sweep interval: drop expired keys + report their repeats.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// Max chars of peer-chosen text (username) in a log line.
const CLIP_CHARS: usize = 64;

/// Source of a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remote {
    Addr(SocketAddr),
    Ip(IpAddr),
    /// Source not known at the refusal point.
    Unknown,
}

impl Remote {
    /// Counting key. IPv4-mapped IPv6 = IPv4.
    fn key_ip(self) -> IpAddr {
        match self {
            Self::Addr(a) => a.ip().to_canonical(),
            Self::Ip(ip) => ip.to_canonical(),
            Self::Unknown => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

impl fmt::Display for Remote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Addr(a) => write!(f, "{}", SocketAddr::new(a.ip().to_canonical(), a.port())),
            Self::Ip(ip) => write!(f, "{}", ip.to_canonical()),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

impl From<SocketAddr> for Remote {
    fn from(a: SocketAddr) -> Self {
        Self::Addr(a)
    }
}

impl From<IpAddr> for Remote {
    fn from(ip: IpAddr) -> Self {
        Self::Ip(ip)
    }
}

impl From<Option<SocketAddr>> for Remote {
    fn from(a: Option<SocketAddr>) -> Self {
        a.map_or(Self::Unknown, Self::Addr)
    }
}

impl From<Option<IpAddr>> for Remote {
    fn from(ip: Option<IpAddr>) -> Self {
        ip.map_or(Self::Unknown, Self::Ip)
    }
}

/// First `CLIP_CHARS` chars of peer-chosen text.
///
/// Must log with `?` (Debug) -> quoted + control chars escaped -> no forged lines or fields.
pub fn clip(text: &str) -> String {
    text.chars().take(CLIP_CHARS).collect()
}

type Key = (&'static str, &'static str, IpAddr);

#[derive(Debug)]
struct Entry {
    /// Key in `order`. New number at each window start.
    seq: u64,
    started: Instant,
    suppressed: u64,
}

/// Repeats not logged with a next line -> own report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flushed {
    pub listener: &'static str,
    pub reason: &'static str,
    pub ip: IpAddr,
    /// Refusals left out.
    pub suppressed: u64,
}

/// Result of [`RefusalLimiter::admit`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Admission {
    /// `Some(n)` -> log this refusal; `n` earlier ones of its key left out.
    /// `None` -> repeat inside the window, only counted.
    pub log: Option<u64>,
    /// Counts of keys gone without a next line (expired or dropped for room).
    pub flushed: Vec<Flushed>,
}

/// Each (listener, reason, source IP) -> one line per window. Bounded memory.
#[derive(Debug)]
pub struct RefusalLimiter {
    window: Duration,
    cap: usize,
    entries: HashMap<Key, Entry>,
    /// Keys by window-start number, oldest first.
    order: BTreeMap<u64, Key>,
    next_seq: u64,
    last_sweep: Option<Instant>,
}

impl RefusalLimiter {
    /// `window` between lines of a key, max `cap` keys (min 1).
    pub fn new(window: Duration, cap: usize) -> Self {
        Self {
            window,
            cap: cap.max(1),
            entries: HashMap::new(),
            order: BTreeMap::new(),
            next_seq: 0,
            last_sweep: None,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Count a refusal at `now` -> log it or not.
    pub fn admit(
        &mut self,
        now: Instant,
        listener: &'static str,
        reason: &'static str,
        ip: IpAddr,
    ) -> Admission {
        let mut flushed = Vec::new();
        let key = (listener, reason, ip);
        let log = if let Some(e) = self.entries.get_mut(&key) {
            if now.saturating_duration_since(e.started) < self.window {
                e.suppressed += 1;
                None
            } else {
                // Window over -> log this one + repeat count.
                let suppressed = std::mem::take(&mut e.suppressed);
                self.order.remove(&e.seq);
                e.seq = self.next_seq;
                e.started = now;
                self.next_seq += 1;
                self.order.insert(e.seq, key);
                Some(suppressed)
            }
        } else {
            if self.entries.len() >= self.cap
                && let Some((_, oldest)) = self.order.pop_first()
                && let Some(gone) = self.entries.remove(&oldest)
            {
                flushed.extend(flush_of(oldest, gone.suppressed));
            }
            let seq = self.next_seq;
            self.next_seq += 1;
            self.order.insert(seq, key);
            self.entries.insert(
                key,
                Entry {
                    seq,
                    started: now,
                    suppressed: 0,
                },
            );
            Some(0)
        };
        // Sweep after key update -> restarted key not expired, its count already logged.
        self.sweep(now, &mut flushed);
        Admission { log, flushed }
    }

    /// Drop keys with window over, max once per [`SWEEP_EVERY`]. Their repeats -> `flushed`.
    fn sweep(&mut self, now: Instant, flushed: &mut Vec<Flushed>) {
        if self
            .last_sweep
            .is_some_and(|t| now.saturating_duration_since(t) < SWEEP_EVERY)
        {
            return;
        }
        self.last_sweep = Some(now);
        while let Some((&seq, &key)) = self.order.first_key_value() {
            let expired = self
                .entries
                .get(&key)
                .is_none_or(|e| now.saturating_duration_since(e.started) >= self.window);
            if !expired {
                break;
            }
            self.order.remove(&seq);
            if let Some(gone) = self.entries.remove(&key) {
                flushed.extend(flush_of(key, gone.suppressed));
            }
        }
    }
}

fn flush_of((listener, reason, ip): Key, suppressed: u64) -> Option<Flushed> {
    (suppressed > 0).then_some(Flushed {
        listener,
        reason,
        ip,
        suppressed,
    })
}

fn shared() -> &'static Mutex<RefusalLimiter> {
    static SHARED: OnceLock<Mutex<RefusalLimiter>> = OnceLock::new();
    SHARED.get_or_init(|| Mutex::new(RefusalLimiter::new(WINDOW, MAX_KEYS)))
}

/// Count a refusal in the process-wide limiter.
///
/// `Some(n)` -> log it; `n` repeats since last line of its key (0 = none).
/// Repeats gone without a next line -> logged here as `refusals suppressed`.
/// Caller: [`connection_refused!`](crate::connection_refused) +
/// [`request_refused!`](crate::request_refused) only, not for direct use.
#[doc(hidden)]
pub fn admit(listener: &'static str, reason: &'static str, remote: Remote) -> Option<u64> {
    let Admission { log, flushed } = {
        let mut limiter = shared().lock().unwrap_or_else(PoisonError::into_inner);
        limiter.admit(Instant::now(), listener, reason, remote.key_ip())
    };
    for f in &flushed {
        log_flushed(f);
    }
    log
}

fn log_flushed(f: &Flushed) {
    tracing::info!(
        listener = %f.listener,
        remote = %f.ip,
        reason = %f.reason,
        suppressed = f.suppressed,
        "refusals suppressed"
    );
}

/// Log a refused connection at `info` (TLS handshake, connection caps, stream closed by error).
///
/// Same listener + reason + source IP within [`WINDOW`](crate::refusal::WINDOW) -> no line.
/// `connection_refused!(listener, reason, remote [, field = value ...])`.
/// `listener`, `reason`: short `&'static str` tokens, e.g. `"cwmp"`, `"tls_handshake"`.
/// `remote`: anything [`Remote`](crate::refusal::Remote) is made from.
/// Rest: `tracing` fields. Peer-chosen text -> [`clip`](crate::refusal::clip) + `?`.
#[macro_export]
macro_rules! connection_refused {
    ($listener:expr, $reason:expr, $remote:expr $(, $($fields:tt)+)?) => {
        $crate::__refused!("connection refused", $listener, $reason, $remote $(, $($fields)+)?)
    };
}

/// Log a refused request at `info` (failed login, malformed or forbidden request).
///
/// Same listener + reason + source IP within [`WINDOW`](crate::refusal::WINDOW) -> no line.
/// Arguments = [`connection_refused!`](crate::connection_refused).
#[macro_export]
macro_rules! request_refused {
    ($listener:expr, $reason:expr, $remote:expr $(, $($fields:tt)+)?) => {
        $crate::__refused!("request refused", $listener, $reason, $remote $(, $($fields)+)?)
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __refused {
    ($message:literal, $listener:expr, $reason:expr, $remote:expr $(, $($fields:tt)+)?) => {{
        let listener: &'static str = $listener;
        let reason: &'static str = $reason;
        let remote = $crate::refusal::Remote::from($remote);
        if let ::core::option::Option::Some(repeats) =
            $crate::refusal::admit(listener, reason, remote)
        {
            // Field only when repeats > 0.
            let suppressed = (repeats > 0).then_some(repeats);
            $crate::refusal::tracing::info!(
                listener = %listener,
                remote = %remote,
                reason = %reason,
                suppressed,
                $($($fields)+,)?
                $message
            );
        }
    }};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::io::Write;
    use std::sync::Arc;

    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    fn limiter() -> (RefusalLimiter, Instant) {
        (RefusalLimiter::new(10 * MINUTE, 4), Instant::now())
    }

    #[test]
    fn the_first_refusal_is_logged_and_repeats_are_counted() {
        let (mut l, t0) = limiter();
        let first = l.admit(t0, "cwmp", "auth_failed", ip(1));
        assert_eq!(first.log, Some(0));
        for i in 1..=5 {
            let again = l.admit(t0 + Duration::from_secs(i), "cwmp", "auth_failed", ip(1));
            assert_eq!(again.log, None, "repeat {i}");
        }
        // Line after the window -> count of left-out repeats.
        let after = l.admit(t0 + 10 * MINUTE, "cwmp", "auth_failed", ip(1));
        assert_eq!(after.log, Some(5));
        assert!(after.flushed.is_empty());
        // Count restarts.
        let next = l.admit(t0 + 10 * MINUTE + MINUTE, "cwmp", "auth_failed", ip(1));
        assert_eq!(next.log, None);
        let last = l.admit(t0 + 20 * MINUTE, "cwmp", "auth_failed", ip(1));
        assert_eq!(last.log, Some(1));
    }

    #[test]
    fn the_window_runs_from_the_logged_line_not_from_the_last_repeat() {
        let (mut l, t0) = limiter();
        l.admit(t0, "cwmp", "auth_failed", ip(1));
        // Refusal every 1 min -> key quiet for max 1 window.
        for m in 1..10 {
            assert_eq!(
                l.admit(t0 + m * MINUTE, "cwmp", "auth_failed", ip(1)).log,
                None
            );
        }
        assert_eq!(
            l.admit(t0 + 10 * MINUTE, "cwmp", "auth_failed", ip(1)).log,
            Some(9)
        );
    }

    #[test]
    fn listener_reason_and_address_are_separate_keys() {
        let (mut l, t0) = limiter();
        assert_eq!(l.admit(t0, "cwmp", "auth_failed", ip(1)).log, Some(0));
        assert_eq!(l.admit(t0, "xmpp", "auth_failed", ip(1)).log, Some(0));
        assert_eq!(l.admit(t0, "cwmp", "tls_handshake", ip(1)).log, Some(0));
        assert_eq!(l.admit(t0, "cwmp", "auth_failed", ip(2)).log, Some(0));
        assert_eq!(l.admit(t0, "cwmp", "auth_failed", ip(1)).log, None);
        assert_eq!(l.len(), 4);
    }

    #[test]
    fn repeats_without_a_next_line_are_flushed_by_the_sweep() {
        let (mut l, t0) = limiter();
        l.admit(t0, "cwmp", "auth_failed", ip(1));
        l.admit(t0 + MINUTE, "cwmp", "auth_failed", ip(1));
        l.admit(t0 + MINUTE, "cwmp", "auth_failed", ip(1));
        l.admit(t0, "stun", "invalid", ip(2));
        // Any refusal after the window -> sweep. ip(1): 2 repeats, ip(2): 0.
        let swept = l.admit(t0 + 11 * MINUTE, "xmpp", "tls_handshake", ip(3));
        assert_eq!(swept.log, Some(0));
        assert_eq!(
            swept.flushed,
            [Flushed {
                listener: "cwmp",
                reason: "auth_failed",
                ip: ip(1),
                suppressed: 2,
            }]
        );
        assert_eq!(l.len(), 1, "expired keys are gone");
    }

    #[test]
    fn sweeps_do_not_run_on_every_refusal() {
        let (mut l, t0) = limiter();
        l.admit(t0, "cwmp", "auth_failed", ip(1));
        l.admit(t0, "cwmp", "auth_failed", ip(1));
        // 1st admit swept (empty) -> next sweep due 1 min later.
        let early = l.admit(t0 + Duration::from_secs(30), "stun", "invalid", ip(2));
        assert!(early.flushed.is_empty());
        let due = l.admit(t0 + 11 * MINUTE, "stun", "invalid", ip(2));
        assert_eq!(due.flushed.len(), 1);
    }

    #[test]
    fn the_oldest_key_makes_room_and_its_count_is_reported() {
        let (mut l, t0) = limiter();
        l.admit(t0, "cwmp", "a", ip(1));
        l.admit(t0, "cwmp", "a", ip(1));
        for i in 2..=4 {
            l.admit(t0 + Duration::from_secs(u64::from(i)), "cwmp", "a", ip(i));
        }
        assert_eq!(l.len(), 4);
        let fifth = l.admit(t0 + Duration::from_secs(5), "cwmp", "a", ip(5));
        assert_eq!(fifth.log, Some(0));
        assert_eq!(l.len(), 4, "the cap holds");
        assert_eq!(
            fifth.flushed,
            [Flushed {
                listener: "cwmp",
                reason: "a",
                ip: ip(1),
                suppressed: 1,
            }]
        );
        // Dropped key -> new key. Others still kept.
        assert_eq!(
            l.admit(t0 + Duration::from_secs(6), "cwmp", "a", ip(3)).log,
            None
        );
        assert_eq!(
            l.admit(t0 + Duration::from_secs(6), "cwmp", "a", ip(1)).log,
            Some(0)
        );
        assert_eq!(l.len(), 4);
    }

    #[test]
    fn a_flood_of_addresses_stays_within_the_cap() {
        let mut l = RefusalLimiter::new(WINDOW, 64);
        let t0 = Instant::now();
        for i in 0..10_000u32 {
            let addr = IpAddr::V4(Ipv4Addr::from(i));
            l.admit(
                t0 + Duration::from_millis(u64::from(i)),
                "stun",
                "invalid",
                addr,
            );
            assert!(l.len() <= 64);
        }
        assert_eq!(l.len(), 64);
        assert_eq!(l.order.len(), 64, "the order index is bounded too");
    }

    #[test]
    fn mapped_ipv4_addresses_count_as_ipv4() {
        let mapped: SocketAddr = "[::ffff:203.0.113.7]:4000".parse().unwrap();
        let plain: SocketAddr = "203.0.113.7:5000".parse().unwrap();
        assert_eq!(Remote::from(mapped).key_ip(), Remote::from(plain).key_ip());
        assert_eq!(Remote::from(mapped).to_string(), "203.0.113.7:4000");
        assert_eq!(Remote::from(plain.ip()).to_string(), "203.0.113.7");
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(Remote::from(v6).to_string(), "[2001:db8::1]:443");
        assert_eq!(Remote::from(None::<SocketAddr>).to_string(), "unknown");
        assert_eq!(
            Remote::from(None::<IpAddr>).key_ip(),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn peer_text_is_clipped() {
        assert_eq!(clip("admin"), "admin");
        assert_eq!(clip(&"x".repeat(200)).chars().count(), CLIP_CHARS);
        // Chars, not bytes -> no cut inside a multi-byte char.
        assert_eq!(clip(&"é".repeat(100)).chars().count(), CLIP_CHARS);
        // Debug (as macro callers log it) -> escapes line-forging chars.
        let logged = format!("{:?}", clip("a\nINFO fake\u{1b}[31m"));
        assert!(
            !logged.contains('\n') && !logged.contains('\u{1b}'),
            "{logged}"
        );
    }

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl Write for Buf {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Lines the closure logs at info+ on this thread.
    fn logged(f: impl FnOnce()) -> Vec<String> {
        let buf = Buf::default();
        let writer = buf.clone();
        let guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::INFO)
                .with_writer(move || writer.clone())
                .finish(),
        );
        f();
        drop(guard);
        let bytes = buf.0.lock().unwrap_or_else(PoisonError::into_inner).clone();
        String::from_utf8(bytes)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn the_macros_log_listener_remote_and_reason_once() {
        // Own addresses: limiter shared by all tests of the process.
        let remote: SocketAddr = "198.51.100.10:40000".parse().unwrap();
        let lines = logged(|| {
            for _ in 0..3 {
                crate::request_refused!("test", "macro_once", remote, username = ?clip("ad\"min"));
            }
            crate::connection_refused!("test", "macro_conn", remote);
        });
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains("INFO"), "{}", lines[0]);
        assert!(
            lines[0].contains(
                "request refused listener=test remote=198.51.100.10:40000 reason=macro_once"
            ),
            "{}",
            lines[0]
        );
        assert!(lines[0].contains(r#"username="ad\"min""#), "{}", lines[0]);
        assert!(!lines[0].contains("suppressed"), "{}", lines[0]);
        assert!(
            lines[1].contains("connection refused listener=test"),
            "{}",
            lines[1]
        );
        assert!(lines[1].contains("reason=macro_conn"), "{}", lines[1]);
    }

    #[test]
    fn repeats_are_a_field_only_when_there_are_some_and_flushes_have_their_own_line() {
        // Macro count field = `Option` -> recorded only when `Some`.
        let lines = logged(|| {
            let none: Option<u64> = None;
            tracing::info!(listener = "x", suppressed = none, "request refused");
            tracing::info!(listener = "x", suppressed = Some(57u64), "request refused");
            log_flushed(&Flushed {
                listener: "xmpp",
                reason: "auth_failed",
                ip: ip(9),
                suppressed: 12,
            });
        });
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(!lines[0].contains("suppressed"), "{}", lines[0]);
        assert!(
            lines[1].ends_with("request refused listener=\"x\" suppressed=57"),
            "{}",
            lines[1]
        );
        assert!(
            lines[2].ends_with(
                "refusals suppressed listener=xmpp remote=203.0.113.9 reason=auth_failed suppressed=12"
            ),
            "{}",
            lines[2]
        );
    }

    #[test]
    fn a_source_that_is_not_known_is_still_logged() {
        let lines = logged(|| {
            crate::request_refused!("test", "macro_unknown", None::<SocketAddr>);
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("remote=unknown"), "{}", lines[0]);
    }
}
