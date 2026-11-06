//! Last delivery time of an Agent connection -> the Agent's `last_contact_at`.
//!
//! Two sources, later one counts:
//! - App stamp: set on anything from the peer (any WebSocket frame incl. Ping + Pong; any
//!   STOMP bytes incl. heart-beat newlines).
//! - Linux + TCP: kernel clock. `tcpi_last_ack_recv` = time since the peer TCP stack last
//!   ACKed anything. Agent without STOMP heart-beat (e.g. obuspa) sends nothing between
//!   Records, but a live peer answers TCP keepalive probes (see `enable_tcp_keepalive`) ->
//!   value moves while the device is alive, stops at power loss. ACK can be for data from
//!   this side -> still proves the peer TCP stack is alive.
//!
//! Agents behind an external MQTT broker -> no own connection to ask.
//! Planned embedded MQTT broker (docs/design/11-mqtt-broker.md) -> same mechanism: one
//! [`Heard`] per connection, touched per packet, same accessors on its MTP type.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// TCP socket of a connection, as its task knows it: raw fd on Unix.
#[cfg(unix)]
pub(crate) type Sock = std::os::fd::RawFd;
/// TCP socket of a connection (not available here).
#[cfg(not(unix))]
pub(crate) type Sock = ();

/// Socket of `stream`, for [`Heard::watch_tcp`].
pub(crate) fn sock_of(stream: &tokio::net::TcpStream) -> Sock {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        stream.as_raw_fd()
    }
    #[cfg(not(unix))]
    {
        let _ = stream;
    }
}

fn unix_ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn from_unix_ms(ms: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(u64::try_from(ms).unwrap_or(0))
}

/// Later of app stamp and last TCP ACK.
/// Kernel gives the ACK as age in ms at `now_ms` (`u32` -> max ~49 days).
fn effective_ms(app_ms: i64, now_ms: i64, ack_age_ms: Option<u32>) -> i64 {
    ack_age_ms.map_or(app_ms, |age| {
        app_ms.max(now_ms.saturating_sub(i64::from(age)))
    })
}

/// ms since the kernel last got an ACK on TCP socket `fd` (`tcpi_last_ack_recv` of `TCP_INFO`).
/// `None` if not readable: not a TCP socket, closed fd, or older kernel without the field.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub(crate) fn last_ack_age_ms(fd: Sock) -> Option<u32> {
    use std::mem::{offset_of, size_of};
    // SAFETY: `tcp_info` = plain integers -> all-zero bits is a valid value.
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = libc::socklen_t::try_from(size_of::<libc::tcp_info>()).ok()?;
    // SAFETY: `info` writable for `len` bytes, `len` for one `socklen_t`, for the whole call.
    // `getsockopt` checks `fd` itself: closed or non-socket fd -> EBADF / ENOTSOCK -> stale
    // `fd` cannot cause memory unsafety. Callers still serialise with the owner closing it
    // (see `Heard::watch_tcp`) -> no read of another socket that reused the number.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&raw mut info).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    // Kernel fills max `len` bytes of its own (maybe shorter) struct.
    let filled = usize::try_from(len).ok()?;
    let needed = offset_of!(libc::tcp_info, tcpi_last_ack_recv) + size_of::<u32>();
    (rc == 0 && filled >= needed).then_some(info.tcpi_last_ack_recv)
}

/// Not Linux: no TCP view -> app stamp only.
#[cfg(not(target_os = "linux"))]
pub(crate) fn last_ack_age_ms(_fd: Sock) -> Option<u32> {
    None
}

/// Last delivery time of one connection.
/// Shared: connection task (feeds it) + MTP (answers for it).
#[derive(Debug)]
pub(crate) struct Heard {
    /// Unix ms of the last receive, app view.
    app_ms: AtomicI64,
    /// TCP socket of the connection while its task owns it (see [`Heard::watch_tcp`]).
    tcp: Mutex<Option<Sock>>,
}

impl Heard {
    /// For a new connection -> counts as heard from.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            app_ms: AtomicI64::new(unix_ms(SystemTime::now())),
            tcp: Mutex::new(None),
        })
    }

    /// Peer sent something just now.
    pub(crate) fn touch(&self) {
        self.app_ms
            .fetch_max(unix_ms(SystemTime::now()), Ordering::Relaxed);
    }

    /// [`Heard::get`] also asks the kernel about `sock`, until the returned guard drops.
    /// Connection task must keep the guard while it uses the socket + drop it before the
    /// socket closes. fd read only while the guard exists, under a lock its drop takes ->
    /// never read after the number can belong to another socket.
    pub(crate) fn watch_tcp(self: &Arc<Self>, sock: Sock) -> TcpWatch {
        if let Ok(mut tcp) = self.tcp.lock() {
            *tcp = Some(sock);
        }
        TcpWatch(self.clone())
    }

    /// Last time the peer was heard from.
    pub(crate) fn get(&self) -> SystemTime {
        let app = self.app_ms.load(Ordering::Relaxed);
        let age = match self.tcp.lock() {
            Ok(tcp) => (*tcp).and_then(last_ack_age_ms),
            Err(_) => None,
        };
        from_unix_ms(effective_ms(app, unix_ms(SystemTime::now()), age))
    }
}

/// Keeps the TCP socket of a connection readable by [`Heard::get`]; see [`Heard::watch_tcp`].
#[derive(Debug)]
pub(crate) struct TcpWatch(Arc<Heard>);

impl Drop for TcpWatch {
    fn drop(&mut self) {
        if let Ok(mut tcp) = self.0.tcp.lock() {
            *tcp = None;
        }
    }
}

/// Keep time of the final last-heard time of a closed connection, until collected.
const CLOSED_KEEP: Duration = Duration::from_secs(600);

#[derive(Debug, Default)]
struct ClosedInner {
    heard: HashMap<String, (Instant, SystemTime)>,
    pruned: Option<Instant>,
}

/// Last-heard time of just-closed connections, until the Controller takes it.
/// Controller learns of the close later, when the connection is already gone.
#[derive(Debug, Clone, Default)]
pub(crate) struct Closed(Arc<Mutex<ClosedInner>>);

impl Closed {
    /// Connection of `eid` closed, last heard from at `heard`.
    pub(crate) fn record(&self, eid: &str, heard: SystemTime) {
        let Ok(mut inner) = self.0.lock() else {
            return;
        };
        let now = Instant::now();
        // Agents still reachable on another MTP -> nobody collects their times.
        // Drop old ones, max 1/min.
        if inner
            .pruned
            .is_none_or(|p| now.duration_since(p) >= Duration::from_secs(60))
        {
            inner
                .heard
                .retain(|_, (at, _)| now.duration_since(*at) < CLOSED_KEEP);
            inner.pruned = Some(now);
        }
        inner.heard.insert(eid.to_owned(), (now, heard));
    }

    /// Recorded time of the last closed connection of `eid`; once.
    pub(crate) fn take(&self, eid: &str) -> Option<SystemTime> {
        let mut inner = self.0.lock().ok()?;
        inner.heard.remove(eid).map(|(_, heard)| heard)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn the_later_of_the_stamp_and_the_last_ack_counts() {
        // No kernel figure -> stamp.
        assert_eq!(effective_ms(1_000, 9_000, None), 1_000);
        // ACK 2 s ago at t = 9 s -> later than stamp.
        assert_eq!(effective_ms(1_000, 9_000, Some(2_000)), 7_000);
        // Stamp later than last ACK.
        assert_eq!(effective_ms(8_000, 9_000, Some(5_000)), 8_000);
        // Max `u32` age -> no overflow, not below 0.
        assert_eq!(effective_ms(0, 1_000, Some(u32::MAX)), 0);
        assert_eq!(
            effective_ms(5, i64::MAX, Some(u32::MAX)),
            i64::MAX - i64::from(u32::MAX)
        );
    }

    #[test]
    fn the_stamp_only_moves_forward() {
        let heard = Heard::new();
        heard.app_ms.store(i64::MAX, Ordering::Relaxed);
        heard.touch();
        assert_eq!(heard.app_ms.load(Ordering::Relaxed), i64::MAX);
    }

    #[test]
    fn closed_connections_are_collected_once() {
        let closed = Closed::default();
        let at = SystemTime::now();
        closed.record("os::A", at);
        assert_eq!(closed.take("os::B"), None);
        assert_eq!(closed.take("os::A"), Some(at));
        assert_eq!(closed.take("os::A"), None);
        // Later connection of same Agent -> replaces the record.
        closed.record("os::A", at);
        let later = at + Duration::from_secs(5);
        closed.record("os::A", later);
        assert_eq!(closed.take("os::A"), Some(later));
    }

    #[cfg(target_os = "linux")]
    fn loopback() -> (std::net::TcpStream, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_kernel_reports_when_a_loopback_peer_last_acknowledged() {
        use std::io::Write as _;
        use std::os::fd::AsRawFd as _;
        let (client, mut server) = loopback();
        // Handshake just done -> small age.
        let young = last_ack_age_ms(client.as_raw_fd()).unwrap();
        assert!(young < 5_000, "age {young} ms right after connecting");
        // No exchange -> age grows with time...
        std::thread::sleep(Duration::from_millis(400));
        let old = last_ack_age_ms(client.as_raw_fd()).unwrap();
        assert!(old >= 350, "age {old} ms after 400 ms of silence");
        // ...until the peer ACKs data (client kernel ACKs it unread).
        server.write_all(b"x").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let age = last_ack_age_ms(server.as_raw_fd()).unwrap();
            if age < 300 {
                break;
            }
            assert!(Instant::now() < deadline, "no ACK seen, age {age} ms");
            std::thread::sleep(Duration::from_millis(20));
        }
        // Not a socket / not open -> no value, no crash.
        assert_eq!(last_ack_age_ms(-1), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn heard_combines_the_stamp_with_the_socket_while_watched() {
        use std::os::fd::AsRawFd as _;
        let (client, _server) = loopback();
        let heard = Heard::new();
        // App stamp long ago; connection itself young.
        heard.app_ms.store(1_000, Ordering::Relaxed);
        assert_eq!(unix_ms(heard.get()), 1_000);
        let watch = heard.watch_tcp(client.as_raw_fd());
        let combined = unix_ms(heard.get());
        let now = unix_ms(SystemTime::now());
        assert!(
            (0..5_000).contains(&(now - combined)),
            "{combined} is not within 5 s of {now}"
        );
        // Guard dropped -> fd no longer read.
        drop(watch);
        assert_eq!(unix_ms(heard.get()), 1_000);
    }
}
