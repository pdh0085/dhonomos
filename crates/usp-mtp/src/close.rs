//! Why an Agent connection ended.
//!
//! Each MTP with one connection per Agent -> cause recorded where its loop stops.
//! Reported once: "closed" log line (`reason`, `error`, `connected_secs`)
//! and `dhonomos_usp_connections_closed_total`.
//! Reporting only: nothing here decides when a connection closes.

use std::error::Error;
use std::fmt;
use std::io;
use std::sync::Mutex;

use tokio::sync::Notify;
use tokio_tungstenite::tungstenite;

/// Why an Agent connection ended.
///
/// [`CloseReason::as_str`] = label of `dhonomos_usp_connections_closed_total{mtp, reason}`
/// and `reason` field of the log line -> labels must stay stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloseReason {
    /// Agent ended the session: WebSocket Close frame, STOMP `DISCONNECT`, MQTT `DISCONNECT`.
    AgentClosed,
    /// Transport ended (TCP FIN, TLS EOF), no protocol-level close.
    Eof,
    /// Peer reset (`ECONNRESET`).
    Reset,
    /// Kernel gave up (`ETIMEDOUT`). Idle socket -> TCP keepalive found the peer gone.
    TcpTimeout,
    /// Any other socket read error.
    ReadError,
    /// Packet started but not complete in time (MQTT).
    ReadTimeout,
    /// Agent took nothing written for the write timeout (stopped reading).
    WriteTimeout,
    WriteError,
    /// Agent silent too long: WebSocket no-traffic limit, STOMP heart-beat limit,
    /// MQTT Keep Alive limit.
    IdleTimeout,
    /// Receive Maximum window full -> Agent did not ack Records (MQTT).
    AckTimeout,
    /// Newer connection of the same Agent took its place.
    Replaced,
    /// Agent client certificate revoked.
    Revoked,
    /// Server asked to close it (acceptance policy refused the Agent, or operator disconnect).
    ClosedByServer,
    /// Agent data not readable as a frame or packet of the protocol.
    BadFrame,
    /// Well-formed data from the Agent, but against a protocol rule.
    ProtocolError,
    /// Hand-off of a Record to the Controller failed.
    DeliveryFailed,
    /// Record queue of the Agent closed under its connection.
    QueueClosed,
}

impl CloseReason {
    /// Stable snake_case label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentClosed => "agent_closed",
            Self::Eof => "eof",
            Self::Reset => "reset",
            Self::TcpTimeout => "tcp_timeout",
            Self::ReadError => "read_error",
            Self::ReadTimeout => "read_timeout",
            Self::WriteTimeout => "write_timeout",
            Self::WriteError => "write_error",
            Self::IdleTimeout => "idle_timeout",
            Self::AckTimeout => "ack_timeout",
            Self::Replaced => "replaced",
            Self::Revoked => "revoked",
            Self::ClosedByServer => "closed_by_server",
            Self::BadFrame => "bad_frame",
            Self::ProtocolError => "protocol_error",
            Self::DeliveryFailed => "delivery_failed",
            Self::QueueClosed => "queue_closed",
        }
    }
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a connection ended: reason + error behind it, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cause {
    pub(crate) reason: CloseReason,
    pub(crate) error: Option<String>,
}

impl From<CloseReason> for Cause {
    fn from(reason: CloseReason) -> Self {
        Self {
            reason,
            error: None,
        }
    }
}

impl Cause {
    /// `reason` caused by `error`.
    pub(crate) fn because(reason: CloseReason, error: impl fmt::Display) -> Self {
        Self {
            reason,
            error: Some(error.to_string()),
        }
    }

    pub(crate) fn read(e: &io::Error) -> Self {
        Self::because(classify_io(e), e)
    }

    pub(crate) fn write(e: &io::Error) -> Self {
        Self::because(classify_write_io(e), e)
    }

    /// Failed WebSocket read (tungstenite, or axum wrapping it).
    pub(crate) fn read_chain(e: &(dyn Error + 'static)) -> Self {
        Self::because(classify_chain(e, classify_io, CloseReason::ReadError), e)
    }

    /// Failed WebSocket write.
    pub(crate) fn write_chain(e: &(dyn Error + 'static)) -> Self {
        Self::because(
            classify_chain(e, classify_write_io, CloseReason::WriteError),
            e,
        )
    }

    /// Count the close in `dhonomos_usp_connections_closed_total`.
    pub(crate) fn count(&self, mtp: &'static str) {
        metrics::counter!(
            "dhonomos_usp_connections_closed_total",
            "mtp" => mtp,
            "reason" => self.reason.as_str()
        )
        .increment(1);
    }
}

/// Kind of failure of a read from an Agent socket.
///
/// Idle socket: `TimedOut` = kernel TCP keepalive gave up on the peer.
/// `UnexpectedEof` = also TLS for a peer closed without `close_notify`.
pub(crate) fn classify_io(e: &io::Error) -> CloseReason {
    match e.kind() {
        io::ErrorKind::UnexpectedEof => CloseReason::Eof,
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => CloseReason::Reset,
        io::ErrorKind::TimedOut => CloseReason::TcpTimeout,
        _ => CloseReason::ReadError,
    }
}

/// Kind of failure of a write to an Agent socket: own stall ([`WriteStalled`]), peer reset,
/// kernel gave up, or other.
pub(crate) fn classify_write_io(e: &io::Error) -> CloseReason {
    if e.get_ref().is_some_and(|inner| inner.is::<WriteStalled>()) {
        return CloseReason::WriteTimeout;
    }
    match e.kind() {
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe => CloseReason::Reset,
        io::ErrorKind::TimedOut => CloseReason::TcpTimeout,
        _ => CloseReason::WriteError,
    }
}

/// Error of a write that took nothing for the write timeout.
///
/// `TimedOut` io error (what callers always saw) + marker -> told apart from kernel `ETIMEDOUT`.
#[derive(Debug)]
pub(crate) struct WriteStalled;

impl fmt::Display for WriteStalled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the Agent took nothing written to it within the write timeout")
    }
}

impl Error for WriteStalled {}

impl WriteStalled {
    pub(crate) fn error() -> io::Error {
        io::Error::new(io::ErrorKind::TimedOut, Self)
    }
}

/// Walk an error + its sources (axum WebSocket error -> tungstenite error -> `io::Error`)
/// to the most telling cause: `io::Error` (sorted by `io`) or WebSocket protocol error.
/// None -> `fallback`.
fn classify_chain(
    e: &(dyn Error + 'static),
    io: fn(&io::Error) -> CloseReason,
    fallback: CloseReason,
) -> CloseReason {
    use tungstenite::Error as Ws;
    use tungstenite::error::ProtocolError;
    let mut next = Some(e);
    while let Some(err) = next {
        if let Some(e) = err.downcast_ref::<io::Error>() {
            let reason = io(e);
            if reason != fallback {
                return reason;
            }
        } else if let Some(ws) = err.downcast_ref::<Ws>() {
            match ws {
                // Transport ended under an open WebSocket, no Close frame.
                Ws::Protocol(ProtocolError::ResetWithoutClosingHandshake) => {
                    return CloseReason::Eof;
                }
                Ws::Protocol(_) | Ws::Capacity(_) | Ws::Utf8(_) | Ws::AttackAttempt => {
                    return CloseReason::BadFrame;
                }
                _ => {}
            }
        }
        next = err.source();
    }
    fallback
}

/// Close one connection from outside its task + say why. First caller sets the reason.
///
/// Reason can also be [noted](Self::note) without waking the task -> for a connection that
/// ends by itself (Record queue closed after a newer connection replaced it).
#[derive(Debug, Default)]
pub(crate) struct CloseSignal {
    why: Mutex<Option<CloseReason>>,
    notify: Notify,
}

impl CloseSignal {
    /// Note why the connection will end, without waking it.
    pub(crate) fn note(&self, reason: CloseReason) {
        if let Ok(mut why) = self.why.lock() {
            why.get_or_insert(reason);
        }
    }

    /// Ask the connection to close for `reason`.
    pub(crate) fn close(&self, reason: CloseReason) {
        self.note(reason);
        self.notify.notify_one();
    }

    /// Reason noted or asked for, if any.
    pub(crate) fn reason(&self) -> Option<CloseReason> {
        self.why.lock().ok().and_then(|why| *why)
    }

    /// Wait for a close request -> its reason.
    pub(crate) async fn closed(&self) -> CloseReason {
        self.notify.notified().await;
        self.reason().unwrap_or(CloseReason::ClosedByServer)
    }

    /// End reason after the Record queue closed: noted reason, if any (newer connection
    /// replaced it), else `QueueClosed`.
    pub(crate) fn queue_closed(&self) -> CloseReason {
        self.reason().unwrap_or(CloseReason::QueueClosed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::io::{Error, ErrorKind};

    use super::*;

    const ALL: [CloseReason; 17] = [
        CloseReason::AgentClosed,
        CloseReason::Eof,
        CloseReason::Reset,
        CloseReason::TcpTimeout,
        CloseReason::ReadError,
        CloseReason::ReadTimeout,
        CloseReason::WriteTimeout,
        CloseReason::WriteError,
        CloseReason::IdleTimeout,
        CloseReason::AckTimeout,
        CloseReason::Replaced,
        CloseReason::Revoked,
        CloseReason::ClosedByServer,
        CloseReason::BadFrame,
        CloseReason::ProtocolError,
        CloseReason::DeliveryFailed,
        CloseReason::QueueClosed,
    ];

    #[test]
    fn labels_are_distinct_snake_case_words() {
        let labels: std::collections::HashSet<_> = ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(labels.len(), ALL.len());
        for l in labels {
            assert!(
                !l.is_empty() && l.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{l}"
            );
        }
        assert_eq!(CloseReason::TcpTimeout.to_string(), "tcp_timeout");
    }

    #[test]
    fn a_failed_read_is_sorted_by_what_the_kernel_or_tls_said() {
        let of = |k: ErrorKind| classify_io(&Error::from(k));
        assert_eq!(of(ErrorKind::TimedOut), CloseReason::TcpTimeout);
        assert_eq!(of(ErrorKind::ConnectionReset), CloseReason::Reset);
        assert_eq!(of(ErrorKind::ConnectionAborted), CloseReason::Reset);
        // TLS: peer closed without close_notify.
        assert_eq!(of(ErrorKind::UnexpectedEof), CloseReason::Eof);
        assert_eq!(of(ErrorKind::InvalidData), CloseReason::ReadError);
        assert_eq!(of(ErrorKind::PermissionDenied), CloseReason::ReadError);
    }

    /// Kernel TCP keepalive gives up -> read returns ETIMEDOUT.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_read_that_fails_with_etimedout_is_the_kernel_giving_up() {
        let e = Error::from_raw_os_error(libc::ETIMEDOUT);
        assert_eq!(e.kind(), ErrorKind::TimedOut);
        assert_eq!(classify_io(&e), CloseReason::TcpTimeout);
        // != own write stall.
        assert_eq!(classify_write_io(&e), CloseReason::TcpTimeout);
    }

    #[test]
    fn a_failed_write_tells_our_own_stall_from_the_kernel_giving_up() {
        let of = |e: Error| classify_write_io(&e);
        assert_eq!(of(WriteStalled::error()), CloseReason::WriteTimeout);
        assert_eq!(WriteStalled::error().kind(), ErrorKind::TimedOut);
        // Kernel timeout != own stall.
        assert_eq!(
            of(Error::from(ErrorKind::TimedOut)),
            CloseReason::TcpTimeout
        );
        assert_eq!(of(Error::from(ErrorKind::BrokenPipe)), CloseReason::Reset);
        assert_eq!(
            of(Error::from(ErrorKind::ConnectionReset)),
            CloseReason::Reset
        );
        assert_eq!(of(Error::from(ErrorKind::Other)), CloseReason::WriteError);
    }

    #[test]
    fn websocket_errors_are_followed_down_to_what_caused_them() {
        use tungstenite::Error as Ws;
        use tungstenite::error::{CapacityError, ProtocolError};
        let read = |e: &(dyn std::error::Error + 'static)| Cause::read_chain(e).reason;
        // io error in tungstenite error in axum error.
        let timed_out = Ws::Io(Error::from(ErrorKind::TimedOut));
        assert_eq!(read(&timed_out), CloseReason::TcpTimeout);
        let wrapped = axum::Error::new(Ws::Io(Error::from(ErrorKind::ConnectionReset)));
        assert_eq!(read(&wrapped), CloseReason::Reset);
        let tls_eof = axum::Error::new(Ws::Io(Error::from(ErrorKind::UnexpectedEof)));
        assert_eq!(read(&tls_eof), CloseReason::Eof);
        // Transport ended, no Close frame.
        let reset = axum::Error::new(Ws::Protocol(ProtocolError::ResetWithoutClosingHandshake));
        assert_eq!(read(&reset), CloseReason::Eof);
        // Other protocol violations + oversized messages -> bad frame.
        let bad = axum::Error::new(Ws::Protocol(ProtocolError::UnmaskedFrameFromClient));
        assert_eq!(read(&bad), CloseReason::BadFrame);
        let big = Ws::Capacity(CapacityError::MessageTooLong {
            size: 2,
            max_size: 1,
        });
        assert_eq!(read(&big), CloseReason::BadFrame);
        assert_eq!(read(&Ws::Utf8("x".into())), CloseReason::BadFrame);
        // Unknown error -> plain read error, text kept.
        let other = Cause::read_chain(&Ws::AlreadyClosed);
        assert_eq!(other.reason, CloseReason::ReadError);
        assert_eq!(
            other.error.as_deref(),
            Some("Trying to work with closed connection")
        );

        // Writes: own sorting of io errors.
        let write = |e: &(dyn std::error::Error + 'static)| Cause::write_chain(e).reason;
        let broken = axum::Error::new(Ws::Io(Error::from(ErrorKind::BrokenPipe)));
        assert_eq!(write(&broken), CloseReason::Reset);
        let stalled = Ws::Io(WriteStalled::error());
        assert_eq!(write(&stalled), CloseReason::WriteTimeout);
        assert_eq!(write(&Ws::ConnectionClosed), CloseReason::WriteError);
    }

    #[tokio::test]
    async fn the_first_reason_counts_and_a_noted_one_does_not_wake() {
        let signal = CloseSignal::default();
        assert_eq!(signal.queue_closed(), CloseReason::QueueClosed);
        signal.note(CloseReason::Replaced);
        // Noted only -> no wake.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), signal.closed())
                .await
                .is_err()
        );
        assert_eq!(signal.queue_closed(), CloseReason::Replaced);
        // Close later -> wake, first reason kept.
        signal.close(CloseReason::Revoked);
        assert_eq!(signal.closed().await, CloseReason::Replaced);

        // Close before any waiter -> not lost.
        let signal = CloseSignal::default();
        signal.close(CloseReason::ClosedByServer);
        signal.close(CloseReason::Revoked);
        assert_eq!(signal.closed().await, CloseReason::ClosedByServer);
    }
}
