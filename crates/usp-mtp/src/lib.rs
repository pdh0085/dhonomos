//! USP MTPs: MQTT 5 (US-04, external or embedded broker), WebSocket (US-05),
//! STOMP 1.2 with embedded broker (US-06).

mod close;
mod connlimit;
pub mod dynsec;
mod heard;
mod identity;
pub mod mqtt;
pub mod mqtt_broker;
pub mod stomp;
pub mod tls_bridge;
pub mod ws;
pub mod ws_client;

pub use close::CloseReason;
pub use dynsec::{Dynsec, DynsecConfig, DynsecError};
pub use mqtt::{Inbound, MqttConfig, MqttMtp, MtpError};
pub use mqtt_broker::{MQTT_BROKER_PREFIX, MqttBrokerConfig, MqttBrokerMtp};
pub use stomp::{STOMP_PREFIX, StompConfig, StompMtp};
pub use tls_bridge::MqttTls;
pub use ws::{WS_PREFIX, WsMtp, tls_acceptor, tls_acceptor_with};
pub use ws_client::{ClientHandle, client_tls};

/// `eid` usable as EndpointID on every MTP here.
///
/// Registry key + in logs + part of a topic or destination -> no topic special chars
/// (`+`, `#`, `/`), no spaces, no control chars.
pub(crate) fn valid_eid(eid: &str) -> bool {
    !eid.is_empty()
        && eid.len() <= 256
        && !eid
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '+' | '#' | '/'))
}

/// Max Records waiting for write on 1 Agent connection.
pub(crate) const SEND_QUEUE: usize = 64;

/// Write to an Agent with no progress this long -> connection closed.
pub(crate) const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Queue a Record on an Agent connection, no wait.
///
/// Agent not reading (or not acking) -> queue full -> sender fails at once, not blocked.
/// Connection close = job of its own write or ack timeout.
pub(crate) fn enqueue<T>(
    tx: &tokio::sync::mpsc::Sender<T>,
    item: T,
    mtp: &'static str,
    endpoint_id: &str,
) -> Result<(), MtpError> {
    use tokio::sync::mpsc::error::TrySendError;
    tx.try_send(item).map_err(|e| match e {
        TrySendError::Full(_) => {
            metrics::counter!("dhonomos_usp_send_queue_full_total", "mtp" => mtp).increment(1);
            MtpError::Unavailable(format!(
                "agent send queue full: {endpoint_id} is not reading from its {mtp} connection"
            ))
        }
        TrySendError::Closed(_) => MtpError::Unavailable(format!("{mtp} connection closed")),
    })
}

fn write_timed_out(mtp: &'static str, budget: std::time::Duration) {
    metrics::counter!("dhonomos_usp_write_timeouts_total", "mtp" => mtp).increment(1);
    tracing::debug!(
        mtp,
        ?budget,
        "write to the Agent timed out; closing the connection"
    );
}

/// Write + flush `bytes` to an Agent socket; fail after `timeout` with no progress.
///
/// Timeout per 64 KiB chunk -> big Record on a slow link may take as long as needed.
/// Else a peer that stopped reading holds the connection task (+ connection) forever.
/// Error -> caller closes the connection.
pub(crate) async fn write_all_within<W: tokio::io::AsyncWrite + Unpin>(
    mtp: &'static str,
    wr: &mut W,
    bytes: &[u8],
    timeout: std::time::Duration,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt as _;
    let stalled = || {
        write_timed_out(mtp, timeout);
        close::WriteStalled::error()
    };
    for chunk in bytes.chunks(64 * 1024) {
        tokio::time::timeout(timeout, wr.write_all(chunk))
            .await
            .map_err(|_| stalled())??;
    }
    tokio::time::timeout(timeout, wr.flush())
        .await
        .map_err(|_| stalled())?
}

/// Await `write` of one `len`-byte message to an Agent; limit = `base` + 1 s per 128 KiB.
///
/// Big Record on a slow link -> more time, but not forever.
/// For writers of whole messages; raw socket -> [`write_all_within`].
/// `Err` -> failed or timed out -> close the connection with this cause.
pub(crate) async fn write_within<T, E: std::error::Error + 'static>(
    mtp: &'static str,
    base: std::time::Duration,
    len: usize,
    write: impl std::future::Future<Output = Result<T, E>>,
) -> Result<(), close::Cause> {
    let budget = base + std::time::Duration::from_secs((len / (128 * 1024)) as u64);
    match tokio::time::timeout(budget, write).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(close::Cause::write_chain(&e)),
        Err(_) => {
            write_timed_out(mtp, budget);
            Err(CloseReason::WriteTimeout.into())
        }
    }
}

/// TCP keepalive on an Agent socket (accepted or outgoing). Best effort.
///
/// Peer gone without close (power loss) -> kernel notices.
/// Probes after 60 s idle, then every 10 s; 3 unanswered -> socket error
/// (count set on Linux, Android, macOS, FreeBSD only).
pub(crate) fn enable_tcp_keepalive(stream: &tokio::net::TcpStream) {
    use std::time::Duration;
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(10));
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    let ka = ka.with_retries(3);
    if let Err(e) = socket2::SockRef::from(stream).set_tcp_keepalive(&ka) {
        tracing::debug!(error = %e, "could not enable TCP keepalive");
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn keepalive_is_enabled_on_accepted_sockets() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap());
        let (accepted, client) = tokio::join!(listener.accept(), client);
        let (stream, _) = accepted.unwrap();
        let _client = client.unwrap();
        assert!(!socket2::SockRef::from(&stream).keepalive().unwrap());
        super::enable_tcp_keepalive(&stream);
        let sock = socket2::SockRef::from(&stream);
        assert!(sock.keepalive().unwrap());
        assert_eq!(sock.tcp_keepalive_time().unwrap().as_secs(), 60);
    }
}

/// Send via the MTP of an address: `ws:<EndpointID>`, `stomp:<EndpointID>`,
/// `mqtt:<EndpointID>` (embedded MQTT broker), else MQTT topic on the external broker.
#[derive(Debug, Clone, Default)]
pub struct MultiMtp {
    /// External MQTT broker.
    pub mqtt: Option<MqttMtp>,
    pub ws: Option<WsMtp>,
    /// Embedded STOMP broker.
    pub stomp: Option<StompMtp>,
    /// Embedded MQTT broker. Can run together with `mqtt`:
    /// own addresses start with [`MQTT_BROKER_PREFIX`], `mqtt` ones = bare topics.
    pub mqtt_broker: Option<MqttBrokerMtp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route<'a> {
    Ws(&'a str),
    Stomp(&'a str),
    MqttBroker(&'a str),
    /// Topic on the external MQTT broker.
    Topic(&'a str),
}

/// Prefixes checked first -> prefixed address never reaches the external broker, any config.
fn route(address: &str) -> Route<'_> {
    if let Some(eid) = address.strip_prefix(STOMP_PREFIX) {
        Route::Stomp(eid)
    } else if let Some(eid) = address.strip_prefix(MQTT_BROKER_PREFIX) {
        Route::MqttBroker(eid)
    } else if let Some(eid) = address.strip_prefix(WS_PREFIX) {
        Route::Ws(eid)
    } else {
        Route::Topic(address)
    }
}

impl MultiMtp {
    /// Source IP of the Agent connection to Dhonomos (WebSocket, STOMP, embedded MQTT).
    ///
    /// Agent on the external MQTT broker -> connects there -> `None`.
    pub fn peer_addr(&self, endpoint_id: &str) -> Option<std::net::IpAddr> {
        self.ws
            .as_ref()
            .and_then(|w| w.peer_addr(endpoint_id))
            .or_else(|| self.stomp.as_ref().and_then(|s| s.peer_addr(endpoint_id)))
            .or_else(|| {
                self.mqtt_broker
                    .as_ref()
                    .and_then(|m| m.peer_addr(endpoint_id))
            })
    }

    /// `address` (as [`Inbound::reply_to`]) = connection to Dhonomos itself.
    ///
    /// WebSocket, STOMP, embedded MQTT -> Agent in [`MultiMtp::heard_from`] while open.
    /// Other MQTT addresses = topics on the external broker.
    pub fn is_connection_address(address: &str) -> bool {
        !matches!(route(address), Route::Topic(_))
    }

    /// Agents connected to Dhonomos (WebSocket, STOMP, embedded MQTT) + last heard time.
    ///
    /// Last heard = last frame, packet or byte sent; Linux: also last TCP ACK (STOMP, MQTT).
    /// Agents on the external MQTT broker: not listed, no own connection to ask.
    /// Agent on several MTPs -> later time wins.
    pub fn heard_from(&self) -> std::collections::HashMap<String, std::time::SystemTime> {
        let mut all = std::collections::HashMap::new();
        let listed = self
            .ws
            .iter()
            .flat_map(WsMtp::heard_from)
            .chain(self.stomp.iter().flat_map(StompMtp::heard_from))
            .chain(self.mqtt_broker.iter().flat_map(MqttBrokerMtp::heard_from));
        for (eid, at) in listed {
            all.entry(eid)
                .and_modify(|t: &mut std::time::SystemTime| *t = (*t).max(at))
                .or_insert(at);
        }
        all
    }

    /// Last heard time of the Agent on its connection closed last; given out once.
    ///
    /// Closed connection -> gone from [`MultiMtp::heard_from`].
    /// Controller gets the close a moment later -> asks here for that last time.
    pub fn take_final_heard(&self, endpoint_id: &str) -> Option<std::time::SystemTime> {
        let ws = self
            .ws
            .as_ref()
            .and_then(|w| w.take_final_heard(endpoint_id));
        let stomp = self
            .stomp
            .as_ref()
            .and_then(|s| s.take_final_heard(endpoint_id));
        let mqtt = self
            .mqtt_broker
            .as_ref()
            .and_then(|m| m.take_final_heard(endpoint_id));
        ws.into_iter().chain(stomp).chain(mqtt).max()
    }

    /// Replace revoked Agent client certs (SHA-256 fingerprints, hex) -> number closed.
    ///
    /// Scope: MTPs Dhonomos serves over TLS (WebSocket, STOMP, embedded MQTT).
    /// Revoked cert -> refused at connect; open connections with it -> closed.
    /// External MQTT broker Agents: not affected, the broker terminates their TLS.
    pub fn set_revoked(&self, fingerprints: std::collections::HashSet<String>) -> usize {
        let ws = self
            .ws
            .as_ref()
            .map_or(0, |w| w.set_revoked(fingerprints.clone()));
        let stomp = self
            .stomp
            .as_ref()
            .map_or(0, |s| s.set_revoked(fingerprints.clone()));
        let mqtt = self
            .mqtt_broker
            .as_ref()
            .map_or(0, |m| m.set_revoked(fingerprints));
        ws + stomp + mqtt
    }

    /// Replace the EndpointIDs with an issued (not revoked) client cert.
    ///
    /// Every MTP Dhonomos serves (WebSocket, STOMP, embedded MQTT) refuses a connection for
    /// such an EID without a client cert naming it.
    /// Why: weaker MTPs (shared STOMP/MQTT account, plain connections) must not take the place
    /// of an Agent that proves its identity with its cert.
    /// Open connections stay.
    /// External MQTT broker: out of reach, no client cert seen there -> its per-device
    /// accounts + topic ACLs are the control.
    pub fn set_certificate_bound(&self, eids: std::collections::HashSet<String>) {
        if let Some(ws) = &self.ws {
            ws.set_certificate_bound(eids.clone());
        }
        if let Some(stomp) = &self.stomp {
            stomp.set_certificate_bound(eids.clone());
        }
        if let Some(mqtt) = &self.mqtt_broker {
            mqtt.set_certificate_bound(eids);
        }
    }

    /// Close the Agent connections on MTPs Dhonomos serves -> `true` if one was open.
    ///
    /// Scope: WebSocket, STOMP, embedded MQTT.
    /// MQTT Agents on the external broker -> shut out by their broker account instead.
    pub fn disconnect(&self, endpoint_id: &str) -> bool {
        let ws = self.ws.as_ref().is_some_and(|w| w.disconnect(endpoint_id));
        let stomp = self
            .stomp
            .as_ref()
            .is_some_and(|s| s.disconnect(endpoint_id));
        let mqtt = self
            .mqtt_broker
            .as_ref()
            .is_some_and(|m| m.disconnect(endpoint_id));
        ws || stomp || mqtt
    }

    /// Send by address -> serial of the connection the Record was queued on.
    ///
    /// Serial only on MTPs Dhonomos serves (WebSocket, STOMP, embedded MQTT): new Agent
    /// connection replaces the old one under the same address.
    /// Topic on the external broker -> `None`.
    /// Serials: unique per MTP, never reused, grow in registration order.
    /// [`Inbound::replaced_by`] = serial of the new connection -> Records sent to the same
    /// address over a smaller serial are lost.
    pub async fn send(&self, address: &str, payload: Vec<u8>) -> Result<Option<u64>, MtpError> {
        let none = || MtpError::Unavailable(format!("no MTP for address {address}"));
        match route(address) {
            Route::Stomp(eid) => match &self.stomp {
                Some(stomp) => stomp.send(eid, payload).await.map(Some),
                None => Err(none()),
            },
            Route::MqttBroker(eid) => match &self.mqtt_broker {
                Some(broker) => broker.send(eid, payload).await.map(Some),
                None => Err(none()),
            },
            Route::Ws(eid) => match &self.ws {
                Some(ws) => ws.send(eid, payload).await.map(Some),
                None => Err(none()),
            },
            Route::Topic(topic) => match &self.mqtt {
                Some(mqtt) => mqtt.send(topic, payload).await.map(|()| None),
                None => Err(none()),
            },
        }
    }
}

#[cfg(test)]
mod route_tests {
    #![allow(clippy::unwrap_used)]
    use super::{MultiMtp, Route, route};

    #[test]
    fn prefixes_pick_the_mtp_and_everything_else_is_a_topic_on_the_external_broker() {
        assert_eq!(route("ws:os::A"), Route::Ws("os::A"));
        assert_eq!(route("stomp:os::A"), Route::Stomp("os::A"));
        assert_eq!(route("mqtt:os::A"), Route::MqttBroker("os::A"));
        assert_eq!(route("usp/agent/os::A"), Route::Topic("usp/agent/os::A"));
        // Prefix only at the start + only whole.
        assert_eq!(route("usp/mqtt:os::A"), Route::Topic("usp/mqtt:os::A"));
        assert_eq!(route("mqttx:os::A"), Route::Topic("mqttx:os::A"));
        assert_eq!(route("ws"), Route::Topic("ws"));
    }

    #[test]
    fn connection_addresses_are_those_of_the_mtps_dhonomos_serves() {
        for a in ["ws:os::A", "stomp:os::A", "mqtt:os::A"] {
            assert!(MultiMtp::is_connection_address(a), "{a}");
        }
        assert!(!MultiMtp::is_connection_address("usp/agent/os::A"));
    }

    #[tokio::test]
    async fn an_address_with_a_prefix_never_falls_back_to_the_external_broker() {
        let (mqtt, _inbound) = super::MqttMtp::start(super::MqttConfig {
            host: "127.0.0.1".into(),
            port: 1,
            client_id: "route-test".into(),
            credentials: None,
            controller_topic: "usp/controller/test".into(),
            keep_alive: std::time::Duration::from_secs(30),
            tls: None,
        });
        let multi = MultiMtp {
            mqtt: Some(mqtt),
            ..MultiMtp::default()
        };
        for a in ["ws:os::A", "stomp:os::A", "mqtt:os::A"] {
            let e = multi.send(a, vec![1]).await.unwrap_err();
            assert!(
                matches!(e, super::MtpError::Unavailable(m) if m.contains("no MTP for address")),
                "{a}"
            );
        }
    }
}
