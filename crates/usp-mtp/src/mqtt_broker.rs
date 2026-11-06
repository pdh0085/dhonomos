//! MQTT MTP, Controller = broker (US-04, ADR-093).
//! Agent connects with MQTT 5.0 -> CONNACK gives its topic (`subscribe-topic` user property,
//! Response Information) -> Records published to the Controller topic, its own back as
//! QoS 1 PUBLISH.
//!
//! Only what USP needs. Refused: wildcard + shared subscriptions, QoS 2, retained messages,
//! topic aliases, subscription identifiers, enhanced authentication.
//! Nothing stored (clean start, no session, no queue): Record for an Agent not connected =
//! error -> task goes out again at its next connection.
//! Will accepted + ignored: broker = Controller itself.
//!
//! EndpointID of the connection = sender the MTP vouches for (ADR-087). Sources, in order:
//! 1. TLS client certificate, `urn:bbf:usp:id:` subjectAltName (`usp-endpoint-id` claim +
//!    first Record must agree);
//! 2. (phase 3) Username of a per-device account;
//! 3. `usp-endpoint-id` user property of CONNECT, required of MQTT 5.0 Agents by TR-369
//!    (unauthenticated claim, like STOMP `endpoint-id` header);
//! 4. `from_id` of the first Record, for clients that say nothing at CONNECT.
//!
//! Once known: first Record with another `from_id` -> connection closed.
//! Later Records carry the vouched sender -> Controller drops those that differ.
//!
//! Connection without client certificate -> never replaces a live connection of the same
//! EndpointID made with one.
//! EndpointID with a client certificate issued ([`MqttBrokerMtp::set_certificate_bound`]) ->
//! refused to connections without one, whatever the account.
//! Revoked certificate ([`MqttBrokerMtp::set_revoked`]) -> refused + its connections closed.
//!
//! MQTT 3.1.1 (phase 2): refused today. [`negotiate`] = where its CONNECT would be told apart.
//!
//! Limits per connection (docs/design/11-mqtt-broker.md, section 9): connections (total + per
//! source address), size of a non-PUBLISH packet, topic filters + property size of a packet,
//! Keep Alive, time for a packet to arrive, time the Agent's Receive Maximum window may stay
//! full. Packet sizes + counts checked on raw bytes, before any decode into strings.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use bytes::{Buf as _, Bytes, BytesMut};
use dhonomos_common::refusal::Remote;
use prost::Message as _;
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::{
    ConnAck, ConnAckProperties, Connect, ConnectReturnCode, Disconnect, DisconnectProperties,
    DisconnectReasonCode, Login, Packet, PingResp, PubAck, PubAckReason, Publish,
    PublishProperties, SubAck, Subscribe, SubscribeReasonCode, UnsubAck, UnsubAckReason,
    Unsubscribe,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, info, warn};

use crate::close::{Cause, CloseReason};
use crate::connlimit::{ConnLimiter, ConnPermit};
use crate::heard::{Closed, Heard, Sock, sock_of};
use crate::identity::{CertPolicy, ClientCert, Refusal};
use crate::stomp::same;
use crate::{Inbound, MtpError, SEND_QUEUE, WRITE_TIMEOUT, enqueue, valid_eid};

/// Address prefix of embedded-broker connections in `Inbound::reply_to`.
/// External-broker MQTT addresses = bare topics -> never this prefix.
pub const MQTT_BROKER_PREFIX: &str = "mqtt:";

/// USP MQTT content type (TR-369).
pub const USP_CONTENT_TYPE: &str = "usp.msg";

/// CONNECT user property with the EndpointID of an MQTT 5.0 Agent (TR-369).
const EID_PROPERTY: &str = "usp-endpoint-id";

/// CONNACK user property: topic the Agent subscribes to (TR-369).
const SUBSCRIBE_TOPIC_PROPERTY: &str = "subscribe-topic";

/// Max PUBLISH after CONNECT (= other MTPs).
const MAX_PACKET: u32 = crate::mqtt::MAX_PACKET_SIZE;

/// Max non-PUBLISH packet after CONNECT. PUBACK = few bytes, SUBSCRIBE with max filters =
/// few KiB; only a Record is big. Checked from the fixed header, before buffering.
const MAX_CONTROL_PACKET: u32 = 16 * 1024;

/// Max property section of PUBLISH, SUBSCRIBE, UNSUBSCRIBE. USP properties (Content Type,
/// Response Topic) < 100 bytes. User property >= 5 bytes, decoded into 2 strings
/// -> section as big as the packet = memory amplifier.
const MAX_PROPERTIES: usize = 4 * 1024;

/// Max CONNECT: arrives before authentication.
const MAX_CONNECT_PACKET: u32 = 64 * 1024;

/// Max time for a new connection to send its CONNECT (+ finish the TLS handshake).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Keep Alive given to a client that asked for none (0) -> else vanished client never noticed.
const DEFAULT_KEEP_ALIVE: u16 = 60;

/// Default max Keep Alive (s). Client asking more -> told this in CONNACK (Server Keep Alive)
/// -> must use it.
pub const DEFAULT_MAX_KEEP_ALIVE: u16 = 1200;

/// Default max time for a packet to arrive, from its first byte.
/// Big PUBLISH: +1 s per 64 KiB announced.
pub const DEFAULT_PARTIAL_PACKET_TIMEOUT: Duration = Duration::from_secs(60);

/// Default max time the Agent's Receive Maximum window stays full without PUBACK -> close.
pub const DEFAULT_ACK_TIMEOUT: Duration = Duration::from_secs(60);

/// Closing connection keeps reading this long -> DISCONNECT reaches a client still sending
/// (close with unread data = connection reset).
const LINGER: Duration = Duration::from_millis(500);

/// Max subscriptions per connection + max filters per SUBSCRIBE or UNSUBSCRIBE.
const MAX_SUBSCRIPTIONS: usize = 16;

/// Records up to this size decoded for the Agent's topic after the first one
/// (MQTTConnectRecord is tiny). Big ones: never decoded here.
const SMALL_RECORD: usize = 4096;

/// Max Client Identifier length; longer -> refused.
const MAX_CLIENT_ID: usize = 256;

/// CONNACK an MQTT 3.1.1 / 3.1 client can read: return code 0x01 (protocol level not
/// supported). MQTT 5 CONNACK (0x84) -> misread by such a client (its CONNACK has no
/// properties).
const REFUSED_PROTOCOL_VERSION: [u8; 4] = [0x20, 0x02, 0x00, 0x01];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttBrokerConfig {
    /// Shared first-contact account; `None` -> any client.
    pub login: Option<(String, String)>,
    /// Agents send Records here (their `Controller.{i}.MTP.{i}.MQTT.Topic`) or to
    /// `<topic>/<EndpointID>`.
    pub controller_topic: String,
    /// Agent topic = this + EndpointID (`subscribe-topic`).
    pub agent_topic_prefix: String,
    /// Max open connections; more -> closed at accept. 0 = unlimited.
    pub max_connections: usize,
    /// Max open connections per address (IPv6: /64); more -> closed at accept. 0 = unlimited.
    pub max_connections_per_ip: usize,
    /// Max client Keep Alive (s). Longer -> CONNACK carries this as Server Keep Alive.
    /// No packet for 1.5x it -> close. 0 = no limit.
    pub max_keep_alive: u16,
    /// Max time for a packet to arrive, from its first byte (big PUBLISH: +1 s per 64 KiB),
    /// however many bytes trickle in.
    pub partial_packet_timeout: Duration,
    /// Max time the Agent's Receive Maximum window stays full without PUBACK -> close.
    pub ack_timeout: Duration,
}

impl Default for MqttBrokerConfig {
    fn default() -> Self {
        Self {
            login: None,
            controller_topic: "usp/controller/dhonomos".into(),
            agent_topic_prefix: "usp/agent/".into(),
            max_connections: 20_000,
            max_connections_per_ip: 256,
            max_keep_alive: DEFAULT_MAX_KEEP_ALIVE,
            partial_packet_timeout: DEFAULT_PARTIAL_PACKET_TIMEOUT,
            ack_timeout: DEFAULT_ACK_TIMEOUT,
        }
    }
}

impl MqttBrokerConfig {
    /// Check topics: published to + compared as plain strings -> no wildcards, no empty
    /// Controller topic.
    pub fn validate(&self) -> Result<(), String> {
        let t = &self.controller_topic;
        if t.is_empty() || t.starts_with('/') || t.ends_with('/') || t.contains(['+', '#', '\0']) {
            return Err(format!(
                "invalid Controller topic {t:?} (not empty, no wildcards, no leading or trailing '/')"
            ));
        }
        if self.agent_topic_prefix.contains(['+', '#', '\0']) {
            return Err(format!(
                "invalid Agent topic prefix {:?} (no wildcards)",
                self.agent_topic_prefix
            ));
        }
        Ok(())
    }
}

/// Why a packet could not be read -> DISCONNECT reason for the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketError {
    /// Reason Code of the answering DISCONNECT (or CONNACK).
    pub reason: DisconnectReasonCode,
    /// What is wrong (English).
    pub message: String,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:?})", self.message, self.reason)
    }
}

impl std::error::Error for PacketError {}

fn malformed(message: impl Into<String>) -> PacketError {
    PacketError {
        reason: DisconnectReasonCode::MalformedPacket,
        message: message.into(),
    }
}

/// Read one packet (MQTT 5.0) from the start of `buf` + consume it.
/// `Ok(None)` -> need more bytes.
/// `max_size` bounds the Remaining Length -> big packet refused before it is read.
///
/// Only broker entry point for network bytes -> fuzz target.
/// Parsing = `rumqttc` packet reader. Added here: reserved fixed header flags checked;
/// DISCONNECT with Remaining Length 0 accepted (= normal disconnection, allowed by MQTT 5.0,
/// sent by libmosquitto).
pub fn read_packet(buf: &mut BytesMut, max_size: u32) -> Result<Option<Packet>, PacketError> {
    read_packet_limited(buf, max_size, max_size)
}

/// [`read_packet`] with 2 limits: `max_publish` for PUBLISH, `max_other` for other packets.
/// Both checked from the fixed header, before waiting for the rest.
/// Whole PUBLISH, SUBSCRIBE, UNSUBSCRIBE within them: property section + topic filter count
/// checked on raw bytes, before `rumqttc` decodes into strings
/// -> millions of tiny entries cost nothing.
/// More than [`MAX_PROPERTIES`] bytes of properties or [`MAX_SUBSCRIPTIONS`] topic filters
/// -> refused, Reason Code 0x97 (Quota exceeded).
pub fn read_packet_limited(
    buf: &mut BytesMut,
    max_publish: u32,
    max_other: u32,
) -> Result<Option<Packet>, PacketError> {
    use rumqttc::v5::mqttbytes::Error as Codec;
    let Some(&first) = buf.first() else {
        return Ok(None);
    };
    let flags = first & 0x0F;
    let flags_ok = match first >> 4 {
        3 => true,
        6 | 8 | 10 => flags == 0b0010,
        1 | 2 | 4 | 5 | 7 | 9 | 11..=15 => flags == 0,
        _ => false,
    };
    if !flags_ok {
        return Err(malformed("reserved bits of the fixed header are wrong"));
    }
    if buf.len() >= 2 && first == 0xE0 && buf[1] == 0 {
        buf.advance(2);
        return Ok(Some(Packet::Disconnect(Disconnect::new(
            DisconnectReasonCode::NormalDisconnection,
        ))));
    }
    if let Some((header_len, remaining)) = fixed_header(buf) {
        let max = if first >> 4 == 3 {
            max_publish
        } else {
            max_other
        };
        if remaining > max as usize {
            return Err(too_large(remaining, max));
        }
        if let Some(body) = buf.get(header_len..header_len + remaining) {
            precheck(first, body)?;
        }
    }
    match Packet::read(buf, Some(max_publish)) {
        Ok(p) => Ok(Some(p)),
        Err(Codec::InsufficientBytes(_)) => Ok(None),
        Err(Codec::PayloadSizeLimitExceeded { pkt_size, max }) => Err(too_large(pkt_size, max)),
        // AUTH: CONNACK offered no enhanced authentication.
        Err(Codec::InvalidPacketType(15)) => Err(PacketError {
            reason: DisconnectReasonCode::ProtocolError,
            message: "AUTH is not supported".into(),
        }),
        Err(e) => Err(malformed(e.to_string())),
    }
}

fn too_large(size: usize, max: u32) -> PacketError {
    PacketError {
        reason: DisconnectReasonCode::PacketTooLarge,
        message: format!("packet of {size} bytes exceeds the maximum of {max}"),
    }
}

fn over_limit(message: String) -> PacketError {
    PacketError {
        reason: DisconnectReasonCode::QuotaExceeded,
        message,
    }
}

/// Fixed header at the start of `buf` -> (its length, Remaining Length).
/// `None`: Remaining Length incomplete, or > 4 bytes (packet reader reports that error).
fn fixed_header(buf: &[u8]) -> Option<(usize, usize)> {
    let mut remaining = 0usize;
    for (i, b) in buf.iter().skip(1).take(4).enumerate() {
        remaining |= usize::from(b & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            return Some((i + 2, remaining));
        }
    }
    None
}

/// Variable Byte Integer at `at` in `body` -> (value, end). `None`: cut short or too long.
fn variable_int(body: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut value = 0usize;
    for i in 0..4 {
        let b = *body.get(at + i)?;
        value |= usize::from(b & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            return Some((value, at + i + 1));
        }
    }
    None
}

/// Pre-check of a whole PUBLISH, SUBSCRIBE, UNSUBSCRIBE (`body` = after the fixed header)
/// for what is expensive to decode: big property section, many topic filters.
/// Anything not understood -> left to the packet reader to refuse.
fn precheck(first: u8, body: &[u8]) -> Result<(), PacketError> {
    let properties_at = |at: usize| -> Result<Option<usize>, PacketError> {
        let Some((len, end)) = variable_int(body, at) else {
            return Ok(None);
        };
        if len > MAX_PROPERTIES {
            return Err(over_limit(format!(
                "properties of {len} bytes exceed the maximum of {MAX_PROPERTIES}"
            )));
        }
        Ok(Some(end + len))
    };
    match first >> 4 {
        // PUBLISH: topic name, packet identifier (QoS 1 + 2), properties, payload.
        3 => {
            let Some(topic) = body.get(..2) else {
                return Ok(());
            };
            let mut at = 2 + usize::from(u16::from_be_bytes([topic[0], topic[1]]));
            if first & 0b0110 != 0 {
                at += 2;
            }
            properties_at(at)?;
        }
        // SUBSCRIBE: packet identifier, properties, filters (string + option byte).
        // UNSUBSCRIBE: same, filters without option byte.
        kind @ (8 | 10) => {
            let Some(mut at) = properties_at(2)? else {
                return Ok(());
            };
            let option = usize::from(kind == 8);
            let mut filters = 0usize;
            while let Some(len) = body.get(at..at + 2) {
                filters += 1;
                if filters > MAX_SUBSCRIPTIONS {
                    return Err(over_limit(format!(
                        "more than {MAX_SUBSCRIPTIONS} topic filters in one packet"
                    )));
                }
                at += 2 + usize::from(u16::from_be_bytes([len[0], len[1]])) + option;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Protocol of a first packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Version {
    V5,
    /// CONNECT of another protocol level (3.1.1 = 4, 3.1 = 3): phase 2.
    Other,
    /// Not a CONNECT, or not MQTT.
    NotMqtt,
}

/// Kind of an incoming first packet, from its start, before it is complete.
/// `None`: need more bytes.
fn negotiate(buf: &[u8]) -> Option<Version> {
    let first = *buf.first()?;
    if first != 0x10 {
        return Some(Version::NotMqtt);
    }
    // Remaining Length (1 to 4 bytes), protocol name, level.
    let mut at = 1;
    loop {
        let b = *buf.get(at)?;
        at += 1;
        if b & 0x80 == 0 {
            break;
        }
        if at > 4 {
            return Some(Version::NotMqtt);
        }
    }
    let len = usize::from(u16::from_be_bytes([*buf.get(at)?, *buf.get(at + 1)?]));
    let name = buf.get(at + 2..at + 2 + len)?;
    let level = *buf.get(at + 2 + len)?;
    Some(match (name, level) {
        (b"MQTT", 5) => Version::V5,
        (b"MQTT", _) | (b"MQIsdp", _) => Version::Other,
        _ => Version::NotMqtt,
    })
}

/// Max silence of a connection + Keep Alive to tell the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeepAlive {
    /// Server Keep Alive for CONNACK, when the client's own value is overridden.
    server: Option<u16>,
    /// No packet for this long -> close.
    idle_limit: Duration,
}

/// Keep Alive rules. Client asked none -> [`DEFAULT_KEEP_ALIVE`] told in CONNACK.
/// Asked more than `max` (0 = no limit) -> `max`.
/// No packet for 1.5x the Keep Alive in force -> close (MQTT 5.0, 3.1.2.10).
/// Client must use the Server Keep Alive (3.2.2.3.14) -> limit holds without client consent
/// -> vanished or silent client cannot hold a connection for 18 h (65535 s).
fn keep_alive(client: u16, max: u16) -> KeepAlive {
    let limit = if max == 0 { u16::MAX } else { max };
    let (server, effective) = if client == 0 {
        let default = DEFAULT_KEEP_ALIVE.min(limit);
        (Some(default), default)
    } else if client > limit {
        (Some(limit), limit)
    } else {
        (None, client)
    };
    KeepAlive {
        server,
        idle_limit: Duration::from_millis(u64::from(effective) * 1500),
    }
}

/// Why the identity at CONNECT is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityError {
    /// EndpointID not usable (see [`valid_eid`]).
    Invalid,
    /// Client certificate does not name the claimed EndpointID.
    Certificate,
}

/// EndpointID at CONNECT, if any: client certificate, else `usp-endpoint-id` claim.
/// Certificate with several EndpointIDs + no claim -> open (first Record decides, among those).
/// `cert_ids` = `None` -> no client certificate.
fn eid_at_connect(
    claim: Option<&str>,
    cert_ids: Option<&[String]>,
) -> Result<Option<String>, IdentityError> {
    let claim = claim.map(str::trim).filter(|c| !c.is_empty());
    let eid = match (cert_ids, claim) {
        (Some(ids), Some(c)) if ids.iter().any(|i| i == c) => Some(c),
        (Some(_), Some(_)) => return Err(IdentityError::Certificate),
        (Some([only]), None) => Some(only.as_str()),
        (Some(_), None) | (None, None) => None,
        (None, Some(c)) => Some(c),
    };
    match eid {
        Some(e) if !valid_eid(e) => Err(IdentityError::Invalid),
        other => Ok(other.map(str::to_owned)),
    }
}

/// Agent topic = prefix + EndpointID.
fn agent_topic(prefix: &str, eid: &str) -> String {
    format!("{prefix}{eid}")
}

/// Meaning of a topic an Agent publishes to.
#[derive(Debug, PartialEq, Eq)]
enum TopicCheck<'a> {
    Controller,
    /// `<Controller topic>/<EndpointID>` -> the EndpointID in it.
    ForAgent(&'a str),
    /// Not a topic name (empty, wildcards).
    Invalid,
    /// Topic nothing may be published to.
    NotAllowed,
}

/// Agents may publish to: Controller topic + `<Controller topic>/<EndpointID>` with own
/// EndpointID (`bound` once known; before: any single level).
/// Nothing else: broker carries messages for the Controller only.
fn check_publish_topic<'a>(
    controller_topic: &str,
    topic: &'a str,
    bound: Option<&str>,
) -> TopicCheck<'a> {
    if topic.is_empty() || topic.contains(['+', '#', '\0']) {
        return TopicCheck::Invalid;
    }
    if topic == controller_topic {
        return TopicCheck::Controller;
    }
    match topic
        .strip_prefix(controller_topic)
        .and_then(|rest| rest.strip_prefix('/'))
    {
        Some(eid) if !eid.is_empty() && !eid.contains('/') && bound.is_none_or(|b| b == eid) => {
            TopicCheck::ForAgent(eid)
        }
        _ => TopicCheck::NotAllowed,
    }
}

/// Kind of a SUBSCRIBE topic filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterKind {
    Plain,
    Wildcard,
    Shared,
    Invalid,
}

fn classify_filter(filter: &str) -> FilterKind {
    if filter.is_empty() || filter.contains('\0') {
        FilterKind::Invalid
    } else if filter.starts_with("$share/") {
        FilterKind::Shared
    } else if filter.contains(['+', '#']) {
        FilterKind::Wildcard
    } else {
        FilterKind::Plain
    }
}

/// Topic name usable for replies.
fn valid_reply_topic(topic: &str) -> bool {
    !topic.is_empty() && !topic.contains(['+', '#', '\0'])
}

/// Topic state of a connection. Shared with [`MqttBrokerMtp::send`] -> refuse a Record the
/// Agent cannot receive.
#[derive(Debug, Default)]
struct Topics {
    /// Subscribed topics + granted QoS (0 or 1).
    subscribed: HashMap<String, QoS>,
    /// Reply topic from the Agent: Response Topic of its last Record, or topic in its
    /// MQTTConnectRecord.
    reply: Option<String>,
    /// `subscribe-topic` given in CONNACK.
    assigned: Option<String>,
    /// Agent's Maximum Packet Size.
    max_packet: Option<u32>,
}

impl Topics {
    /// Topic for a Record to the Agent: its announced reply topic, else the given one.
    fn reply_topic(&self) -> Option<&str> {
        self.reply.as_deref().or(self.assigned.as_deref())
    }

    /// Record can go to the Agent: reply topic known (or given) + subscribed to it.
    fn ready(&self) -> bool {
        self.reply_topic()
            .is_some_and(|t| self.subscribed.contains_key(t))
    }

    /// Learn from an inbound Record: Response Topic = reply topic; else the topic its
    /// MQTTConnectRecord says it subscribed to.
    fn learn(&mut self, response_topic: Option<&str>, connect_topic: Option<&str>) {
        if let Some(t) = response_topic.filter(|t| valid_reply_topic(t)) {
            self.reply = Some(t.to_owned());
        } else if let Some(t) = connect_topic.filter(|t| valid_reply_topic(t)) {
            self.reply = Some(t.to_owned());
        }
    }
}

/// Close request with DISCONNECT from outside the connection task: Reason Code + string for
/// the Agent, why the connection ended.
type Requested = (DisconnectReasonCode, &'static str, CloseReason);

#[derive(Debug, Default)]
struct Close {
    why: Mutex<Option<Requested>>,
    notify: Notify,
}

impl Close {
    /// First request counts.
    fn request(&self, code: DisconnectReasonCode, why: &'static str, reason: CloseReason) {
        if let Ok(mut w) = self.why.lock() {
            w.get_or_insert((code, why, reason));
        }
        self.notify.notify_one();
    }

    fn requested(&self) -> Requested {
        self.why.lock().ok().and_then(|mut w| w.take()).unwrap_or((
            DisconnectReasonCode::NormalDisconnection,
            "closed",
            CloseReason::ClosedByServer,
        ))
    }
}

/// Open Agent connection with known EndpointID.
#[derive(Debug)]
struct Conn {
    id: u64,
    /// Connection serial: taken under the connections lock at registration -> grows in
    /// registration order, never reused. (`id`: taken at accept, source of the assigned
    /// Client Identifier.)
    serial: u64,
    tx: mpsc::Sender<Publish>,
    close: Arc<Close>,
    /// SHA-256 of the Agent's TLS client certificate.
    fingerprint: Option<String>,
    /// Agent source address.
    peer: std::net::IpAddr,
    /// Last time the Agent sent anything.
    heard: Arc<Heard>,
    topics: Arc<Mutex<Topics>>,
}

type Conns = Arc<Mutex<HashMap<String, Conn>>>;

/// Embedded MQTT broker; cheap to clone.
#[derive(Debug, Clone)]
pub struct MqttBrokerMtp {
    conns: Conns,
    inbound: mpsc::Sender<Inbound>,
    next: Arc<AtomicU64>,
    /// Connections past CONNECT, with or without EndpointID.
    open: Arc<AtomicUsize>,
    config: Arc<MqttBrokerConfig>,
    /// Last-heard times of Agents of just-closed connections.
    closed: Closed,
    /// Broker start (Unix s) -> assigned Client Identifiers unique across restarts too
    /// (Agent may keep one; obuspa stores it).
    started: u64,
    /// Open connections, total + per source address (from accept, CONNECT or not).
    limiter: Arc<ConnLimiter>,
    /// EndpointIDs that need a client certificate + revoked client certificates.
    policy: CertPolicy,
}

/// Per-connection state of its task.
struct Session {
    id: u64,
    peer: std::net::IpAddr,
    heard: Arc<Heard>,
    /// Client certificate, if any.
    cert: Option<ClientCert>,
    /// EndpointID of this connection, once known.
    eid: Option<String>,
    /// First Record already checked against `eid`.
    first_checked: bool,
    topics: Arc<Mutex<Topics>>,
    close: Arc<Close>,
    tx: mpsc::Sender<Publish>,
    /// "Replaced another connection" signal for the Controller. Delivered once the Agent can
    /// get Records (see [`Topics::ready`]) -> else a Record sent on it would be refused.
    replaced: Option<Inbound>,
}

/// Action after a packet.
enum Next {
    /// Nothing to do.
    Continue,
    /// Write this, go on.
    Write(Bytes),
    /// Send DISCONNECT with this reason + close.
    Close(DisconnectReasonCode, &'static str),
    /// Close silently (client said goodbye).
    End,
}

impl MqttBrokerMtp {
    /// Records from Agents -> `inbound`.
    pub fn new(inbound: mpsc::Sender<Inbound>, config: MqttBrokerConfig) -> Self {
        Self {
            conns: Arc::default(),
            inbound,
            next: Arc::default(),
            open: Arc::default(),
            limiter: ConnLimiter::new(config.max_connections, config.max_connections_per_ip),
            config: Arc::new(config),
            closed: Closed::default(),
            started: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            policy: CertPolicy::default(),
        }
    }

    pub fn config(&self) -> &MqttBrokerConfig {
        &self.config
    }

    /// Replace the revoked client certificate fingerprints (SHA-256, hex) + close connections
    /// made with one (DISCONNECT 0x87). Returns count closed.
    pub fn set_revoked(&self, fingerprints: HashSet<String>) -> usize {
        let Ok(conns) = self.conns.lock() else {
            return 0;
        };
        let mut closed = 0;
        for (eid, c) in conns.iter() {
            if c.fingerprint
                .as_ref()
                .is_some_and(|f| fingerprints.contains(f))
            {
                warn!(agent = %eid, "closing a connection made with a revoked certificate");
                c.close.request(
                    DisconnectReasonCode::NotAuthorized,
                    "the client certificate is revoked",
                    CloseReason::Revoked,
                );
                closed += 1;
            }
        }
        // Still under the connections lock: connection registering meanwhile -> closed here or
        // sees the new set. (Not named yet -> not listed; its naming Record is checked against
        // the new set.)
        self.policy.replace_revoked(fingerprints);
        closed
    }

    /// Replace the EndpointIDs with a client certificate issued. Agent for one of them must
    /// present a certificate naming it (MQTT over TLS, client certificate); shared account +
    /// plain connections refused for it. Open connections stay.
    pub fn set_certificate_bound(&self, eids: HashSet<String>) {
        self.policy.set_bound(eids);
    }

    /// Send a Record to the Agent `endpoint_id`: PUBLISH to its reply topic (Response Topic,
    /// MQTTConnectRecord topic, or CONNACK topic), QoS 1 unless it subscribed for less.
    /// Refused: Agent not connected, not subscribed to that topic, packet too big for it, or
    /// queue of untaken Records full (see `MqttBrokerConfig::ack_timeout`).
    /// Returns once queued, never waits for the Agent -> serial of the connection used
    /// (see [`crate::MultiMtp::send`]).
    pub async fn send(&self, endpoint_id: &str, payload: Vec<u8>) -> Result<u64, MtpError> {
        let (tx, topic, qos, max_packet, serial) = {
            let conns = self
                .conns
                .lock()
                .map_err(|_| MtpError::Unavailable("MQTT connections unavailable".into()))?;
            let conn = conns.get(endpoint_id).ok_or_else(|| {
                MtpError::Unavailable(format!("no MQTT connection for {endpoint_id}"))
            })?;
            let topics = conn
                .topics
                .lock()
                .map_err(|_| MtpError::Unavailable("MQTT connection unavailable".into()))?;
            let topic = topics.reply_topic().ok_or_else(|| {
                MtpError::Unavailable(format!(
                    "{endpoint_id} has not said where replies go (no Response Topic, MQTTConnectRecord or subscribe-topic)"
                ))
            })?;
            let qos = topics.subscribed.get(topic).copied().ok_or_else(|| {
                MtpError::Unavailable(format!("{endpoint_id} has not subscribed to {topic}"))
            })?;
            (
                conn.tx.clone(),
                topic.to_owned(),
                qos,
                topics.max_packet,
                conn.serial,
            )
        };
        let publish = Publish {
            qos,
            topic: Bytes::from(topic.into_bytes()),
            payload: Bytes::from(payload),
            properties: Some(PublishProperties {
                response_topic: Some(self.config.controller_topic.clone()),
                content_type: Some(USP_CONTENT_TYPE.into()),
                ..PublishProperties::default()
            }),
            ..Publish::default()
        };
        if let Some(max) = max_packet {
            // Size includes the packet identifier, counted only once set.
            let mut sized = publish.clone();
            sized.pkid = 1;
            if sized.size() > usize::try_from(max).unwrap_or(usize::MAX) {
                return Err(MtpError::Unavailable(format!(
                    "Record larger than the Maximum Packet Size {max} of {endpoint_id}"
                )));
            }
        }
        // Queue drains as the Agent acks (its Receive Maximum). Agent not acking -> queue full
        // -> fail at once, caller never waits (window full too long -> close, see `ack_timeout`).
        enqueue(&tx, publish, "mqtt", endpoint_id)?;
        metrics::counter!("dhonomos_usp_mqtt_broker_sent_total").increment(1);
        Ok(serial)
    }

    /// Source address of the Agent `endpoint_id`, while connected.
    pub fn peer_addr(&self, endpoint_id: &str) -> Option<std::net::IpAddr> {
        self.conns
            .lock()
            .ok()
            .and_then(|c| c.get(endpoint_id).map(|c| c.peer))
    }

    /// Last heard from Agent `endpoint_id` on its open connection: later of last byte sent
    /// (any packet, PINGREQ too) + on Linux last ack from its TCP stack.
    pub fn last_heard(&self, endpoint_id: &str) -> Option<SystemTime> {
        let heard = self
            .conns
            .lock()
            .ok()
            .and_then(|c| c.get(endpoint_id).map(|c| c.heard.clone()))?;
        Some(heard.get())
    }

    /// Every connected Agent + last heard (see [`MqttBrokerMtp::last_heard`]).
    pub fn heard_from(&self) -> Vec<(String, SystemTime)> {
        let conns: Vec<(String, Arc<Heard>)> = self.conns.lock().map_or_else(
            |_| Vec::new(),
            |c| {
                c.iter()
                    .map(|(e, c)| (e.clone(), c.heard.clone()))
                    .collect()
            },
        );
        conns.into_iter().map(|(e, h)| (e, h.get())).collect()
    }

    /// Last heard from Agent `endpoint_id` on its last closed connection, given once
    /// (see [`crate::MultiMtp::take_final_heard`]).
    pub fn take_final_heard(&self, endpoint_id: &str) -> Option<SystemTime> {
        self.closed.take(endpoint_id)
    }

    /// Close the connection of `endpoint_id` with DISCONNECT 0x87 (Not authorized), if any:
    /// Agent turned away by the acceptance policy.
    pub fn disconnect(&self, endpoint_id: &str) -> bool {
        let Ok(conns) = self.conns.lock() else {
            return false;
        };
        let Some(conn) = conns.get(endpoint_id) else {
            return false;
        };
        conn.close.request(
            DisconnectReasonCode::NotAuthorized,
            "this Agent is not admitted",
            CloseReason::ClosedByServer,
        );
        true
    }

    /// Open Agent connections with known EndpointID.
    pub fn connections(&self) -> usize {
        self.conns.lock().map_or(0, |c| c.len())
    }

    /// Accept Agents on `listener` (TLS with `tls`) until `shutdown` resolves.
    pub async fn serve(
        &self,
        listener: tokio::net::TcpListener,
        tls: Option<tokio_rustls::TlsAcceptor>,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> std::io::Result<()> {
        // Acceptor shared with HTTP listeners offering `http/1.1` -> MQTT client offering its own
        // ALPN protocol would fail the handshake. None wanted here.
        let tls = tls.map(|t| {
            let mut config = (**t.config()).clone();
            config.alpn_protocols.clear();
            tokio_rustls::TlsAcceptor::from(Arc::new(config))
        });
        tokio::pin!(shutdown);
        loop {
            let (stream, remote) = tokio::select! {
                () = &mut shutdown => return Ok(()),
                accepted = listener.accept() => match accepted {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(error = %e, "MQTT accept failed");
                        continue;
                    }
                },
            };
            // Over a cap -> close at once, before any task, TLS handshake or read buffer.
            let permit = match self.limiter.acquire(remote.ip()) {
                Ok(p) => p,
                Err(refused) => {
                    Self::rejected(refused.reason(), remote);
                    continue;
                }
            };
            crate::enable_tcp_keepalive(&stream);
            let sock = sock_of(&stream);
            let (mtp, tls) = (self.clone(), tls.clone());
            tokio::spawn(async move {
                match tls {
                    None => mtp.session(stream, None, remote.ip(), sock, permit).await,
                    Some(tls) => {
                        let stream =
                            match tokio::time::timeout(CONNECT_TIMEOUT, tls.accept(stream)).await {
                                Ok(Ok(s)) => s,
                                Ok(Err(e)) => {
                                    metrics::counter!(
                                        "dhonomos_usp_mqtt_broker_tls_handshake_failures_total"
                                    )
                                    .increment(1);
                                    dhonomos_common::connection_refused!(
                                        "usp_mqtt",
                                        "tls_handshake",
                                        remote,
                                        error = %e
                                    );
                                    return;
                                }
                                Err(_) => {
                                    dhonomos_common::connection_refused!(
                                        "usp_mqtt",
                                        "tls_handshake_timeout",
                                        remote
                                    );
                                    return;
                                }
                            };
                        let cert = ClientCert::of(stream.get_ref().1);
                        mtp.session(stream, cert, remote.ip(), sock, permit).await;
                    }
                }
            });
        }
    }

    /// Count + log a refusal of the connection from `peer`.
    fn rejected(reason: &'static str, peer: impl Into<Remote>) {
        Self::count_rejected(reason);
        dhonomos_common::connection_refused!("usp_mqtt", reason, peer.into());
    }

    fn count_rejected(reason: &'static str) {
        metrics::counter!("dhonomos_usp_mqtt_broker_rejected_total", "reason" => reason)
            .increment(1);
    }

    /// Make `eid` the connection identity: listed, previous connection of the same Agent
    /// closed (Session taken over). Refused: no client certificate but previous one has one,
    /// or certificate revoked. Check + replacement = one step.
    fn register(&self, s: &mut Session, eid: String) -> Result<(), Refusal> {
        let Ok(mut conns) = self.conns.lock() else {
            return Err(Refusal::Outranked);
        };
        let fingerprint = s.cert.as_ref().map(|c| c.fingerprint.clone());
        let live = conns.get(&eid).and_then(|c| c.fingerprint.as_deref());
        self.policy.admit(live, fingerprint.as_deref())?;
        // Under the lock -> serials grow in registration order.
        let serial = self.next.fetch_add(1, Ordering::Relaxed);
        let conn = Conn {
            id: s.id,
            serial,
            tx: s.tx.clone(),
            close: s.close.clone(),
            fingerprint,
            peer: s.peer,
            heard: s.heard.clone(),
            topics: s.topics.clone(),
        };
        if let Some(old) = conns.insert(eid.clone(), conn) {
            // Reconnecting Agent replaces its previous connection.
            old.close.request(
                DisconnectReasonCode::SessionTakenOver,
                "another connection of this Agent took over",
                CloseReason::Replaced,
            );
            s.replaced = Some(Inbound::replaced(
                "mqtt",
                format!("{MQTT_BROKER_PREFIX}{eid}"),
                &eid,
                serial,
            ));
        }
        s.eid = Some(eid);
        Ok(())
    }

    /// Tell the Controller the connection replaced another, once the Agent can get Records.
    /// Call after packets that can make it so.
    async fn announce_replaced(&self, s: &mut Session) {
        if s.replaced.is_none() || !s.topics.lock().is_ok_and(|t| t.ready()) {
            return;
        }
        if let Some(signal) = s.replaced.take() {
            let _ = self.inbound.send(signal).await;
        }
    }

    /// Connection for `eid` with client certificate `fingerprint` (if any) refused by
    /// [`MqttBrokerMtp::register`] now? -> lets the CONNACK refuse the CONNECT.
    fn would_conflict(&self, eid: &str, fingerprint: Option<&str>) -> bool {
        self.conns.lock().is_ok_and(|conns| {
            let live = conns.get(eid).and_then(|c| c.fingerprint.as_deref());
            self.policy.admit(live, fingerprint).is_err()
        })
    }

    async fn unregister(&self, eid: &str, id: u64) {
        let current = self.conns.lock().ok().and_then(|mut conns| {
            let current = conns.get(eid).is_some_and(|c| c.id == id);
            if current { conns.remove(eid) } else { None }
        });
        if let Some(conn) = current {
            // Controller hears of the close below, after the connection is gone.
            // Socket still open here -> its TCP state counts too.
            self.closed.record(eid, conn.heard.get());
            let _ = self
                .inbound
                .send(Inbound {
                    topic: "mqtt".into(),
                    reply_to: Some(format!("{MQTT_BROKER_PREFIX}{eid}")),
                    payload: Bytes::new(),
                    closed: true,
                    opened: false,
                    sender: Some(eid.to_owned()),
                    replaced_by: None,
                })
                .await;
        }
    }

    /// Check a CONNECT -> CONNACK answer + starting EndpointID. `Err` = refusal CONNACK.
    fn accept(
        &self,
        connect: &Connect,
        login: Option<&Login>,
        cert: Option<&ClientCert>,
        id: u64,
        peer: std::net::IpAddr,
    ) -> Result<(Option<String>, ConnAck, KeepAlive), Box<ConnAck>> {
        let props = connect.properties.as_ref();
        if props.is_some_and(|p| p.authentication_method.is_some()) {
            Self::rejected("auth_method", peer);
            return Err(Box::new(refusal(
                ConnectReturnCode::BadAuthenticationMethod,
                "enhanced authentication is not supported",
            )));
        }
        if props.is_some_and(|p| p.receive_maximum == Some(0) || p.max_packet_size == Some(0)) {
            Self::rejected("protocol", peer);
            return Err(Box::new(refusal(
                ConnectReturnCode::ProtocolError,
                "Receive Maximum and Maximum Packet Size must not be 0",
            )));
        }
        if connect.client_id.len() > MAX_CLIENT_ID {
            Self::rejected("client_id", peer);
            return Err(Box::new(refusal(
                ConnectReturnCode::ClientIdentifierNotValid,
                "Client Identifier too long",
            )));
        }
        if let Some((user, pass)) = &self.config.login {
            let (u, p) = login.map_or(("", ""), |l| (l.username.as_str(), l.password.as_str()));
            if !(same(u, user) & same(p, pass)) {
                Self::count_rejected("credentials");
                dhonomos_common::connection_refused!(
                    "usp_mqtt",
                    "credentials",
                    peer,
                    username = ?dhonomos_common::refusal::clip(u)
                );
                return Err(Box::new(refusal(
                    ConnectReturnCode::BadUserNamePassword,
                    "invalid user name or password",
                )));
            }
        }
        let claim = props.and_then(|p| {
            p.user_properties
                .iter()
                .find(|(k, _)| k == EID_PROPERTY)
                .map(|(_, v)| v.as_str())
        });
        let eid = match eid_at_connect(claim, cert.map(|c| c.ids.as_slice())) {
            Ok(eid) => eid,
            Err(IdentityError::Certificate) => {
                Self::count_rejected("certificate");
                let agent = claim.map(dhonomos_common::refusal::clip);
                dhonomos_common::connection_refused!(
                    "usp_mqtt",
                    "certificate",
                    peer,
                    agent = agent.as_deref(),
                    certificate = ?cert.map(|c| &c.ids)
                );
                return Err(Box::new(refusal(
                    ConnectReturnCode::NotAuthorized,
                    "the client certificate is not issued to this EndpointID",
                )));
            }
            Err(IdentityError::Invalid) => {
                Self::rejected("endpoint_id", peer);
                return Err(Box::new(refusal(
                    ConnectReturnCode::NotAuthorized,
                    "invalid EndpointID",
                )));
            }
        };
        // Revoked certificate, or none for an EndpointID with one issued -> weaker way in shut.
        // Same for taking over, without certificate, the EndpointID of a connection with one.
        let refusal = self.policy.check(eid.as_deref(), cert).err().or_else(|| {
            eid.as_deref()
                .filter(|e| self.would_conflict(e, cert.map(|c| c.fingerprint.as_str())))
                .map(|_| Refusal::Outranked)
        });
        if let Some(refusal) = refusal {
            Self::count_rejected(refusal.reason());
            dhonomos_common::connection_refused!(
                "usp_mqtt",
                refusal.reason(),
                peer,
                agent = eid.as_deref()
            );
            return Err(Box::new(refusal_ack(refusal)));
        }
        let ka = keep_alive(connect.keep_alive, self.config.max_keep_alive);
        let assigned_id = connect
            .client_id
            .is_empty()
            .then(|| format!("dhonomos-{:x}-{id}", self.started));
        let topic = eid
            .as_deref()
            .map(|e| agent_topic(&self.config.agent_topic_prefix, e));
        let want_info = props.is_some_and(|p| p.request_response_info == Some(1));
        let ack = connack(&assigned_id, ka.server, topic.as_deref(), want_info);
        Ok((eid, ack, ka))
    }

    /// Serve one Agent connection.
    ///
    /// `sock` = TCP socket under `stream` (maybe TLS over it): kernel view via [`Heard`],
    /// must not outlive `stream`. `_permit` = connection slot under the caps, freed at end.
    async fn session<S>(
        &self,
        stream: S,
        cert: Option<ClientCert>,
        peer: std::net::IpAddr,
        sock: Sock,
        _permit: ConnPermit,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let heard = Heard::new();
        // Dropped (reverse declaration order) before `rd` + `wr` close the socket.
        let _tcp = heard.watch_tcp(sock);
        let mut buf = BytesMut::with_capacity(4096);
        let hello = tokio::time::timeout(CONNECT_TIMEOUT, read_connect(&mut rd, &mut buf)).await;
        let (connect, will, login) = match hello {
            Ok(Ok(Hello::V5(c))) => *c,
            Ok(Ok(Hello::Refused(bytes, reason))) => {
                Self::rejected(reason, peer);
                let _ = write_all(&mut wr, &bytes).await;
                finish(&mut rd, &mut wr, true).await;
                return;
            }
            _ => {
                Self::rejected("connect", peer);
                return;
            }
        };
        debug!(
            client_id = %printable(&connect.client_id),
            keep_alive = connect.keep_alive,
            clean_start = connect.clean_start,
            username = login.as_ref().map(|l| printable(&l.username)),
            will = will.is_some(),
            properties = ?connect.properties,
            certificate = ?cert.as_ref().map(|c| &c.ids),
            %peer,
            "MQTT CONNECT"
        );
        let (eid, ack, ka) = match self.accept(&connect, login.as_ref(), cert.as_ref(), id, peer) {
            Ok(v) => v,
            Err(ack) => {
                let _ = write_all(&mut wr, &encode(&Packet::ConnAck(*ack))).await;
                finish(&mut rd, &mut wr, true).await;
                return;
            }
        };
        let topics = Arc::new(Mutex::new(Topics {
            assigned: ack
                .properties
                .as_ref()
                .and_then(|p| p.user_properties.first())
                .map(|(_, t)| t.clone()),
            max_packet: connect.properties.as_ref().and_then(|p| p.max_packet_size),
            ..Topics::default()
        }));
        let receive_max = usize::from(
            connect
                .properties
                .as_ref()
                .and_then(|p| p.receive_maximum)
                .unwrap_or(u16::MAX),
        );
        if write_all(&mut wr, &encode(&Packet::ConnAck(ack)))
            .await
            .is_err()
        {
            return;
        }
        let (tx, mut rx) = mpsc::channel::<Publish>(SEND_QUEUE);
        let close = Arc::new(Close::default());
        let mut s = Session {
            id,
            peer: peer.to_canonical(),
            heard: heard.clone(),
            cert,
            eid: None,
            first_checked: false,
            topics,
            close: close.clone(),
            tx,
            replaced: None,
        };
        if let Some(eid) = eid
            && let Err(refusal) = self.register(&mut s, eid)
        {
            // Lost a race with the `accept` checks: certificate revoked, or connection with one
            // registered, since. Loop below sends the DISCONNECT.
            Self::rejected(refusal.reason(), peer);
            close.request(
                DisconnectReasonCode::NotAuthorized,
                refusal.message(),
                CloseReason::ClosedByServer,
            );
        }
        let open = self.open.fetch_add(1, Ordering::Relaxed) + 1;
        metrics::gauge!("dhonomos_usp_mqtt_broker_connections").set(open as f64);
        match &s.eid {
            Some(eid) => {
                info!(agent = %eid, remote = %peer, client_id = %printable(&connect.client_id), "USP MQTT connected")
            }
            None => {
                debug!(client_id = %printable(&connect.client_id), "USP MQTT connected; the Agent is not named yet")
            }
        }

        let connected = std::time::Instant::now();
        let mut inflight: HashSet<u16> = HashSet::new();
        let mut next_pkid: u16 = 0;
        // Last whole packet. Bytes of an incomplete packet != alive -> else a client holds the
        // connection by trickling one.
        let mut last_rx = tokio::time::Instant::now();
        // Start of arrival of the current packet.
        let mut partial_since: Option<tokio::time::Instant> = None;
        // Agent's Receive Maximum window full since.
        let mut full_since: Option<tokio::time::Instant> = None;
        let mut goodbye: Option<(DisconnectReasonCode, String)> = None;
        let cause: Cause = 'conn: loop {
            // Buffered packets first.
            let mut received = false;
            loop {
                match read_packet_limited(&mut buf, MAX_PACKET, MAX_CONTROL_PACKET) {
                    Ok(None) => break,
                    Ok(Some(packet)) => {
                        received = true;
                        last_rx = tokio::time::Instant::now();
                        let next = self.handle(&mut s, packet, &mut inflight).await;
                        self.announce_replaced(&mut s).await;
                        match next {
                            Next::Continue => {}
                            Next::Write(bytes) => {
                                if let Err(e) = write_all(&mut wr, &bytes).await {
                                    break 'conn Cause::write(&e);
                                }
                            }
                            Next::Close(reason, why) => {
                                goodbye = Some((reason, why.to_owned()));
                                break 'conn Cause::because(close_reason(reason), why);
                            }
                            Next::End => break 'conn CloseReason::AgentClosed.into(),
                        }
                    }
                    Err(e) => {
                        Self::rejected(
                            match e.reason {
                                DisconnectReasonCode::PacketTooLarge
                                | DisconnectReasonCode::QuotaExceeded => "limits",
                                _ => "malformed",
                            },
                            peer,
                        );
                        let cause = Cause::because(CloseReason::BadFrame, &e.message);
                        goodbye = Some((e.reason, e.message));
                        break 'conn cause;
                    }
                }
            }
            let now = tokio::time::Instant::now();
            // Incomplete packet must complete in time; each one timed from its own first byte.
            if received || buf.is_empty() {
                partial_since = None;
            }
            if !buf.is_empty() {
                partial_since.get_or_insert(now);
            }
            full_since = if inflight.len() >= receive_max {
                full_since.or(Some(now))
            } else {
                None
            };
            // Disabled `select!` branches still evaluate their deadlines.
            let never = now + Duration::from_secs(24 * 60 * 60);
            let partial_deadline = partial_since.map_or(never, |t| {
                t + partial_budget(self.config.partial_packet_timeout, &buf)
            });
            let ack_deadline = full_since.map_or(never, |t| t + self.config.ack_timeout);
            tokio::select! {
                () = close.notify.notified() => {
                    let (code, why, reason) = close.requested();
                    goodbye = Some((code, why.to_owned()));
                    break reason.into();
                }
                read = rd.read_buf(&mut buf) => match read {
                    Ok(0) => break CloseReason::Eof.into(),
                    Err(e) => break Cause::read(&e),
                    Ok(_) => heard.touch(),
                },
                out = rx.recv(), if inflight.len() < receive_max => {
                    let Some(mut publish) = out else { break CloseReason::QueueClosed.into() };
                    if publish.qos == QoS::AtLeastOnce {
                        let Some(pkid) = free_packet_id(&mut next_pkid, &inflight) else {
                            warn!(agent = ?s.eid, "no free packet identifier; Record dropped");
                            continue;
                        };
                        publish.pkid = pkid;
                        inflight.insert(pkid);
                    }
                    if let Err(e) = write_all(&mut wr, &encode(&Packet::Publish(publish))).await {
                        break Cause::write(&e);
                    }
                }
                // Keep Alive clock only for an idle connection.
                // Mid-packet -> deadline of that packet.
                () = tokio::time::sleep_until(last_rx + ka.idle_limit), if buf.is_empty() => {
                    debug!(agent = ?s.eid, "nothing from the Agent for 1.5 times its Keep Alive; closing");
                    Self::rejected("keep_alive", peer);
                    goodbye = Some((
                        DisconnectReasonCode::KeepAliveTimeout,
                        "no packet within 1.5 times the Keep Alive".into(),
                    ));
                    break CloseReason::IdleTimeout.into();
                }
                () = tokio::time::sleep_until(partial_deadline), if partial_since.is_some() => {
                    debug!(agent = ?s.eid, "a packet did not arrive in time; closing");
                    Self::rejected("partial_packet", peer);
                    goodbye = Some((
                        DisconnectReasonCode::UnspecifiedError,
                        "a packet did not arrive in time".into(),
                    ));
                    break CloseReason::ReadTimeout.into();
                }
                () = tokio::time::sleep_until(ack_deadline), if full_since.is_some() => {
                    debug!(agent = ?s.eid, "no PUBACK for a full Receive Maximum window; closing");
                    Self::rejected("ack_timeout", peer);
                    goodbye = Some((
                        DisconnectReasonCode::UnspecifiedError,
                        "no PUBACK for the Records sent, Receive Maximum is full".into(),
                    ));
                    break CloseReason::AckTimeout.into();
                }
            }
        };
        // Controller hears of the close at once; DISCONNECT + drain below may take a moment.
        if let Some(eid) = &s.eid {
            self.unregister(eid, s.id).await;
        }
        let open = self.open.fetch_sub(1, Ordering::Relaxed).saturating_sub(1);
        metrics::gauge!("dhonomos_usp_mqtt_broker_connections").set(open as f64);
        let lingering = goodbye.is_some();
        if let Some((reason, why)) = goodbye {
            debug!(agent = ?s.eid, ?reason, why, "closing the MQTT connection");
            let packet = Packet::Disconnect(Disconnect {
                reason_code: reason,
                properties: Some(DisconnectProperties {
                    session_expiry_interval: None,
                    reason_string: Some(why),
                    user_properties: Vec::new(),
                    server_reference: None,
                }),
            });
            let _ = write_all(&mut wr, &encode(&packet)).await;
        }
        finish(&mut rd, &mut wr, lingering).await;
        cause.count("mqtt");
        info!(
            agent = ?s.eid,
            reason = %cause.reason,
            error = cause.error.as_deref(),
            connected_secs = connected.elapsed().as_secs(),
            "USP MQTT closed"
        );
    }

    /// Act on one packet after the connection is set up.
    async fn handle(&self, s: &mut Session, packet: Packet, inflight: &mut HashSet<u16>) -> Next {
        match packet {
            Packet::PingReq(_) => Next::Write(encode(&Packet::PingResp(PingResp))),
            Packet::Disconnect(d) => {
                debug!(agent = ?s.eid, reason = ?d.reason_code, "the Agent disconnected");
                Next::End
            }
            Packet::Publish(p) => self.on_publish(s, p).await,
            Packet::PubAck(a) => {
                if !inflight.remove(&a.pkid) {
                    debug!(agent = ?s.eid, pkid = a.pkid, "PUBACK for a packet identifier not in use");
                } else if a.reason != PubAckReason::Success
                    && a.reason != PubAckReason::NoMatchingSubscribers
                {
                    warn!(agent = ?s.eid, reason = ?a.reason, "the Agent refused a Record");
                }
                Next::Continue
            }
            Packet::Subscribe(sub) => self.on_subscribe(s, sub),
            Packet::Unsubscribe(unsub) => on_unsubscribe(s, &unsub),
            Packet::Connect(..) => {
                Self::rejected("protocol", s.peer);
                Next::Close(
                    DisconnectReasonCode::ProtocolError,
                    "a second CONNECT on a connection",
                )
            }
            // QoS 2 handshakes: nothing here starts one.
            Packet::PubRec(_) | Packet::PubRel(_) | Packet::PubComp(_) => {
                Self::rejected("qos2", s.peer);
                Next::Close(
                    DisconnectReasonCode::ProtocolError,
                    "QoS 2 is not supported (maximum QoS is 1)",
                )
            }
            // Server-to-client packets + AUTH (refused when read).
            Packet::ConnAck(_)
            | Packet::SubAck(_)
            | Packet::UnsubAck(_)
            | Packet::PingResp(_)
            | Packet::Auth(_) => {
                Self::rejected("protocol", s.peer);
                Next::Close(
                    DisconnectReasonCode::ProtocolError,
                    "a packet only the server sends",
                )
            }
        }
    }

    /// PUBLISH from the Agent = Record for the Controller.
    async fn on_publish(&self, s: &mut Session, p: Publish) -> Next {
        let qos1 = p.qos == QoS::AtLeastOnce;
        let refuse = |code: PubAckReason, close: DisconnectReasonCode, why: &'static str| {
            if qos1 {
                Next::Write(encode(&Packet::PubAck(PubAck {
                    pkid: p.pkid,
                    reason: code,
                    properties: None,
                })))
            } else {
                Next::Close(close, why)
            }
        };
        if p.retain {
            Self::rejected("retain", s.peer);
            return Next::Close(
                DisconnectReasonCode::RetainNotSupported,
                "retained messages are not supported",
            );
        }
        if p.qos == QoS::ExactlyOnce {
            Self::rejected("qos2", s.peer);
            return Next::Close(
                DisconnectReasonCode::QoSNotSupported,
                "QoS 2 is not supported (maximum QoS is 1)",
            );
        }
        let props = p.properties.as_ref();
        if props.is_some_and(|x| x.topic_alias.is_some()) {
            Self::rejected("topic_alias", s.peer);
            return Next::Close(
                DisconnectReasonCode::TopicAliasInvalid,
                "topic aliases are not supported (Topic Alias Maximum is 0)",
            );
        }
        if props.is_some_and(|x| !x.subscription_identifiers.is_empty()) {
            Self::rejected("protocol", s.peer);
            return Next::Close(
                DisconnectReasonCode::ProtocolError,
                "a client must not send a Subscription Identifier",
            );
        }
        let Ok(topic) = std::str::from_utf8(&p.topic) else {
            Self::rejected("malformed", s.peer);
            return Next::Close(DisconnectReasonCode::MalformedPacket, "topic is not UTF-8");
        };
        let topic_eid = match check_publish_topic(
            &self.config.controller_topic,
            topic,
            s.eid.as_deref(),
        ) {
            TopicCheck::Controller => None,
            TopicCheck::ForAgent(eid) => Some(eid),
            TopicCheck::Invalid => {
                Self::rejected("topic", s.peer);
                return refuse(
                    PubAckReason::TopicNameInvalid,
                    DisconnectReasonCode::TopicNameInvalid,
                    "invalid topic name",
                );
            }
            TopicCheck::NotAllowed => {
                Self::rejected("topic", s.peer);
                debug!(agent = ?s.eid, topic, "PUBLISH to a topic other than the Controller's refused");
                return refuse(
                    PubAckReason::NotAuthorized,
                    DisconnectReasonCode::NotAuthorized,
                    "only the Controller topic may be published to",
                );
            }
        };
        match props.and_then(|x| x.content_type.as_deref()) {
            Some(USP_CONTENT_TYPE) => {}
            other => {
                debug!(agent = ?s.eid, content_type = ?other, "PUBLISH without Content Type usp.msg")
            }
        }
        let response_topic = props.and_then(|x| x.response_topic.as_deref());

        // First Record names the Agent or confirms the connection's EndpointID.
        // Later ones: looked at only until the Agent says where replies go.
        let reply_unknown = s.topics.lock().is_ok_and(|t| t.reply_topic().is_none());
        let look = !s.first_checked
            || (response_topic.is_none() && reply_unknown && p.payload.len() <= SMALL_RECORD);
        let mut connect_topic = None;
        if look {
            match record_info(&p.payload) {
                Some(info) => {
                    match &s.eid {
                        None => {
                            if let Some(why) = self.bind(s, &info.from_id, topic_eid) {
                                return Next::Close(DisconnectReasonCode::NotAuthorized, why);
                            }
                            s.first_checked = true;
                            connect_topic = info.connect_topic;
                        }
                        Some(eid) if *eid == info.from_id => {
                            s.first_checked = true;
                            connect_topic = info.connect_topic;
                        }
                        Some(eid) if !s.first_checked => {
                            warn!(agent = %eid, from = %info.from_id, "first Record does not come from the EndpointID of the connection");
                            Self::rejected("endpoint_id", s.peer);
                            return Next::Close(
                                DisconnectReasonCode::NotAuthorized,
                                "the Record's from_id is not the EndpointID of this connection",
                            );
                        }
                        // Later Record of someone else -> Controller drops it.
                        // Its topic info not trusted.
                        Some(_) => {}
                    }
                }
                None if s.eid.is_none() => {
                    Self::rejected("record", s.peer);
                    return Next::Close(
                        DisconnectReasonCode::PayloadFormatInvalid,
                        "the first Record could not be read, so the Agent cannot be identified",
                    );
                }
                None => {}
            }
        }
        let Some(eid) = s.eid.clone() else {
            return Next::Close(DisconnectReasonCode::ProtocolError, "no EndpointID");
        };
        if let Ok(mut t) = s.topics.lock() {
            t.learn(response_topic, connect_topic.as_deref());
        }
        metrics::counter!("dhonomos_usp_mqtt_broker_received_total").increment(1);
        let inbound = Inbound {
            topic: topic.to_owned(),
            reply_to: Some(format!("{MQTT_BROKER_PREFIX}{eid}")),
            payload: p.payload.clone(),
            closed: false,
            opened: false,
            sender: Some(eid),
            replaced_by: None,
        };
        if self.inbound.send(inbound).await.is_err() {
            return Next::Close(DisconnectReasonCode::ServerShuttingDown, "shutting down");
        }
        if qos1 {
            Next::Write(encode(&Packet::PubAck(PubAck::new(p.pkid, None))))
        } else {
            Next::Continue
        }
    }

    /// First Record of a connection without EndpointID names it.
    /// Returns why not, if the connection cannot have it.
    fn bind(
        &self,
        s: &mut Session,
        from_id: &str,
        topic_eid: Option<&str>,
    ) -> Option<&'static str> {
        if !valid_eid(from_id) {
            Self::rejected("endpoint_id", s.peer);
            return Some("the Record's from_id is not a usable EndpointID");
        }
        if let Some(c) = &s.cert
            && !c.ids.iter().any(|i| i == from_id)
        {
            Self::count_rejected("certificate");
            dhonomos_common::connection_refused!(
                "usp_mqtt",
                "certificate",
                s.peer,
                agent = %from_id,
                certificate = ?c.ids
            );
            return Some("the client certificate is not issued to this EndpointID");
        }
        if topic_eid.is_some_and(|t| t != from_id) {
            Self::rejected("topic", s.peer);
            return Some("the topic names another EndpointID than the Record's from_id");
        }
        // Same rules as at CONNECT, for a connection named only now.
        if let Err(refusal) = self.policy.check(Some(from_id), s.cert.as_ref()) {
            Self::count_rejected(refusal.reason());
            dhonomos_common::connection_refused!(
                "usp_mqtt",
                refusal.reason(),
                s.peer,
                agent = %from_id
            );
            return Some(refusal.message());
        }
        // Topic the CONNACK could not name (no EndpointID then).
        if let Err(refusal) = self.register(s, from_id.to_owned()) {
            Self::count_rejected(refusal.reason());
            dhonomos_common::connection_refused!(
                "usp_mqtt",
                refusal.reason(),
                s.peer,
                agent = %from_id
            );
            return Some(refusal.message());
        }
        info!(agent = %from_id, "USP MQTT Agent identified by its first Record");
        None
    }

    /// SUBSCRIBE: plain topics kept, wildcards + shared subscriptions refused.
    fn on_subscribe(&self, s: &mut Session, sub: Subscribe) -> Next {
        if sub.pkid == 0 {
            Self::rejected("protocol", s.peer);
            return Next::Close(DisconnectReasonCode::ProtocolError, "packet identifier 0");
        }
        let ids_unsupported = sub.properties.as_ref().is_some_and(|p| p.id.is_some());
        let mut codes = Vec::with_capacity(sub.filters.len());
        if let Ok(mut topics) = s.topics.lock() {
            for f in &sub.filters {
                let code = if ids_unsupported {
                    SubscribeReasonCode::SubscriptionIdNotSupported
                } else {
                    match classify_filter(&f.path) {
                        FilterKind::Invalid => SubscribeReasonCode::TopicFilterInvalid,
                        FilterKind::Shared => SubscribeReasonCode::SharedSubscriptionsNotSupported,
                        FilterKind::Wildcard => {
                            SubscribeReasonCode::WildcardSubscriptionsNotSupported
                        }
                        FilterKind::Plain => {
                            let granted = if f.qos == QoS::AtMostOnce {
                                QoS::AtMostOnce
                            } else {
                                QoS::AtLeastOnce
                            };
                            if topics.subscribed.len() >= MAX_SUBSCRIPTIONS
                                && !topics.subscribed.contains_key(&f.path)
                            {
                                SubscribeReasonCode::QuotaExceeded
                            } else {
                                topics.subscribed.insert(f.path.clone(), granted);
                                SubscribeReasonCode::Success(granted)
                            }
                        }
                    }
                };
                if !matches!(code, SubscribeReasonCode::Success(_)) {
                    Self::rejected("subscription", s.peer);
                }
                codes.push(code);
            }
        }
        debug!(agent = ?s.eid, filters = ?sub.filters.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(), ?codes, "SUBSCRIBE");
        Next::Write(encode(&Packet::SubAck(SubAck {
            pkid: sub.pkid,
            return_codes: codes,
            properties: None,
        })))
    }
}

/// UNSUBSCRIBE: subscriptions dropped.
fn on_unsubscribe(s: &mut Session, unsub: &Unsubscribe) -> Next {
    if unsub.pkid == 0 || unsub.filters.is_empty() {
        return Next::Close(
            DisconnectReasonCode::ProtocolError,
            "UNSUBSCRIBE without a packet identifier or topic filter",
        );
    }
    let mut reasons = Vec::with_capacity(unsub.filters.len());
    if let Ok(mut topics) = s.topics.lock() {
        for f in &unsub.filters {
            reasons.push(if topics.subscribed.remove(f).is_some() {
                UnsubAckReason::Success
            } else {
                UnsubAckReason::NoSubscriptionExisted
            });
        }
    }
    Next::Write(encode(&Packet::UnsubAck(UnsubAck {
        pkid: unsub.pkid,
        reasons,
        properties: None,
    })))
}

/// Record sender + for a MQTTConnectRecord the topic its sender subscribed to.
#[derive(Debug, PartialEq, Eq)]
struct RecordInfo {
    from_id: String,
    connect_topic: Option<String>,
}

/// Sender of a Record. `None`: not a Record, or no sender.
fn record_info(payload: &[u8]) -> Option<RecordInfo> {
    use dhonomos_usp_proto::record::{Record, record::RecordType};
    let record = Record::decode(payload).ok()?;
    if record.from_id.is_empty() {
        return None;
    }
    let connect_topic = match record.record_type {
        Some(RecordType::MqttConnect(c)) if !c.subscribed_topic.is_empty() => {
            Some(c.subscribed_topic)
        }
        _ => None,
    };
    Some(RecordInfo {
        from_id: record.from_id,
        connect_topic,
    })
}

/// Next unused packet identifier after `*next`; `None` if all in use.
fn free_packet_id(next: &mut u16, inflight: &HashSet<u16>) -> Option<u16> {
    for _ in 0..=u16::MAX {
        *next = next.checked_add(1).unwrap_or(1);
        if !inflight.contains(next) {
            return Some(*next);
        }
    }
    None
}

/// CONNACK properties, all unset.
fn no_properties() -> ConnAckProperties {
    ConnAckProperties {
        session_expiry_interval: None,
        receive_max: None,
        max_qos: None,
        retain_available: None,
        max_packet_size: None,
        assigned_client_identifier: None,
        topic_alias_max: None,
        reason_string: None,
        user_properties: Vec::new(),
        wildcard_subscription_available: None,
        subscription_identifiers_available: None,
        shared_subscription_available: None,
        server_keep_alive: None,
        response_information: None,
        server_reference: None,
        authentication_method: None,
        authentication_data: None,
    }
}

/// Refusal CONNACK.
fn refusal(code: ConnectReturnCode, why: &str) -> ConnAck {
    ConnAck {
        session_present: false,
        code,
        properties: Some(ConnAckProperties {
            reason_string: Some(why.to_owned()),
            ..no_properties()
        }),
    }
}

/// Refusal CONNACK for what the certificate (or no certificate) says.
fn refusal_ack(why: Refusal) -> ConnAck {
    refusal(ConnectReturnCode::NotAuthorized, why.message())
}

/// CONNACK of an accepted client: broker features, assigned Client Identifier (client had
/// none), required Keep Alive (client's own overridden), Agent topic if EndpointID known:
/// `subscribe-topic` + Response Information if asked.
fn connack(
    assigned_id: &Option<String>,
    server_keep_alive: Option<u16>,
    agent_topic: Option<&str>,
    want_response_info: bool,
) -> ConnAck {
    ConnAck {
        // No session kept.
        session_present: false,
        code: ConnectReturnCode::Success,
        properties: Some(ConnAckProperties {
            session_expiry_interval: Some(0),
            max_qos: Some(1),
            retain_available: Some(0),
            max_packet_size: Some(MAX_PACKET),
            topic_alias_max: Some(0),
            wildcard_subscription_available: Some(0),
            subscription_identifiers_available: Some(0),
            shared_subscription_available: Some(0),
            assigned_client_identifier: assigned_id.clone(),
            server_keep_alive,
            user_properties: agent_topic
                .map(|t| vec![(SUBSCRIBE_TOPIC_PROPERTY.to_owned(), t.to_owned())])
                .unwrap_or_default(),
            response_information: agent_topic
                .filter(|_| want_response_info)
                .map(str::to_owned),
            ..no_properties()
        }),
    }
}

/// CONNECT + its Will + credentials.
type ConnectPacket = (
    Connect,
    Option<rumqttc::v5::mqttbytes::v5::LastWill>,
    Option<Login>,
);

/// Kind of the first packet of a connection.
enum Hello {
    /// MQTT 5.0 CONNECT.
    V5(Box<ConnectPacket>),
    /// Answer with these bytes, then close (counted as rejected for this reason).
    Refused(Bytes, &'static str),
}

/// Read the CONNECT. Protocol level != 5 -> answered in that version's CONNACK format;
/// phase 2 (MQTT 3.1.1) takes over there.
async fn read_connect<R: AsyncRead + Unpin>(
    rd: &mut R,
    buf: &mut BytesMut,
) -> std::io::Result<Hello> {
    loop {
        match negotiate(buf) {
            Some(Version::V5) => match read_packet(buf, MAX_CONNECT_PACKET) {
                Ok(Some(Packet::Connect(c, w, l))) => return Ok(Hello::V5(Box::new((c, w, l)))),
                Ok(Some(_)) => return Ok(Hello::Refused(Bytes::new(), "malformed")),
                Err(e) => {
                    let code = if e.reason == DisconnectReasonCode::PacketTooLarge {
                        ConnectReturnCode::PacketTooLarge
                    } else {
                        ConnectReturnCode::MalformedPacket
                    };
                    return Ok(Hello::Refused(
                        encode(&Packet::ConnAck(refusal(code, &e.message))),
                        "malformed",
                    ));
                }
                Ok(None) => {}
            },
            Some(Version::Other) => {
                return Ok(Hello::Refused(
                    Bytes::from_static(&REFUSED_PROTOCOL_VERSION),
                    "protocol_version",
                ));
            }
            Some(Version::NotMqtt) => {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            None => {}
        }
        if rd.read_buf(buf).await? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
    }
}

/// Time for the packet at the start of `buf` to arrive, from its first byte: `base` + 1 s
/// per 64 KiB announced (big Record on a slow link -> as long as needed, but not forever,
/// not as long as a trickling client likes).
fn partial_budget(base: Duration, buf: &[u8]) -> Duration {
    let declared = fixed_header(buf).map_or(0, |(_, remaining)| remaining);
    base + Duration::from_secs((declared / (64 * 1024)) as u64)
}

/// Wire form of a packet.
fn encode(packet: &Packet) -> Bytes {
    let mut out = BytesMut::with_capacity(packet.size());
    if let Err(e) = packet.write(&mut out, None) {
        warn!(error = %e, "MQTT packet could not be encoded");
        return Bytes::new();
    }
    out.freeze()
}

/// Write + flush; give up after [`WRITE_TIMEOUT`] without the peer taking anything
/// (big Record on a slow link takes as long as it takes).
async fn write_all<W: AsyncWrite + Unpin>(wr: &mut W, bytes: &[u8]) -> std::io::Result<()> {
    crate::write_all_within("mqtt", wr, bytes, WRITE_TIMEOUT).await
}

/// Close the write side. After a send: read what the client still sends for a moment
/// -> close does not reset the connection under it.
async fn finish<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(rd: &mut R, wr: &mut W, linger: bool) {
    let _ = tokio::time::timeout(Duration::from_secs(5), wr.shutdown()).await;
    if linger {
        let mut sink = [0u8; 4096];
        let _ = tokio::time::timeout(LINGER, async {
            while matches!(rd.read(&mut sink).await, Ok(n) if n > 0) {}
        })
        .await;
    }
}

/// Close reason after a DISCONNECT with this Reason Code (rule broken): unreadable frame,
/// Record not passed on, or protocol rule.
fn close_reason(code: DisconnectReasonCode) -> CloseReason {
    match code {
        DisconnectReasonCode::ServerShuttingDown => CloseReason::DeliveryFailed,
        DisconnectReasonCode::MalformedPacket
        | DisconnectReasonCode::PayloadFormatInvalid
        | DisconnectReasonCode::PacketTooLarge => CloseReason::BadFrame,
        _ => CloseReason::ProtocolError,
    }
}

/// Client string safe to log, cut short.
fn printable(s: &str) -> String {
    s.chars()
        .take(64)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn bytes(b: &[u8]) -> BytesMut {
        BytesMut::from(b)
    }

    #[test]
    fn a_connection_sent_away_for_a_rule_it_broke_says_which_kind() {
        use DisconnectReasonCode as C;
        for (code, reason) in [
            (C::MalformedPacket, CloseReason::BadFrame),
            (C::PayloadFormatInvalid, CloseReason::BadFrame),
            (C::PacketTooLarge, CloseReason::BadFrame),
            (C::ServerShuttingDown, CloseReason::DeliveryFailed),
            (C::ProtocolError, CloseReason::ProtocolError),
            (C::NotAuthorized, CloseReason::ProtocolError),
            (C::TopicNameInvalid, CloseReason::ProtocolError),
            (C::QoSNotSupported, CloseReason::ProtocolError),
        ] {
            assert_eq!(close_reason(code), reason, "{code:?}");
        }
    }

    #[test]
    fn keep_alive_is_one_and_a_half_times_the_clients_or_sixty_for_none() {
        let max = DEFAULT_MAX_KEEP_ALIVE;
        let ka = keep_alive(30, max);
        assert_eq!(ka.server, None);
        assert_eq!(ka.idle_limit, Duration::from_secs(45));
        let ka = keep_alive(1, max);
        assert_eq!(ka.idle_limit, Duration::from_millis(1500));
        // None asked -> 60 s in CONNACK, limit 90 s.
        let ka = keep_alive(0, max);
        assert_eq!(ka.server, Some(60));
        assert_eq!(ka.idle_limit, Duration::from_secs(90));
        // No limit -> max value does not overflow.
        assert_eq!(
            keep_alive(u16::MAX, 0).idle_limit,
            Duration::from_millis(65535 * 1500)
        );
    }

    #[test]
    fn a_keep_alive_over_the_limit_is_replaced_by_it_in_the_connack() {
        // Up to the limit -> client's own stands.
        let ka = keep_alive(1200, 1200);
        assert_eq!(
            (ka.server, ka.idle_limit),
            (None, Duration::from_secs(1800))
        );
        // Over it -> client told the limit (Server Keep Alive), which counts:
        // 18 h (65535 s) -> 30 min of silence.
        let ka = keep_alive(u16::MAX, 1200);
        assert_eq!(ka.server, Some(1200));
        assert_eq!(ka.idle_limit, Duration::from_secs(1800));
        let ka = keep_alive(1201, 1200);
        assert_eq!(ka.server, Some(1200));
        // Limit < default for "none asked" -> holds there too.
        let ka = keep_alive(0, 30);
        assert_eq!(ka.server, Some(30));
        assert_eq!(ka.idle_limit, Duration::from_secs(45));
        // 0 = no limit.
        assert_eq!(keep_alive(65000, 0).server, None);
    }

    #[test]
    fn publishing_is_limited_to_the_controller_topic_and_the_agents_own() {
        let t = "usp/controller/dhonomos";
        assert_eq!(check_publish_topic(t, t, None), TopicCheck::Controller);
        let own = format!("{t}/os::A");
        assert_eq!(
            check_publish_topic(t, &own, None),
            TopicCheck::ForAgent("os::A")
        );
        assert_eq!(
            check_publish_topic(t, &own, Some("os::A")),
            TopicCheck::ForAgent("os::A")
        );
        // Another Agent's topic, once the connection's EndpointID is known.
        assert_eq!(
            check_publish_topic(t, &own, Some("os::B")),
            TopicCheck::NotAllowed
        );
        for foreign in [
            "usp/agent/os::A",
            "usp/controller",
            "usp/controller/dhonomosX",
            "usp/controller/dhonomos/",
            "usp/controller/dhonomos/os::A/more",
            "$SYS/broker/uptime",
        ] {
            assert_eq!(
                check_publish_topic(t, foreign, None),
                TopicCheck::NotAllowed,
                "{foreign}"
            );
        }
        for bad in ["", "usp/#", "usp/controller/+", "a\0b"] {
            assert_eq!(
                check_publish_topic(t, bad, None),
                TopicCheck::Invalid,
                "{bad}"
            );
        }
    }

    #[test]
    fn filters_are_plain_wildcard_shared_or_invalid() {
        assert_eq!(classify_filter("usp/agent/os::A"), FilterKind::Plain);
        assert_eq!(classify_filter("usp/agent/#"), FilterKind::Wildcard);
        assert_eq!(classify_filter("usp/+/os::A"), FilterKind::Wildcard);
        assert_eq!(classify_filter("#"), FilterKind::Wildcard);
        assert_eq!(classify_filter("$share/g/usp/agent"), FilterKind::Shared);
        // Shared wins over its wildcard -> client told what it asked for.
        assert_eq!(classify_filter("$share/g/usp/#"), FilterKind::Shared);
        assert_eq!(classify_filter(""), FilterKind::Invalid);
    }

    #[test]
    fn replies_go_to_the_response_topic_then_the_connect_record_then_the_given_topic() {
        let mut t = Topics {
            assigned: Some("usp/agent/os::A".into()),
            ..Topics::default()
        };
        // Nothing announced -> topic from CONNACK.
        assert_eq!(t.reply_topic(), Some("usp/agent/os::A"));
        // MQTTConnectRecord topic.
        t.learn(None, Some("usp/agent/connect"));
        assert_eq!(t.reply_topic(), Some("usp/agent/connect"));
        // Response Topic wins over it, now + later.
        t.learn(Some("usp/agent/response"), Some("usp/agent/connect"));
        assert_eq!(t.reply_topic(), Some("usp/agent/response"));
        // Unusable -> ignored.
        t.learn(Some("usp/#"), None);
        t.learn(Some(""), None);
        assert_eq!(t.reply_topic(), Some("usp/agent/response"));
        // None of them -> nowhere to reply.
        assert_eq!(Topics::default().reply_topic(), None);
    }

    #[test]
    fn identity_at_connect_comes_from_the_certificate_then_the_claim() {
        let ids = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        // No certificate -> claim, if any.
        assert_eq!(eid_at_connect(None, None), Ok(None));
        assert_eq!(
            eid_at_connect(Some(" os::A "), None),
            Ok(Some("os::A".into()))
        );
        assert_eq!(eid_at_connect(Some(""), None), Ok(None));
        // Certificate names the Agent; claim must agree.
        let one = ids(&["os::A"]);
        assert_eq!(eid_at_connect(None, Some(&one)), Ok(Some("os::A".into())));
        assert_eq!(
            eid_at_connect(Some("os::A"), Some(&one)),
            Ok(Some("os::A".into()))
        );
        assert_eq!(
            eid_at_connect(Some("os::B"), Some(&one)),
            Err(IdentityError::Certificate)
        );
        // Several names, no claim -> first Record decides; with a claim -> claim decides.
        let two = ids(&["os::A", "os::B"]);
        assert_eq!(eid_at_connect(None, Some(&two)), Ok(None));
        assert_eq!(
            eid_at_connect(Some("os::B"), Some(&two)),
            Ok(Some("os::B".into()))
        );
        // Certificate naming nobody -> vouches for nobody.
        assert_eq!(eid_at_connect(None, Some(&[])), Ok(None));
        assert_eq!(
            eid_at_connect(Some("os::A"), Some(&[])),
            Err(IdentityError::Certificate)
        );
        // Names unusable as topic levels or log lines -> refused.
        for bad in [
            "os::a/b",
            "os::a+",
            "os::#",
            "os:: a",
            "os::a\nb",
            "os::\u{7f}",
        ] {
            assert_eq!(
                eid_at_connect(Some(bad), None),
                Err(IdentityError::Invalid),
                "{bad:?}"
            );
        }
        assert!(!valid_eid(&"x".repeat(257)));
        assert!(valid_eid("oui:00AA00:serial-1"));
    }

    #[test]
    fn the_connack_states_what_the_broker_supports() {
        let ack = connack(&None, None, Some("usp/agent/os::A"), false);
        let p = ack.properties.unwrap();
        assert_eq!(ack.code, ConnectReturnCode::Success);
        assert!(!ack.session_present);
        assert_eq!(p.session_expiry_interval, Some(0));
        assert_eq!(p.max_qos, Some(1));
        assert_eq!(p.retain_available, Some(0));
        assert_eq!(p.wildcard_subscription_available, Some(0));
        assert_eq!(p.subscription_identifiers_available, Some(0));
        assert_eq!(p.shared_subscription_available, Some(0));
        assert_eq!(p.topic_alias_max, Some(0));
        assert_eq!(p.max_packet_size, Some(8 * 1024 * 1024));
        assert_eq!(p.assigned_client_identifier, None);
        assert_eq!(p.server_keep_alive, None);
        assert_eq!(
            p.user_properties,
            vec![("subscribe-topic".to_owned(), "usp/agent/os::A".to_owned())]
        );
        // Response Information only when asked; no topic info when EndpointID unknown.
        assert_eq!(p.response_information, None);
        let p = connack(
            &Some("dhonomos-7".into()),
            Some(60),
            Some("usp/agent/os::A"),
            true,
        )
        .properties
        .unwrap();
        assert_eq!(p.response_information.as_deref(), Some("usp/agent/os::A"));
        assert_eq!(p.assigned_client_identifier.as_deref(), Some("dhonomos-7"));
        assert_eq!(p.server_keep_alive, Some(60));
        let p = connack(&None, None, None, true).properties.unwrap();
        assert!(p.user_properties.is_empty());
        assert_eq!(p.response_information, None);
    }

    #[test]
    fn the_first_packet_tells_the_protocol_level() {
        let connect = |name: &[u8], level: u8| {
            let mut v = vec![0x10, 0x00];
            v.extend_from_slice(&(name.len() as u16).to_be_bytes());
            v.extend_from_slice(name);
            v.push(level);
            v.extend_from_slice(&[0x02, 0x00, 0x3C]);
            v[1] = (v.len() - 2) as u8;
            v
        };
        assert_eq!(negotiate(&connect(b"MQTT", 5)), Some(Version::V5));
        assert_eq!(negotiate(&connect(b"MQTT", 4)), Some(Version::Other));
        assert_eq!(negotiate(&connect(b"MQIsdp", 3)), Some(Version::Other));
        assert_eq!(negotiate(&connect(b"HTTP", 5)), Some(Version::NotMqtt));
        assert_eq!(negotiate(b"GET / HTTP/1.1\r\n"), Some(Version::NotMqtt));
        // Incomplete.
        let whole = connect(b"MQTT", 5);
        for cut in 0..8 {
            assert_eq!(negotiate(&whole[..cut]), None, "{cut} bytes");
        }
        // Remaining Length > 4 bytes -> not MQTT.
        assert_eq!(
            negotiate(&[0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]),
            Some(Version::NotMqtt)
        );
    }

    #[test]
    fn packets_are_read_whole_or_not_at_all() {
        // PINGREQ.
        let mut b = bytes(&[0xC0, 0x00, 0xC0]);
        assert!(matches!(
            read_packet(&mut b, 1024),
            Ok(Some(Packet::PingReq(_)))
        ));
        assert_eq!(b.len(), 1, "one packet consumed");
        assert_eq!(read_packet(&mut b, 1024), Ok(None));
        // DISCONNECT without reason code = normal disconnection.
        let mut b = bytes(&[0xE0, 0x00]);
        match read_packet(&mut b, 1024) {
            Ok(Some(Packet::Disconnect(d))) => {
                assert_eq!(d.reason_code, DisconnectReasonCode::NormalDisconnection);
            }
            other => panic!("{other:?}"),
        }
        assert!(b.is_empty());
        // Nothing, half a header, half a packet.
        assert_eq!(read_packet(&mut bytes(&[]), 1024), Ok(None));
        assert_eq!(read_packet(&mut bytes(&[0x30]), 1024), Ok(None));
        assert_eq!(read_packet(&mut bytes(&[0x30, 0x05, 0x00]), 1024), Ok(None));
    }

    #[test]
    fn bad_packets_say_why() {
        let reason = |raw: &[u8], max: u32| read_packet(&mut bytes(raw), max).unwrap_err().reason;
        // Reserved flags: PINGREQ with a bit set, SUBSCRIBE without fixed 0b0010, type 0.
        assert_eq!(
            reason(&[0xC1, 0x00], 1024),
            DisconnectReasonCode::MalformedPacket
        );
        assert_eq!(
            reason(&[0x80, 0x03, 0x00, 0x01, 0x00], 1024),
            DisconnectReasonCode::MalformedPacket
        );
        assert_eq!(
            reason(&[0x00, 0x00], 1024),
            DisconnectReasonCode::MalformedPacket
        );
        // AUTH.
        assert_eq!(
            reason(&[0xF0, 0x00], 1024),
            DisconnectReasonCode::ProtocolError
        );
        // Over the limit -> refused from the header alone.
        assert_eq!(
            reason(&[0x30, 0xFF, 0xFF, 0x7F], 1024),
            DisconnectReasonCode::PacketTooLarge
        );
        // Remaining Length of 5 bytes; QoS 3; PUBLISH cut short inside.
        assert_eq!(
            reason(&[0x30, 0x80, 0x80, 0x80, 0x80, 0x01], 1 << 20),
            DisconnectReasonCode::MalformedPacket
        );
        assert_eq!(
            reason(&[0x36, 0x04, 0x00, 0x01, b'a', 0x00], 1024),
            DisconnectReasonCode::MalformedPacket
        );
        assert_eq!(
            reason(&[0x30, 0x03, 0x00, 0x09, b'a'], 1024),
            DisconnectReasonCode::MalformedPacket
        );
    }

    #[test]
    fn packets_the_broker_writes_are_read_back() {
        // Broker packets = what a client library reads.
        let mut b = BytesMut::new();
        connack(&None, None, Some("usp/agent/os::A"), true)
            .write(&mut b)
            .unwrap();
        match read_packet(&mut b, 1 << 20) {
            Ok(Some(Packet::ConnAck(a))) => {
                assert_eq!(a.properties.unwrap().max_packet_size, Some(MAX_PACKET));
            }
            other => panic!("{other:?}"),
        }
        let wire = encode(&Packet::Disconnect(Disconnect {
            reason_code: DisconnectReasonCode::SessionTakenOver,
            properties: Some(DisconnectProperties {
                session_expiry_interval: None,
                reason_string: Some("x".into()),
                user_properties: Vec::new(),
                server_reference: None,
            }),
        }));
        match read_packet(&mut bytes(&wire), 1 << 20) {
            Ok(Some(Packet::Disconnect(d))) => {
                assert_eq!(d.reason_code, DisconnectReasonCode::SessionTakenOver);
            }
            other => panic!("{other:?}"),
        }
        // Refusal for MQTT 3.1.1 clients = 4-byte CONNACK, return code 1.
        assert_eq!(REFUSED_PROTOCOL_VERSION, [0x20, 0x02, 0x00, 0x01]);
    }

    #[test]
    fn packet_identifiers_skip_those_in_use_and_wrap() {
        let mut next = 0;
        let mut inflight = HashSet::new();
        assert_eq!(free_packet_id(&mut next, &inflight), Some(1));
        inflight.insert(2);
        assert_eq!(free_packet_id(&mut next, &inflight), Some(3));
        next = u16::MAX;
        assert_eq!(free_packet_id(&mut next, &inflight), Some(1));
        // All in use.
        let all: HashSet<u16> = (1..=u16::MAX).collect();
        assert_eq!(free_packet_id(&mut next, &all), None);
    }

    #[test]
    fn records_are_looked_at_for_their_sender_and_topic() {
        use dhonomos_usp_proto::{UspVersion, builder};
        let v = UspVersion { major: 1, minor: 3 };
        let rec = builder::mqtt_connect_record(v, "os::A", "self::ctrl", "usp/agent/os::A");
        let info = record_info(&rec.encode_to_vec()).unwrap();
        assert_eq!(info.from_id, "os::A");
        assert_eq!(info.connect_topic.as_deref(), Some("usp/agent/os::A"));
        let rec = builder::stomp_connect_record(v, "os::B", "self::ctrl", "/queue/x");
        let info = record_info(&rec.encode_to_vec()).unwrap();
        assert_eq!((info.from_id.as_str(), info.connect_topic), ("os::B", None));
        assert_eq!(record_info(b"not a record"), None);
        assert_eq!(record_info(b""), None, "no from_id");
    }

    fn wire(packet: &Packet) -> BytesMut {
        BytesMut::from(encode(packet).as_ref())
    }

    fn subscribe_of(filters: usize) -> Packet {
        Packet::Subscribe(Subscribe {
            pkid: 1,
            filters: (0..filters)
                .map(|i| {
                    rumqttc::v5::mqttbytes::v5::Filter::new(format!("t/{i}"), QoS::AtLeastOnce)
                })
                .collect(),
            properties: None,
        })
    }

    fn publish_with_properties(qos: QoS, user_properties: usize) -> Packet {
        Packet::Publish(Publish {
            qos,
            pkid: u16::from(qos != QoS::AtMostOnce),
            topic: Bytes::from_static(b"usp/controller/dhonomos"),
            payload: Bytes::from_static(b"record"),
            properties: Some(PublishProperties {
                content_type: Some(USP_CONTENT_TYPE.into()),
                user_properties: (0..user_properties)
                    .map(|_| ("k".to_owned(), "v".to_owned()))
                    .collect(),
                ..PublishProperties::default()
            }),
            ..Publish::default()
        })
    }

    #[test]
    fn a_big_packet_other_than_a_publish_is_refused_from_its_header() {
        let (publish_max, other_max) = (MAX_PACKET, MAX_CONTROL_PACKET);
        // SUBSCRIBE (+ other control packets) announcing 2 MiB -> refused at once,
        // nothing buffered.
        for first in [0x82u8, 0xA2, 0x62, 0x40, 0xC0, 0xE0] {
            let mut b = bytes(&[first, 0x80, 0x80, 0x80, 0x01]);
            let e = read_packet_limited(&mut b, publish_max, other_max).unwrap_err();
            assert_eq!(e.reason, DisconnectReasonCode::PacketTooLarge, "{first:#x}");
        }
        // PUBLISH of that size = Record -> reader waits for the rest.
        let mut b = bytes(&[0x30, 0x80, 0x80, 0x80, 0x01]);
        assert_eq!(
            read_packet_limited(&mut b, publish_max, other_max),
            Ok(None)
        );
        // Over the PUBLISH limit -> refused too; single limit of `read_packet` holds for both.
        let mut b = bytes(&[0x30, 0xFF, 0xFF, 0xFF, 0x7F]);
        assert_eq!(
            read_packet_limited(&mut b, publish_max, other_max)
                .unwrap_err()
                .reason,
            DisconnectReasonCode::PacketTooLarge
        );
        let mut b = bytes(&[0x82, 0xFF, 0x7F]);
        assert_eq!(
            read_packet(&mut b, 1024).unwrap_err().reason,
            DisconnectReasonCode::PacketTooLarge
        );
        // Right at the limit -> read.
        let mut b = wire(&subscribe_of(MAX_SUBSCRIPTIONS));
        assert!(b.len() <= other_max as usize);
        assert!(matches!(
            read_packet_limited(&mut b, publish_max, other_max),
            Ok(Some(Packet::Subscribe(_)))
        ));
    }

    #[test]
    fn a_subscribe_or_unsubscribe_with_many_filters_is_refused_before_it_is_decoded() {
        let mut b = wire(&subscribe_of(MAX_SUBSCRIPTIONS));
        match read_packet(&mut b, 1 << 20) {
            Ok(Some(Packet::Subscribe(s))) => assert_eq!(s.filters.len(), MAX_SUBSCRIPTIONS),
            other => panic!("{other:?}"),
        }
        let mut b = wire(&subscribe_of(MAX_SUBSCRIPTIONS + 1));
        let e = read_packet(&mut b, 1 << 20).unwrap_err();
        assert_eq!(e.reason, DisconnectReasonCode::QuotaExceeded);
        assert!(e.message.contains("topic filters"), "{e}");
        // 5000 one-byte filters, hand-written -> refused from raw bytes, no string made.
        let mut body = vec![0, 1, 0];
        for _ in 0..5000 {
            body.extend_from_slice(&[0, 1, b'a', 0]);
        }
        let mut huge = vec![0x82u8];
        let mut len = body.len();
        loop {
            let byte = (len & 0x7F) as u8;
            len >>= 7;
            huge.push(if len > 0 { byte | 0x80 } else { byte });
            if len == 0 {
                break;
            }
        }
        huge.extend_from_slice(&body);
        let e = read_packet(&mut bytes(&huge), 1 << 20).unwrap_err();
        assert_eq!(e.reason, DisconnectReasonCode::QuotaExceeded);

        let unsub = |n: usize| {
            wire(&Packet::Unsubscribe(Unsubscribe {
                pkid: 1,
                filters: (0..n).map(|i| format!("t/{i}")).collect(),
                properties: None,
            }))
        };
        assert!(matches!(
            read_packet(&mut unsub(MAX_SUBSCRIPTIONS), 1 << 20),
            Ok(Some(Packet::Unsubscribe(_)))
        ));
        let e = read_packet(&mut unsub(MAX_SUBSCRIPTIONS + 1), 1 << 20).unwrap_err();
        assert_eq!(e.reason, DisconnectReasonCode::QuotaExceeded);
    }

    #[test]
    fn a_big_property_section_is_refused_before_it_is_decoded() {
        // Normal properties pass, QoS 0 + QoS 1 (packet identifier skipped).
        for qos in [QoS::AtMostOnce, QoS::AtLeastOnce] {
            let mut b = wire(&publish_with_properties(qos, 3));
            match read_packet(&mut b, 1 << 20) {
                Ok(Some(Packet::Publish(p))) => {
                    assert_eq!(p.properties.unwrap().user_properties.len(), 3);
                }
                other => panic!("{qos:?}: {other:?}"),
            }
            // Section over the limit -> refused: 2000 user properties = 14 KB.
            let mut b = wire(&publish_with_properties(qos, 2000));
            let e = read_packet(&mut b, 1 << 20).unwrap_err();
            assert_eq!(e.reason, DisconnectReasonCode::QuotaExceeded, "{qos:?}");
            assert!(e.message.contains("properties"), "{e}");
        }
        // Same for SUBSCRIBE.
        let subscribe = |user_properties: usize| {
            wire(&Packet::Subscribe(Subscribe {
                pkid: 1,
                filters: vec![rumqttc::v5::mqttbytes::v5::Filter::new(
                    "usp/agent/os::A",
                    QoS::AtLeastOnce,
                )],
                properties: Some(rumqttc::v5::mqttbytes::v5::SubscribeProperties {
                    id: None,
                    user_properties: (0..user_properties)
                        .map(|_| ("k".to_owned(), "v".to_owned()))
                        .collect(),
                }),
            }))
        };
        assert!(matches!(
            read_packet(&mut subscribe(1), 1 << 20),
            Ok(Some(Packet::Subscribe(_)))
        ));
        let e = read_packet(&mut subscribe(2000), 1 << 20).unwrap_err();
        assert_eq!(e.reason, DisconnectReasonCode::QuotaExceeded);
        // Property section claiming more than the packet holds -> refused, no out-of-bounds read
        // in the pre-check.
        let mut b = bytes(&[
            0x30, 0x0A, 0x00, 0x01, b't', 0xFF, 0xFF, 0xFF, 0x7F, 0, 0, 0,
        ]);
        assert!(read_packet(&mut b, 1 << 20).is_err());
        let mut b = bytes(&[0x82, 0x06, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(read_packet(&mut b, 1 << 20).is_err());
    }

    #[test]
    fn a_packet_that_is_not_all_there_gets_time_by_its_size() {
        let base = Duration::from_secs(60);
        // Size unknown yet, or small -> base.
        assert_eq!(partial_budget(base, &[0x30]), base);
        assert_eq!(partial_budget(base, &[0x30, 0x10]), base);
        // +1 s per 64 KiB announced: ~8 MiB -> +127 s.
        assert_eq!(
            partial_budget(base, &[0x30, 0xFF, 0xFF, 0xFF, 0x03]),
            base + Duration::from_secs(((1 << 23) - 1) / 65536)
        );
        assert_eq!(
            partial_budget(base, &[0x30, 0x80, 0x80, 0x04]),
            base + Duration::from_secs(1)
        );
    }

    #[test]
    fn the_configuration_is_checked() {
        assert!(MqttBrokerConfig::default().validate().is_ok());
        for bad in ["", "/usp", "usp/", "usp/#", "usp/+/x"] {
            let c = MqttBrokerConfig {
                controller_topic: bad.into(),
                ..MqttBrokerConfig::default()
            };
            assert!(c.validate().is_err(), "{bad:?}");
        }
        let c = MqttBrokerConfig {
            agent_topic_prefix: "usp/#/".into(),
            ..MqttBrokerConfig::default()
        };
        assert!(c.validate().is_err());
    }
}
