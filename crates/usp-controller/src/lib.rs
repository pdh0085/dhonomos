//! USP Controller: Agent connection state, request/response matching, Notify handling.
//!
//! Pluggable: [`Transport`] -> send Record bytes to an Agent MTP address
//! (MQTT topic, or `ws:` / `stomp:` / `mqtt:` + EndpointID).
//! [`Handler`] -> get connection changes + notifications.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use dhonomos_usp_mtp::{Inbound, MqttMtp, MultiMtp, WS_PREFIX};
use dhonomos_usp_proto::msg::{self, body::MsgBody, request::ReqType, response::RespType};
use dhonomos_usp_proto::record::record::RecordType;
use dhonomos_usp_proto::validate::{decode_record, message_of};
use dhonomos_usp_proto::{ErrorCode, UspVersion, builder};
use prost::Message as _;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

/// Send Record bytes to an MTP address.
pub trait Transport: Send + Sync + 'static {
    /// Send `bytes` to `address` (MQTT: Agent topic).
    ///
    /// Returns serial of the connection that queued the Record, if the transport numbers its
    /// connections (see [`MultiMtp::send`]); else `None`.
    /// New Agent connection replaces the old one under the same address;
    /// [`Inbound::replaced_by`] says when -> requests sent over the old one fail at once.
    fn send(
        &self,
        address: &str,
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<Option<u64>, String>> + Send;
}

impl Transport for MqttMtp {
    async fn send(&self, address: &str, bytes: Vec<u8>) -> Result<Option<u64>, String> {
        MqttMtp::send(self, address, bytes)
            .await
            .map(|()| None)
            .map_err(|e| e.to_string())
    }
}

impl Transport for MultiMtp {
    async fn send(&self, address: &str, bytes: Vec<u8>) -> Result<Option<u64>, String> {
        MultiMtp::send(self, address, bytes)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Get Agent lifecycle events + notifications.
pub trait Handler: Send + Sync + 'static {
    /// Agent connected (Connect Record) or first heard from.
    fn agent_connected(
        &self,
        endpoint_id: &str,
        version: UspVersion,
    ) -> impl Future<Output = ()> + Send;
    /// Agent sent a Disconnect Record or its WebSocket closed.
    fn agent_disconnected(&self, endpoint_id: &str) -> impl Future<Output = ()> + Send;
    /// Notify arrived. NotifyResp (if asked) queued, maybe not sent yet.
    /// `msg_id` = ID of the Notify; Agent resends an unanswered Notify with the same ID.
    fn notify(
        &self,
        endpoint_id: &str,
        msg_id: &str,
        notify: msg::Notify,
    ) -> impl Future<Output = ()> + Send;
}

/// Why a request failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UspError {
    /// No MTP address known for the Agent.
    #[error("agent is not connected")]
    NotConnected,
    /// See [`Controller::request_with_timeout`].
    #[error("no response within the timeout")]
    Timeout,
    #[error("transport error: {0}")]
    Transport(String),
    /// Agent answered with an Error message.
    #[error("agent error {code}: {message}")]
    Agent {
        /// Error code.
        code: ErrorCode,
        /// Error message.
        message: String,
    },
    /// Agent disconnected while the request was outstanding.
    #[error("agent disconnected")]
    Disconnected,
    /// Request connection replaced by a newer one of the same Agent before the answer.
    /// Sent over a gone connection -> never answered.
    /// Agent still reachable over the new connection -> resend at once is OK.
    #[error("the connection was replaced before the agent answered")]
    ConnectionReplaced,
}

#[derive(Debug, Clone)]
struct Agent {
    /// MTP addresses the Agent was heard on (US-16), in request try order:
    /// MTP-vouched sender (`vouched`) first, most recent first; then others, most recent first.
    /// Unvouched address = claim -> never outranks a vouched one.
    addresses: Vec<String>,
    /// Addresses in `addresses` announced by a sender the MTP vouched for:
    /// connection to Dhonomos (WebSocket, STOMP, embedded MQTT: its certificate or account),
    /// or the Agent's own topic on an external broker.
    /// Not: topic shared by all Agents of an external broker (sender = whoever says so).
    vouched: HashSet<String>,
    version: UspVersion,
}

type PendingTx = oneshot::Sender<Result<msg::Response, UspError>>;

/// Request waiting for its Response.
struct Pending {
    /// Agent the request went to. Only it may answer: Response (or Error) with this
    /// `msg_id` from another Agent -> ignored.
    endpoint_id: String,
    /// Response type name that answers the request (Error answers any).
    expected: &'static str,
    tx: PendingTx,
    /// MTP address + serial of the connection that took the request (see [`Transport::send`]).
    /// `None` until the send returned, and always for a transport without connection serials.
    sent_on: Option<(String, u64)>,
}

/// Where a Record went: MTP address that took it + connection serial (if the transport
/// numbers its connections).
struct Sent {
    address: String,
    serial: Option<u64>,
}

/// How an unanswered request ended.
enum Ended {
    /// Timed out; with its timeout.
    TimedOut(Duration),
    /// Its connection was replaced.
    Replaced,
}

/// Request ended without answer. Kept a while -> late Response can be told from one to a
/// request never ours.
struct Expired {
    msg_id: String,
    /// Agent the request went to.
    endpoint_id: String,
    /// Request end time.
    at: Instant,
    ended: Ended,
}

/// Max remembered unanswered requests; oldest dropped first.
const MAX_EXPIRED: usize = 256;

/// Keep time of an unanswered request.
const EXPIRED_KEPT_FOR: Duration = Duration::from_secs(600);

/// Response type name that answers `req`.
fn expected_response(req: &ReqType) -> &'static str {
    match req {
        ReqType::Get(_) => "GetResp",
        ReqType::GetSupportedDm(_) => "GetSupportedDmResp",
        ReqType::GetInstances(_) => "GetInstancesResp",
        ReqType::Set(_) => "SetResp",
        ReqType::Add(_) => "AddResp",
        ReqType::Delete(_) => "DeleteResp",
        ReqType::Operate(_) => "OperateResp",
        ReqType::Notify(_) => "NotifyResp",
        ReqType::GetSupportedProtocol(_) => "GetSupportedProtocolResp",
        ReqType::Register(_) => "RegisterResp",
        ReqType::Deregister(_) => "DeregisterResp",
    }
}

/// Type name of `resp`; `"none"` for a Response without body.
fn response_name(resp: &msg::Response) -> &'static str {
    match &resp.resp_type {
        Some(RespType::GetResp(_)) => "GetResp",
        Some(RespType::GetSupportedDmResp(_)) => "GetSupportedDmResp",
        Some(RespType::GetInstancesResp(_)) => "GetInstancesResp",
        Some(RespType::SetResp(_)) => "SetResp",
        Some(RespType::AddResp(_)) => "AddResp",
        Some(RespType::DeleteResp(_)) => "DeleteResp",
        Some(RespType::OperateResp(_)) => "OperateResp",
        Some(RespType::NotifyResp(_)) => "NotifyResp",
        Some(RespType::GetSupportedProtocolResp(_)) => "GetSupportedProtocolResp",
        Some(RespType::RegisterResp(_)) => "RegisterResp",
        Some(RespType::DeregisterResp(_)) => "DeregisterResp",
        None => "none",
    }
}

/// Fresh unguessable message ID: `dhonomos-` + 128 random bits in hex.
/// Agent that learns or predicts the `msg_id` of a request to another Agent must not be
/// able to answer it.
fn new_msg_id() -> Result<String, getrandom::Error> {
    use std::fmt::Write as _;
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw)?;
    let mut id = String::with_capacity(9 + 32);
    id.push_str("dhonomos-");
    for b in raw {
        let _ = write!(id, "{b:02x}");
    }
    Ok(id)
}

/// Send to the most recent Agent address, fall back to the others (US-16).
async fn send_to_agent<T: Transport>(
    transport: &T,
    addresses: &[String],
    bytes: Vec<u8>,
) -> Result<Sent, String> {
    let mut last = "agent has no MTP address".to_owned();
    for (i, to) in addresses.iter().enumerate() {
        match transport.send(to, bytes.clone()).await {
            Ok(serial) => {
                if i > 0 {
                    metrics::counter!("dhonomos_usp_mtp_fallbacks_total").increment(1);
                }
                return Ok(Sent {
                    address: to.clone(),
                    serial,
                });
            }
            Err(e) => {
                debug!(mtp = %to, error = %e, "MTP send failed; trying the next one");
                last = e;
            }
        }
    }
    Err(last)
}

/// Count + log a reply not queued.
fn drop_reply(endpoint_id: &str, limit: &'static str) {
    metrics::counter!("dhonomos_usp_replies_dropped_total", "limit" => limit).increment(1);
    warn!(agent = %endpoint_id, limit, "reply to the Agent dropped: too many replies waiting for it");
}

/// Remove an Agent queue + its rest when the sending task is gone before emptying it
/// (panic in the transport). Else queue stays + blocks later replies (queue = task sending it).
/// Task disarms this on normal end (it removed the queue itself): another task may have
/// started a new queue for the Agent by drop time.
struct EndOfQueue {
    outboxes: Arc<Outboxes>,
    endpoint_id: String,
    armed: bool,
}

impl Drop for EndOfQueue {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut queues = self
            .outboxes
            .queues
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(left) = queues.remove(&self.endpoint_id) {
            self.outboxes
                .queued
                .fetch_sub(left.len(), Ordering::Relaxed);
        }
    }
}

/// Send queued replies of `endpoint_id` one by one until none left; queue removed with the
/// last (reply queued after that -> new task).
async fn send_replies<T: Transport>(
    transport: Arc<T>,
    outboxes: Arc<Outboxes>,
    endpoint_id: String,
) {
    let mut end = EndOfQueue {
        outboxes: Arc::clone(&outboxes),
        endpoint_id: endpoint_id.clone(),
        armed: true,
    };
    loop {
        let next = {
            let mut queues = outboxes
                .queues
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            match queues.get_mut(&endpoint_id).and_then(VecDeque::pop_front) {
                Some(reply) => reply,
                None => {
                    // Same lock as the check -> reply queued from now finds no queue
                    // -> starts its own task.
                    queues.remove(&endpoint_id);
                    end.armed = false;
                    return;
                }
            }
        };
        outboxes.queued.fetch_sub(1, Ordering::Relaxed);
        if let Err(e) = send_to_agent(&*transport, &next.addresses, next.bytes).await {
            warn!(agent = %endpoint_id, error = %e, "failed to send reply");
        }
    }
}

/// Max queued replies (NotifyResp, Error) per Agent.
/// Agent not taking them, or Notifies faster than they go out -> newest dropped.
const MAX_QUEUED_REPLIES_PER_AGENT: usize = 32;

/// Max queued replies, all Agents together.
const MAX_QUEUED_REPLIES: usize = 8192;

/// Reply to send: addresses the Agent was heard on + Record.
struct Reply {
    addresses: Vec<String>,
    bytes: Vec<u8>,
}

/// Replies to send, by Agent. Entry exists while a task sends its replies,
/// one at a time, in queue order.
#[derive(Default)]
struct Outboxes {
    queues: Mutex<HashMap<String, VecDeque<Reply>>>,
    /// Replies in all queues.
    queued: AtomicUsize,
}

/// `d` in whole ms, saturated.
fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

pub struct Controller<T: Transport, H: Handler> {
    endpoint_id: String,
    transport: Arc<T>,
    handler: H,
    /// Response wait of [`Controller::request`] in ms ([`Controller::set_timeout`]).
    timeout_ms: AtomicU64,
    agents: Mutex<HashMap<String, Agent>>,
    pending: Mutex<HashMap<String, Pending>>,
    /// Per MTP address: serial of the newest connection that replaced another there
    /// (see [`Inbound::replaced_by`]). Request sent over a smaller serial -> never answered.
    /// Catches a request whose send returned after the replacement report (see `record_sent`).
    /// Lock order: `pending`, `replaced_before`, `expired`.
    replaced_before: Mutex<HashMap<String, u64>>,
    /// Requests ended without answer, oldest first.
    /// Max [`MAX_EXPIRED`], none older than [`EXPIRED_KEPT_FOR`].
    expired: Mutex<VecDeque<Expired>>,
    outboxes: Arc<Outboxes>,
}

impl<T: Transport, H: Handler> std::fmt::Debug for Controller<T, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Controller")
            .field("endpoint_id", &self.endpoint_id)
            .finish_non_exhaustive()
    }
}

impl<T: Transport, H: Handler> Controller<T, H> {
    /// Controller with EndpointID `endpoint_id` (ADR-020).
    /// `timeout` = Response wait of [`Controller::request`].
    pub fn new(
        endpoint_id: impl Into<String>,
        transport: T,
        handler: H,
        timeout: Duration,
    ) -> Self {
        Self {
            endpoint_id: endpoint_id.into(),
            transport: Arc::new(transport),
            handler,
            timeout_ms: AtomicU64::new(millis(timeout)),
            agents: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            replaced_before: Mutex::new(HashMap::new()),
            expired: Mutex::new(VecDeque::new()),
            outboxes: Arc::default(),
        }
    }

    pub fn handler(&self) -> &H {
        &self.handler
    }

    /// Response wait of [`Controller::request`].
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.load(Ordering::Relaxed))
    }

    /// Set Response wait of [`Controller::request`], for requests sent from now on.
    pub fn set_timeout(&self, timeout: Duration) {
        self.timeout_ms.store(millis(timeout), Ordering::Relaxed);
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// `true` if an MTP address is known for the Agent.
    pub fn is_connected(&self, endpoint_id: &str) -> bool {
        self.agents
            .lock()
            .is_ok_and(|a| a.contains_key(endpoint_id))
    }

    /// EndpointIDs of connected Agents.
    pub fn connected_agents(&self) -> Vec<String> {
        self.agents
            .lock()
            .map(|a| a.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// EndpointIDs of connected Agents + MTP addresses each was heard on.
    pub fn connected_agent_addresses(&self) -> Vec<(String, Vec<String>)> {
        self.agents
            .lock()
            .map(|a| {
                a.iter()
                    .map(|(eid, agent)| (eid.clone(), agent.addresses.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Handle inbound Records until the channel closes.
    ///
    /// One Record at a time; nothing in it waits for an Agent:
    /// replies queued + sent by own tasks (see `reply`); [`Handler`] expected to return fast
    /// (the Dhonomos one only queues the event).
    /// -> Agent that stalls its own connection cannot hold up the others.
    pub async fn run(&self, mut inbound: mpsc::Receiver<Inbound>) {
        while let Some(i) = inbound.recv().await {
            self.handle(i).await;
        }
    }

    /// Note Agent heard on `reply_to`.
    /// `vouched` = MTP vouched for the Record sender (`Inbound::sender`) -> address first;
    /// else after the vouched ones -> Agent that only claims to be another cannot put its
    /// address before the real one's (H-3). Once vouched -> stays vouched.
    fn remember(
        &self,
        endpoint_id: &str,
        reply_to: String,
        version: UspVersion,
        vouched: bool,
    ) -> bool {
        let Ok(mut agents) = self.agents.lock() else {
            return false;
        };
        let new = !agents.contains_key(endpoint_id);
        let agent = agents
            .entry(endpoint_id.to_owned())
            .or_insert_with(|| Agent {
                addresses: Vec::new(),
                vouched: HashSet::new(),
                version,
            });
        agent.version = version;
        agent.addresses.retain(|a| *a != reply_to);
        if vouched || agent.vouched.contains(&reply_to) {
            agent.vouched.insert(reply_to.clone());
            agent.addresses.insert(0, reply_to);
        } else {
            let after = agent
                .addresses
                .iter()
                .take_while(|a| agent.vouched.contains(*a))
                .count();
            agent.addresses.insert(after, reply_to);
        }
        metrics::gauge!("dhonomos_usp_agents_connected").set(agents.len() as f64);
        new
    }

    /// Handle one inbound Record.
    pub async fn handle(&self, inbound: Inbound) {
        if inbound.closed {
            if let Some(address) = &inbound.reply_to {
                self.mtp_closed(address).await;
            }
            return;
        }
        // Newer Agent connection replaced an older one under the same address
        // -> Agent still reachable, but what was sent over the old one is lost.
        if let Some(serial) = inbound.replaced_by {
            if let Some(address) = &inbound.reply_to {
                self.mtp_replaced(address, serial);
            }
            return;
        }
        // Controller connected to the Agent WebSocket server (US-05) -> reachable now, as after
        // a WebSocketConnect Record; its Records then give its protocol version.
        if inbound.opened {
            if let Some(address) = inbound.reply_to
                && let Some(eid) = address.strip_prefix(WS_PREFIX).map(str::to_owned)
            {
                let version = UspVersion { major: 1, minor: 3 };
                info!(agent = %eid, reply_to = %address, "agent reachable (Controller connected)");
                self.remember(&eid, address, version, true);
                self.handler.agent_connected(&eid, version).await;
            }
            return;
        }
        let valid = match decode_record(&inbound.payload) {
            Ok(v) => v,
            Err(e) => {
                metrics::counter!("dhonomos_usp_invalid_records_total").increment(1);
                warn!(from = ?e.from_id, error = %e, "invalid USP Record");
                return;
            }
        };
        let rec = valid.record;
        if rec.to_id != self.endpoint_id {
            // Usually Agent set up with another Controller EndpointID -> warn,
            // else Agent looks connected but is never served.
            metrics::counter!("dhonomos_usp_records_ignored_total", "reason" => "to_id")
                .increment(1);
            warn!(from = %rec.from_id, to = %rec.to_id, controller = %self.endpoint_id,
                "Record addressed to another Controller ignored (check the Agent's Controller EndpointID)");
            return;
        }
        let from = rec.from_id.clone();
        // Record must come from the EndpointID its MTP vouches for: WebSocket, STOMP or
        // embedded MQTT connection, or Agent's own MQTT topic on an external broker
        // (no posing as another Agent).
        if let Some(eid) = inbound.sender.as_deref()
            && eid != from
        {
            metrics::counter!("dhonomos_usp_invalid_records_total").increment(1);
            warn!(agent = %eid, from = %from, "Record from_id does not match the sender the MTP vouches for");
            return;
        }
        // MTP vouched for the sender (= `from`, by the check above).
        let vouched = inbound.sender.is_some();
        match &rec.record_type {
            // External broker: Agent address = topic it subscribed to.
            // Embedded broker: MTP set `reply_to` = `mqtt:` + EndpointID; broker tracks
            // the Agent topic itself.
            Some(RecordType::MqttConnect(c)) => {
                let reply_to = inbound
                    .reply_to
                    .clone()
                    .unwrap_or_else(|| c.subscribed_topic.clone());
                info!(agent = %from, reply_to = %reply_to, version = %valid.version, "agent connected");
                self.remember(&from, reply_to, valid.version, vouched);
                self.handler.agent_connected(&from, valid.version).await;
                return;
            }
            // WebSocket/STOMP: connection = reply address (`ws:` / `stomp:` + EndpointID);
            // MTP set `reply_to`.
            Some(RecordType::WebsocketConnect(_) | RecordType::StompConnect(_)) => {
                let Some(reply_to) = inbound.reply_to.clone() else {
                    return;
                };
                info!(agent = %from, reply_to = %reply_to, version = %valid.version, "agent connected");
                self.remember(&from, reply_to, valid.version, vouched);
                self.handler.agent_connected(&from, valid.version).await;
                return;
            }
            Some(RecordType::Disconnect(d)) => {
                info!(agent = %from, reason = %d.reason, "agent disconnecting");
                // Agent leaves only the MTP of this Record; other MTPs stay usable (US-16).
                // Only its own entry touched: external broker -> address = Response Topic
                // chosen by the sender, may name anybody's (L-2).
                match &inbound.reply_to {
                    Some(address) => self.address_left(&from, address).await,
                    None => self.forget(&from).await,
                }
                return;
            }
            Some(RecordType::NoSessionContext(_)) => {}
            other => {
                debug!(agent = %from, kind = ?other.as_ref().map(std::mem::discriminant), "unsupported Record type ignored");
                return;
            }
        }
        // Agent heard without a Connect Record (e.g. after Controller restart).
        if let Some(reply_to) = inbound.reply_to.clone()
            && self.remember(&from, reply_to, valid.version, vouched)
        {
            self.handler.agent_connected(&from, valid.version).await;
        }
        let m = match message_of(&rec) {
            Ok(Some(m)) => m,
            Ok(None) => return,
            Err(e) => {
                metrics::counter!("dhonomos_usp_invalid_records_total").increment(1);
                warn!(agent = %from, error = %e, "invalid USP Message");
                return;
            }
        };
        let msg_id = m
            .header
            .as_ref()
            .map(|h| h.msg_id.clone())
            .unwrap_or_default();
        match m.body.and_then(|b| b.msg_body) {
            Some(MsgBody::Response(r)) => self.resolve(&from, &msg_id, Ok(r)),
            Some(MsgBody::Error(e)) => {
                // Per-parameter errors as `msg | path: code msg` (like CWMP 9003).
                let mut message = e.err_msg;
                for p in &e.param_errs {
                    message.push_str(&format!(
                        " | {}: {} {}",
                        p.param_path, p.err_code, p.err_msg
                    ));
                }
                self.resolve(
                    &from,
                    &msg_id,
                    Err(UspError::Agent {
                        code: ErrorCode(e.err_code),
                        message,
                    }),
                )
            }
            Some(MsgBody::Request(req)) => match req.req_type {
                Some(ReqType::Notify(n)) => {
                    metrics::counter!("dhonomos_usp_notifications_total").increment(1);
                    if n.send_resp {
                        let resp = builder::notify_resp(&msg_id, n.subscription_id.clone());
                        self.reply(&from, &resp);
                    }
                    self.handler.notify(&from, &msg_id, n).await;
                }
                _ => {
                    let err = builder::error(
                        &msg_id,
                        ErrorCode::MESSAGE_NOT_SUPPORTED,
                        "Controller does not accept this request",
                    );
                    self.reply(&from, &err);
                }
            },
            None => {}
        }
    }

    async fn forget(&self, endpoint_id: &str) {
        if let Ok(mut agents) = self.agents.lock() {
            agents.remove(endpoint_id);
            metrics::gauge!("dhonomos_usp_agents_connected").set(agents.len() as f64);
        }
        self.fail_pending_of(endpoint_id, UspError::Disconnected);
        self.handler.agent_disconnected(endpoint_id).await;
    }

    /// Disconnect Record: Agent `endpoint_id` leaves the MTP at `address` -> loses that
    /// address; gone if no other left (US-16). No other entry touched, whatever `address` is.
    async fn address_left(&self, endpoint_id: &str, address: &str) {
        let gone = self.agents.lock().is_ok_and(|mut agents| {
            let Some(agent) = agents.get_mut(endpoint_id) else {
                return false;
            };
            let before = agent.addresses.len();
            agent.addresses.retain(|a| a != address);
            agent.vouched.remove(address);
            if agent.addresses.is_empty() {
                return true;
            }
            if agent.addresses.len() < before {
                info!(agent = %endpoint_id, mtp = %address, "agent still reachable on another MTP");
            } else {
                debug!(agent = %endpoint_id, mtp = %address, "Disconnect names an address the Agent does not have; ignored");
            }
            false
        });
        if gone {
            info!(agent = %endpoint_id, "agent disconnected (MTP closed)");
            self.forget(endpoint_id).await;
        }
    }

    /// MTP connection at `address` closed -> Agents lose that address; those without any
    /// -> gone (US-16).
    async fn mtp_closed(&self, address: &str) {
        // Connections gone for good: Agents losing their last address -> requests failed
        // below; new connection -> serial above all used so far.
        if let Ok(mut replaced) = self.replaced_before.lock() {
            replaced.remove(address);
        }
        let gone: Vec<String> = self
            .agents
            .lock()
            .map(|mut agents| {
                let mut gone = Vec::new();
                for (eid, agent) in agents.iter_mut() {
                    let before = agent.addresses.len();
                    agent.addresses.retain(|a| a != address);
                    agent.vouched.remove(address);
                    if agent.addresses.is_empty() {
                        gone.push(eid.clone());
                    } else if agent.addresses.len() < before {
                        info!(agent = %eid, mtp = %address, "agent still reachable on another MTP");
                    }
                }
                gone
            })
            .unwrap_or_default();
        for eid in gone {
            info!(agent = %eid, "agent disconnected (MTP closed)");
            self.forget(&eid).await;
        }
    }

    /// Connection `serial` replaced the older ones of the Agent at `address`
    /// (see [`Inbound::replaced_by`]).
    /// Requests sent over those -> [`UspError::ConnectionReplaced`] now, not at timeout:
    /// Agent drops its unanswered requests with the connection.
    /// Requests sent over `serial` or newer -> untouched, however close to the replacement:
    /// each request carries the serial of its connection.
    ///
    /// Request known to be on an old connection only after its send returned (`record_sent`).
    /// Send returned after this ran -> found by the serial noted here. Both steps under the
    /// `pending` lock -> each request seen by one or both, never by neither.
    fn mtp_replaced(&self, address: &str, serial: u64) {
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        if let Ok(mut replaced) = self.replaced_before.lock() {
            let newest = replaced.entry(address.to_owned()).or_insert(serial);
            *newest = (*newest).max(serial);
        }
        let ids: Vec<String> = pending
            .iter()
            .filter(|(_, p)| {
                p.sent_on
                    .as_ref()
                    .is_some_and(|(to, on)| to == address && *on < serial)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in &ids {
            self.fail_replaced(&mut pending, id);
        }
        if ids.is_empty() {
            debug!(mtp = %address, serial, "connection replaced; no request was waiting on the old one");
        } else {
            info!(mtp = %address, serial, requests = ids.len(),
                "connection replaced; the requests sent over the old one failed");
        }
    }

    /// Note request `msg_id` went over `sent`.
    /// Connection already replaced (reported before the send returned) -> request ends here.
    fn record_sent(&self, msg_id: &str, sent: Sent) {
        let Some(serial) = sent.serial else {
            return;
        };
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        let replaced = self.replaced_before.lock().is_ok_and(|replaced| {
            replaced
                .get(&sent.address)
                .is_some_and(|newest| serial < *newest)
        });
        if replaced {
            self.fail_replaced(&mut pending, msg_id);
        } else if let Some(p) = pending.get_mut(msg_id) {
            p.sent_on = Some((sent.address, serial));
        }
    }

    /// End request `msg_id` with [`UspError::ConnectionReplaced`] if outstanding.
    /// Remembered like a timeout -> late answer (over the new connection) recognised + dropped.
    /// Caller holds the `pending` lock throughout -> answer meanwhile finds the request
    /// outstanding or remembered, never forgotten.
    fn fail_replaced(&self, pending: &mut HashMap<String, Pending>, msg_id: &str) {
        let Some(p) = pending.remove(msg_id) else {
            return;
        };
        self.note_expired(msg_id, &p.endpoint_id, Ended::Replaced);
        metrics::counter!("dhonomos_usp_request_replaced_total").increment(1);
        let _ = p.tx.send(Err(UspError::ConnectionReplaced));
    }

    /// Complete request `msg_id` with `result` = answer of `from` (EndpointID the MTP
    /// vouched for). Only the Agent the request went to may answer: anyone else -> request
    /// stays outstanding, answer counted + dropped.
    /// Response of another type than the request needs (Error fits any) -> Agent error,
    /// wrong data not passed on.
    fn resolve(&self, from: &str, msg_id: &str, result: Result<msg::Response, UspError>) {
        let waiter = {
            let Ok(mut pending) = self.pending.lock() else {
                return;
            };
            match pending.get(msg_id).map(|p| p.endpoint_id.clone()) {
                Some(target) if target == from => pending.remove(msg_id),
                Some(target) => {
                    drop(pending);
                    metrics::counter!("dhonomos_usp_response_mismatch_total", "reason" => "sender")
                        .increment(1);
                    warn!(agent = %from, %target, "answer to a request sent to another Agent ignored");
                    return;
                }
                None => None,
            }
        };
        let Some(waiter) = waiter else {
            match self.take_expired(from, msg_id) {
                Some(Expired {
                    ended: Ended::TimedOut(timeout),
                    at,
                    ..
                }) => {
                    info!(agent = %from, msg_id, timeout_ms = timeout.as_millis(),
                        late_ms = at.elapsed().as_millis(),
                        "response arrived after the request timed out; dropped");
                }
                Some(Expired {
                    ended: Ended::Replaced,
                    at,
                    ..
                }) => {
                    info!(agent = %from, msg_id, late_ms = at.elapsed().as_millis(),
                        "response arrived after the connection the request was sent over was replaced; dropped");
                }
                None => debug!(agent = %from, "response to an unknown request"),
            }
            return;
        };
        let result = match result {
            Ok(resp) if response_name(&resp) != waiter.expected => {
                let got = response_name(&resp);
                metrics::counter!("dhonomos_usp_response_mismatch_total", "reason" => "type")
                    .increment(1);
                warn!(agent = %from, expected = waiter.expected, got,
                    "Response of the wrong type for the request");
                Err(UspError::Agent {
                    code: ErrorCode::MESSAGE_FAILED,
                    message: format!(
                        "unexpected {got} in answer to a request that expects {}",
                        waiter.expected
                    ),
                })
            }
            other => other,
        };
        let _ = waiter.tx.send(result);
    }

    /// Remember: request `msg_id` to `endpoint_id` ended without answer.
    fn note_expired(&self, msg_id: &str, endpoint_id: &str, ended: Ended) {
        let Ok(mut expired) = self.expired.lock() else {
            return;
        };
        while expired
            .front()
            .is_some_and(|e| e.at.elapsed() > EXPIRED_KEPT_FOR)
        {
            expired.pop_front();
        }
        if expired.len() >= MAX_EXPIRED {
            expired.pop_front();
        }
        expired.push_back(Expired {
            msg_id: msg_id.to_owned(),
            endpoint_id: endpoint_id.to_owned(),
            at: Instant::now(),
            ended,
        });
    }

    /// Unanswered ended request `msg_id` to `from`, if still remembered.
    /// Only the Agent the request went to counts; taken once.
    fn take_expired(&self, from: &str, msg_id: &str) -> Option<Expired> {
        let mut expired = self.expired.lock().ok()?;
        let i = expired
            .iter()
            .position(|e| e.msg_id == msg_id && e.endpoint_id == from)?;
        expired
            .remove(i)
            .filter(|e| e.at.elapsed() <= EXPIRED_KEPT_FOR)
    }

    fn fail_pending_of(&self, endpoint_id: &str, error: UspError) {
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        let ids: Vec<String> = pending
            .iter()
            .filter(|(_, p)| p.endpoint_id == endpoint_id)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            if let Some(p) = pending.remove(&id) {
                let _ = p.tx.send(Err(error.clone()));
            }
        }
    }

    fn record_for(&self, endpoint_id: &str, m: &msg::Msg) -> Option<(Vec<String>, Vec<u8>)> {
        let agent = self.agents.lock().ok()?.get(endpoint_id).cloned()?;
        let version = UspVersion::CURRENT.negotiate(agent.version);
        let rec = builder::no_session_record(version, &self.endpoint_id, endpoint_id, m);
        Some((agent.addresses, rec.encode_to_vec()))
    }

    /// Queue a reply (NotifyResp, Error) to the Agent + return; never waits for the Agent.
    /// Inbound loop ([`Controller::run`]) serves all Agents -> one not taking what is sent
    /// (stalled connection, full queue behind it) must not hold it up -> replies sent by
    /// their own task.
    ///
    /// Per Agent: one at a time, in queue order, by a task alive while replies wait.
    /// Order not needed today (each reply echoes its `msg_id`, Agent matches by it); queue per
    /// Agent costs nothing over task per reply + keeps the order a trace reader expects.
    /// Over limit ([`MAX_QUEUED_REPLIES_PER_AGENT`] per Agent, [`MAX_QUEUED_REPLIES`] total)
    /// -> dropped + counted; Agent resends a Notify without NotifyResp.
    fn reply(&self, endpoint_id: &str, m: &msg::Msg) {
        let Some((addresses, bytes)) = self.record_for(endpoint_id, m) else {
            return;
        };
        let outboxes = &self.outboxes;
        if outboxes.queued.fetch_add(1, Ordering::Relaxed) >= MAX_QUEUED_REPLIES {
            outboxes.queued.fetch_sub(1, Ordering::Relaxed);
            drop_reply(endpoint_id, "total");
            return;
        }
        enum Queued {
            /// No task sending replies of this Agent -> start one.
            Start,
            /// Task running -> takes this one too.
            Joined,
            Full,
        }
        let queued = {
            let Ok(mut queues) = outboxes.queues.lock() else {
                outboxes.queued.fetch_sub(1, Ordering::Relaxed);
                return;
            };
            match queues.get_mut(endpoint_id) {
                Some(queue) if queue.len() >= MAX_QUEUED_REPLIES_PER_AGENT => Queued::Full,
                Some(queue) => {
                    queue.push_back(Reply { addresses, bytes });
                    Queued::Joined
                }
                None => {
                    let queue = VecDeque::from([Reply { addresses, bytes }]);
                    queues.insert(endpoint_id.to_owned(), queue);
                    Queued::Start
                }
            }
        };
        match queued {
            Queued::Start => {
                tokio::spawn(send_replies(
                    Arc::clone(&self.transport),
                    Arc::clone(&self.outboxes),
                    endpoint_id.to_owned(),
                ));
            }
            Queued::Joined => {}
            Queued::Full => {
                outboxes.queued.fetch_sub(1, Ordering::Relaxed);
                drop_reply(endpoint_id, "per_agent");
            }
        }
    }

    /// Send a request + wait for the matching Response (or Error), up to the Controller
    /// timeout (see [`Controller::new`]).
    pub async fn request(
        &self,
        endpoint_id: &str,
        req: ReqType,
    ) -> Result<msg::Response, UspError> {
        self.request_with_timeout(endpoint_id, req, self.timeout())
            .await
    }

    /// [`Controller::request`] with its own timeout: for slow answers (e.g. Get of the whole
    /// data model).
    ///
    /// Response after the timeout -> dropped (caller got [`UspError::Timeout`]);
    /// logged at info while the request is remembered.
    ///
    /// Request connection replaced by a newer one of the same Agent (MTP reports it, see
    /// [`Inbound::replaced_by`]) -> request ends at once with [`UspError::ConnectionReplaced`]:
    /// Agent loses its unanswered requests with the old connection.
    /// Request sent over the new connection -> not affected.
    /// Later Response -> dropped like one after a timeout.
    #[tracing::instrument(name = "usp.request", skip_all, fields(agent = %endpoint_id))]
    pub async fn request_with_timeout(
        &self,
        endpoint_id: &str,
        req: ReqType,
        timeout: Duration,
    ) -> Result<msg::Response, UspError> {
        let msg_id =
            new_msg_id().map_err(|e| UspError::Transport(format!("OS RNG unavailable: {e}")))?;
        let expected = expected_response(&req);
        let m = builder::request(&msg_id, req);
        let (to, bytes) = self
            .record_for(endpoint_id, &m)
            .ok_or(UspError::NotConnected)?;
        let (tx, rx) = oneshot::channel();
        if let Ok(mut p) = self.pending.lock() {
            p.insert(
                msg_id.clone(),
                Pending {
                    endpoint_id: endpoint_id.to_owned(),
                    expected,
                    tx,
                    sent_on: None,
                },
            );
        }
        match send_to_agent(&*self.transport, &to, bytes).await {
            Ok(sent) => self.record_sent(&msg_id, sent),
            Err(e) => {
                self.pending.lock().ok().and_then(|mut p| p.remove(&msg_id));
                return Err(UspError::Transport(e));
            }
        }
        metrics::counter!("dhonomos_usp_requests_total").increment(1);
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(UspError::Disconnected),
            Err(_) => {
                // Remember before stop of waiting -> answer arriving in between still finds
                // the request.
                self.note_expired(&msg_id, endpoint_id, Ended::TimedOut(timeout));
                self.pending.lock().ok().and_then(|mut p| p.remove(&msg_id));
                metrics::counter!("dhonomos_usp_request_timeouts_total").increment(1);
                Err(UspError::Timeout)
            }
        }
    }
}
