//! Broker access control via the Mosquitto dynamic-security plugin (US-17).
//!
//! Each Agent -> own broker account (username = EndpointID) + shared role.
//! Publish only to `<controller topic>/<username>` -> Controller knows the sender of a Record.
//! Subscribe only to `<prefix><username>`.
//! Commands -> `$CONTROL/dynamic-security/v1` over a separate admin connection.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::Packet;
use rumqttc::v5::{AsyncClient, Event, MqttOptions};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{oneshot, watch};
use tracing::{debug, info, warn};

/// Role of every Agent account.
pub const AGENT_ROLE: &str = "dhonomos-usp-agent";
/// Role of the Controller's own broker account.
pub const CONTROLLER_ROLE: &str = "dhonomos-usp-controller";

const COMMAND_TOPIC: &str = "$CONTROL/dynamic-security/v1";
const RESPONSE_TOPIC: &str = "$CONTROL/dynamic-security/v1/response";

/// Admin connection settings.
#[derive(Debug, Clone)]
pub struct DynsecConfig {
    pub host: String,
    pub port: u16,
    /// MQTT client ID of the admin connection.
    pub client_id: String,
    /// Account with publish right on `$CONTROL/dynamic-security/#`.
    pub username: String,
    pub password: String,
    /// Max wait for the plugin answer.
    pub timeout: Duration,
    /// TLS to the broker (ADR-081); `None` -> plain TCP.
    pub tls: Option<crate::MqttTls>,
}

/// Command failed or not sent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DynsecError {
    /// No broker connection (or admin account refused).
    #[error("broker admin connection is not available")]
    NotConnected,
    #[error("no answer from the dynamic-security plugin")]
    Timeout,
    /// Plugin rejected a command.
    #[error("{command}: {error}")]
    Rejected {
        command: String,
        /// Plugin error text.
        error: String,
    },
    /// EndpointID not usable as MQTT username + topic level.
    #[error(
        "EndpointID {0:?} cannot be used as a broker account (contains '/', '+', '#' or control characters)"
    )]
    InvalidEndpointId(String),
}

/// Result of one command.
#[derive(Debug, Clone, Deserialize)]
pub struct CommandResult {
    pub command: String,
    /// Error text if it failed.
    #[serde(default)]
    pub error: Option<String>,
    /// Returned data (e.g. `getClient`).
    #[serde(default)]
    pub data: Option<Value>,
    #[serde(default, rename = "correlationData")]
    correlation: Option<String>,
}

#[derive(Deserialize)]
struct Responses {
    responses: Vec<CommandResult>,
}

type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<Vec<CommandResult>>>>>;

/// Dynamic-security client. Cheap clone.
#[derive(Debug, Clone)]
pub struct Dynsec {
    client: AsyncClient,
    pending: Pending,
    ready: watch::Receiver<bool>,
    seq: Arc<AtomicU64>,
    timeout: Duration,
}

/// `endpoint_id` usable as MQTT username + single topic level?
pub fn valid_endpoint_id(endpoint_id: &str) -> bool {
    !endpoint_id.is_empty()
        && !endpoint_id
            .chars()
            .any(|c| matches!(c, '/' | '+' | '#') || c.is_control())
}

fn already_exists(e: &str) -> bool {
    e.to_ascii_lowercase().contains("already")
}

fn not_found(e: &str) -> bool {
    e.to_ascii_lowercase().contains("not found")
}

impl Dynsec {
    /// Connect in background, reconnect with backoff.
    pub fn start(config: DynsecConfig) -> Self {
        let mut opts = crate::tls_bridge::mqtt_options(
            config.client_id.clone(),
            &config.host,
            config.port,
            config.tls.as_ref(),
        )
        .unwrap_or_else(|_| {
            let mut o = MqttOptions::new(config.client_id.clone(), "/nonexistent", 0);
            o.set_transport(rumqttc::Transport::Unix);
            o
        });
        opts.set_keep_alive(Duration::from_secs(30));
        opts.set_clean_start(true);
        opts.set_max_packet_size(Some(crate::mqtt::MAX_PACKET_SIZE));
        opts.set_credentials(config.username.clone(), config.password.clone());
        let (client, mut eventloop) = AsyncClient::new(opts, 64);
        let pending: Pending = Arc::default();
        let (ready_tx, ready) = watch::channel(false);
        let sub_client = client.clone();
        let waiters = pending.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_millis(500);
            loop {
                match eventloop.poll().await {
                    Ok(Event::Incoming(Packet::ConnAck(_))) => {
                        backoff = Duration::from_millis(500);
                        info!(broker = %format!("{}:{}", config.host, config.port), "broker admin connected");
                        if let Err(e) = sub_client.subscribe(RESPONSE_TOPIC, QoS::AtLeastOnce).await
                        {
                            warn!(error = %e, "subscribing to dynamic-security responses failed");
                        }
                    }
                    Ok(Event::Incoming(Packet::SubAck(_))) => {
                        let _ = ready_tx.send(true);
                    }
                    Ok(Event::Incoming(Packet::Publish(p))) => {
                        let Ok(r) = serde_json::from_slice::<Responses>(&p.payload) else {
                            warn!("unparseable dynamic-security response");
                            continue;
                        };
                        let key = r.responses.first().and_then(|c| c.correlation.clone());
                        let waiter = key.and_then(|k| waiters.lock().ok()?.remove(&k));
                        match waiter {
                            Some(tx) => {
                                let _ = tx.send(r.responses);
                            }
                            None => debug!("dynamic-security response without a waiter"),
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        let _ = ready_tx.send(false);
                        if ready_tx.is_closed() {
                            return;
                        }
                        warn!(error = %e, retry_in = ?backoff, "broker admin connection error");
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(30));
                    }
                }
            }
        });
        Self {
            client,
            pending,
            ready,
            seq: Arc::default(),
            timeout: config.timeout,
        }
    }

    /// Send commands in one message -> results in same order.
    pub async fn exec(&self, mut commands: Vec<Value>) -> Result<Vec<CommandResult>, DynsecError> {
        let mut ready = self.ready.clone();
        tokio::time::timeout(self.timeout, ready.wait_for(|r| *r))
            .await
            .map_err(|_| DynsecError::NotConnected)?
            .map_err(|_| DynsecError::NotConnected)?;
        let key = format!("dhonomos-{}", self.seq.fetch_add(1, Ordering::Relaxed));
        for c in &mut commands {
            c["correlationData"] = Value::String(key.clone());
        }
        let (tx, rx) = oneshot::channel();
        if let Ok(mut p) = self.pending.lock() {
            p.insert(key.clone(), tx);
        }
        let body = json!({ "commands": commands }).to_string();
        if self
            .client
            .publish(COMMAND_TOPIC, QoS::AtLeastOnce, false, body)
            .await
            .is_err()
        {
            self.forget(&key);
            return Err(DynsecError::NotConnected);
        }
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(results)) => Ok(results),
            _ => {
                self.forget(&key);
                Err(DynsecError::Timeout)
            }
        }
    }

    fn forget(&self, key: &str) {
        if let Ok(mut p) = self.pending.lock() {
            p.remove(key);
        }
    }

    /// Run commands; errors accepted by `ok` -> ignored.
    async fn run(&self, commands: Vec<Value>, ok: fn(&str) -> bool) -> Result<(), DynsecError> {
        for r in self.exec(commands).await? {
            if let Some(error) = r.error.filter(|e| !ok(e)) {
                return Err(DynsecError::Rejected {
                    command: r.command,
                    error,
                });
            }
        }
        Ok(())
    }

    /// Create (or complete) Agent + Controller roles; idempotent.
    /// `controller_username` -> this existing account gets the Controller role.
    pub async fn ensure_roles(
        &self,
        controller_topic: &str,
        agent_topic_prefix: &str,
        controller_username: Option<&str>,
    ) -> Result<(), DynsecError> {
        let acl = |role: &str, acltype: &str, topic: String| {
            json!({ "command": "addRoleACL", "rolename": role, "acltype": acltype,
                    "topic": topic, "allow": true })
        };
        let commands = vec![
            json!({ "command": "createRole", "rolename": AGENT_ROLE,
                    "textdescription": "USP Agent (managed by Dhonomos)" }),
            acl(
                AGENT_ROLE,
                "publishClientSend",
                format!("{controller_topic}/%u"),
            ),
            acl(
                AGENT_ROLE,
                "subscribePattern",
                format!("{agent_topic_prefix}%u"),
            ),
            json!({ "command": "createRole", "rolename": CONTROLLER_ROLE,
                    "textdescription": "USP Controller (managed by Dhonomos)" }),
            acl(
                CONTROLLER_ROLE,
                "subscribeLiteral",
                controller_topic.to_owned(),
            ),
            acl(
                CONTROLLER_ROLE,
                "subscribePattern",
                format!("{controller_topic}/+"),
            ),
            acl(
                CONTROLLER_ROLE,
                "publishClientSend",
                format!("{agent_topic_prefix}#"),
            ),
        ];
        self.run(commands, already_exists).await?;
        // Roles of earlier versions: every Agent may publish to the shared topic -> can pose
        // as another Agent. Remove that ACL.
        self.run(
            vec![json!({ "command": "removeRoleACL", "rolename": AGENT_ROLE,
                         "acltype": "publishClientSend", "topic": controller_topic })],
            |e| not_found(e) || e.to_ascii_lowercase().contains("not"),
        )
        .await?;
        if let Some(user) = controller_username {
            self.grant_role(user, CONTROLLER_ROLE).await?;
        }
        Ok(())
    }

    /// Create Agent account, or reset its password + enable it.
    pub async fn upsert_agent(&self, endpoint_id: &str, password: &str) -> Result<(), DynsecError> {
        if !valid_endpoint_id(endpoint_id) {
            return Err(DynsecError::InvalidEndpointId(endpoint_id.to_owned()));
        }
        let created = self
            .exec(vec![json!({
                "command": "createClient", "username": endpoint_id, "password": password,
                "textdescription": "USP Agent", "roles": [{ "rolename": AGENT_ROLE }]
            })])
            .await?;
        match created.into_iter().next().and_then(|r| r.error) {
            None => Ok(()),
            Some(e) if already_exists(&e) => {
                self.run(
                    vec![
                        json!({ "command": "setClientPassword", "username": endpoint_id,
                                "password": password }),
                        json!({ "command": "enableClient", "username": endpoint_id }),
                    ],
                    already_exists,
                )
                .await?;
                self.grant_role(endpoint_id, AGENT_ROLE).await
            }
            Some(error) => Err(DynsecError::Rejected {
                command: "createClient".into(),
                error,
            }),
        }
    }

    /// Add `role` to an existing account, only if missing.
    /// Add twice -> "Internal error" in Mosquitto 2.1.
    async fn grant_role(&self, username: &str, role: &str) -> Result<(), DynsecError> {
        let got = self
            .exec(vec![
                json!({ "command": "getClient", "username": username }),
            ])
            .await?
            .into_iter()
            .next();
        let Some(got) = got else {
            return Err(DynsecError::Timeout);
        };
        if let Some(error) = got.error {
            return Err(DynsecError::Rejected {
                command: got.command,
                error,
            });
        }
        let has = got
            .data
            .as_ref()
            .and_then(|d| d["client"]["roles"].as_array())
            .is_some_and(|roles| roles.iter().any(|r| r["rolename"] == role));
        if has {
            return Ok(());
        }
        self.run(
            vec![json!({ "command": "addClientRole", "username": username, "rolename": role })],
            |_| false,
        )
        .await
    }

    /// Enable or disable Agent account. Disable -> disconnect.
    pub async fn set_agent_enabled(
        &self,
        endpoint_id: &str,
        enabled: bool,
    ) -> Result<(), DynsecError> {
        let command = if enabled {
            "enableClient"
        } else {
            "disableClient"
        };
        self.run(
            vec![json!({ "command": command, "username": endpoint_id })],
            not_found,
        )
        .await
    }

    /// Delete Agent account (-> disconnect). Missing account = OK.
    pub async fn delete_agent(&self, endpoint_id: &str) -> Result<(), DynsecError> {
        self.run(
            vec![json!({ "command": "deleteClient", "username": endpoint_id })],
            not_found,
        )
        .await
    }
}
