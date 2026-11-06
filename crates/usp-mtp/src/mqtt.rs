//! MQTT 5 MTP for the Controller (TR-369 MQTT binding).
//!
//! Controller subscribes to its own topic; Agents publish Records there, reply topic in the
//! Response Topic property.
//! Records to Agents: Response Topic = Controller topic, Content Type `usp.msg`.
//!
//! Broker = somebody else's -> it terminates TLS -> no client cert seen here.
//! Cert rules of the MTPs Dhonomos serves ([`crate::MultiMtp::set_certificate_bound`],
//! [`crate::MultiMtp::set_revoked`]) do not reach it.
//! Agent identity on this MTP = job of the broker.
//! Per-device accounts ([`crate::dynsec`]) -> Agent may publish only to
//! `<Controller topic>/<EndpointID>` -> Record from there has a vouched `sender`.
//! Shared Controller topic -> sender = whoever says so; Controller ranks such an address
//! after every MTP-vouched one.
//! Identity matters -> use per-device accounts or the embedded MQTT broker.

use std::time::Duration;

use bytes::Bytes;
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::{Packet, PublishProperties, SubscribeReasonCode};
use rumqttc::v5::{AsyncClient, Event, MqttOptions};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Max MQTT packet in + out. rumqttc default (10 KiB) too small for USP responses,
/// e.g. a full GetSupportedDM.
pub const MAX_PACKET_SIZE: u32 = 8 * 1024 * 1024;

/// Broker connection settings.
#[derive(Debug, Clone)]
pub struct MqttConfig {
    pub host: String,
    pub port: u16,
    pub client_id: String,
    /// (username, password); `None` -> no login.
    pub credentials: Option<(String, String)>,
    /// Controller subscribes here (= Agents' `Controller.{i}.MTP.{i}.MQTT.Topic`).
    pub controller_topic: String,
    pub keep_alive: Duration,
    /// TLS to the broker (ADR-081); `None` -> plain TCP.
    pub tls: Option<crate::MqttTls>,
}

/// Inbound Record or connection signal from an MTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    /// Topic it came in on.
    pub topic: String,
    /// Reply address of the sender (MQTT 5: Response Topic).
    pub reply_to: Option<String>,
    /// USP Record bytes.
    pub payload: Bytes,
    /// MTP connection behind `reply_to` closed (WebSocket); `payload` empty.
    pub closed: bool,
    /// Controller opened a connection to the Agent behind `reply_to` (WebSocket client,
    /// US-05); `payload` empty. Agent as server waits for the Controller to speak first.
    pub opened: bool,
    /// EndpointID the MTP vouches for: of the WebSocket connection, or last level of the
    /// Agent's own Controller topic (`<controller topic>/<EndpointID>`, broker lets only
    /// that Agent publish there).
    /// Controller refuses Records with another `from_id`. `None` -> MTP cannot tell.
    pub sender: Option<String>,
    /// Connection behind `reply_to` replaced by a newer one of the same Agent, with this
    /// serial (see [`crate::MultiMtp::send`]); `payload` empty.
    /// Address still reachable. Gone: connections with a smaller serial + Records sent on them.
    /// Sent once the new connection takes Records -> resend on this signal not in vain.
    pub replaced_by: Option<u64>,
}

impl Inbound {
    /// Signal: connection `serial` of Agent `eid` replaced an older one.
    pub(crate) fn replaced(topic: &str, reply_to: String, eid: &str, serial: u64) -> Self {
        Self {
            topic: topic.to_owned(),
            reply_to: Some(reply_to),
            payload: Bytes::new(),
            closed: false,
            opened: false,
            sender: Some(eid.to_owned()),
            replaced_by: Some(serial),
        }
    }
}

/// Agent Response Topic -> reply address.
///
/// Topic like a connection address to Dhonomos (`ws:`, `stomp:`, `mqtt:`) -> dropped.
/// Else an Agent on the external broker could send Records to another Agent's connection.
fn reply_topic(response_topic: Option<String>) -> Option<String> {
    response_topic.filter(|t| {
        let reserved = crate::MultiMtp::is_connection_address(t);
        if reserved {
            warn!(topic = %t, "Response Topic starts like an address of a connection to Dhonomos; ignored");
        }
        !reserved
    })
}

/// Sending failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MtpError {
    /// Client request queue closed (event loop stopped).
    #[error("MQTT client is not running: {0}")]
    Closed(String),
    /// No open connection or MTP for the address, or Agent send queue full.
    #[error("{0}")]
    Unavailable(String),
    /// TLS material unusable.
    #[error("TLS: {0}")]
    Tls(String),
}

/// MQTT MTP handle; cheap clone.
#[derive(Debug, Clone)]
pub struct MqttMtp {
    client: AsyncClient,
    controller_topic: String,
}

impl MqttMtp {
    /// Connect in background (reconnect with backoff) -> handle + stream of inbound Records.
    pub fn start(config: MqttConfig) -> (Self, mpsc::Receiver<Inbound>) {
        // Bridge fails to start -> address that never connects (logged).
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
        opts.set_keep_alive(config.keep_alive);
        opts.set_clean_start(true);
        opts.set_max_packet_size(Some(MAX_PACKET_SIZE));
        if let Some((u, p)) = &config.credentials {
            opts.set_credentials(u.clone(), p.clone());
        }
        let (client, mut eventloop) = AsyncClient::new(opts, 1024);
        let (tx, rx) = mpsc::channel(4096);
        let topic = config.controller_topic.clone();
        let sub_client = client.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_millis(500);
            loop {
                match eventloop.poll().await {
                    Ok(Event::Incoming(Packet::ConnAck(_))) => {
                        backoff = Duration::from_millis(500);
                        metrics::gauge!("dhonomos_usp_mqtt_connected").set(1.0);
                        info!(broker = %format!("{}:{}", config.host, config.port), topic = %topic, "MQTT connected");
                        // Clean start -> (re)subscribe on every connection:
                        // shared topic + own `<topic>/<EndpointID>` of each Agent.
                        for t in [topic.clone(), format!("{topic}/+")] {
                            if let Err(e) = sub_client.subscribe(t, QoS::AtLeastOnce).await {
                                warn!(error = %e, "MQTT subscribe failed");
                            }
                        }
                    }
                    Ok(Event::Incoming(Packet::SubAck(ack)))
                        if ack
                            .return_codes
                            .iter()
                            .any(|c| !matches!(c, SubscribeReasonCode::Success(_))) =>
                    {
                        warn!(topic = %topic, codes = ?ack.return_codes, "broker refused the Controller topic subscription (check ACLs)");
                    }
                    Ok(Event::Incoming(Packet::Publish(p))) => {
                        metrics::counter!("dhonomos_usp_mqtt_received_total").increment(1);
                        let arrived = String::from_utf8_lossy(&p.topic).into_owned();
                        let sender = arrived
                            .strip_prefix(topic.as_str())
                            .and_then(|rest| rest.strip_prefix('/'))
                            .filter(|eid| !eid.is_empty() && !eid.contains('/'))
                            .map(str::to_owned);
                        let inbound = Inbound {
                            topic: arrived,
                            reply_to: reply_topic(p.properties.and_then(|pp| pp.response_topic)),
                            payload: p.payload,
                            closed: false,
                            opened: false,
                            sender,
                            replaced_by: None,
                        };
                        if tx.try_send(inbound).is_err() {
                            if tx.is_closed() {
                                debug!("inbound receiver dropped; stopping MQTT loop");
                                return;
                            }
                            metrics::counter!("dhonomos_usp_mqtt_dropped_total").increment(1);
                            warn!("inbound queue full; dropping a USP Record");
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        metrics::gauge!("dhonomos_usp_mqtt_connected").set(0.0);
                        if tx.is_closed() {
                            return;
                        }
                        warn!(error = %e, retry_in = ?backoff, "MQTT connection error");
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(30));
                    }
                }
            }
        });
        (
            Self {
                client,
                controller_topic: config.controller_topic,
            },
            rx,
        )
    }

    /// Publish a Record to an Agent topic (QoS 1, Response Topic = Controller topic).
    pub async fn send(&self, topic: &str, payload: Vec<u8>) -> Result<(), MtpError> {
        let props = PublishProperties {
            response_topic: Some(self.controller_topic.clone()),
            content_type: Some("usp.msg".into()),
            ..PublishProperties::default()
        };
        self.client
            .publish_with_properties(topic.to_owned(), QoS::AtLeastOnce, false, payload, props)
            .await
            .map_err(|e| MtpError::Closed(e.to_string()))?;
        metrics::counter!("dhonomos_usp_mqtt_sent_total").increment(1);
        Ok(())
    }

    pub fn controller_topic(&self) -> &str {
        &self.controller_topic
    }
}

#[cfg(test)]
mod tests {
    use super::reply_topic;

    #[test]
    fn response_topics_cannot_name_connections_to_dhonomos() {
        let some = |t: &str| Some(t.to_owned());
        assert_eq!(
            reply_topic(some("usp/agent/os::A")),
            some("usp/agent/os::A")
        );
        assert_eq!(reply_topic(None), None);
        for reserved in ["ws:os::A", "stomp:os::A", "mqtt:os::A"] {
            assert_eq!(reply_topic(some(reserved)), None, "{reserved}");
        }
    }
}
