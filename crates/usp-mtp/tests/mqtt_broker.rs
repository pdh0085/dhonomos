//! Embedded MQTT broker (ADR-093) vs scripted MQTT 5.0 clients + the rumqttc client.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::{Bytes, BytesMut};
use dhonomos_pki::{Ca, Issued, Profile};
use dhonomos_usp_mtp::{Inbound, MqttBrokerConfig, MqttBrokerMtp, MultiMtp, tls_acceptor};
use dhonomos_usp_proto::{UspVersion, builder};
use prost::Message as _;
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::{
    ConnAck, Connect, ConnectProperties, ConnectReturnCode, DisconnectReasonCode, Filter, Login,
    Packet, PingReq, PubAck, PubAckReason, Publish, PublishProperties, Subscribe,
    SubscribeProperties, SubscribeReasonCode, UnsubAckReason, Unsubscribe,
};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::mpsc;

const CTRL: &str = "self::dhonomos-test";
const CTRL_TOPIC: &str = "usp/controller/dhonomos";
const V: UspVersion = UspVersion { major: 1, minor: 3 };

/// Scripted MQTT 5.0 client: sends any packet it is told, shows the reply.
struct Raw<S> {
    io: S,
    buf: BytesMut,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Raw<S> {
    fn new(io: S) -> Self {
        Self {
            io,
            buf: BytesMut::new(),
        }
    }

    async fn send(&mut self, p: Packet) {
        let mut b = BytesMut::new();
        p.write(&mut b, None).unwrap();
        self.send_raw(&b).await;
    }

    async fn send_raw(&mut self, bytes: &[u8]) {
        self.io.write_all(bytes).await.unwrap();
    }

    /// Next packet; `None` = broker closed the connection.
    async fn next(&mut self) -> Option<Packet> {
        self.next_within(Duration::from_secs(5))
            .await
            .expect("nothing from the broker")
    }

    async fn next_within(
        &mut self,
        wait: Duration,
    ) -> Result<Option<Packet>, tokio::time::error::Elapsed> {
        use rumqttc::v5::mqttbytes::Error;
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            match Packet::read(&mut self.buf, Some(16 << 20)) {
                Ok(p) => return Ok(Some(p)),
                Err(Error::InsufficientBytes(_)) => {}
                Err(e) => panic!("the broker sent an unreadable packet: {e}"),
            }
            let n = tokio::time::timeout(wait, self.io.read(&mut chunk)).await?;
            match n {
                Ok(0) | Err(_) => return Ok(None),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// Broker DISCONNECT, then connection end.
    async fn expect_disconnect(&mut self) -> DisconnectReasonCode {
        let Some(Packet::Disconnect(d)) = self.next().await else {
            panic!("expected a DISCONNECT");
        };
        assert!(self.next().await.is_none(), "the connection closes");
        d.reason_code
    }
}

fn subscribe_packet(pkid: u16, filters: &[(&str, QoS)]) -> Packet {
    Packet::Subscribe(Subscribe {
        pkid,
        filters: filters.iter().map(|(t, q)| Filter::new(*t, *q)).collect(),
        properties: None,
    })
}

fn connect_packet(
    client_id: &str,
    keep_alive: u16,
    props: Option<ConnectProperties>,
    login: Option<(&str, &str)>,
) -> Packet {
    Packet::Connect(
        Connect {
            keep_alive,
            client_id: client_id.into(),
            clean_start: true,
            properties: props,
        },
        None,
        login.map(|(u, p)| Login::new(u, p)),
    )
}

/// CONNECT properties of a TR-369 Agent: `usp-endpoint-id`.
fn claim(eid: &str) -> ConnectProperties {
    let mut p = ConnectProperties::new();
    p.user_properties = vec![("usp-endpoint-id".into(), eid.into())];
    p
}

fn publish(
    topic: &str,
    qos: QoS,
    pkid: u16,
    payload: Vec<u8>,
    response_topic: Option<&str>,
) -> Publish {
    Publish {
        qos,
        topic: Bytes::copy_from_slice(topic.as_bytes()),
        pkid,
        payload: payload.into(),
        properties: Some(PublishProperties {
            response_topic: response_topic.map(str::to_owned),
            content_type: Some("usp.msg".into()),
            ..PublishProperties::default()
        }),
        ..Publish::default()
    }
}

/// MQTTConnectRecord from `from`, announcing `topic`.
fn hello(from: &str, topic: &str) -> Vec<u8> {
    builder::mqtt_connect_record(V, from, CTRL, topic).encode_to_vec()
}

struct Env {
    broker: MqttBrokerMtp,
    addr: std::net::SocketAddr,
    inbound: mpsc::Receiver<Inbound>,
}

impl Env {
    async fn start(config: MqttBrokerConfig) -> Self {
        Self::start_with(config, None).await
    }

    async fn start_with(config: MqttBrokerConfig, tls: Option<tokio_rustls::TlsAcceptor>) -> Self {
        let (tx, inbound) = mpsc::channel(64);
        let broker = MqttBrokerMtp::new(tx, config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = broker.clone();
        tokio::spawn(async move {
            serving
                .serve(listener, tls, std::future::pending())
                .await
                .unwrap()
        });
        Self {
            broker,
            addr,
            inbound,
        }
    }

    async fn tcp(&self) -> Raw<tokio::net::TcpStream> {
        Raw::new(tokio::net::TcpStream::connect(self.addr).await.unwrap())
    }

    /// Agent connect with `usp-endpoint-id` = `eid` -> CONNACK.
    async fn agent(&self, eid: &str) -> (Raw<tokio::net::TcpStream>, ConnAck) {
        let mut c = self.tcp().await;
        c.send(connect_packet(
            &format!("c-{eid}"),
            60,
            Some(claim(eid)),
            None,
        ))
        .await;
        let Some(Packet::ConnAck(ack)) = c.next().await else {
            panic!("expected a CONNACK");
        };
        assert_eq!(ack.code, ConnectReturnCode::Success, "{eid}");
        (c, ack)
    }

    async fn inbound(&mut self) -> Inbound {
        tokio::time::timeout(Duration::from_secs(5), self.inbound.recv())
            .await
            .expect("no Inbound")
            .unwrap()
    }

    async fn no_inbound(&mut self) {
        assert!(
            tokio::time::timeout(Duration::from_millis(300), self.inbound.recv())
                .await
                .is_err(),
            "unexpected Inbound"
        );
    }
}

async fn poll<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn ago(t: SystemTime) -> Duration {
    SystemTime::now().duration_since(t).unwrap_or_default()
}

#[tokio::test]
async fn connack_tells_the_agent_its_topic_and_what_the_broker_does_not_do() {
    let env = Env::start(MqttBrokerConfig::default()).await;
    let (_agent, ack) = env.agent("os::A").await;
    assert!(!ack.session_present);
    let p = ack.properties.unwrap();
    assert_eq!(p.session_expiry_interval, Some(0));
    assert_eq!(p.max_qos, Some(1));
    assert_eq!(p.retain_available, Some(0));
    assert_eq!(p.wildcard_subscription_available, Some(0));
    assert_eq!(p.subscription_identifiers_available, Some(0));
    assert_eq!(p.shared_subscription_available, Some(0));
    assert_eq!(p.topic_alias_max, Some(0));
    assert_eq!(p.max_packet_size, Some(8 * 1024 * 1024));
    // Agent topic = prefix + claimed EndpointID.
    // No Response Information asked -> none; its Keep Alive stays.
    assert_eq!(
        p.user_properties,
        vec![("subscribe-topic".to_owned(), "usp/agent/os::A".to_owned())]
    );
    assert_eq!(p.response_information, None);
    assert_eq!(p.server_keep_alive, None);
    assert_eq!(p.assigned_client_identifier, None);

    // Response Information on request + assigned Client Identifier for an empty one
    // + 60 s for Keep Alive 0.
    let mut c = env.tcp().await;
    let mut props = claim("os::B");
    props.request_response_info = Some(1);
    c.send(connect_packet("", 0, Some(props), None)).await;
    let Some(Packet::ConnAck(ack)) = c.next().await else {
        panic!("expected a CONNACK");
    };
    let p = ack.properties.unwrap();
    assert_eq!(p.response_information.as_deref(), Some("usp/agent/os::B"));
    assert!(
        p.assigned_client_identifier
            .is_some_and(|id| !id.is_empty())
    );
    assert_eq!(p.server_keep_alive, Some(60));
    assert_eq!(
        p.user_properties,
        vec![("subscribe-topic".to_owned(), "usp/agent/os::B".to_owned())]
    );

    // Client with no identity -> no topic; must use its own.
    let mut c = env.tcp().await;
    let mut props = ConnectProperties::new();
    props.request_response_info = Some(1);
    c.send(connect_packet("anon", 60, Some(props), None)).await;
    let Some(Packet::ConnAck(ack)) = c.next().await else {
        panic!("expected a CONNACK");
    };
    let p = ack.properties.unwrap();
    assert!(p.user_properties.is_empty());
    assert_eq!(p.response_information, None);

    // Topics from settings.
    let other = Env::start(MqttBrokerConfig {
        agent_topic_prefix: "cpe/".into(),
        ..MqttBrokerConfig::default()
    })
    .await;
    let (_a, ack) = other.agent("os::C").await;
    assert_eq!(
        ack.properties.unwrap().user_properties,
        vec![("subscribe-topic".to_owned(), "cpe/os::C".to_owned())]
    );
}

#[tokio::test]
async fn records_go_both_ways_through_the_agents_topic() {
    let mut env = Env::start(MqttBrokerConfig::default()).await;
    let (mut agent, _) = env.agent("os::A").await;
    let topic = "usp/agent/os::A";

    // Nowhere to send yet: no subscription, no reply topic.
    assert!(env.broker.send("os::A", vec![1]).await.is_err());
    agent
        .send(subscribe_packet(1, &[(topic, QoS::AtLeastOnce)]))
        .await;
    let Some(Packet::SubAck(ack)) = agent.next().await else {
        panic!("expected a SUBACK");
    };
    assert_eq!(
        (ack.pkid, ack.return_codes),
        (1, vec![SubscribeReasonCode::Success(QoS::AtLeastOnce)])
    );

    // Its MQTTConnectRecord, no Response Topic -> topic in the Record is used.
    agent
        .send(Packet::Publish(publish(
            CTRL_TOPIC,
            QoS::AtLeastOnce,
            7,
            hello("os::A", topic),
            None,
        )))
        .await;
    let Some(Packet::PubAck(ack)) = agent.next().await else {
        panic!("expected a PUBACK");
    };
    assert_eq!((ack.pkid, ack.reason), (7, PubAckReason::Success));
    let got = env.inbound().await;
    assert_eq!(got.topic, CTRL_TOPIC);
    assert_eq!(got.reply_to.as_deref(), Some("mqtt:os::A"));
    assert_eq!(got.sender.as_deref(), Some("os::A"));
    assert!(!got.closed && !got.opened);
    assert!(!got.payload.is_empty());
    assert_eq!(env.broker.connections(), 1);
    assert!(env.broker.peer_addr("os::A").unwrap().is_loopback());

    // Controller -> QoS 1 to Agent topic, Response Topic = Controller topic.
    env.broker.send("os::A", vec![9, 9, 9]).await.unwrap();
    let Some(Packet::Publish(p)) = agent.next().await else {
        panic!("expected a PUBLISH");
    };
    assert_eq!(&p.topic[..], topic.as_bytes());
    assert_eq!(p.qos, QoS::AtLeastOnce);
    assert!(p.pkid != 0 && !p.retain);
    assert_eq!(&p.payload[..], &[9, 9, 9]);
    let props = p.properties.unwrap();
    assert_eq!(props.content_type.as_deref(), Some("usp.msg"));
    assert_eq!(props.response_topic.as_deref(), Some(CTRL_TOPIC));
    agent.send(Packet::PubAck(PubAck::new(p.pkid, None))).await;

    // Response Topic of a later Record -> reply topic from then on.
    agent
        .send(subscribe_packet(2, &[("usp/agent/else", QoS::AtLeastOnce)]))
        .await;
    assert!(matches!(agent.next().await, Some(Packet::SubAck(_))));
    agent
        .send(Packet::Publish(publish(
            CTRL_TOPIC,
            QoS::AtMostOnce,
            0,
            vec![5],
            Some("usp/agent/else"),
        )))
        .await;
    env.inbound().await;
    env.broker.send("os::A", vec![1]).await.unwrap();
    let Some(Packet::Publish(p)) = agent.next().await else {
        panic!("expected a PUBLISH");
    };
    assert_eq!(&p.topic[..], b"usp/agent/else");

    // Not subscribed to that topic -> no send; same after unsubscribe.
    agent
        .send(Packet::Publish(publish(
            CTRL_TOPIC,
            QoS::AtMostOnce,
            0,
            vec![5],
            Some("usp/agent/nowhere"),
        )))
        .await;
    env.inbound().await;
    let e = env.broker.send("os::A", vec![1]).await.unwrap_err();
    assert!(e.to_string().contains("not subscribed"), "{e}");
    agent
        .send(Packet::Publish(publish(
            CTRL_TOPIC,
            QoS::AtMostOnce,
            0,
            vec![5],
            Some("usp/agent/else"),
        )))
        .await;
    env.inbound().await;
    agent
        .send(Packet::Unsubscribe(Unsubscribe {
            pkid: 3,
            filters: vec!["usp/agent/else".into(), "usp/agent/never".into()],
            properties: None,
        }))
        .await;
    let Some(Packet::UnsubAck(ack)) = agent.next().await else {
        panic!("expected an UNSUBACK");
    };
    assert_eq!(
        (ack.pkid, ack.reasons),
        (
            3,
            vec![
                UnsubAckReason::Success,
                UnsubAckReason::NoSubscriptionExisted
            ]
        )
    );
    assert!(env.broker.send("os::A", vec![1]).await.is_err());
    // Not connected.
    let e = env.broker.send("os::Z", vec![1]).await.unwrap_err();
    assert!(e.to_string().contains("no MQTT connection"), "{e}");
}

#[tokio::test]
async fn a_subscription_for_less_than_qos_1_gets_qos_0() {
    let mut env = Env::start(MqttBrokerConfig::default()).await;
    let (mut agent, _) = env.agent("os::A").await;
    agent
        .send(subscribe_packet(1, &[("usp/agent/os::A", QoS::AtMostOnce)]))
        .await;
    let Some(Packet::SubAck(ack)) = agent.next().await else {
        panic!("expected a SUBACK");
    };
    assert_eq!(
        ack.return_codes,
        vec![SubscribeReasonCode::Success(QoS::AtMostOnce)]
    );
    // CONNACK topic = default reply topic.
    agent
        .send(Packet::Publish(publish(
            CTRL_TOPIC,
            QoS::AtMostOnce,
            0,
            hello("os::A", "usp/agent/os::A"),
            None,
        )))
        .await;
    env.inbound().await;
    env.broker.send("os::A", vec![1]).await.unwrap();
    let Some(Packet::Publish(p)) = agent.next().await else {
        panic!("expected a PUBLISH");
    };
    assert_eq!((p.qos, p.pkid), (QoS::AtMostOnce, 0));
}

#[tokio::test]
async fn wildcard_and_shared_subscriptions_are_refused_and_qos_2_is_granted_as_1() {
    let env = Env::start(MqttBrokerConfig::default()).await;
    let (mut agent, _) = env.agent("os::A").await;
    agent
        .send(subscribe_packet(
            1,
            &[
                ("usp/agent/#", QoS::AtLeastOnce),
                ("usp/+/os::A", QoS::AtLeastOnce),
                ("$share/g/usp/agent/os::A", QoS::AtLeastOnce),
                ("usp/agent/os::A", QoS::ExactlyOnce),
                ("", QoS::AtLeastOnce),
            ],
        ))
        .await;
    let Some(Packet::SubAck(ack)) = agent.next().await else {
        panic!("expected a SUBACK");
    };
    assert_eq!(
        ack.return_codes,
        vec![
            SubscribeReasonCode::WildcardSubscriptionsNotSupported,
            SubscribeReasonCode::WildcardSubscriptionsNotSupported,
            SubscribeReasonCode::SharedSubscriptionsNotSupported,
            SubscribeReasonCode::Success(QoS::AtLeastOnce),
            SubscribeReasonCode::TopicFilterInvalid,
        ]
    );
    // Subscription Identifier -> refused too.
    agent
        .send(Packet::Subscribe(Subscribe {
            pkid: 2,
            filters: vec![Filter::new("usp/agent/x", QoS::AtLeastOnce)],
            properties: Some(SubscribeProperties {
                id: Some(5),
                user_properties: Vec::new(),
            }),
        }))
        .await;
    let Some(Packet::SubAck(ack)) = agent.next().await else {
        panic!("expected a SUBACK");
    };
    assert_eq!(
        ack.return_codes,
        vec![SubscribeReasonCode::SubscriptionIdNotSupported]
    );
    // Packet identifier 0 = protocol error.
    agent
        .send(subscribe_packet(0, &[("a", QoS::AtLeastOnce)]))
        .await;
    assert_eq!(
        agent.expect_disconnect().await,
        DisconnectReasonCode::ProtocolError
    );
}

#[tokio::test]
async fn too_many_subscriptions_are_refused() {
    let env = Env::start(MqttBrokerConfig::default()).await;
    let (mut agent, _) = env.agent("os::A").await;
    let topics: Vec<String> = (0..18).map(|i| format!("usp/agent/t{i}")).collect();
    let filters: Vec<(&str, QoS)> = topics
        .iter()
        .map(|t| (t.as_str(), QoS::AtLeastOnce))
        .collect();
    // Max 16 subscriptions per connection, in one SUBSCRIBE or several.
    agent.send(subscribe_packet(1, &filters[..10])).await;
    agent.send(subscribe_packet(2, &filters[10..16])).await;
    for (pkid, n) in [(1, 10), (2, 6)] {
        let Some(Packet::SubAck(ack)) = agent.next().await else {
            panic!("expected a SUBACK");
        };
        assert_eq!(ack.pkid, pkid);
        assert_eq!(ack.return_codes.len(), n);
        assert!(
            ack.return_codes
                .iter()
                .all(|c| matches!(c, SubscribeReasonCode::Success(_)))
        );
    }
    // 17th -> quota exceeded; one already held != new one.
    agent.send(subscribe_packet(3, &filters[16..17])).await;
    let Some(Packet::SubAck(ack)) = agent.next().await else {
        panic!("expected a SUBACK");
    };
    assert_eq!(ack.return_codes, vec![SubscribeReasonCode::QuotaExceeded]);
    agent.send(subscribe_packet(4, &filters[..1])).await;
    let Some(Packet::SubAck(ack)) = agent.next().await else {
        panic!("expected a SUBACK");
    };
    assert!(matches!(
        ack.return_codes[..],
        [SubscribeReasonCode::Success(_)]
    ));
    // > 16 filters in one packet -> not looked at, connection closed.
    agent.send(subscribe_packet(5, &filters)).await;
    assert_eq!(
        agent.expect_disconnect().await,
        DisconnectReasonCode::QuotaExceeded
    );
}

#[tokio::test]
async fn credentials_of_the_shared_account_are_checked() {
    let env = Env::start(MqttBrokerConfig {
        login: Some(("cpe".into(), "factory".into())),
        ..MqttBrokerConfig::default()
    })
    .await;
    let refused = |c: Packet| {
        let env = &env;
        async move {
            let mut conn = env.tcp().await;
            conn.send(c).await;
            let Some(Packet::ConnAck(ack)) = conn.next().await else {
                panic!("expected a CONNACK");
            };
            assert!(conn.next().await.is_none(), "closed after the refusal");
            ack
        }
    };
    let props = || Some(claim("os::A"));
    // Wrong password, wrong user, no credentials, password only.
    for (login, why) in [
        (Some(("cpe", "guess")), "password"),
        (Some(("root", "factory")), "user"),
        (None, "none"),
        (Some(("", "factory")), "password only"),
    ] {
        let ack = refused(connect_packet("c", 60, props(), login)).await;
        assert_eq!(ack.code, ConnectReturnCode::BadUserNamePassword, "{why}");
        assert!(ack.properties.unwrap().reason_string.is_some());
    }
    assert_eq!(env.broker.connections(), 0);

    // Right ones.
    let mut ok = env.tcp().await;
    ok.send(connect_packet("c", 60, props(), Some(("cpe", "factory"))))
        .await;
    let Some(Packet::ConnAck(ack)) = ok.next().await else {
        panic!("expected a CONNACK");
    };
    assert_eq!(ack.code, ConnectReturnCode::Success);

    // No account configured -> anybody accepted (with or without credentials).
    let open = Env::start(MqttBrokerConfig::default()).await;
    let mut c = open.tcp().await;
    c.send(connect_packet("c", 60, props(), Some(("who", "ever"))))
        .await;
    assert!(
        matches!(c.next().await, Some(Packet::ConnAck(a)) if a.code == ConnectReturnCode::Success)
    );
}

#[tokio::test]
async fn connect_is_checked() {
    let env = Env::start(MqttBrokerConfig::default()).await;
    // No enhanced authentication.
    let mut c = env.tcp().await;
    let mut props = claim("os::A");
    props.authentication_method = Some("SCRAM-SHA-1".into());
    c.send(connect_packet("c", 60, Some(props), None)).await;
    let Some(Packet::ConnAck(ack)) = c.next().await else {
        panic!("expected a CONNACK");
    };
    assert_eq!(ack.code, ConnectReturnCode::BadAuthenticationMethod);
    // Receive Maximum 0 = protocol error.
    let mut c = env.tcp().await;
    let mut props = claim("os::A");
    props.receive_maximum = Some(0);
    c.send(connect_packet("c", 60, Some(props), None)).await;
    let Some(Packet::ConnAck(ack)) = c.next().await else {
        panic!("expected a CONNACK");
    };
    assert_eq!(ack.code, ConnectReturnCode::ProtocolError);
    // EndpointID not valid as a topic level.
    let mut c = env.tcp().await;
    c.send(connect_packet("c", 60, Some(claim("os::a/b")), None))
        .await;
    let Some(Packet::ConnAck(ack)) = c.next().await else {
        panic!("expected a CONNACK");
    };
    assert_eq!(ack.code, ConnectReturnCode::NotAuthorized);
    // Will accepted + ignored.
    let mut c = env.tcp().await;
    let will = rumqttc::v5::mqttbytes::v5::LastWill::new(
        "will/topic",
        "bye",
        QoS::AtLeastOnce,
        true,
        None,
    );
    c.send(Packet::Connect(
        Connect {
            keep_alive: 60,
            client_id: "with-will".into(),
            clean_start: false,
            properties: Some(claim("os::W")),
        },
        Some(will),
        None,
    ))
    .await;
    let Some(Packet::ConnAck(ack)) = c.next().await else {
        panic!("expected a CONNACK");
    };
    assert_eq!(ack.code, ConnectReturnCode::Success);
    assert!(
        !ack.session_present,
        "no session is kept, whatever Clean Start says"
    );
    // Second CONNECT on the connection.
    c.send(connect_packet("again", 60, None, None)).await;
    assert_eq!(
        c.expect_disconnect().await,
        DisconnectReasonCode::ProtocolError
    );
}

#[tokio::test]
async fn mqtt_3_1_1_is_refused_in_a_connack_a_3_1_1_client_reads() {
    let env = Env::start(MqttBrokerConfig::default()).await;
    // CONNECT: "MQTT" level 4, clean session, keep alive 60, client id "c".
    let v311 = [
        0x10, 0x0D, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, b'c',
    ];
    let mut c = env.tcp().await;
    c.send_raw(&v311).await;
    let mut got = Vec::new();
    c.io.read_to_end(&mut got).await.unwrap();
    // Return code 1 = unsupported MQTT protocol level.
    assert_eq!(got, [0x20, 0x02, 0x00, 0x01]);
    // MQTT 3.1 (level 3, "MQIsdp") -> same.
    let v31 = [
        0x10, 0x0F, 0x00, 0x06, b'M', b'Q', b'I', b's', b'd', b'p', 0x03, 0x02, 0x00, 0x3C, 0x00,
        0x01, b'c',
    ];
    let mut c = env.tcp().await;
    c.send_raw(&v31).await;
    let mut got = Vec::new();
    c.io.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, [0x20, 0x02, 0x00, 0x01]);
    // Not MQTT at all -> just dropped.
    let mut c = env.tcp().await;
    c.send_raw(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    let mut got = Vec::new();
    c.io.read_to_end(&mut got).await.unwrap();
    assert!(got.is_empty());
    // First packet != CONNECT.
    let mut c = env.tcp().await;
    c.send(Packet::PingReq(PingReq)).await;
    assert!(c.next().await.is_none());
}

#[tokio::test]
async fn an_oversized_or_unreadable_connect_is_refused_before_anyone_is_authenticated() {
    let env = Env::start(MqttBrokerConfig::default()).await;
    // CONNECT > 100 KiB (limit before CONNACK = 64 KiB).
    let mut props = claim("os::A");
    props
        .user_properties
        .push(("pad".into(), "x".repeat(60_000)));
    props
        .user_properties
        .push(("pad2".into(), "x".repeat(60_000)));
    let mut c = env.tcp().await;
    c.send(connect_packet("c", 60, Some(props), None)).await;
    let Some(Packet::ConnAck(ack)) = c.next().await else {
        panic!("expected a CONNACK");
    };
    assert_eq!(ack.code, ConnectReturnCode::PacketTooLarge);
    // MQTT 5 CONNECT, bad protocol name.
    let mut c = env.tcp().await;
    c.send_raw(&[
        0x10, 0x0A, 0x00, 0x04, b'M', b'Q', b'T', b'X', 0x05, 0x02, 0x00, 0x3C, 0x00,
    ])
    .await;
    let mut got = Vec::new();
    c.io.read_to_end(&mut got).await.unwrap();
    assert!(got.is_empty() || got[0] == 0x20, "{got:?}");
}

#[tokio::test]
async fn publishing_anywhere_but_the_controller_topic_is_refused() {
    let mut env = Env::start(MqttBrokerConfig::default()).await;
    let (mut agent, _) = env.agent("os::A").await;
    let record = || hello("os::A", "usp/agent/os::A");
    // QoS 1 elsewhere -> refused in PUBACK, connection stays.
    for foreign in ["usp/agent/os::B", "usp/controller", "other"] {
        agent
            .send(Packet::Publish(publish(
                foreign,
                QoS::AtLeastOnce,
                4,
                record(),
                None,
            )))
            .await;
        let Some(Packet::PubAck(ack)) = agent.next().await else {
            panic!("expected a PUBACK");
        };
        assert_eq!(
            (ack.pkid, ack.reason),
            (4, PubAckReason::NotAuthorized),
            "{foreign}"
        );
    }
    // Wildcard != topic name.
    agent
        .send(Packet::Publish(publish(
            "usp/#",
            QoS::AtLeastOnce,
            5,
            record(),
            None,
        )))
        .await;
    let Some(Packet::PubAck(ack)) = agent.next().await else {
        panic!("expected a PUBACK");
    };
    assert_eq!(ack.reason, PubAckReason::TopicNameInvalid);
    // Controller topic of another Agent.
    agent
        .send(Packet::Publish(publish(
            &format!("{CTRL_TOPIC}/os::B"),
            QoS::AtLeastOnce,
            6,
            record(),
            None,
        )))
        .await;
    let Some(Packet::PubAck(ack)) = agent.next().await else {
        panic!("expected a PUBACK");
    };
    assert_eq!(ack.reason, PubAckReason::NotAuthorized);
    env.no_inbound().await;
    // Its own -> OK.
    agent
        .send(Packet::Publish(publish(
            &format!("{CTRL_TOPIC}/os::A"),
            QoS::AtLeastOnce,
            8,
            record(),
            None,
        )))
        .await;
    assert!(matches!(
        agent.next().await,
        Some(Packet::PubAck(a)) if a.reason == PubAckReason::Success
    ));
    let got = env.inbound().await;
    assert_eq!(got.topic, format!("{CTRL_TOPIC}/os::A"));
    assert_eq!(got.sender.as_deref(), Some("os::A"));
    // QoS 0 elsewhere -> no per-message answer possible -> connection closed.
    agent
        .send(Packet::Publish(publish(
            "usp/agent/os::B",
            QoS::AtMostOnce,
            0,
            record(),
            None,
        )))
        .await;
    assert_eq!(
        agent.expect_disconnect().await,
        DisconnectReasonCode::NotAuthorized
    );
    assert!(env.inbound().await.closed, "only the end of the connection");
    env.no_inbound().await;
}

#[tokio::test]
async fn qos_2_retain_topic_aliases_and_other_packets_are_refused() {
    let env = Env::start(MqttBrokerConfig::default()).await;
    let record = || hello("os::A", "usp/agent/os::A");
    let cases: Vec<(&str, Packet, DisconnectReasonCode)> = vec![
        (
            "QoS 2",
            Packet::Publish(publish(CTRL_TOPIC, QoS::ExactlyOnce, 1, record(), None)),
            DisconnectReasonCode::QoSNotSupported,
        ),
        (
            "retain",
            Packet::Publish(Publish {
                retain: true,
                ..publish(CTRL_TOPIC, QoS::AtMostOnce, 0, record(), None)
            }),
            DisconnectReasonCode::RetainNotSupported,
        ),
        (
            "topic alias",
            Packet::Publish(Publish {
                properties: Some(PublishProperties {
                    topic_alias: Some(1),
                    ..PublishProperties::default()
                }),
                ..publish(CTRL_TOPIC, QoS::AtMostOnce, 0, record(), None)
            }),
            DisconnectReasonCode::TopicAliasInvalid,
        ),
        (
            "subscription identifier",
            Packet::Publish(Publish {
                properties: Some(PublishProperties {
                    subscription_identifiers: vec![3],
                    ..PublishProperties::default()
                }),
                ..publish(CTRL_TOPIC, QoS::AtMostOnce, 0, record(), None)
            }),
            DisconnectReasonCode::ProtocolError,
        ),
        (
            "PUBREL",
            Packet::PubRel(rumqttc::v5::mqttbytes::v5::PubRel::new(1, None)),
            DisconnectReasonCode::ProtocolError,
        ),
        (
            "PUBREC",
            Packet::PubRec(rumqttc::v5::mqttbytes::v5::PubRec::new(1, None)),
            DisconnectReasonCode::ProtocolError,
        ),
        (
            "PUBCOMP",
            Packet::PubComp(rumqttc::v5::mqttbytes::v5::PubComp::new(1, None)),
            DisconnectReasonCode::ProtocolError,
        ),
        (
            "PINGRESP",
            Packet::PingResp(rumqttc::v5::mqttbytes::v5::PingResp),
            DisconnectReasonCode::ProtocolError,
        ),
    ];
    for (what, packet, expected) in cases {
        let (mut agent, _) = env.agent("os::A").await;
        agent.send(packet).await;
        assert_eq!(agent.expect_disconnect().await, expected, "{what}");
    }
    // AUTH (type 15) + reserved bits, as raw bytes.
    for (what, raw, expected) in [
        (
            "AUTH",
            vec![0xF0, 0x00],
            DisconnectReasonCode::ProtocolError,
        ),
        (
            "reserved flags",
            vec![0xC1, 0x00],
            DisconnectReasonCode::MalformedPacket,
        ),
        (
            "reserved type",
            vec![0x00, 0x00],
            DisconnectReasonCode::MalformedPacket,
        ),
        (
            "QoS 3",
            vec![0x36, 0x04, 0x00, 0x01, b'a', 0x00],
            DisconnectReasonCode::MalformedPacket,
        ),
        (
            "too large",
            vec![0x30, 0xFF, 0xFF, 0xFF, 0x7F],
            DisconnectReasonCode::PacketTooLarge,
        ),
    ] {
        let (mut agent, _) = env.agent("os::A").await;
        agent.send_raw(&raw).await;
        assert_eq!(agent.expect_disconnect().await, expected, "{what}");
    }
}

#[tokio::test]
async fn the_sender_is_the_connections_identity_whatever_a_record_says() {
    let mut env = Env::start(MqttBrokerConfig::default()).await;
    let (mut agent, _) = env.agent("os::A").await;
    agent
        .send(subscribe_packet(
            1,
            &[
                ("usp/agent/os::A", QoS::AtLeastOnce),
                ("usp/agent/os::B", QoS::AtLeastOnce),
            ],
        ))
        .await;
    assert!(matches!(agent.next().await, Some(Packet::SubAck(_))));
    agent
        .send(Packet::Publish(publish(
            CTRL_TOPIC,
            QoS::AtMostOnce,
            0,
            hello("os::A", "usp/agent/os::A"),
            None,
        )))
        .await;
    assert_eq!(env.inbound().await.sender.as_deref(), Some("os::A"));
    // Later Record claiming another sender -> still os::A's;
    // Controller compares the two + drops it (ADR-087).
    agent
        .send(Packet::Publish(publish(
            CTRL_TOPIC,
            QoS::AtMostOnce,
            0,
            hello("os::B", "usp/agent/os::B"),
            None,
        )))
        .await;
    let got = env.inbound().await;
    assert_eq!(got.sender.as_deref(), Some("os::A"));
    assert_eq!(got.reply_to.as_deref(), Some("mqtt:os::A"));
    // Its topic claims not believed -> replies still go where os::A said.
    env.broker.send("os::A", vec![1]).await.unwrap();
    let Some(Packet::Publish(p)) = agent.next().await else {
        panic!("expected a PUBLISH");
    };
    assert_eq!(&p.topic[..], b"usp/agent/os::A");

    // First Record not from the claimed EndpointID -> connection closed.
    let (mut liar, _) = env.agent("os::C").await;
    liar.send(Packet::Publish(publish(
        CTRL_TOPIC,
        QoS::AtMostOnce,
        0,
        hello("os::D", "usp/agent/os::D"),
        None,
    )))
    .await;
    assert_eq!(
        liar.expect_disconnect().await,
        DisconnectReasonCode::NotAuthorized
    );
    // Controller gets nothing of it but the end of the claimed connection.
    let end = env.inbound().await;
    assert!(end.closed && end.reply_to.as_deref() == Some("mqtt:os::C"));
    env.no_inbound().await;
}

#[tokio::test]
async fn a_client_that_names_nobody_at_connect_is_named_by_its_first_record() {
    let mut env = Env::start(MqttBrokerConfig::default()).await;
    let mut c = env.tcp().await;
    c.send(connect_packet("nameless", 60, None, None)).await;
    let Some(Packet::ConnAck(ack)) = c.next().await else {
        panic!("expected a CONNACK");
    };
    assert!(ack.properties.unwrap().user_properties.is_empty());
    assert_eq!(env.broker.connections(), 0, "not yet known");
    c.send(subscribe_packet(1, &[("my/own/topic", QoS::AtLeastOnce)]))
        .await;
    assert!(matches!(c.next().await, Some(Packet::SubAck(_))));
    // Its own Controller topic names another EndpointID than the Record -> refused.
    c.send(Packet::Publish(publish(
        &format!("{CTRL_TOPIC}/os::Y"),
        QoS::AtLeastOnce,
        1,
        hello("os::X", "my/own/topic"),
        Some("my/own/topic"),
    )))
    .await;
    assert_eq!(
        c.expect_disconnect().await,
        DisconnectReasonCode::NotAuthorized
    );

    // Garbage names nobody.
    let mut c = env.tcp().await;
    c.send(connect_packet("nameless", 60, None, None)).await;
    assert!(matches!(c.next().await, Some(Packet::ConnAck(_))));
    c.send(Packet::Publish(publish(
        CTRL_TOPIC,
        QoS::AtLeastOnce,
        1,
        vec![0xFF, 0xFF, 0xFF],
        None,
    )))
    .await;
    assert_eq!(
        c.expect_disconnect().await,
        DisconnectReasonCode::PayloadFormatInvalid
    );

    // Good one does.
    let mut c = env.tcp().await;
    c.send(connect_packet("nameless", 60, None, None)).await;
    assert!(matches!(c.next().await, Some(Packet::ConnAck(_))));
    c.send(subscribe_packet(1, &[("my/own/topic", QoS::AtLeastOnce)]))
        .await;
    assert!(matches!(c.next().await, Some(Packet::SubAck(_))));
    c.send(Packet::Publish(publish(
        CTRL_TOPIC,
        QoS::AtLeastOnce,
        2,
        hello("os::X", "my/own/topic"),
        Some("my/own/topic"),
    )))
    .await;
    assert!(matches!(c.next().await, Some(Packet::PubAck(_))));
    let got = env.inbound().await;
    assert_eq!(got.sender.as_deref(), Some("os::X"));
    assert_eq!(got.reply_to.as_deref(), Some("mqtt:os::X"));
    assert_eq!(env.broker.connections(), 1);
    env.broker.send("os::X", vec![4]).await.unwrap();
    let Some(Packet::Publish(p)) = c.next().await else {
        panic!("expected a PUBLISH");
    };
    assert_eq!(&p.topic[..], b"my/own/topic");
}

#[tokio::test]
async fn a_new_connection_of_an_agent_takes_over_from_the_old_one() {
    let mut env = Env::start(MqttBrokerConfig::default()).await;
    let (mut old, _) = env.agent("os::A").await;
    old.send(subscribe_packet(
        1,
        &[("usp/agent/os::A", QoS::AtLeastOnce)],
    ))
    .await;
    assert!(matches!(old.next().await, Some(Packet::SubAck(_))));
    // Send result = serial of the connection that took it.
    let old_serial = env.broker.send("os::A", vec![0]).await.unwrap();
    assert!(matches!(old.next().await, Some(Packet::Publish(_))));
    let (mut new, _) = env.agent("os::A").await;
    assert_eq!(
        old.expect_disconnect().await,
        DisconnectReasonCode::SessionTakenOver
    );
    // Old connection end != Agent end: new one goes on, Controller not told Agent is gone.
    // No "replaced" notice yet either: Controller Record on it -> refused (not subscribed).
    env.no_inbound().await;
    assert_eq!(env.broker.connections(), 1);
    assert!(env.broker.send("os::A", vec![1]).await.is_err());
    new.send(subscribe_packet(
        1,
        &[("usp/agent/os::A", QoS::AtLeastOnce)],
    ))
    .await;
    assert!(matches!(new.next().await, Some(Packet::SubAck(_))));
    // Now the notice, with new connection serial -> Records sent over the old one
    // (smaller serial) get no answer.
    let replaced = env.inbound().await;
    assert!(!replaced.closed);
    assert_eq!(replaced.reply_to.as_deref(), Some("mqtt:os::A"));
    assert_eq!(replaced.sender.as_deref(), Some("os::A"));
    assert!(replaced.payload.is_empty());
    let new_serial = env.broker.send("os::A", vec![1]).await.unwrap();
    assert!(matches!(new.next().await, Some(Packet::Publish(_))));
    assert_eq!(replaced.replaced_by, Some(new_serial));
    assert!(old_serial < new_serial);
    env.no_inbound().await;
    // Its own end = Agent end.
    drop(new);
    let closed = env.inbound().await;
    assert!(closed.closed);
    assert_eq!(closed.reply_to.as_deref(), Some("mqtt:os::A"));
    assert_eq!(closed.sender.as_deref(), Some("os::A"));
}

#[tokio::test]
async fn a_silent_agent_is_closed_after_one_and_a_half_keep_alives() {
    let mut env = Env::start(MqttBrokerConfig::default()).await;
    let mut agent = env.tcp().await;
    agent
        .send(connect_packet("quiet", 1, Some(claim("os::Q")), None))
        .await;
    assert!(matches!(agent.next().await, Some(Packet::ConnAck(_))));
    // Pings -> alive well past 1.5 s.
    let start = tokio::time::Instant::now();
    let mut last_ping = start;
    while start.elapsed() < Duration::from_millis(2500) {
        agent.send(Packet::PingReq(PingReq)).await;
        last_ping = tokio::time::Instant::now();
        assert!(matches!(agent.next().await, Some(Packet::PingResp(_))));
        tokio::time::sleep(Duration::from_millis(700)).await;
    }
    assert_eq!(env.broker.connections(), 1);
    // Silence -> close with 0x8D 1.5 s after last packet, Controller told.
    assert_eq!(
        agent.expect_disconnect().await,
        DisconnectReasonCode::KeepAliveTimeout
    );
    let took = last_ping.elapsed();
    assert!(
        took >= Duration::from_millis(1400) && took < Duration::from_millis(2300),
        "closed {took:?} after the last packet"
    );
    let closed = env.inbound().await;
    assert!(closed.closed);
    assert_eq!(env.broker.connections(), 0);
}

#[tokio::test]
async fn a_closed_connection_is_known_at_once_and_its_last_word_is_kept() {
    let mut env = Env::start(MqttBrokerConfig::default()).await;
    let (mut agent, _) = env.agent("os::A").await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let idle = env.broker.last_heard("os::A").unwrap();
    assert!(ago(idle) >= Duration::from_secs(1), "idle: heard {idle:?}");
    assert_eq!(env.broker.heard_from().len(), 1);
    // PINGREQ = heard from Agent. `Heard` stamps whole ms -> compare in whole ms too
    // (else stamp up to 1 ms before `sent` -> fails now and then).
    let sent = {
        let now = SystemTime::now();
        let ms = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        SystemTime::UNIX_EPOCH + Duration::from_millis(u64::try_from(ms).unwrap())
    };
    agent.send(Packet::PingReq(PingReq)).await;
    assert!(matches!(agent.next().await, Some(Packet::PingResp(_))));
    let heard = poll("the ping to count", || {
        env.broker.last_heard("os::A").filter(|t| *t >= sent)
    })
    .await;
    // Goodbye like libmosquitto: DISCONNECT with no reason code at all.
    agent.send_raw(&[0xE0, 0x00]).await;
    let closed = env.inbound().await;
    assert!(closed.closed && closed.reply_to.as_deref() == Some("mqtt:os::A"));
    assert!(env.broker.last_heard("os::A").is_none());
    assert!(env.broker.heard_from().is_empty());
    let finale = env.broker.take_final_heard("os::A").unwrap();
    assert!(finale >= heard, "the final time is the last thing heard");
    assert_eq!(env.broker.take_final_heard("os::A"), None);

    // Socket drop -> same close.
    let (agent, _) = env.agent("os::B").await;
    drop(agent);
    assert!(env.inbound().await.closed);
}

#[tokio::test]
async fn the_agent_is_heard_from_through_multi_mtp() {
    let (tx, mut inbound) = mpsc::channel(8);
    let broker = MqttBrokerMtp::new(tx, MqttBrokerConfig::default());
    let multi = MultiMtp {
        mqtt_broker: Some(broker.clone()),
        ..MultiMtp::default()
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = broker.clone();
    tokio::spawn(async move {
        serving
            .serve(listener, None, std::future::pending())
            .await
            .unwrap()
    });
    let mut agent = Raw::new(tokio::net::TcpStream::connect(addr).await.unwrap());
    agent
        .send(connect_packet("c", 60, Some(claim("os::A")), None))
        .await;
    assert!(matches!(agent.next().await, Some(Packet::ConnAck(_))));
    assert!(MultiMtp::is_connection_address("mqtt:os::A"));
    assert!(multi.peer_addr("os::A").unwrap().is_loopback());
    assert!(multi.heard_from().contains_key("os::A"));
    // Address routes to the broker; unsubscribed Agent -> error, not a topic on another broker.
    let e = multi.send("mqtt:os::A", vec![1]).await.unwrap_err();
    assert!(e.to_string().contains("not subscribed"), "{e}");
    // Acceptance policy rejects an Agent via `disconnect`.
    assert!(multi.disconnect("os::A"));
    assert!(!multi.disconnect("os::none"));
    assert_eq!(
        agent.expect_disconnect().await,
        DisconnectReasonCode::NotAuthorized
    );
    assert!(inbound.recv().await.unwrap().closed);
    assert!(multi.take_final_heard("os::A").is_some());
}

#[tokio::test]
async fn the_agents_receive_maximum_limits_unacknowledged_records() {
    let env = Env::start(MqttBrokerConfig::default()).await;
    let mut agent = env.tcp().await;
    let mut props = claim("os::A");
    props.receive_maximum = Some(1);
    agent.send(connect_packet("c", 60, Some(props), None)).await;
    assert!(matches!(agent.next().await, Some(Packet::ConnAck(_))));
    agent
        .send(Packet::Publish(publish(
            CTRL_TOPIC,
            QoS::AtMostOnce,
            0,
            hello("os::A", "usp/agent/os::A"),
            Some("usp/agent/os::A"),
        )))
        .await;
    agent
        .send(subscribe_packet(
            1,
            &[("usp/agent/os::A", QoS::AtLeastOnce)],
        ))
        .await;
    assert!(matches!(agent.next().await, Some(Packet::SubAck(_))));
    env.broker.send("os::A", vec![1]).await.unwrap();
    env.broker.send("os::A", vec![2]).await.unwrap();
    env.broker.send("os::A", vec![3]).await.unwrap();
    // One at a time, each after the PUBACK of the one before.
    for expected in [1u8, 2, 3] {
        let Some(Packet::Publish(p)) = agent.next().await else {
            panic!("expected a PUBLISH");
        };
        assert_eq!(&p.payload[..], &[expected]);
        assert!(
            agent.next_within(Duration::from_millis(300)).await.is_err(),
            "the next waits for the PUBACK"
        );
        agent.send(Packet::PubAck(PubAck::new(p.pkid, None))).await;
    }
}

#[tokio::test]
async fn a_record_bigger_than_the_agents_maximum_packet_size_is_not_sent() {
    let env = Env::start(MqttBrokerConfig::default()).await;
    let mut agent = env.tcp().await;
    let mut props = claim("os::A");
    props.max_packet_size = Some(200);
    agent.send(connect_packet("c", 60, Some(props), None)).await;
    assert!(matches!(agent.next().await, Some(Packet::ConnAck(_))));
    agent
        .send(subscribe_packet(
            1,
            &[("usp/agent/os::A", QoS::AtLeastOnce)],
        ))
        .await;
    assert!(matches!(agent.next().await, Some(Packet::SubAck(_))));
    // CONNACK topic = reply topic until the Agent says otherwise.
    env.broker.send("os::A", vec![0; 50]).await.unwrap();
    assert!(matches!(agent.next().await, Some(Packet::Publish(_))));
    let e = env.broker.send("os::A", vec![0; 300]).await.unwrap_err();
    assert!(e.to_string().contains("Maximum Packet Size"), "{e}");
}

#[tokio::test]
async fn records_up_to_the_packet_limit_pass() {
    let mut env = Env::start(MqttBrokerConfig::default()).await;
    let (mut agent, _) = env.agent("os::A").await;
    agent
        .send(Packet::Publish(publish(
            CTRL_TOPIC,
            QoS::AtLeastOnce,
            1,
            hello("os::A", "usp/agent/os::A"),
            None,
        )))
        .await;
    assert!(matches!(agent.next().await, Some(Packet::PubAck(_))));
    env.inbound().await;
    // 5 MiB: > any default, < 8 MiB promised in CONNACK.
    let big = vec![0xAB; 5 * 1024 * 1024];
    agent
        .send(Packet::Publish(publish(
            CTRL_TOPIC,
            QoS::AtLeastOnce,
            2,
            big.clone(),
            None,
        )))
        .await;
    assert!(matches!(agent.next().await, Some(Packet::PubAck(_))));
    assert_eq!(env.inbound().await.payload.len(), big.len());
    // Other direction.
    agent
        .send(subscribe_packet(
            3,
            &[("usp/agent/os::A", QoS::AtLeastOnce)],
        ))
        .await;
    assert!(matches!(agent.next().await, Some(Packet::SubAck(_))));
    env.broker.send("os::A", big.clone()).await.unwrap();
    let Some(Packet::Publish(p)) = agent.next().await else {
        panic!("expected a PUBLISH");
    };
    assert_eq!(p.payload.len(), big.len());
}

#[tokio::test]
async fn rumqttc_works_as_an_agent() {
    use rumqttc::v5::{AsyncClient, Event, MqttOptions};
    let mut env = Env::start(MqttBrokerConfig {
        login: Some(("cpe".into(), "factory".into())),
        ..MqttBrokerConfig::default()
    })
    .await;
    let mut opts = MqttOptions::new("agent-client", "127.0.0.1", env.addr.port());
    opts.set_credentials("cpe", "factory");
    opts.set_keep_alive(Duration::from_secs(30));
    opts.set_clean_start(true);
    opts.set_connect_properties(claim("os::R"));
    let (client, mut eventloop) = AsyncClient::new(opts, 16);
    let (got_tx, mut got) = mpsc::channel(8);
    tokio::spawn(async move {
        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(Packet::ConnAck(ack))) => {
                    let topic = ack.properties.unwrap().user_properties[0].1.clone();
                    client
                        .subscribe(topic.clone(), QoS::AtLeastOnce)
                        .await
                        .unwrap();
                    client
                        .publish_with_properties(
                            CTRL_TOPIC,
                            QoS::AtLeastOnce,
                            false,
                            hello("os::R", &topic),
                            PublishProperties {
                                response_topic: Some(topic),
                                content_type: Some("usp.msg".into()),
                                ..PublishProperties::default()
                            },
                        )
                        .await
                        .unwrap();
                }
                Ok(Event::Incoming(Packet::Publish(p))) => {
                    let _ = got_tx.send(p).await;
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });
    let hello_in = env.inbound().await;
    assert_eq!(hello_in.sender.as_deref(), Some("os::R"));
    env.broker.send("os::R", vec![7, 7]).await.unwrap();
    let p = tokio::time::timeout(Duration::from_secs(5), got.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&p.payload[..], &[7, 7]);
    assert_eq!(&p.topic[..], b"usp/agent/os::R");
}

// --- TLS ---

fn agent_cert(ca: &Ca, eid: &str) -> Issued {
    ca.issue(&Profile {
        endpoint_id: eid.into(),
        days: 1,
        ..Profile::default()
    })
    .unwrap()
}

fn client_config(ca: &Ca, agent: Option<&Issued>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(ca.cert_pem().as_bytes()).unwrap())
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    let mut config = match agent {
        Some(a) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from_pem_slice(a.cert_pem.as_bytes()).unwrap()],
                PrivateKeyDer::from_pem_slice(a.key_pem.as_deref().unwrap().as_bytes()).unwrap(),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    // MQTT clients may offer own ALPN protocol; listener has none to agree on.
    config.alpn_protocols = vec![b"mqtt".to_vec()];
    Arc::new(config)
}

async fn tls_client(
    addr: std::net::SocketAddr,
    config: Arc<rustls::ClientConfig>,
) -> Raw<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(config)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    Raw::new(tls)
}

#[tokio::test]
async fn mqtt_over_tls_binds_connections_to_certificate_endpoint_ids() {
    let ca = Ca::generate("Test USP CA").unwrap();
    let server = ca
        .issue(&Profile {
            endpoint_id: "self::ctrl".into(),
            dns_names: vec!["localhost".into()],
            server: true,
            days: 1,
            ..Profile::default()
        })
        .unwrap();
    // Client certificates optional, as on wss.
    let acceptor = tls_acceptor(
        &server.cert_pem,
        server.key_pem.as_deref().unwrap(),
        Some(ca.cert_pem()),
        false,
    )
    .unwrap();
    let mut env = Env::start_with(MqttBrokerConfig::default(), Some(acceptor)).await;

    // Certificate names the Agent -> CONNACK has its topic, no claim needed.
    let alice = agent_cert(&ca, "os::alice");
    let mut c = tls_client(env.addr, client_config(&ca, Some(&alice))).await;
    c.send(connect_packet("c", 60, None, None)).await;
    let Some(Packet::ConnAck(ack)) = c.next().await else {
        panic!("expected a CONNACK");
    };
    assert_eq!(ack.code, ConnectReturnCode::Success);
    assert_eq!(
        ack.properties.unwrap().user_properties,
        vec![(
            "subscribe-topic".to_owned(),
            "usp/agent/os::alice".to_owned()
        )]
    );
    c.send(subscribe_packet(
        1,
        &[("usp/agent/os::alice", QoS::AtLeastOnce)],
    ))
    .await;
    assert!(matches!(c.next().await, Some(Packet::SubAck(_))));
    c.send(Packet::Publish(publish(
        CTRL_TOPIC,
        QoS::AtLeastOnce,
        1,
        hello("os::alice", "usp/agent/os::alice"),
        None,
    )))
    .await;
    assert!(matches!(c.next().await, Some(Packet::PubAck(_))));
    let got = env.inbound().await;
    assert_eq!(got.sender.as_deref(), Some("os::alice"));
    env.broker.send("os::alice", vec![3]).await.unwrap();
    assert!(matches!(c.next().await, Some(Packet::Publish(_))));
    assert!(env.broker.peer_addr("os::alice").unwrap().is_loopback());

    // Alice's certificate != Bob, in claim or in first Record.
    let mut c = tls_client(env.addr, client_config(&ca, Some(&alice))).await;
    c.send(connect_packet("c", 60, Some(claim("os::bob")), None))
        .await;
    let Some(Packet::ConnAck(ack)) = c.next().await else {
        panic!("expected a CONNACK");
    };
    assert_eq!(ack.code, ConnectReturnCode::NotAuthorized);
    // Take over her connection with her certificate -> OK; as Bob -> not.
    let mut c = tls_client(env.addr, client_config(&ca, Some(&alice))).await;
    c.send(connect_packet("c2", 60, None, None)).await;
    assert!(matches!(c.next().await, Some(Packet::ConnAck(_))));
    c.send(Packet::Publish(publish(
        CTRL_TOPIC,
        QoS::AtMostOnce,
        0,
        hello("os::bob", "usp/agent/os::bob"),
        None,
    )))
    .await;
    assert_eq!(
        c.expect_disconnect().await,
        DisconnectReasonCode::NotAuthorized
    );

    // No certificate -> claim stands (like STOMP endpoint-id with shared login).
    let mut c = tls_client(env.addr, client_config(&ca, None)).await;
    c.send(connect_packet("c3", 60, Some(claim("os::carol")), None))
        .await;
    let Some(Packet::ConnAck(ack)) = c.next().await else {
        panic!("expected a CONNACK");
    };
    assert_eq!(ack.code, ConnectReturnCode::Success);
    // Alice's connections gone (first taken over, last closed on Bob's Record).
    assert_eq!(env.broker.connections(), 1);
}

// --- Resource limits (M-6) and stalled Agents (H-4) -------------------------------------

/// New connection closed at accept? CONNECT (any part of it) -> only connection end.
async fn refused_at_accept(env: &Env) -> bool {
    let mut c = env.tcp().await;
    let mut wire = BytesMut::new();
    connect_packet("c", 60, Some(claim("os::probe")), None)
        .write(&mut wire, None)
        .unwrap();
    // Broker may have closed the socket already.
    let _ = c.io.write_all(&wire).await;
    matches!(c.next_within(Duration::from_secs(2)).await, Ok(None))
}

/// Connection accepted (+ answered) once a slot is free again.
async fn accepted_eventually(env: &Env) -> Raw<tokio::net::TcpStream> {
    let mut wire = BytesMut::new();
    connect_packet("c", 60, Some(claim("os::probe")), None)
        .write(&mut wire, None)
        .unwrap();
    for _ in 0..100 {
        let mut c = env.tcp().await;
        let _ = c.io.write_all(&wire).await;
        if let Ok(Some(Packet::ConnAck(_))) = c.next_within(Duration::from_secs(2)).await {
            return c;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no free slot");
}

#[tokio::test]
async fn connections_over_the_per_address_cap_are_closed_at_accept() {
    // All clients from loopback = one address.
    let env = Env::start(MqttBrokerConfig {
        max_connections_per_ip: 2,
        ..MqttBrokerConfig::default()
    })
    .await;
    let (a, _) = env.agent("os::A").await;
    let (_b, _) = env.agent("os::B").await;
    assert!(refused_at_accept(&env).await, "a third connection");
    assert!(refused_at_accept(&env).await, "and a fourth");
    assert_eq!(env.broker.connections(), 2);
    // Connection end -> slot free.
    drop(a);
    let _c = accepted_eventually(&env).await;
}

#[tokio::test]
async fn connections_over_the_global_cap_are_closed_at_accept() {
    let env = Env::start(MqttBrokerConfig {
        max_connections: 1,
        max_connections_per_ip: 0,
        ..MqttBrokerConfig::default()
    })
    .await;
    let (a, _) = env.agent("os::A").await;
    assert!(refused_at_accept(&env).await);
    drop(a);
    let _b = accepted_eventually(&env).await;
    // 0 = no cap.
    let env = Env::start(MqttBrokerConfig {
        max_connections: 0,
        max_connections_per_ip: 0,
        ..MqttBrokerConfig::default()
    })
    .await;
    let mut held = Vec::new();
    for i in 0..30 {
        held.push(env.agent(&format!("os::{i}")).await);
    }
}

#[tokio::test]
async fn a_big_control_packet_is_refused_from_its_header() {
    let env = Env::start(MqttBrokerConfig::default()).await;
    let (mut agent, _) = env.agent("os::A").await;
    // SUBSCRIBE with length 100 000 bytes -> refused at once, rest never sent
    // (nothing buffered).
    agent.send_raw(&[0x82, 0xA0, 0x8D, 0x06]).await;
    assert_eq!(
        agent.expect_disconnect().await,
        DisconnectReasonCode::PacketTooLarge
    );
    // PUBLISH (Record) of same size -> waited for.
    let (mut agent, _) = env.agent("os::B").await;
    agent.send_raw(&[0x30, 0xA0, 0x8D, 0x06]).await;
    assert!(
        agent.next_within(Duration::from_millis(300)).await.is_err(),
        "the broker waits for the rest of a big PUBLISH"
    );
}

#[tokio::test]
async fn a_packet_with_too_many_filters_or_properties_is_refused() {
    let env = Env::start(MqttBrokerConfig::default()).await;
    // 16 filters -> OK (all granted) ...
    let (mut agent, _) = env.agent("os::A").await;
    let names: Vec<String> = (0..16).map(|i| format!("usp/agent/os::A/{i}")).collect();
    let filters: Vec<(&str, QoS)> = names
        .iter()
        .map(|n| (n.as_str(), QoS::AtLeastOnce))
        .collect();
    agent.send(subscribe_packet(1, &filters)).await;
    let Some(Packet::SubAck(ack)) = agent.next().await else {
        panic!("expected a SUBACK");
    };
    assert_eq!(ack.return_codes.len(), 16);
    // ... 17 -> quota exceeded, as SUBSCRIBE ...
    let (mut agent, _) = env.agent("os::B").await;
    let names: Vec<String> = (0..17).map(|i| format!("usp/agent/os::B/{i}")).collect();
    let filters: Vec<(&str, QoS)> = names
        .iter()
        .map(|n| (n.as_str(), QoS::AtLeastOnce))
        .collect();
    agent.send(subscribe_packet(1, &filters)).await;
    assert_eq!(
        agent.expect_disconnect().await,
        DisconnectReasonCode::QuotaExceeded
    );
    // ... and as UNSUBSCRIBE.
    let (mut agent, _) = env.agent("os::C").await;
    agent
        .send(Packet::Unsubscribe(Unsubscribe {
            pkid: 1,
            filters: names.clone(),
            properties: None,
        }))
        .await;
    assert_eq!(
        agent.expect_disconnect().await,
        DisconnectReasonCode::QuotaExceeded
    );
    // 1000s of user properties on a PUBLISH (2 strings each) -> not decoded at all.
    let (mut agent, _) = env.agent("os::D").await;
    let mut p = publish(
        CTRL_TOPIC,
        QoS::AtLeastOnce,
        1,
        hello("os::D", "usp/agent/os::D"),
        None,
    );
    p.properties.as_mut().unwrap().user_properties = (0..5000)
        .map(|_| ("k".to_owned(), "v".to_owned()))
        .collect();
    agent.send(Packet::Publish(p)).await;
    assert_eq!(
        agent.expect_disconnect().await,
        DisconnectReasonCode::QuotaExceeded
    );
    // Neither reached the Controller; ordinary Agent Record still does.
    let (mut agent, _) = env.agent("os::E").await;
    agent
        .send(Packet::Publish(publish(
            CTRL_TOPIC,
            QoS::AtLeastOnce,
            1,
            hello("os::E", "usp/agent/os::E"),
            None,
        )))
        .await;
    assert!(matches!(agent.next().await, Some(Packet::PubAck(_))));
}

#[tokio::test]
async fn a_long_keep_alive_is_replaced_by_the_limit() {
    let env = Env::start(MqttBrokerConfig::default()).await;
    let connack = |keep_alive: u16| {
        let env = &env;
        async move {
            let mut c = env.tcp().await;
            c.send(connect_packet("c", keep_alive, Some(claim("os::A")), None))
                .await;
            let Some(Packet::ConnAck(ack)) = c.next().await else {
                panic!("expected a CONNACK");
            };
            ack.properties.unwrap().server_keep_alive
        }
    };
    // 18 h -> 20 min; allowed value stays (not told); 0 -> 60 s.
    assert_eq!(connack(u16::MAX).await, Some(1200));
    assert_eq!(connack(1201).await, Some(1200));
    assert_eq!(connack(1200).await, None);
    assert_eq!(connack(30).await, None);
    assert_eq!(connack(0).await, Some(60));

    // Idle limit = 1.5 x the limit, not 1.5 x 18 h.
    let env = Env::start(MqttBrokerConfig {
        max_keep_alive: 1,
        ..MqttBrokerConfig::default()
    })
    .await;
    let mut agent = env.tcp().await;
    agent
        .send(connect_packet("c", 1000, Some(claim("os::A")), None))
        .await;
    let Some(Packet::ConnAck(ack)) = agent.next().await else {
        panic!("expected a CONNACK");
    };
    assert_eq!(ack.properties.unwrap().server_keep_alive, Some(1));
    let started = tokio::time::Instant::now();
    assert_eq!(
        agent.expect_disconnect().await,
        DisconnectReasonCode::KeepAliveTimeout
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_packet_must_arrive_in_time_however_many_bytes_trickle_in() {
    let env = Env::start(MqttBrokerConfig {
        partial_packet_timeout: Duration::from_secs(1),
        ..MqttBrokerConfig::default()
    })
    .await;
    let (mut agent, _) = env.agent("os::A").await;
    // Idle connection != late packet: this ping comes after > the silence limit.
    tokio::time::sleep(Duration::from_millis(1300)).await;
    agent.send(Packet::PingReq(PingReq)).await;
    assert!(matches!(agent.next().await, Some(Packet::PingResp(_))));

    // PUBLISH of 100 bytes, rest 1 byte at a time: each byte = "life",
    // but packet not complete 1 s after its first byte.
    let started = tokio::time::Instant::now();
    agent.send_raw(&[0x30, 100]).await;
    let reason = loop {
        match agent.next_within(Duration::from_millis(200)).await {
            Err(_) => agent.send_raw(&[0]).await,
            Ok(Some(Packet::Disconnect(d))) => break d.reason_code,
            other => panic!("{other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(5), "still open");
    };
    assert_eq!(reason, DisconnectReasonCode::UnspecifiedError);
    assert!(
        started.elapsed() >= Duration::from_millis(900)
            && started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert!(agent.next().await.is_none(), "the connection closes");
}

/// Agent with Receive Maximum 1 + no PUBACK -> stalls only its own connection:
/// sends to it fail at once when its queue is full, sends to others go through at once,
/// connection closed when window full too long.
#[tokio::test]
async fn an_agent_that_never_acknowledges_does_not_hold_up_others_and_is_closed() {
    let mut env = Env::start(MqttBrokerConfig {
        ack_timeout: Duration::from_secs(1),
        ..MqttBrokerConfig::default()
    })
    .await;
    let mut stuck = env.tcp().await;
    let mut props = claim("os::stuck");
    props.receive_maximum = Some(1);
    stuck.send(connect_packet("c", 60, Some(props), None)).await;
    assert!(matches!(stuck.next().await, Some(Packet::ConnAck(_))));
    stuck
        .send(subscribe_packet(
            1,
            &[("usp/agent/os::stuck", QoS::AtLeastOnce)],
        ))
        .await;
    assert!(matches!(stuck.next().await, Some(Packet::SubAck(_))));
    let (mut fine, _) = env.agent("os::fine").await;
    fine.send(subscribe_packet(
        1,
        &[("usp/agent/os::fine", QoS::AtLeastOnce)],
    ))
    .await;
    assert!(matches!(fine.next().await, Some(Packet::SubAck(_))));

    // 1st Record sent, never ACKed; next 64 wait in queue; then sends fail at once.
    // No call takes time.
    let started = tokio::time::Instant::now();
    let mut failed = 0;
    for i in 0..200u8 {
        match env.broker.send("os::stuck", vec![i]).await {
            Ok(_) => {}
            Err(e) => {
                assert!(e.to_string().contains("queue full"), "{e}");
                failed += 1;
            }
        }
    }
    assert!(failed >= 100, "{failed} sends failed");
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "200 sends took {:?}",
        started.elapsed()
    );
    // Other Agent served meanwhile.
    env.broker.send("os::fine", vec![7]).await.unwrap();
    let Some(Packet::Publish(p)) = fine.next().await else {
        panic!("expected a PUBLISH");
    };
    assert_eq!(&p.payload[..], &[7]);
    fine.send(Packet::PubAck(PubAck::new(p.pkid, None))).await;

    // Stuck Agent: its one Record, then nothing, then connection end.
    let Some(Packet::Publish(first)) = stuck.next().await else {
        panic!("expected the first PUBLISH");
    };
    assert_eq!(&first.payload[..], &[0]);
    let Some(Packet::Disconnect(d)) = stuck.next_within(Duration::from_secs(5)).await.unwrap()
    else {
        panic!("expected a DISCONNECT");
    };
    assert_eq!(d.reason_code, DisconnectReasonCode::UnspecifiedError);
    assert!(stuck.next().await.is_none());
    let closed = env.inbound().await;
    assert!(closed.closed && closed.reply_to.as_deref() == Some("mqtt:os::stuck"));
    assert_eq!(
        env.broker.connections(),
        1,
        "the other Agent is still there"
    );
}

/// Agent that ACKs -> not closed for a full window now and then.
#[tokio::test]
async fn an_agent_that_keeps_acknowledging_is_not_closed() {
    let env = Env::start(MqttBrokerConfig {
        ack_timeout: Duration::from_secs(1),
        ..MqttBrokerConfig::default()
    })
    .await;
    let mut agent = env.tcp().await;
    let mut props = claim("os::A");
    props.receive_maximum = Some(1);
    agent.send(connect_packet("c", 60, Some(props), None)).await;
    assert!(matches!(agent.next().await, Some(Packet::ConnAck(_))));
    agent
        .send(subscribe_packet(
            1,
            &[("usp/agent/os::A", QoS::AtLeastOnce)],
        ))
        .await;
    assert!(matches!(agent.next().await, Some(Packet::SubAck(_))));
    // Each Record ACKed after 700 ms: window always full, no stretch > limit.
    for i in 0..4u8 {
        env.broker.send("os::A", vec![i]).await.unwrap();
        let Some(Packet::Publish(p)) = agent.next().await else {
            panic!("expected a PUBLISH");
        };
        tokio::time::sleep(Duration::from_millis(700)).await;
        agent.send(Packet::PubAck(PubAck::new(p.pkid, None))).await;
    }
    env.broker.send("os::A", vec![9]).await.unwrap();
    assert!(matches!(agent.next().await, Some(Packet::Publish(_))));
    assert_eq!(env.broker.connections(), 1);
}

// --- Client certificates (H-3, M-5) ------------------------------------------------------

/// TLS, client certificates optional, as on wss.
fn optional_client_certs(ca: &Ca) -> tokio_rustls::TlsAcceptor {
    let server = ca
        .issue(&Profile {
            endpoint_id: "self::ctrl".into(),
            dns_names: vec!["localhost".into()],
            server: true,
            days: 1,
            ..Profile::default()
        })
        .unwrap();
    tls_acceptor(
        &server.cert_pem,
        server.key_pem.as_deref().unwrap(),
        Some(ca.cert_pem()),
        false,
    )
    .unwrap()
}

/// CONNACK after a CONNECT -> asserts Not authorized, returns its reason string.
async fn refused_with<S: AsyncRead + AsyncWrite + Unpin>(c: &mut Raw<S>) -> String {
    let Some(Packet::ConnAck(ack)) = c.next().await else {
        panic!("expected a CONNACK");
    };
    assert_eq!(ack.code, ConnectReturnCode::NotAuthorized);
    ack.properties.unwrap().reason_string.unwrap()
}

/// Connected + subscribed Agent over TLS; `cert` = client certificate it presents.
async fn tls_agent(
    env: &Env,
    ca: &Ca,
    cert: Option<&Issued>,
    eid: &str,
) -> Raw<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let mut c = tls_client(env.addr, client_config(ca, cert)).await;
    c.send(connect_packet(
        &format!("c-{eid}"),
        60,
        Some(claim(eid)),
        None,
    ))
    .await;
    let Some(Packet::ConnAck(ack)) = c.next().await else {
        panic!("expected a CONNACK");
    };
    assert_eq!(ack.code, ConnectReturnCode::Success, "{eid}");
    c.send(subscribe_packet(
        1,
        &[(&format!("usp/agent/{eid}"), QoS::AtLeastOnce)],
    ))
    .await;
    assert!(matches!(c.next().await, Some(Packet::SubAck(_))));
    c
}

/// Claim only -> cannot take an EndpointID from a connection proved by certificate,
/// whatever name it uses. Connection with certificate -> replaces any.
#[tokio::test]
async fn a_claim_never_replaces_a_connection_made_with_a_certificate() {
    let ca = Ca::generate("Test USP CA").unwrap();
    let mut env = Env::start_with(
        MqttBrokerConfig::default(),
        Some(optional_client_certs(&ca)),
    )
    .await;
    let alice = agent_cert(&ca, "os::alice");
    let mut genuine = tls_agent(&env, &ca, Some(&alice), "os::alice").await;

    for _ in 0..3 {
        // In the CONNECT ...
        let mut anon = tls_client(env.addr, client_config(&ca, None)).await;
        anon.send(connect_packet("x", 60, Some(claim("os::alice")), None))
            .await;
        let why = refused_with(&mut anon).await;
        assert!(why.contains("connected with a client certificate"), "{why}");
    }
    // ... and in first Record of a client nameless at CONNECT.
    let mut nameless = tls_client(env.addr, client_config(&ca, None)).await;
    nameless.send(connect_packet("n", 60, None, None)).await;
    assert!(matches!(nameless.next().await, Some(Packet::ConnAck(_))));
    nameless
        .send(Packet::Publish(publish(
            CTRL_TOPIC,
            QoS::AtLeastOnce,
            1,
            hello("os::alice", "usp/agent/os::alice"),
            None,
        )))
        .await;
    assert_eq!(
        nameless.expect_disconnect().await,
        DisconnectReasonCode::NotAuthorized
    );

    // Alice's connection untouched: still hers, Controller heard nothing.
    env.no_inbound().await;
    assert_eq!(env.broker.connections(), 1);
    env.broker.send("os::alice", vec![5]).await.unwrap();
    let Some(Packet::Publish(p)) = genuine.next().await else {
        panic!("expected a PUBLISH");
    };
    assert_eq!(&p.payload[..], &[5]);

    // Claims of other EndpointIDs unaffected; claim still replaces claim.
    let mut bob = tls_agent(&env, &ca, None, "os::bob").await;
    let _bob_again = tls_agent(&env, &ca, None, "os::bob").await;
    assert_eq!(
        bob.expect_disconnect().await,
        DisconnectReasonCode::SessionTakenOver
    );

    // Certificate takes over from a claim + from an older certificate.
    let bob_cert = agent_cert(&ca, "os::bob");
    let _bob_proved = tls_agent(&env, &ca, Some(&bob_cert), "os::bob").await;
    let renewed = agent_cert(&ca, "os::alice");
    let mut newer = tls_agent(&env, &ca, Some(&renewed), "os::alice").await;
    assert_eq!(
        genuine.expect_disconnect().await,
        DisconnectReasonCode::SessionTakenOver
    );
    env.broker.send("os::alice", vec![6]).await.unwrap();
    assert!(matches!(newer.next().await, Some(Packet::Publish(_))));
}

/// EndpointID with an issued client certificate -> refused without it,
/// plain or TLS, by CONNECT or first Record; open connections stay.
#[tokio::test]
async fn an_endpoint_id_with_a_certificate_issued_is_refused_without_it() {
    let ca = Ca::generate("Test USP CA").unwrap();
    let tls_env = Env::start_with(
        MqttBrokerConfig::default(),
        Some(optional_client_certs(&ca)),
    )
    .await;
    let plain_env = Env::start(MqttBrokerConfig::default()).await;
    // Controller feeds all MTPs at once this way.
    let multi = |env: &Env| MultiMtp {
        mqtt_broker: Some(env.broker.clone()),
        ..MultiMtp::default()
    };

    // Alice connected with shared account before she gets a certificate ...
    let mut before = tls_agent(&tls_env, &ca, None, "os::alice").await;
    let (_before_plain, _) = plain_env.agent("os::alice").await;
    // ... issued now.
    for env in [&tls_env, &plain_env] {
        multi(env).set_certificate_bound(["os::alice".to_owned()].into());
    }
    // Her connections stay (certificate may be on its way over them).
    tls_env.broker.send("os::alice", vec![1]).await.unwrap();
    assert!(matches!(before.next().await, Some(Packet::Publish(_))));
    assert_eq!(plain_env.broker.connections(), 1);

    // New ones without it -> refused, TLS or plain ...
    let mut anon = tls_client(tls_env.addr, client_config(&ca, None)).await;
    anon.send(connect_packet("x", 60, Some(claim("os::alice")), None))
        .await;
    let why = refused_with(&mut anon).await;
    assert!(why.contains("bound to a client certificate"), "{why}");
    let mut plain = plain_env.tcp().await;
    plain
        .send(connect_packet("x", 60, Some(claim("os::alice")), None))
        .await;
    let why = refused_with(&mut plain).await;
    assert!(why.contains("bound to a client certificate"), "{why}");
    // ... also by EndpointID in first Record only.
    let mut nameless = plain_env.tcp().await;
    nameless.send(connect_packet("n", 60, None, None)).await;
    assert!(matches!(nameless.next().await, Some(Packet::ConnAck(_))));
    nameless
        .send(Packet::Publish(publish(
            CTRL_TOPIC,
            QoS::AtLeastOnce,
            1,
            hello("os::alice", "usp/agent/os::alice"),
            None,
        )))
        .await;
    assert_eq!(
        nameless.expect_disconnect().await,
        DisconnectReasonCode::NotAuthorized
    );
    // Other EndpointIDs unaffected.
    let _bob = plain_env.agent("os::bob").await;

    // With certificate -> in; EndpointID released -> claims allowed again.
    let alice = agent_cert(&ca, "os::alice");
    let _proved = tls_agent(&tls_env, &ca, Some(&alice), "os::alice").await;
    for env in [&tls_env, &plain_env] {
        multi(env).set_certificate_bound(Default::default());
    }
    let _claim = plain_env.agent("os::alice").await;
}

/// Revoked client certificate -> refused + its connections closed.
#[tokio::test]
async fn a_revoked_certificate_is_refused_and_its_connections_are_closed() {
    let ca = Ca::generate("Test USP CA").unwrap();
    let mut env = Env::start_with(
        MqttBrokerConfig::default(),
        Some(optional_client_certs(&ca)),
    )
    .await;
    let multi = MultiMtp {
        mqtt_broker: Some(env.broker.clone()),
        ..MultiMtp::default()
    };
    let alice = agent_cert(&ca, "os::alice");
    let mut conn = tls_agent(&env, &ca, Some(&alice), "os::alice").await;
    let _claim = tls_agent(&env, &ca, None, "os::bob").await;

    // Revoke another certificate -> nothing closed.
    let stranger = agent_cert(&ca, "os::stranger");
    assert_eq!(multi.set_revoked([stranger.sha256.clone()].into()), 0);
    assert_eq!(env.broker.connections(), 2);
    // Revoke hers -> her connection closed (only hers), Controller hears it.
    assert_eq!(multi.set_revoked([alice.sha256.clone()].into()), 1);
    assert_eq!(
        conn.expect_disconnect().await,
        DisconnectReasonCode::NotAuthorized
    );
    let closed = env.inbound().await;
    assert!(closed.closed);
    assert_eq!(closed.reply_to.as_deref(), Some("mqtt:os::alice"));
    assert_eq!(env.broker.connections(), 1);
    // Revoked certificate -> no new connection; renewed one -> OK.
    let mut again = tls_client(env.addr, client_config(&ca, Some(&alice))).await;
    again.send(connect_packet("a", 60, None, None)).await;
    let why = refused_with(&mut again).await;
    assert!(why.contains("revoked"), "{why}");
    let renewed = agent_cert(&ca, "os::alice");
    let _ok = tls_agent(&env, &ca, Some(&renewed), "os::alice").await;
    // List replaced as a whole: certificate not in it -> allowed again.
    assert_eq!(multi.set_revoked(Default::default()), 0);
    let _back = tls_agent(&env, &ca, Some(&alice), "os::alice").await;
}
