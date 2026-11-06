//! MQTT MTP vs a real Mosquitto broker (container).
#![allow(clippy::unwrap_used)]

use std::time::Duration;

use dhonomos_usp_mtp::{MqttConfig, MqttMtp};
use testcontainers_modules::testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{GenericImage, ImageExt};

#[tokio::test]
async fn round_trip_through_the_broker() {
    let broker = GenericImage::new("eclipse-mosquitto", "2")
        .with_exposed_port(1883.tcp())
        .with_wait_for(WaitFor::message_on_stderr("running"))
        .with_cmd(["mosquitto", "-c", "/mosquitto-no-auth.conf"])
        .start()
        .await
        .unwrap();
    let port = broker.get_host_port_ipv4(1883).await.unwrap();
    let cfg = |id: &str, topic: &str| MqttConfig {
        host: "127.0.0.1".into(),
        port,
        client_id: id.into(),
        credentials: None,
        controller_topic: topic.into(),
        keep_alive: Duration::from_secs(30),
        tls: None,
    };
    // Two MTP endpoints = Controller + Agent.
    let (controller, mut c_rx) = MqttMtp::start(cfg("ctrl", "usp/controller/test"));
    let (agent, mut a_rx) = MqttMtp::start(cfg("agent", "usp/agent/test"));
    tokio::time::sleep(Duration::from_millis(500)).await; // let subscriptions settle

    agent
        .send("usp/controller/test", b"hello controller".to_vec())
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), c_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got.payload[..], b"hello controller");
    assert_eq!(
        got.reply_to.as_deref(),
        Some("usp/agent/test"),
        "Response Topic carries the reply address"
    );

    controller
        .send(got.reply_to.as_deref().unwrap(), b"hello agent".to_vec())
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), a_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got.payload[..], b"hello agent");
    assert_eq!(got.reply_to.as_deref(), Some("usp/controller/test"));

    // Large Records (e.g. GetSupportedDM responses) pass both ways.
    let big = vec![0x5a; 1024 * 1024];
    agent
        .send("usp/controller/test", big.clone())
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), c_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.payload.len(), big.len());
    controller
        .send("usp/agent/test", big.clone())
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), a_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.payload.len(), big.len());
}
