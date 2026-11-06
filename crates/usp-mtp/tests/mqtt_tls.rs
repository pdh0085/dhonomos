//! MQTT MTP over TLS (client certs) via in-process bridge (ADR-081).
//! Against a real Mosquitto broker.
#![allow(clippy::unwrap_used)]

use std::time::Duration;

use dhonomos_pki::{Ca, Profile};
use dhonomos_usp_mtp::{MqttConfig, MqttMtp, MqttTls};
use testcontainers_modules::testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{CopyTargetOptions, GenericImage, ImageExt};

const CONF: &str = "listener 8883\n\
    cafile /mosquitto/config/ca.pem\n\
    certfile /mosquitto/config/server.pem\n\
    keyfile /mosquitto/config/server.key\n\
    require_certificate true\n\
    allow_anonymous true\n";

fn tls(ca_pem: &str, client: Option<(&str, &str)>, dir: &std::path::Path) -> MqttTls {
    MqttTls {
        config: dhonomos_usp_mtp::tls_bridge::client_config(Some(ca_pem), client).unwrap(),
        server_name: Some("localhost".into()),
        socket_dir: dir.to_path_buf(),
    }
}

#[tokio::test]
async fn round_trip_over_mutual_tls() {
    let ca = Ca::generate("Broker CA").unwrap();
    let server = ca
        .issue(&Profile {
            endpoint_id: "self::broker".into(),
            dns_names: vec!["localhost".into()],
            server: true,
            days: 1,
            ..Profile::default()
        })
        .unwrap();
    let key = server.key_pem.clone().unwrap();
    let file = |path: &str| CopyTargetOptions::new(path).with_mode(0o644);
    let broker = GenericImage::new("eclipse-mosquitto", "2")
        .with_exposed_port(8883.tcp())
        .with_wait_for(WaitFor::message_on_stderr("running"))
        .with_copy_to(file("/mosquitto/config/tls.conf"), CONF.as_bytes().to_vec())
        .with_copy_to(
            file("/mosquitto/config/ca.pem"),
            ca.cert_pem().as_bytes().to_vec(),
        )
        .with_copy_to(
            file("/mosquitto/config/server.pem"),
            server.cert_pem.as_bytes().to_vec(),
        )
        .with_copy_to(
            file("/mosquitto/config/server.key"),
            key.as_bytes().to_vec(),
        )
        .with_cmd(["mosquitto", "-c", "/mosquitto/config/tls.conf"])
        .start()
        .await
        .unwrap();
    let port = broker.get_host_port_ipv4(8883).await.unwrap();
    let dir = std::env::temp_dir().join(format!("dhonomos-mqtt-tls-{}", std::process::id()));

    let client = |eid: &str| {
        let c = ca
            .issue(&Profile {
                endpoint_id: eid.into(),
                days: 1,
                ..Profile::default()
            })
            .unwrap();
        (c.cert_pem, c.key_pem.unwrap())
    };
    let (ctrl_cert, ctrl_key) = client("self::ctrl");
    let (agent_cert, agent_key) = client("os::agent");
    let cfg = |id: &str, topic: &str, tls: MqttTls| MqttConfig {
        host: "127.0.0.1".into(),
        port,
        client_id: id.into(),
        credentials: None,
        controller_topic: topic.into(),
        keep_alive: Duration::from_secs(30),
        tls: Some(tls),
    };
    let (controller, mut c_rx) = MqttMtp::start(cfg(
        "ctrl",
        "usp/controller/tls",
        tls(ca.cert_pem(), Some((&ctrl_cert, &ctrl_key)), &dir),
    ));
    let (agent, mut a_rx) = MqttMtp::start(cfg(
        "agent",
        "usp/agent/tls",
        tls(ca.cert_pem(), Some((&agent_cert, &agent_key)), &dir),
    ));
    tokio::time::sleep(Duration::from_millis(800)).await;
    agent
        .send("usp/controller/tls", b"over tls".to_vec())
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), c_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got.payload[..], b"over tls");
    controller
        .send(got.reply_to.as_deref().unwrap(), b"and back".to_vec())
        .await
        .unwrap();
    let back = tokio::time::timeout(Duration::from_secs(5), a_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&back.payload[..], b"and back");

    // Bridge sockets: private to this user.
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);

    // No client cert, or other CA trusted -> nothing gets through.
    let other = Ca::generate("Other").unwrap();
    for (name, t) in [
        ("no client certificate", tls(ca.cert_pem(), None, &dir)),
        (
            "unknown broker CA",
            tls(other.cert_pem(), Some((&agent_cert, &agent_key)), &dir),
        ),
    ] {
        let (bad, _rx) = MqttMtp::start(cfg(name, "usp/agent/bad", t));
        tokio::time::sleep(Duration::from_millis(800)).await;
        let _ = bad.send("usp/controller/tls", b"sneaky".to_vec()).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(800), c_rx.recv())
                .await
                .is_err(),
            "{name}: a message got through"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
