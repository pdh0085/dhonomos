//! Broker access control: Mosquitto + dynamic-security plugin (US-17).
#![allow(clippy::unwrap_used)]

use std::time::Duration;

use dhonomos_usp_mtp::dynsec::CONTROLLER_ROLE;
use dhonomos_usp_mtp::{Dynsec, DynsecConfig, DynsecError, MqttConfig, MqttMtp};
use rumqttc::v5::mqttbytes::v5::Packet;
use rumqttc::v5::{AsyncClient, Event, MqttOptions};
use serde_json::json;
use testcontainers_modules::testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{GenericImage, ImageExt};

const SETUP: &str = r#"
cat > /tmp/m.conf <<CONF
listener 1883
allow_anonymous false
persistence false
plugin /usr/lib/mosquitto_dynamic_security.so
plugin_opt_config_file /mosquitto/data/dynsec.json
log_dest stderr
CONF
mosquitto_ctrl dynsec init /mosquitto/data/dynsec.json admin admin-pw >/dev/null
chown mosquitto /mosquitto/data/dynsec.json
exec mosquitto -c /tmp/m.conf
"#;

const CTRL_TOPIC: &str = "usp/controller/test";
const AGENT: &str = "os::agent-1";

/// Broker accepts `username`/`password`? (CONNACK success).
async fn can_connect(port: u16, username: &str, password: &str) -> bool {
    let mut opts = MqttOptions::new(format!("probe-{username}"), "127.0.0.1", port);
    opts.set_credentials(username, password);
    let (_client, mut el) = AsyncClient::new(opts, 8);
    loop {
        match tokio::time::timeout(Duration::from_secs(5), el.poll()).await {
            Ok(Ok(Event::Incoming(Packet::ConnAck(_)))) => return true,
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => return false,
        }
    }
}

#[tokio::test]
async fn agents_get_their_own_account_and_topic() {
    let broker = GenericImage::new("eclipse-mosquitto", "2")
        .with_exposed_port(1883.tcp())
        .with_wait_for(WaitFor::message_on_stderr("running"))
        .with_entrypoint("sh")
        .with_cmd(["-c", SETUP])
        .start()
        .await
        .unwrap();
    let port = broker.get_host_port_ipv4(1883).await.unwrap();
    let dynsec = Dynsec::start(DynsecConfig {
        host: "127.0.0.1".into(),
        port,
        client_id: "dhonomos-admin".into(),
        username: "admin".into(),
        password: "admin-pw".into(),
        timeout: Duration::from_secs(5),
        tls: None,
    });

    // Controller account.
    let made = dynsec
        .exec(vec![
            json!({ "command": "createClient", "username": "ctrl", "password": "ctrl-pw" }),
        ])
        .await
        .unwrap();
    assert_eq!(made[0].error, None);
    // Role as made by older versions: Agents may publish to the shared topic.
    dynsec
        .exec(vec![
            json!({ "command": "createRole", "rolename": dhonomos_usp_mtp::dynsec::AGENT_ROLE }),
            json!({ "command": "addRoleACL", "rolename": dhonomos_usp_mtp::dynsec::AGENT_ROLE,
                    "acltype": "publishClientSend", "topic": CTRL_TOPIC, "allow": true }),
        ])
        .await
        .unwrap();
    for _ in 0..2 {
        dynsec
            .ensure_roles(CTRL_TOPIC, "usp/agent/", Some("ctrl"))
            .await
            .unwrap();
    }
    let ctrl = dynsec
        .exec(vec![json!({ "command": "getClient", "username": "ctrl" })])
        .await
        .unwrap();
    let roles = &ctrl[0].data.as_ref().unwrap()["client"]["roles"];
    assert_eq!(roles.as_array().unwrap().len(), 1, "granted once: {roles}");
    assert_eq!(roles[0]["rolename"], CONTROLLER_ROLE);

    assert!(
        !can_connect(port, AGENT, "agent-pw").await,
        "unknown agents are refused"
    );
    dynsec.upsert_agent(AGENT, "agent-pw").await.unwrap();
    assert!(can_connect(port, AGENT, "agent-pw").await);
    assert!(!can_connect(port, AGENT, "wrong").await);
    assert!(matches!(
        dynsec.upsert_agent("os::bad/topic", "x").await,
        Err(DynsecError::InvalidEndpointId(_))
    ));

    let cfg = |id: &str, user: &str, pw: &str, topic: &str| MqttConfig {
        host: "127.0.0.1".into(),
        port,
        client_id: id.into(),
        credentials: Some((user.into(), pw.into())),
        controller_topic: topic.into(),
        keep_alive: Duration::from_secs(30),
        tls: None,
    };
    let (controller, mut c_rx) = MqttMtp::start(cfg("ctrl", "ctrl", "ctrl-pw", CTRL_TOPIC));
    let (agent, mut a_rx) = MqttMtp::start(cfg(
        "agent",
        AGENT,
        "agent-pw",
        &format!("usp/agent/{AGENT}"),
    ));
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Agent publish: own Controller topic only -> topic tells the Controller the sender.
    let own = format!("{CTRL_TOPIC}/{AGENT}");
    agent.send(&own, b"to controller".to_vec()).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), c_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got.payload[..], b"to controller");
    assert_eq!(got.sender.as_deref(), Some(AGENT));
    // Not to the shared topic (old ACL gone), not to another Agent's topic.
    let _ = agent.send(CTRL_TOPIC, b"shared".to_vec()).await;
    let _ = agent
        .send(
            &format!("{CTRL_TOPIC}/os::someone-else"),
            b"posing".to_vec(),
        )
        .await;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), c_rx.recv())
            .await
            .is_err(),
        "the broker let an Agent publish outside its own topic"
    );
    controller
        .send(&format!("usp/agent/{AGENT}"), b"to agent".to_vec())
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), a_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got.payload[..], b"to agent");

    // Rotated password -> old one invalid.
    dynsec.upsert_agent(AGENT, "agent-pw-2").await.unwrap();
    assert!(!can_connect(port, AGENT, "agent-pw").await);
    assert!(can_connect(port, AGENT, "agent-pw-2").await);

    dynsec.set_agent_enabled(AGENT, false).await.unwrap();
    assert!(!can_connect(port, AGENT, "agent-pw-2").await, "disabled");
    dynsec.set_agent_enabled(AGENT, true).await.unwrap();
    assert!(can_connect(port, AGENT, "agent-pw-2").await);

    dynsec.delete_agent(AGENT).await.unwrap();
    dynsec.delete_agent(AGENT).await.unwrap();
    assert!(!can_connect(port, AGENT, "agent-pw-2").await, "deleted");
}
