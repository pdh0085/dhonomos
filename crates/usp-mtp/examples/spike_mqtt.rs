//! Spike A (Phase 0): one USP Record round trip with OB-USP-Agent over MQTT 5
//! (Mosquitto), rumqttc v5.
//!
//! 1. Subscribe to controller topic -> wait for agent's MQTTConnectRecord.
//! 2. Send Get `Device.DeviceInfo.` to agent's reply topic.
//! 3. Print GetResp + every MQTT 5 property seen.
//!
//! Run: dev stack up, start this example, then `docker compose ... restart obuspa`.
#![allow(clippy::print_stdout, clippy::unwrap_used)]

use std::time::Duration;

use dhonomos_usp_proto::{USP_VERSION, msg, record};
use prost::Message;
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::{ConnectProperties, Packet, PublishProperties};
use rumqttc::v5::{AsyncClient, Event, MqttOptions};

const CONTROLLER_EID: &str = "self::dhonomos-controller";
const CONTROLLER_TOPIC: &str = "usp/controller/dhonomos";

fn get_request(msg_id: &str, path: &str) -> msg::Msg {
    use msg::{body, header, request};
    msg::Msg {
        header: Some(msg::Header {
            msg_id: msg_id.into(),
            msg_type: header::MsgType::Get as i32,
        }),
        body: Some(msg::Body {
            msg_body: Some(body::MsgBody::Request(msg::Request {
                req_type: Some(request::ReqType::Get(msg::Get {
                    param_paths: vec![path.into()],
                    max_depth: 0,
                })),
            })),
        }),
    }
}

fn wrap(to: &str, m: &msg::Msg) -> Vec<u8> {
    record::Record {
        version: USP_VERSION.into(),
        to_id: to.into(),
        from_id: CONTROLLER_EID.into(),
        payload_security: record::record::PayloadSecurity::Plaintext as i32,
        record_type: Some(record::record::RecordType::NoSessionContext(
            record::NoSessionContextRecord {
                payload: m.encode_to_vec(),
            },
        )),
        ..Default::default()
    }
    .encode_to_vec()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut opts = MqttOptions::new("dhonomos-controller-spike", "127.0.0.1", 1883);
    opts.set_keep_alive(Duration::from_secs(30));
    let mut props = ConnectProperties::new();
    props.request_response_info = Some(1);
    opts.set_connect_properties(props);

    let (client, mut eventloop) = AsyncClient::new(opts, 16);
    client.subscribe(CONTROLLER_TOPIC, QoS::AtLeastOnce).await?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let ev = tokio::time::timeout_at(deadline, eventloop.poll()).await??;
        match ev {
            Event::Incoming(Packet::ConnAck(ack)) => {
                println!("CONNACK code={:?} props={:?}", ack.code, ack.properties);
            }
            Event::Incoming(Packet::Publish(p)) => {
                let topic = String::from_utf8_lossy(&p.topic).into_owned();
                println!(
                    "\nPUBLISH topic={topic} qos={:?} props={:?}",
                    p.qos, p.properties
                );
                let rec = record::Record::decode(p.payload.clone())?;
                println!(
                    "  Record version={} from={} to={}",
                    rec.version, rec.from_id, rec.to_id
                );
                let reply_topic = p
                    .properties
                    .as_ref()
                    .and_then(|pp| pp.response_topic.clone());
                match rec.record_type {
                    Some(record::record::RecordType::MqttConnect(c)) => {
                        println!("  MQTTConnectRecord {c:?}");
                        let agent_topic = reply_topic.unwrap_or(c.subscribed_topic);
                        let get = get_request("spike-1", "Device.DeviceInfo.");
                        let pub_props = PublishProperties {
                            response_topic: Some(CONTROLLER_TOPIC.into()),
                            content_type: Some("usp.msg".into()),
                            ..Default::default()
                        };
                        client
                            .publish_with_properties(
                                agent_topic.clone(),
                                QoS::AtLeastOnce,
                                false,
                                wrap(&rec.from_id, &get),
                                pub_props,
                            )
                            .await?;
                        println!("  -> sent Get(Device.DeviceInfo.) to {agent_topic}");
                    }
                    Some(record::record::RecordType::NoSessionContext(n)) => {
                        let m = msg::Msg::decode(n.payload.as_slice())?;
                        println!("  Msg header={:?}", m.header);
                        if let Some(msg::body::MsgBody::Response(r)) =
                            m.body.and_then(|b| b.msg_body)
                            && let Some(msg::response::RespType::GetResp(g)) = r.resp_type
                        {
                            for rp in g.req_path_results {
                                println!("  GetResp {} err={}", rp.requested_path, rp.err_code);
                                for res in rp.resolved_path_results {
                                    let mut kv: Vec<_> = res.result_params.into_iter().collect();
                                    kv.sort();
                                    for (k, v) in kv {
                                        println!("    {}{k} = {v:?}", res.resolved_path);
                                    }
                                }
                            }
                            println!("\nROUND TRIP OK");
                            client.disconnect().await?;
                            return Ok(());
                        }
                    }
                    other => println!("  other record: {other:?}"),
                }
            }
            _ => {}
        }
    }
}
