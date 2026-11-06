//! Live check vs dev-stack OB-USP-Agent: wait for Agent -> Get `Device.DeviceInfo.` -> print.
//!
//! `cargo run -p dhonomos-usp-controller --example obuspa_get`, then restart obuspa.
#![allow(clippy::print_stdout, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use dhonomos_usp_controller::{Controller, Handler};
use dhonomos_usp_mtp::{MqttConfig, MqttMtp};
use dhonomos_usp_proto::UspVersion;
use dhonomos_usp_proto::msg::{self, request::ReqType, response::RespType};
use tokio::sync::mpsc;

struct Events(mpsc::UnboundedSender<String>);

impl Handler for Events {
    async fn agent_connected(&self, eid: &str, v: UspVersion) {
        println!("connected: {eid} (USP {v})");
        let _ = self.0.send(eid.to_owned());
    }
    async fn agent_disconnected(&self, eid: &str) {
        println!("disconnected: {eid}");
    }
    async fn notify(&self, eid: &str, msg_id: &str, n: msg::Notify) {
        println!("notify {msg_id} from {eid}: {n:?}");
    }
}

#[tokio::main]
async fn main() {
    let (mtp, inbound) = MqttMtp::start(MqttConfig {
        host: "127.0.0.1".into(),
        port: 1883,
        client_id: "dhonomos-example".into(),
        credentials: None,
        controller_topic: "usp/controller/dhonomos".into(),
        keep_alive: Duration::from_secs(30),
        tls: None,
    });
    let (tx, mut agents) = mpsc::unbounded_channel();
    let ctrl = Arc::new(Controller::new(
        "self::dhonomos-controller",
        mtp,
        Events(tx),
        Duration::from_secs(10),
    ));
    let runner = ctrl.clone();
    tokio::spawn(async move { runner.run(inbound).await });

    let eid = tokio::time::timeout(Duration::from_secs(60), agents.recv())
        .await
        .unwrap()
        .unwrap();
    let resp = ctrl
        .request(
            &eid,
            ReqType::Get(msg::Get {
                param_paths: vec!["Device.DeviceInfo.".into()],
                max_depth: 0,
            }),
        )
        .await
        .unwrap();
    let Some(RespType::GetResp(g)) = resp.resp_type else {
        panic!("unexpected response")
    };
    for r in g.req_path_results {
        for res in r.resolved_path_results {
            let mut kv: Vec<_> = res.result_params.into_iter().collect();
            kv.sort();
            for (k, v) in kv {
                println!("{}{k} = {v}", res.resolved_path);
            }
        }
    }
    println!("OK");
}
