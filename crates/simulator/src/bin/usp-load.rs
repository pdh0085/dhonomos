//! USP load: N simulated Agents on MQTT answer Get of an in-process Controller.
//! Fixed concurrency -> report msg/s + latency.
//!
//! `cargo run --release -p dhonomos-simulator --bin usp-load -- --agents 1000 --concurrency 500 --duration 60`
#![allow(clippy::print_stdout)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::Parser;
use dhonomos_usp_controller::{Controller, Handler};
use dhonomos_usp_mtp::{MqttConfig, MqttMtp};
use dhonomos_usp_proto::msg::{self, body::MsgBody, request::ReqType, response::RespType};
use dhonomos_usp_proto::record::{self, record::RecordType};
use dhonomos_usp_proto::{UspVersion, builder};
use prost::Message as _;
use tokio::sync::Mutex;

#[derive(Debug, Parser)]
struct Args {
    /// Broker host.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// Broker port.
    #[arg(long, default_value_t = 1883)]
    port: u16,
    /// Simulated Agents.
    #[arg(long, default_value_t = 100)]
    agents: usize,
    /// Requests in flight.
    #[arg(long, default_value_t = 200)]
    concurrency: usize,
    /// Seconds of load.
    #[arg(long, default_value_t = 30)]
    duration: u64,
}

const CTRL: &str = "self::usp-load-controller";
const CTRL_TOPIC: &str = "usp/controller/usp-load";

struct Quiet;

impl Handler for Quiet {
    async fn agent_connected(&self, _: &str, _: UspVersion) {}
    async fn agent_disconnected(&self, _: &str) {}
    async fn notify(&self, _: &str, _: &str, _: msg::Notify) {}
}

fn cfg(args: &Args, id: String, topic: String) -> MqttConfig {
    MqttConfig {
        host: args.host.clone(),
        port: args.port,
        client_id: id,
        credentials: None,
        controller_topic: topic,
        keep_alive: Duration::from_secs(60),
        tls: None,
    }
}

fn ms(d: Duration) -> String {
    format!("{:.1} ms", d.as_secs_f64() * 1000.0)
}

async fn agent(args: Arc<Args>, i: usize) -> anyhow::Result<()> {
    let eid = format!("proto::load-{i:05}");
    let topic = format!("usp/agent/load-{i:05}");
    let (mtp, mut rx) = MqttMtp::start(cfg(&args, format!("load-agent-{i}"), topic.clone()));
    let v13 = UspVersion { major: 1, minor: 3 };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let connect = record::Record {
        version: "1.3".into(),
        to_id: CTRL.into(),
        from_id: eid.clone(),
        record_type: Some(RecordType::MqttConnect(record::MqttConnectRecord {
            version: 1,
            subscribed_topic: topic,
        })),
        ..Default::default()
    };
    mtp.send(CTRL_TOPIC, connect.encode_to_vec()).await?;
    let params: HashMap<String, String> = [("SoftwareVersion", "1.0"), ("UpTime", "1")]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
    while let Some(inbound) = rx.recv().await {
        let Ok(rec) = record::Record::decode(inbound.payload) else {
            continue;
        };
        let Some(RecordType::NoSessionContext(ns)) = rec.record_type else {
            continue;
        };
        let Ok(m) = msg::Msg::decode(ns.payload.as_slice()) else {
            continue;
        };
        let id = m.header.map(|h| h.msg_id).unwrap_or_default();
        let Some(MsgBody::Request(msg::Request {
            req_type: Some(ReqType::Get(_)),
        })) = m.body.and_then(|b| b.msg_body)
        else {
            continue;
        };
        let resp = builder::response(
            &id,
            RespType::GetResp(msg::GetResp {
                req_path_results: vec![msg::get_resp::RequestedPathResult {
                    requested_path: "Device.DeviceInfo.".into(),
                    err_code: 0,
                    err_msg: String::new(),
                    resolved_path_results: vec![msg::get_resp::ResolvedPathResult {
                        resolved_path: "Device.DeviceInfo.".into(),
                        result_params: params.clone(),
                    }],
                }],
            }),
        );
        let out = builder::no_session_record(v13, &eid, CTRL, &resp).encode_to_vec();
        mtp.send(CTRL_TOPIC, out).await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Arc::new(Args::parse());
    let (mtp, inbound) =
        MqttMtp::start(cfg(&args, "usp-load-controller".into(), CTRL_TOPIC.into()));
    let ctrl = Arc::new(Controller::new(CTRL, mtp, Quiet, Duration::from_secs(10)));
    let runner = ctrl.clone();
    tokio::spawn(async move { runner.run(inbound).await });
    tokio::time::sleep(Duration::from_millis(500)).await;

    for i in 0..args.agents {
        let a = args.clone();
        tokio::spawn(async move {
            if let Err(e) = agent(a, i).await {
                eprintln!("agent {i}: {e:#}");
            }
        });
    }
    let start = Instant::now();
    while ctrl.connected_agents().len() < args.agents {
        anyhow::ensure!(
            start.elapsed() < Duration::from_secs(60),
            "only {} agents connected",
            ctrl.connected_agents().len()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let agents = ctrl.connected_agents();
    println!(
        "{} agents connected in {}",
        agents.len(),
        ms(start.elapsed())
    );

    let agents = Arc::new(agents);
    let ok = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let latencies = Arc::new(Mutex::new(Vec::<Duration>::new()));
    let deadline = Instant::now() + Duration::from_secs(args.duration);
    let next = Arc::new(AtomicU64::new(0));
    let begin = Instant::now();
    let mut workers = Vec::new();
    for _ in 0..args.concurrency {
        let (ctrl, agents, ok, errors, latencies, next) = (
            ctrl.clone(),
            agents.clone(),
            ok.clone(),
            errors.clone(),
            latencies.clone(),
            next.clone(),
        );
        workers.push(tokio::spawn(async move {
            let mut local = Vec::new();
            while Instant::now() < deadline {
                let i = next.fetch_add(1, Ordering::Relaxed) as usize % agents.len();
                let t = Instant::now();
                let req = ReqType::Get(msg::Get {
                    param_paths: vec!["Device.DeviceInfo.".into()],
                    max_depth: 0,
                });
                match ctrl.request(&agents[i], req).await {
                    Ok(_) => {
                        ok.fetch_add(1, Ordering::Relaxed);
                        local.push(t.elapsed());
                    }
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            latencies.lock().await.extend(local);
        }));
    }
    for w in workers {
        let _ = w.await;
    }
    let elapsed = begin.elapsed().as_secs_f64();
    let mut lat = latencies.lock().await.clone();
    lat.sort();
    let p = |q: f64| {
        lat.get(((lat.len().max(1) - 1) as f64 * q) as usize)
            .copied()
            .unwrap_or_default()
    };
    let n = ok.load(Ordering::Relaxed);
    println!("--- results ---");
    println!("requests ok={n} errors={}", errors.load(Ordering::Relaxed));
    println!(
        "throughput {:.0} requests/s = {:.0} USP messages/s (request + response)",
        n as f64 / elapsed,
        2.0 * n as f64 / elapsed
    );
    println!(
        "latency p50 {} p95 {} p99 {} max {}",
        ms(p(0.5)),
        ms(p(0.95)),
        ms(p(0.99)),
        ms(lat.last().copied().unwrap_or_default())
    );
    Ok(())
}
