//! USP fleet: N simulated Agents on MQTT -> external Controller (running `dhonomos`).
//! Answers like a small compliant Agent.
//! Report: Agents provisioned with a given parameter (e.g. by a preset) + time taken.
//!
//! `cargo run --release -p dhonomos-simulator --bin usp-fleet -- --agents 1000 --expect Device.DeviceInfo.ProvisioningCode`
#![allow(clippy::print_stdout)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::Parser;
use dhonomos_usp_mtp::{MqttConfig, MqttMtp};
use dhonomos_usp_proto::msg::{self, body::MsgBody, request::ReqType, response::RespType};
use dhonomos_usp_proto::record::{self, record::RecordType};
use dhonomos_usp_proto::{ErrorCode, UspVersion, builder};
use prost::Message as _;

#[derive(Debug, Parser)]
struct Args {
    /// Broker host.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// Broker port.
    #[arg(long, default_value_t = 1883)]
    port: u16,
    /// Simulated Agents (EndpointIDs `proto::fleet-00000`...).
    #[arg(long, default_value_t = 100)]
    agents: usize,
    /// Controller EndpointID.
    #[arg(long, default_value = "self::dhonomos-controller")]
    controller: String,
    /// Controller topic.
    #[arg(long, default_value = "usp/controller/dhonomos")]
    controller_topic: String,
    /// Set writes this parameter -> Agent counted as provisioned.
    #[arg(long, default_value = "Device.DeviceInfo.ProvisioningCode")]
    expect: String,
    /// Give up after this many seconds.
    #[arg(long, default_value_t = 120)]
    timeout: u64,
    /// Firmware the Agents start with.
    #[arg(long, default_value = "1.0.0")]
    software_version: String,
    /// Firmware after a successful FirmwareImage Download().
    #[arg(long, default_value = "2.0.0")]
    upgrade_to: String,
    /// Run N s -> report firmware upgrades + config backups/restores; no wait for `--expect`.
    #[arg(long)]
    run_for: Option<u64>,
}

#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    provisioned: AtomicU64,
    upgraded: AtomicU64,
    backups: AtomicU64,
    restores: AtomicU64,
}

/// Async command action after the response.
enum Action {
    /// FirmwareImage Download() (FW-05).
    Firmware,
    /// VendorConfigFile Backup(): PUT config to URL (CO-08).
    Backup(String),
    /// VendorConfigFile Restore(): GET config from URL.
    Restore(String),
}

/// Async command -> OperationComplete after the response.
struct AsyncJob {
    obj_path: String,
    command_name: String,
    command_key: String,
    action: Action,
}

const VENDOR_CONFIG: &str = "Device.DeviceInfo.VendorConfigFile.";

/// Answers of a small Agent. Other requests -> Error 7001.
fn answer(
    i: usize,
    req: ReqType,
    expect: &str,
    version: &str,
    counters: &Counters,
    job: &mut Option<AsyncJob>,
) -> Result<RespType, String> {
    counters.requests.fetch_add(1, Ordering::Relaxed);
    let started = |command: String| {
        RespType::OperateResp(msg::OperateResp {
            operation_results: vec![msg::operate_resp::OperationResult {
                executed_command: command,
                operation_resp: Some(
                    msg::operate_resp::operation_result::OperationResp::ReqObjPath(
                        "Device.LocalAgent.Request.1".into(),
                    ),
                ),
            }],
        })
    };
    Ok(match req {
        ReqType::Get(g) if g.param_paths.iter().any(|p| p.starts_with(VENDOR_CONFIG)) => {
            RespType::GetResp(msg::GetResp {
                req_path_results: vec![msg::get_resp::RequestedPathResult {
                    requested_path: VENDOR_CONFIG.into(),
                    resolved_path_results: vec![msg::get_resp::ResolvedPathResult {
                        resolved_path: format!("{VENDOR_CONFIG}1."),
                        result_params: [
                            ("Name".to_owned(), "fleetbox.cfg".to_owned()),
                            ("Version".to_owned(), version.to_owned()),
                        ]
                        .into(),
                    }],
                    ..Default::default()
                }],
            })
        }
        ReqType::Operate(o)
            if o.command.starts_with(VENDOR_CONFIG)
                && (o.command.ends_with(".Backup()") || o.command.ends_with(".Restore()")) =>
        {
            let url = o.input_args.get("URL").cloned().unwrap_or_default();
            let (obj_path, command_name) = o
                .command
                .rsplit_once('.')
                .map(|(obj, cmd)| (format!("{obj}."), cmd.to_owned()))
                .unwrap_or_default();
            let action = if command_name == "Backup()" {
                Action::Backup(url)
            } else {
                Action::Restore(url)
            };
            *job = Some(AsyncJob {
                obj_path,
                command_name,
                command_key: o.command_key.clone(),
                action,
            });
            started(o.command)
        }
        ReqType::Get(g)
            if g.param_paths.iter().any(|p| {
                p.starts_with("Device.DeviceInfo.FirmwareImage")
                    || p.ends_with("ActiveFirmwareImage")
            }) =>
        {
            let bank = |n: u32, status: &str| msg::get_resp::ResolvedPathResult {
                resolved_path: format!("Device.DeviceInfo.FirmwareImage.{n}."),
                result_params: [("Status".to_owned(), status.to_owned())].into(),
            };
            RespType::GetResp(msg::GetResp {
                req_path_results: vec![msg::get_resp::RequestedPathResult {
                    requested_path: "Device.DeviceInfo.".into(),
                    resolved_path_results: vec![
                        msg::get_resp::ResolvedPathResult {
                            resolved_path: "Device.DeviceInfo.".into(),
                            result_params: [(
                                "ActiveFirmwareImage".to_owned(),
                                "Device.DeviceInfo.FirmwareImage.1".to_owned(),
                            )]
                            .into(),
                        },
                        bank(1, "Active"),
                        bank(2, "Available"),
                    ],
                    ..Default::default()
                }],
            })
        }
        ReqType::Operate(o) if o.command.ends_with(".Download()") => {
            *job = Some(AsyncJob {
                obj_path: o.command.trim_end_matches("Download()").to_owned(),
                command_name: "Download()".into(),
                command_key: o.command_key.clone(),
                action: Action::Firmware,
            });
            started(o.command)
        }
        ReqType::Get(g) => {
            let info: HashMap<String, String> = [
                ("Manufacturer", "Dhonomos Sim".to_owned()),
                ("ManufacturerOUI", "00AA00".to_owned()),
                ("ProductClass", "FleetBox".to_owned()),
                ("ModelName", "FleetBox 1".to_owned()),
                ("SerialNumber", format!("FLEET{i:05}")),
                ("SoftwareVersion", version.to_owned()),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v))
            .collect();
            RespType::GetResp(msg::GetResp {
                req_path_results: g
                    .param_paths
                    .iter()
                    .map(|p| msg::get_resp::RequestedPathResult {
                        requested_path: p.clone(),
                        resolved_path_results: vec![msg::get_resp::ResolvedPathResult {
                            resolved_path: "Device.DeviceInfo.".into(),
                            result_params: info.clone(),
                        }],
                        ..Default::default()
                    })
                    .collect(),
            })
        }
        ReqType::Set(s) => {
            let wrote = s.update_objs.iter().any(|o| {
                o.param_settings
                    .iter()
                    .any(|p| format!("{}{}", o.obj_path, p.param) == expect)
            });
            if wrote {
                counters.provisioned.fetch_add(1, Ordering::Relaxed);
            }
            RespType::SetResp(msg::SetResp::default())
        }
        // Subscriptions + other objects: accepted, nothing to report.
        ReqType::Add(_) => RespType::AddResp(msg::AddResp::default()),
        ReqType::GetSupportedDm(_) => {
            use msg::get_supported_dm_resp as g;
            RespType::GetSupportedDmResp(msg::GetSupportedDmResp {
                req_obj_results: vec![g::RequestedObjectResult {
                    req_obj_path: "Device.".into(),
                    supported_objs: vec![g::SupportedObjectResult {
                        supported_obj_path: "Device.DeviceInfo.".into(),
                        supported_params: vec![g::SupportedParamResult {
                            param_name: "ProvisioningCode".into(),
                            access: g::ParamAccessType::ParamReadWrite as i32,
                            value_type: g::ParamValueType::ParamString as i32,
                            value_change: g::ValueChangeType::ValueChangeAllowed as i32,
                        }],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
            })
        }
        other => return Err(format!("{other:?}")),
    })
}

fn version_of() -> UspVersion {
    UspVersion { major: 1, minor: 3 }
}

async fn agent(args: Arc<Args>, i: usize, counters: Arc<Counters>) -> anyhow::Result<()> {
    let eid = format!("proto::fleet-{i:05}");
    let topic = format!("usp/agent/fleet-{i:05}");
    let (mtp, mut rx) = MqttMtp::start(MqttConfig {
        host: args.host.clone(),
        port: args.port,
        client_id: format!("fleet-agent-{i}"),
        credentials: None,
        controller_topic: topic.clone(),
        keep_alive: Duration::from_secs(60),
        tls: None,
    });
    let usp_version = version_of();
    let version = Arc::new(std::sync::Mutex::new(args.software_version.clone()));
    let config = Arc::new(std::sync::Mutex::new(format!(
        "# FleetBox configuration\nSerialNumber=FLEET{i:05}\nWiFi.SSID=fleet-{i}\n"
    )));
    tokio::time::sleep(Duration::from_millis(500)).await;
    let connect = builder::mqtt_connect_record(usp_version, &eid, &args.controller, &topic);
    mtp.send(&args.controller_topic, connect.encode_to_vec())
        .await?;
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
            req_type: Some(req),
        })) = m.body.and_then(|b| b.msg_body)
        else {
            continue;
        };
        let mut job = None;
        let current = version.lock().map(|v| v.clone()).unwrap_or_default();
        let reply = match answer(i, req, &args.expect, &current, &counters, &mut job) {
            Ok(resp) => builder::response(&id, resp),
            Err(_) => builder::error(&id, ErrorCode::MESSAGE_NOT_SUPPORTED, "not supported"),
        };
        if let Some(job) = job {
            let (mtp, args, eid, topic, version, counters, config) = (
                mtp.clone(),
                args.clone(),
                eid.clone(),
                topic.clone(),
                version.clone(),
                counters.clone(),
                config.clone(),
            );
            tokio::spawn(async move {
                use msg::notify::{Notification, OperationComplete, operation_complete};
                tokio::time::sleep(Duration::from_secs(1)).await;
                let outcome: anyhow::Result<()> = match &job.action {
                    Action::Firmware => {
                        if let Ok(mut v) = version.lock() {
                            v.clone_from(&args.upgrade_to);
                        }
                        counters.upgraded.fetch_add(1, Ordering::Relaxed);
                        Ok(())
                    }
                    Action::Backup(url) => {
                        let body = config.lock().map(|c| c.clone()).unwrap_or_default();
                        let r = dhonomos_simulator::put(url, body).await;
                        if r.is_ok() {
                            counters.backups.fetch_add(1, Ordering::Relaxed);
                        }
                        r
                    }
                    Action::Restore(url) => match dhonomos_simulator::get(url).await {
                        Ok(body) => {
                            if let Ok(mut c) = config.lock() {
                                *c = String::from_utf8_lossy(&body).into_owned();
                            }
                            counters.restores.fetch_add(1, Ordering::Relaxed);
                            Ok(())
                        }
                        Err(e) => Err(e),
                    },
                };
                let operation_resp = match outcome {
                    Ok(()) => operation_complete::OperationResp::ReqOutputArgs(
                        operation_complete::OutputArgs::default(),
                    ),
                    Err(e) => {
                        eprintln!("{eid}: {}{} failed: {e:#}", job.obj_path, job.command_name);
                        operation_complete::OperationResp::CmdFailure(
                            operation_complete::CommandFailure {
                                err_code: 7002,
                                err_msg: format!("transfer failed: {e}"),
                            },
                        )
                    }
                };
                let notify = builder::request(
                    format!("oc-{}", job.command_key),
                    ReqType::Notify(msg::Notify {
                        subscription_id: "dhonomos-operation-complete".into(),
                        send_resp: false,
                        notification: Some(Notification::OperComplete(OperationComplete {
                            obj_path: job.obj_path,
                            command_name: job.command_name,
                            command_key: job.command_key,
                            operation_resp: Some(operation_resp),
                        })),
                    }),
                );
                let rec = builder::no_session_record(version_of(), &eid, &args.controller, &notify);
                let _ = mtp.send(&args.controller_topic, rec.encode_to_vec()).await;
                if matches!(job.action, Action::Firmware) {
                    // "Reboot" -> reconnect with the new version.
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let connect =
                        builder::mqtt_connect_record(version_of(), &eid, &args.controller, &topic);
                    let _ = mtp
                        .send(&args.controller_topic, connect.encode_to_vec())
                        .await;
                }
            });
        }
        let out = builder::no_session_record(usp_version, &eid, &args.controller, &reply);
        let reply_to = inbound
            .reply_to
            .unwrap_or_else(|| args.controller_topic.clone());
        mtp.send(&reply_to, out.encode_to_vec()).await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Arc::new(Args::parse());
    let counters = Arc::new(Counters::default());
    let start = Instant::now();
    for i in 0..args.agents {
        let (a, c) = (args.clone(), counters.clone());
        tokio::spawn(async move {
            if let Err(e) = agent(a, i, c).await {
                eprintln!("agent {i}: {e:#}");
            }
        });
    }
    if let Some(secs) = args.run_for {
        // Campaign mode: check every 5 s -> line when upgrades/backups/restores change.
        let mut last = u64::MAX;
        while start.elapsed() < Duration::from_secs(secs) {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let up = counters.upgraded.load(Ordering::Relaxed);
            let (b, r) = (
                counters.backups.load(Ordering::Relaxed),
                counters.restores.load(Ordering::Relaxed),
            );
            if up + b + r != last {
                println!(
                    "{:>6.1}s upgraded {up}/{}, config backups {b}, restores {r}",
                    start.elapsed().as_secs_f64(),
                    args.agents
                );
                last = up + b + r;
            }
        }
        println!(
            "--- results ---\nagents {} upgraded {}; config backups {}, restores {}; requests answered {}",
            args.agents,
            counters.upgraded.load(Ordering::Relaxed),
            counters.backups.load(Ordering::Relaxed),
            counters.restores.load(Ordering::Relaxed),
            counters.requests.load(Ordering::Relaxed)
        );
        return Ok(());
    }
    let deadline = start + Duration::from_secs(args.timeout);
    let mut last = 0;
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let done = counters.provisioned.load(Ordering::Relaxed);
        if done != last {
            println!(
                "{:>6.1}s provisioned {done}/{}",
                start.elapsed().as_secs_f64(),
                args.agents
            );
            last = done;
        }
        if done as usize >= args.agents {
            break;
        }
    }
    let done = counters.provisioned.load(Ordering::Relaxed);
    println!("--- results ---");
    println!(
        "agents {} provisioned {done} in {:.1}s; requests answered {}",
        args.agents,
        start.elapsed().as_secs_f64(),
        counters.requests.load(Ordering::Relaxed)
    );
    anyhow::ensure!(
        done as usize == args.agents,
        "not every agent was provisioned"
    );
    Ok(())
}
