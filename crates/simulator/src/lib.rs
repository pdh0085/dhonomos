//! CWMP CPE simulator for `cwmp-load` + tests.

pub mod nat;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dhonomos_cwmp_codec::{
    Body, CwmpNamespace, DeviceId, DownloadResponse, Envelope, EventStruct, Fault,
    GetParameterNamesResponse, GetParameterValuesResponse, Inform, ParameterInfo, ParameterValue,
    Rpc, SetParameterAttributesResponse, SetParameterValuesResponse, TransferComplete,
    TransferFault, UploadResponse,
};
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

/// CPE kind to simulate.
#[derive(Debug, Clone)]
pub struct CpeProfile {
    /// Product class in the DeviceId.
    pub product_class: String,
    /// Firmware at start.
    pub software_version: String,
    /// Firmware after a successful Download.
    pub upgrade_to: String,
    /// true -> Downloads fail (TransferComplete fault 9010).
    pub fail_downloads: bool,
}

impl Default for CpeProfile {
    fn default() -> Self {
        Self {
            product_class: "LoadBox".into(),
            software_version: "1.0.0".into(),
            upgrade_to: "2.0.0".into(),
            fail_downloads: false,
        }
    }
}

#[derive(Debug, Default)]
struct CpeState {
    software_version: String,
    /// CommandKey of a Download/Upload answered as pending (status 1).
    pending_transfer: Option<String>,
    /// Diagnostics object with a requested test -> reported in next session.
    pending_diagnostic: Option<String>,
    /// `ManagementServer.*` values set by the ACS (STUN, CR credentials).
    management: std::collections::BTreeMap<String, String>,
}

/// Simulated CPE: identity + state kept between sessions.
#[derive(Debug, Clone)]
pub struct VirtualCpe {
    /// Unique per CPE.
    pub serial: String,
    /// CR URL in the Inform.
    pub connection_request_url: String,
    pub profile: CpeProfile,
    state: Arc<Mutex<CpeState>>,
}

/// HTTP PUT `body` -> `url` (Upload RPC, USP Backup()).
pub async fn put(url: &str, body: String) -> anyhow::Result<()> {
    let uri: hyper::Uri = url.parse()?;
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("no host"))?
        .to_owned();
    let port = uri.port_u16().unwrap_or(80);
    let io = TokioIo::new(TcpStream::connect((host.as_str(), port)).await?);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);
    let path = uri.path_and_query().map_or("/", |p| p.as_str()).to_owned();
    let resp = sender
        .send_request(
            Request::put(path)
                .header("host", format!("{host}:{port}"))
                .body(Full::new(Bytes::from(body)))?,
        )
        .await?;
    anyhow::ensure!(resp.status().is_success(), "HTTP {}", resp.status());
    Ok(())
}

/// HTTP GET `url` (USP Restore()) -> body.
pub async fn get(url: &str) -> anyhow::Result<Bytes> {
    let uri: hyper::Uri = url.parse()?;
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("no host"))?
        .to_owned();
    let port = uri.port_u16().unwrap_or(80);
    let io = TokioIo::new(TcpStream::connect((host.as_str(), port)).await?);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);
    let path = uri.path_and_query().map_or("/", |p| p.as_str()).to_owned();
    let resp = sender
        .send_request(
            Request::get(path)
                .header("host", format!("{host}:{port}"))
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    anyhow::ensure!(resp.status().is_success(), "HTTP {}", resp.status());
    Ok(resp.into_body().collect().await?.to_bytes())
}

const UNKNOWN_TIME: &str = "0001-01-01T00:00:00Z";

/// Timing of one session.
#[derive(Debug, Clone, Copy)]
pub struct SessionStats {
    /// Inform request -> InformResponse.
    pub inform: Duration,
    /// Whole session until HTTP 204.
    pub session: Duration,
    /// ACS requests answered.
    pub requests: u32,
}

impl VirtualCpe {
    /// CPE with `profile.software_version` at start.
    pub fn new(serial: String, connection_request_url: String, profile: CpeProfile) -> Self {
        let state = CpeState {
            software_version: profile.software_version.clone(),
            pending_transfer: None,
            pending_diagnostic: None,
            management: std::collections::BTreeMap::new(),
        };
        Self {
            serial,
            connection_request_url,
            profile,
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// Running firmware.
    pub fn software_version(&self) -> String {
        self.state
            .lock()
            .map(|s| s.software_version.clone())
            .unwrap_or_default()
    }

    /// `ManagementServer.` parameter set by the ACS, e.g. `STUNServerAddress`.
    pub fn management(&self, name: &str) -> Option<String> {
        self.state
            .lock()
            .ok()
            .and_then(|s| s.management.get(name).cloned())
    }

    fn inform(&self, events: &[(String, String)]) -> Envelope {
        let version = self.software_version();
        let p = |name: &str, value: &str, ty: &str| {
            ParameterValue::new(format!("Device.{name}"), value, ty)
        };
        Envelope::rpc(
            CwmpNamespace::V1_2,
            "1",
            Inform {
                device_id: DeviceId {
                    manufacturer: "Dhonomos Sim".into(),
                    oui: "00AA00".into(),
                    product_class: self.profile.product_class.clone(),
                    serial_number: self.serial.clone(),
                },
                events: events
                    .iter()
                    .map(|(code, key)| EventStruct {
                        event_code: code.clone(),
                        command_key: key.clone(),
                    })
                    .collect(),
                max_envelopes: 1,
                current_time: "2026-10-03T00:00:00Z".into(),
                retry_count: 0,
                parameter_list: vec![
                    p("DeviceInfo.SoftwareVersion", &version, "string"),
                    p("DeviceInfo.HardwareVersion", "A1", "string"),
                    p("DeviceInfo.ProvisioningCode", "", "string"),
                    p("DeviceInfo.UpTime", "3600", "unsignedInt"),
                    p("ManagementServer.ParameterKey", "", "string"),
                    p(
                        "ManagementServer.ConnectionRequestURL",
                        &self.connection_request_url,
                        "string",
                    ),
                    p(
                        "IP.Interface.1.IPv4Address.1.IPAddress",
                        "192.0.2.10",
                        "string",
                    ),
                    p("DeviceInfo.MemoryStatus.Free", "65536", "unsignedInt"),
                ],
            },
        )
    }

    /// Answer of a minimal but compliant CPE.
    fn answer(&self, rpc: &Rpc) -> Body {
        match rpc {
            Rpc::GetParameterValues(r) => Body::Rpc(
                GetParameterValuesResponse {
                    parameter_list: r
                        .parameter_names
                        .iter()
                        .flat_map(|n| {
                            if n.ends_with("Diagnostics.")
                                || n.ends_with(".IPPing.")
                                || n.ends_with(".TraceRoute.")
                            {
                                // Finished ping: fixed, plausible results.
                                [
                                    ("DiagnosticsState", "Complete"),
                                    ("SuccessCount", "4"),
                                    ("FailureCount", "0"),
                                    ("AverageResponseTime", "12"),
                                    ("MinimumResponseTime", "9"),
                                    ("MaximumResponseTime", "17"),
                                ]
                                .iter()
                                .map(|(k, v)| ParameterValue::new(format!("{n}{k}"), *v, "string"))
                                .collect::<Vec<_>>()
                            } else if n.ends_with("NeighboringWiFiDiagnostic.") {
                                let mut v = vec![ParameterValue::new(
                                    format!("{n}DiagnosticsState"),
                                    "Complete",
                                    "string",
                                )];
                                for (i, (ssid, ch, sig)) in
                                    [("CafeNet", "6", "-71"), ("Neighbor-5G", "44", "-80")]
                                        .iter()
                                        .enumerate()
                                {
                                    let r = format!("{n}Result.{}.", i + 1);
                                    v.push(ParameterValue::new(
                                        format!("{r}SSID"),
                                        *ssid,
                                        "string",
                                    ));
                                    v.push(ParameterValue::new(
                                        format!("{r}BSSID"),
                                        format!("02:00:00:00:00:0{i}"),
                                        "string",
                                    ));
                                    v.push(ParameterValue::new(
                                        format!("{r}Channel"),
                                        *ch,
                                        "unsignedInt",
                                    ));
                                    v.push(ParameterValue::new(
                                        format!("{r}SignalStrength"),
                                        *sig,
                                        "int",
                                    ));
                                    v.push(ParameterValue::new(
                                        format!("{r}OperatingFrequencyBand"),
                                        if *ch == "6" { "2.4GHz" } else { "5GHz" },
                                        "string",
                                    ));
                                }
                                v
                            } else if n == "Device.WiFi." {
                                [
                                    ("Radio.1.OperatingFrequencyBand", "2.4GHz"),
                                    ("Radio.1.Channel", "1"),
                                    ("Radio.1.CurrentOperatingChannelBandwidth", "20MHz"),
                                    ("Radio.1.Stats.Noise", "-92"),
                                    ("Radio.1.Status", "Up"),
                                    ("SSID.1.SSID", "Dhonomos-Home"),
                                    ("SSID.1.BSSID", "02:aa:00:00:00:01"),
                                    ("AccessPoint.1.SSIDReference", "Device.WiFi.SSID.1"),
                                    ("AccessPoint.1.Security.ModeEnabled", "WPA2-Personal"),
                                    (
                                        "AccessPoint.1.AssociatedDevice.1.MACAddress",
                                        "3c:22:fb:00:00:01",
                                    ),
                                    ("AccessPoint.1.AssociatedDevice.1.SignalStrength", "-58"),
                                    (
                                        "AccessPoint.1.AssociatedDevice.1.LastDataDownlinkRate",
                                        "144000",
                                    ),
                                ]
                                .iter()
                                .map(|(k, v)| ParameterValue::new(format!("{n}{k}"), *v, "string"))
                                .collect()
                            } else if n == "Device." {
                                // Small config for backups.
                                vec![
                                    ParameterValue::new(
                                        "Device.WiFi.SSID.1.SSID",
                                        format!("Dhonomos-{}", self.serial),
                                        "string",
                                    ),
                                    ParameterValue::new(
                                        "Device.Time.NTPServer1",
                                        "pool.ntp.org",
                                        "string",
                                    ),
                                ]
                            } else if n.ends_with('.') {
                                Vec::new()
                            } else {
                                vec![ParameterValue::new(n.clone(), "0", "string")]
                            }
                        })
                        .collect(),
                }
                .into(),
            ),
            Rpc::SetParameterValues(r) => {
                if let Ok(mut s) = self.state.lock() {
                    for p in &r.parameter_list {
                        if let Some((_, name)) = p.name.split_once(".ManagementServer.") {
                            s.management.insert(name.to_owned(), p.value.clone());
                        }
                    }
                }
                if let Some(p) = r
                    .parameter_list
                    .iter()
                    .find(|p| p.name.ends_with(".DiagnosticsState") && p.value == "Requested")
                    && let Ok(mut s) = self.state.lock()
                {
                    s.pending_diagnostic =
                        Some(p.name.trim_end_matches("DiagnosticsState").to_owned());
                }
                Body::Rpc(SetParameterValuesResponse { status: 0 }.into())
            }
            Rpc::SetParameterAttributes(_) => Body::Rpc(SetParameterAttributesResponse {}.into()),
            Rpc::GetParameterNames(_) => Body::Rpc(
                GetParameterNamesResponse {
                    parameter_list: [
                        ("Device.DeviceInfo.ProvisioningCode", true),
                        ("Device.DeviceInfo.UpTime", false),
                        ("Device.ManagementServer.PeriodicInformInterval", true),
                        ("Device.WiFi.SSID.1.SSID", true),
                        ("Device.Time.NTPServer1", true),
                    ]
                    .iter()
                    .map(|(n, w)| ParameterInfo {
                        name: (*n).into(),
                        writable: *w,
                    })
                    .collect(),
                }
                .into(),
            ),
            // Config PUT now -> TransferComplete in next session.
            Rpc::Upload(u) => {
                let (url, body) = (
                    u.url.clone(),
                    format!("# configuration of {}\n", self.serial),
                );
                tokio::spawn(async move {
                    if let Err(e) = put(&url, body).await {
                        eprintln!("upload to {url}: {e:#}");
                    }
                });
                if let Ok(mut s) = self.state.lock() {
                    s.pending_transfer = Some(u.command_key.clone());
                }
                Body::Rpc(
                    UploadResponse {
                        status: 1,
                        start_time: UNKNOWN_TIME.into(),
                        complete_time: UNKNOWN_TIME.into(),
                    }
                    .into(),
                )
            }
            // Accepted -> outcome via TransferComplete in next session.
            Rpc::Download(d) => {
                if let Ok(mut s) = self.state.lock() {
                    s.pending_transfer = Some(d.command_key.clone());
                }
                Body::Rpc(
                    DownloadResponse {
                        status: 1,
                        start_time: UNKNOWN_TIME.into(),
                        complete_time: UNKNOWN_TIME.into(),
                    }
                    .into(),
                )
            }
            _ => Body::Fault(Fault::new(9000, "Method not supported")),
        }
    }

    /// One full session with the ACS on a new connection.
    pub async fn session(&self, acs: SocketAddr, events: &[&str]) -> anyhow::Result<SessionStats> {
        let start = Instant::now();
        let io = TokioIo::new(TcpStream::connect(acs).await?);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(conn);
        let mut post = async |body: String| -> anyhow::Result<(StatusCode, Bytes)> {
            let resp = sender
                .send_request(Request::post("/").body(Full::new(Bytes::from(body)))?)
                .await?;
            let status = resp.status();
            Ok((status, resp.into_body().collect().await?.to_bytes()))
        };

        // Pending Download done "during CPE reboot".
        let transfer = self.state.lock().ok().and_then(|mut s| {
            let key = s.pending_transfer.take()?;
            if !self.profile.fail_downloads {
                s.software_version = self.profile.upgrade_to.clone();
            }
            Some(key)
        });
        let mut all_events: Vec<(String, String)> = events
            .iter()
            .map(|e| ((*e).to_owned(), String::new()))
            .collect();
        if let Some(key) = &transfer {
            all_events.push(("7 TRANSFER COMPLETE".into(), String::new()));
            all_events.push(("M Download".into(), key.clone()));
        }
        // Requested diagnostic -> done by next session.
        if self
            .state
            .lock()
            .ok()
            .and_then(|mut s| s.pending_diagnostic.take())
            .is_some()
        {
            all_events.push(("8 DIAGNOSTICS COMPLETE".into(), String::new()));
        }
        let (status, _) = post(self.inform(&all_events).encode()).await?;
        anyhow::ensure!(status == StatusCode::OK, "Inform answered with {status}");
        let inform = start.elapsed();

        if let Some(command_key) = transfer {
            let fault = if self.profile.fail_downloads {
                TransferFault {
                    fault_code: 9010,
                    fault_string: "Download failure".into(),
                }
            } else {
                TransferFault {
                    fault_code: 0,
                    fault_string: String::new(),
                }
            };
            let tc = Envelope::rpc(
                CwmpNamespace::V1_2,
                "2",
                TransferComplete {
                    command_key,
                    fault,
                    start_time: "2026-10-03T00:00:00Z".into(),
                    complete_time: "2026-10-03T00:00:10Z".into(),
                },
            );
            let (status, body) = post(tc.encode()).await?;
            anyhow::ensure!(
                status == StatusCode::OK,
                "TransferComplete answered with {status}"
            );
            let ok = matches!(
                Envelope::decode(&body)?.map(|e| e.body),
                Some(Body::Rpc(Rpc::TransferCompleteResponse(_)))
            );
            anyhow::ensure!(ok, "expected TransferCompleteResponse");
        }

        let mut requests = 0;
        let mut next = String::new();
        loop {
            let (status, body) = post(std::mem::take(&mut next)).await?;
            if status == StatusCode::NO_CONTENT {
                break;
            }
            anyhow::ensure!(status == StatusCode::OK, "ACS answered with {status}");
            let env =
                Envelope::decode(&body)?.ok_or_else(|| anyhow::anyhow!("empty 200 response"))?;
            let Body::Rpc(rpc) = &env.body else {
                anyhow::bail!("ACS sent a fault");
            };
            requests += 1;
            anyhow::ensure!(requests < 50, "ACS keeps sending requests");
            next = Envelope {
                namespace: env.namespace,
                header: env.header.clone(),
                body: self.answer(rpc),
            }
            .encode();
        }
        Ok(SessionStats {
            inform,
            session: start.elapsed(),
            requests,
        })
    }
}
