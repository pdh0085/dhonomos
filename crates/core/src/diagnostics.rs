//! Diagnostics: one request + one result shape for CWMP and USP (DG-01).
//! Design: docs/design/06-diagnostics.md.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagTest {
    IpPing,
    TraceRoute,
    NsLookup,
    /// HTTP/FTP download throughput (TR-143).
    Download,
    /// HTTP/FTP upload throughput (TR-143).
    Upload,
    /// Wi-Fi neighbour scan (DG-02).
    WifiNeighbors,
}

impl DiagTest {
    /// (neutral input name, data model argument name).
    fn inputs(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::IpPing => &[
                ("host", "Host"),
                ("count", "NumberOfRepetitions"),
                ("timeout_ms", "Timeout"),
                ("size", "DataBlockSize"),
                ("dscp", "DSCP"),
                ("interface", "Interface"),
            ],
            Self::TraceRoute => &[
                ("host", "Host"),
                ("tries", "NumberOfTries"),
                ("timeout_ms", "Timeout"),
                ("max_hops", "MaxHopCount"),
                ("size", "DataBlockSize"),
                ("dscp", "DSCP"),
                ("interface", "Interface"),
            ],
            Self::NsLookup => &[
                ("host", "HostName"),
                ("server", "DNSServer"),
                ("count", "NumberOfRepetitions"),
                ("timeout_ms", "Timeout"),
                ("interface", "Interface"),
            ],
            // `size` -> size of the file server test link when no `url`; not sent to the device.
            Self::Download => &[
                ("url", "DownloadURL"),
                ("size", ""),
                ("dscp", "DSCP"),
                ("interface", "Interface"),
            ],
            Self::Upload => &[
                ("url", "UploadURL"),
                ("size", "TestFileLength"),
                ("dscp", "DSCP"),
                ("interface", "Interface"),
            ],
            Self::WifiNeighbors => &[],
        }
    }

    fn required(self) -> Option<&'static str> {
        match self {
            // No url -> run against the file server (`files::resolve_diagnostic`).
            Self::Download | Self::Upload | Self::WifiNeighbors => None,
            _ => Some("host"),
        }
    }

    /// CWMP diagnostics object for a data model root (`Device` or `InternetGatewayDevice`).
    /// TR-098: no NSLookup + no Wi-Fi neighbour object -> `None`.
    pub fn cwmp_object(self, root: &str) -> Option<String> {
        let path = match (root, self) {
            ("InternetGatewayDevice", Self::IpPing) => "IPPingDiagnostics.",
            ("InternetGatewayDevice", Self::TraceRoute) => "TraceRouteDiagnostics.",
            ("InternetGatewayDevice", Self::Download) => "DownloadDiagnostics.",
            ("InternetGatewayDevice", Self::Upload) => "UploadDiagnostics.",
            ("InternetGatewayDevice", Self::NsLookup | Self::WifiNeighbors) => return None,
            (_, Self::WifiNeighbors) => "WiFi.NeighboringWiFiDiagnostic.",
            (_, Self::IpPing) => "IP.Diagnostics.IPPing.",
            (_, Self::TraceRoute) => "IP.Diagnostics.TraceRoute.",
            (_, Self::NsLookup) => "DNS.Diagnostics.NSLookupDiagnostics.",
            (_, Self::Download) => "IP.Diagnostics.DownloadDiagnostics.",
            (_, Self::Upload) => "IP.Diagnostics.UploadDiagnostics.",
        };
        Some(format!("{root}.{path}"))
    }

    pub fn usp_command(self) -> &'static str {
        match self {
            Self::IpPing => "Device.IP.Diagnostics.IPPing()",
            Self::TraceRoute => "Device.IP.Diagnostics.TraceRoute()",
            Self::NsLookup => "Device.DNS.Diagnostics.NSLookupDiagnostics()",
            Self::Download => "Device.IP.Diagnostics.DownloadDiagnostics()",
            Self::Upload => "Device.IP.Diagnostics.UploadDiagnostics()",
            Self::WifiNeighbors => "Device.WiFi.NeighboringWiFiDiagnostic()",
        }
    }

    /// Check neutral inputs: names known, required one present.
    pub fn validate(self, params: &BTreeMap<String, String>) -> Result<(), String> {
        let known = self.inputs();
        if let Some(bad) = params.keys().find(|k| !known.iter().any(|(n, _)| n == k)) {
            let names: Vec<&str> = known.iter().map(|(n, _)| *n).collect();
            return Err(format!(
                "unknown input {bad:?}; expected one of {}",
                names.join(", ")
            ));
        }
        if let Some(required) = self.required()
            && params.get(required).is_none_or(|v| v.trim().is_empty())
        {
            return Err(format!("input {required:?} is required"));
        }
        Ok(())
    }

    /// Inputs under data model names. Input without a device argument -> dropped.
    pub fn device_inputs(self, params: &BTreeMap<String, String>) -> Vec<(String, String)> {
        self.inputs()
            .iter()
            .filter(|(_, name)| !name.is_empty())
            .filter_map(|(neutral, name)| {
                params
                    .get(*neutral)
                    .map(|v| ((*name).to_owned(), v.clone()))
            })
            .collect()
    }
}

fn int(raw: &BTreeMap<String, String>, name: &str) -> Value {
    raw.get(name)
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map_or(Value::Null, Value::from)
}

fn text(raw: &BTreeMap<String, String>, name: &str) -> Value {
    raw.get(name)
        .map_or(Value::Null, |v| Value::from(v.clone()))
}

/// Entries `prefix.{i}.field` -> by instance number.
fn instances<'a>(
    raw: &'a BTreeMap<String, String>,
    prefix: &str,
) -> BTreeMap<u32, BTreeMap<&'a str, &'a str>> {
    let mut out: BTreeMap<u32, BTreeMap<&str, &str>> = BTreeMap::new();
    for (k, v) in raw {
        let Some(rest) = k.strip_prefix(prefix).and_then(|r| r.strip_prefix('.')) else {
            continue;
        };
        let Some((i, field)) = rest.split_once('.') else {
            continue;
        };
        if let Ok(i) = i.parse() {
            out.entry(i).or_default().insert(field, v);
        }
    }
    out
}

/// ms between two ISO 8601 times, optional fractions (TR-143 BOM/EOM).
/// Parse fail or not `> 0` -> `None`.
fn duration_ms(from: Option<&String>, to: Option<&String>) -> Option<f64> {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    let parse = |s: &String| OffsetDateTime::parse(s, &Rfc3339).ok();
    let (a, b) = (parse(from?)?, parse(to?)?);
    let ms = (b - a).as_seconds_f64() * 1000.0;
    (ms > 0.0).then_some(ms)
}

/// Device values -> normalized result.
/// Names relative to the diagnostics object or USP output arguments.
/// Returns (test completed, result doc).
pub fn normalize(test: DiagTest, raw: &BTreeMap<String, String>) -> (bool, Value) {
    let status = raw
        .get("DiagnosticsState")
        .or_else(|| raw.get("Status"))
        .cloned()
        .unwrap_or_default();
    let ok = status == "Complete";
    let result = match test {
        DiagTest::IpPing => json!({
            "success_count": int(raw, "SuccessCount"),
            "failure_count": int(raw, "FailureCount"),
            "avg_ms": int(raw, "AverageResponseTime"),
            "min_ms": int(raw, "MinimumResponseTime"),
            "max_ms": int(raw, "MaximumResponseTime"),
        }),
        DiagTest::TraceRoute => json!({
            "response_ms": int(raw, "ResponseTime"),
            "hops": instances(raw, "RouteHops").values().map(|h| json!({
                "host": h.get("Host"),
                "address": h.get("HostAddress"),
                "error_code": h.get("ErrorCode").and_then(|v| v.parse::<i64>().ok()),
                "rtt_ms": h.get("RTTimes").map(|t| t.split(',').filter_map(|x| x.trim().parse::<i64>().ok()).collect::<Vec<_>>()),
            })).collect::<Vec<_>>(),
        }),
        DiagTest::NsLookup => json!({
            "success_count": int(raw, "SuccessCount"),
            "answers": instances(raw, "Result").values().map(|r| json!({
                "status": r.get("Status"),
                "answer_type": r.get("AnswerType"),
                "host_name": r.get("HostNameReturned"),
                "addresses": r.get("IPAddresses").map(|a| a.split(',').map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>()),
                "server": r.get("DNSServerIP"),
                "response_ms": r.get("ResponseTime").and_then(|v| v.parse::<i64>().ok()),
            })).collect::<Vec<_>>(),
        }),
        DiagTest::WifiNeighbors => json!({
            "neighbors": instances(raw, "Result").values().map(|r| json!({
                "ssid": r.get("SSID"),
                "bssid": r.get("BSSID"),
                "channel": r.get("Channel").and_then(|v| v.parse::<i64>().ok()),
                "signal_dbm": r.get("SignalStrength").and_then(|v| v.parse::<i64>().ok()),
                "band": r.get("OperatingFrequencyBand"),
                "bandwidth": r.get("OperatingChannelBandwidth"),
                "standards": r.get("OperatingStandards"),
                "security": r.get("SecurityModeEnabled"),
                "noise_dbm": r.get("Noise").and_then(|v| v.parse::<i64>().ok()),
            })).collect::<Vec<_>>(),
        }),
        DiagTest::Download | DiagTest::Upload => {
            // TR-181 -> bytes moved; TR-098 upload -> only echo of the requested length.
            let names: &[&str] = if test == DiagTest::Download {
                &["TestBytesReceived"]
            } else {
                &["TestBytesSent", "TestFileLength"]
            };
            let bytes = names
                .iter()
                .find_map(|n| raw.get(*n))
                .and_then(|v| v.parse::<f64>().ok());
            let ms = duration_ms(raw.get("BOMTime"), raw.get("EOMTime"));
            json!({
                "bytes": bytes,
                "duration_ms": ms,
                "throughput_bps": bytes.zip(ms).map(|(b, ms)| (b * 8.0 * 1000.0 / ms).round()),
                "rom_time": text(raw, "ROMTime"),
                "bom_time": text(raw, "BOMTime"),
                "eom_time": text(raw, "EOMTime"),
            })
        }
    };
    (
        ok,
        json!({ "test": test, "status": status, "ok": ok, "result": result, "raw": raw }),
    )
}

/// Normalized result -> task outcome. State != `Complete` (e.g. `Error_*`) -> task fails.
pub fn outcome(test: DiagTest, raw: &BTreeMap<String, String>) -> Result<Value, String> {
    let (ok, doc) = normalize(test, raw);
    if ok {
        Ok(doc)
    } else {
        let status = doc["status"].as_str().unwrap_or_default();
        Err(if status.is_empty() {
            "the device reported no diagnostics state".to_owned()
        } else {
            format!("diagnostic ended with {status}")
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect()
    }

    #[test]
    fn inputs_are_checked_and_mapped() {
        let p = map(&[("host", "192.0.2.1"), ("count", "3")]);
        assert!(DiagTest::IpPing.validate(&p).is_ok());
        assert_eq!(
            DiagTest::IpPing.device_inputs(&p),
            vec![
                ("Host".into(), "192.0.2.1".into()),
                ("NumberOfRepetitions".into(), "3".into())
            ]
        );
        assert!(DiagTest::IpPing.validate(&map(&[("count", "3")])).is_err());
        assert!(
            DiagTest::IpPing
                .validate(&map(&[("host", "h"), ("ttl", "3")]))
                .is_err()
        );
        assert!(
            DiagTest::Download
                .validate(&map(&[("url", "http://x/f")]))
                .is_ok()
        );
        // No url -> file server = test server; `size` stays with Dhonomos.
        assert!(
            DiagTest::Download
                .validate(&map(&[("size", "1000")]))
                .is_ok()
        );
        assert_eq!(
            DiagTest::Download.device_inputs(&map(&[("url", "http://x/f"), ("size", "9")])),
            vec![("DownloadURL".into(), "http://x/f".into())]
        );
        assert!(DiagTest::WifiNeighbors.validate(&map(&[])).is_ok());
        assert_eq!(
            DiagTest::WifiNeighbors.cwmp_object("Device").unwrap(),
            "Device.WiFi.NeighboringWiFiDiagnostic."
        );
        assert_eq!(
            DiagTest::IpPing
                .cwmp_object("InternetGatewayDevice")
                .unwrap(),
            "InternetGatewayDevice.IPPingDiagnostics."
        );
        assert_eq!(
            DiagTest::NsLookup.cwmp_object("InternetGatewayDevice"),
            None
        );
    }

    #[test]
    fn results_are_normalized() {
        let (ok, doc) = normalize(
            DiagTest::IpPing,
            &map(&[
                ("DiagnosticsState", "Complete"),
                ("SuccessCount", "4"),
                ("FailureCount", "0"),
                ("AverageResponseTime", "12"),
            ]),
        );
        assert!(ok);
        assert_eq!(doc["result"]["success_count"], 4);
        assert_eq!(doc["result"]["avg_ms"], 12);

        let (_, doc) = normalize(
            DiagTest::TraceRoute,
            &map(&[
                ("Status", "Complete"),
                ("RouteHops.2.Host", "b"),
                ("RouteHops.1.Host", "a"),
                ("RouteHops.1.RTTimes", "1,2, 3"),
            ]),
        );
        assert_eq!(doc["result"]["hops"][0]["host"], "a");
        assert_eq!(doc["result"]["hops"][0]["rtt_ms"], json!([1, 2, 3]));
        assert_eq!(doc["result"]["hops"][1]["host"], "b");

        let (_, doc) = normalize(
            DiagTest::Download,
            &map(&[
                ("DiagnosticsState", "Complete"),
                ("TestBytesReceived", "1000000"),
                ("BOMTime", "2026-10-04T00:00:00.000000Z"),
                ("EOMTime", "2026-10-04T00:00:02.000000Z"),
            ]),
        );
        assert_eq!(doc["result"]["throughput_bps"], 4_000_000.0);
        // Upload -> bytes sent (USP output, TR-181), else the requested length.
        let (_, doc) = normalize(
            DiagTest::Upload,
            &map(&[
                ("Status", "Complete"),
                ("TestBytesSent", "500000"),
                ("BOMTime", "2026-10-04T00:00:00.000000Z"),
                ("EOMTime", "2026-10-04T00:00:01.000000Z"),
            ]),
        );
        assert_eq!(
            (&doc["result"]["bytes"], &doc["result"]["throughput_bps"]),
            (&json!(500_000.0), &json!(4_000_000.0))
        );
        let (_, doc) = normalize(DiagTest::Upload, &map(&[("TestFileLength", "7")]));
        assert_eq!(doc["result"]["bytes"], 7.0);

        let err = outcome(
            DiagTest::IpPing,
            &map(&[("DiagnosticsState", "Error_CannotResolveHostName")]),
        );
        assert_eq!(
            err.unwrap_err(),
            "diagnostic ended with Error_CannotResolveHostName"
        );
    }
}
