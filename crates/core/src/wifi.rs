//! Wi-Fi view (DG-02): radios, networks, connected stations from the parameter snapshot.
//! TR-181 (`Device.WiFi.`) + TR-098 (`WLANConfiguration`) -> one shape.

use std::collections::BTreeMap;

use dhonomos_store::StoredParam;
use serde_json::{Value, json};

/// `prefix{i}.field` values by instance: `{i -> {field -> value}}`.
/// Field may be nested (`Stats.Noise`).
fn instances<'a>(
    params: &'a [StoredParam],
    prefix: &str,
) -> BTreeMap<u32, BTreeMap<&'a str, &'a str>> {
    let mut out: BTreeMap<u32, BTreeMap<&str, &str>> = BTreeMap::new();
    for p in params {
        let (Some(rest), Some(value)) = (p.path.strip_prefix(prefix), p.value.as_deref()) else {
            continue;
        };
        let Some((i, field)) = rest.split_once('.') else {
            continue;
        };
        if let Ok(i) = i.parse() {
            out.entry(i).or_default().insert(field, value);
        }
    }
    out
}

fn num(v: Option<&&str>) -> Value {
    v.and_then(|s| s.trim().parse::<i64>().ok())
        .map_or(Value::Null, Value::from)
}

fn text(v: Option<&&str>) -> Value {
    v.map_or(Value::Null, |s| Value::from(*s))
}

/// Stations `AssociatedDevice.{j}.*` in the fields of an access point or WLAN.
fn stations(fields: &BTreeMap<&str, &str>, mac_field: &str) -> Vec<Value> {
    let mut by: BTreeMap<u32, BTreeMap<&str, &str>> = BTreeMap::new();
    for (k, v) in fields {
        let Some(rest) = k.strip_prefix("AssociatedDevice.") else {
            continue;
        };
        if let Some((j, f)) = rest.split_once('.')
            && let Ok(j) = j.parse()
        {
            by.entry(j).or_default().insert(f, v);
        }
    }
    by.values()
        .map(|s| {
            json!({
                "mac": text(s.get(mac_field)),
                "signal_dbm": num(s.get("SignalStrength")),
                "down_kbps": num(s.get("LastDataDownlinkRate")),
                "up_kbps": num(s.get("LastDataUplinkRate")),
                "active": s.get("Active").map(|a| *a == "true" || *a == "1"),
            })
        })
        .collect()
}

/// Wi-Fi view of a device snapshot.
pub fn view(params: &[StoredParam]) -> Value {
    // TR-181
    let radios: Vec<Value> = instances(params, "Device.WiFi.Radio.")
        .iter()
        .map(|(i, r)| {
            json!({
                "id": format!("Device.WiFi.Radio.{i}"),
                "enabled": r.get("Enable").map(|v| *v == "true" || *v == "1"),
                "status": text(r.get("Status")),
                "band": text(r.get("OperatingFrequencyBand")),
                "channel": num(r.get("Channel")),
                "bandwidth": text(r.get("CurrentOperatingChannelBandwidth")),
                "standards": text(r.get("OperatingStandards")),
                "tx_power_pct": num(r.get("TransmitPower")),
                "noise_dbm": num(r.get("Stats.Noise")),
            })
        })
        .collect();
    let ssids = instances(params, "Device.WiFi.SSID.");
    let mut networks: Vec<Value> = instances(params, "Device.WiFi.AccessPoint.")
        .values()
        .map(|ap| {
            let ssid = ap
                .get("SSIDReference")
                .and_then(|r| r.trim_end_matches('.').rsplit('.').next())
                .and_then(|i| i.parse::<u32>().ok())
                .and_then(|i| ssids.get(&i));
            json!({
                "ssid": text(ssid.and_then(|s| s.get("SSID"))),
                "bssid": text(ssid.and_then(|s| s.get("BSSID"))),
                "radio": text(ssid.and_then(|s| s.get("LowerLayers"))),
                "enabled": ap.get("Enable").map(|v| *v == "true" || *v == "1"),
                "security": text(ap.get("Security.ModeEnabled")),
                "stations": stations(ap, "MACAddress"),
            })
        })
        .collect();
    // TR-098: InternetGatewayDevice.LANDevice.{l}.WLANConfiguration.{w}.
    for (_, lan) in instances(params, "InternetGatewayDevice.LANDevice.") {
        let mut by: BTreeMap<u32, BTreeMap<&str, &str>> = BTreeMap::new();
        for (k, v) in &lan {
            if let Some(rest) = k.strip_prefix("WLANConfiguration.")
                && let Some((w, f)) = rest.split_once('.')
                && let Ok(w) = w.parse()
            {
                by.entry(w).or_default().insert(f, v);
            }
        }
        for w in by.values() {
            networks.push(json!({
                "ssid": text(w.get("SSID")),
                "bssid": text(w.get("BSSID")),
                "channel": num(w.get("Channel")),
                "standards": text(w.get("Standard")),
                "enabled": w.get("Enable").map(|v| *v == "true" || *v == "1"),
                "security": text(w.get("BeaconType")),
                "stations": stations(w, "AssociatedDeviceMACAddress"),
            }));
        }
    }
    json!({ "radios": radios, "networks": networks })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(path: &str, value: &str) -> StoredParam {
        StoredParam {
            path: path.into(),
            value: Some(value.into()),
            xsd_type: None,
            writable: None,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn tr181_and_tr098_views() {
        let v = view(&[
            p("Device.WiFi.Radio.1.Channel", "36"),
            p("Device.WiFi.Radio.1.OperatingFrequencyBand", "5GHz"),
            p("Device.WiFi.Radio.1.Stats.Noise", "-95"),
            p("Device.WiFi.SSID.2.SSID", "home"),
            p("Device.WiFi.SSID.2.LowerLayers", "Device.WiFi.Radio.1."),
            p(
                "Device.WiFi.AccessPoint.1.SSIDReference",
                "Device.WiFi.SSID.2.",
            ),
            p(
                "Device.WiFi.AccessPoint.1.AssociatedDevice.1.MACAddress",
                "aa:bb:cc:00:00:01",
            ),
            p(
                "Device.WiFi.AccessPoint.1.AssociatedDevice.1.SignalStrength",
                "-61",
            ),
            p(
                "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
                "legacy",
            ),
            p(
                "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.Channel",
                "6",
            ),
            p(
                "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.AssociatedDevice.3.AssociatedDeviceMACAddress",
                "aa:bb:cc:00:00:02",
            ),
        ]);
        assert_eq!(v["radios"][0]["channel"], 36);
        assert_eq!(v["radios"][0]["noise_dbm"], -95);
        assert_eq!(v["networks"][0]["ssid"], "home");
        assert_eq!(v["networks"][0]["stations"][0]["signal_dbm"], -61);
        assert_eq!(v["networks"][1]["ssid"], "legacy");
        assert_eq!(v["networks"][1]["stations"][0]["mac"], "aa:bb:cc:00:00:02");
    }
}
