//! Config backups, drift + restore (CO-08). Device replacement (CO-14) builds on them.
//!
//! Backup = writable values of the parameter snapshot.
//! Left out: unit settings, not config (management server, device info, USP agent, MQTT client).
//! Left out: secrets -> devices read them back empty.

use std::collections::{BTreeMap, HashMap};

use dhonomos_store::StoredParam;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::task::{SetValue, TaskKind};

/// One saved value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupValue {
    pub path: String,
    pub value: String,
    /// XML Schema type, if known.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub xsd_type: Option<String>,
}

/// Result of [`snapshot`]: kept values + left-out counts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub values: Vec<BackupValue>,
    /// Secrets left out (read back empty).
    pub skipped_secrets: usize,
    /// Left out: writability not known.
    pub unknown_writability: usize,
}

const UNIT_SPECIFIC: &[&str] = &[
    ".ManagementServer.",
    ".DeviceInfo.",
    ".LocalAgent.",
    ".MQTT.Client.",
    ".Time.CurrentLocalTime",
];

const SECRET_SUFFIXES: &[&str] = &["Password", "Passphrase", "PreSharedKey", "WEPKey", "Secret"];

fn is_secret(path: &str) -> bool {
    let leaf = path.rsplit('.').next().unwrap_or(path);
    SECRET_SUFFIXES.iter().any(|s| leaf.ends_with(s))
}

/// `Device.WiFi.SSID.1.SSID` -> (`Device.WiFi.SSID.{i}.`, `SSID`).
fn template(path: &str) -> Option<(String, &str)> {
    let (object, name) = path.rsplit_once('.')?;
    let object: Vec<&str> = object
        .split('.')
        .map(|seg| {
            if !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()) {
                "{i}"
            } else {
                seg
            }
        })
        .collect();
    Some((format!("{}.", object.join(".")), name))
}

/// (object template, parameter name) -> writable.
/// Source: supported data model doc (USP GetSupportedDM, ADR-034).
fn model_writability(model: &Value) -> HashMap<(String, String), bool> {
    let mut out = HashMap::new();
    for o in model["objects"].as_array().into_iter().flatten() {
        let Some(path) = o["path"].as_str() else {
            continue;
        };
        for p in o["params"].as_array().into_iter().flatten() {
            if let (Some(name), Some(access)) = (p["name"].as_str(), p["access"].as_str()) {
                out.insert((path.to_owned(), name.to_owned()), access != "read_only");
            }
        }
    }
    out
}

/// Values of `params` worth saving.
///
/// Writability: snapshot (CWMP GPN), else supported data model of the device (USP).
pub fn snapshot(params: &[StoredParam], model: Option<&Value>) -> Snapshot {
    let model = model.map(model_writability).unwrap_or_default();
    let mut out = Snapshot::default();
    for p in params {
        let Some(value) = &p.value else { continue };
        if p.path.ends_with('.') || UNIT_SPECIFIC.iter().any(|u| p.path.contains(u)) {
            continue;
        }
        let writable = p.writable.or_else(|| {
            let (object, name) = template(&p.path)?;
            model.get(&(object, name.to_owned())).copied()
        });
        match writable {
            Some(true) if is_secret(&p.path) => out.skipped_secrets += 1,
            Some(true) => out.values.push(BackupValue {
                path: p.path.clone(),
                value: value.clone(),
                xsd_type: p.xsd_type.clone(),
            }),
            Some(false) => {}
            None => out.unknown_writability += 1,
        }
    }
    out
}

/// SPV tasks for `values`, max `chunk` per task.
///
/// Why: CPEs reject very large requests + one bad value fails the whole request.
pub fn restore_tasks(values: &[BackupValue], chunk: usize) -> Vec<TaskKind> {
    values
        .chunks(chunk.max(1))
        .map(|c| TaskKind::SetParameterValues {
            values: c
                .iter()
                .map(|v| SetValue {
                    name: v.path.clone(),
                    value: v.value.clone(),
                    xsd_type: v.xsd_type.clone(),
                    secret: false,
                })
                .collect(),
        })
        .collect()
}

/// Drift: backup vs current snapshot.
pub fn diff(backup: &[BackupValue], current: &[StoredParam]) -> Value {
    let now: BTreeMap<&str, Option<&str>> = current
        .iter()
        .map(|p| (p.path.as_str(), p.value.as_deref()))
        .collect();
    let mut changed = Vec::new();
    let mut missing = Vec::new();
    let mut same = 0;
    for b in backup {
        match now.get(b.path.as_str()) {
            Some(Some(v)) if *v == b.value => same += 1,
            Some(v) => changed.push(json!({ "path": b.path, "backup": b.value, "current": v })),
            None => missing.push(b.path.clone()),
        }
    }
    json!({ "changed": changed, "missing": missing, "unchanged": same })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn param(path: &str, value: &str, writable: Option<bool>) -> StoredParam {
        StoredParam {
            path: path.into(),
            value: Some(value.into()),
            xsd_type: Some("string".into()),
            writable,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn backups_keep_configuration_only() {
        let params = [
            param("Device.WiFi.SSID.1.SSID", "home", Some(true)),
            param(
                "Device.WiFi.AccessPoint.1.Security.KeyPassphrase",
                "",
                Some(true),
            ),
            param("Device.WiFi.SSID.1.Stats.BytesSent", "5", Some(false)),
            param(
                "Device.ManagementServer.PeriodicInformInterval",
                "60",
                Some(true),
            ),
            param("Device.DeviceInfo.ProvisioningCode", "X", Some(true)),
            param("Device.NAT.PortMapping.2.ExternalPort", "8080", None),
            param("Device.Hosts.HostNumberOfEntries", "3", None),
        ];
        let model = json!({ "objects": [
            { "path": "Device.NAT.PortMapping.{i}.", "params": [ { "name": "ExternalPort", "access": "read_write" } ] }
        ] });
        let s = snapshot(&params, Some(&model));
        let paths: Vec<&str> = s.values.iter().map(|v| v.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "Device.WiFi.SSID.1.SSID",
                "Device.NAT.PortMapping.2.ExternalPort"
            ]
        );
        assert_eq!((s.skipped_secrets, s.unknown_writability), (1, 1));

        let tasks = restore_tasks(&s.values, 1);
        assert_eq!(tasks.len(), 2);

        let current = [param("Device.WiFi.SSID.1.SSID", "guest", Some(true))];
        let d = diff(&s.values, &current);
        assert_eq!(d["changed"][0]["current"], "guest");
        assert_eq!(d["missing"][0], "Device.NAT.PortMapping.2.ExternalPort");
    }
}
