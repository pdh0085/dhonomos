//! Task kinds: what operators ask devices to do. Independent of the queue.

use dhonomos_cwmp_codec::{
    AddObject, DeleteObject, Download, FactoryReset, GetParameterAttributes, GetParameterNames,
    GetParameterValues, ParameterValue, Reboot, Rpc, SetParameterAttributes,
    SetParameterAttributesStruct, SetParameterValues, Upload,
};
use dhonomos_store::NewTask;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Firmware images of a TR-181 device. Read again at each boot (ADR-108).
pub(crate) const FIRMWARE_IMAGES: &str = "Device.DeviceInfo.FirmwareImage.";

/// Task queued at boot -> read firmware images again (ADR-108).
/// Fallback to the other image changes neither firmware version nor full-read data
/// -> only this read shows it.
/// `boot` = boot ID (Inform CurrentTime, Notify `msg_id`) -> same boot read once.
pub(crate) fn boot_firmware_read(tenant_id: Uuid, device_id: Uuid, boot: &str) -> NewTask {
    let (kind, payload) = TaskKind::GetParameterValues {
        names: vec![FIRMWARE_IMAGES.into()],
    }
    .to_row();
    NewTask {
        priority: -10,
        idempotency_key: Some(format!("boot-fwimage:{device_id}:{boot}")),
        created_by: Some("system:boot".into()),
        ..NewTask::new(tenant_id, device_id, kind, payload)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetValue {
    /// Parameter path.
    pub name: String,
    pub value: String,
    /// XML Schema type, e.g. `unsignedInt`. Default `string`.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub xsd_type: Option<String>,
    /// Password or key -> stored encrypted in queue (needs `--secrets-key`), shown as `********`.
    /// Value starting with `enc:` -> refused.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub secret: bool,
}

/// Notification attribute change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetNotification {
    /// Parameter path.
    pub name: String,
    /// 0 = off, 1 = passive, 2 = active.
    pub notification: i32,
}

/// What a task does. Task table: `kind` + JSON `payload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum TaskKind {
    /// Read values. Path ending in `.` -> subtree.
    GetParameterValues {
        /// Parameter or object paths.
        names: Vec<String>,
    },
    /// Write values.
    SetParameterValues {
        values: Vec<SetValue>,
    },
    /// Get names under a path.
    GetParameterNames {
        /// Object path.
        path: String,
        /// Only direct children.
        #[serde(default)]
        next_level: bool,
    },
    /// Read notification attributes.
    GetParameterAttributes {
        /// Parameter paths.
        names: Vec<String>,
    },
    /// Change notification attributes (CW-18).
    SetParameterAttributes {
        changes: Vec<SetNotification>,
    },
    /// Create object instance.
    AddObject {
        /// Table path (parent of `{i}.`), e.g. `Device.NAT.PortMapping.`.
        object: String,
        /// Params of the new instance, names relative to it (e.g. `Alias`).
        /// USP only: CWMP AddObject RPC has none.
        /// Never secret: only SetParameterValues `values` are sealed + hidden.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        params: Vec<SetValue>,
    },
    /// Delete object instance.
    DeleteObject {
        /// Instance path, e.g. `Device.NAT.PortMapping.3.`.
        object: String,
    },
    Reboot,
    FactoryReset,
    /// Download a file (firmware, config).
    /// Needs `file_id` (uploaded to Dhonomos -> sent as signed URL) or `url` (external server).
    Download {
        /// File stored in Dhonomos -> fills `url`, `file_size` + defaults at send.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        file_id: Option<uuid::Uuid>,
        /// TR-069 file type, e.g. `1 Firmware Upgrade Image`. Default: type of stored file.
        #[serde(default)]
        file_type: String,
        /// URL of an external file.
        #[serde(default)]
        url: String,
        /// File server credentials.
        #[serde(default)]
        username: String,
        /// File server credentials.
        #[serde(default)]
        password: String,
        /// Size in bytes, 0 = unknown.
        #[serde(default)]
        file_size: u32,
        /// SHA-256, lowercase hex (from stored file for `file_id`).
        /// USP device checks download against it. CWMP Download RPC: no such argument.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        sha256: String,
        /// File name on device.
        #[serde(default)]
        target_file_name: String,
        /// Delay before starting.
        #[serde(default)]
        delay_seconds: u32,
    },
    /// Diagnostic test, protocol-neutral inputs (DG-01).
    Diagnostic {
        test: crate::diagnostics::DiagTest,
        /// Inputs, e.g. `host`, `count` (docs/design/06-diagnostics.md).
        #[serde(default)]
        params: std::collections::BTreeMap<String, String>,
    },
    /// Internal (CWMP): read results of diagnostic `task` after 8 DIAGNOSTICS COMPLETE.
    DiagnosticResult {
        /// Diagnostic task it completes.
        task: uuid::Uuid,
        test: crate::diagnostics::DiagTest,
        /// Diagnostics object path.
        object: String,
    },
    /// Run USP command (USP only), e.g. `Device.IP.Diagnostics.IPPing()`.
    Operate {
        /// Command path ending in `()`.
        command: String,
        #[serde(default)]
        input: std::collections::BTreeMap<String, String>,
    },
    /// Upload a file (configuration, log).
    Upload {
        /// TR-069 file type, e.g. `1 Vendor Configuration File`.
        file_type: String,
        url: String,
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
        /// Delay before starting.
        #[serde(default)]
        delay_seconds: u32,
    },
}

impl TaskKind {
    /// `kind` string in the queue.
    pub fn name(&self) -> &'static str {
        match self {
            Self::GetParameterValues { .. } => "get_parameter_values",
            Self::SetParameterValues { .. } => "set_parameter_values",
            Self::GetParameterNames { .. } => "get_parameter_names",
            Self::GetParameterAttributes { .. } => "get_parameter_attributes",
            Self::SetParameterAttributes { .. } => "set_parameter_attributes",
            Self::AddObject { .. } => "add_object",
            Self::DeleteObject { .. } => "delete_object",
            Self::Reboot => "reboot",
            Self::FactoryReset => "factory_reset",
            Self::Download { .. } => "download",
            Self::Upload { .. } => "upload",
            Self::Operate { .. } => "operate",
            Self::Diagnostic { .. } => "diagnostic",
            Self::DiagnosticResult { .. } => "diagnostic_result",
        }
    }

    /// Split into queue columns `(kind, payload)`.
    pub fn to_row(&self) -> (String, serde_json::Value) {
        let v = serde_json::to_value(self).unwrap_or_default();
        let payload = v.get("payload").cloned().unwrap_or(serde_json::json!({}));
        (self.name().to_owned(), payload)
    }

    /// Rebuild from queue columns.
    pub fn from_row(kind: &str, payload: &serde_json::Value) -> Result<Self, serde_json::Error> {
        let unit = matches!(kind, "reboot" | "factory_reset");
        let v = if unit {
            serde_json::json!({ "kind": kind })
        } else {
            serde_json::json!({ "kind": kind, "payload": payload })
        };
        serde_json::from_value(v)
    }

    /// Check a task an operator asks for (API, preset, job).
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Diagnostic { test, params } => test.validate(params),
            Self::DiagnosticResult { .. } => Err("diagnostic_result is internal".into()),
            // Only SetParameterValues `values` are sealed + hidden as secrets.
            Self::AddObject { params, .. } if params.iter().any(|p| p.secret) => {
                Err("AddObject parameters cannot be secret".into())
            }
            Self::Operate { command, .. } if !command.ends_with("()") => Err(format!(
                "{command:?} is not a command path (must end in \"()\")"
            )),
            Self::Download { sha256, .. }
                if !sha256.is_empty()
                    && (sha256.len() != 64
                        || !sha256
                            .bytes()
                            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))) =>
            {
                Err("sha256 must be 64 lowercase hex digits".into())
            }
            _ => Ok(()),
        }
    }

    /// CWMP request, TR-181 (`Device`) root. See [`Self::to_cwmp_in`].
    pub fn to_cwmp(&self, key: &str) -> Result<Rpc, String> {
        self.to_cwmp_in(key, "Device")
    }

    /// CWMP request for this task, data model root `root`.
    /// `key` -> ParameterKey / CommandKey -> TransferComplete matched to task.
    /// USP-only task -> error.
    pub fn to_cwmp_in(&self, key: &str, root: &str) -> Result<Rpc, String> {
        Ok(match self.clone() {
            Self::Diagnostic { test, params } => {
                let object = test.cwmp_object(root).ok_or_else(|| {
                    format!("{test:?} diagnostics are not available on {root} devices")
                })?;
                let unsigned = [
                    "NumberOfRepetitions",
                    "Timeout",
                    "DataBlockSize",
                    "DSCP",
                    "NumberOfTries",
                    "MaxHopCount",
                    "TestFileLength",
                ];
                let mut list: Vec<ParameterValue> = test
                    .device_inputs(&params)
                    .into_iter()
                    .map(|(name, value)| {
                        let ty = if unsigned.contains(&name.as_str()) {
                            "unsignedInt"
                        } else {
                            "string"
                        };
                        ParameterValue::new(format!("{object}{name}"), value, ty)
                    })
                    .collect();
                list.push(ParameterValue::new(
                    format!("{object}DiagnosticsState"),
                    "Requested",
                    "string",
                ));
                SetParameterValues {
                    parameter_list: list,
                    parameter_key: key.to_owned(),
                }
                .into()
            }
            Self::DiagnosticResult { object, .. } => GetParameterValues {
                parameter_names: vec![object],
            }
            .into(),
            Self::GetParameterValues { names } => GetParameterValues {
                parameter_names: names,
            }
            .into(),
            Self::SetParameterValues { values } => SetParameterValues {
                parameter_list: values
                    .into_iter()
                    .map(|v| ParameterValue {
                        name: v.name,
                        value: v.value,
                        xsd_type: Some(v.xsd_type.unwrap_or_else(|| "string".into())),
                    })
                    .collect(),
                parameter_key: key.to_owned(),
            }
            .into(),
            Self::GetParameterNames { path, next_level } => GetParameterNames {
                parameter_path: path,
                next_level,
            }
            .into(),
            Self::GetParameterAttributes { names } => GetParameterAttributes {
                parameter_names: names,
            }
            .into(),
            Self::SetParameterAttributes { changes } => SetParameterAttributes {
                parameter_list: changes
                    .into_iter()
                    .map(|c| SetParameterAttributesStruct {
                        name: c.name,
                        notification_change: true,
                        notification: c.notification,
                        access_list_change: false,
                        access_list: Vec::new(),
                    })
                    .collect(),
            }
            .into(),
            Self::AddObject { params, .. } if !params.is_empty() => {
                return Err("AddObject parameters are not supported over CWMP".into());
            }
            Self::AddObject { object, .. } => AddObject {
                object_name: object,
                parameter_key: key.to_owned(),
            }
            .into(),
            Self::DeleteObject { object } => DeleteObject {
                object_name: object,
                parameter_key: key.to_owned(),
            }
            .into(),
            Self::Reboot => Reboot {
                command_key: key.to_owned(),
            }
            .into(),
            Self::FactoryReset => FactoryReset {}.into(),
            Self::Download {
                file_id: _,
                file_type,
                url,
                username,
                password,
                file_size,
                target_file_name,
                // CWMP Download: no checksum argument.
                sha256: _,
                delay_seconds,
            } => Download {
                command_key: key.to_owned(),
                file_type,
                url,
                username,
                password,
                file_size,
                target_file_name,
                delay_seconds,
                ..Download::default()
            }
            .into(),
            Self::Upload {
                file_type,
                url,
                username,
                password,
                delay_seconds,
            } => Upload {
                command_key: key.to_owned(),
                file_type,
                url,
                username,
                password,
                delay_seconds,
            }
            .into(),
            Self::Operate { .. } => {
                return Err("operate is only supported for USP devices".into());
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_object_parameters_cannot_be_secret() {
        let add = |secret: bool| TaskKind::AddObject {
            object: "Device.WireGuard.Peer.".into(),
            params: vec![SetValue {
                name: "PresharedKey".into(),
                value: "k".into(),
                xsd_type: None,
                secret,
            }],
        };
        assert_eq!(
            add(true).validate().err().as_deref(),
            Some("AddObject parameters cannot be secret")
        );
        assert!(add(false).validate().is_ok());
    }

    #[test]
    fn cwmp_has_no_add_object_parameters() {
        let with = TaskKind::AddObject {
            object: "Device.WireGuard.Peer.".into(),
            params: vec![SetValue {
                name: "Alias".into(),
                value: "a".into(),
                xsd_type: None,
                secret: false,
            }],
        };
        assert_eq!(
            with.to_cwmp("k").err().as_deref(),
            Some("AddObject parameters are not supported over CWMP")
        );
        let without = TaskKind::AddObject {
            object: "Device.WireGuard.Peer.".into(),
            params: vec![],
        };
        assert!(matches!(
            without.to_cwmp("k"),
            Ok(Rpc::AddObject(a)) if a.object_name == "Device.WireGuard.Peer."
        ));
    }

    #[test]
    fn download_checksum_is_hex_sha256() {
        let dl = |sha256: &str| {
            let Ok(kind) = TaskKind::from_row(
                "download",
                &serde_json::json!({"url": "http://f/fw.bin", "sha256": sha256}),
            ) else {
                panic!("not a download payload")
            };
            kind
        };
        assert!(dl("").validate().is_ok());
        assert!(dl(&"0a".repeat(32)).validate().is_ok());
        assert!(dl(&"0A".repeat(32)).validate().is_err(), "uppercase");
        assert!(dl("abc").validate().is_err(), "length");
        // Empty checksum -> not in stored payload.
        assert!(dl("").to_row().1.get("sha256").is_none());
    }

    #[test]
    fn row_round_trip() {
        let kinds = [
            TaskKind::Reboot,
            TaskKind::FactoryReset,
            TaskKind::GetParameterValues {
                names: vec!["Device.".into()],
            },
            TaskKind::SetParameterValues {
                values: vec![SetValue {
                    name: "Device.X".into(),
                    value: "1".into(),
                    xsd_type: Some("unsignedInt".into()),
                    secret: false,
                }],
            },
            TaskKind::Download {
                file_id: None,
                file_type: "1 Firmware Upgrade Image".into(),
                url: "http://f/fw.bin".into(),
                username: String::new(),
                password: String::new(),
                file_size: 0,
                target_file_name: String::new(),
                sha256: String::new(),
                delay_seconds: 0,
            },
        ];
        for k in kinds {
            let (kind, payload) = k.to_row();
            assert_eq!(kind, k.name());
            assert_eq!(TaskKind::from_row(&kind, &payload).ok(), Some(k));
        }
        // Missing optional fields -> defaults.
        let gpn = TaskKind::from_row(
            "get_parameter_names",
            &serde_json::json!({"path": "Device."}),
        );
        assert_eq!(
            gpn.ok(),
            Some(TaskKind::GetParameterNames {
                path: "Device.".into(),
                next_level: false
            })
        );
        assert!(TaskKind::from_row("frobnicate", &serde_json::json!({})).is_err());
    }

    #[test]
    fn cwmp_mapping_uses_key() {
        let Ok(Rpc::Reboot(r)) = TaskKind::Reboot.to_cwmp("task-1") else {
            panic!()
        };
        assert_eq!(r.command_key, "task-1");
        let Ok(Rpc::SetParameterValues(s)) = (TaskKind::SetParameterValues {
            values: vec![SetValue {
                name: "Device.X".into(),
                value: "v".into(),
                xsd_type: None,
                secret: false,
            }],
        })
        .to_cwmp("k") else {
            panic!()
        };
        assert_eq!(s.parameter_key, "k");
        assert_eq!(s.parameter_list[0].xsd_type.as_deref(), Some("string"));
        let op = TaskKind::Operate {
            command: "Device.IP.Diagnostics.IPPing()".into(),
            input: [("Host".to_owned(), "192.0.2.1".to_owned())].into(),
        };
        assert!(op.to_cwmp("k").is_err(), "USP only");
        let (kind, payload) = op.to_row();
        assert_eq!(kind, "operate");
        assert_eq!(TaskKind::from_row(&kind, &payload).ok(), Some(op));
    }
}
