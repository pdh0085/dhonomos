//! Task kinds -> USP requests, USP responses -> task results.

use std::collections::BTreeMap;

use dhonomos_store::ParamUpdate;
use dhonomos_usp_proto::msg::{self, request::ReqType, response::RespType};
use serde_json::{Value, json};

use crate::task::TaskKind;

/// USP request for a task. `key` -> Operate CommandKey.
pub fn to_request(kind: &TaskKind, key: &str) -> Result<ReqType, String> {
    Ok(match kind {
        TaskKind::GetParameterValues { names } => ReqType::Get(msg::Get {
            param_paths: names.clone(),
            max_depth: 0,
        }),
        TaskKind::SetParameterValues { values } => {
            // Group by object, keep first-seen order.
            let mut objs: Vec<msg::set::UpdateObject> = Vec::new();
            for v in values {
                let (obj, param) = split_param(&v.name)?;
                let setting = msg::set::UpdateParamSetting {
                    param: param.to_owned(),
                    value: v.value.clone(),
                    required: true,
                };
                match objs.iter_mut().find(|o| o.obj_path == obj) {
                    Some(o) => o.param_settings.push(setting),
                    None => objs.push(msg::set::UpdateObject {
                        obj_path: obj.to_owned(),
                        param_settings: vec![setting],
                    }),
                }
            }
            ReqType::Set(msg::Set {
                allow_partial: false,
                update_objs: objs,
            })
        }
        TaskKind::AddObject { object, params } => ReqType::Add(msg::Add {
            allow_partial: false,
            create_objs: vec![msg::add::CreateObject {
                obj_path: object.clone(),
                param_settings: params
                    .iter()
                    .map(|p| msg::add::CreateParamSetting {
                        param: p.name.clone(),
                        value: p.value.clone(),
                        required: true,
                    })
                    .collect(),
            }],
        }),
        TaskKind::DeleteObject { object } => ReqType::Delete(msg::Delete {
            allow_partial: false,
            obj_paths: vec![object.clone()],
        }),
        TaskKind::Reboot => operate("Device.Reboot()", key),
        TaskKind::FactoryReset => operate("Device.FactoryReset()", key),
        TaskKind::Diagnostic { test, params } => ReqType::Operate(msg::Operate {
            command: test.usp_command().into(),
            command_key: key.into(),
            send_resp: true,
            input_args: test.device_inputs(params).into_iter().collect(),
        }),
        TaskKind::Operate { command, input } => {
            if !command.ends_with("()") {
                return Err(format!(
                    "{command:?} is not a command path (must end in \"()\")"
                ));
            }
            ReqType::Operate(msg::Operate {
                command: command.clone(),
                command_key: key.into(),
                send_resp: true,
                input_args: input.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            })
        }
        other => return Err(format!("{} is not supported for USP devices", other.name())),
    })
}

fn operate(command: &str, key: &str) -> ReqType {
    ReqType::Operate(msg::Operate {
        command: command.into(),
        command_key: key.into(),
        send_resp: true,
        input_args: Default::default(),
    })
}

fn split_param(path: &str) -> Result<(&str, &str), String> {
    match path.rfind('.') {
        Some(i) if i + 1 < path.len() => Ok((&path[..=i], &path[i + 1..])),
        _ => Err(format!("{path:?} is not a parameter path")),
    }
}

/// Response -> effect on task + snapshot.
#[derive(Debug, Default, PartialEq)]
pub struct Applied {
    /// Task result (stored as JSON).
    pub result: Value,
    /// Parameters to store.
    pub params: Vec<ParamUpdate>,
    /// Object subtrees to drop from the snapshot (Delete).
    pub deleted: Vec<String>,
    /// Operation still running -> completed by OperationComplete.
    pub pending: bool,
    /// OK object reads of a GetParameterValues Get (ADR-111).
    /// (requested path, all returned paths = params + their objects).
    /// Only requested paths that may drop stored rows the Agent no longer has.
    pub reads: Vec<(String, Vec<String>)>,
}

/// Interpret a response. `Err` = failure message for the task.
pub fn apply(kind: &TaskKind, resp: &msg::Response) -> Result<Applied, String> {
    let fail = |code: u32, msg: &str| Err(format!("{code} {msg}"));
    match resp.resp_type.as_ref() {
        Some(RespType::GetResp(g)) => {
            let mut params = Vec::new();
            let mut errors = Vec::new();
            let mut reads = Vec::new();
            for r in &g.req_path_results {
                if r.err_code != 0 {
                    errors.push(format!(
                        "{}: {} {}",
                        r.requested_path, r.err_code, r.err_msg
                    ));
                } else if matches!(kind, TaskKind::GetParameterValues { .. })
                    && crate::param_prune::prunable(&r.requested_path)
                {
                    let mut paths = Vec::new();
                    for res in &r.resolved_path_results {
                        paths.push(res.resolved_path.clone());
                        paths.extend(
                            res.result_params
                                .keys()
                                .map(|name| format!("{}{name}", res.resolved_path)),
                        );
                    }
                    reads.push((r.requested_path.clone(), paths));
                }
                for res in &r.resolved_path_results {
                    let sorted: BTreeMap<_, _> = res.result_params.iter().collect();
                    for (name, value) in sorted {
                        params.push(ParamUpdate {
                            path: format!("{}{name}", res.resolved_path),
                            value: Some(value.clone()),
                            ..ParamUpdate::default()
                        });
                    }
                }
            }
            if params.is_empty() && !errors.is_empty() {
                return Err(errors.join("; "));
            }
            Ok(Applied {
                result: json!({ "parameters": params.len(), "errors": errors }),
                params,
                reads,
                ..Applied::default()
            })
        }
        Some(RespType::SetResp(s)) => {
            use msg::set_resp::updated_object_result::operation_status::OperStatus;
            let mut params = Vec::new();
            for r in &s.updated_obj_results {
                match r.oper_status.as_ref().and_then(|o| o.oper_status.as_ref()) {
                    Some(OperStatus::OperFailure(f)) => {
                        let mut msg = f.err_msg.clone();
                        for inst in &f.updated_inst_failures {
                            for p in &inst.param_errs {
                                msg.push_str(&format!(
                                    " | {}{}: {} {}",
                                    inst.affected_path, p.param, p.err_code, p.err_msg
                                ));
                            }
                        }
                        return fail(f.err_code, &msg);
                    }
                    Some(OperStatus::OperSuccess(ok)) => {
                        for inst in &ok.updated_inst_results {
                            for (name, value) in &inst.updated_params {
                                params.push(ParamUpdate {
                                    path: format!("{}{name}", inst.affected_path),
                                    value: Some(value.clone()),
                                    writable: Some(true),
                                    ..ParamUpdate::default()
                                });
                            }
                        }
                    }
                    None => {}
                }
            }
            // Agents may omit updated_params -> use requested values.
            if params.is_empty()
                && let TaskKind::SetParameterValues { values } = kind
            {
                params = values
                    .iter()
                    .map(|v| ParamUpdate {
                        path: v.name.clone(),
                        value: Some(v.value.clone()),
                        writable: Some(true),
                        ..ParamUpdate::default()
                    })
                    .collect();
            }
            // Secrets never in the snapshot, requested or echoed by the Agent.
            // Same rule as CWMP SetParameterValuesResponse.
            if let TaskKind::SetParameterValues { values } = kind {
                for p in &mut params {
                    if values.iter().any(|v| v.secret && v.name == p.path) {
                        p.value = Some(String::new());
                    }
                }
            }
            Ok(Applied {
                result: json!({ "updated": params.len() }),
                params,
                ..Applied::default()
            })
        }
        Some(RespType::AddResp(a)) => {
            use msg::add_resp::created_object_result::operation_status::OperStatus;
            let mut created = Vec::new();
            for r in &a.created_obj_results {
                match r.oper_status.as_ref().and_then(|o| o.oper_status.as_ref()) {
                    Some(OperStatus::OperFailure(f)) => return fail(f.err_code, &f.err_msg),
                    Some(OperStatus::OperSuccess(ok)) => created.push(ok.instantiated_path.clone()),
                    None => {}
                }
            }
            Ok(Applied {
                result: json!({ "instantiated_paths": created }),
                ..Applied::default()
            })
        }
        Some(RespType::DeleteResp(d)) => {
            use msg::delete_resp::deleted_object_result::operation_status::OperStatus;
            let mut deleted = Vec::new();
            for r in &d.deleted_obj_results {
                match r.oper_status.as_ref().and_then(|o| o.oper_status.as_ref()) {
                    Some(OperStatus::OperFailure(f)) => return fail(f.err_code, &f.err_msg),
                    Some(OperStatus::OperSuccess(ok)) => {
                        deleted.extend(ok.affected_paths.iter().cloned())
                    }
                    None => {}
                }
            }
            Ok(Applied {
                result: json!({ "affected_paths": deleted }),
                deleted,
                ..Applied::default()
            })
        }
        Some(RespType::OperateResp(o)) => {
            use msg::operate_resp::operation_result::OperationResp;
            let mut pending = false;
            let mut outputs = Vec::new();
            for r in &o.operation_results {
                match &r.operation_resp {
                    Some(OperationResp::CmdFailure(f)) => return fail(f.err_code, &f.err_msg),
                    Some(OperationResp::ReqObjPath(p)) => {
                        pending = true;
                        outputs.push(json!({ "command": r.executed_command, "request": p }));
                    }
                    Some(OperationResp::ReqOutputArgs(a)) => {
                        // Synchronous diagnostic -> normalize now (DG-01).
                        if let TaskKind::Diagnostic { test, .. } = kind {
                            let raw = a
                                .output_args
                                .iter()
                                .map(|(k, v)| (k.clone(), v.clone()))
                                .collect();
                            return crate::diagnostics::outcome(*test, &raw).map(|result| {
                                Applied {
                                    result,
                                    ..Applied::default()
                                }
                            });
                        }
                        outputs.push(
                            json!({ "command": r.executed_command, "output": a.output_args }),
                        );
                    }
                    None => {}
                }
            }
            Ok(Applied {
                result: json!({ "operations": outputs }),
                pending,
                ..Applied::default()
            })
        }
        other => Err(format!("unexpected response {other:?}")),
    }
}

/// Firmware image slot to download into (FW-05).
/// First `Device.DeviceInfo.FirmwareImage.{i}.` != `ActiveFirmwareImage`.
/// Input: Get of `Device.DeviceInfo.FirmwareImage.` + `Device.DeviceInfo.ActiveFirmwareImage`.
pub fn firmware_bank(params: &[ParamUpdate]) -> Result<String, String> {
    const PREFIX: &str = "Device.DeviceInfo.FirmwareImage.";
    let active = params
        .iter()
        .find(|p| p.path == "Device.DeviceInfo.ActiveFirmwareImage")
        .and_then(|p| p.value.clone())
        .map(|v| format!("{}.", v.trim_end_matches('.')))
        .unwrap_or_default();
    let mut banks: Vec<u32> = params
        .iter()
        .filter_map(|p| p.path.strip_prefix(PREFIX))
        .filter_map(|rest| rest.split('.').next()?.parse().ok())
        .collect();
    banks.sort_unstable();
    banks.dedup();
    banks
        .into_iter()
        .map(|i| format!("{PREFIX}{i}."))
        .find(|bank| *bank != active)
        .ok_or_else(|| "the device has no inactive firmware image slot".into())
}

/// `{bank}Download()` for a resolved Download task.
/// AutoActivate -> device reboots into the new image.
pub fn firmware_download(bank: &str, kind: &TaskKind, key: &str) -> Result<ReqType, String> {
    let TaskKind::Download {
        file_type,
        url,
        username,
        password,
        file_size,
        sha256,
        ..
    } = kind
    else {
        return Err("not a download".into());
    };
    if !file_type.starts_with("1 ") {
        return Err(format!(
            "{file_type:?} downloads are not supported for USP devices (firmware and vendor configuration files only)"
        ));
    }
    if url.is_empty() {
        return Err("the download has no URL".into());
    }
    let mut input = std::collections::HashMap::from([
        ("URL".to_owned(), url.clone()),
        ("AutoActivate".to_owned(), "true".to_owned()),
    ]);
    if *file_size > 0 {
        input.insert("FileSize".into(), file_size.to_string());
    }
    // Checksum via the authenticated USP channel -> device can reject an image swapped
    // on the plain HTTP path from the file server.
    if !sha256.is_empty() {
        input.insert("CheckSumAlgorithm".into(), "SHA-256".into());
        input.insert("CheckSum".into(), sha256.clone());
    }
    if !username.is_empty() {
        input.insert("Username".into(), username.clone());
        input.insert("Password".into(), password.clone());
    }
    Ok(ReqType::Operate(msg::Operate {
        command: format!("{bank}Download()"),
        command_key: key.into(),
        send_resp: true,
        input_args: input,
    }))
}

/// Parameter writability from a USP supported data model (GetSupportedDM, US-11).
/// `read_write` + `write_only` -> writable.
/// Instances by pattern: `Device.IP.Interface.3.Name` = `Device.IP.Interface.{i}.Name`.
#[derive(Debug, Default)]
pub struct Writability(std::collections::HashMap<String, bool>);

impl Writability {
    /// From a stored model (`{"objects": [{"path", "params": [{"name", "access"}]}]}`).
    pub fn from_model(model: &serde_json::Value) -> Self {
        let mut map = std::collections::HashMap::new();
        for object in model["objects"].as_array().into_iter().flatten() {
            let Some(path) = object["path"].as_str() else {
                continue;
            };
            for param in object["params"].as_array().into_iter().flatten() {
                if let (Some(name), Some(access)) =
                    (param["name"].as_str(), param["access"].as_str())
                {
                    map.insert(format!("{path}{name}"), access != "read_only");
                }
            }
        }
        Self(map)
    }

    /// Writability of `path` (with instance numbers). `None` -> model does not know it.
    pub fn of(&self, path: &str) -> Option<bool> {
        let pattern: Vec<&str> = path
            .split('.')
            .map(|s| {
                if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
                    "{i}"
                } else {
                    s
                }
            })
            .collect();
        self.0.get(&pattern.join(".")).copied()
    }

    /// Fill unknown writability of `params`.
    pub fn fill(&self, params: &mut [ParamUpdate]) {
        for p in params.iter_mut().filter(|p| p.writable.is_none()) {
            p.writable = self.of(&p.path);
        }
    }
}

/// TR-181 table for a file transfer on a USP device (CO-08).
/// Vendor config file backup/restore, vendor log upload.
pub fn transfer_table(kind: &TaskKind) -> Option<&'static str> {
    match kind {
        TaskKind::Upload { file_type, .. } if file_type.starts_with("1 ") => {
            Some("Device.DeviceInfo.VendorConfigFile.")
        }
        TaskKind::Upload { file_type, .. } if file_type.starts_with("2 ") => {
            Some("Device.DeviceInfo.VendorLogFile.")
        }
        TaskKind::Download { file_type, .. } if file_type.starts_with("3 ") => {
            Some("Device.DeviceInfo.VendorConfigFile.")
        }
        _ => None,
    }
}

/// Lowest instance of `table` (e.g. `Device.DeviceInfo.VendorConfigFile.`) in a Get result.
/// Result: `table{i}.`.
pub fn first_instance(params: &[ParamUpdate], table: &str) -> Result<String, String> {
    params
        .iter()
        .filter_map(|p| p.path.strip_prefix(table))
        .filter_map(|rest| rest.split('.').next()?.parse::<u32>().ok())
        .min()
        .map(|i| format!("{table}{i}."))
        .ok_or_else(|| format!("the device reports no {table}{{i}} instance"))
}

/// Upload task -> `{entry}Backup()` / `{entry}Upload()`; config Download -> `{entry}Restore()`.
/// `entry` = instance of [`transfer_table`].
pub fn file_transfer(entry: &str, kind: &TaskKind, key: &str) -> Result<ReqType, String> {
    let (command, url, username, password, extra) = match kind {
        TaskKind::Upload {
            file_type,
            url,
            username,
            password,
            ..
        } => {
            let command = if file_type.starts_with("2 ") {
                "Upload()"
            } else {
                "Backup()"
            };
            (command, url, username, password, Vec::new())
        }
        TaskKind::Download {
            url,
            username,
            password,
            file_size,
            target_file_name,
            sha256,
            ..
        } => {
            let mut extra = Vec::new();
            if *file_size > 0 {
                extra.push(("FileSize".to_owned(), file_size.to_string()));
            }
            if !target_file_name.is_empty() {
                extra.push(("TargetFileName".to_owned(), target_file_name.clone()));
            }
            // Same as firmware: device checks the fetched file against it.
            if !sha256.is_empty() {
                extra.push(("CheckSumAlgorithm".to_owned(), "SHA-256".to_owned()));
                extra.push(("CheckSum".to_owned(), sha256.clone()));
            }
            ("Restore()", url, username, password, extra)
        }
        other => return Err(format!("{} is not a file transfer", other.name())),
    };
    if url.is_empty() {
        return Err("the transfer has no URL".into());
    }
    let mut input: std::collections::HashMap<String, String> = [("URL".to_owned(), url.clone())]
        .into_iter()
        .chain(extra)
        .collect();
    if !username.is_empty() {
        input.insert("Username".into(), username.clone());
        input.insert("Password".into(), password.clone());
    }
    Ok(ReqType::Operate(msg::Operate {
        command: format!("{entry}{command}"),
        command_key: key.into(),
        send_resp: true,
        input_args: input,
    }))
}

/// `PARAM_READ_WRITE` -> `read_write` for a prost enum value.
fn enum_name(name: Option<&str>, prefix: &str) -> String {
    name.map(|n| n.strip_prefix(prefix).unwrap_or(n).to_ascii_lowercase())
        .unwrap_or_else(|| "unknown".into())
}

/// Supported data model document stored per firmware (US-11).
/// One entry per object: parameters, commands, events.
pub fn supported_model(resp: &msg::GetSupportedDmResp) -> Result<Value, String> {
    use msg::get_supported_dm_resp::{
        CmdType, ObjAccessType, ParamAccessType, ParamValueType, ValueChangeType,
    };
    let mut objects = Vec::new();
    let mut errors = Vec::new();
    for r in &resp.req_obj_results {
        if r.err_code != 0 {
            errors.push(format!("{}: {} {}", r.req_obj_path, r.err_code, r.err_msg));
            continue;
        }
        for o in &r.supported_objs {
            let access = ObjAccessType::try_from(o.access).ok();
            objects.push(json!({
                "path": o.supported_obj_path,
                "access": enum_name(access.map(|a| a.as_str_name()), "OBJ_"),
                "multi_instance": o.is_multi_instance,
                "params": o.supported_params.iter().map(|p| json!({
                    "name": p.param_name,
                    "access": enum_name(ParamAccessType::try_from(p.access).ok().map(|a| a.as_str_name()), "PARAM_"),
                    "type": enum_name(ParamValueType::try_from(p.value_type).ok().map(|a| a.as_str_name()), "PARAM_"),
                    "value_change": enum_name(ValueChangeType::try_from(p.value_change).ok().map(|a| a.as_str_name()), "VALUE_CHANGE_"),
                })).collect::<Vec<_>>(),
                "commands": o.supported_commands.iter().map(|c| json!({
                    "name": c.command_name,
                    "type": enum_name(CmdType::try_from(c.command_type).ok().map(|a| a.as_str_name()), "CMD_"),
                    "inputs": c.input_arg_names,
                    "outputs": c.output_arg_names,
                })).collect::<Vec<_>>(),
                "events": o.supported_events.iter().map(|e| json!({
                    "name": e.event_name, "args": e.arg_names,
                })).collect::<Vec<_>>(),
                "unique_keys": o.unique_key_sets.iter().map(|k| &k.key_names).collect::<Vec<_>>(),
            }));
        }
    }
    if objects.is_empty() {
        return Err(if errors.is_empty() {
            "the agent reported no supported objects".into()
        } else {
            errors.join("; ")
        });
    }
    Ok(json!({ "objects": objects, "errors": errors }))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::task::SetValue;

    #[test]
    fn add_object_parameters_go_into_the_create_object() {
        let kind = TaskKind::AddObject {
            object: "Device.WireGuard.Peer.".into(),
            params: vec![SetValue {
                name: "Alias".into(),
                value: "dhonomos-wg-x".into(),
                xsd_type: Some("string".into()),
                secret: false,
            }],
        };
        let Ok(ReqType::Add(add)) = to_request(&kind, "k") else {
            panic!("not an Add");
        };
        assert_eq!(
            add,
            msg::Add {
                allow_partial: false,
                create_objs: vec![msg::add::CreateObject {
                    obj_path: "Device.WireGuard.Peer.".into(),
                    param_settings: vec![msg::add::CreateParamSetting {
                        param: "Alias".into(),
                        value: "dhonomos-wg-x".into(),
                        required: true,
                    }],
                }],
            }
        );
        // No parameters, as before -> stored payload has no `params`.
        let plain = TaskKind::AddObject {
            object: "Device.NAT.PortMapping.".into(),
            params: vec![],
        };
        let Ok(ReqType::Add(add)) = to_request(&plain, "k") else {
            panic!("not an Add");
        };
        assert!(add.create_objs[0].param_settings.is_empty());
        assert_eq!(
            plain.to_row().1,
            json!({ "object": "Device.NAT.PortMapping." })
        );
        assert_eq!(
            TaskKind::from_row(
                "add_object",
                &json!({ "object": "Device.NAT.PortMapping." })
            )
            .ok(),
            Some(plain)
        );
    }

    #[test]
    fn supported_model_document() {
        use msg::get_supported_dm_resp as g;
        let resp = msg::GetSupportedDmResp {
            req_obj_results: vec![g::RequestedObjectResult {
                req_obj_path: "Device.".into(),
                supported_objs: vec![g::SupportedObjectResult {
                    supported_obj_path: "Device.IP.Diagnostics.".into(),
                    access: g::ObjAccessType::ObjReadOnly as i32,
                    supported_commands: vec![g::SupportedCommandResult {
                        command_name: "IPPing()".into(),
                        input_arg_names: vec!["Host".into()],
                        output_arg_names: vec!["Status".into()],
                        command_type: g::CmdType::CmdAsync as i32,
                    }],
                    supported_params: vec![g::SupportedParamResult {
                        param_name: "IPv4PingSupported".into(),
                        access: g::ParamAccessType::ParamReadOnly as i32,
                        value_type: g::ParamValueType::ParamBoolean as i32,
                        value_change: g::ValueChangeType::ValueChangeAllowed as i32,
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let Ok(m) = supported_model(&resp) else {
            panic!()
        };
        let o = &m["objects"][0];
        assert_eq!(o["access"], "read_only");
        assert_eq!(o["commands"][0]["type"], "async");
        assert_eq!(o["commands"][0]["inputs"][0], "Host");
        assert_eq!(o["params"][0]["type"], "boolean");
        assert_eq!(o["params"][0]["value_change"], "allowed");
        assert!(supported_model(&msg::GetSupportedDmResp::default()).is_err());
    }

    #[test]
    fn writability_comes_from_the_supported_model() {
        let model = json!({ "objects": [
            { "path": "Device.Time.", "params": [
                { "name": "Enable", "access": "read_write" },
                { "name": "Status", "access": "read_only" },
            ]},
            { "path": "Device.IP.Interface.{i}.IPv4Address.{i}.", "params": [
                { "name": "IPAddress", "access": "read_write" },
            ]},
        ]});
        let w = Writability::from_model(&model);
        assert_eq!(w.of("Device.Time.Enable"), Some(true));
        assert_eq!(w.of("Device.Time.Status"), Some(false));
        assert_eq!(
            w.of("Device.IP.Interface.12.IPv4Address.1.IPAddress"),
            Some(true)
        );
        assert_eq!(w.of("Device.Time.Unknown"), None);
        let mut params = vec![
            ParamUpdate {
                path: "Device.Time.Status".into(),
                ..ParamUpdate::default()
            },
            // Known writability kept.
            ParamUpdate {
                path: "Device.Time.Enable".into(),
                writable: Some(false),
                ..ParamUpdate::default()
            },
        ];
        w.fill(&mut params);
        assert_eq!(
            (params[0].writable, params[1].writable),
            (Some(false), Some(false))
        );
    }

    #[test]
    fn firmware_goes_to_the_inactive_bank() {
        let p = |path: &str, value: &str| ParamUpdate {
            path: path.into(),
            value: Some(value.into()),
            ..ParamUpdate::default()
        };
        let params = [
            p(
                "Device.DeviceInfo.ActiveFirmwareImage",
                "Device.DeviceInfo.FirmwareImage.1",
            ),
            p("Device.DeviceInfo.FirmwareImage.1.Status", "Active"),
            p("Device.DeviceInfo.FirmwareImage.2.Status", "Available"),
        ];
        assert_eq!(
            firmware_bank(&params).as_deref(),
            Ok("Device.DeviceInfo.FirmwareImage.2.")
        );
        assert!(firmware_bank(&params[..2]).is_err(), "single bank");
        let dl = TaskKind::Download {
            file_id: None,
            file_type: "1 Firmware Upgrade Image".into(),
            url: "http://f/fw.bin".into(),
            username: String::new(),
            password: String::new(),
            file_size: 9,
            target_file_name: String::new(),
            sha256: String::new(),
            delay_seconds: 0,
        };
        let Ok(ReqType::Operate(o)) =
            firmware_download("Device.DeviceInfo.FirmwareImage.2.", &dl, "t")
        else {
            panic!()
        };
        assert_eq!(o.command, "Device.DeviceInfo.FirmwareImage.2.Download()");
        assert_eq!(
            (
                o.input_args["AutoActivate"].as_str(),
                o.input_args["FileSize"].as_str()
            ),
            ("true", "9")
        );
        assert!(!o.input_args.contains_key("CheckSum"), "no checksum known");
        // Stored file SHA-256 -> sent for the device to check the image.
        let mut checked = dl.clone();
        if let TaskKind::Download { sha256, .. } = &mut checked {
            *sha256 = "ab".repeat(32);
        }
        let Ok(ReqType::Operate(o)) =
            firmware_download("Device.DeviceInfo.FirmwareImage.2.", &checked, "t")
        else {
            panic!()
        };
        assert_eq!(
            (
                o.input_args["CheckSumAlgorithm"].as_str(),
                o.input_args["CheckSum"].as_str()
            ),
            ("SHA-256", "ab".repeat(32).as_str())
        );
        let mut cfg = dl.clone();
        if let TaskKind::Download { file_type, .. } = &mut cfg {
            *file_type = "3 Vendor Configuration File".into();
        }
        assert!(firmware_download("x.", &cfg, "t").is_err());
    }

    #[test]
    fn vendor_file_transfers() {
        let p = |path: &str| ParamUpdate {
            path: path.into(),
            value: Some(String::new()),
            ..ParamUpdate::default()
        };
        let params = vec![
            p("Device.DeviceInfo.VendorConfigFile.3.Name"),
            p("Device.DeviceInfo.VendorConfigFile.2.Name"),
            p("Device.DeviceInfo.VendorLogFile.1.Name"),
        ];
        let table = "Device.DeviceInfo.VendorConfigFile.";
        assert_eq!(
            first_instance(&params, table).as_deref(),
            Ok("Device.DeviceInfo.VendorConfigFile.2.")
        );
        assert!(first_instance(&params[2..], table).is_err());

        let backup = TaskKind::Upload {
            file_type: "1 Vendor Configuration File".into(),
            url: "http://f/uploads/d/u".into(),
            username: String::new(),
            password: String::new(),
            delay_seconds: 0,
        };
        assert_eq!(transfer_table(&backup), Some(table));
        let Ok(ReqType::Operate(o)) =
            file_transfer("Device.DeviceInfo.VendorConfigFile.2.", &backup, "k")
        else {
            panic!()
        };
        assert_eq!(o.command, "Device.DeviceInfo.VendorConfigFile.2.Backup()");
        assert_eq!(o.input_args.len(), 1);
        assert_eq!(o.input_args["URL"], "http://f/uploads/d/u");

        let log = TaskKind::Upload {
            file_type: "2 Vendor Log File".into(),
            url: "http://f/uploads/d/u".into(),
            username: String::new(),
            password: String::new(),
            delay_seconds: 0,
        };
        assert_eq!(
            transfer_table(&log),
            Some("Device.DeviceInfo.VendorLogFile.")
        );
        let Ok(ReqType::Operate(o)) =
            file_transfer("Device.DeviceInfo.VendorLogFile.1.", &log, "k")
        else {
            panic!()
        };
        assert_eq!(o.command, "Device.DeviceInfo.VendorLogFile.1.Upload()");

        let restore = TaskKind::Download {
            file_id: None,
            file_type: "3 Vendor Configuration File".into(),
            url: "http://f/files/x".into(),
            username: "u".into(),
            password: "p".into(),
            file_size: 12,
            target_file_name: String::new(),
            sha256: "cd".repeat(32),
            delay_seconds: 0,
        };
        assert_eq!(transfer_table(&restore), Some(table));
        let Ok(ReqType::Operate(o)) =
            file_transfer("Device.DeviceInfo.VendorConfigFile.2.", &restore, "k")
        else {
            panic!()
        };
        assert_eq!(o.command, "Device.DeviceInfo.VendorConfigFile.2.Restore()");
        assert_eq!(
            (
                o.input_args["FileSize"].as_str(),
                o.input_args["Username"].as_str()
            ),
            ("12", "u")
        );
        assert_eq!(
            (
                o.input_args["CheckSumAlgorithm"].as_str(),
                o.input_args["CheckSum"].as_str()
            ),
            ("SHA-256", "cd".repeat(32).as_str())
        );
        let firmware = TaskKind::Download {
            file_id: None,
            file_type: "1 Firmware Upgrade Image".into(),
            url: "http://f/files/x".into(),
            username: String::new(),
            password: String::new(),
            file_size: 12,
            target_file_name: String::new(),
            sha256: String::new(),
            delay_seconds: 0,
        };
        assert_eq!(transfer_table(&firmware), None);
    }

    #[test]
    fn synchronous_diagnostics_are_normalized() {
        use crate::diagnostics::DiagTest;
        use msg::operate_resp::{
            OperationResult,
            operation_result::{OperationResp, OutputArgs},
        };
        let kind = TaskKind::Diagnostic {
            test: DiagTest::IpPing,
            params: [("host".to_owned(), "h".to_owned())].into(),
        };
        let Ok(ReqType::Operate(o)) = to_request(&kind, "t") else {
            panic!()
        };
        assert_eq!(o.command, "Device.IP.Diagnostics.IPPing()");
        assert_eq!(o.input_args["Host"], "h");
        let reply = |status: &str| msg::Response {
            resp_type: Some(RespType::OperateResp(msg::OperateResp {
                operation_results: vec![OperationResult {
                    executed_command: o.command.clone(),
                    operation_resp: Some(OperationResp::ReqOutputArgs(OutputArgs {
                        output_args: [("Status", status), ("SuccessCount", "2")]
                            .into_iter()
                            .map(|(k, v)| (k.to_owned(), v.to_owned()))
                            .collect(),
                    })),
                }],
            })),
        };
        let Ok(ok) = apply(&kind, &reply("Complete")) else {
            panic!()
        };
        assert_eq!(ok.result["result"]["success_count"], 2);
        assert!(!ok.pending);
        assert!(apply(&kind, &reply("Error_Other")).is_err());
    }

    #[test]
    fn operate_requires_a_command_path() {
        let op = |c: &str| TaskKind::Operate {
            command: c.into(),
            input: [("Host".to_owned(), "h".to_owned())].into(),
        };
        let Ok(ReqType::Operate(o)) = to_request(&op("Device.IP.Diagnostics.IPPing()"), "t") else {
            panic!()
        };
        assert_eq!(
            (o.command_key.as_str(), o.input_args["Host"].as_str()),
            ("t", "h")
        );
        assert!(to_request(&op("Device.IP.Diagnostics."), "t").is_err());
    }

    /// Set secret -> stored empty, echoed by the Agent or not. Other values stored as set.
    #[test]
    fn set_response_keeps_secrets_out_of_the_snapshot() {
        use msg::set_resp::updated_object_result::{OperationStatus, operation_status};
        let kind = TaskKind::SetParameterValues {
            values: vec![
                SetValue {
                    name: "Device.WiFi.AccessPoint.1.Security.KeyPassphrase".into(),
                    value: "invented-passphrase".into(),
                    xsd_type: None,
                    secret: true,
                },
                SetValue {
                    name: "Device.WiFi.SSID.1.SSID".into(),
                    value: "home".into(),
                    xsd_type: None,
                    secret: false,
                },
            ],
        };
        let stored = |resp: msg::SetResp| -> Vec<(String, Option<String>)> {
            let resp = msg::Response {
                resp_type: Some(RespType::SetResp(resp)),
            };
            let mut params: Vec<_> = apply(&kind, &resp)
                .unwrap_or_else(|e| panic!("{e}"))
                .params
                .into_iter()
                .map(|p| (p.path, p.value))
                .collect();
            params.sort();
            params
        };
        let expected = vec![
            (
                "Device.WiFi.AccessPoint.1.Security.KeyPassphrase".to_owned(),
                Some(String::new()),
            ),
            (
                "Device.WiFi.SSID.1.SSID".to_owned(),
                Some("home".to_owned()),
            ),
        ];
        // No updated_params -> requested values.
        assert_eq!(stored(msg::SetResp::default()), expected);
        // Agent echoes both.
        let echo = |path: &str, name: &str, value: &str| msg::set_resp::UpdatedObjectResult {
            requested_path: path.into(),
            oper_status: Some(OperationStatus {
                oper_status: Some(operation_status::OperStatus::OperSuccess(
                    operation_status::OperationSuccess {
                        updated_inst_results: vec![msg::set_resp::UpdatedInstanceResult {
                            affected_path: path.into(),
                            param_errs: vec![],
                            updated_params: HashMap::from([(name.into(), value.into())]),
                        }],
                    },
                )),
            }),
        };
        let resp = msg::SetResp {
            updated_obj_results: vec![
                echo(
                    "Device.WiFi.AccessPoint.1.Security.",
                    "KeyPassphrase",
                    "invented-passphrase",
                ),
                echo("Device.WiFi.SSID.1.", "SSID", "home"),
            ],
        };
        assert_eq!(stored(resp), expected);
    }

    #[test]
    fn set_groups_by_object() {
        let kind = TaskKind::SetParameterValues {
            values: vec![
                SetValue {
                    name: "Device.WiFi.SSID.1.SSID".into(),
                    value: "a".into(),
                    xsd_type: None,
                    secret: false,
                },
                SetValue {
                    name: "Device.Time.Enable".into(),
                    value: "true".into(),
                    xsd_type: None,
                    secret: false,
                },
                SetValue {
                    name: "Device.WiFi.SSID.1.Enable".into(),
                    value: "1".into(),
                    xsd_type: None,
                    secret: false,
                },
            ],
        };
        let Ok(ReqType::Set(s)) = to_request(&kind, "k") else {
            panic!()
        };
        let objs: Vec<_> = s
            .update_objs
            .iter()
            .map(|o| (o.obj_path.as_str(), o.param_settings.len()))
            .collect();
        assert_eq!(objs, [("Device.WiFi.SSID.1.", 2), ("Device.Time.", 1)]);
        assert!(
            to_request(
                &TaskKind::SetParameterValues {
                    values: vec![SetValue {
                        name: "Device.".into(),
                        value: String::new(),
                        xsd_type: None,
                        secret: false
                    }]
                },
                "k"
            )
            .is_err()
        );
        assert!(to_request(&TaskKind::GetParameterAttributes { names: vec![] }, "k").is_err());
        let Ok(ReqType::Operate(o)) = to_request(&TaskKind::Reboot, "task-1") else {
            panic!()
        };
        assert_eq!(
            (o.command.as_str(), o.command_key.as_str(), o.send_resp),
            ("Device.Reboot()", "task-1", true)
        );
    }

    #[test]
    fn get_response_becomes_parameters() {
        let resp = msg::Response {
            resp_type: Some(RespType::GetResp(msg::GetResp {
                req_path_results: vec![msg::get_resp::RequestedPathResult {
                    requested_path: "Device.DeviceInfo.".into(),
                    err_code: 0,
                    err_msg: String::new(),
                    resolved_path_results: vec![msg::get_resp::ResolvedPathResult {
                        resolved_path: "Device.DeviceInfo.".into(),
                        result_params: HashMap::from([
                            ("SerialNumber".into(), "SN".into()),
                            ("UpTime".into(), "5".into()),
                        ]),
                    }],
                }],
            })),
        };
        let a = apply(&TaskKind::GetParameterValues { names: vec![] }, &resp)
            .unwrap_or_else(|e| panic!("{e}"));
        let paths: Vec<_> = a.params.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(
            paths,
            ["Device.DeviceInfo.SerialNumber", "Device.DeviceInfo.UpTime"]
        );
    }

    #[test]
    fn a_get_with_some_failed_paths_keeps_the_values_of_the_others() {
        let ok = |param: &str, value: &str| msg::get_resp::RequestedPathResult {
            requested_path: format!("Device.DeviceInfo.{param}"),
            err_code: 0,
            err_msg: String::new(),
            resolved_path_results: vec![msg::get_resp::ResolvedPathResult {
                resolved_path: "Device.DeviceInfo.".into(),
                result_params: HashMap::from([(param.to_owned(), value.to_owned())]),
            }],
        };
        let failed = |param: &str| msg::get_resp::RequestedPathResult {
            requested_path: format!("Device.DeviceInfo.{param}"),
            err_code: 7026,
            err_msg: "Invalid path".into(),
            resolved_path_results: Vec::new(),
        };
        let get = |results| msg::Response {
            resp_type: Some(RespType::GetResp(msg::GetResp {
                req_path_results: results,
            })),
        };
        let kind = TaskKind::GetParameterValues { names: vec![] };
        let a = apply(
            &kind,
            &get(vec![
                ok("Manufacturer", "Acme"),
                failed("HardwareVersion"),
                ok("SerialNumber", "SN"),
            ]),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let stored: Vec<_> = a
            .params
            .iter()
            .map(|p| (p.path.as_str(), p.value.as_deref()))
            .collect();
        assert_eq!(
            stored,
            [
                ("Device.DeviceInfo.Manufacturer", Some("Acme")),
                ("Device.DeviceInfo.SerialNumber", Some("SN"))
            ]
        );
        assert_eq!(
            a.result["errors"],
            json!(["Device.DeviceInfo.HardwareVersion: 7026 Invalid path"])
        );
        // Whole Get fails only when no path gave anything.
        let none = apply(
            &kind,
            &get(vec![failed("HardwareVersion"), failed("ModelName")]),
        );
        assert_eq!(
            none,
            Err("Device.DeviceInfo.HardwareVersion: 7026 Invalid path; \
                 Device.DeviceInfo.ModelName: 7026 Invalid path"
                .into())
        );
    }

    #[test]
    fn failures_and_async_operations() {
        use msg::operate_resp::operation_result::{CommandFailure, OperationResp};
        let op = |r: OperationResp| msg::Response {
            resp_type: Some(RespType::OperateResp(msg::OperateResp {
                operation_results: vec![msg::operate_resp::OperationResult {
                    executed_command: "Device.Reboot()".into(),
                    operation_resp: Some(r),
                }],
            })),
        };
        let failed = apply(
            &TaskKind::Reboot,
            &op(OperationResp::CmdFailure(CommandFailure {
                err_code: 7022,
                err_msg: "busy".into(),
            })),
        );
        assert_eq!(failed, Err("7022 busy".into()));
        let started = apply(
            &TaskKind::Reboot,
            &op(OperationResp::ReqObjPath(
                "Device.LocalAgent.Request.1.".into(),
            )),
        );
        assert!(started.is_ok_and(|a| a.pending));
    }

    #[test]
    fn successful_object_reads_list_what_the_agent_returned() {
        let result = |path: &str, code: u32, resolved: Vec<(&str, &[&str])>| {
            msg::get_resp::RequestedPathResult {
                requested_path: path.into(),
                err_code: code,
                err_msg: if code == 0 { "" } else { "Invalid path" }.into(),
                resolved_path_results: resolved
                    .into_iter()
                    .map(|(obj, names)| msg::get_resp::ResolvedPathResult {
                        resolved_path: obj.into(),
                        result_params: names
                            .iter()
                            .map(|n| ((*n).to_owned(), "v".to_owned()))
                            .collect(),
                    })
                    .collect(),
            }
        };
        let resp = msg::Response {
            resp_type: Some(RespType::GetResp(msg::GetResp {
                req_path_results: vec![
                    result(
                        "Device.Ethernet.",
                        0,
                        vec![
                            ("Device.Ethernet.", &["InterfaceNumberOfEntries"]),
                            ("Device.Ethernet.Interface.1.", &["Name"]),
                        ],
                    ),
                    result("Device.Foo.", 7026, vec![]),
                    result(
                        "Device.WiFi.SSID.[Enable==true].",
                        0,
                        vec![("Device.WiFi.SSID.1.", &["Enable"])],
                    ),
                ],
            })),
        };
        let a = apply(
            &TaskKind::GetParameterValues {
                names: vec!["Device.Ethernet.".into(), "Device.Foo.".into()],
            },
            &resp,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let reads: Vec<_> = a
            .reads
            .into_iter()
            .map(|(path, mut seen)| {
                seen.sort();
                (path, seen)
            })
            .collect();
        assert_eq!(
            reads,
            [(
                "Device.Ethernet.".to_owned(),
                vec![
                    "Device.Ethernet.".to_owned(),
                    "Device.Ethernet.Interface.1.".to_owned(),
                    "Device.Ethernet.Interface.1.Name".to_owned(),
                    "Device.Ethernet.InterfaceNumberOfEntries".to_owned(),
                ]
            )]
        );
    }
}
