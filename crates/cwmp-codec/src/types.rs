//! CWMP data structures (TR-069 Annex A, `cwmp-1-2.xsd`).

use crate::error::Result;
use crate::field::{ArrayItem, Field, cwmp_struct};
use crate::xml::{Element, Writer};

/// Parameter value + XML Schema type (`ParameterValueStruct`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParameterValue {
    /// Full parameter path.
    pub name: String,
    /// Value as sent, not trimmed.
    pub value: String,
    /// `xsi:type` local name, e.g. `string`, `unsignedInt`. `None` -> sender omitted it.
    /// Encode: type always written, `None` -> `string`.
    pub xsd_type: Option<String>,
}

impl ParameterValue {
    /// Value with explicit type, e.g. `"unsignedInt"`.
    pub fn new(name: impl Into<String>, value: impl Into<String>, xsd_type: &str) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            xsd_type: Some(xsd_type.to_owned()),
        }
    }
}

impl Field for ParameterValue {
    fn read(el: Option<&Element>) -> Result<Self> {
        let Some(el) = el else {
            return Ok(Self::default());
        };
        let value_el = el.child("Value");
        Ok(Self {
            name: String::read(el.child("Name"))?,
            value: value_el.map(|v| v.text.clone()).unwrap_or_default(),
            xsd_type: value_el
                .and_then(|v| v.attr("type"))
                .map(|t| t.rsplit_once(':').map_or(t, |(_, l)| l).to_owned()),
        })
    }

    fn write(&self, w: &mut Writer, name: &str) {
        w.open(name, &[]);
        w.leaf("Name", &[], &self.name);
        let ty = format!("xsd:{}", self.xsd_type.as_deref().unwrap_or("string"));
        w.leaf("Value", &[("xsi:type", &ty)], &self.value);
        w.close(name);
    }
}

impl ArrayItem for ParameterValue {
    const ITEM: &'static str = "ParameterValueStruct";
    const TYPE: &'static str = "cwmp:ParameterValueStruct";
}

/// Base64 voucher (`SetVouchers`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Voucher(pub String);

impl Field for Voucher {
    fn read(el: Option<&Element>) -> Result<Self> {
        String::read(el).map(Self)
    }
    fn write(&self, w: &mut Writer, name: &str) {
        w.leaf(name, &[], &self.0);
    }
}

impl ArrayItem for Voucher {
    const ITEM: &'static str = "base64";
    const TYPE: &'static str = "soap-enc:base64";
}

cwmp_struct! {
    /// CPE identity in an Inform.
    pub struct DeviceId {
        "Manufacturer" => manufacturer: String,
        "OUI" => oui: String,
        "ProductClass" => product_class: String,
        "SerialNumber" => serial_number: String,
    }
}

cwmp_struct! {
    /// Inform event, e.g. `1 BOOT`, `M Reboot`.
    pub struct EventStruct as "EventStruct" {
        "EventCode" => event_code: String,
        "CommandKey" => command_key: String,
    }
}

cwmp_struct! {
    /// Name + writable flag from GPN.
    pub struct ParameterInfo as "ParameterInfoStruct" {
        "Name" => name: String,
        "Writable" => writable: bool,
    }
}

cwmp_struct! {
    /// One SetParameterAttributes entry.
    pub struct SetParameterAttributesStruct as "SetParameterAttributesStruct" {
        "Name" => name: String,
        "NotificationChange" => notification_change: bool,
        /// 0 off, 1 passive, 2 active (3-6: lightweight variants).
        "Notification" => notification: i32,
        "AccessListChange" => access_list_change: bool,
        "AccessList" => access_list: Vec<String>,
    }
}

cwmp_struct! {
    /// Attributes from GetParameterAttributes.
    pub struct ParameterAttribute as "ParameterAttributeStruct" {
        "Name" => name: String,
        "Notification" => notification: i32,
        "AccessList" => access_list: Vec<String>,
    }
}

cwmp_struct! {
    /// TransferComplete fault (`FaultCode` 0 = success).
    pub struct TransferFault {
        "FaultCode" => fault_code: u32,
        "FaultString" => fault_string: String,
    }
}

cwmp_struct! {
    /// Download time window (ScheduleDownload).
    pub struct TimeWindow as "TimeWindowStruct" {
        "WindowStart" => window_start: u32,
        "WindowEnd" => window_end: u32,
        "WindowMode" => window_mode: String,
        "UserMessage" => user_message: String,
        "MaxRetries" => max_retries: i32,
    }
}

cwmp_struct! {
    /// Queued transfer (GetQueuedTransfers).
    pub struct QueuedTransfer as "QueuedTransferStruct" {
        "CommandKey" => command_key: String,
        /// 1 not started, 2 in progress, 3 completed.
        "State" => state: i32,
    }
}

cwmp_struct! {
    /// Queued transfer + details (GetAllQueuedTransfers).
    pub struct AllQueuedTransfer as "AllQueuedTransferStruct" {
        "CommandKey" => command_key: String,
        "State" => state: i32,
        "IsDownload" => is_download: bool,
        "FileType" => file_type: String,
        "FileSize" => file_size: u32,
        "TargetFileName" => target_file_name: String,
    }
}

cwmp_struct! {
    /// Software option (GetOptions).
    pub struct OptionStruct as "OptionStruct" {
        "OptionName" => option_name: String,
        "VoucherSN" => voucher_sn: u32,
        "State" => state: u32,
        "Mode" => mode: i32,
        "StartDate" => start_date: String,
        "ExpirationDate" => expiration_date: Option<String>,
        "IsTransferable" => is_transferable: i32,
    }
}

cwmp_struct! {
    /// Name/value arg (RequestDownload `FileTypeArg`).
    pub struct Arg as "ArgStruct" {
        "Name" => name: String,
        "Value" => value: String,
    }
}

cwmp_struct! {
    /// Deployment unit operation fault.
    pub struct DeploymentUnitFault {
        "FaultCode" => fault_code: u32,
        "FaultString" => fault_string: Option<String>,
    }
}

cwmp_struct! {
    /// Result of one deployment unit operation (DUStateChangeComplete).
    pub struct OpResult as "OpResultStruct" {
        "UUID" => uuid: String,
        "DeploymentUnitRef" => deployment_unit_ref: String,
        "Version" => version: String,
        "CurrentState" => current_state: String,
        "Resolved" => resolved: bool,
        "ExecutionUnitRefList" => execution_unit_ref_list: String,
        "StartTime" => start_time: String,
        "CompleteTime" => complete_time: String,
        "Fault" => fault: DeploymentUnitFault,
    }
}

cwmp_struct! {
    /// Result of an autonomous deployment unit operation.
    pub struct AutonOpResult as "AutonOpResultStruct" {
        "UUID" => uuid: String,
        "DeploymentUnitRef" => deployment_unit_ref: String,
        "Version" => version: String,
        "CurrentState" => current_state: String,
        "Resolved" => resolved: bool,
        "ExecutionUnitRefList" => execution_unit_ref_list: String,
        "StartTime" => start_time: String,
        "CompleteTime" => complete_time: String,
        "Fault" => fault: DeploymentUnitFault,
        /// `Install`, `Update` or `Uninstall`.
        "OperationPerformed" => operation_performed: String,
    }
}

cwmp_struct! {
    /// Install a deployment unit (ChangeDUState).
    pub struct InstallOp {
        "URL" => url: String,
        "UUID" => uuid: Option<String>,
        "Username" => username: Option<String>,
        "Password" => password: Option<String>,
        "ExecutionEnvRef" => execution_env_ref: Option<String>,
    }
}

cwmp_struct! {
    /// Update a deployment unit (ChangeDUState).
    pub struct UpdateOp {
        "UUID" => uuid: Option<String>,
        "Version" => version: Option<String>,
        "URL" => url: Option<String>,
        "Username" => username: Option<String>,
        "Password" => password: Option<String>,
    }
}

cwmp_struct! {
    /// Uninstall a deployment unit (ChangeDUState).
    pub struct UninstallOp {
        "UUID" => uuid: String,
        "Version" => version: Option<String>,
        "ExecutionEnvRef" => execution_env_ref: Option<String>,
    }
}

/// One ChangeDUState operation. Kind from `xsi:type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DuOperation {
    /// `cwmp:InstallOpStruct`
    Install(InstallOp),
    /// `cwmp:UpdateOpStruct`
    Update(UpdateOp),
    /// `cwmp:UninstallOpStruct`
    Uninstall(UninstallOp),
}

impl Default for DuOperation {
    fn default() -> Self {
        Self::Install(InstallOp::default())
    }
}

impl Field for DuOperation {
    fn read(el: Option<&Element>) -> Result<Self> {
        let Some(el) = el else {
            return Ok(Self::default());
        };
        let ty = el
            .attr("type")
            .map(|t| t.rsplit_once(':').map_or(t, |(_, l)| l));
        // Lenient: no `xsi:type` -> some senders wrap the struct in a `*OpStruct` element.
        let (kind, body) = match ty {
            Some(t) => (t.to_owned(), el),
            None => match el.children.iter().find(|c| c.name.ends_with("OpStruct")) {
                Some(inner) => (inner.name.clone(), inner),
                None => (String::new(), el),
            },
        };
        Ok(match kind.as_str() {
            "UpdateOpStruct" => Self::Update(UpdateOp::decode_fields(body)?),
            "UninstallOpStruct" => Self::Uninstall(UninstallOp::decode_fields(body)?),
            _ => Self::Install(InstallOp::decode_fields(body)?),
        })
    }

    fn write(&self, w: &mut Writer, name: &str) {
        let (ty, write): (&str, &dyn Fn(&mut Writer)) = match self {
            Self::Install(op) => ("cwmp:InstallOpStruct", &|w| op.encode_fields(w)),
            Self::Update(op) => ("cwmp:UpdateOpStruct", &|w| op.encode_fields(w)),
            Self::Uninstall(op) => ("cwmp:UninstallOpStruct", &|w| op.encode_fields(w)),
        };
        w.open(name, &[("xsi:type", ty)]);
        write(w);
        w.close(name);
    }
}

impl ArrayItem for DuOperation {
    const ITEM: &'static str = "Operations";
    const TYPE: &'static str = "cwmp:OperationStruct";
}
