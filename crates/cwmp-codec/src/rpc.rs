//! All CWMP 1.4 RPC methods + responses (TR-069 Annex A).

use crate::error::Result;
use crate::field::cwmp_struct;
use crate::types::*;
use crate::xml::{Element, Writer};

macro_rules! rpcs {
    ( $( $(#[$m:meta])* $name:ident { $($body:tt)* } )* ) => {
        $( cwmp_struct! { $(#[$m])* pub struct $name { $($body)* } } )*

        /// CWMP RPC request or response in a SOAP Body.
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[allow(clippy::large_enum_variant)]
        pub enum Rpc {
            $( $(#[$m])* $name($name), )*
            /// Method not known to the codec -> fault 9000 (CPE) / 8000 (ACS).
            Unknown {
                name: String,
            },
        }

        impl Rpc {
            /// Method name in the SOAP Body, e.g. `InformResponse`.
            pub fn name(&self) -> &str {
                match self {
                    $( Self::$name(_) => stringify!($name), )*
                    Self::Unknown { name } => name,
                }
            }

            pub(crate) fn decode(el: &Element) -> Result<Self> {
                $(
                    if el.name.eq_ignore_ascii_case(stringify!($name)) {
                        return Ok(Self::$name($name::decode_fields(el)?));
                    }
                )*
                Ok(Self::Unknown { name: el.name.clone() })
            }

            pub(crate) fn encode(&self, w: &mut Writer) {
                // Unknown name = from input -> never emit an invalid name.
                if !crate::xml::is_ncname(self.name()) {
                    return;
                }
                let name = format!("cwmp:{}", self.name());
                w.open(&name, &[]);
                match self {
                    $( Self::$name(v) => v.encode_fields(w), )*
                    Self::Unknown { .. } => {}
                }
                w.close(&name);
            }
        }

        $(
            impl From<$name> for Rpc {
                fn from(v: $name) -> Self {
                    Self::$name(v)
                }
            }
        )*
    };
}

impl Rpc {
    /// `...Response` -> true, request -> false.
    pub fn is_response(&self) -> bool {
        self.name().ends_with("Response")
    }
}

rpcs! {
    // ---- both directions ----
    /// Ask peer for its supported RPC methods.
    GetRPCMethods {}
    GetRPCMethodsResponse {
        "MethodList" => method_list: Vec<String>,
    }

    // ---- CPE methods (ACS -> CPE) ----
    SetParameterValues {
        "ParameterList" => parameter_list: Vec<ParameterValue>,
        "ParameterKey" => parameter_key: String,
    }
    /// 0 = applied, 1 = applied, not yet effective (e.g. needs reboot).
    SetParameterValuesResponse {
        "Status" => status: i32,
    }
    /// Name ending in `.` -> subtree.
    GetParameterValues {
        "ParameterNames" => parameter_names: Vec<String>,
    }
    GetParameterValuesResponse {
        "ParameterList" => parameter_list: Vec<ParameterValue>,
    }
    /// Parameter + object names under a path.
    GetParameterNames {
        "ParameterPath" => parameter_path: String,
        "NextLevel" => next_level: bool,
    }
    GetParameterNamesResponse {
        "ParameterList" => parameter_list: Vec<ParameterInfo>,
    }
    /// Set notification + access attributes.
    SetParameterAttributes {
        "ParameterList" => parameter_list: Vec<SetParameterAttributesStruct>,
    }
    SetParameterAttributesResponse {}
    /// Get notification + access attributes.
    GetParameterAttributes {
        "ParameterNames" => parameter_names: Vec<String>,
    }
    GetParameterAttributesResponse {
        "ParameterList" => parameter_list: Vec<ParameterAttribute>,
    }
    /// New instance of a multi-instance object (`ObjectName` ends with `.`).
    AddObject {
        "ObjectName" => object_name: String,
        "ParameterKey" => parameter_key: String,
    }
    /// `InstanceNumber` = created instance.
    AddObjectResponse {
        "InstanceNumber" => instance_number: u32,
        "Status" => status: i32,
    }
    DeleteObject {
        "ObjectName" => object_name: String,
        "ParameterKey" => parameter_key: String,
    }
    DeleteObjectResponse {
        "Status" => status: i32,
    }
    /// File download (firmware, config, ...).
    Download {
        "CommandKey" => command_key: String,
        "FileType" => file_type: String,
        "URL" => url: String,
        "Username" => username: String,
        "Password" => password: String,
        "FileSize" => file_size: u32,
        "TargetFileName" => target_file_name: String,
        "DelaySeconds" => delay_seconds: u32,
        "SuccessURL" => success_url: String,
        "FailureURL" => failure_url: String,
    }
    /// 0 = completed (times valid), 1 = not yet completed (TransferComplete follows).
    DownloadResponse {
        "Status" => status: i32,
        "StartTime" => start_time: String,
        "CompleteTime" => complete_time: String,
    }
    Reboot {
        "CommandKey" => command_key: String,
    }
    RebootResponse {}
    /// Deprecated -> GetAllQueuedTransfers.
    GetQueuedTransfers {}
    GetQueuedTransfersResponse {
        "TransferList" => transfer_list: Vec<QueuedTransfer>,
    }
    /// Inform after a delay.
    ScheduleInform {
        "DelaySeconds" => delay_seconds: u32,
        "CommandKey" => command_key: String,
    }
    ScheduleInformResponse {}
    /// Install option vouchers.
    SetVouchers {
        "VoucherList" => voucher_list: Vec<Voucher>,
    }
    SetVouchersResponse {}
    /// Get option state.
    GetOptions {
        "OptionName" => option_name: String,
    }
    GetOptionsResponse {
        "OptionList" => option_list: Vec<OptionStruct>,
    }
    /// File upload (config, log).
    Upload {
        "CommandKey" => command_key: String,
        "FileType" => file_type: String,
        "URL" => url: String,
        "Username" => username: String,
        "Password" => password: String,
        "DelaySeconds" => delay_seconds: u32,
    }
    /// `Status` = as in DownloadResponse.
    UploadResponse {
        "Status" => status: i32,
        "StartTime" => start_time: String,
        "CompleteTime" => complete_time: String,
    }
    FactoryReset {}
    FactoryResetResponse {}
    GetAllQueuedTransfers {}
    GetAllQueuedTransfersResponse {
        "TransferList" => transfer_list: Vec<AllQueuedTransfer>,
    }
    /// Download in time windows.
    ScheduleDownload {
        "CommandKey" => command_key: String,
        "FileType" => file_type: String,
        "URL" => url: String,
        "Username" => username: String,
        "Password" => password: String,
        "FileSize" => file_size: u32,
        "TargetFileName" => target_file_name: String,
        "TimeWindowList" => time_window_list: Vec<TimeWindow>,
    }
    ScheduleDownloadResponse {}
    CancelTransfer {
        "CommandKey" => command_key: String,
    }
    CancelTransferResponse {}
    /// Install / update / uninstall software modules.
    ChangeDUState {
        "Operations" as repeated => operations: Vec<DuOperation>,
        "CommandKey" => command_key: String,
    }
    ChangeDUStateResponse {}

    // ---- ACS methods (CPE -> ACS) ----
    /// First RPC of every session.
    Inform {
        "DeviceId" => device_id: DeviceId,
        "Event" => events: Vec<EventStruct>,
        "MaxEnvelopes" => max_envelopes: u32,
        "CurrentTime" => current_time: String,
        "RetryCount" => retry_count: u32,
        "ParameterList" => parameter_list: Vec<ParameterValue>,
    }
    /// `MaxEnvelopes` must be 1.
    InformResponse {
        "MaxEnvelopes" => max_envelopes: u32,
    }
    /// End of a Download or Upload.
    TransferComplete {
        "CommandKey" => command_key: String,
        "FaultStruct" => fault: TransferFault,
        "StartTime" => start_time: String,
        "CompleteTime" => complete_time: String,
    }
    TransferCompleteResponse {}
    /// Transfer not requested by the ACS.
    AutonomousTransferComplete {
        "AnnounceURL" => announce_url: String,
        "TransferURL" => transfer_url: String,
        "IsDownload" => is_download: bool,
        "FileType" => file_type: String,
        "FileSize" => file_size: u32,
        "TargetFileName" => target_file_name: String,
        "FaultStruct" => fault: TransferFault,
        "StartTime" => start_time: String,
        "CompleteTime" => complete_time: String,
    }
    AutonomousTransferCompleteResponse {}
    /// End of a ChangeDUState.
    DUStateChangeComplete {
        "Results" as repeated => results: Vec<OpResult>,
        "CommandKey" => command_key: String,
    }
    DUStateChangeCompleteResponse {}
    /// DU changes not requested by the ACS.
    AutonomousDUStateChangeComplete {
        "Results" as repeated => results: Vec<AutonOpResult>,
    }
    AutonomousDUStateChangeCompleteResponse {}
    /// CPE asks ACS for a Download.
    RequestDownload {
        "FileType" => file_type: String,
        "FileTypeArg" => file_type_arg: Vec<Arg>,
    }
    RequestDownloadResponse {}
    /// Web-identity kick (deprecated).
    Kicked {
        "Command" => command: String,
        "Referer" => referer: String,
        "Arg" => arg: String,
        "Next" => next: String,
    }
    /// Browser redirect URL.
    KickedResponse {
        "NextURL" => next_url: String,
    }
}
