//! Inform event codes and CWMP fault codes.

use std::fmt;

/// Inform event code (`EventStruct.EventCode`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EventCode {
    /// `0 BOOTSTRAP`: first contact or new ACS URL.
    Bootstrap,
    /// `1 BOOT`
    Boot,
    /// `2 PERIODIC`
    Periodic,
    /// `3 SCHEDULED` (after ScheduleInform)
    Scheduled,
    /// `4 VALUE CHANGE`
    ValueChange,
    /// `5 KICKED`
    Kicked,
    /// `6 CONNECTION REQUEST`
    ConnectionRequest,
    /// `7 TRANSFER COMPLETE`
    TransferComplete,
    /// `8 DIAGNOSTICS COMPLETE`
    DiagnosticsComplete,
    /// `9 REQUEST DOWNLOAD`
    RequestDownload,
    /// `10 AUTONOMOUS TRANSFER COMPLETE`
    AutonomousTransferComplete,
    /// `11 DU STATE CHANGE COMPLETE`
    DuStateChangeComplete,
    /// `12 AUTONOMOUS DU STATE CHANGE COMPLETE`
    AutonomousDuStateChangeComplete,
    /// `13 WAKEUP`
    Wakeup,
    /// `14 HEARTBEAT`
    Heartbeat,
    /// `M Reboot`
    MReboot,
    /// `M ScheduleInform`
    MScheduleInform,
    /// `M Download`
    MDownload,
    /// `M ScheduleDownload`
    MScheduleDownload,
    /// `M Upload`
    MUpload,
    /// `M ChangeDUState`
    MChangeDuState,
    /// Vendor (`X <OUI> <event>`, `M X_<OUI>_<method>`) or unknown code, verbatim.
    Other(String),
}

const TABLE: &[(EventCode, &str)] = &[
    (EventCode::Bootstrap, "0 BOOTSTRAP"),
    (EventCode::Boot, "1 BOOT"),
    (EventCode::Periodic, "2 PERIODIC"),
    (EventCode::Scheduled, "3 SCHEDULED"),
    (EventCode::ValueChange, "4 VALUE CHANGE"),
    (EventCode::Kicked, "5 KICKED"),
    (EventCode::ConnectionRequest, "6 CONNECTION REQUEST"),
    (EventCode::TransferComplete, "7 TRANSFER COMPLETE"),
    (EventCode::DiagnosticsComplete, "8 DIAGNOSTICS COMPLETE"),
    (EventCode::RequestDownload, "9 REQUEST DOWNLOAD"),
    (
        EventCode::AutonomousTransferComplete,
        "10 AUTONOMOUS TRANSFER COMPLETE",
    ),
    (
        EventCode::DuStateChangeComplete,
        "11 DU STATE CHANGE COMPLETE",
    ),
    (
        EventCode::AutonomousDuStateChangeComplete,
        "12 AUTONOMOUS DU STATE CHANGE COMPLETE",
    ),
    (EventCode::Wakeup, "13 WAKEUP"),
    (EventCode::Heartbeat, "14 HEARTBEAT"),
    (EventCode::MReboot, "M Reboot"),
    (EventCode::MScheduleInform, "M ScheduleInform"),
    (EventCode::MDownload, "M Download"),
    (EventCode::MScheduleDownload, "M ScheduleDownload"),
    (EventCode::MUpload, "M Upload"),
    (EventCode::MChangeDuState, "M ChangeDUState"),
];

impl EventCode {
    /// Lenient parse: ignores outer whitespace, repeated inner spaces, case.
    /// Unknown -> [`EventCode::Other`], trimmed.
    pub fn parse(s: &str) -> Self {
        let norm = s.split_whitespace().collect::<Vec<_>>().join(" ");
        TABLE
            .iter()
            .find(|(_, t)| t.eq_ignore_ascii_case(&norm))
            .map_or_else(|| Self::Other(s.trim().to_owned()), |(c, _)| c.clone())
    }

    /// Canonical string.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Other(s) => s,
            known => TABLE
                .iter()
                .find(|(c, _)| c == known)
                .map_or("", |(_, t)| t),
        }
    }

    /// Cumulative (may repeat in one Inform) -> true for `M` codes, incl. vendor `M X_...`.
    /// Else single -> must not repeat in one Inform.
    pub fn is_cumulative(&self) -> bool {
        matches!(
            self,
            Self::MReboot
                | Self::MScheduleInform
                | Self::MDownload
                | Self::MScheduleDownload
                | Self::MUpload
                | Self::MChangeDuState
        ) || matches!(self, Self::Other(s) if s.starts_with("M "))
    }
}

impl fmt::Display for EventCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// CWMP fault code + standard description.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FaultCode(pub u32);

macro_rules! fault_codes {
    ($($name:ident = $code:literal, $desc:literal;)*) => {
        impl FaultCode {
            $( #[doc = $desc] pub const $name: Self = Self($code); )*

            /// Standard description. Vendor code -> description by range.
            pub fn description(self) -> &'static str {
                match self.0 {
                    $( $code => $desc, )*
                    9800..=9899 => "Vendor-specific CPE fault",
                    8800..=8899 => "Vendor-specific ACS fault",
                    _ => "Unknown fault",
                }
            }
        }
    };
}

fault_codes! {
    // ACS faults
    ACS_METHOD_NOT_SUPPORTED = 8000, "Method not supported";
    ACS_REQUEST_DENIED = 8001, "Request denied";
    ACS_INTERNAL_ERROR = 8002, "Internal error";
    ACS_INVALID_ARGUMENTS = 8003, "Invalid arguments";
    ACS_RESOURCES_EXCEEDED = 8004, "Resources exceeded";
    ACS_RETRY_REQUEST = 8005, "Retry request";
    ACS_VERSION_INCOMPATIBLE = 8006, "ACS version incompatible";
    // CPE faults
    METHOD_NOT_SUPPORTED = 9000, "Method not supported";
    REQUEST_DENIED = 9001, "Request denied";
    INTERNAL_ERROR = 9002, "Internal error";
    INVALID_ARGUMENTS = 9003, "Invalid arguments";
    RESOURCES_EXCEEDED = 9004, "Resources exceeded";
    INVALID_PARAMETER_NAME = 9005, "Invalid parameter name";
    INVALID_PARAMETER_TYPE = 9006, "Invalid parameter type";
    INVALID_PARAMETER_VALUE = 9007, "Invalid parameter value";
    NON_WRITABLE_PARAMETER = 9008, "Attempt to set a non-writable parameter";
    NOTIFICATION_REJECTED = 9009, "Notification request rejected";
    TRANSFER_FAILURE = 9010, "File transfer failure";
    UPLOAD_FAILURE = 9011, "Upload failure";
    TRANSFER_AUTH_FAILURE = 9012, "File transfer server authentication failure";
    UNSUPPORTED_TRANSFER_PROTOCOL = 9013, "Unsupported protocol for file transfer";
    MULTICAST_JOIN_FAILURE = 9014, "File transfer failure: unable to join multicast group";
    FILE_SERVER_UNREACHABLE = 9015, "File transfer failure: unable to contact file server";
    FILE_ACCESS_FAILURE = 9016, "File transfer failure: unable to access file";
    DOWNLOAD_INCOMPLETE = 9017, "File transfer failure: unable to complete download";
    FILE_CORRUPTED = 9018, "File transfer failure: file corrupted or otherwise unusable";
    FILE_AUTH_FAILURE = 9019, "File transfer failure: file authentication failure";
    TIME_WINDOW_MISSED = 9020, "File transfer failure: unable to complete download within specified time windows";
    CANCEL_NOT_PERMITTED = 9021, "Cancelation of file transfer not permitted in current transfer state";
    INVALID_UUID = 9022, "Invalid UUID format";
    UNKNOWN_EXECUTION_ENV = 9023, "Unknown execution environment";
    DISABLED_EXECUTION_ENV = 9024, "Disabled execution environment";
    DU_EE_MISMATCH = 9025, "Deployment unit to execution environment mismatch";
    DUPLICATE_DU = 9026, "Duplicate deployment unit";
    SYSTEM_RESOURCES_EXCEEDED = 9027, "System resources exceeded";
    UNKNOWN_DU = 9028, "Unknown deployment unit";
    INVALID_DU_STATE = 9029, "Invalid deployment unit state";
    DU_DOWNGRADE_NOT_PERMITTED = 9030, "Invalid deployment unit update: downgrade not permitted";
    DU_VERSION_NOT_SPECIFIED = 9031, "Invalid deployment unit update: version not specified";
    DU_VERSION_EXISTS = 9032, "Invalid deployment unit update: version already exists";
}

impl fmt::Display for FaultCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.0, self.description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_codes_parse_leniently() {
        assert_eq!(EventCode::parse("1 BOOT"), EventCode::Boot);
        assert_eq!(
            EventCode::parse("  6   connection request "),
            EventCode::ConnectionRequest
        );
        assert_eq!(EventCode::parse("M Reboot").as_str(), "M Reboot");
        assert_eq!(
            EventCode::parse("X 00D09E CUSTOM"),
            EventCode::Other("X 00D09E CUSTOM".into())
        );
        assert!(EventCode::MDownload.is_cumulative());
        assert!(!EventCode::Boot.is_cumulative());
        assert!(EventCode::parse("M X_00D09E_Foo").is_cumulative());
    }

    #[test]
    fn fault_descriptions() {
        assert_eq!(FaultCode::ACS_RETRY_REQUEST.0, 8005);
        assert_eq!(FaultCode(9005).description(), "Invalid parameter name");
        assert_eq!(FaultCode(9850).description(), "Vendor-specific CPE fault");
    }
}
