//! USP error codes (TR-369 Message + Record errors).

use std::fmt;

/// USP error code (`Error.err_code`, `DisconnectRecord.reason_code`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCode(pub u32);

macro_rules! error_codes {
    ($($name:ident = $code:literal, $desc:literal;)*) => {
        impl ErrorCode {
            $( #[doc = $desc] pub const $name: Self = Self($code); )*

            /// Standard name of the code, else name of its range.
            pub fn description(self) -> &'static str {
                match self.0 {
                    $( $code => $desc, )*
                    7100..=7199 => "USP Record error",
                    7200..=7299 => "Data model defined error",
                    7800..=7999 => "Vendor defined error",
                    _ => "Unknown error",
                }
            }
        }
    };
}

error_codes! {
    MESSAGE_FAILED = 7000, "Message failed";
    MESSAGE_NOT_SUPPORTED = 7001, "Message not supported";
    REQUEST_DENIED = 7002, "Request denied (no reason specified)";
    INTERNAL_ERROR = 7003, "Internal error";
    INVALID_ARGUMENTS = 7004, "Invalid arguments";
    RESOURCES_EXCEEDED = 7005, "Resources exceeded";
    PERMISSION_DENIED = 7006, "Permission denied";
    INVALID_CONFIGURATION = 7007, "Invalid configuration";
    INVALID_PATH_SYNTAX = 7008, "Invalid path syntax";
    PARAMETER_ACTION_FAILED = 7009, "Parameter action failed";
    UNSUPPORTED_PARAMETER = 7010, "Unsupported parameter";
    INVALID_TYPE = 7011, "Invalid type";
    INVALID_VALUE = 7012, "Invalid value";
    PARAMETER_READ_ONLY = 7013, "Attempt to update non-writeable parameter";
    VALUE_CONFLICT = 7014, "Value conflict";
    OPERATION_ERROR = 7015, "Operation error";
    OBJECT_DOES_NOT_EXIST = 7016, "Object does not exist";
    OBJECT_NOT_CREATED = 7017, "Object could not be created";
    OBJECT_NOT_A_TABLE = 7018, "Object is not a table";
    OBJECT_NOT_CREATABLE = 7019, "Attempt to create non-creatable object";
    OBJECT_NOT_UPDATED = 7020, "Object could not be updated";
    REQUIRED_PARAMETER_FAILED = 7021, "Required parameter failed";
    COMMAND_FAILURE = 7022, "Command failure";
    COMMAND_CANCELED = 7023, "Command canceled";
    DELETE_FAILURE = 7024, "Delete failure";
    DUPLICATE_KEY = 7025, "Object exists with duplicate key";
    INVALID_PATH = 7026, "Invalid path";
    INVALID_COMMAND_ARGUMENTS = 7027, "Invalid command arguments";
    REGISTER_FAILURE = 7028, "Register failure";
    ALREADY_IN_USE = 7029, "Already in use";
    DEREGISTER_FAILURE = 7030, "Deregister failure";
    PATH_ALREADY_REGISTERED = 7031, "Path already registered";
    RECORD_NOT_PARSED = 7100, "Record could not be parsed";
    SECURE_SESSION_REQUIRED = 7101, "Secure session required";
    SECURE_SESSION_NOT_SUPPORTED = 7102, "Secure session not supported";
    SEGMENTATION_NOT_SUPPORTED = 7103, "Segmentation and reassembly not supported";
    INVALID_RECORD_VALUE = 7104, "Invalid Record value";
    SESSION_CONTEXT_TERMINATED = 7105, "Session Context terminated";
    SESSION_CONTEXT_NOT_ALLOWED = 7106, "Session Context not allowed";
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.0, self.description())
    }
}
