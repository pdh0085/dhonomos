//! USP (TR-369) Message + Record protobuf types, builders, validation.
//!
//! Types generated at build time from `proto/usp-msg-1-5.proto` +
//! `proto/usp-record-1-5.proto` (Broadband Forum, BSD-3-Clause).
//!
//! ```
//! use prost::Message as _;
//! use dhonomos_usp_proto::{builder, validate, UspVersion};
//!
//! let get = builder::get("m1", &["Device.DeviceInfo."], 0);
//! let rec = builder::no_session_record(UspVersion::CURRENT, "self::ctrl", "os::agent", &get);
//! let valid = validate::decode_record(&rec.encode_to_vec()).unwrap();
//! assert_eq!(validate::message_of(&valid.record).unwrap(), Some(get));
//! ```

pub mod builder;
mod errors;
pub mod validate;
mod version;

pub use errors::ErrorCode;
pub use version::{ParseVersionError, UspVersion};

/// USP Message types (`usp` protobuf package).
#[allow(missing_debug_implementations, unreachable_pub, clippy::all)]
pub mod msg {
    include!(concat!(env!("OUT_DIR"), "/usp.rs"));
}

/// USP Record types (`usp_record` protobuf package).
#[allow(missing_debug_implementations, unreachable_pub, clippy::all)]
pub mod record {
    include!(concat!(env!("OUT_DIR"), "/usp_record.rs"));
}

/// Default USP version sent by this crate.
pub const USP_VERSION: &str = "1.5";
