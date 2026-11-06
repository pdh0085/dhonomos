//! Decode + check received Records and Messages.

use prost::Message as _;

use crate::builder::msg_type_of;
use crate::errors::ErrorCode;
use crate::msg;
use crate::record::{self, record::RecordType};
use crate::version::UspVersion;

/// Why a received Record is rejected.
///
/// Endpoint IDs, if readable -> caller decides:
/// Error back to sender (TR-369 R-MTP.5) or drop the Record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {reason}")]
pub struct RecordError {
    /// 7100 (not parseable) or 7104 (bad field value).
    pub code: ErrorCode,
    /// Reason text, English.
    pub reason: String,
    /// `Some` if Record decoded + field not empty.
    pub from_id: Option<String>,
    /// `Some` if Record decoded + field not empty.
    pub to_id: Option<String>,
}

/// Decoded Record, checks passed.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidRecord {
    pub version: UspVersion,
    pub record: record::Record,
}

/// Decode a Record + check the fields every Record must have.
///
/// Any USP 1.x version accepted (older agents, e.g. OB-USP-Agent, send `1.3`).
pub fn decode_record(bytes: &[u8]) -> Result<ValidRecord, RecordError> {
    let record = record::Record::decode(bytes).map_err(|e| RecordError {
        code: ErrorCode::RECORD_NOT_PARSED,
        reason: format!("protobuf decode failed: {e}"),
        from_id: None,
        to_id: None,
    })?;
    let invalid = |reason: String| RecordError {
        code: ErrorCode::INVALID_RECORD_VALUE,
        reason,
        from_id: Some(record.from_id.clone()).filter(|s| !s.is_empty()),
        to_id: Some(record.to_id.clone()).filter(|s| !s.is_empty()),
    };
    let version: UspVersion = record
        .version
        .parse()
        .map_err(|_| invalid(format!("invalid version {:?}", record.version)))?;
    if version.major != 1 {
        return Err(invalid(format!("unsupported major version {version}")));
    }
    if record.from_id.is_empty() {
        return Err(invalid("from_id is empty".into()));
    }
    if record.to_id.is_empty() {
        return Err(invalid("to_id is empty".into()));
    }
    if record.record_type.is_none() {
        return Err(invalid("record_type is missing".into()));
    }
    Ok(ValidRecord { version, record })
}

/// Why the Message in a Record is unusable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MsgError {
    /// Payload not a Message -> no msg_id -> Error 7000 cannot be addressed.
    #[error("payload is not a USP Message: {0}")]
    Decode(String),
    /// Header or `msg_id` missing -> no Error can be correlated.
    #[error("Message has no header or an empty msg_id")]
    MissingHeader,
    #[error("Message {msg_id} has no body")]
    MissingBody {
        /// Message ID.
        msg_id: String,
    },
    /// `header.msg_type` != body type.
    #[error("Message {msg_id}: header type {header} does not match body type {body}")]
    TypeMismatch {
        msg_id: String,
        /// Type in the header.
        header: i32,
        /// Type from the body.
        body: i32,
    },
}

/// Get + check the Message of a NoSessionContext Record.
///
/// `Ok(None)` for Record types without a Message (Connect, Disconnect).
/// Session-context Records: not supported yet -> `Ok(None)` too.
pub fn message_of(record: &record::Record) -> Result<Option<msg::Msg>, MsgError> {
    let Some(RecordType::NoSessionContext(ns)) = &record.record_type else {
        return Ok(None);
    };
    let m = msg::Msg::decode(ns.payload.as_slice()).map_err(|e| MsgError::Decode(e.to_string()))?;
    let header = m
        .header
        .as_ref()
        .filter(|h| !h.msg_id.is_empty())
        .ok_or(MsgError::MissingHeader)?;
    let body = m
        .body
        .as_ref()
        .and_then(|b| b.msg_body.as_ref())
        .ok_or_else(|| MsgError::MissingBody {
            msg_id: header.msg_id.clone(),
        })?;
    let expected = msg_type_of(body) as i32;
    if header.msg_type != expected {
        return Err(MsgError::TypeMismatch {
            msg_id: header.msg_id.clone(),
            header: header.msg_type,
            body: expected,
        });
    }
    Ok(Some(m))
}
