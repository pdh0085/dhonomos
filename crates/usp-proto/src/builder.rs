//! Constructors: USP Messages + Records.

use prost::Message as _;

use crate::errors::ErrorCode;
use crate::msg::{self, body, header::MsgType, request::ReqType, response::RespType};
use crate::record::{self, record::RecordType};
use crate::version::UspVersion;

/// Header `MsgType` that must match the body.
pub fn msg_type_of(body: &body::MsgBody) -> MsgType {
    match body {
        body::MsgBody::Error(_) => MsgType::Error,
        body::MsgBody::Request(r) => match &r.req_type {
            Some(ReqType::Get(_)) => MsgType::Get,
            Some(ReqType::GetSupportedDm(_)) => MsgType::GetSupportedDm,
            Some(ReqType::GetInstances(_)) => MsgType::GetInstances,
            Some(ReqType::Set(_)) => MsgType::Set,
            Some(ReqType::Add(_)) => MsgType::Add,
            Some(ReqType::Delete(_)) => MsgType::Delete,
            Some(ReqType::Operate(_)) => MsgType::Operate,
            Some(ReqType::Notify(_)) => MsgType::Notify,
            Some(ReqType::GetSupportedProtocol(_)) => MsgType::GetSupportedProto,
            Some(ReqType::Register(_)) => MsgType::Register,
            Some(ReqType::Deregister(_)) => MsgType::Deregister,
            None => MsgType::Error,
        },
        body::MsgBody::Response(r) => match &r.resp_type {
            Some(RespType::GetResp(_)) => MsgType::GetResp,
            Some(RespType::GetSupportedDmResp(_)) => MsgType::GetSupportedDmResp,
            Some(RespType::GetInstancesResp(_)) => MsgType::GetInstancesResp,
            Some(RespType::SetResp(_)) => MsgType::SetResp,
            Some(RespType::AddResp(_)) => MsgType::AddResp,
            Some(RespType::DeleteResp(_)) => MsgType::DeleteResp,
            Some(RespType::OperateResp(_)) => MsgType::OperateResp,
            Some(RespType::NotifyResp(_)) => MsgType::NotifyResp,
            Some(RespType::GetSupportedProtocolResp(_)) => MsgType::GetSupportedProtoResp,
            Some(RespType::RegisterResp(_)) => MsgType::RegisterResp,
            Some(RespType::DeregisterResp(_)) => MsgType::DeregisterResp,
            None => MsgType::Error,
        },
    }
}

fn message(msg_id: impl Into<String>, body: body::MsgBody) -> msg::Msg {
    msg::Msg {
        header: Some(msg::Header {
            msg_id: msg_id.into(),
            msg_type: msg_type_of(&body) as i32,
        }),
        body: Some(msg::Body {
            msg_body: Some(body),
        }),
    }
}

/// Request Message; header type from `req`.
pub fn request(msg_id: impl Into<String>, req: ReqType) -> msg::Msg {
    message(
        msg_id,
        body::MsgBody::Request(msg::Request {
            req_type: Some(req),
        }),
    )
}

/// Response Message; header type from `resp`.
pub fn response(msg_id: impl Into<String>, resp: RespType) -> msg::Msg {
    message(
        msg_id,
        body::MsgBody::Response(msg::Response {
            resp_type: Some(resp),
        }),
    )
}

/// Error Message -> answer to the request `msg_id`.
pub fn error(msg_id: impl Into<String>, code: ErrorCode, err_msg: impl Into<String>) -> msg::Msg {
    message(
        msg_id,
        body::MsgBody::Error(msg::Error {
            err_code: code.0,
            err_msg: err_msg.into(),
            param_errs: Vec::new(),
        }),
    )
}

/// Get request. `max_depth` 0 = unlimited.
pub fn get(msg_id: impl Into<String>, paths: &[&str], max_depth: u32) -> msg::Msg {
    request(
        msg_id,
        ReqType::Get(msg::Get {
            param_paths: paths.iter().map(|p| (*p).to_owned()).collect(),
            max_depth,
        }),
    )
}

/// NotifyResp -> ack of a Notify with `send_resp` set.
pub fn notify_resp(msg_id: impl Into<String>, subscription_id: impl Into<String>) -> msg::Msg {
    response(
        msg_id,
        RespType::NotifyResp(msg::NotifyResp {
            subscription_id: subscription_id.into(),
        }),
    )
}

fn base_record(version: UspVersion, from: &str, to: &str, ty: RecordType) -> record::Record {
    record::Record {
        version: version.to_string(),
        to_id: to.to_owned(),
        from_id: from.to_owned(),
        payload_security: record::record::PayloadSecurity::Plaintext as i32,
        record_type: Some(ty),
        ..Default::default()
    }
}

/// Plaintext NoSessionContext Record with `msg`.
pub fn no_session_record(
    version: UspVersion,
    from: &str,
    to: &str,
    msg: &msg::Msg,
) -> record::Record {
    base_record(
        version,
        from,
        to,
        RecordType::NoSessionContext(record::NoSessionContextRecord {
            payload: msg.encode_to_vec(),
        }),
    )
}

/// MQTTConnectRecord: topic the sender subscribed to.
pub fn mqtt_connect_record(
    version: UspVersion,
    from: &str,
    to: &str,
    subscribed_topic: &str,
) -> record::Record {
    base_record(
        version,
        from,
        to,
        RecordType::MqttConnect(record::MqttConnectRecord {
            version: record::mqtt_connect_record::MqttVersion::V5 as i32,
            subscribed_topic: subscribed_topic.to_owned(),
        }),
    )
}

/// STOMPConnectRecord: destination the sender subscribed to.
pub fn stomp_connect_record(
    version: UspVersion,
    from: &str,
    to: &str,
    subscribed_destination: &str,
) -> record::Record {
    base_record(
        version,
        from,
        to,
        RecordType::StompConnect(record::StompConnectRecord {
            version: record::stomp_connect_record::StompVersion::V12 as i32,
            subscribed_destination: subscribed_destination.to_owned(),
        }),
    )
}

pub fn websocket_connect_record(version: UspVersion, from: &str, to: &str) -> record::Record {
    base_record(
        version,
        from,
        to,
        RecordType::WebsocketConnect(record::WebSocketConnectRecord {}),
    )
}

/// DisconnectRecord with `code` + `reason`.
pub fn disconnect_record(
    version: UspVersion,
    from: &str,
    to: &str,
    code: ErrorCode,
    reason: &str,
) -> record::Record {
    base_record(
        version,
        from,
        to,
        RecordType::Disconnect(record::DisconnectRecord {
            reason: reason.to_owned(),
            reason_code: code.0,
        }),
    )
}
