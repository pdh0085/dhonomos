//! Record + Msg validation, incl. bytes captured from OB-USP-Agent.
#![allow(clippy::unwrap_used)]

use dhonomos_usp_proto::msg::{self, header::MsgType};
use dhonomos_usp_proto::record::{self, record::RecordType};
use dhonomos_usp_proto::validate::{MsgError, decode_record, message_of};
use dhonomos_usp_proto::{ErrorCode, UspVersion, builder};
use prost::Message as _;

#[test]
fn obuspa_mqtt_connect_record() {
    let bytes = include_bytes!("corpus/obuspa-11.0.7-mqtt-connect.bin");
    let v = decode_record(bytes).unwrap();
    assert_eq!(v.version, UspVersion { major: 1, minor: 3 });
    assert_eq!(v.record.to_id, "self::rms-controller");
    assert!(v.record.from_id.starts_with("os::012345-"));
    let Some(RecordType::MqttConnect(c)) = &v.record.record_type else {
        panic!("expected MQTTConnectRecord")
    };
    assert_eq!(c.subscribed_topic, "usp/agent/obuspa-1");
    assert_eq!(message_of(&v.record), Ok(None));
}

#[test]
fn version_negotiation() {
    let agent: UspVersion = "1.3".parse().unwrap();
    assert_eq!(UspVersion::CURRENT.negotiate(agent).to_string(), "1.3");
    assert!("1".parse::<UspVersion>().is_err());
    assert!("x.y".parse::<UspVersion>().is_err());
}

#[test]
fn builders_set_matching_types_and_round_trip() {
    let get = builder::get("m1", &["Device.DeviceInfo.", "Device.Time."], 2);
    assert_eq!(get.header.as_ref().unwrap().msg_type, MsgType::Get as i32);
    let rec = builder::no_session_record(UspVersion::CURRENT, "self::c", "os::a", &get);
    assert_eq!(rec.version, "1.5");
    let v = decode_record(&rec.encode_to_vec()).unwrap();
    assert_eq!(message_of(&v.record).unwrap(), Some(get));

    let err = builder::error("m2", ErrorCode::INVALID_PATH, "no such path");
    assert_eq!(err.header.as_ref().unwrap().msg_type, MsgType::Error as i32);
    let resp = builder::notify_resp("m3", "sub-1");
    assert_eq!(resp.header.unwrap().msg_type, MsgType::NotifyResp as i32);

    let disc = builder::disconnect_record(
        UspVersion::CURRENT,
        "self::c",
        "os::a",
        ErrorCode::SESSION_CONTEXT_TERMINATED,
        "shutting down",
    );
    let Some(RecordType::Disconnect(d)) = disc.record_type else {
        panic!()
    };
    assert_eq!(d.reason_code, 7105);
}

#[test]
fn invalid_records() {
    let e = decode_record(&[0xff, 0xff, 0xff]).unwrap_err();
    assert_eq!(e.code, ErrorCode::RECORD_NOT_PARSED);
    assert_eq!(e.from_id, None);

    let base = builder::websocket_connect_record(UspVersion::CURRENT, "self::c", "os::a");
    let check = |r: record::Record| decode_record(&r.encode_to_vec()).unwrap_err();

    let e = check(record::Record {
        version: "2.0".into(),
        ..base.clone()
    });
    assert_eq!(e.code, ErrorCode::INVALID_RECORD_VALUE);
    // IDs reported -> caller decides if an Error may be returned.
    assert_eq!(e.from_id.as_deref(), Some("self::c"));

    let e = check(record::Record {
        to_id: String::new(),
        ..base.clone()
    });
    assert_eq!((e.code, e.to_id), (ErrorCode::INVALID_RECORD_VALUE, None));
    let e = check(record::Record {
        record_type: None,
        ..base
    });
    assert!(e.reason.contains("record_type"));
}

#[test]
fn invalid_messages() {
    let wrap = |m: &msg::Msg| builder::no_session_record(UspVersion::CURRENT, "a", "b", m);

    let mut m = builder::get("m1", &["Device."], 0);
    m.header.as_mut().unwrap().msg_type = MsgType::Set as i32;
    assert!(matches!(
        message_of(&wrap(&m)),
        Err(MsgError::TypeMismatch { .. })
    ));

    let mut m = builder::get("", &["Device."], 0);
    assert_eq!(message_of(&wrap(&m)), Err(MsgError::MissingHeader));
    m.header.as_mut().unwrap().msg_id = "m2".into();
    m.body = None;
    assert!(matches!(
        message_of(&wrap(&m)),
        Err(MsgError::MissingBody { .. })
    ));

    let garbage = record::Record {
        record_type: Some(RecordType::NoSessionContext(
            record::NoSessionContextRecord {
                payload: vec![0xff, 0x01],
            },
        )),
        ..wrap(&builder::get("x", &[], 0))
    };
    assert!(matches!(message_of(&garbage), Err(MsgError::Decode(_))));
}

#[test]
fn error_code_descriptions() {
    assert_eq!(ErrorCode(7016).description(), "Object does not exist");
    assert_eq!(ErrorCode(7250).description(), "Data model defined error");
    assert_eq!(ErrorCode(7900).to_string(), "7900 Vendor defined error");
}
