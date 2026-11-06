//! USP Record + Msg validation: never panic on any bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message as _;
use dhonomos_usp_proto::validate::{decode_record, message_of};

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = decode_record(data) {
        let _ = message_of(&v.record);
        // Valid Record -> re-encode -> valid again.
        let bytes = v.record.encode_to_vec();
        assert!(decode_record(&bytes).is_ok());
    }
});
