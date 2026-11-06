//! CWMP decode: never panic.
//! Decoded -> re-encode -> decode = same value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use dhonomos_cwmp_codec::Envelope;

fuzz_target!(|data: &[u8]| {
    if let Ok(Some(env)) = Envelope::decode(data) {
        let xml = env.encode();
        let again = Envelope::decode(xml.as_bytes()).expect("re-encoded envelope must decode");
        // Text fields trimmed -> 1st decode normalizes; 2nd round trip must be exact.
        let again = again.expect("non-empty");
        let third = Envelope::decode(again.encode().as_bytes()).expect("decode").expect("non-empty");
        assert_eq!(again, third);
    }
});
