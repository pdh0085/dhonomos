//! Built-in MQTT broker packet reader: never panic on any bytes.
//! Packet returned -> its bytes consumed.
#![no_main]

use bytes::BytesMut;
use dhonomos_usp_mtp::mqtt_broker::read_packet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = BytesMut::from(data);
    while let Ok(Some(_)) = read_packet(&mut buf, 8 * 1024 * 1024) {}
    // Packets read from the front for any chunking -> also 1 byte at a time.
    let mut buf = BytesMut::new();
    for b in data.iter().take(4096) {
        buf.extend_from_slice(&[*b]);
        loop {
            match read_packet(&mut buf, 8 * 1024 * 1024) {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
});
