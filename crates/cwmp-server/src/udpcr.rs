//! UDP CR (CW-08, TR-069 Annex G): signed HTTP-style GET in 1 UDP datagram
//! -> address a NATed CPE learned with STUN.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use tokio::net::UdpSocket;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Request line `GET http://addr?ts&id&un&cn&sig HTTP/1.1`.
/// sig = HMAC-SHA1(password, ts id un cn concatenated).
pub fn message(
    addr: SocketAddr,
    username: &str,
    password: &str,
    ts: u64,
    id: u64,
    cnonce: &str,
) -> String {
    let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(password.as_bytes())
        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    mac.update(format!("{ts}{id}{username}{cnonce}").as_bytes());
    let sig = hex(&mac.finalize().into_bytes());
    format!(
        "GET http://{addr}?ts={ts}&id={id}&un={username}&cn={cnonce}&sig={sig} HTTP/1.1\r\nHost: {addr}\r\n\r\n"
    )
}

/// Send UDP CR x3, 1 s apart (UDP may drop it).
pub async fn send(
    socket: &UdpSocket,
    addr: SocketAddr,
    username: &str,
    password: &str,
) -> std::io::Result<()> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut raw = [0u8; 8];
    getrandom::fill(&mut raw).map_err(|e| std::io::Error::other(e.to_string()))?;
    let id = u64::from_be_bytes(raw);
    let cnonce = format!("{:016x}", id.rotate_left(17));
    let msg = message(addr, username, password, ts, id, &cnonce);
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        socket.send_to(msg.as_bytes(), addr).await?;
    }
    metrics::counter!("dhonomos_udp_connection_requests_total").increment(1);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_request_line() {
        let addr: SocketAddr = "203.0.113.5:7547"
            .parse()
            .unwrap_or_else(|_| unreachable!());
        let m = message(addr, "cpe", "secret", 1_791_000_000, 42, "abc");
        assert!(
            m.starts_with("GET http://203.0.113.5:7547?ts=1791000000&id=42&un=cpe&cn=abc&sig=")
        );
        assert!(m.ends_with(" HTTP/1.1\r\nHost: 203.0.113.5:7547\r\n\r\n"));
        // sig = HMAC-SHA1 over ts id un cn concatenated.
        let mut mac =
            <Hmac<Sha1> as KeyInit>::new_from_slice(b"secret").unwrap_or_else(|_| unreachable!());
        mac.update(b"179100000042cpeabc");
        assert!(m.contains(&format!("sig={}", hex(&mac.finalize().into_bytes()))));
    }
}
