//! Built-in STUN server for CPEs behind NAT (CW-08, TR-069 Annex G / TR-111 Part 2).
//!
//! CPE sends Binding Requests from its UDP CR port.
//! Response -> its public address: RFC 5389 XOR-MAPPED-ADDRESS, also MAPPED-ADDRESS (RFC 3489).
//! Request with CONNECTION-REQUEST-BINDING + USERNAME -> ACS learns where to send UDP CRs.

use std::net::{IpAddr, SocketAddr};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, warn};

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const MAGIC_COOKIE: u32 = 0x2112_A442;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// TR-111: request comes from the UDP CR port.
const ATTR_CONNECTION_REQUEST_BINDING: u16 = 0xC001;
/// TR-111: CPE binding changed since its last request.
const ATTR_BINDING_CHANGE: u16 = 0xC002;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingRequest {
    /// Transaction ID: 12 bytes; 16 for RFC 3489 (cookie field = part of the ID).
    pub transaction: [u8; 16],
    /// RFC 3489 request (no magic cookie).
    pub classic: bool,
    /// USERNAME = CPE `ManagementServer.STUNUsername`.
    pub username: Option<String>,
    /// Sent from the UDP CR port (TR-111).
    pub connection_request_binding: bool,
    /// CPE binding changed (TR-111).
    pub binding_change: bool,
    /// MESSAGE-INTEGRITY: attribute start offset + HMAC-SHA1.
    pub integrity: Option<(usize, [u8; 20])>,
}

/// Binding Request -> `Some`, anything else -> `None`.
pub fn parse_binding(buf: &[u8]) -> Option<BindingRequest> {
    if buf.len() < 20 || buf[0] & 0xC0 != 0 {
        return None;
    }
    let ty = u16::from_be_bytes([buf[0], buf[1]]);
    let len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    if ty != BINDING_REQUEST || len % 4 != 0 || buf.len() < 20 + len {
        return None;
    }
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let mut transaction = [0u8; 16];
    transaction.copy_from_slice(&buf[4..20]);
    let mut req = BindingRequest {
        transaction,
        classic: cookie != MAGIC_COOKIE,
        username: None,
        connection_request_binding: false,
        binding_change: false,
        integrity: None,
    };
    let mut at = 20;
    while at + 4 <= 20 + len {
        let t = u16::from_be_bytes([buf[at], buf[at + 1]]);
        let l = usize::from(u16::from_be_bytes([buf[at + 2], buf[at + 3]]));
        let value = buf.get(at + 4..at + 4 + l)?;
        match t {
            ATTR_USERNAME => req.username = std::str::from_utf8(value).ok().map(str::to_owned),
            ATTR_CONNECTION_REQUEST_BINDING => req.connection_request_binding = true,
            ATTR_BINDING_CHANGE => req.binding_change = true,
            ATTR_MESSAGE_INTEGRITY if l == 20 && req.integrity.is_none() => {
                let mut mac = [0u8; 20];
                mac.copy_from_slice(value);
                req.integrity = Some((at, mac));
            }
            _ => {}
        }
        at += 4 + l.div_ceil(4) * 4;
    }
    Some(req)
}

fn address_attr(ty: u16, addr: SocketAddr, xor: Option<&[u8; 16]>) -> Vec<u8> {
    let mut port = addr.port();
    let mut ip: Vec<u8> = match addr.ip() {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    if let Some(tx) = xor {
        port ^= (MAGIC_COOKIE >> 16) as u16;
        // IPv4: XOR with cookie. IPv6: cookie + transaction ID.
        for (b, k) in ip.iter_mut().zip(tx.iter()) {
            *b ^= k;
        }
    }
    let family: u8 = if addr.is_ipv4() { 1 } else { 2 };
    let mut v = Vec::with_capacity(8 + ip.len());
    v.extend_from_slice(&ty.to_be_bytes());
    v.extend_from_slice(&u16::try_from(4 + ip.len()).unwrap_or(8).to_be_bytes());
    v.extend_from_slice(&[0, family]);
    v.extend_from_slice(&port.to_be_bytes());
    v.extend_from_slice(&ip);
    v
}

/// True if MESSAGE-INTEGRITY = HMAC-SHA1 of the message under `key` (STUN password).
///
/// Accepted inputs: RFC 5389 (length field covers the attribute), RFC 3489 (zero-padded
/// to a multiple of 64 bytes).
pub fn verify_integrity(buf: &[u8], req: &BindingRequest, key: &[u8]) -> bool {
    use hmac::{Hmac, KeyInit, Mac};
    let Some((at, expected)) = req.integrity else {
        return false;
    };
    let Some(prefix) = buf.get(..at) else {
        return false;
    };
    let check = |input: &[u8]| {
        let mut mac = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(key)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        mac.update(input);
        mac.verify_slice(&expected).is_ok()
    };
    // RFC 5389: length field counts up to end of MESSAGE-INTEGRITY.
    let mut rfc5389 = prefix.to_vec();
    let len = u16::try_from(at + 24 - 20).unwrap_or(0).to_be_bytes();
    rfc5389[2..4].copy_from_slice(&len);
    // RFC 3489: as sent, zero-padded to multiple of 64 bytes.
    let mut rfc3489 = prefix.to_vec();
    rfc3489.resize(prefix.len().div_ceil(64) * 64, 0);
    check(&rfc5389) || check(&rfc3489)
}

/// Success response: client address as seen by the server.
pub fn binding_response(req: &BindingRequest, from: SocketAddr) -> Vec<u8> {
    let mut attrs = address_attr(ATTR_MAPPED_ADDRESS, from, None);
    if !req.classic {
        attrs.extend(address_attr(
            ATTR_XOR_MAPPED_ADDRESS,
            from,
            Some(&req.transaction),
        ));
    }
    let mut out = Vec::with_capacity(20 + attrs.len());
    out.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
    out.extend_from_slice(&u16::try_from(attrs.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&req.transaction);
    out.extend(attrs);
    out
}

/// Where a CPE gets UDP CRs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrBinding {
    /// USERNAME of the request.
    pub username: String,
    /// Public address (request source).
    pub address: SocketAddr,
}

/// USERNAME -> STUN password, `None` if unknown.
pub type PasswordOf = std::sync::Arc<dyn Fn(&str) -> Option<Vec<u8>> + Send + Sync>;

/// Answer Binding Requests on `socket` until it fails.
///
/// Request from CR port with USERNAME -> reported on `bindings`.
/// With `passwords` -> only if MESSAGE-INTEGRITY verifies.
/// Share the socket with the UDP CR sender: NAT filtering by source lets in only packets
/// from the address the CPE sent its binding to.
pub async fn serve(
    socket: std::sync::Arc<UdpSocket>,
    bindings: mpsc::Sender<CrBinding>,
    passwords: Option<PasswordOf>,
) -> std::io::Result<()> {
    let mut buf = [0u8; 1500];
    loop {
        let (n, from) = socket.recv_from(&mut buf).await?;
        let Some(req) = parse_binding(&buf[..n]) else {
            metrics::counter!("dhonomos_stun_requests_total", "outcome" => "invalid").increment(1);
            dhonomos_common::request_refused!("stun", "invalid", from);
            continue;
        };
        metrics::counter!("dhonomos_stun_requests_total", "outcome" => "binding").increment(1);
        if let Err(e) = socket.send_to(&binding_response(&req, from), from).await {
            debug!(%from, error = %e, "STUN response not sent");
        }
        if let (true, Some(username)) = (req.connection_request_binding, req.username.clone()) {
            if let Some(password_of) = &passwords {
                let ok = password_of(&username)
                    .is_some_and(|key| verify_integrity(&buf[..n], &req, &key));
                if !ok {
                    metrics::counter!("dhonomos_stun_requests_total", "outcome" => "unauthenticated")
                        .increment(1);
                    debug!(%from, %username, "STUN binding without valid MESSAGE-INTEGRITY ignored");
                    continue;
                }
            }
            let b = CrBinding {
                username,
                address: from,
            };
            if bindings.try_send(b).is_err() {
                warn!("STUN binding queue full; dropping a binding update");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(cookie: u32, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            body.resize(body.len().div_ceil(4) * 4, 0);
        }
        let mut m = Vec::new();
        m.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
        m.extend_from_slice(&(body.len() as u16).to_be_bytes());
        m.extend_from_slice(&cookie.to_be_bytes());
        m.extend_from_slice(&[7; 12]);
        m.extend(body);
        m
    }

    #[test]
    fn message_integrity() {
        use hmac::{Hmac, KeyInit, Mac};
        // USERNAME, then MESSAGE-INTEGRITY over the RFC 5389 input.
        let mut m = request(MAGIC_COOKIE, &[(ATTR_USERNAME, b"dev-1")]);
        let at = m.len();
        let len = (m.len() - 20 + 24) as u16;
        m[2..4].copy_from_slice(&len.to_be_bytes());
        let mut mac =
            <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(b"pw").unwrap_or_else(|_| unreachable!());
        mac.update(&m);
        let tag = mac.finalize().into_bytes();
        m.extend_from_slice(&ATTR_MESSAGE_INTEGRITY.to_be_bytes());
        m.extend_from_slice(&20u16.to_be_bytes());
        m.extend_from_slice(&tag);
        let req = parse_binding(&m).unwrap_or_else(|| unreachable!());
        assert_eq!(req.integrity.map(|i| i.0), Some(at));
        assert!(verify_integrity(&m, &req, b"pw"));
        assert!(!verify_integrity(&m, &req, b"wrong"));
        let unsigned = parse_binding(&request(MAGIC_COOKIE, &[])).unwrap_or_else(|| unreachable!());
        assert!(!verify_integrity(
            &request(MAGIC_COOKIE, &[]),
            &unsigned,
            b"pw"
        ));
    }

    #[test]
    fn tr111_binding_requests() {
        let m = request(
            MAGIC_COOKIE,
            &[
                (ATTR_USERNAME, b"dev-1"),
                (ATTR_CONNECTION_REQUEST_BINDING, b"dslforum.org/TR-111 "),
            ],
        );
        let req = parse_binding(&m).unwrap_or_else(|| unreachable!());
        assert_eq!(req.username.as_deref(), Some("dev-1"));
        assert!(req.connection_request_binding && !req.classic && !req.binding_change);

        let from: SocketAddr = "198.51.100.7:40001"
            .parse()
            .unwrap_or_else(|_| unreachable!());
        let resp = binding_response(&req, from);
        assert_eq!(&resp[0..2], &BINDING_RESPONSE.to_be_bytes());
        assert_eq!(&resp[4..20], &req.transaction);
        // XOR-MAPPED-ADDRESS -> decodes to the source.
        let xor = &resp[20 + 12..];
        assert_eq!(&xor[0..2], &ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        let port = u16::from_be_bytes([xor[6], xor[7]]) ^ 0x2112;
        let ip: Vec<u8> = xor[8..12]
            .iter()
            .zip(MAGIC_COOKIE.to_be_bytes())
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!((port, ip), (40001, vec![198, 51, 100, 7]));

        // RFC 3489 client -> MAPPED-ADDRESS only.
        let classic = parse_binding(&request(0x0102_0304, &[])).unwrap_or_else(|| unreachable!());
        assert!(classic.classic);
        assert_eq!(binding_response(&classic, from).len(), 20 + 12);
        assert!(parse_binding(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_binding(&request(MAGIC_COOKIE, &[])[..19]).is_none());
    }
}
