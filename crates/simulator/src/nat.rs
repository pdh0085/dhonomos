//! CPE side of NAT traversal (TR-069 Annex G, TR-111 Part 2).
//! STUN Binding Requests from the UDP CR port + signed UDP CRs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

const MAGIC_COOKIE: u32 = 0x2112_A442;

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Binding Request: USERNAME + CONNECTION-REQUEST-BINDING, MESSAGE-INTEGRITY (RFC 5389)
/// with `password`.
pub fn binding_request(username: &str, password: &str, transaction: [u8; 12]) -> Vec<u8> {
    let mut attrs = Vec::new();
    let mut attr = |ty: u16, value: &[u8]| {
        attrs.extend_from_slice(&ty.to_be_bytes());
        attrs.extend_from_slice(&u16::try_from(value.len()).unwrap_or(0).to_be_bytes());
        attrs.extend_from_slice(value);
        attrs.resize(attrs.len().div_ceil(4) * 4, 0);
    };
    attr(0x0006, username.as_bytes());
    attr(0xC001, b"dslforum.org/TR-111 ");
    let mut msg = Vec::with_capacity(20 + attrs.len() + 24);
    msg.extend_from_slice(&0x0001u16.to_be_bytes());
    // Length incl. MESSAGE-INTEGRITY; MESSAGE-INTEGRITY = HMAC over all bytes before it.
    msg.extend_from_slice(&u16::try_from(attrs.len() + 24).unwrap_or(0).to_be_bytes());
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(&transaction);
    msg.extend_from_slice(&attrs);
    let tag = hmac_sha1(password.as_bytes(), &msg);
    msg.extend_from_slice(&[0x00, 0x08, 0x00, 0x14]);
    msg.extend_from_slice(&tag);
    msg
}

/// Address in a Binding Success Response (XOR-MAPPED-ADDRESS, else MAPPED-ADDRESS).
pub fn mapped_address(resp: &[u8]) -> Option<SocketAddr> {
    if resp.len() < 20 || resp[0..2] != [0x01, 0x01] {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([resp[2], resp[3]]));
    let body = resp.get(20..20 + len)?;
    let (mut mapped, mut xor) = (None, None);
    let mut at = 0;
    while at + 4 <= body.len() {
        let ty = u16::from_be_bytes([body[at], body[at + 1]]);
        let l = usize::from(u16::from_be_bytes([body[at + 2], body[at + 3]]));
        let v = body.get(at + 4..at + 4 + l)?;
        if (ty == 0x0001 || ty == 0x0020) && l >= 8 {
            let mut port = u16::from_be_bytes([v[2], v[3]]);
            let mut ip = v[4..].to_vec();
            if ty == 0x0020 {
                port ^= (MAGIC_COOKIE >> 16) as u16;
                for (b, k) in ip.iter_mut().zip(resp[4..20].iter()) {
                    *b ^= k;
                }
            }
            let ip = match (v[1], ip.len()) {
                (1, 4) => IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
                (2, 16) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(ip).ok()?)),
                _ => return None,
            };
            let addr = SocketAddr::new(ip, port);
            if ty == 0x0020 {
                xor = Some(addr);
            } else {
                mapped = Some(addr);
            }
        }
        at += 4 + l.div_ceil(4) * 4;
    }
    xor.or(mapped)
}

/// UDP CR: `GET http://addr?ts=&id=&un=&cn=&sig= HTTP/1.1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpConnectionRequest {
    /// Timestamp (s).
    pub ts: String,
    /// Message ID (same for repeated sends).
    pub id: String,
    /// Username.
    pub un: String,
    /// Client nonce.
    pub cn: String,
    /// HMAC-SHA1 sig, hex.
    pub sig: String,
}

impl UdpConnectionRequest {
    /// Parse a datagram. Not a UDP CR -> `None`.
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(datagram).ok()?;
        let target = text.strip_prefix("GET ")?.split(' ').next()?;
        let query = target.split_once('?')?.1;
        let field = |k: &str| {
            query
                .split('&')
                .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
                .map(str::to_owned)
        };
        Some(Self {
            ts: field("ts")?,
            id: field("id")?,
            un: field("un")?,
            cn: field("cn")?,
            sig: field("sig")?,
        })
    }

    /// `username` matches + sig verifies with `password`.
    pub fn verify(&self, username: &str, password: &str) -> bool {
        let expected = hmac_sha1(
            password.as_bytes(),
            format!("{}{}{}{}", self.ts, self.id, self.un, self.cn).as_bytes(),
        );
        let hex: String = expected.iter().map(|b| format!("{b:02X}")).collect();
        self.un == username && hex.eq_ignore_ascii_case(&self.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_connection_requests() {
        let sig: String = hmac_sha1(b"pw", b"17910000004242cpeabc")
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        let msg = format!(
            "GET http://203.0.113.5:7547?ts=1791000000&id=4242&un=cpe&cn=abc&sig={sig} HTTP/1.1\r\nHost: 203.0.113.5:7547\r\n\r\n"
        );
        let cr = UdpConnectionRequest::parse(msg.as_bytes()).unwrap_or_else(|| panic!("parse"));
        assert!(cr.verify("cpe", "pw"));
        assert!(!cr.verify("cpe", "other"));
        assert!(!cr.verify("someone", "pw"));
        assert!(UdpConnectionRequest::parse(b"\x00\x01garbage").is_none());
    }

    #[test]
    fn binding_round_trip() {
        let req = binding_request("dev-1", "secret", [7; 12]);
        // Response for 198.51.100.7:40000, XOR-MAPPED-ADDRESS.
        let mut resp = vec![0x01, 0x01, 0x00, 0x0C];
        resp.extend_from_slice(&req[4..20]);
        let port = 40000u16 ^ (MAGIC_COOKIE >> 16) as u16;
        let ip: Vec<u8> = [198u8, 51, 100, 7]
            .iter()
            .zip(MAGIC_COOKIE.to_be_bytes())
            .map(|(a, b)| a ^ b)
            .collect();
        resp.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
        resp.extend_from_slice(&port.to_be_bytes());
        resp.extend_from_slice(&ip);
        assert_eq!(
            mapped_address(&resp),
            Some("198.51.100.7:40000".parse().unwrap_or_else(|_| panic!()))
        );
        assert_eq!(&req[0..2], &[0x00, 0x01]);
        assert_eq!(
            usize::from(u16::from_be_bytes([req[2], req[3]])),
            req.len() - 20
        );
    }
}
