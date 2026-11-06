//! Messages between server and hub process `dhonomos-wg-hub` (ADR-110, stage 2):
//! desired hub state, hub public key, peer status report, interface name per network.
//!
//! Both sides use these types -> they are the wire format.
//! Unknown fields ignored on read -> either side may add fields, no break.

use std::fmt;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::prefix::Ipv4Prefix;

pub const HUB_TOKEN_PREFIX: &str = "dwh_";
/// Max long-poll wait (s).
pub const MAX_WAIT_SECS: u64 = 60;
/// Max peers per status report.
pub const MAX_STATUS_PEERS: usize = 65_536;

/// Interface of a network at the hub: `dwg<port>` (e.g. `dwg51820`).
/// Port unique per hub -> name too.
pub fn interface_name(listen_port: u16) -> String {
    format!("dwg{listen_port}")
}

/// Port of a `dwg<port>` name: "dwg" + 1-5 ASCII digits, no leading zero, 1..=65535.
/// Else `None` -> hub never touches an interface it did not name.
pub fn parse_interface_name(name: &str) -> Option<u16> {
    let digits = name.strip_prefix("dwg")?;
    if digits.is_empty()
        || digits.len() > 5
        || digits.starts_with('0')
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    digits.parse::<u16>().ok().filter(|p| *p != 0)
}

/// All a hub should run: networks + peers.
/// Answer of `GET /api/v1/wg-hub/state`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubState {
    pub hub_id: Uuid,
    /// Grows on any change here (`ETag` = `"r<revision>"`).
    pub revision: i64,
    /// By listen port.
    pub networks: Vec<HubNetwork>,
}

/// One network = one interface on the hub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubNetwork {
    pub id: Uuid,
    pub name: String,
    /// [`interface_name`] of `listen_port`.
    pub interface: String,
    /// UDP port of the hub.
    pub listen_port: u16,
    /// Tunnel prefix, e.g. `10.77.0.0/24`.
    pub prefix: Ipv4Prefix,
    /// Own hub address = first host of `prefix`.
    pub address: Ipv4Addr,
    pub mtu: u16,
    /// Live members with a public key, by address.
    pub peers: Vec<HubPeer>,
}

/// Peer of a network. `Debug` hides the PSK.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubPeer {
    pub member_id: Uuid,
    /// `device` or `client`.
    pub kind: String,
    pub public_key: String,
    /// Member `/32`, then LAN prefixes behind it, ascending.
    pub allowed_ips: Vec<Ipv4Prefix>,
    /// PSK of the peer: 32 bytes base64 (44 chars); absent = none.
    /// Secret -> never logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
}

impl fmt::Debug for HubPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HubPeer")
            .field("member_id", &self.member_id)
            .field("kind", &self.kind)
            .field("public_key", &self.public_key)
            .field("allowed_ips", &self.allowed_ips)
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| REDACTED),
            )
            .finish()
    }
}

/// `Debug` text in place of a secret.
const REDACTED: &str = "********";

/// Body of `PUT /api/v1/wg-hub/public-key`: own hub public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyReport {
    /// 44 chars base64.
    pub public_key: String,
}

/// Body of `POST /api/v1/wg-hub/status`: peer status from the hub interfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusReport {
    /// Max [`MAX_STATUS_PEERS`].
    pub peers: Vec<PeerStatus>,
}

/// One peer as the hub sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStatus {
    /// Network (interface) of the peer.
    pub network_id: Uuid,
    pub public_key: String,
    /// Last seen `ip:port`.
    pub endpoint: Option<String>,
    /// Last handshake, Unix s. `None` or 0 and below = never.
    pub latest_handshake: Option<i64>,
    /// Bytes from the peer.
    pub rx_bytes: u64,
    /// Bytes to the peer.
    pub tx_bytes: u64,
}

/// Answer of `POST /api/v1/wg-hub/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusAccepted {
    /// Peers matched to a live member of a hub network.
    pub accepted: usize,
    /// Peers not matched (unknown key, revoked, network of another hub, duplicate).
    pub ignored: usize,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn interface_names_round_trip() {
        for port in [1, 9, 10, 51820, 65535] {
            assert_eq!(parse_interface_name(&interface_name(port)), Some(port));
        }
        assert_eq!(interface_name(51820), "dwg51820");
        for bad in [
            "dwg",
            "dwg0",
            "dwg065535",
            "dwg01",
            "dwg65536",
            "dwg99999",
            "dwg123456",
            "dwg51820x",
            "dwg+1",
            "dwg-1",
            "wg0",
            "Dwg51820",
            "",
        ] {
            assert_eq!(parse_interface_name(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn hub_state_json() {
        let state = HubState {
            hub_id: Uuid::from_u128(1),
            revision: 7,
            networks: vec![HubNetwork {
                id: Uuid::from_u128(2),
                name: "lab".into(),
                interface: interface_name(51820),
                listen_port: 51820,
                prefix: "10.77.0.0/24".parse().unwrap(),
                address: Ipv4Addr::new(10, 77, 0, 1),
                mtu: 1420,
                peers: vec![HubPeer {
                    member_id: Uuid::from_u128(3),
                    kind: "device".into(),
                    public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=".into(),
                    allowed_ips: vec![
                        "10.77.0.2/32".parse().unwrap(),
                        "192.168.10.0/24".parse().unwrap(),
                    ],
                    preshared_key: None,
                }],
            }],
        };
        let text = serde_json::to_string(&state).unwrap();
        assert_eq!(
            text,
            concat!(
                r#"{"hub_id":"00000000-0000-0000-0000-000000000001","revision":7,"networks":[{"#,
                r#""id":"00000000-0000-0000-0000-000000000002","name":"lab","interface":"dwg51820","#,
                r#""listen_port":51820,"prefix":"10.77.0.0/24","address":"10.77.0.1","mtu":1420,"#,
                r#""peers":[{"member_id":"00000000-0000-0000-0000-000000000003","kind":"device","#,
                r#""public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=","#,
                r#""allowed_ips":["10.77.0.2/32","192.168.10.0/24"]}]}]}"#
            )
        );
        assert_eq!(serde_json::from_str::<HubState>(&text).unwrap(), state);
    }

    #[test]
    fn a_preshared_key_is_sent_but_never_shown() {
        let psk = "UFNLcHNrUFNLcHNrUFNLcHNrUFNLcHNrUFNLcHNrMDA=";
        let mut peer = HubPeer {
            member_id: Uuid::from_u128(3),
            kind: "client".into(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=".into(),
            allowed_ips: vec!["10.77.0.3/32".parse().unwrap()],
            preshared_key: Some(psk.into()),
        };
        let text = serde_json::to_string(&peer).unwrap();
        assert!(
            text.ends_with(&format!(r#","preshared_key":"{psk}"}}"#)),
            "{text}"
        );
        assert_eq!(serde_json::from_str::<HubPeer>(&text).unwrap(), peer);
        let shown = format!("{peer:?}");
        assert!(!shown.contains(psk), "{shown}");
        assert!(
            shown.contains("preshared_key: Some(\"********\")"),
            "{shown}"
        );
        // None -> field left out; state without it reads as none.
        peer.preshared_key = None;
        let text = serde_json::to_string(&peer).unwrap();
        assert!(!text.contains("preshared_key"), "{text}");
        assert_eq!(serde_json::from_str::<HubPeer>(&text).unwrap(), peer);
    }

    #[test]
    fn prefixes_are_read_strictly_from_json() {
        assert!(serde_json::from_str::<Ipv4Prefix>(r#""10.77.0.1/24""#).is_err());
        assert!(serde_json::from_str::<Ipv4Prefix>(r#""10.77.0.0""#).is_err());
        assert!(serde_json::from_str::<Ipv4Prefix>("24").is_err());
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let report: StatusAccepted =
            serde_json::from_str(r#"{"accepted":1,"ignored":2,"later":true}"#).unwrap();
        assert_eq!(
            report,
            StatusAccepted {
                accepted: 1,
                ignored: 2
            }
        );
    }
}
