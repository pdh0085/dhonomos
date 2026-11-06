//! Peer status for the server, from hub interfaces: last handshake, endpoint, traffic.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use dhonomos_wireguard::{HubState, MAX_STATUS_PEERS, PeerStatus, StatusReport, interface_name};
use uuid::Uuid;
use wireguard_uapi::get;
use zeroize::Zeroize as _;

use crate::kernel::read_device;

/// Peers of `device` = interface of network `network_id`.
pub(crate) fn peer_status(network_id: Uuid, device: &get::Device) -> Vec<PeerStatus> {
    device
        .peers
        .iter()
        .map(|p| {
            let secs = i64::try_from(p.last_handshake_time.as_secs()).unwrap_or(i64::MAX);
            PeerStatus {
                network_id,
                public_key: STANDARD.encode(p.public_key),
                endpoint: p.endpoint.map(|e| e.to_string()),
                latest_handshake: (secs > 0).then_some(secs),
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
            }
        })
        .collect()
}

/// Peer status of all interfaces in `state`.
/// Interface not readable (not created yet) -> left out.
pub(crate) async fn collect(state: &HubState) -> StatusReport {
    let mut peers = Vec::new();
    for n in &state.networks {
        let name = interface_name(n.listen_port);
        match read_device(name.clone()).await {
            Ok(mut device) => {
                peers.extend(peer_status(n.id, &device));
                // Report needs no keys -> zero them.
                if let Some(k) = device.private_key.as_mut() {
                    k.zeroize();
                }
                for p in &mut device.peers {
                    p.preshared_key.zeroize();
                }
            }
            Err(e) => {
                tracing::debug!(interface = %name, error = %format!("{e:#}"), "no peer status")
            }
        }
    }
    peers.truncate(MAX_STATUS_PEERS);
    StatusReport { peers }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::time::Duration;

    use super::*;

    fn peer(handshake: u64, endpoint: Option<&str>) -> get::Peer {
        get::Peer {
            public_key: [7; 32],
            preshared_key: [0; 32],
            endpoint: endpoint.map(|e| e.parse().unwrap()),
            persistent_keepalive_interval: 0,
            last_handshake_time: Duration::from_secs(handshake),
            rx_bytes: 10,
            tx_bytes: 20,
            allowed_ips: vec![],
            protocol_version: 1,
        }
    }

    #[test]
    fn kernel_peers_become_status() {
        let device = get::Device {
            ifindex: 3,
            ifname: "dwg51820".into(),
            private_key: None,
            public_key: None,
            listen_port: 51820,
            fwmark: 0,
            peers: vec![
                peer(1_700_000_000, Some("172.31.30.21:40000")),
                peer(0, None),
            ],
        };
        let id = Uuid::from_u128(5);
        let status = peer_status(id, &device);
        assert_eq!(
            status,
            [
                PeerStatus {
                    network_id: id,
                    public_key: STANDARD.encode([7; 32]),
                    endpoint: Some("172.31.30.21:40000".into()),
                    latest_handshake: Some(1_700_000_000),
                    rx_bytes: 10,
                    tx_bytes: 20,
                },
                PeerStatus {
                    network_id: id,
                    public_key: STANDARD.encode([7; 32]),
                    endpoint: None,
                    latest_handshake: None,
                    rx_bytes: 10,
                    tx_bytes: 20,
                },
            ]
        );
    }
}
