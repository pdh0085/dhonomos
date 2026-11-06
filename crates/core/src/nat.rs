//! NAT traversal for CWMP CR (CW-08).
//! Built-in STUN server learns UDP CR addresses -> stored here.

use dhonomos_cwmp_server::stun::{CrBinding, PasswordOf};
use dhonomos_store::Store;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::sync::mpsc;
use tracing::debug;
use uuid::Uuid;

/// STUN password of a device = HMAC-SHA256 of server secret -> nothing stored.
/// Zero-touch writes it to `ManagementServer.STUNPassword`.
pub fn stun_password(secret: &[u8], device: Uuid) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret)
        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    mac.update(format!("stun|{device}").as_bytes());
    mac.finalize().into_bytes()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// STUN server password lookup. Username = device ID.
pub fn stun_passwords(secret: Vec<u8>) -> PasswordOf {
    std::sync::Arc::new(move |username: &str| {
        let device = username.parse::<Uuid>().ok()?;
        Some(stun_password(&secret, device).into_bytes())
    })
}

/// Store STUN bindings until channel close.
/// STUN username = device ID, set at zero-touch by
/// [`crate::CwmpBackend::with_stun_provisioning`].
pub async fn record_bindings(
    store: Store,
    tenant_id: Uuid,
    mut bindings: mpsc::Receiver<CrBinding>,
) {
    while let Some(b) = bindings.recv().await {
        let Ok(device) = b.username.parse::<Uuid>() else {
            debug!(username = %b.username, "STUN binding with an unknown username");
            continue;
        };
        match store
            .set_udp_cr_address(tenant_id, device, &b.address.to_string())
            .await
        {
            Ok(true) => metrics::counter!("dhonomos_stun_bindings_total").increment(1),
            Ok(false) => debug!(%device, "STUN binding for an unknown device"),
            Err(e) => debug!(%device, error = %e, "storing a STUN binding failed"),
        }
    }
}
