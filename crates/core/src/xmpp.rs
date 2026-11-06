//! Accounts of the built-in XMPP server (ADR-104).
//! Device login = `<device ID>@<domain>` + its provisioned password.
//! Kind `xmpp_pending` until 1st login, then `xmpp` (same rule as ACS credentials, ADR-095).

use std::sync::Arc;
use std::time::SystemTime;

use dhonomos_store::Store;
use dhonomos_xmpp::{Accounts, Credential, Unavailable};
use time::OffsetDateTime;
use tracing::{info, warn};
use uuid::Uuid;

use crate::secrets::SecretBox;

/// Kind of the device's XMPP password.
pub(crate) const KIND_ACTIVE: &str = "xmpp";
/// Kind during provisioning.
pub(crate) const KIND_PENDING: &str = "xmpp_pending";

/// Account lookup in the device registry.
#[derive(Debug, Clone)]
pub struct XmppAccounts {
    store: Store,
    tenant_id: Uuid,
    secrets: Arc<SecretBox>,
}

impl XmppAccounts {
    /// Accounts of one tenant's devices. Passwords opened with `secrets`.
    pub fn new(store: Store, tenant_id: Uuid, secrets: Arc<SecretBox>) -> Self {
        Self {
            store,
            tenant_id,
            secrets,
        }
    }
}

/// JID local part of `device` = its ID, lowercase + hyphenated.
pub fn account_of(device: Uuid) -> String {
    device.hyphenated().to_string()
}

/// Device of an account (JID local part). Only the exact form of [`account_of`].
fn device_of(account: &str) -> Option<Uuid> {
    let id = Uuid::parse_str(account).ok()?;
    (account_of(id) == account).then_some(id)
}

#[async_trait::async_trait]
impl Accounts for XmppAccounts {
    async fn credentials(&self, account: &str) -> Result<Vec<Credential>, Unavailable> {
        let Some(device) = device_of(account) else {
            return Ok(Vec::new());
        };
        let rows = self
            .store
            .find_xmpp_credentials(self.tenant_id, device)
            .await
            .map_err(|e| {
                warn!(error = %e, "XMPP credential lookup failed");
                Unavailable
            })?;
        Ok(rows
            .into_iter()
            .filter_map(|c| {
                match self
                    .secrets
                    .open_credential(device, &c.ciphertext, &c.nonce)
                {
                    Ok(password) => Some(Credential {
                        password,
                        pending: c.kind == KIND_PENDING,
                    }),
                    Err(e) => {
                        warn!(%device, error = %e, "cannot decrypt the XMPP credential");
                        None
                    }
                }
            })
            .collect())
    }

    async fn accepted(&self, account: &str, credential: &Credential) {
        let Some(device) = device_of(account) else {
            return;
        };
        if !credential.pending {
            return;
        }
        // Login with the given password -> it is the device's password now.
        match self
            .store
            .promote_credential(device, KIND_PENDING, KIND_ACTIVE)
            .await
        {
            Ok(true) => {
                info!(%device, "per-device XMPP credentials active");
                metrics::counter!("dhonomos_xmpp_credentials_provisioned_total").increment(1);
            }
            Ok(false) => {}
            Err(e) => warn!(%device, error = %e, "promoting the XMPP credential failed"),
        }
    }

    async fn connected(&self, account: &str, at: SystemTime) {
        let Some(device) = device_of(account) else {
            return;
        };
        if let Err(e) = self
            .store
            .set_xmpp_connected(device, OffsetDateTime::from(at))
            .await
        {
            warn!(%device, error = %e, "recording the XMPP session failed");
        }
    }

    async fn disconnected(&self, account: &str, at: SystemTime) {
        let Some(device) = device_of(account) else {
            return;
        };
        if let Err(e) = self
            .store
            .clear_xmpp_connected(device, OffsetDateTime::from(at))
            .await
        {
            warn!(%device, error = %e, "recording the end of the XMPP session failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_are_hyphenated_lowercase_device_ids() {
        let id = Uuid::now_v7();
        assert_eq!(account_of(id), id.to_string());
        assert_eq!(device_of(&id.to_string()), Some(id));
        for bad in [
            id.simple().to_string(),
            id.to_string().to_uppercase(),
            format!("{{{id}}}"),
            format!("urn:uuid:{id}"),
            "acs".to_owned(),
            String::new(),
        ] {
            assert_eq!(device_of(&bad), None, "{bad}");
        }
    }
}
