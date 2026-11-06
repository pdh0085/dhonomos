//! Broker accounts for USP Agents (US-17): issue, rotate, revoke, follow device status.
//!
//! Agent account: username = EndpointID, random password.
//! Publish only to its own Controller topic `<controller topic>/<EndpointID>`.
//! Subscribe only to `<prefix><EndpointID>`.
//! Password returned once, stored encrypted (CO-16).

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dhonomos_store::{Device, SealedCredential, Store};
pub use dhonomos_usp_mtp::dynsec::valid_endpoint_id;
use dhonomos_usp_mtp::{Dynsec, DynsecError};
use ring::rand::{SecureRandom as _, SystemRandom};

use crate::SecretBox;

/// Credential kind of broker accounts.
pub const MQTT_KIND: &str = "mqtt";

/// Broker account for an Agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCredentials {
    /// MQTT username (= EndpointID).
    pub username: String,
    /// MQTT password; shown once.
    pub password: String,
    /// Agent subscribe topic (its `LocalAgent.MTP.{i}.MQTT.ResponseTopicConfigured`).
    pub agent_topic: String,
    /// Agent publish topic (its `Controller.{i}.MTP.{i}.MQTT.Topic`).
    pub controller_topic: String,
}

/// Broker operation failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BrokerError {
    #[error("broker accounts are only for USP devices")]
    NotUsp,
    /// Broker refused or no answer.
    #[error("broker: {0}")]
    Broker(#[from] DynsecError),
    /// Credential store failed.
    #[error("store: {0}")]
    Store(#[from] dhonomos_store::StoreError),
    /// Password generate or encrypt failed.
    #[error("{0}")]
    Secret(#[from] crate::SecretError),
}

/// Agent accounts on the broker.
#[derive(Debug, Clone)]
pub struct BrokerAccess {
    dynsec: Dynsec,
    secrets: Arc<SecretBox>,
    controller_topic: String,
    agent_topic_prefix: String,
}

impl BrokerAccess {
    /// `dynsec` -> broker changes; `secrets` -> encrypt issued passwords.
    pub fn new(
        dynsec: Dynsec,
        secrets: Arc<SecretBox>,
        controller_topic: impl Into<String>,
        agent_topic_prefix: impl Into<String>,
    ) -> Self {
        Self {
            dynsec,
            secrets,
            controller_topic: controller_topic.into(),
            agent_topic_prefix: agent_topic_prefix.into(),
        }
    }

    /// Create the broker roles; `controller_username` -> Controller role.
    pub async fn bootstrap(&self, controller_username: Option<&str>) -> Result<(), BrokerError> {
        self.dynsec
            .ensure_roles(
                &self.controller_topic,
                &self.agent_topic_prefix,
                controller_username,
            )
            .await?;
        Ok(())
    }

    fn endpoint_id(device: &Device) -> Result<&str, BrokerError> {
        match (&*device.protocol, device.endpoint_id.as_deref()) {
            ("usp", Some(eid)) => Ok(eid),
            _ => Err(BrokerError::NotUsp),
        }
    }

    /// Issue or rotate the broker account of the device.
    /// Device not active -> disabled account.
    pub async fn issue(
        &self,
        store: &Store,
        device: &Device,
    ) -> Result<IssuedCredentials, BrokerError> {
        let eid = Self::endpoint_id(device)?;
        let mut raw = [0u8; 18];
        SystemRandom::new()
            .fill(&mut raw)
            .map_err(|_| crate::SecretError::Rng)?;
        let password = URL_SAFE_NO_PAD.encode(raw);
        self.dynsec.upsert_agent(eid, &password).await?;
        if device.status != "active" {
            self.dynsec.set_agent_enabled(eid, false).await?;
        }
        let (ciphertext, nonce) = self
            .secrets
            .seal_credential(device.id, password.as_bytes())?;
        store
            .put_credential(&SealedCredential {
                device_id: device.id,
                kind: MQTT_KIND.into(),
                username: eid.to_owned(),
                ciphertext,
                nonce,
                key_id: self.secrets.key_id().to_owned(),
            })
            .await?;
        Ok(IssuedCredentials {
            username: eid.to_owned(),
            password,
            agent_topic: format!("{}{eid}", self.agent_topic_prefix),
            // Own Controller topic of the Agent: only this account may publish there
            // -> Records on it come from this EndpointID.
            controller_topic: format!("{}/{eid}", self.controller_topic),
        })
    }

    /// Delete the broker account of the device -> Agent disconnected.
    /// Returns: device had one.
    pub async fn revoke(&self, store: &Store, device: &Device) -> Result<bool, BrokerError> {
        let eid = Self::endpoint_id(device)?;
        self.dynsec.delete_agent(eid).await?;
        Ok(store.delete_credential(device.id, MQTT_KIND).await?)
    }

    /// Active device -> account enabled; else disabled (-> Agent disconnected).
    /// Device without account -> left alone.
    pub async fn apply_status(&self, store: &Store, device: &Device) -> Result<(), BrokerError> {
        let Ok(eid) = Self::endpoint_id(device) else {
            return Ok(());
        };
        if store.get_credential(device.id, MQTT_KIND).await?.is_none() {
            return Ok(());
        }
        self.dynsec
            .set_agent_enabled(eid, device.status == "active")
            .await?;
        Ok(())
    }
}
