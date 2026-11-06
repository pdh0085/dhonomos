//! Wake devices -> queued tasks run now (Connection Request, CW-08).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dhonomos_cwmp_server::{AddressPolicy, ConnReqCredentials, connection_request};
use dhonomos_store::Store;
use dhonomos_xmpp::{CrOutcome, XmppServer};
use tokio::net::UdpSocket;
use tracing::{debug, warn};
use uuid::Uuid;

/// Max wait for the device answer to an XMPP CR -> then HTTP + UDP.
const XMPP_TIMEOUT: Duration = Duration::from_secs(10);

/// Result of a wake attempt -> API callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeOutcome {
    /// HTTP CR accepted by the device.
    Sent,
    /// UDP CR (CPE behind NAT, CW-08). Delivery not confirmed.
    SentUdp,
    /// CR over the XMPP connection of the device (Annex K, ADR-104).
    /// Device answered -> delivery confirmed.
    SentXmpp,
    /// No CR URL -> device gets its tasks at next Inform.
    NoUrl,
    Failed(String),
    /// USP Agent connected -> queued tasks sent now.
    UspSending,
    /// USP Agent offline -> tasks run at next connect.
    UspOffline,
}

impl WakeOutcome {
    /// Short English text for API responses.
    pub fn describe(&self) -> String {
        match self {
            Self::Sent => "sent".into(),
            Self::SentUdp => "sent over UDP (device behind NAT)".into(),
            Self::SentXmpp => "sent over XMPP".into(),
            Self::NoUrl => "skipped: no connection request URL".into(),
            Self::Failed(e) => format!("failed: {e}"),
            Self::UspSending => "sent (USP agent connected)".into(),
            Self::UspOffline => "queued: USP agent offline".into(),
        }
    }

    /// Way the request went out = `devices.last_wake_method`: `xmpp`, `http`, `udp`, `usp`.
    /// `None` -> nothing sent (no URL, failure, Agent offline).
    pub fn method(&self) -> Option<&'static str> {
        match self {
            Self::Sent => Some("http"),
            Self::SentUdp => Some("udp"),
            Self::SentXmpp => Some("xmpp"),
            Self::UspSending => Some("usp"),
            Self::NoUrl | Self::Failed(_) | Self::UspOffline => None,
        }
    }
}

/// Connection Requests (XMPP, HTTP, UDP) + USP wakes.
#[derive(Debug, Clone)]
pub struct Waker {
    store: Store,
    credentials: Option<ConnReqCredentials>,
    timeout: Duration,
    secrets: Option<std::sync::Arc<crate::secrets::SecretBox>>,
    usp: Option<crate::usp::UspService>,
    udp: Option<Arc<UdpSocket>>,
    xmpp: Option<XmppServer>,
    xmpp_timeout: Duration,
    policy: Arc<AddressPolicy>,
    basic_auth: bool,
}

/// URL not reachable from the Internet: private, CGNAT, loopback, link-local.
fn unreachable_url(url: &str) -> bool {
    let host = url
        .split_once("://")
        .map_or(url, |(_, rest)| rest)
        .split(['/', '?'])
        .next()
        .unwrap_or_default();
    // `[v6]:port`, `[v6]`, `v4:port`, `name:port` or bare host.
    let host = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => host.split(':').next().unwrap_or_default(),
    };
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        Ok(IpAddr::V6(v6)) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        Err(_) => false,
    }
}

impl Waker {
    /// `credentials` -> fallback for devices without own CR credentials (CO-16).
    pub fn new(store: Store, credentials: Option<ConnReqCredentials>, timeout: Duration) -> Self {
        Self {
            store,
            credentials,
            timeout,
            secrets: None,
            usp: None,
            udp: None,
            xmpp: None,
            xmpp_timeout: XMPP_TIMEOUT,
            policy: Arc::new(AddressPolicy::default()),
            basic_auth: false,
        }
    }

    /// Answer a Basic auth challenge of a CR URL with the CR credentials.
    ///
    /// Basic over plain http -> credentials in clear text.
    /// CPE (or whoever answers at its reported address) picks the scheme.
    /// -> off by default, only Digest answered (L-6).
    pub fn with_basic_auth(mut self, allow: bool) -> Self {
        self.basic_auth = allow;
        self
    }

    /// Allowed target addresses of CRs (HTTP + UDP).
    /// Default refuses loopback, link-local, multicast, unspecified (SE-03).
    pub fn with_address_policy(mut self, policy: AddressPolicy) -> Self {
        self.policy = Arc::new(policy);
        self
    }

    /// UDP CRs from `socket` to CPEs behind NAT (CW-08).
    pub fn with_udp(mut self, socket: Arc<UdpSocket>) -> Self {
        self.udp = Some(socket);
        self
    }

    /// CRs over the built-in XMPP server (TR-069 Annex K, ADR-104), before HTTP + UDP.
    ///
    /// XMPP connections live in process memory -> Waker must run in the same process.
    pub fn with_xmpp(mut self, xmpp: XmppServer) -> Self {
        self.xmpp = Some(xmpp);
        self
    }

    /// Max wait for the device answer to an XMPP CR -> then HTTP + UDP. Default 10 s.
    pub fn with_xmpp_timeout(mut self, timeout: Duration) -> Self {
        self.xmpp_timeout = timeout;
        self
    }

    /// Wake USP devices via the USP service.
    pub fn with_usp(mut self, usp: crate::usp::UspService) -> Self {
        self.usp = Some(usp);
        self
    }

    /// Per-device CR credentials when stored (CO-16).
    pub fn with_secrets(mut self, secrets: std::sync::Arc<crate::secrets::SecretBox>) -> Self {
        self.secrets = Some(secrets);
        self
    }

    async fn device_credentials(&self, device: Uuid) -> Option<ConnReqCredentials> {
        let secrets = self.secrets.as_ref()?;
        let c = self
            .store
            .get_credential(device, "connection_request")
            .await
            .ok()??;
        let password = String::from_utf8(
            secrets
                .open_credential(device, &c.ciphertext, &c.nonce)
                .ok()?,
        )
        .ok()?;
        Some(ConnReqCredentials {
            username: c.username,
            password,
        })
    }

    /// CR over XMPP. `None` -> go on with HTTP + UDP
    /// (no session, no answer in time, or not sent).
    async fn wake_xmpp(
        &self,
        xmpp: &XmppServer,
        device: Uuid,
        creds: Option<&ConnReqCredentials>,
    ) -> Option<WakeOutcome> {
        let account = crate::xmpp::account_of(device);
        if !xmpp.is_connected(&account) {
            return None;
        }
        // Device checks the CR credentials + some xmppc crash on a CR without user name.
        // -> no user name -> HTTP + UDP only.
        let Some(creds) = creds.filter(|c| !c.username.is_empty()) else {
            debug!(%device, "no Connection Request credentials to send over XMPP");
            return None;
        };
        match xmpp
            .send_connection_request(
                &account,
                &creds.username,
                &creds.password,
                self.xmpp_timeout,
            )
            .await
        {
            Ok(CrOutcome::Acknowledged) => Some(WakeOutcome::SentXmpp),
            // Wrong credentials or sender refused. HTTP + UDP use the same credentials
            // -> not tried.
            Ok(CrOutcome::Rejected(condition)) => Some(WakeOutcome::Failed(format!(
                "XMPP connection request refused: {condition}"
            ))),
            Ok(CrOutcome::TimedOut) => {
                debug!(%device, "XMPP connection request not answered; trying HTTP and UDP");
                None
            }
            Ok(CrOutcome::NotConnected) => None,
            Err(e) => {
                warn!(%device, error = %e, "XMPP connection request not sent; trying HTTP and UDP");
                None
            }
        }
    }

    /// Ask the device to open a session. Outcome -> metric + device record.
    pub async fn wake(&self, device: Uuid) -> WakeOutcome {
        let outcome = self.wake_inner(device).await;
        let label = match &outcome {
            WakeOutcome::Sent => "sent",
            WakeOutcome::SentUdp => "sent_udp",
            WakeOutcome::SentXmpp => "sent_xmpp",
            WakeOutcome::NoUrl => "no_url",
            WakeOutcome::Failed(_) => "failed",
            WakeOutcome::UspSending => "usp_sending",
            WakeOutcome::UspOffline => "usp_offline",
        };
        metrics::counter!("dhonomos_connection_requests_total", "outcome" => label).increment(1);
        // Display only (last wake of the device) -> record failure != wake failure.
        if let Err(e) = self
            .store
            .record_wake(device, outcome.method(), &outcome.describe())
            .await
        {
            warn!(%device, error = %e, "recording the wake failed");
        }
        outcome
    }

    async fn wake_inner(&self, device: Uuid) -> WakeOutcome {
        let url = match self.store.get_device(device).await {
            Ok(Some(d)) if d.protocol == "usp" => {
                let (Some(usp), Some(eid)) = (&self.usp, d.endpoint_id) else {
                    return WakeOutcome::Failed("USP is not enabled".into());
                };
                return if usp.wake(device, &eid).await {
                    WakeOutcome::UspSending
                } else {
                    WakeOutcome::UspOffline
                };
            }
            Ok(Some(d)) => d.connection_request_url,
            Ok(None) => return WakeOutcome::Failed("unknown device".into()),
            Err(e) => return WakeOutcome::Failed(e.to_string()),
        };
        let per_device = self.device_credentials(device).await;
        let creds = per_device.or_else(|| self.credentials.clone());
        // XMPP session first: CR on the connection the device opened -> NAT no problem.
        // Device answers. Address policy for outgoing requests does not apply.
        if let Some(xmpp) = &self.xmpp
            && let Some(outcome) = self.wake_xmpp(xmpp, device, creds.as_ref()).await
        {
            return outcome;
        }
        let udp = match &self.udp {
            Some(socket) => self
                .store
                .udp_cr_address(device)
                .await
                .ok()
                .flatten()
                .and_then(|(a, _)| a.parse::<SocketAddr>().ok())
                .map(|a| (socket.clone(), a)),
            None => None,
        };
        let url = url.filter(|u| !u.is_empty());
        // Behind NAT -> HTTP URL unreachable -> straight to UDP.
        let try_http = match (&url, &udp) {
            (Some(u), Some(_)) => !unreachable_url(u),
            (Some(_), None) => true,
            (None, _) => false,
        };
        let mut http_error = None;
        if let (true, Some(u)) = (try_http, &url) {
            match connection_request(
                u,
                creds.as_ref(),
                self.timeout,
                &self.policy,
                self.basic_auth,
            )
            .await
            {
                Ok(()) => return WakeOutcome::Sent,
                Err(e) => http_error = Some(e.to_string()),
            }
        }
        if let Some((socket, addr)) = udp {
            if !self.policy.permits(addr.ip()) {
                return WakeOutcome::Failed(format!(
                    "UDP connection request: address not permitted: {}",
                    addr.ip()
                ));
            }
            let (user, pass) = creds
                .as_ref()
                .map_or(("", ""), |c| (c.username.as_str(), c.password.as_str()));
            return match dhonomos_cwmp_server::udpcr::send(&socket, addr, user, pass).await {
                Ok(()) => WakeOutcome::SentUdp,
                Err(e) => WakeOutcome::Failed(format!("UDP connection request: {e}")),
            };
        }
        match (url, http_error) {
            (None, _) => WakeOutcome::NoUrl,
            (_, Some(e)) => WakeOutcome::Failed(e),
            (Some(_), None) => WakeOutcome::NoUrl,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WakeOutcome;

    #[test]
    fn outcomes_name_the_way_they_went() {
        assert_eq!(WakeOutcome::Sent.method(), Some("http"));
        assert_eq!(WakeOutcome::SentUdp.method(), Some("udp"));
        assert_eq!(WakeOutcome::SentXmpp.method(), Some("xmpp"));
        assert_eq!(WakeOutcome::UspSending.method(), Some("usp"));
        for nothing_sent in [
            WakeOutcome::NoUrl,
            WakeOutcome::Failed("x".into()),
            WakeOutcome::UspOffline,
        ] {
            assert_eq!(nothing_sent.method(), None, "{nothing_sent:?}");
        }
    }

    #[test]
    fn private_urls() {
        for u in [
            "http://192.168.1.1:7547/",
            "http://10.0.0.2:7547/cr",
            "http://100.70.1.1:30005/",
            "http://[fd00::1]:7547/",
            "http://[fd00::1]/",
            "http://127.0.0.1:7547",
        ] {
            assert!(super::unreachable_url(u), "{u}");
        }
        for u in [
            "http://203.0.113.9:7547/",
            "http://cpe.example.net:7547/",
            "http://[2001:db8::1]:7547/",
        ] {
            assert!(!super::unreachable_url(u), "{u}");
        }
    }
}
