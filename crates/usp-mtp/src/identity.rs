//! Identity rules shared by the MTPs Dhonomos serves (WebSocket, STOMP, embedded MQTT
//! broker): who may be whom.
//!
//! EndpointID of an Agent = claim until proved. Over TLS: proof = client cert naming the
//! EndpointID. Shared first-contact accounts (STOMP, MQTT) + lab modes without any -> no proof.
//! Two rules -> weak proofs cannot undo the strong one (H-3):
//!
//! - One MTP: connection without client cert never replaces a live connection of the same
//!   EndpointID made with one ([`may_replace`]).
//! - Across MTPs: EndpointID with an issued client cert (Controller tells the MTPs which:
//!   [`CertPolicy::set_bound`]) -> refused on every MTP to a connection without a cert naming
//!   it. Else an Agent with the shared account of one MTP could claim the EndpointID of an
//!   Agent proved on another MTP and become its newest address.
//!
//! Revoked client cert (by SHA-256 fingerprint, M-5) -> refused at connect; its connections
//! closed at revocation.
//!
//! MQTT via external broker: out of reach of both. Broker terminates TLS -> Controller sees no
//! client cert. Control there = broker's own (per-device accounts + topic ACLs, see
//! [`crate::dynsec`]).

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

/// TLS client cert of a connection: its EndpointIDs + fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientCert {
    /// EndpointIDs in its `urn:bbf:usp:id:` subjectAltNames.
    pub(crate) ids: Vec<String>,
    /// SHA-256 of the DER cert, hex.
    pub(crate) fingerprint: String,
}

impl ClientCert {
    /// Cert presented by the client of `tls`, if any.
    /// Already verified against the trusted CAs by the handshake.
    pub(crate) fn of(tls: &rustls::ServerConnection) -> Option<Self> {
        tls.peer_certificates()
            .and_then(|chain| chain.first())
            .map(|cert| Self {
                ids: dhonomos_pki::endpoint_ids(cert),
                fingerprint: dhonomos_pki::fingerprint(cert),
            })
    }
}

/// Reason a connection is refused because of client certs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Client cert revoked.
    Revoked,
    /// EndpointID has an issued client cert, connection has none.
    CertificateRequired,
    /// EndpointID connected with a client cert, new connection has none.
    Outranked,
}

impl Refusal {
    /// Text for the peer.
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Revoked => "the client certificate is revoked",
            Self::CertificateRequired => "the EndpointID is bound to a client certificate",
            Self::Outranked => "the EndpointID is connected with a client certificate",
        }
    }

    /// Metrics label.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Revoked => "certificate_revoked",
            Self::CertificateRequired => "certificate_required",
            Self::Outranked => "outranked",
        }
    }
}

/// New connection may replace a live one of the same EndpointID?
/// `existing`, `new`: fingerprints of their client certs (`None` -> only the claimed EndpointID).
/// Without cert -> never displaces one with cert. With cert -> displaces anything.
pub(crate) fn may_replace(existing: Option<&str>, new: Option<&str>) -> bool {
    new.is_some() || existing.is_none()
}

/// Cert rules of one MTP, fed by the Controller: EndpointIDs bound to a client cert +
/// fingerprints of revoked certs. Cheap clone; clones share the sets.
#[derive(Debug, Clone, Default)]
pub(crate) struct CertPolicy {
    bound: Arc<RwLock<HashSet<String>>>,
    revoked: Arc<RwLock<HashSet<String>>>,
}

impl CertPolicy {
    /// Replace the set of EndpointIDs that need a client cert to connect.
    /// Live connections untouched -> Agent getting its cert over its current connection must
    /// not be cut off mid-way.
    pub(crate) fn set_bound(&self, eids: HashSet<String>) {
        if let Ok(mut b) = self.bound.write() {
            *b = eids;
        }
    }

    /// `eid` refused to connections without client cert?
    pub(crate) fn requires_cert(&self, eid: &str) -> bool {
        self.bound.read().is_ok_and(|b| b.contains(eid))
    }

    pub(crate) fn is_revoked(&self, fingerprint: &str) -> bool {
        self.revoked.read().is_ok_and(|r| r.contains(fingerprint))
    }

    /// Replace the revoked set. MTP calls this under the lock of its connection registry,
    /// after closing the connections of a newly revoked cert -> a connection registering
    /// meanwhile is either among those closed or sees the new set.
    pub(crate) fn replace_revoked(&self, fingerprints: HashSet<String>) {
        if let Ok(mut r) = self.revoked.write() {
            *r = fingerprints;
        }
    }

    /// Refusal check before registration.
    /// `eid`: claimed EndpointID (`None` until it names itself); `cert`: client cert presented.
    pub(crate) fn check(
        &self,
        eid: Option<&str>,
        cert: Option<&ClientCert>,
    ) -> Result<(), Refusal> {
        match cert {
            Some(c) if self.is_revoked(&c.fingerprint) => Err(Refusal::Revoked),
            None if eid.is_some_and(|e| self.requires_cert(e)) => Err(Refusal::CertificateRequired),
            _ => Ok(()),
        }
    }

    /// Connection with cert `new` (if any) may register for an EndpointID whose live
    /// connection has `existing`? Caller holds the registry lock across this + registration.
    pub(crate) fn admit(&self, existing: Option<&str>, new: Option<&str>) -> Result<(), Refusal> {
        if new.is_some_and(|f| self.is_revoked(f)) {
            return Err(Refusal::Revoked);
        }
        if !may_replace(existing, new) {
            return Err(Refusal::Outranked);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(fp: &str) -> ClientCert {
        ClientCert {
            ids: vec!["os::a".into()],
            fingerprint: fp.into(),
        }
    }

    #[test]
    fn a_certificate_outranks_a_claim() {
        assert!(may_replace(None, None));
        assert!(may_replace(None, Some("fp")));
        assert!(may_replace(Some("old"), Some("new")));
        assert!(may_replace(Some("fp"), Some("fp")));
        assert!(!may_replace(Some("fp"), None));
    }

    #[test]
    fn bound_endpoint_ids_need_a_certificate_and_revoked_certificates_are_refused() {
        let p = CertPolicy::default();
        // Nothing bound or revoked at start.
        assert_eq!(p.check(Some("os::a"), None), Ok(()));
        assert_eq!(p.check(Some("os::a"), Some(&cert("fp"))), Ok(()));

        p.set_bound(["os::a".to_owned()].into());
        assert_eq!(
            p.check(Some("os::a"), None),
            Err(Refusal::CertificateRequired)
        );
        // Other EndpointID, not yet named, or with cert -> OK.
        assert_eq!(p.check(Some("os::b"), None), Ok(()));
        assert_eq!(p.check(None, None), Ok(()));
        assert_eq!(p.check(Some("os::a"), Some(&cert("fp"))), Ok(()));
        // Unbind -> claims allowed again.
        p.set_bound(HashSet::new());
        assert_eq!(p.check(Some("os::a"), None), Ok(()));

        p.replace_revoked(["fp".to_owned()].into());
        assert_eq!(
            p.check(Some("os::a"), Some(&cert("fp"))),
            Err(Refusal::Revoked)
        );
        assert_eq!(p.check(None, Some(&cert("fp"))), Err(Refusal::Revoked));
        assert_eq!(p.check(Some("os::a"), Some(&cert("renewed"))), Ok(()));
    }

    #[test]
    fn registration_is_admitted_unless_revoked_or_outranked() {
        let p = CertPolicy::default();
        assert_eq!(p.admit(None, None), Ok(()));
        assert_eq!(p.admit(Some("fp"), Some("renewed")), Ok(()));
        assert_eq!(p.admit(Some("fp"), None), Err(Refusal::Outranked));
        p.replace_revoked(["bad".to_owned()].into());
        assert_eq!(p.admit(None, Some("bad")), Err(Refusal::Revoked));
        assert_eq!(p.admit(Some("fp"), Some("bad")), Err(Refusal::Revoked));
    }

    #[test]
    fn clones_share_what_they_are_told() {
        let p = CertPolicy::default();
        let q = p.clone();
        q.set_bound(["os::a".to_owned()].into());
        assert!(p.requires_cert("os::a"));
    }
}
