//! Built-in XMPP server for TR-069 Annex K CR (ADR-104).
//!
//! CPE behind NAT/CGNAT -> no HTTP CR. Its `xmppc` keeps a connection to this server open.
//! Wake = ACS sends an `iq` on it; device `result` -> delivery confirmed.
//!
//! Only what Annex K needs of RFC 6120: STARTTLS (required), SASL PLAIN, resource binding,
//! XEP-0199 ping, one session per device account.
//! None of: routing between clients, roster, presence, message delivery (messages dropped),
//! server-to-server, stream management, compression -> device talks to this server only.
//! Design: `docs/design/12-xmpp-server.md`.
//!
//! No device registry here: app plugs in [`Accounts`] (who logs in with which password,
//! note when a device connects or goes away).
//! App wakes a device with [`XmppServer::send_connection_request`].
//!
//! Logs + metrics: stanza kinds and error conditions only.
//! Never logged: passwords, CR credentials, stanza bodies.

mod attempts;
mod connlimit;
mod sasl;
mod server;
mod session;
mod wire;
mod xml;

pub use server::{
    ACS_LOCALPART, Accounts, CrOutcome, Credential, SendError, Unavailable, XmppConfig, XmppServer,
    tls_acceptor,
};
pub use xml::{
    Element, Event, MAX_ATTRIBUTES, MAX_DEPTH, MAX_NAME, MAX_NAMESPACE, MAX_STANZA,
    MAX_STANZA_PRE_AUTH, NS_CLIENT, NS_STREAMS, Parser, StreamHeader,
};

/// Stream error condition (RFC 6120 sec. 4.9.3): why the server closes a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Condition {
    /// Newer session of the same account took over.
    Conflict,
    ConnectionTimeout,
    /// Stream for a domain this server does not serve.
    HostUnknown,
    InternalServerError,
    /// Wrong namespace on the stream or its content.
    InvalidNamespace,
    /// Sent before allowed (before TLS, before login).
    NotAuthorized,
    NotWellFormed,
    /// Limit exceeded (stanza size, depth, attributes, names).
    PolicyViolation,
    /// Server cannot hold what the connection needs (reader too slow).
    ResourceConstraint,
    /// XML the protocol forbids: DTD, comment, processing instruction, entity.
    RestrictedXml,
    SystemShutdown,
    /// First-level element that is not a stanza of the stream.
    UnsupportedStanzaType,
    /// Stream version older than 1.0.
    UnsupportedVersion,
}

impl Condition {
    /// Element name of the condition = metric label.
    pub fn name(self) -> &'static str {
        match self {
            Self::Conflict => "conflict",
            Self::ConnectionTimeout => "connection-timeout",
            Self::HostUnknown => "host-unknown",
            Self::InternalServerError => "internal-server-error",
            Self::InvalidNamespace => "invalid-namespace",
            Self::NotAuthorized => "not-authorized",
            Self::NotWellFormed => "not-well-formed",
            Self::PolicyViolation => "policy-violation",
            Self::ResourceConstraint => "resource-constraint",
            Self::RestrictedXml => "restricted-xml",
            Self::SystemShutdown => "system-shutdown",
            Self::UnsupportedStanzaType => "unsupported-stanza-type",
            Self::UnsupportedVersion => "unsupported-version",
        }
    }
}
