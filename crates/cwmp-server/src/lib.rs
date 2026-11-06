//! CWMP ACS HTTP listener: sessions, CPE auth, listener protection.
//!
//! One [`dhonomos_cwmp_session::Session`] per CPE. Business decisions -> [`Backend`].

mod addrpolicy;
mod auth;
mod backend;
mod connlimit;
mod connreq;
mod guard;
mod server;
pub mod stun;
mod tls;
pub mod udpcr;

pub use addrpolicy::{AddressPolicy, Cidr};
pub use auth::{AuthMode, DigestInput, digest_response};
pub use backend::{Backend, InformContext, PasswordCandidate};
pub use connreq::{ConnReqCredentials, ConnReqError, connection_request};
pub use server::{AcsServer, Config, bind};
pub use tls::{TlsError, acceptor, acceptor_from_pem, acceptor_with_resolver};
