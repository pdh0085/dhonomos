//! CWMP (TR-069) SOAP envelope + RPC codec.
//!
//! Sans-IO: [`Envelope::decode`] HTTP body -> typed RPCs; [`Envelope::encode`] -> body.
//! Decode lenient to real CPE output (prefixes, missing fields, array wrapper variants,
//! boolean spelling). Encode strict, standard prefixes.
//!
//! ```
//! use dhonomos_cwmp_codec::{CwmpNamespace, Envelope, InformResponse};
//!
//! let reply = Envelope::rpc(CwmpNamespace::V1_0, "42", InformResponse { max_envelopes: 1 });
//! let xml = reply.encode();
//! assert_eq!(Envelope::decode(xml.as_bytes()).unwrap(), Some(reply));
//! ```

mod codes;
mod envelope;
mod error;
mod field;
mod rpc;
mod types;
mod xml;

pub use codes::{EventCode, FaultCode};
pub use envelope::{Body, CwmpNamespace, Envelope, Fault, Header, SetParameterValuesFault};
pub use error::{DecodeError, Result};
pub use rpc::*;
pub use types::*;
