//! Decode errors.

/// CWMP decode errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// Not well-formed XML.
    #[error("XML error at byte {position}: {source}")]
    Xml {
        /// Byte offset of the error.
        position: u64,
        #[source]
        source: quick_xml::Error,
    },
    /// Element name = not a valid XML name.
    #[error("invalid element name {0:?}")]
    InvalidName(String),
    /// Nesting deeper than the decoder limit.
    #[error("XML nesting deeper than {0} levels")]
    TooDeep(usize),
    /// Structural limit hit: element, attribute, text or namespace-declaration count.
    /// Even for a small input.
    #[error("XML document exceeds the limit of {limit} {what}")]
    TooLarge {
        /// What was counted.
        what: &'static str,
        limit: usize,
    },
    /// Root element != SOAP `Envelope`.
    #[error("root element is <{0}>, expected a SOAP Envelope")]
    NotAnEnvelope(String),
    /// No `Body`, or empty `Body`.
    #[error("SOAP Body is missing or empty")]
    MissingBody,
    /// Field value fails to parse.
    #[error("invalid {ty} value {value:?} in <{element}>")]
    InvalidValue {
        element: String,
        /// Expected type.
        ty: &'static str,
        /// Raw text.
        value: String,
    },
}

pub type Result<T, E = DecodeError> = std::result::Result<T, E>;
