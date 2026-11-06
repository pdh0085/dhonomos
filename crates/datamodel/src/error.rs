//! Data model load errors.

/// Error of a BBF data model document load.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Input not well-formed XML.
    #[error("XML error at byte {position}: {source}")]
    Xml {
        /// Byte offset of the error in the input.
        position: u64,
        #[source]
        source: quick_xml::Error,
    },

    /// Root element != DM `<document>`.
    #[error("root element is <{0}>, expected <document>")]
    NotADocument(String),

    /// No `<model>` element.
    #[error("document contains no <model>")]
    MissingModel,

    /// `<import>` used -> unsupported, only self-contained `-full` files.
    #[error("<import> of {0:?} is not supported; load the -full variant of the model")]
    UnsupportedImport(String),

    /// Required attribute missing.
    #[error("<{element}> in {context} is missing attribute {attribute:?}")]
    MissingAttribute {
        element: &'static str,
        attribute: &'static str,
        /// Where: object path, data type name, ...
        context: String,
    },

    /// Attribute value not parseable.
    #[error("invalid {attribute:?} value {value:?} in {context}")]
    InvalidAttribute {
        attribute: &'static str,
        /// Raw value.
        value: String,
        /// Where the element is.
        context: String,
    },

    /// Syntax or data type -> reference to undefined data type.
    #[error("unknown data type {name:?} referenced from {context}")]
    UnknownDataType {
        /// Referenced name.
        name: String,
        /// Where the reference is.
        context: String,
    },

    /// Cycle in data type `base` references.
    #[error("data type {0:?} has a cyclic base chain")]
    DataTypeCycle(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
