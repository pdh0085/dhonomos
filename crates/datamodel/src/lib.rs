//! TR-106 DM XML loader + type system + path expressions.
//!
//! Self-contained BBF DM docs (`-full.xml`, e.g. `tr-181-2-21-0-usp-full.xml`)
//! -> [`DataModel`]: query by template path, validate values.
//!
//! ```no_run
//! let xml = std::fs::read_to_string("schemas/tr-181-2-21-0-usp-full.xml")?;
//! let dm = dhonomos_datamodel::DataModel::from_xml(&xml)?;
//! let (_, serial) = dm.parameter("Device.DeviceInfo.SerialNumber").unwrap();
//! assert_eq!(dm.resolve(&serial.syntax)?.base, dhonomos_datamodel::BaseType::String);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod error;
mod model;
mod parse;
mod path;
mod syntax;
mod value;
mod version;
mod xml;

pub use error::{Error, Result};
pub use model::{
    Access, ActiveNotify, ArgumentObject, Arguments, Checked, Command, DataModel, Event, Item,
    MaxEntries, Object, Parameter, Profile, ProfileObject, Requirement, UniqueKey, Variant,
};
pub use path::{Expr, Op, Path, PathError, RefIndex, RelStep, Segment, Target};
pub use syntax::{
    BaseType, DataType, DefaultKind, DefaultValue, Enumeration, EnumerationRef, Facets, ListFacet,
    PathRef, Range, ResolvedType, Size, Status, Syntax, TypeRef,
};
pub use value::ValueError;
pub use version::{ParseVersionError, Version};
