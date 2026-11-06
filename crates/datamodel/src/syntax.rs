//! Parameter syntax: primitive types, facets, named data types (TR-106).

use crate::version::Version;

/// TR-106 primitive types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BaseType {
    /// `string`
    String,
    /// `int` (32-bit signed)
    Int,
    /// `unsignedInt` (32-bit unsigned)
    UnsignedInt,
    /// `long` (64-bit signed)
    Long,
    /// `unsignedLong` (64-bit unsigned)
    UnsignedLong,
    /// `boolean`
    Boolean,
    /// `dateTime`
    DateTime,
    /// `base64`
    Base64,
    /// `hexBinary`
    HexBinary,
    /// `decimal`
    Decimal,
}

impl BaseType {
    /// From XML element name, e.g. `unsignedInt`.
    pub fn from_element(name: &str) -> Option<Self> {
        Some(match name {
            "string" => Self::String,
            "int" => Self::Int,
            "unsignedInt" => Self::UnsignedInt,
            "long" => Self::Long,
            "unsignedLong" => Self::UnsignedLong,
            "boolean" => Self::Boolean,
            "dateTime" => Self::DateTime,
            "base64" => Self::Base64,
            "hexBinary" => Self::HexBinary,
            "decimal" => Self::Decimal,
            _ => return None,
        })
    }

    /// XML element / CWMP `xsd:` type name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Int => "int",
            Self::UnsignedInt => "unsignedInt",
            Self::Long => "long",
            Self::UnsignedLong => "unsignedLong",
            Self::Boolean => "boolean",
            Self::DateTime => "dateTime",
            Self::Base64 => "base64",
            Self::HexBinary => "hexBinary",
            Self::Decimal => "decimal",
        }
    }
}

/// Item status. Absent in XML = current.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Status {
    #[default]
    Current,
    /// Defined, should not be used.
    Deprecated,
    /// Only for backward compatibility.
    Obsoleted,
    /// Removed; still in the XML for history.
    Deleted,
}

impl Status {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "current" => Self::Current,
            "deprecated" => Self::Deprecated,
            "obsoleted" => Self::Obsoleted,
            "deleted" => Self::Deleted,
            _ => return None,
        })
    }
}

/// Length constraint, string / binary (`<size>`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Size {
    pub min: Option<u64>,
    pub max: Option<u64>,
}

/// Numeric range (`<range>`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Range {
    /// Inclusive.
    pub min: Option<i128>,
    /// Inclusive.
    pub max: Option<i128>,
    /// Step between valid values.
    pub step: Option<u64>,
}

/// One allowed value of an enumerated string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enumeration {
    pub value: String,
    /// Optional for implementations.
    pub optional: bool,
    /// Read-only: ACS/Controller cannot set it.
    pub read_only: bool,
    pub status: Status,
    /// Version that added the value.
    pub version: Option<Version>,
}

/// String holds a path to another object (`<pathRef>`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathRef {
    /// `strong` reference, else `weak`.
    pub strong: bool,
    /// Allowed parent object paths.
    pub target_parents: Vec<String>,
    /// `any`, `parameter`, `object`, `single` or `row`.
    pub target_type: Option<String>,
}

/// Value = one of another parameter's values (`<enumerationRef>`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnumerationRef {
    /// Path of the parameter with the values.
    pub target_param: String,
    /// Value for "none".
    pub null_value: Option<String>,
}

/// Facets restricting a primitive type.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facets {
    /// Length constraints, any one must match.
    pub sizes: Vec<Size>,
    /// Any one must match.
    pub ranges: Vec<Range>,
    /// Allowed values.
    pub enumerations: Vec<Enumeration>,
    /// Regexes, any one must match.
    pub patterns: Vec<String>,
    pub path_ref: Option<PathRef>,
    pub enumeration_ref: Option<EnumerationRef>,
    /// Unit of measure.
    pub units: Option<String>,
}

impl Facets {
    /// Apply `other` on top of `self`: non-empty facet of `other` replaces the one of `self`.
    /// -> derived type can narrow its base.
    pub(crate) fn overlay(&mut self, other: &Facets) {
        if !other.sizes.is_empty() {
            self.sizes.clone_from(&other.sizes);
        }
        if !other.ranges.is_empty() {
            self.ranges.clone_from(&other.ranges);
        }
        if !other.enumerations.is_empty() {
            self.enumerations.clone_from(&other.enumerations);
        }
        if !other.patterns.is_empty() {
            self.patterns.clone_from(&other.patterns);
        }
        if other.path_ref.is_some() {
            self.path_ref.clone_from(&other.path_ref);
        }
        if other.enumeration_ref.is_some() {
            self.enumeration_ref.clone_from(&other.enumeration_ref);
        }
        if other.units.is_some() {
            self.units.clone_from(&other.units);
        }
    }
}

/// Value = comma-separated list (`<list>`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListFacet {
    pub min_items: Option<u64>,
    pub max_items: Option<u64>,
    /// Length of the whole list string.
    pub size: Option<Size>,
}

/// Source of the type of a syntax or data type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeRef {
    Base(BaseType),
    /// Named data type of the document.
    Named(String),
}

/// Named data type (`<dataType>`), e.g. `IPAddress`, `StatsCounter64`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataType {
    pub name: String,
    /// Derives from this.
    pub base: TypeRef,
    /// Set if the type is a list.
    pub list: Option<ListFacet>,
    pub facets: Facets,
    pub description: String,
}

/// Kind of a default value (`<default type=...>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DefaultKind {
    /// After factory reset.
    Factory,
    /// On object instance creation.
    Object,
    /// Implementation-defined.
    Implementation,
    /// Default of a command/event argument.
    Parameter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultValue {
    pub kind: DefaultKind,
    /// As in the XML.
    pub value: String,
}

/// Parameter syntax (`<syntax>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Syntax {
    /// Primitive or named type.
    pub ty: TypeRef,
    /// Set if the value is a list.
    pub list: Option<ListFacet>,
    /// Declared directly on the parameter.
    pub facets: Facets,
    pub defaults: Vec<DefaultValue>,
    /// Secret value -> reads return empty string (`secured`, formerly `hidden`).
    pub secured: bool,
    /// Set -> triggers an action (`command="true"`).
    pub command: bool,
}

/// Syntax with its named data type chain flattened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedType {
    /// Underlying primitive type.
    pub base: BaseType,
    /// Most derived named data type, if any.
    pub data_type: Option<String>,
    /// Effective list facet.
    pub list: Option<ListFacet>,
    /// Effective facets: chain applied from primitive up to parameter.
    pub facets: Facets,
}
