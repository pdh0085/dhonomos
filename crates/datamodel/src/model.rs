//! Loaded data model: objects, parameters, commands, events and profiles.

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::path::{Path, Segment, Target};
use crate::syntax::{DataType, ResolvedType, Status, Syntax, TypeRef};
use crate::value::{self, Patterns, ValueError};
use crate::version::Version;

/// Protocol variant of a DM document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Variant {
    /// `-cwmp` docs (TR-069).
    Cwmp,
    /// `-usp` docs (TR-369) -> also commands + events.
    Usp,
    /// No protocol suffix (e.g. TR-098).
    Common,
}

/// Write access of object or parameter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Access {
    #[default]
    ReadOnly,
    /// Read + write. Objects -> instances can be added + deleted.
    ReadWrite,
    /// Writable only at instance creation.
    WriteOnceReadOnly,
}

/// Max instances of an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxEntries {
    Bounded(u32),
    Unbounded,
}

/// Unique key of a multi-instance object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniqueKey {
    /// Functional -> unique among enabled instances only.
    /// Non-functional (e.g. `Alias`) -> must be unique among all instances.
    pub functional: bool,
    /// Parameter names.
    pub parameters: Vec<String>,
}

/// Active notification capability of a parameter (CWMP).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ActiveNotify {
    /// Notification: any value allowed.
    #[default]
    Normal,
    /// Active notification always on, cannot be turned off.
    ForceEnabled,
    /// Active notification on by default, can be turned off.
    ForceDefaultEnabled,
    /// CPE may reject a request to enable active notification.
    CanDeny,
}

/// Parameter definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameter {
    /// Name without object path.
    pub name: String,
    pub access: Access,
    pub syntax: Syntax,
    /// Version added. `None` = same as its object.
    pub version: Option<Version>,
    pub status: Status,
    /// Always in CWMP Inform.
    pub forced_inform: bool,
    pub active_notify: ActiveNotify,
    /// Command/event argument must be given.
    pub mandatory: bool,
    pub description: String,
}

/// Object inside a command/event argument list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentObject {
    /// Relative path, e.g. `Result.{i}.`.
    pub name: String,
    pub min_entries: u32,
    pub max_entries: MaxEntries,
    pub parameters: Vec<Parameter>,
}

/// Command input/output arguments, or event arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Arguments {
    pub parameters: Vec<Parameter>,
    pub objects: Vec<ArgumentObject>,
}

/// USP command, e.g. `Reboot()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// Name incl. `()`.
    pub name: String,
    pub is_async: bool,
    pub input: Arguments,
    pub output: Arguments,
    /// Version added.
    pub version: Option<Version>,
    pub status: Status,
    pub description: String,
}

/// USP event, e.g. `Boot!`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Name incl. `!`.
    pub name: String,
    pub arguments: Arguments,
    /// Version added.
    pub version: Option<Version>,
    pub status: Status,
    pub description: String,
}

/// Object definition. Multi-instance -> path ends in `{i}.`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    /// Full path with `{i}` placeholders, e.g. `Device.WiFi.Radio.{i}.`.
    pub path: String,
    /// `ReadWrite` -> instances can be added/deleted.
    pub access: Access,
    pub min_entries: u32,
    pub max_entries: MaxEntries,
    /// Version added.
    pub version: Option<Version>,
    pub status: Status,
    pub unique_keys: Vec<UniqueKey>,
    /// Parameter (name) that enables an instance.
    pub enable_parameter: Option<String>,
    /// Path of the `...NumberOfEntries` parameter = instance count.
    pub num_entries_parameter: Option<String>,
    /// USP mount type (`mountable` / `mountPoint`).
    pub mount_type: Option<String>,
    pub description: String,
    pub parameters: Vec<Parameter>,
    /// USP only.
    pub commands: Vec<Command>,
    /// USP only.
    pub events: Vec<Event>,
}

impl Object {
    pub fn is_multi_instance(&self) -> bool {
        self.path.ends_with(".{i}.")
    }

    pub fn parameter(&self, name: &str) -> Option<&Parameter> {
        self.parameters.iter().find(|p| p.name == name)
    }

    /// `name` incl. `()`.
    pub fn command(&self, name: &str) -> Option<&Command> {
        self.commands.iter().find(|c| c.name == name)
    }

    /// `name` incl. `!`.
    pub fn event(&self, name: &str) -> Option<&Event> {
        self.events.iter().find(|e| e.name == name)
    }
}

/// Requirement level of a profile item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Requirement {
    /// Must be present (objects).
    Present,
    /// Must be readable.
    ReadOnly,
    /// Must be writable. Also `writeOnceReadOnly`.
    ReadWrite,
    /// Objects: instances must be creatable.
    Create,
    /// Objects: instances must be deletable.
    Delete,
    /// Objects: instances must be creatable + deletable.
    CreateDelete,
    /// Not required (`notSpecified`).
    NotSpecified,
}

impl Requirement {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "present" => Self::Present,
            "readOnly" => Self::ReadOnly,
            "readWrite" | "writeOnceReadOnly" => Self::ReadWrite,
            "create" => Self::Create,
            "delete" => Self::Delete,
            "createDelete" => Self::CreateDelete,
            "notSpecified" => Self::NotSpecified,
            _ => return None,
        })
    }
}

/// Object entry of a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileObject {
    pub path: String,
    pub requirement: Requirement,
    /// Required parameters + their level.
    pub parameters: Vec<(String, Requirement)>,
    pub commands: Vec<String>,
    pub events: Vec<String>,
}

/// Profile: named set of requirements, e.g. `Baseline:3`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// Name with version, e.g. `Baseline:3`.
    pub name: String,
    /// Profile this one is a newer version of.
    pub base: Option<String>,
    pub extends: Vec<String>,
    /// Version added.
    pub version: Option<Version>,
    pub status: Status,
    pub objects: Vec<ProfileObject>,
}

/// DM item found by [`DataModel::lookup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item<'a> {
    Object(&'a Object),
    Parameter(&'a Object, &'a Parameter),
    Command(&'a Object, &'a Command),
    Event(&'a Object, &'a Event),
}

/// Result of [`DataModel::check_parameter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checked {
    /// Value fits the parameter type. Holds the normalized value.
    Valid(String),
    /// Parameter not in this model -> value not checked (DM-06).
    /// Devices may have vendor extensions or newer model versions.
    NotInModel {
        /// Path has a vendor-specific name (`X_...`).
        vendor_extension: bool,
    },
}

/// Loaded data model (one `<model>` of a `-full` DM document).
#[derive(Debug, Clone)]
pub struct DataModel {
    pub(crate) spec: String,
    pub(crate) variant: Variant,
    pub(crate) root: String,
    pub(crate) version: Version,
    pub(crate) data_types: HashMap<String, DataType>,
    pub(crate) objects: Vec<Object>,
    pub(crate) object_index: HashMap<String, usize>,
    pub(crate) profiles: Vec<Profile>,
    pub(crate) patterns: Patterns,
}

impl DataModel {
    /// Load a self-contained (`-full`) DM XML document.
    pub fn from_xml(input: &str) -> Result<Self> {
        crate::parse::load(input)
    }

    /// Document spec URN, e.g. `urn:broadband-forum-org:tr-181-2-21-0-usp`.
    pub fn spec(&self) -> &str {
        &self.spec
    }

    pub fn variant(&self) -> Variant {
        self.variant
    }

    /// Root object name, e.g. `Device` or `InternetGatewayDevice`.
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Model version, e.g. `2.21`.
    pub fn version(&self) -> Version {
        self.version
    }

    /// All objects, document order.
    pub fn objects(&self) -> &[Object] {
        &self.objects
    }

    /// By template path, e.g. `Device.WiFi.Radio.{i}.`.
    pub fn object(&self, path: &str) -> Option<&Object> {
        self.object_index.get(path).map(|&i| &self.objects[i])
    }

    /// By full template path, e.g. `Device.DeviceInfo.SerialNumber`.
    pub fn parameter(&self, path: &str) -> Option<(&Object, &Parameter)> {
        let (obj, name) = split_item(path)?;
        let o = self.object(obj)?;
        Some((o, o.parameter(name)?))
    }

    /// By full template path, e.g. `Device.Reboot()`.
    pub fn command(&self, path: &str) -> Option<(&Object, &Command)> {
        let (obj, name) = split_item(path)?;
        let o = self.object(obj)?;
        Some((o, o.command(name)?))
    }

    /// By full template path, e.g. `Device.Boot!`.
    pub fn event(&self, path: &str) -> Option<(&Object, &Event)> {
        let (obj, name) = split_item(path)?;
        let o = self.object(obj)?;
        Some((o, o.event(name)?))
    }

    /// Definition of a concrete or wildcard path, e.g.
    /// `Device.WiFi.Radio.1.Channel` or `Device.IP.Interface.[Name=="wan"].`.
    ///
    /// Instance selector only after a multi-instance object (lookup via `{i}` template).
    /// Path that follows a reference (`+`) -> `None`: needs instance data.
    pub fn lookup(&self, path: &Path) -> Option<Item<'_>> {
        let template = path.template()?;
        match path.target {
            Target::Object => self.object(&template).map(Item::Object),
            Target::Parameter => self
                .parameter(&template)
                .map(|(o, p)| Item::Parameter(o, p)),
            Target::Command => self.command(&template).map(|(o, c)| Item::Command(o, c)),
            Target::Event => self.event(&template).map(|(o, e)| Item::Event(o, e)),
        }
    }

    /// Version an item was added: own `version`, else its object's.
    /// `None` -> model has no version info (e.g. TR-098).
    pub fn introduced_in(&self, item: Item<'_>) -> Option<Version> {
        match item {
            Item::Object(o) => o.version,
            Item::Parameter(o, p) => p.version.or(o.version),
            Item::Command(o, c) => c.version.or(o.version),
            Item::Event(o, e) => e.version.or(o.version),
        }
    }

    /// Like [`lookup`](Self::lookup), only items present in model `version`.
    /// `version` e.g. from the supported data models a device reports.
    pub fn lookup_in_version(&self, path: &Path, version: Version) -> Option<Item<'_>> {
        let item = self.lookup(path)?;
        self.introduced_in(item)
            .is_none_or(|v| v <= version)
            .then_some(item)
    }

    pub fn data_type(&self, name: &str) -> Option<&DataType> {
        self.data_types.get(name)
    }

    /// All named data types, no order.
    pub fn data_types(&self) -> impl Iterator<Item = &DataType> {
        self.data_types.values()
    }

    /// Profiles, document order.
    pub fn profiles(&self) -> &[Profile] {
        &self.profiles
    }

    /// Flatten a syntax through its named data type chain.
    ///
    /// Facets applied from primitive type up to the parameter.
    /// Non-empty facet at a more derived level -> replaces the base one.
    pub fn resolve(&self, syntax: &Syntax) -> Result<ResolvedType> {
        let mut chain: Vec<&DataType> = Vec::new();
        let mut next = &syntax.ty;
        let base = loop {
            match next {
                TypeRef::Base(b) => break *b,
                TypeRef::Named(name) => {
                    let dt = self
                        .data_types
                        .get(name)
                        .ok_or_else(|| Error::UnknownDataType {
                            name: name.clone(),
                            context: "syntax".into(),
                        })?;
                    if chain.len() > self.data_types.len() {
                        return Err(Error::DataTypeCycle(name.clone()));
                    }
                    chain.push(dt);
                    next = &dt.base;
                }
            }
        };
        let mut resolved = ResolvedType {
            base,
            data_type: chain.first().map(|d| d.name.clone()),
            list: None,
            facets: Default::default(),
        };
        for dt in chain.iter().rev() {
            resolved.facets.overlay(&dt.facets);
            if dt.list.is_some() {
                resolved.list = dt.list;
            }
        }
        resolved.facets.overlay(&syntax.facets);
        if syntax.list.is_some() {
            resolved.list = syntax.list;
        }
        Ok(resolved)
    }
}

impl DataModel {
    /// Validate a value against a syntax -> normalized form.
    pub fn check_value(&self, syntax: &Syntax, value: &str) -> Result<String, ValueError> {
        match self.resolve(syntax) {
            Ok(ty) => value::check(&ty, &self.patterns, value),
            // Unreachable for loaded models: type refs checked at load time.
            Err(_) => Ok(value.to_owned()),
        }
    }

    /// Validate a value for the parameter at `path` (concrete or template).
    ///
    /// Parameter not in model -> [`Checked::NotInModel`], not an error.
    pub fn check_parameter(&self, path: &Path, value: &str) -> Result<Checked, ValueError> {
        match self.lookup(path) {
            Some(Item::Parameter(_, p)) => self.check_value(&p.syntax, value).map(Checked::Valid),
            _ => Ok(Checked::NotInModel {
                vendor_extension: path
                    .segments
                    .iter()
                    .any(|s| matches!(s, Segment::Name(step) if step.name.starts_with("X_"))),
            }),
        }
    }

    /// `<pattern>` values the regex engine cannot compile -> not enforced.
    pub fn unsupported_patterns(&self) -> impl Iterator<Item = &str> {
        self.patterns.failed()
    }
}

/// `Device.DeviceInfo.SerialNumber` -> (`Device.DeviceInfo.`, `SerialNumber`).
fn split_item(path: &str) -> Option<(&str, &str)> {
    let idx = path.rfind('.')?;
    let (obj, name) = path.split_at(idx + 1);
    (!name.is_empty()).then_some((obj, name))
}
