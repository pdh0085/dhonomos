//! XML tree -> [`DataModel`].

use std::collections::HashMap;
use std::str::FromStr;

use crate::error::{Error, Result};
use crate::model::{
    Access, ActiveNotify, ArgumentObject, Arguments, Command, DataModel, Event, MaxEntries, Object,
    Parameter, Profile, ProfileObject, Requirement, UniqueKey, Variant,
};
use crate::syntax::{
    BaseType, DataType, DefaultKind, DefaultValue, Enumeration, EnumerationRef, Facets, ListFacet,
    PathRef, Range, Size, Status, Syntax, TypeRef,
};
use crate::value::Patterns;
use crate::version::Version;
use crate::xml::{self, Element};

pub(crate) fn load(input: &str) -> Result<DataModel> {
    let root = xml::parse(input)?;
    if root.name != "document" {
        return Err(Error::NotADocument(root.name));
    }
    if let Some(imp) = root.child("import") {
        return Err(Error::UnsupportedImport(
            imp.attr("file").unwrap_or_default().to_owned(),
        ));
    }

    let spec = root.attr("spec").unwrap_or_default().to_owned();
    let variant = if spec.ends_with("-usp") {
        Variant::Usp
    } else if spec.ends_with("-cwmp") {
        Variant::Cwmp
    } else {
        Variant::Common
    };

    let mut data_types = HashMap::new();
    for dt in root.children_named("dataType") {
        let dt = data_type(dt)?;
        data_types.insert(dt.name.clone(), dt);
    }

    let model = root.child("model").ok_or(Error::MissingModel)?;
    let model_name = req(model, "model", "name", "document")?;
    let (root_name, version) = model_name
        .split_once(':')
        .and_then(|(n, v)| Some((n.to_owned(), v.parse().ok()?)))
        .ok_or_else(|| invalid("name", model_name, "<model>"))?;

    let mut objects = Vec::new();
    let mut profiles = Vec::new();
    for child in &model.children {
        match child.name.as_str() {
            "object" => objects.push(object(child)?),
            "profile" => profiles.push(profile(child)?),
            _ => {}
        }
    }
    let object_index = objects
        .iter()
        .enumerate()
        .map(|(i, o)| (o.path.clone(), i))
        .collect();

    let mut patterns = Patterns::default();
    let mut add = |f: &Facets| f.patterns.iter().for_each(|p| patterns.add(p));
    data_types.values().for_each(|d| add(&d.facets));
    for o in &objects {
        let args = o
            .commands
            .iter()
            .flat_map(|c| [&c.input, &c.output])
            .chain(o.events.iter().map(|e| &e.arguments));
        let arg_params = args.flat_map(|a| {
            a.parameters
                .iter()
                .chain(a.objects.iter().flat_map(|ao| &ao.parameters))
        });
        o.parameters
            .iter()
            .chain(arg_params)
            .for_each(|p| add(&p.syntax.facets));
    }

    let dm = DataModel {
        spec,
        variant,
        root: root_name,
        version,
        data_types,
        objects,
        object_index,
        profiles,
        patterns,
    };
    validate_type_refs(&dm)?;
    let mut dm = dm;
    unbracket_list_defaults(&mut dm);
    Ok(dm)
}

/// Every named type ref resolves + no base chain is cyclic.
fn validate_type_refs(dm: &DataModel) -> Result<()> {
    for dt in dm.data_types.values() {
        let mut seen = vec![dt.name.as_str()];
        let mut next = &dt.base;
        while let TypeRef::Named(name) = next {
            if seen.contains(&name.as_str()) {
                return Err(Error::DataTypeCycle(dt.name.clone()));
            }
            seen.push(name);
            next = &dm
                .data_types
                .get(name)
                .ok_or_else(|| Error::UnknownDataType {
                    name: name.clone(),
                    context: format!("data type {}", dt.name),
                })?
                .base;
        }
    }
    let check = |p: &Parameter, ctx: &str| match &p.syntax.ty {
        TypeRef::Named(name) if !dm.data_types.contains_key(name) => Err(Error::UnknownDataType {
            name: name.clone(),
            context: format!("{ctx}{}", p.name),
        }),
        _ => Ok(()),
    };
    for o in &dm.objects {
        for p in &o.parameters {
            check(p, &o.path)?;
        }
    }
    Ok(())
}

/// DM XML list default = `[a,b]` -> store in wire format (`a,b`).
fn unbracket_list_defaults(dm: &mut DataModel) {
    let is_list: Vec<Vec<bool>> = dm
        .objects
        .iter()
        .map(|o| {
            o.parameters
                .iter()
                .map(|p| dm.resolve(&p.syntax).is_ok_and(|t| t.list.is_some()))
                .collect()
        })
        .collect();
    for (o, flags) in dm.objects.iter_mut().zip(is_list) {
        for (p, list) in o.parameters.iter_mut().zip(flags) {
            if !list {
                continue;
            }
            for d in &mut p.syntax.defaults {
                if let Some(inner) = d.value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
                    d.value = inner.to_owned();
                }
            }
        }
    }
}

// ---- helpers ---------------------------------------------------------------

fn invalid(attribute: &'static str, value: &str, context: &str) -> Error {
    Error::InvalidAttribute {
        attribute,
        value: value.to_owned(),
        context: context.to_owned(),
    }
}

fn req<'a>(
    el: &'a Element,
    element: &'static str,
    attribute: &'static str,
    context: &str,
) -> Result<&'a str> {
    el.attr(attribute).ok_or_else(|| Error::MissingAttribute {
        element,
        attribute,
        context: context.to_owned(),
    })
}

fn opt_parse<T: FromStr>(el: &Element, attribute: &'static str, ctx: &str) -> Result<Option<T>> {
    el.attr(attribute)
        .map(|v| v.trim().parse().map_err(|_| invalid(attribute, v, ctx)))
        .transpose()
}

fn bool_attr(el: &Element, attribute: &'static str, ctx: &str) -> Result<bool> {
    match el.attr(attribute) {
        None | Some("false") | Some("0") => Ok(false),
        Some("true") | Some("1") => Ok(true),
        Some(v) => Err(invalid(attribute, v, ctx)),
    }
}

fn status(el: &Element, ctx: &str) -> Result<Status> {
    el.attr("status").map_or(Ok(Status::Current), |v| {
        Status::parse(v).ok_or_else(|| invalid("status", v, ctx))
    })
}

fn access(el: &Element, ctx: &str) -> Result<Access> {
    Ok(match el.attr("access") {
        None | Some("readOnly") => Access::ReadOnly,
        Some("readWrite") => Access::ReadWrite,
        Some("writeOnceReadOnly") => Access::WriteOnceReadOnly,
        Some(v) => return Err(invalid("access", v, ctx)),
    })
}

fn max_entries(el: &Element, ctx: &str) -> Result<MaxEntries> {
    Ok(match el.attr("maxEntries") {
        None => MaxEntries::Bounded(1),
        Some("unbounded") => MaxEntries::Unbounded,
        Some(v) => MaxEntries::Bounded(v.parse().map_err(|_| invalid("maxEntries", v, ctx))?),
    })
}

/// Description text, outer whitespace + common indent removed.
fn description(el: &Element) -> String {
    let Some(d) = el.child("description") else {
        return String::new();
    };
    let lines: Vec<&str> = d.text.trim_matches('\n').lines().collect();
    let indent = lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);
    lines
        .iter()
        .map(|l| l.get(indent..).unwrap_or("").trim_end())
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_owned()
}

// ---- syntax ----------------------------------------------------------------

fn facets_into(f: &mut Facets, el: &Element, ctx: &str) -> Result<()> {
    for c in &el.children {
        match c.name.as_str() {
            "size" => f.sizes.push(Size {
                min: opt_parse(c, "minLength", ctx)?,
                max: opt_parse(c, "maxLength", ctx)?,
            }),
            "range" => f.ranges.push(Range {
                min: opt_parse(c, "minInclusive", ctx)?,
                max: opt_parse(c, "maxInclusive", ctx)?,
                step: opt_parse(c, "step", ctx)?,
            }),
            "enumeration" => f.enumerations.push(Enumeration {
                value: req(c, "enumeration", "value", ctx)?.to_owned(),
                optional: bool_attr(c, "optional", ctx)?,
                read_only: c.attr("access") == Some("readOnly"),
                status: status(c, ctx)?,
                version: opt_parse(c, "version", ctx)?,
            }),
            "pattern" => f.patterns.push(req(c, "pattern", "value", ctx)?.to_owned()),
            "pathRef" => {
                f.path_ref = Some(PathRef {
                    strong: c.attr("refType") == Some("strong"),
                    target_parents: c
                        .attr("targetParent")
                        .map(|v| v.split_whitespace().map(str::to_owned).collect())
                        .unwrap_or_default(),
                    target_type: c.attr("targetType").map(str::to_owned),
                })
            }
            "enumerationRef" => {
                f.enumeration_ref = Some(EnumerationRef {
                    target_param: req(c, "enumerationRef", "targetParam", ctx)?.to_owned(),
                    null_value: c.attr("nullValue").map(str::to_owned),
                })
            }
            "units" => f.units = c.attr("value").map(str::to_owned),
            _ => {}
        }
    }
    Ok(())
}

fn list_facet(el: &Element, ctx: &str) -> Result<ListFacet> {
    let size = el
        .child("size")
        .map(|s| -> Result<Size> {
            Ok(Size {
                min: opt_parse(s, "minLength", ctx)?,
                max: opt_parse(s, "maxLength", ctx)?,
            })
        })
        .transpose()?;
    Ok(ListFacet {
        min_items: opt_parse(el, "minItems", ctx)?,
        max_items: opt_parse(el, "maxItems", ctx)?,
        size,
    })
}

fn data_type(el: &Element) -> Result<DataType> {
    let name = req(el, "dataType", "name", "document")?.to_owned();
    let ctx = format!("data type {name}");
    let mut facets = Facets::default();
    let mut list = None;
    let mut base = el.attr("base").map(|b| TypeRef::Named(b.to_owned()));
    for c in &el.children {
        if let Some(b) = BaseType::from_element(&c.name) {
            base = Some(TypeRef::Base(b));
            facets_into(&mut facets, c, &ctx)?;
        } else if c.name == "list" {
            list = Some(list_facet(c, &ctx)?);
        }
    }
    // Facets also directly under <dataType> when derived from another type.
    facets_into(&mut facets, el, &ctx)?;
    let base = base.ok_or(Error::MissingAttribute {
        element: "dataType",
        attribute: "base",
        context: ctx,
    })?;
    Ok(DataType {
        description: description(el),
        name,
        base,
        list,
        facets,
    })
}

fn syntax(el: &Element, ctx: &str) -> Result<Syntax> {
    let mut ty = None;
    let mut list = None;
    let mut facets = Facets::default();
    let mut defaults = Vec::new();
    for c in &el.children {
        if let Some(b) = BaseType::from_element(&c.name) {
            ty = Some(TypeRef::Base(b));
            facets_into(&mut facets, c, ctx)?;
            continue;
        }
        match c.name.as_str() {
            "dataType" => {
                let r = c.attr("ref").or_else(|| c.attr("base"));
                ty = Some(TypeRef::Named(
                    r.ok_or_else(|| Error::MissingAttribute {
                        element: "dataType",
                        attribute: "ref",
                        context: ctx.to_owned(),
                    })?
                    .to_owned(),
                ));
                facets_into(&mut facets, c, ctx)?;
            }
            "list" => list = Some(list_facet(c, ctx)?),
            "default" => {
                let kind = match req(c, "default", "type", ctx)? {
                    "factory" => DefaultKind::Factory,
                    "object" => DefaultKind::Object,
                    "implementation" => DefaultKind::Implementation,
                    "parameter" => DefaultKind::Parameter,
                    v => return Err(invalid("type", v, ctx)),
                };
                defaults.push(DefaultValue {
                    kind,
                    value: req(c, "default", "value", ctx)?.to_owned(),
                });
            }
            _ => {}
        }
    }
    Ok(Syntax {
        ty: ty.ok_or_else(|| Error::MissingAttribute {
            element: "syntax",
            attribute: "type element",
            context: ctx.to_owned(),
        })?,
        list,
        facets,
        defaults,
        secured: bool_attr(el, "secured", ctx)? || bool_attr(el, "hidden", ctx)?,
        command: bool_attr(el, "command", ctx)?,
    })
}

// ---- items -----------------------------------------------------------------

fn parameter(el: &Element, obj_ctx: &str) -> Result<Parameter> {
    let name = req(el, "parameter", "name", obj_ctx)?.to_owned();
    let ctx = format!("{obj_ctx}{name}");
    let syntax_el = el.child("syntax").ok_or_else(|| Error::MissingAttribute {
        element: "parameter",
        attribute: "syntax",
        context: ctx.clone(),
    })?;
    let active_notify = match el.attr("activeNotify") {
        None | Some("normal") => ActiveNotify::Normal,
        Some("forceEnabled") => ActiveNotify::ForceEnabled,
        Some("forceDefaultEnabled") => ActiveNotify::ForceDefaultEnabled,
        Some("canDeny") => ActiveNotify::CanDeny,
        Some(v) => return Err(invalid("activeNotify", v, &ctx)),
    };
    Ok(Parameter {
        access: access(el, &ctx)?,
        syntax: syntax(syntax_el, &ctx)?,
        version: opt_parse(el, "version", &ctx)?,
        status: status(el, &ctx)?,
        forced_inform: bool_attr(el, "forcedInform", &ctx)?,
        active_notify,
        mandatory: bool_attr(el, "mandatory", &ctx)?,
        description: description(el),
        name,
    })
}

fn arguments(el: Option<&Element>, ctx: &str) -> Result<Arguments> {
    let mut args = Arguments::default();
    let Some(el) = el else { return Ok(args) };
    for c in &el.children {
        match c.name.as_str() {
            "parameter" => args.parameters.push(parameter(c, ctx)?),
            "object" => {
                let name = req(c, "object", "name", ctx)?.to_owned();
                let octx = format!("{ctx}{name}");
                args.objects.push(ArgumentObject {
                    min_entries: opt_parse(c, "minEntries", &octx)?.unwrap_or(1),
                    max_entries: max_entries(c, &octx)?,
                    parameters: c
                        .children_named("parameter")
                        .map(|p| parameter(p, &octx))
                        .collect::<Result<_>>()?,
                    name,
                });
            }
            _ => {}
        }
    }
    Ok(args)
}

fn command(el: &Element, obj: &str) -> Result<Command> {
    let name = req(el, "command", "name", obj)?.to_owned();
    let ctx = format!("{obj}{name}.");
    Ok(Command {
        is_async: bool_attr(el, "async", &ctx)?,
        input: arguments(el.child("input"), &ctx)?,
        output: arguments(el.child("output"), &ctx)?,
        version: opt_parse(el, "version", &ctx)?,
        status: status(el, &ctx)?,
        description: description(el),
        name,
    })
}

fn event(el: &Element, obj: &str) -> Result<Event> {
    let name = req(el, "event", "name", obj)?.to_owned();
    let ctx = format!("{obj}{name}.");
    Ok(Event {
        arguments: arguments(Some(el), &ctx)?,
        version: opt_parse(el, "version", &ctx)?,
        status: status(el, &ctx)?,
        description: description(el),
        name,
    })
}

fn object(el: &Element) -> Result<Object> {
    let path = req(el, "object", "name", "model")?.to_owned();
    let ctx = path.as_str();
    let mut o = Object {
        access: access(el, ctx)?,
        min_entries: opt_parse(el, "minEntries", ctx)?.unwrap_or(1),
        max_entries: max_entries(el, ctx)?,
        version: opt_parse(el, "version", ctx)?,
        status: status(el, ctx)?,
        unique_keys: Vec::new(),
        enable_parameter: el.attr("enableParameter").map(str::to_owned),
        num_entries_parameter: el.attr("numEntriesParameter").map(str::to_owned),
        mount_type: el.attr("mountType").map(str::to_owned),
        description: description(el),
        parameters: Vec::new(),
        commands: Vec::new(),
        events: Vec::new(),
        path: path.clone(),
    };
    for c in &el.children {
        match c.name.as_str() {
            "parameter" => o.parameters.push(parameter(c, ctx)?),
            "command" => o.commands.push(command(c, ctx)?),
            "event" => o.events.push(event(c, ctx)?),
            "uniqueKey" => o.unique_keys.push(UniqueKey {
                functional: c.attr("functional") != Some("false"),
                parameters: c
                    .children_named("parameter")
                    .map(|p| req(p, "parameter", "ref", ctx).map(str::to_owned))
                    .collect::<Result<_>>()?,
            }),
            _ => {}
        }
    }
    Ok(o)
}

fn requirement(el: &Element, element: &'static str, ctx: &str) -> Result<Requirement> {
    let v = req(el, element, "requirement", ctx)?;
    Requirement::parse(v).ok_or_else(|| invalid("requirement", v, ctx))
}

fn profile(el: &Element) -> Result<Profile> {
    let name = req(el, "profile", "name", "model")?.to_owned();
    let ctx = format!("profile {name}");
    let mut objects = Vec::new();
    for o in el.children_named("object") {
        let path = req(o, "object", "ref", &ctx)?.to_owned();
        let mut po = ProfileObject {
            requirement: requirement(o, "object", &ctx)?,
            parameters: Vec::new(),
            commands: Vec::new(),
            events: Vec::new(),
            path,
        };
        for c in &o.children {
            match c.name.as_str() {
                "parameter" => po.parameters.push((
                    req(c, "parameter", "ref", &ctx)?.to_owned(),
                    requirement(c, "parameter", &ctx)?,
                )),
                "command" => po.commands.push(req(c, "command", "ref", &ctx)?.to_owned()),
                "event" => po.events.push(req(c, "event", "ref", &ctx)?.to_owned()),
                _ => {}
            }
        }
        objects.push(po);
    }
    Ok(Profile {
        base: el.attr("base").map(str::to_owned),
        extends: el
            .attr("extends")
            .map(|v| v.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default(),
        version: opt_parse::<Version>(el, "version", &ctx)?,
        status: status(el, &ctx)?,
        objects,
        name,
    })
}
