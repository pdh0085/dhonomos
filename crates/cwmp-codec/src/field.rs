//! Field (de)serialization for RPC and struct definitions.
//!
//! Decode lenient: missing element -> default, array wrapper -> any item element name,
//! boolean -> `1`/`0`/`true`/`false` in any case.
//! Encode strict, per TR-069 schema.

use crate::error::{DecodeError, Result};
use crate::xml::{Element, Writer};

/// Value = content of one named element.
pub(crate) trait Field: Sized + Default {
    /// Absent element -> default.
    fn read(el: Option<&Element>) -> Result<Self>;
    /// Encode as `<name>...</name>`.
    fn write(&self, w: &mut Writer, name: &str);
}

/// Item of a SOAP-encoded array.
pub(crate) trait ArrayItem: Field {
    /// Element name per item, e.g. `ParameterValueStruct`, `string`.
    const ITEM: &'static str;
    /// Qualified type in `soap-enc:arrayType`, e.g. `cwmp:ParameterValueStruct`.
    const TYPE: &'static str;
}

fn invalid(el: &Element, ty: &'static str) -> DecodeError {
    DecodeError::InvalidValue {
        element: el.name.clone(),
        ty,
        value: el.text.clone(),
    }
}

impl Field for String {
    fn read(el: Option<&Element>) -> Result<Self> {
        Ok(el.map(|e| e.text.trim().to_owned()).unwrap_or_default())
    }
    fn write(&self, w: &mut Writer, name: &str) {
        w.leaf(name, &[], self);
    }
}

impl ArrayItem for String {
    const ITEM: &'static str = "string";
    const TYPE: &'static str = "xsd:string";
}

macro_rules! numeric_field {
    ($($t:ty => $name:literal),*) => {$(
        impl Field for $t {
            fn read(el: Option<&Element>) -> Result<Self> {
                match el.map(|e| (e, e.text.trim())) {
                    None | Some((_, "")) => Ok(0),
                    Some((e, t)) => t.parse().map_err(|_| invalid(e, $name)),
                }
            }
            fn write(&self, w: &mut Writer, name: &str) {
                w.leaf(name, &[], &self.to_string());
            }
        }
    )*};
}
numeric_field!(u32 => "unsignedInt", i32 => "int");

impl Field for bool {
    fn read(el: Option<&Element>) -> Result<Self> {
        let Some(e) = el else { return Ok(false) };
        match e.text.trim().to_ascii_lowercase().as_str() {
            "" | "0" | "false" => Ok(false),
            "1" | "true" => Ok(true),
            _ => Err(invalid(e, "boolean")),
        }
    }
    fn write(&self, w: &mut Writer, name: &str) {
        w.leaf(name, &[], if *self { "1" } else { "0" });
    }
}

impl<T: Field> Field for Option<T> {
    fn read(el: Option<&Element>) -> Result<Self> {
        el.map(|e| T::read(Some(e))).transpose()
    }
    fn write(&self, w: &mut Writer, name: &str) {
        if let Some(v) = self {
            v.write(w, name);
        }
    }
}

/// SOAP-encoded array: `<Name soap-enc:arrayType="T[n]"><Item/>...</Name>`.
impl<T: ArrayItem> Field for Vec<T> {
    fn read(el: Option<&Element>) -> Result<Self> {
        el.map_or(Ok(Vec::new()), |e| {
            e.children.iter().map(|c| T::read(Some(c))).collect()
        })
    }
    fn write(&self, w: &mut Writer, name: &str) {
        let ty = format!("{}[{}]", T::TYPE, self.len());
        w.open(name, &[("soap-enc:arrayType", &ty)]);
        for item in self {
            item.write(w, T::ITEM);
        }
        w.close(name);
    }
}

/// Field repeated directly in its parent (`maxOccurs="unbounded"`).
/// Also accepts common non-conforming form: items wrapped in one array element.
pub(crate) fn read_repeated<T: ArrayItem>(parent: &Element, name: &str) -> Result<Vec<T>> {
    let mut els: Vec<&Element> = parent.children_named(name).collect();
    if let [single] = els.as_slice()
        && single
            .children
            .iter()
            .any(|c| c.name.eq_ignore_ascii_case(T::ITEM))
    {
        els = single.children.iter().collect();
    }
    els.into_iter().map(|e| T::read(Some(e))).collect()
}

pub(crate) fn write_repeated<T: Field>(items: &[T], w: &mut Writer, name: &str) {
    for item in items {
        item.write(w, name);
    }
}

/// CWMP struct: pub fields, lenient decode, strict encode.
///
/// `"XmlName" => field: Type` -> one element.
/// `"XmlName" as repeated => field: Vec<Type>` -> element repeated directly in the parent.
/// `as "Item"` -> struct usable as SOAP array item (`cwmp:Item`).
macro_rules! cwmp_struct {
    (
        $(#[$meta:meta])*
        pub struct $name:ident $(as $item:literal)? {
            $(
                $(#[$fmeta:meta])*
                $xml:literal $(as $rep:ident)? => $field:ident : $ty:ty
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct $name {
            $( $(#[$fmeta])* pub $field: $ty, )*
        }

        impl $name {
            #[allow(unused_variables)]
            pub(crate) fn decode_fields(el: &$crate::xml::Element) -> $crate::error::Result<Self> {
                Ok(Self {
                    $( $field: cwmp_struct!(@read el, $xml $(, $rep)?), )*
                })
            }

            #[allow(unused_variables)]
            pub(crate) fn encode_fields(&self, w: &mut $crate::xml::Writer) {
                $( cwmp_struct!(@write self.$field, w, $xml $(, $rep)?); )*
            }
        }

        impl $crate::field::Field for $name {
            fn read(el: Option<&$crate::xml::Element>) -> $crate::error::Result<Self> {
                el.map_or_else(|| Ok(Self::default()), Self::decode_fields)
            }
            fn write(&self, w: &mut $crate::xml::Writer, name: &str) {
                w.open(name, &[]);
                self.encode_fields(w);
                w.close(name);
            }
        }

        $(
            impl $crate::field::ArrayItem for $name {
                const ITEM: &'static str = $item;
                const TYPE: &'static str = concat!("cwmp:", $item);
            }
        )?
    };

    (@read $el:ident, $xml:literal) => {
        $crate::field::Field::read($el.child($xml))?
    };
    (@read $el:ident, $xml:literal, repeated) => {
        $crate::field::read_repeated($el, $xml)?
    };
    (@write $v:expr, $w:ident, $xml:literal) => {
        $crate::field::Field::write(&$v, $w, $xml)
    };
    (@write $v:expr, $w:ident, $xml:literal, repeated) => {
        $crate::field::write_repeated(&$v, $w, $xml)
    };
}

pub(crate) use cwmp_struct;
