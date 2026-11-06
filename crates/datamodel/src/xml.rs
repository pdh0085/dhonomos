//! Minimal owned XML tree: intermediate form for loading DM documents.
//!
//! Namespace prefixes dropped (DM documents: one default namespace per element type).
//! Comments + processing instructions skipped.
//! Text collected per element; predefined + character entities resolved.

use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

use crate::error::{Error, Result};

#[derive(Debug, Default)]
pub(crate) struct Element {
    pub(crate) name: String,
    pub(crate) attrs: Vec<(String, String)>,
    pub(crate) children: Vec<Element>,
    pub(crate) text: String,
}

impl Element {
    pub(crate) fn attr(&self, key: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    pub(crate) fn children_named<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }
}

fn local(name: &str) -> &str {
    name.rsplit_once(':').map_or(name, |(_, l)| l)
}

fn xml_err(reader: &Reader<&[u8]>, source: quick_xml::Error) -> Error {
    Error::Xml {
        position: reader.error_position(),
        source,
    }
}

fn open(reader: &Reader<&[u8]>, e: &BytesStart<'_>) -> Result<Element> {
    let mut el = Element {
        name: local(e.name().as_ref()).to_owned(),
        ..Element::default()
    };
    for a in e.attributes() {
        let a = a.map_err(|err| xml_err(reader, err.into()))?;
        let value = a
            .normalized_value(XmlVersion::default())
            .map_err(|err| xml_err(reader, err))?;
        el.attrs
            .push((local(a.key.as_ref()).to_owned(), value.into_owned()));
    }
    Ok(el)
}

fn predefined_entity(name: &str) -> Option<char> {
    Some(match name {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "apos" => '\'',
        "quot" => '"',
        _ => return None,
    })
}

/// Parse `input` -> root element.
pub(crate) fn parse(input: &str) -> Result<Element> {
    let mut reader = Reader::from_str(input);
    let mut stack: Vec<Element> = Vec::new();

    loop {
        let event = reader.read_event().map_err(|err| xml_err(&reader, err))?;
        match event {
            Event::Start(e) => {
                let el = open(&reader, &e)?;
                stack.push(el);
            }
            Event::Empty(e) => {
                let el = open(&reader, &e)?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(el),
                    None => return Ok(el),
                }
            }
            Event::End(_) => {
                // quick-xml checks end tag = start tag.
                let Some(el) = stack.pop() else { continue };
                match stack.last_mut() {
                    Some(parent) => parent.children.push(el),
                    None => return Ok(el),
                }
            }
            Event::Text(t) => {
                if let Some(cur) = stack.last_mut() {
                    cur.text.push_str(&t.xml_content(XmlVersion::default()));
                }
            }
            Event::CData(t) => {
                if let Some(cur) = stack.last_mut() {
                    cur.text.push_str(&t.into_inner());
                }
            }
            Event::GeneralRef(r) => {
                if let Some(cur) = stack.last_mut() {
                    let resolved = if r.is_char_ref() {
                        r.resolve_char_ref().map_err(|err| xml_err(&reader, err))?
                    } else {
                        predefined_entity(&r.clone().into_inner())
                    };
                    match resolved {
                        Some(c) => cur.text.push(c),
                        // Unknown entity -> keep verbatim, no failure.
                        None => {
                            cur.text.push('&');
                            cur.text.push_str(&r.into_inner());
                            cur.text.push(';');
                        }
                    }
                }
            }
            Event::Eof => {
                return Err(xml_err(
                    &reader,
                    quick_xml::Error::Syntax(quick_xml::errors::SyntaxError::UnclosedTag),
                ));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_tree_with_entities() {
        let root = parse(
            r#"<?xml version="1.0"?>
<dm:document xmlns:dm="urn:x" spec="s">
  <!-- comment -->
  <a k="v &amp; w"><b/>x &lt; y &#65;</a>
</dm:document>"#,
        )
        .unwrap_or_default();
        assert_eq!(root.name, "document");
        assert_eq!(root.attr("spec"), Some("s"));
        let a = root
            .child("a")
            .map(|a| (a.attr("k"), a.text.as_str(), a.children.len()));
        assert_eq!(a, Some((Some("v & w"), "x < y A", 1)));
    }

    #[test]
    fn rejects_truncated_input() {
        assert!(matches!(parse("<document><a>"), Err(Error::Xml { .. })));
    }
}
