//! Namespace-aware owned XML tree (decode) + small writer (encode).
//!
//! Parser input is untrusted -> each document bounded: depth, elements, attributes,
//! retained text, namespace declarations (`MAX_*` constants).
//! Limit exceeded -> decode error, never a partial tree.

use std::sync::Arc;

use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

use crate::error::{DecodeError, Result};

/// Max element nesting on decode. CWMP messages are shallow.
pub(crate) const MAX_DEPTH: usize = 32;

/// Max elements per document.
/// GPV response: 3 elements per parameter -> 10,000 parameters ~ 30,000 elements.
/// 8 MiB response, shortest realistic parameters -> still under 300,000.
/// ~150 bytes heap per element -> cap bounds one decode to ~75 MB, however small the input.
pub(crate) const MAX_ELEMENTS: usize = 500_000;

/// Max attributes per document (namespace declarations excluded).
/// CWMP: ~1 per parameter (`xsi:type`) -> far above any real message.
pub(crate) const MAX_ATTRIBUTES: usize = 250_000;

/// Max bytes of retained text + attribute values per document.
/// = ACS decoded body limit -> never rejects a body the ACS accepts.
/// Still bounds callers that feed the codec larger inputs.
pub(crate) const MAX_TEXT_BYTES: usize = 8 << 20;

/// Max namespace declarations in scope at once (SOAP envelope: ~10).
/// Prefix lookup scans the table -> unbounded table = CPU amplifier
/// (1 MB of declarations -> seconds to resolve against).
pub(crate) const MAX_NS_DECLARATIONS: usize = 256;

pub(crate) const NS_SOAP_ENV: &str = "http://schemas.xmlsoap.org/soap/envelope/";
pub(crate) const NS_SOAP_ENC: &str = "http://schemas.xmlsoap.org/soap/encoding/";
pub(crate) const NS_XSD: &str = "http://www.w3.org/2001/XMLSchema";
pub(crate) const NS_XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";

#[derive(Debug, Default, Clone)]
pub(crate) struct Element {
    /// Namespace URI, if any. Same `Arc` as its declaration -> long URI stored once.
    pub(crate) ns: Option<Arc<str>>,
    /// Local name (prefix removed).
    pub(crate) name: String,
    /// Attributes as (local name, value). No namespace declarations.
    pub(crate) attrs: Vec<(String, String)>,
    pub(crate) children: Vec<Element>,
    pub(crate) text: String,
}

impl Element {
    pub(crate) fn attr(&self, local: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == local)
            .map(|(_, v)| v.as_str())
    }

    /// First child with this local name. Exact match first, else case-insensitive (lenient).
    pub(crate) fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name).or_else(|| {
            self.children
                .iter()
                .find(|c| c.name.eq_ignore_ascii_case(name))
        })
    }

    pub(crate) fn children_named<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Iterator<Item = &'a Element> + 'a {
        self.children
            .iter()
            .filter(move |c| c.name.eq_ignore_ascii_case(name))
    }
}

/// `s` = valid XML NCName (no colon)? Non-ASCII letters accepted.
pub(crate) fn is_ncname(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_alphabetic() || first == '_')
        && chars.all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

fn split(qname: &str) -> (Option<&str>, &str) {
    match qname.split_once(':') {
        Some((p, l)) => (Some(p), l),
        None => (None, qname),
    }
}

fn xml_err(reader: &Reader<&[u8]>, source: quick_xml::Error) -> DecodeError {
    DecodeError::Xml {
        position: reader.error_position(),
        source,
    }
}

/// Namespace declarations in scope: (prefix or "" for default, uri, depth).
type Scopes = Vec<(String, Arc<str>, usize)>;

fn resolve(scopes: &Scopes, prefix: Option<&str>) -> Option<Arc<str>> {
    let p = prefix.unwrap_or("");
    scopes
        .iter()
        .rev()
        .find(|(sp, _, _)| sp == p)
        .map(|(_, uri, _)| Arc::clone(uri))
}

/// Used part of the document budget (`MAX_*` limits).
#[derive(Debug, Default)]
struct Budget {
    elements: usize,
    attributes: usize,
    text: usize,
}

impl Budget {
    fn element(&mut self) -> Result<()> {
        self.elements += 1;
        if self.elements > MAX_ELEMENTS {
            return Err(DecodeError::TooLarge {
                what: "elements",
                limit: MAX_ELEMENTS,
            });
        }
        Ok(())
    }

    fn attribute(&mut self, value_len: usize) -> Result<()> {
        self.attributes += 1;
        if self.attributes > MAX_ATTRIBUTES {
            return Err(DecodeError::TooLarge {
                what: "attributes",
                limit: MAX_ATTRIBUTES,
            });
        }
        self.text(value_len)
    }

    fn text(&mut self, len: usize) -> Result<()> {
        self.text = self.text.saturating_add(len);
        if self.text > MAX_TEXT_BYTES {
            return Err(DecodeError::TooLarge {
                what: "bytes of text and attribute values",
                limit: MAX_TEXT_BYTES,
            });
        }
        Ok(())
    }
}

fn open(
    reader: &Reader<&[u8]>,
    e: &BytesStart<'_>,
    scopes: &mut Scopes,
    depth: usize,
    budget: &mut Budget,
) -> Result<Element> {
    budget.element()?;
    let mut attrs = Vec::new();
    for a in e.attributes() {
        let a = a.map_err(|err| xml_err(reader, err.into()))?;
        let key: &str = a.key.as_ref();
        let value = a
            .normalized_value(XmlVersion::default())
            .map_err(|err| xml_err(reader, err))?;
        if key == "xmlns" || key.starts_with("xmlns:") {
            if scopes.len() >= MAX_NS_DECLARATIONS {
                return Err(DecodeError::TooLarge {
                    what: "namespace declarations in scope",
                    limit: MAX_NS_DECLARATIONS,
                });
            }
            let prefix = key.strip_prefix("xmlns:").unwrap_or_default();
            scopes.push((prefix.to_owned(), Arc::from(&*value), depth));
        } else {
            budget.attribute(value.len())?;
            attrs.push((split(key).1.to_owned(), value.into_owned()));
        }
    }
    let qname = e.name();
    let (prefix, local) = split(qname.as_ref());
    // quick-xml accepts some malformed names -> reject, so never echoed.
    if !is_ncname(local) || prefix.is_some_and(|p| !is_ncname(p)) {
        return Err(DecodeError::InvalidName(qname.as_ref().to_owned()));
    }
    Ok(Element {
        ns: resolve(scopes, prefix),
        name: local.to_owned(),
        attrs,
        ..Element::default()
    })
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

/// Parse `input` into a tree. DTDs ignored, custom entities not expanded.
pub(crate) fn parse(input: &[u8]) -> Result<Element> {
    let mut reader = Reader::from_reader(input);
    let mut stack: Vec<Element> = Vec::new();
    let mut scopes: Scopes = Vec::new();
    let mut budget = Budget::default();

    loop {
        let event = reader.read_event().map_err(|err| xml_err(&reader, err))?;
        match event {
            Event::Start(e) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(DecodeError::TooDeep(MAX_DEPTH));
                }
                let el = open(&reader, &e, &mut scopes, stack.len() + 1, &mut budget)?;
                stack.push(el);
            }
            Event::Empty(e) => {
                let el = open(&reader, &e, &mut scopes, stack.len() + 1, &mut budget)?;
                scopes.retain(|(_, _, d)| *d <= stack.len());
                match stack.last_mut() {
                    Some(parent) => parent.children.push(el),
                    None => return Ok(el),
                }
            }
            Event::End(_) => {
                let Some(el) = stack.pop() else { continue };
                scopes.retain(|(_, _, d)| *d <= stack.len());
                match stack.last_mut() {
                    Some(parent) => parent.children.push(el),
                    None => return Ok(el),
                }
            }
            Event::Text(t) => {
                if let Some(cur) = stack.last_mut() {
                    let text = t.xml_content(XmlVersion::default());
                    budget.text(text.len())?;
                    cur.text.push_str(&text);
                }
            }
            Event::CData(t) => {
                if let Some(cur) = stack.last_mut() {
                    let text = t.into_inner();
                    budget.text(text.len())?;
                    cur.text.push_str(&text);
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
                        Some(c) => {
                            budget.text(c.len_utf8())?;
                            cur.text.push(c);
                        }
                        None => {
                            let name = r.into_inner();
                            budget.text(name.len() + 2)?;
                            cur.text.push('&');
                            cur.text.push_str(&name);
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

/// Minimal XML writer, compact output.
#[derive(Debug, Default)]
pub(crate) struct Writer {
    pub(crate) out: String,
}

fn escape_into(out: &mut String, s: &str, attr: bool) {
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' if attr => out.push_str("&quot;"),
            '\r' => out.push_str("&#13;"),
            c => out.push(c),
        }
    }
}

impl Writer {
    /// `<name a="v"...>`, attribute values escaped.
    pub(crate) fn open(&mut self, name: &str, attrs: &[(&str, &str)]) {
        self.out.push('<');
        self.out.push_str(name);
        for (k, v) in attrs {
            self.out.push(' ');
            self.out.push_str(k);
            self.out.push_str("=\"");
            escape_into(&mut self.out, v, true);
            self.out.push('"');
        }
        self.out.push('>');
    }

    pub(crate) fn close(&mut self, name: &str) {
        self.out.push_str("</");
        self.out.push_str(name);
        self.out.push('>');
    }

    pub(crate) fn text(&mut self, s: &str) {
        escape_into(&mut self.out, s, false);
    }

    /// `<name attrs>text</name>`
    pub(crate) fn leaf(&mut self, name: &str, attrs: &[(&str, &str)], text: &str) {
        self.open(name, attrs);
        self.text(text);
        self.close(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_namespaces_and_scopes() {
        let root = parse(
            br#"<a:Envelope xmlns:a="urn:soap"><a:Body xmlns="urn:dflt"><x/><b:y xmlns:b="urn:b"/><a:z/></a:Body><q/></a:Envelope>"#,
        )
        .unwrap_or_default();
        assert_eq!(
            (root.ns.as_deref(), root.name.as_str()),
            (Some("urn:soap"), "Envelope")
        );
        let body = &root.children[0];
        let ns: Vec<_> = body.children.iter().map(|c| c.ns.as_deref()).collect();
        assert_eq!(ns, [Some("urn:dflt"), Some("urn:b"), Some("urn:soap")]);
        // Default namespace of Body -> out of scope for <q>.
        assert_eq!(root.children[1].ns, None);
    }

    #[test]
    fn rejects_malformed_names() {
        for bad in ["<a(b/>", "<1a/>", "<a:b:c/>", "<x><y<</x>"] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad}");
        }
        assert!(is_ncname("X_00D09E_Foo") && is_ncname("한글") && !is_ncname("a b"));
    }

    #[test]
    fn depth_limit() {
        let deep = "<a>".repeat(MAX_DEPTH + 1) + &"</a>".repeat(MAX_DEPTH + 1);
        assert!(matches!(
            parse(deep.as_bytes()),
            Err(DecodeError::TooDeep(_))
        ));
    }

    #[test]
    fn namespace_uri_is_shared_between_elements() {
        let root = parse(br#"<a xmlns="urn:x"><b/><c><d/></c></a>"#).unwrap_or_default();
        let ns = root.ns.as_ref().expect("namespace");
        for el in [
            &root.children[0],
            &root.children[1],
            &root.children[1].children[0],
        ] {
            assert!(Arc::ptr_eq(ns, el.ns.as_ref().expect("namespace")));
        }
    }

    /// Many elements, very long namespace URI -> URI must not be copied per element.
    #[test]
    fn long_namespace_uri_is_stored_once() {
        let uri = "u".repeat(20_000);
        let doc = format!("<a xmlns=\"{uri}\">{}</a>", "<b/>".repeat(10_000));
        let root = parse(doc.as_bytes()).unwrap_or_default();
        let ns = root.ns.as_ref().expect("namespace");
        assert_eq!(ns.len(), 20_000);
        assert_eq!(root.children.len(), 10_000);
        assert!(
            root.children
                .iter()
                .all(|c| c.ns.as_ref().is_some_and(|n| Arc::ptr_eq(n, ns)))
        );
        // Root + 10,000 children (scope entry dropped): ref counts, not copies.
        assert_eq!(Arc::strong_count(ns), 10_001);
    }

    #[test]
    fn element_count_is_capped() {
        let at_limit = format!("<a>{}</a>", "<b/>".repeat(MAX_ELEMENTS - 1));
        assert!(parse(at_limit.as_bytes()).is_ok());
        let over = format!("<a>{}</a>", "<b/>".repeat(MAX_ELEMENTS));
        assert!(matches!(
            parse(over.as_bytes()),
            Err(DecodeError::TooLarge {
                what: "elements",
                limit: MAX_ELEMENTS
            })
        ));
        // Start tags count too, not only empty elements.
        let over = format!("<a>{}</a>", "<b></b>".repeat(MAX_ELEMENTS));
        assert!(matches!(
            parse(over.as_bytes()),
            Err(DecodeError::TooLarge {
                what: "elements",
                ..
            })
        ));
    }

    #[test]
    fn attribute_count_is_capped() {
        let at_limit = format!("<a>{}</a>", "<b x=\"1\"/>".repeat(MAX_ATTRIBUTES));
        assert!(parse(at_limit.as_bytes()).is_ok());
        let over = format!("<a>{}</a>", "<b x=\"1\"/>".repeat(MAX_ATTRIBUTES + 1));
        assert!(matches!(
            parse(over.as_bytes()),
            Err(DecodeError::TooLarge {
                what: "attributes",
                limit: MAX_ATTRIBUTES
            })
        ));
        // Namespace declarations != attributes.
        let decls = format!("<a>{}</a>", "<b xmlns=\"u\"/>".repeat(MAX_ATTRIBUTES + 1));
        assert!(parse(decls.as_bytes()).is_ok());
    }

    #[test]
    fn text_and_attribute_bytes_are_capped() {
        let at_limit = format!("<a>{}</a>", "x".repeat(MAX_TEXT_BYTES));
        assert!(parse(at_limit.as_bytes()).is_ok());
        let over = format!("<a>{}</a>", "x".repeat(MAX_TEXT_BYTES + 1));
        assert!(matches!(
            parse(over.as_bytes()),
            Err(DecodeError::TooLarge { .. })
        ));
        // Split over many nodes, entities + CDATA.
        let over = format!(
            "<a>{}</a>",
            "<b>&amp;&#65;<![CDATA[xx]]></b>".repeat(MAX_TEXT_BYTES / 4)
        );
        assert!(matches!(
            parse(over.as_bytes()),
            Err(DecodeError::TooLarge { .. })
        ));
        // Attribute values -> same budget.
        let over = format!("<a v=\"{}\"/>", "x".repeat(MAX_TEXT_BYTES + 1));
        assert!(matches!(
            parse(over.as_bytes()),
            Err(DecodeError::TooLarge { .. })
        ));
        // Text outside the root element: not kept, not counted.
        let doc = format!("<a/>{}", " ".repeat(MAX_TEXT_BYTES + 1));
        assert!(parse(doc.as_bytes()).is_ok());
    }

    #[test]
    fn namespace_declarations_in_scope_are_capped() {
        let decls = |n: usize| {
            (0..n)
                .map(|i| format!(" xmlns:p{i}=\"u\""))
                .collect::<String>()
        };
        let ok = format!("<a{}><p0:b/></a>", decls(MAX_NS_DECLARATIONS));
        assert!(parse(ok.as_bytes()).is_ok());
        let over = format!("<a{}><p0:b/></a>", decls(MAX_NS_DECLARATIONS + 1));
        assert!(matches!(
            parse(over.as_bytes()),
            Err(DecodeError::TooLarge {
                what: "namespace declarations in scope",
                ..
            })
        ));
        // Declarations of nested elements add up while in scope...
        let nested = (0..MAX_DEPTH)
            .map(|i| format!("<e{i}{}>", decls(MAX_NS_DECLARATIONS / 8 + 1)))
            .collect::<String>();
        assert!(matches!(
            parse(nested.as_bytes()),
            Err(DecodeError::TooLarge { .. })
        ));
        // ...and are released at element end.
        let sequential = format!(
            "<a>{}</a>",
            format!("<b{}></b>", decls(MAX_NS_DECLARATIONS)).repeat(8)
        );
        assert!(parse(sequential.as_bytes()).is_ok());
    }

    #[test]
    fn writer_escapes() {
        let mut w = Writer::default();
        w.leaf("V", &[("k", "a\"<")], "x<&>\r");
        assert_eq!(w.out, r#"<V k="a&quot;&lt;">x&lt;&amp;&gt;&#13;</V>"#);
    }
}
