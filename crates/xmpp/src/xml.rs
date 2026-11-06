//! Incremental XML framing of an XMPP stream (RFC 6120 sec. 11): stream header, then one
//! element at a time at depth 1 (stanzas, negotiation elements).
//!
//! Input = bytes from anyone who reaches the port -> strict + bounded:
//!
//! - Comments, processing instructions (except the XML declaration), DTDs, entity
//!   declarations -> `restricted-xml`. Same for any entity ref but the 5 predefined ones.
//!   Nothing expanded -> no entity bomb.
//! - Stanza max [`MAX_STANZA`] bytes ([`MAX_STANZA_PRE_AUTH`] before auth), max [`MAX_DEPTH`]
//!   deep, max [`MAX_ATTRIBUTES`] attributes per element, bounded names + namespaces.
//!   Over -> `policy-violation`, also for a still incomplete token -> buffer never holds more
//!   than 1 stanza.
//! - Rest of what the XML grammar forbids -> `not-well-formed`.
//!
//! Input cut into complete tokens (tag, text run, CDATA section) before `quick-xml` parses one.
//! Bytes come in any chunking; incomplete token waits.
//! Only whole tokens reach `quick-xml` -> split read never seen as a syntax error.

use std::sync::Arc;

use quick_xml::XmlVersion;
use quick_xml::escape::unescape;
use quick_xml::events::{BytesStart, Event as XmlEvent};
use quick_xml::reader::Reader;

use crate::Condition;

/// Namespace of the stream element.
pub const NS_STREAMS: &str = "http://etherx.jabber.org/streams";
/// Content namespace of a client-to-server stream.
pub const NS_CLIENT: &str = "jabber:client";

/// Max stanza (or negotiation element) after auth.
pub const MAX_STANZA: usize = 64 * 1024;
/// Max stanza before auth. SASL PLAIN `<auth/>` ~ few 100 bytes.
pub const MAX_STANZA_PRE_AUTH: usize = 4 * 1024;
const MAX_HEADER: usize = 4 * 1024;
/// Max nesting in a stanza (stanza itself = depth 1).
pub const MAX_DEPTH: usize = 16;
/// Max attributes on one element, namespace declarations included.
pub const MAX_ATTRIBUTES: usize = 32;
/// Max length of element name, attribute name or prefix.
pub const MAX_NAME: usize = 128;
/// Max length of a namespace name.
pub const MAX_NAMESPACE: usize = 512;
/// Max elements in one stanza. ~150 bytes heap each.
const MAX_ELEMENTS: usize = 256;
/// Max namespace declarations in scope at once.
const MAX_SCOPES: usize = 32;

/// Element with resolved namespace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Element {
    /// Shared with the declaration it came from.
    pub ns: Option<Arc<str>>,
    /// Local name, prefix removed.
    pub name: String,
    /// Document order, no namespace declarations.
    /// Unprefixed -> plain name; prefixed keeps its prefix (`xml:lang`).
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Element>,
    /// All character data directly inside, children aside.
    pub text: String,
}

impl Element {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Element `name` in namespace `ns`.
    pub fn is(&self, ns: &str, name: &str) -> bool {
        self.name == name && self.ns.as_deref() == Some(ns)
    }

    /// First child `name` in namespace `ns`.
    pub fn child(&self, ns: &str, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.is(ns, name))
    }

    /// Set attribute `name`, replace an old value.
    pub fn set_attr(&mut self, name: &str, value: &str) {
        match self.attrs.iter_mut().find(|(k, _)| k == name) {
            Some((_, v)) => value.clone_into(v),
            None => self.attrs.push((name.to_owned(), value.to_owned())),
        }
    }
}

/// Used attributes of a client stream header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamHeader {
    /// Target domain of the client.
    pub to: Option<String>,
    /// Client claim, not checked.
    pub from: Option<String>,
    /// Stream ID (no use from a client).
    pub id: Option<String>,
    /// `major.minor`, 1.0 for XMPP 1.0 compliant.
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Client opened its stream.
    StreamOpen(StreamHeader),
    /// Complete element directly inside the stream.
    Stanza(Element),
    /// Client closed its stream (`</stream:stream>`).
    StreamClose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Text,
    CData,
    Decl,
    Start,
    Empty,
    End,
}

/// Stop point of a scan of an incomplete token -> next input resumes there.
/// Token fed 1 byte at a time -> not rescanned from its start each time.
#[derive(Debug, Default, Clone, Copy)]
struct Cursor {
    at: usize,
    quote: Option<u8>,
}

#[derive(Debug)]
struct Frame {
    qname: String,
    depth: usize,
    el: Element,
}

#[derive(Debug)]
struct Scope {
    prefix: String,
    uri: Arc<str>,
    depth: usize,
}

/// Incremental stream parser.
///
/// Bytes in: [`Parser::feed`] or read into [`Parser::read_buffer`].
/// Events out: [`Parser::next_event`].
#[derive(Debug)]
pub struct Parser {
    buf: Vec<u8>,
    pos: usize,
    max_stanza: usize,
    cursor: Cursor,
    t: Tree,
}

/// Parser state except the input buffer.
#[derive(Debug)]
struct Tree {
    /// Client stream header read.
    in_stream: bool,
    /// XML declaration still allowed (before the stream header).
    decl_allowed: bool,
    /// `</stream:stream>` read.
    finished: bool,
    failed: Option<Condition>,
    stream_qname: String,
    stack: Vec<Frame>,
    scopes: Vec<Scope>,
    /// Bytes of the stanza being read.
    stanza_bytes: usize,
    /// Elements of the stanza being read.
    elements: usize,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    /// Waits for a stream header. Stanza limit = [`MAX_STANZA_PRE_AUTH`].
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            max_stanza: MAX_STANZA_PRE_AUTH,
            cursor: Cursor::default(),
            t: Tree {
                in_stream: false,
                decl_allowed: true,
                finished: false,
                failed: None,
                stream_qname: String::new(),
                stack: Vec::new(),
                scopes: Vec::new(),
                stanza_bytes: 0,
                elements: 0,
            },
        }
    }

    /// Max stanza from now on.
    pub fn set_max_stanza(&mut self, bytes: usize) {
        self.max_stanza = bytes;
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Buffer for `AsyncReadExt::read_buf`. Consumed input dropped first, room for >= 1 KiB.
    pub fn read_buffer(&mut self) -> &mut Vec<u8> {
        self.compact();
        if self.buf.capacity() - self.buf.len() < 1024 {
            self.buf.reserve(2048);
        }
        &mut self.buf
    }

    /// Bytes read, not yet consumed.
    /// Must be 0 after `<starttls/>`: clear-text bytes after it never trusted into TLS.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Restart for a new stream on the same connection (after STARTTLS or SASL).
    /// Input already read kept = start of the new stream.
    pub fn restart(&mut self) {
        self.cursor = Cursor::default();
        self.t.in_stream = false;
        self.t.decl_allowed = true;
        self.t.finished = false;
        self.t.stack.clear();
        self.t.scopes.clear();
        self.t.stanza_bytes = 0;
        self.t.elements = 0;
    }

    fn compact(&mut self) {
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
            if self.buf.capacity() > 16 * 1024 {
                self.buf.shrink_to(4 * 1024);
            }
        } else if self.pos > 4096 && self.pos > self.buf.len() / 2 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    /// Next event, `None` -> more input needed.
    /// Error = final: close the stream with that condition; later calls return it again.
    pub fn next_event(&mut self) -> Result<Option<Event>, Condition> {
        if let Some(c) = self.t.failed {
            return Err(c);
        }
        let r = self.step();
        if let Err(c) = r {
            self.t.failed = Some(c);
        }
        r
    }

    fn step(&mut self) -> Result<Option<Event>, Condition> {
        loop {
            if self.t.finished {
                return Ok(None);
            }
            let inter = self.t.stack.is_empty();
            let scanned = scan(&self.buf[self.pos..], &mut self.cursor, inter)?;
            let Some((kind, len)) = scanned else {
                // Incomplete token: max = stanza limit.
                let pending = self.buf.len() - self.pos;
                let (used, limit) = if self.t.in_stream {
                    (self.t.stanza_bytes, self.max_stanza)
                } else {
                    (0, MAX_HEADER)
                };
                if used + pending > limit {
                    return Err(Condition::PolicyViolation);
                }
                self.compact();
                return Ok(None);
            };
            let event = self
                .t
                .token(kind, &self.buf[self.pos..self.pos + len], self.max_stanza)?;
            self.pos += len;
            self.cursor = Cursor::default();
            if event.is_some() {
                return Ok(event);
            }
        }
    }
}

fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

/// End of the next token in `b` (`b` starts at the next unconsumed byte).
/// `inter`: no element open in the stream -> only white space between tags.
/// `None`: token not complete.
fn scan(b: &[u8], cur: &mut Cursor, inter: bool) -> Result<Option<(Kind, usize)>, Condition> {
    let Some(&first) = b.first() else {
        return Ok(None);
    };
    if first != b'<' {
        // Text up to the next tag.
        let end = b[cur.at.min(b.len())..]
            .iter()
            .position(|&c| c == b'<')
            .map(|i| i + cur.at.min(b.len()));
        let text = &b[..end.unwrap_or(b.len())];
        if inter {
            // Between stanzas: white space only (keep-alives, line breaks).
            if !text.iter().copied().all(is_ws) {
                return Err(Condition::NotWellFormed);
            }
            return Ok(Some((Kind::Text, text.len())));
        }
        return match end {
            Some(i) => Ok(Some((Kind::Text, i))),
            None => {
                cur.at = b.len();
                Ok(None)
            }
        };
    }
    if b.len() < 2 {
        return Ok(None);
    }
    match b[1] {
        b'/' => {
            // End tag: no quotes, no nested markup.
            let mut i = cur.at.max(2);
            while i < b.len() {
                match b[i] {
                    b'>' => return Ok(Some((Kind::End, i + 1))),
                    b'<' => return Err(Condition::NotWellFormed),
                    _ => i += 1,
                }
            }
            cur.at = i;
            Ok(None)
        }
        b'?' => {
            // XML declaration = only processing instruction allowed.
            const XML: &[u8] = b"<?xml";
            if b.len() < 6 {
                return if XML.starts_with(b) {
                    Ok(None)
                } else {
                    Err(Condition::RestrictedXml)
                };
            }
            if !(b.starts_with(XML) && (is_ws(b[5]) || b[5] == b'?')) {
                return Err(Condition::RestrictedXml);
            }
            match find(b, cur, b"?>") {
                Some(end) => Ok(Some((Kind::Decl, end))),
                None => Ok(None),
            }
        }
        b'!' => {
            // CDATA = text. Comment, DTD, rest -> not allowed.
            const CDATA: &[u8] = b"<![CDATA[";
            if b.len() < CDATA.len() {
                return if CDATA.starts_with(b) {
                    Ok(None)
                } else {
                    Err(Condition::RestrictedXml)
                };
            }
            if !b.starts_with(CDATA) {
                return Err(Condition::RestrictedXml);
            }
            match find(b, cur, b"]]>") {
                Some(end) => Ok(Some((Kind::CData, end))),
                None => Ok(None),
            }
        }
        _ => {
            // Start or empty-element tag. `>` allowed in a quoted value, `<` nowhere in the tag.
            let mut i = cur.at.max(1);
            let mut quote = cur.quote;
            while i < b.len() {
                let c = b[i];
                match quote {
                    Some(q) => {
                        if c == q {
                            quote = None;
                        } else if c == b'<' {
                            return Err(Condition::NotWellFormed);
                        }
                    }
                    None => match c {
                        b'"' | b'\'' => quote = Some(c),
                        b'<' => return Err(Condition::NotWellFormed),
                        b'>' => {
                            let kind = if b[i - 1] == b'/' {
                                Kind::Empty
                            } else {
                                Kind::Start
                            };
                            return Ok(Some((kind, i + 1)));
                        }
                        _ => {}
                    },
                }
                i += 1;
            }
            cur.at = i;
            cur.quote = quote;
            Ok(None)
        }
    }
}

/// End (exclusive) of the first `term` in `b`. Search from the last scan stop.
fn find(b: &[u8], cur: &mut Cursor, term: &[u8]) -> Option<usize> {
    let from = cur.at.saturating_sub(term.len() - 1);
    if from < b.len()
        && let Some(i) = b[from..].windows(term.len()).position(|w| w == term)
    {
        return Some(from + i + term.len());
    }
    cur.at = b.len();
    None
}

/// XML NCName (no colon). Non-ASCII letters count.
fn is_ncname(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    s.len() <= MAX_NAME
        && (first.is_alphabetic() || first == '_')
        && chars.all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Name with max 1 colon -> (prefix, local name), both NCNames.
fn split_qname(q: &str) -> Option<(Option<&str>, &str)> {
    match q.split_once(':') {
        None => is_ncname(q).then_some((None, q)),
        Some((p, l)) => (is_ncname(p) && is_ncname(l)).then_some((Some(p), l)),
    }
}

/// Chars allowed in XML 1.0 (no surrogates possible in a `str`).
fn valid_chars(s: &str) -> bool {
    s.chars().all(|c| {
        matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && c != '\u{FFFE}' && c != '\u{FFFF}')
    })
}

/// `quick-xml` escape error -> stream condition.
/// Entity ref not of the 5 predefined -> only possible from a DTD -> `restricted-xml`.
fn escape_condition(e: &quick_xml::Error) -> Condition {
    match e {
        quick_xml::Error::Escape(quick_xml::escape::EscapeError::UnrecognizedEntity(..)) => {
            Condition::RestrictedXml
        }
        _ => Condition::NotWellFormed,
    }
}

impl Tree {
    /// One complete token. `tok` = exactly its bytes.
    fn token(
        &mut self,
        kind: Kind,
        tok: &[u8],
        max_stanza: usize,
    ) -> Result<Option<Event>, Condition> {
        let in_element = !self.stack.is_empty();
        if self.in_stream && (in_element || kind != Kind::Text) {
            self.stanza_bytes += tok.len();
            if self.stanza_bytes > max_stanza {
                return Err(Condition::PolicyViolation);
            }
        } else if !self.in_stream && tok.len() > MAX_HEADER {
            return Err(Condition::PolicyViolation);
        }
        let s = std::str::from_utf8(tok).map_err(|_| Condition::NotWellFormed)?;
        match kind {
            Kind::Text => {
                if let Some(frame) = self.stack.last_mut() {
                    let text = unescape(s).map_err(|e| escape_condition(&e.into()))?;
                    if !valid_chars(&text) {
                        return Err(Condition::NotWellFormed);
                    }
                    frame.el.text.push_str(&text);
                }
                Ok(None)
            }
            Kind::CData => {
                let Some(frame) = self.stack.last_mut() else {
                    return Err(Condition::NotWellFormed);
                };
                let text = s
                    .strip_prefix("<![CDATA[")
                    .and_then(|t| t.strip_suffix("]]>"))
                    .ok_or(Condition::NotWellFormed)?;
                if !valid_chars(text) {
                    return Err(Condition::NotWellFormed);
                }
                frame.el.text.push_str(text);
                Ok(None)
            }
            Kind::Decl => {
                if self.in_stream || !self.decl_allowed {
                    return Err(Condition::RestrictedXml);
                }
                self.decl_allowed = false;
                let mut reader = Reader::from_str(s);
                match reader.read_event() {
                    Ok(XmlEvent::Decl(d)) => {
                        let utf8 = match d.encoding() {
                            None => true,
                            Some(Ok(e)) => e.eq_ignore_ascii_case("utf-8"),
                            Some(Err(_)) => false,
                        };
                        if !utf8 {
                            return Err(Condition::NotWellFormed);
                        }
                        Ok(None)
                    }
                    _ => Err(Condition::NotWellFormed),
                }
            }
            Kind::Start | Kind::Empty | Kind::End => {
                let mut reader = Reader::from_str(s);
                let config = reader.config_mut();
                config.check_end_names = false;
                config.allow_unmatched_ends = true;
                let event = reader.read_event().map_err(|_| Condition::NotWellFormed)?;
                match (kind, event) {
                    (Kind::Start, XmlEvent::Start(e)) => self.open(&e, false),
                    (Kind::Empty, XmlEvent::Empty(e)) => self.open(&e, true),
                    (Kind::End, XmlEvent::End(e)) => {
                        let name = e.name();
                        self.close(name.as_ref())
                    }
                    _ => Err(Condition::NotWellFormed),
                }
            }
        }
    }

    /// Start tag (empty-element tag if `empty`).
    fn open(&mut self, e: &BytesStart<'_>, empty: bool) -> Result<Option<Event>, Condition> {
        let depth = if self.in_stream {
            self.stack.last().map_or(0, |f| f.depth) + 1
        } else {
            0
        };
        if self.in_stream {
            if depth > MAX_DEPTH {
                return Err(Condition::PolicyViolation);
            }
            self.elements += 1;
            if self.elements > MAX_ELEMENTS {
                return Err(Condition::PolicyViolation);
            }
        } else if empty {
            // Stream element must stay open.
            return Err(Condition::NotWellFormed);
        }
        let qname_ref = e.name();
        let qname: &str = qname_ref.as_ref();
        let (prefix, local) = split_qname(qname).ok_or(Condition::NotWellFormed)?;
        let mut attrs: Vec<(String, String)> = Vec::new();
        let mut declared = 0usize;
        let mut seen = 0usize;
        for a in e.attributes() {
            let a = a.map_err(|_| Condition::NotWellFormed)?;
            seen += 1;
            if seen > MAX_ATTRIBUTES {
                return Err(Condition::PolicyViolation);
            }
            let key: &str = a.key.as_ref();
            let value = a
                .normalized_value(XmlVersion::default())
                .map_err(|e| escape_condition(&e))?;
            if !valid_chars(&value) {
                return Err(Condition::NotWellFormed);
            }
            if key == "xmlns" || key.starts_with("xmlns:") {
                let declared_prefix = key.strip_prefix("xmlns:").unwrap_or_default();
                if (key != "xmlns" && !is_ncname(declared_prefix))
                    || value.len() > MAX_NAMESPACE
                    || (key != "xmlns" && value.is_empty())
                {
                    return Err(Condition::NotWellFormed);
                }
                if self.scopes.len() + declared >= MAX_SCOPES {
                    return Err(Condition::PolicyViolation);
                }
                declared += 1;
                self.scopes.push(Scope {
                    prefix: declared_prefix.to_owned(),
                    uri: Arc::from(&*value),
                    depth,
                });
            } else {
                split_qname(key).ok_or(Condition::NotWellFormed)?;
                attrs.push((key.to_owned(), value.into_owned()));
            }
        }
        // Declarations on this element apply to itself too.
        let ns = self.resolve(prefix)?;
        let el = Element {
            ns,
            name: local.to_owned(),
            attrs,
            ..Element::default()
        };
        if !self.in_stream {
            return self.open_stream(el, qname);
        }
        if empty {
            self.scopes.retain(|s| s.depth < depth);
            return Ok(self.attach(el));
        }
        self.stack.push(Frame {
            qname: qname.to_owned(),
            depth,
            el,
        });
        Ok(None)
    }

    /// Namespace of `prefix` (`None` -> default namespace).
    fn resolve(&self, prefix: Option<&str>) -> Result<Option<Arc<str>>, Condition> {
        let wanted = prefix.unwrap_or("");
        match self.scopes.iter().rev().find(|s| s.prefix == wanted) {
            Some(s) if s.uri.is_empty() => Ok(None),
            Some(s) => Ok(Some(Arc::clone(&s.uri))),
            None if prefix.is_none() => Ok(None),
            None => Err(Condition::NotWellFormed),
        }
    }

    /// First element of a stream = client stream header.
    fn open_stream(&mut self, el: Element, qname: &str) -> Result<Option<Event>, Condition> {
        if el.name != "stream" {
            return Err(Condition::NotWellFormed);
        }
        let streams = el.ns.as_deref() == Some(NS_STREAMS);
        let client = self.resolve(None)?.as_deref() == Some(NS_CLIENT);
        if !streams || !client {
            return Err(Condition::InvalidNamespace);
        }
        let get = |k: &str| el.attr(k).map(str::to_owned);
        let header = StreamHeader {
            to: get("to"),
            from: get("from"),
            id: get("id"),
            version: get("version"),
        };
        self.in_stream = true;
        self.decl_allowed = false;
        qname.clone_into(&mut self.stream_qname);
        Ok(Some(Event::StreamOpen(header)))
    }

    /// Finished element: depth 1 -> stanza, else child of the open element.
    fn attach(&mut self, el: Element) -> Option<Event> {
        match self.stack.last_mut() {
            Some(parent) => {
                parent.el.children.push(el);
                None
            }
            None => {
                self.stanza_bytes = 0;
                self.elements = 0;
                Some(Event::Stanza(el))
            }
        }
    }

    /// End tag.
    fn close(&mut self, qname: &str) -> Result<Option<Event>, Condition> {
        let Some(frame) = self.stack.pop() else {
            // Nothing open in the stream -> end of the stream itself.
            if self.in_stream && qname == self.stream_qname {
                self.finished = true;
                return Ok(Some(Event::StreamClose));
            }
            return Err(Condition::NotWellFormed);
        };
        if frame.qname != qname {
            return Err(Condition::NotWellFormed);
        }
        self.scopes.retain(|s| s.depth < frame.depth);
        Ok(self.attach(frame.el))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const HEADER: &str = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' \
        xmlns:stream='http://etherx.jabber.org/streams' to='example.net' version='1.0'>";

    fn events(input: &str) -> Vec<Event> {
        let mut p = Parser::new();
        p.feed(input.as_bytes());
        let mut out = Vec::new();
        while let Some(e) = p.next_event().unwrap() {
            out.push(e);
        }
        out
    }

    fn err(input: &str) -> Condition {
        let mut p = Parser::new();
        p.feed(input.as_bytes());
        loop {
            match p.next_event() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("no error for {input:?}"),
                Err(c) => return c,
            }
        }
    }

    fn stanza(e: &Event) -> &Element {
        match e {
            Event::Stanza(el) => el,
            other => panic!("not a stanza: {other:?}"),
        }
    }

    #[test]
    fn reads_the_header_and_stanzas() {
        let evs = events(&format!(
            "{HEADER}<iq type='get' id='1'><ping xmlns='urn:xmpp:ping'/></iq> \n<presence/>"
        ));
        assert_eq!(evs.len(), 3);
        let Event::StreamOpen(h) = &evs[0] else {
            panic!()
        };
        assert_eq!(h.to.as_deref(), Some("example.net"));
        assert_eq!(h.version.as_deref(), Some("1.0"));
        let iq = stanza(&evs[1]);
        assert!(iq.is(NS_CLIENT, "iq"));
        assert_eq!(iq.attr("type"), Some("get"));
        assert!(iq.child("urn:xmpp:ping", "ping").is_some());
        assert!(stanza(&evs[2]).is(NS_CLIENT, "presence"));
    }

    #[test]
    fn the_xml_declaration_is_optional_and_only_before_the_header() {
        assert_eq!(
            events(&HEADER.replace("<?xml version='1.0'?>", "")).len(),
            1
        );
        assert_eq!(
            events("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>").len(),
            1
        );
        assert_eq!(
            err(&format!("{HEADER}<?xml version='1.0'?>")),
            Condition::RestrictedXml
        );
        assert_eq!(
            err("<?xml version='1.0' encoding='ISO-8859-1'?><stream:stream/>"),
            Condition::NotWellFormed
        );
    }

    #[test]
    fn restricted_xml_is_refused() {
        for bad in [
            "<!-- hi -->",
            "<!DOCTYPE x [<!ENTITY a 'b'>]>",
            "<?pi stuff?>",
            "<?xml-stylesheet href='x'?>",
            "<!ENTITY a 'b'>",
        ] {
            assert_eq!(
                err(&format!("{HEADER}{bad}")),
                Condition::RestrictedXml,
                "{bad}"
            );
            assert_eq!(
                err(bad),
                Condition::RestrictedXml,
                "before the header: {bad}"
            );
        }
        // Comment or entity inside a stanza too.
        assert_eq!(
            err(&format!(
                "{HEADER}<message><body><!-- x --></body></message>"
            )),
            Condition::RestrictedXml
        );
        assert_eq!(
            err(&format!("{HEADER}<message><body>&xxe;</body></message>")),
            Condition::RestrictedXml
        );
        assert_eq!(
            err(&format!("{HEADER}<message to='&lol;'/>")),
            Condition::RestrictedXml
        );
    }

    #[test]
    fn predefined_and_numeric_references_are_resolved() {
        let evs = events(&format!(
            "{HEADER}<message to='a&amp;b'><body>&lt;x&gt; &#65;&#x42; &quot;&apos;</body></message>"
        ));
        let m = stanza(&evs[1]);
        assert_eq!(m.attr("to"), Some("a&b"));
        assert_eq!(m.children[0].text, "<x> AB \"'");
    }

    #[test]
    fn cdata_is_text() {
        let evs = events(&format!(
            "{HEADER}<message><body>a<![CDATA[<b>&]]>c</body></message>"
        ));
        assert_eq!(stanza(&evs[1]).children[0].text, "a<b>&c");
    }

    #[test]
    fn malformed_input_is_not_well_formed() {
        for bad in [
            "<iq></message>",
            "<iq><a></iq>",
            "</iq>",
            "<iq a='1' a='2'/>",
            "<iq a=1/>",
            "<iq a='<'/>",
            "<iq <b/>>",
            "<1iq/>",
            "<iq:a:b/>",
            "<x:iq/>",
            "text outside",
            "<iq>&#0;</iq>",
            "<iq>a & b</iq>",
            "<>",
        ] {
            assert_eq!(
                err(&format!("{HEADER}{bad}")),
                Condition::NotWellFormed,
                "{bad}"
            );
        }
        assert_eq!(err("GET / HTTP/1.1\r\n"), Condition::NotWellFormed);
        assert_eq!(err("\u{0}"), Condition::NotWellFormed);
        let mut p = Parser::new();
        p.feed(HEADER.as_bytes());
        p.feed(&[b'<', b'i', b'q', b' ', 0xff, b'/', b'>']);
        assert!(matches!(p.next_event(), Ok(Some(_))));
        assert_eq!(p.next_event(), Err(Condition::NotWellFormed));
    }

    #[test]
    fn the_stream_element_is_checked() {
        assert_eq!(
            err("<stream:stream xmlns='jabber:client' xmlns:stream='urn:wrong'>"),
            Condition::InvalidNamespace
        );
        assert_eq!(
            err("<stream:stream xmlns:stream='http://etherx.jabber.org/streams'>"),
            Condition::InvalidNamespace,
            "no content namespace"
        );
        assert_eq!(
            err(
                "<stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams'>"
            ),
            Condition::InvalidNamespace
        );
        assert_eq!(err("<iq xmlns='jabber:client'/>"), Condition::NotWellFormed);
        assert_eq!(
            err(
                "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'/>"
            ),
            Condition::NotWellFormed,
            "the stream element is not self-closing"
        );
    }

    #[test]
    fn any_prefix_may_stand_for_the_streams_namespace() {
        let evs = events(
            "<s:stream xmlns='jabber:client' xmlns:s='http://etherx.jabber.org/streams' to='a'><iq/></s:stream>",
        );
        assert_eq!(evs.len(), 3);
        assert_eq!(evs[2], Event::StreamClose);
    }

    #[test]
    fn stream_close_is_an_event_and_ends_the_input() {
        let mut p = Parser::new();
        p.feed(format!("{HEADER}</stream:stream><iq/>").as_bytes());
        assert!(matches!(p.next_event(), Ok(Some(Event::StreamOpen(_)))));
        assert_eq!(p.next_event(), Ok(Some(Event::StreamClose)));
        assert_eq!(p.next_event(), Ok(None));
    }

    #[test]
    fn namespaces_follow_scope() {
        let evs = events(&format!(
            "{HEADER}<iq><bind xmlns='urn:b'><resource/></bind><x/></iq>"
        ));
        let iq = stanza(&evs[1]);
        let bind = &iq.children[0];
        assert!(bind.is("urn:b", "bind"));
        assert!(bind.children[0].is("urn:b", "resource"));
        assert!(
            iq.children[1].is(NS_CLIENT, "x"),
            "the default namespace is back"
        );
        let evs = events(&format!(
            "{HEADER}<iq><q:a xmlns:q='urn:q'><q:b/></q:a></iq>"
        ));
        let a = &stanza(&evs[1]).children[0];
        assert!(a.is("urn:q", "a") && a.children[0].is("urn:q", "b"));
    }

    #[test]
    fn a_prefix_out_of_scope_is_not_well_formed() {
        assert_eq!(
            err(&format!("{HEADER}<iq><q:a xmlns:q='urn:q'/><q:b/></iq>")),
            Condition::NotWellFormed
        );
    }

    #[test]
    fn input_in_any_chunking_gives_the_same_events() {
        let doc = format!(
            "{HEADER} <iq type='set' id='a&amp;b'><bind xmlns='urn:b'><resource>r&#233;</resource></bind></iq>\
             <message to='x'><body><![CDATA[1]]>2</body></message>  <presence/>"
        );
        let whole = events(&doc);
        assert_eq!(whole.len(), 4);
        for chunk in [1usize, 2, 3, 5, 7, 64] {
            let mut p = Parser::new();
            let mut got = Vec::new();
            for piece in doc.as_bytes().chunks(chunk) {
                p.feed(piece);
                while let Some(e) = p.next_event().unwrap() {
                    got.push(e);
                }
            }
            assert_eq!(got, whole, "chunk size {chunk}");
        }
    }

    #[test]
    fn restart_keeps_the_input_and_expects_a_new_header() {
        let mut p = Parser::new();
        p.feed(
            format!("{HEADER}<starttls xmlns='urn:t'/>{HEADER}<auth xmlns='urn:s'/>").as_bytes(),
        );
        assert!(matches!(p.next_event(), Ok(Some(Event::StreamOpen(_)))));
        let tls = p.next_event().unwrap().unwrap();
        assert!(stanza(&tls).is("urn:t", "starttls"));
        assert!(p.buffered() > 0, "pipelined input is visible to the caller");
        p.restart();
        assert!(matches!(p.next_event(), Ok(Some(Event::StreamOpen(_)))));
        let auth = p.next_event().unwrap().unwrap();
        assert!(stanza(&auth).is("urn:s", "auth"));
        assert_eq!(p.buffered(), 0);
        // Stanza before the new header -> not a stream.
        let mut p = Parser::new();
        p.feed(format!("{HEADER}<a/>").as_bytes());
        p.next_event().unwrap();
        p.next_event().unwrap();
        p.restart();
        p.feed(b"<iq xmlns='jabber:client'/>");
        assert_eq!(p.next_event(), Err(Condition::NotWellFormed));
    }

    #[test]
    fn stanzas_have_a_size_limit_that_can_be_raised() {
        let big = format!("<message><body>{}</body></message>", "x".repeat(5000));
        let mut p = Parser::new();
        p.feed(HEADER.as_bytes());
        p.feed(big.as_bytes());
        p.next_event().unwrap();
        assert_eq!(
            p.next_event(),
            Err(Condition::PolicyViolation),
            "4 KiB before authentication"
        );
        let mut p = Parser::new();
        p.set_max_stanza(MAX_STANZA);
        p.feed(HEADER.as_bytes());
        p.feed(big.as_bytes());
        p.next_event().unwrap();
        assert!(matches!(p.next_event(), Ok(Some(Event::Stanza(_)))));
        let huge = format!("<message><body>{}</body></message>", "x".repeat(MAX_STANZA));
        let mut p = Parser::new();
        p.set_max_stanza(MAX_STANZA);
        p.feed(HEADER.as_bytes());
        p.feed(huge.as_bytes());
        p.next_event().unwrap();
        assert_eq!(p.next_event(), Err(Condition::PolicyViolation));
    }

    #[test]
    fn an_endless_token_is_cut_off_before_it_is_complete() {
        // Tag without end -> buffer must not grow past 1 stanza.
        let mut p = Parser::new();
        p.feed(HEADER.as_bytes());
        p.feed(b"<iq a='");
        p.next_event().unwrap();
        let mut fed = 0;
        let r = loop {
            p.feed(&[b'a'; 512]);
            fed += 512;
            let r = p.next_event();
            if r != Ok(None) || fed > 100_000 {
                break r;
            }
        };
        assert_eq!(r, Err(Condition::PolicyViolation));
        assert!(
            fed <= MAX_STANZA_PRE_AUTH + 512,
            "stopped after {fed} bytes"
        );
        // Same for text in a stanza that never reaches a tag.
        let mut p = Parser::new();
        p.feed(HEADER.as_bytes());
        p.feed(b"<iq>");
        p.next_event().unwrap();
        let mut fed = 0;
        let r = loop {
            p.feed(&[b'a'; 512]);
            fed += 512;
            let r = p.next_event();
            if r != Ok(None) || fed > 100_000 {
                break r;
            }
        };
        assert_eq!(r, Err(Condition::PolicyViolation));
        assert!(
            fed <= MAX_STANZA_PRE_AUTH + 512,
            "stopped after {fed} bytes"
        );
        // Same before the stream header.
        let mut p = Parser::new();
        p.feed(b"<stream:stream a='");
        let r = loop {
            p.feed(&[b'a'; 512]);
            let r = p.next_event();
            if r != Ok(None) {
                break r;
            }
        };
        assert_eq!(r, Err(Condition::PolicyViolation));
    }

    #[test]
    fn nesting_attributes_names_and_elements_are_bounded() {
        let deep = |n: usize| format!("{}{}", "<a>".repeat(n), "</a>".repeat(n));
        let mut p = Parser::new();
        p.set_max_stanza(MAX_STANZA);
        p.feed(format!("{HEADER}{}", deep(MAX_DEPTH)).as_bytes());
        p.next_event().unwrap();
        assert!(
            matches!(p.next_event(), Ok(Some(Event::Stanza(_)))),
            "depth {MAX_DEPTH} is allowed"
        );
        let mut p = Parser::new();
        p.set_max_stanza(MAX_STANZA);
        p.feed(format!("{HEADER}{}", deep(MAX_DEPTH + 1)).as_bytes());
        p.next_event().unwrap();
        assert_eq!(p.next_event(), Err(Condition::PolicyViolation));

        let attrs = |n: usize| (0..n).map(|i| format!(" a{i}='v'")).collect::<String>();
        let mut p = Parser::new();
        p.set_max_stanza(MAX_STANZA);
        p.feed(format!("{HEADER}<iq{}/>", attrs(MAX_ATTRIBUTES)).as_bytes());
        p.next_event().unwrap();
        assert!(matches!(p.next_event(), Ok(Some(Event::Stanza(_)))));
        let mut p = Parser::new();
        p.set_max_stanza(MAX_STANZA);
        p.feed(format!("{HEADER}<iq{}/>", attrs(MAX_ATTRIBUTES + 1)).as_bytes());
        p.next_event().unwrap();
        assert_eq!(p.next_event(), Err(Condition::PolicyViolation));

        let mut p = Parser::new();
        p.feed(format!("{HEADER}<{}/>", "n".repeat(MAX_NAME + 1)).as_bytes());
        p.next_event().unwrap();
        assert_eq!(p.next_event(), Err(Condition::NotWellFormed));
        let mut p = Parser::new();
        p.set_max_stanza(MAX_STANZA);
        p.feed(format!("{HEADER}<iq xmlns='{}'/>", "u".repeat(MAX_NAMESPACE + 1)).as_bytes());
        p.next_event().unwrap();
        assert_eq!(p.next_event(), Err(Condition::NotWellFormed));

        let mut p = Parser::new();
        p.set_max_stanza(MAX_STANZA);
        p.feed(format!("{HEADER}<iq>{}</iq>", "<a/>".repeat(MAX_ELEMENTS)).as_bytes());
        p.next_event().unwrap();
        assert_eq!(p.next_event(), Err(Condition::PolicyViolation));
    }

    #[test]
    fn many_namespace_declarations_in_scope_are_bounded() {
        let mut p = Parser::new();
        p.set_max_stanza(MAX_STANZA);
        let mut doc = String::from(HEADER);
        for i in 0..=MAX_SCOPES {
            doc.push_str(&format!("<a xmlns:p{i}='u{i}'>"));
        }
        p.feed(doc.as_bytes());
        p.next_event().unwrap();
        assert_eq!(p.next_event(), Err(Condition::PolicyViolation));
    }

    #[test]
    fn white_space_between_stanzas_is_free_but_text_is_not() {
        let mut p = Parser::new();
        p.feed(HEADER.as_bytes());
        p.next_event().unwrap();
        for _ in 0..10 {
            p.feed(&[b' '; 1000]);
            assert_eq!(p.next_event(), Ok(None));
        }
        assert_eq!(p.buffered(), 0, "white space is consumed as it comes");
        p.feed(b" x ");
        assert_eq!(p.next_event(), Err(Condition::NotWellFormed));
    }

    #[test]
    fn an_error_is_final() {
        let mut p = Parser::new();
        p.feed(b"<!-- x -->");
        assert_eq!(p.next_event(), Err(Condition::RestrictedXml));
        p.feed(HEADER.as_bytes());
        assert_eq!(p.next_event(), Err(Condition::RestrictedXml));
    }

    #[test]
    fn element_helpers() {
        let mut el = Element {
            ns: Some(Arc::from("urn:x")),
            name: "a".into(),
            attrs: vec![("k".into(), "v".into())],
            ..Element::default()
        };
        assert_eq!(el.attr("k"), Some("v"));
        assert!(el.is("urn:x", "a") && !el.is("urn:y", "a") && !el.is("urn:x", "b"));
        el.set_attr("k", "w");
        el.set_attr("n", "1");
        assert_eq!(el.attr("k"), Some("w"));
        assert_eq!(el.attr("n"), Some("1"));
    }
}
