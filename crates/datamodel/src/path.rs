//! USP / CWMP path names, instance addressing, search expressions.
//!
//! Grammar (TR-369 path names, TR-069 instance + alias addressing):
//!
//! ```text
//! path      = segment *("." segment) ["."]
//! segment   = name | instance | "{i}" | "*" | "[" (alias | search) "]"
//! item      = name | name "()" | name "!"          ; last segment of a non-object path
//! search    = expr *("&&" expr)
//! expr      = relpath op value
//! relpath   = name ["#" (number | "*")] ["+"] *("." name ...)
//! op        = "==" | "!=" | "<=" | ">=" | "<" | ">"
//! value     = '"' *char '"' | token
//! ```
//!
//! Quoted values: `%XX` percent-decoded (TR-369: `"` = `%22`, `%` = `%25`).
//! [`Display`](fmt::Display) re-encodes them.
//! Unquoted values: should be numbers, any token accepted.
//! Instance numbers in an expression's relative path: not allowed by TR-369, accepted (lenient).

use std::fmt;

/// Comparison operator in a search expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `>`
    Gt,
    /// `<=`
    Le,
    /// `>=`
    Ge,
}

impl Op {
    fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Gt => ">",
            Self::Le => "<=",
            Self::Ge => ">=",
        }
    }
}

/// List index when following a list-valued reference (`Ref#2+`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefIndex {
    /// One item, 1-based.
    Item(u32),
    /// All items (`#*`).
    All,
}

/// One step of the relative path in a search expression.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelStep {
    /// Parameter or object name, or instance number of a sub-object.
    pub name: String,
    /// Index into a list-valued reference.
    pub index: Option<RefIndex>,
    /// Follow the reference (`+`).
    pub deref: bool,
}

/// `relpath op value` inside `[...]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Expr {
    /// Relative parameter path.
    pub path: Vec<RelStep>,
    pub op: Op,
    /// Quotes removed, percent-decoded.
    pub value: String,
    /// Value was in double quotes.
    pub quoted: bool,
}

/// One path segment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Segment {
    /// Object or item name, e.g. `WiFi`. May have reference suffixes (`#n`, `+`).
    Name(RelStep),
    Instance(u32),
    /// `{i}` placeholder (data model templates).
    Placeholder,
    /// `*`
    Wildcard,
    /// `[alias]` (TR-069 alias-based addressing).
    Alias(String),
    /// `[expr&&expr...]`: unique key addressing or search expression.
    Search(Vec<Expr>),
}

impl Segment {
    fn is_instance_selector(&self) -> bool {
        !matches!(self, Self::Name(_))
    }
}

/// What a path names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target {
    /// Ends with `.` -> object (or set of instances).
    Object,
    Parameter,
    /// `Name()`
    Command,
    /// `Name!`
    Event,
}

/// Parsed path name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Path {
    /// In order. Non-object path -> last one = item name.
    pub segments: Vec<Segment>,
    pub target: Target,
}

/// Malformed path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid path {path:?} at offset {offset}: {reason}")]
pub struct PathError {
    pub path: String,
    /// Byte offset of the problem.
    pub offset: usize,
    pub reason: &'static str,
}

impl Path {
    pub fn parse(input: &str) -> Result<Self, PathError> {
        Parser { s: input, pos: 0 }.path()
    }

    /// Can match more than 1 instance: `*`, `#*`, or search != pure equality (unique key).
    pub fn is_wildcarded(&self) -> bool {
        self.segments.iter().any(|s| match s {
            Segment::Wildcard => true,
            Segment::Search(exprs) => exprs.iter().any(|e| e.op != Op::Eq),
            Segment::Name(step) => step.index == Some(RefIndex::All),
            _ => false,
        })
    }

    /// Path has reference following (`+`).
    pub fn follows_references(&self) -> bool {
        self.segments.iter().any(|s| match s {
            Segment::Name(step) => step.deref,
            Segment::Search(exprs) => exprs.iter().any(|e| e.path.iter().any(|st| st.deref)),
            _ => false,
        })
    }

    /// Data model template path: each instance selector -> `{i}`.
    ///
    /// `None` if the path follows references -> template depends on the referenced object.
    pub fn template(&self) -> Option<String> {
        let mut out = String::new();
        for (i, seg) in self.segments.iter().enumerate() {
            if i > 0 {
                out.push('.');
            }
            match seg {
                Segment::Name(step) if step.deref || step.index.is_some() => return None,
                Segment::Name(step) => out.push_str(&step.name),
                _ => out.push_str("{i}"),
            }
        }
        match self.target {
            Target::Object => out.push('.'),
            Target::Command => out.push_str("()"),
            Target::Event => out.push('!'),
            Target::Parameter => {}
        }
        Some(out)
    }
}

impl fmt::Display for RelStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
        match self.index {
            Some(RefIndex::Item(n)) => write!(f, "#{n}")?,
            Some(RefIndex::All) => f.write_str("#*")?,
            None => {}
        }
        if self.deref {
            f.write_str("+")?;
        }
        Ok(())
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, s) in self.path.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{s}")?;
        }
        f.write_str(self.op.as_str())?;
        if self.quoted {
            f.write_str("\"")?;
            for c in self.value.chars() {
                match c {
                    '"' => f.write_str("%22")?,
                    '%' => f.write_str("%25")?,
                    c => write!(f, "{c}")?,
                }
            }
            f.write_str("\"")
        } else {
            f.write_str(&self.value)
        }
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(step) => write!(f, "{step}"),
            Self::Instance(n) => write!(f, "{n}"),
            Self::Placeholder => f.write_str("{i}"),
            Self::Wildcard => f.write_str("*"),
            Self::Alias(a) => write!(f, "[{a}]"),
            Self::Search(exprs) => {
                f.write_str("[")?;
                for (i, e) in exprs.iter().enumerate() {
                    if i > 0 {
                        f.write_str("&&")?;
                    }
                    write!(f, "{e}")?;
                }
                f.write_str("]")
            }
        }
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, seg) in self.segments.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{seg}")?;
        }
        match self.target {
            Target::Object => f.write_str("."),
            Target::Command => f.write_str("()"),
            Target::Event => f.write_str("!"),
            Target::Parameter => Ok(()),
        }
    }
}

impl std::str::FromStr for Path {
    type Err = PathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

// ---- parser ------------------------------------------------------------------

/// Decode `%XX`; malformed sequences kept as-is.
fn percent_decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_owned();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = b
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok());
        match (b[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

struct Parser<'a> {
    s: &'a str,
    pos: usize,
}

fn is_name_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}

fn is_name_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

impl Parser<'_> {
    fn err(&self, reason: &'static str) -> PathError {
        PathError {
            path: self.s.to_owned(),
            offset: self.pos,
            reason,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.as_bytes().get(self.pos).copied()
    }

    fn eat(&mut self, lit: &str) -> bool {
        if self.s[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            true
        } else {
            false
        }
    }

    fn take_while(&mut self, f: impl Fn(u8) -> bool) -> &str {
        let start = self.pos;
        while self.peek().is_some_and(&f) {
            self.pos += 1;
        }
        &self.s[start..self.pos]
    }

    fn name(&mut self) -> Result<String, PathError> {
        if !self.peek().is_some_and(is_name_start) {
            return Err(self.err("expected a name"));
        }
        Ok(self.take_while(is_name_char).to_owned())
    }

    fn number(&mut self) -> Result<u32, PathError> {
        let digits = self.take_while(|c| c.is_ascii_digit());
        match digits.parse::<u32>() {
            Ok(n) if n > 0 && !digits.starts_with('0') => Ok(n),
            _ => Err(self.err("instance numbers are positive integers without leading zeros")),
        }
    }

    /// `name ["#" (n|"*")] ["+"]`
    fn rel_step(&mut self) -> Result<RelStep, PathError> {
        let name = self.name()?;
        let index = if self.eat("#") {
            Some(if self.eat("*") {
                RefIndex::All
            } else {
                RefIndex::Item(self.number()?)
            })
        } else {
            None
        };
        let deref = self.eat("+");
        if index.is_some() && !deref {
            return Err(self.err("'#' must be followed by '+'"));
        }
        Ok(RelStep { name, index, deref })
    }

    fn op(&mut self) -> Result<Op, PathError> {
        for (lit, op) in [
            ("==", Op::Eq),
            ("!=", Op::Ne),
            ("<=", Op::Le),
            (">=", Op::Ge),
            ("<", Op::Lt),
            (">", Op::Gt),
        ] {
            if self.eat(lit) {
                return Ok(op);
            }
        }
        Err(self.err("expected a comparison operator"))
    }

    fn expr(&mut self) -> Result<Expr, PathError> {
        let mut path = vec![self.rel_step()?];
        while self.eat(".") {
            // After 1st step: sub-object instance numbers allowed.
            if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                let n = self.number()?;
                path.push(RelStep {
                    name: n.to_string(),
                    index: None,
                    deref: false,
                });
            } else {
                path.push(self.rel_step()?);
            }
        }
        let op = self.op()?;
        let (value, quoted) = if self.eat("\"") {
            let start = self.pos;
            let Some(len) = self.s[start..].find('"') else {
                return Err(self.err("unterminated string value"));
            };
            self.pos = start + len + 1;
            (percent_decode(&self.s[start..start + len]), true)
        } else {
            let v = self.take_while(|c| c != b'&' && c != b']');
            if v.is_empty() {
                return Err(self.err("expected a value"));
            }
            (v.to_owned(), false)
        };
        Ok(Expr {
            path,
            op,
            value,
            quoted,
        })
    }

    /// Content of `[...]`, after the `[`.
    fn bracket(&mut self) -> Result<Segment, PathError> {
        // Alias = text up to ']', no operator, no '"'.
        let save = self.pos;
        let alias = self
            .take_while(|c| !matches!(c, b']' | b'=' | b'!' | b'<' | b'>'))
            .to_owned();
        if !alias.is_empty() && self.peek() == Some(b']') && !alias.contains('"') {
            self.pos += 1;
            return Ok(Segment::Alias(alias));
        }
        self.pos = save;

        let mut exprs = vec![self.expr()?];
        while self.eat("&&") {
            exprs.push(self.expr()?);
        }
        if !self.eat("]") {
            return Err(self.err("expected ']' or '&&'"));
        }
        Ok(Segment::Search(exprs))
    }

    fn path(mut self) -> Result<Path, PathError> {
        if self.s.is_empty() {
            return Err(self.err("empty path"));
        }
        let mut segments = Vec::new();
        loop {
            let seg = match self.peek() {
                Some(b'*') => {
                    self.pos += 1;
                    Segment::Wildcard
                }
                Some(b'[') => {
                    self.pos += 1;
                    self.bracket()?
                }
                Some(b'{') => {
                    if !self.eat("{i}") {
                        return Err(self.err("expected '{i}'"));
                    }
                    Segment::Placeholder
                }
                Some(c) if c.is_ascii_digit() => Segment::Instance(self.number()?),
                _ => Segment::Name(self.rel_step()?),
            };
            if seg.is_instance_selector() && segments.is_empty() {
                return Err(self.err("path must start with a name"));
            }
            segments.push(seg);

            match self.peek() {
                None => break,
                Some(b'.') => {
                    self.pos += 1;
                    if self.peek().is_none() {
                        return Ok(Path {
                            segments,
                            target: Target::Object,
                        });
                    }
                }
                Some(b'(') | Some(b'!') => {
                    let target = if self.eat("()") {
                        Target::Command
                    } else if self.eat("!") {
                        Target::Event
                    } else {
                        return Err(self.err("expected '()'"));
                    };
                    if self.peek().is_some() {
                        return Err(self.err("unexpected text after command or event name"));
                    }
                    return match segments.last() {
                        Some(Segment::Name(s)) if !s.deref && s.index.is_none() => {
                            Ok(Path { segments, target })
                        }
                        _ => Err(self.err("command or event must follow a plain name")),
                    };
                }
                Some(_) => return Err(self.err("expected '.'")),
            }
        }
        // No trailing dot -> last segment = parameter.
        match segments.last() {
            Some(Segment::Name(s)) if !s.deref && s.index.is_none() => Ok(Path {
                segments,
                target: Target::Parameter,
            }),
            Some(Segment::Name(_)) => Ok(Path {
                // `Ref+` at end -> referenced object.
                segments,
                target: Target::Object,
            }),
            _ => Err(self.err("object paths must end with '.'")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Path {
        Path::parse(s).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn simple_paths() {
        let path = p("Device.DeviceInfo.SerialNumber");
        assert_eq!(path.target, Target::Parameter);
        assert_eq!(path.segments.len(), 3);
        assert_eq!(p("Device.WiFi.Radio.1.").target, Target::Object);
        assert_eq!(p("Device.Reboot()").target, Target::Command);
        assert_eq!(p("Device.Boot!").target, Target::Event);
        assert_eq!(p("Device.").segments.len(), 1);
    }

    #[test]
    fn templates() {
        assert_eq!(
            p("Device.WiFi.Radio.1.Name").template().as_deref(),
            Some("Device.WiFi.Radio.{i}.Name")
        );
        assert_eq!(
            p("Device.WiFi.Radio.*.").template().as_deref(),
            Some("Device.WiFi.Radio.{i}.")
        );
        assert_eq!(
            p("Device.IP.Interface.[Name==\"wan\"].IPv4Address.{i}.IPAddress")
                .template()
                .as_deref(),
            Some("Device.IP.Interface.{i}.IPv4Address.{i}.IPAddress")
        );
        assert_eq!(
            p("Device.IP.Diagnostics.IPPing()").template().as_deref(),
            Some("Device.IP.Diagnostics.IPPing()")
        );
        assert_eq!(
            p("Device.NAT.PortMapping.1.Interface+.Name").template(),
            None
        );
    }

    #[test]
    fn search_expressions() {
        let path = p(
            r#"Device.WiFi.SSID.[Enable==true&&Status!="Down"&&LowerLayers#1+.Name=="wl0"].BSSID"#,
        );
        let Segment::Search(exprs) = &path.segments[3] else {
            panic!("expected search segment")
        };
        assert_eq!(exprs.len(), 3);
        assert_eq!(
            (exprs[0].op, exprs[0].value.as_str(), exprs[0].quoted),
            (Op::Eq, "true", false)
        );
        assert_eq!(
            (exprs[1].op, exprs[1].value.as_str(), exprs[1].quoted),
            (Op::Ne, "Down", true)
        );
        assert_eq!(exprs[2].path[0].index, Some(RefIndex::Item(1)));
        assert!(exprs[2].path[0].deref);
        assert!(path.is_wildcarded());
        assert!(path.follows_references());

        // Pure equality on unique keys -> one instance.
        let key = p(r#"Device.IP.Interface.[Name=="wan"]."#);
        assert!(!key.is_wildcarded());

        // Quoted values: dots + spaces allowed.
        let ip =
            p(r#"Device.DHCPv4.Server.Pool.1.Client.[IPv4Address.1.IPAddress=="192.168.1.10"]."#);
        let Segment::Search(e) = &ip.segments[6] else {
            panic!()
        };
        assert_eq!(e[0].value, "192.168.1.10");

        let esc = p(r#"Device.X.[Name=="say %22hi%22 100%25 a]b&&c"]."#);
        let Segment::Search(e) = &esc.segments[2] else {
            panic!()
        };
        assert_eq!(e[0].value, r#"say "hi" 100% a]b&&c"#);
        assert_eq!(
            esc.to_string(),
            r#"Device.X.[Name=="say %22hi%22 100%25 a]b&&c"]."#
        );
        // Malformed escapes -> kept as-is.
        let Segment::Search(e) = &p(r#"Device.X.[N=="5%"]."#).segments[2] else {
            panic!()
        };
        assert_eq!(e[0].value, "5%");

        let cmp = p("Device.Hosts.Host.[X_Count>=10&&Y<3].");
        let Segment::Search(e) = &cmp.segments[3] else {
            panic!()
        };
        assert_eq!((e[0].op, e[1].op), (Op::Ge, Op::Lt));
    }

    #[test]
    fn alias_addressing() {
        let path = p("Device.WiFi.SSID.[cpe-ssid-1].SSID");
        assert_eq!(path.segments[3], Segment::Alias("cpe-ssid-1".into()));
        assert_eq!(
            path.template().as_deref(),
            Some("Device.WiFi.SSID.{i}.SSID")
        );
    }

    #[test]
    fn display_round_trips() {
        for s in [
            "Device.",
            "Device.WiFi.Radio.1.Name",
            "Device.WiFi.Radio.*.",
            "Device.WiFi.Radio.{i}.Stats.",
            "Device.Reboot()",
            "Device.Boot!",
            "Device.WiFi.SSID.[cpe-1].",
            r#"Device.IP.Interface.[Name=="wan"&&Enable==true].Status"#,
            "Device.NAT.PortMapping.1.Interface+.Name",
            "Device.WiFi.SSID.1.LowerLayers#*+.",
        ] {
            assert_eq!(p(s).to_string(), s);
        }
    }

    #[test]
    fn rejects_malformed() {
        for s in [
            "",
            ".Device",
            "Device..WiFi",
            "Device.WiFi.Radio.0.",
            "Device.WiFi.Radio.01.",
            "Device.WiFi.Radio.1",
            "Device.WiFi.Radio.*",
            "Device.WiFi.[Name==\"x].",
            "Device.WiFi.[Name=].",
            "Device.WiFi.[Name~\"x\"].",
            "Device.Reboot()x",
            "1.Device.",
            "Device.WiFi.SSID.1.LowerLayers#1.",
            "Device.{x}.",
        ] {
            assert!(Path::parse(s).is_err(), "{s:?} should be rejected");
        }
    }
}
