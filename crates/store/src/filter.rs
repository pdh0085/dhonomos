//! Device filter expressions (NB-01, ADR-079), e.g.
//!
//! ```text
//! product_class = "HG8245" and (tag = east or attr.region = busan)
//!   and last_contact > 1d and not param."Device.WiFi.SSID.1.Enable" = false
//! ```
//!
//! - Combine: `and`, `or`, `not`, parentheses. `and` binds tighter than `or`.
//! - Operators: `=`, `!=`, `~` (contains, case-insensitive), `!~`;
//!   `<`, `<=`, `>`, `>=` for numbers (parameters) + ages (times); `exists` after a field.
//! - Fields: `serial`, `endpoint_id`, `oui`, `product_class`, `manufacturer`, `model`,
//!   `version` (`software_version`), `hardware_version`, `protocol`, `status`, `address`,
//!   `data_model`; `tag`; `attr.<key>`; `param.<path>` (quote paths: `param."Device.X"`).
//! - Ages: `last_contact`, `last_boot`, `first_seen` (`5m`, `2h`, `7d`, `1w`).
//! - Flags with `= true`, `= false` or `exists`: `xmpp_connected` = live XMPP session,
//!   `udp_cr` = UDP CR address known, `wg_member` = live WireGuard device member.
//! - `wg_handshake`: age of latest WireGuard handshake (hub report) over the device's live
//!   device members. `< 3m` -> some member had one within 3 min; `> 15m` -> some member had
//!   none for 15 min, or never; `exists` -> some member had one. No member -> none match.
//!
//! Field names from a fixed list + every value a bound parameter -> no SQL injection.

use std::fmt;

use sqlx::{Postgres, QueryBuilder};

/// Max expression length, bytes.
const MAX_LEN: usize = 2000;
/// Max conditions per expression.
const MAX_CONDITIONS: usize = 50;
/// Max nesting depth of parentheses + `not`.
const MAX_DEPTH: usize = 20;

/// Parse error + byte offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterError {
    pub message: String,
    /// Byte offset in the expression.
    pub at: usize,
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "filter, at character {}: {}", self.at + 1, self.message)
    }
}

impl std::error::Error for FilterError {}

/// Parsed + validated filter expression.
#[derive(Debug, Clone, PartialEq)]
pub struct FilterExpr(Node);

#[derive(Debug, Clone, PartialEq)]
enum Node {
    And(Vec<Node>),
    Or(Vec<Node>),
    Not(Box<Node>),
    Cond(Cond),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Eq,
    Ne,
    Like,
    NotLike,
    Lt,
    Le,
    Gt,
    Ge,
    Exists,
}

#[derive(Debug, Clone, PartialEq)]
enum Field {
    /// Text column = SQL expression on `d`.
    Column(&'static str),
    Tag,
    Attr(String),
    Param(String),
    /// Timestamp column, compared by age.
    Age(&'static str),
    /// Yes/no fact = SQL condition on `d`, never NULL.
    Flag(&'static str),
    /// Age of latest handshake over the device's live WireGuard device members.
    WgHandshake,
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    None,
    Text(String),
    Number(f64),
    /// Seconds.
    Age(f64),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq)]
struct Cond {
    field: Field,
    op: Op,
    value: Value,
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    LParen,
    RParen,
    Op(Op),
    /// Bare word: field, keyword or value.
    Word(String),
    Quoted(String),
}

fn err<T>(at: usize, message: impl Into<String>) -> Result<T, FilterError> {
    Err(FilterError {
        message: message.into(),
        at,
    })
}

fn lex(text: &str) -> Result<Vec<(usize, Tok)>, FilterError> {
    let mut out = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some(&(at, c)) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' | ')' => {
                chars.next();
                out.push((at, if c == '(' { Tok::LParen } else { Tok::RParen }));
            }
            '"' | '\'' => {
                chars.next();
                let mut s = String::new();
                let mut closed = false;
                while let Some((_, ch)) = chars.next() {
                    match ch {
                        '\\' => match chars.next() {
                            Some((_, e)) => s.push(e),
                            None => break,
                        },
                        ch if ch == c => {
                            closed = true;
                            break;
                        }
                        ch => s.push(ch),
                    }
                }
                if !closed {
                    return err(at, "unterminated quote");
                }
                out.push((at, Tok::Quoted(s)));
            }
            '=' | '!' | '~' | '<' | '>' => {
                chars.next();
                let next = chars.peek().map(|&(_, n)| n);
                let op = match (c, next) {
                    ('!', Some('=')) => Op::Ne,
                    ('!', Some('~')) => Op::NotLike,
                    ('<', Some('=')) => Op::Le,
                    ('>', Some('=')) => Op::Ge,
                    ('=', _) => Op::Eq,
                    ('~', _) => Op::Like,
                    ('<', _) => Op::Lt,
                    ('>', _) => Op::Gt,
                    _ => return err(at, "expected != or !~"),
                };
                if matches!(op, Op::Ne | Op::NotLike | Op::Le | Op::Ge) {
                    chars.next();
                }
                out.push((at, Tok::Op(op)));
            }
            _ => {
                let mut s = String::new();
                while let Some(&(_, ch)) = chars.peek() {
                    if ch.is_whitespace()
                        || matches!(ch, '(' | ')' | '=' | '!' | '~' | '<' | '>' | '"' | '\'')
                    {
                        break;
                    }
                    s.push(ch);
                    chars.next();
                }
                out.push((at, Tok::Word(s)));
            }
        }
    }
    Ok(out)
}

struct Parser {
    toks: Vec<(usize, Tok)>,
    pos: usize,
    end: usize,
    conditions: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|(_, t)| t)
    }

    fn at(&self) -> usize {
        self.toks.get(self.pos).map_or(self.end, |(a, _)| *a)
    }

    fn keyword(&self, k: &str) -> bool {
        matches!(self.peek(), Some(Tok::Word(w)) if w.eq_ignore_ascii_case(k))
    }

    fn or(&mut self, depth: usize) -> Result<Node, FilterError> {
        let mut parts = vec![self.and(depth)?];
        while self.keyword("or") {
            self.pos += 1;
            parts.push(self.and(depth)?);
        }
        Ok(if parts.len() == 1 {
            parts.remove(0)
        } else {
            Node::Or(parts)
        })
    }

    fn and(&mut self, depth: usize) -> Result<Node, FilterError> {
        let mut parts = vec![self.not(depth)?];
        while self.keyword("and") {
            self.pos += 1;
            parts.push(self.not(depth)?);
        }
        Ok(if parts.len() == 1 {
            parts.remove(0)
        } else {
            Node::And(parts)
        })
    }

    fn not(&mut self, depth: usize) -> Result<Node, FilterError> {
        if depth > MAX_DEPTH {
            return err(self.at(), "nested too deeply");
        }
        if self.keyword("not") {
            self.pos += 1;
            return Ok(Node::Not(Box::new(self.not(depth + 1)?)));
        }
        if self.peek() == Some(&Tok::LParen) {
            self.pos += 1;
            let inner = self.or(depth + 1)?;
            if self.peek() != Some(&Tok::RParen) {
                return err(self.at(), "expected )");
            }
            self.pos += 1;
            return Ok(inner);
        }
        self.cond()
    }

    fn cond(&mut self) -> Result<Node, FilterError> {
        let at = self.at();
        self.conditions += 1;
        if self.conditions > MAX_CONDITIONS {
            return err(at, format!("at most {MAX_CONDITIONS} conditions"));
        }
        let field = match self.toks.get(self.pos) {
            Some((_, Tok::Word(w))) => {
                let w = w.clone();
                self.pos += 1;
                field(&w, at, self)?
            }
            Some(_) => return err(at, "expected a field"),
            None => return err(at, "expected a condition"),
        };
        let op_at = self.at();
        let op = match self.peek() {
            Some(Tok::Op(op)) => *op,
            Some(Tok::Word(w)) if w.eq_ignore_ascii_case("exists") => Op::Exists,
            _ => return err(op_at, "expected an operator (= != ~ !~ < <= > >= exists)"),
        };
        self.pos += 1;
        let value = if op == Op::Exists {
            Value::None
        } else {
            let v_at = self.at();
            let raw = match self.toks.get(self.pos) {
                Some((_, Tok::Word(w) | Tok::Quoted(w))) => w.clone(),
                _ => return err(v_at, "expected a value"),
            };
            self.pos += 1;
            value(&field, op, &raw, v_at)?
        };
        Ok(Node::Cond(Cond { field, op, value }))
    }
}

/// Field named `w`. `param.` may take its path from the next (quoted) token.
fn field(w: &str, at: usize, p: &mut Parser) -> Result<Field, FilterError> {
    let lower = w.to_ascii_lowercase();
    let column = match lower.as_str() {
        "serial" | "serial_number" => Some("d.serial_number"),
        "endpoint_id" => Some("d.endpoint_id"),
        "oui" => Some("d.oui"),
        "product_class" => Some("d.product_class"),
        "manufacturer" => Some("d.manufacturer"),
        "model" | "model_name" => Some("d.model_name"),
        "version" | "software_version" => Some("d.software_version"),
        "hardware_version" => Some("d.hardware_version"),
        "protocol" => Some("d.protocol"),
        "status" => Some("d.status"),
        "address" => Some("host(d.last_remote_addr)"),
        "data_model" => Some("d.data_model"),
        _ => None,
    };
    if let Some(c) = column {
        return Ok(Field::Column(c));
    }
    match lower.as_str() {
        "tag" | "tags" => return Ok(Field::Tag),
        "last_contact" => return Ok(Field::Age("d.last_contact_at")),
        "last_boot" => return Ok(Field::Age("d.last_boot_at")),
        "first_seen" => return Ok(Field::Age("d.first_seen_at")),
        "xmpp_connected" => return Ok(Field::Flag("d.xmpp_connected_at IS NOT NULL")),
        "udp_cr" => return Ok(Field::Flag("d.udp_cr_address IS NOT NULL")),
        "wg_member" => {
            return Ok(Field::Flag(
                "EXISTS (SELECT 1 FROM wg_members m WHERE m.device_id = d.id AND m.kind = 'device' AND m.revoked_at IS NULL)",
            ));
        }
        "wg_handshake" => return Ok(Field::WgHandshake),
        _ => {}
    }
    if let Some(key) = w.strip_prefix("attr.") {
        if key.is_empty() || key.len() > 64 {
            return err(at, "attr.<key> needs a key of up to 64 characters");
        }
        return Ok(Field::Attr(key.to_owned()));
    }
    if w == "param." {
        // param."Device.Path" -> path = next quoted token.
        if let Some((_, Tok::Quoted(path))) = p.toks.get(p.pos) {
            let path = path.clone();
            p.pos += 1;
            return param(path, at);
        }
        return err(
            at,
            "param. needs a path, e.g. param.\"Device.DeviceInfo.UpTime\"",
        );
    }
    if let Some(path) = w.strip_prefix("param.") {
        return param(path.to_owned(), at);
    }
    err(
        at,
        format!(
            "unknown field {w:?} (serial, oui, product_class, model, version, protocol, status, tag, attr.<key>, param.<path>, last_contact, xmpp_connected, udp_cr, wg_member, wg_handshake, ...)"
        ),
    )
}

fn param(path: String, at: usize) -> Result<Field, FilterError> {
    if path.is_empty() || path.len() > 256 {
        return err(at, "parameter paths are 1-256 characters");
    }
    Ok(Field::Param(path))
}

/// `5m`, `2h`, `7d`, `1w` or plain seconds -> seconds.
fn age(raw: &str) -> Option<f64> {
    let (num, unit) = raw.split_at(
        raw.find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(raw.len()),
    );
    let n: f64 = num.parse().ok()?;
    let factor = match unit {
        "" | "s" => 1.0,
        "m" => 60.0,
        "h" => 3600.0,
        "d" => 86_400.0,
        "w" => 604_800.0,
        _ => return None,
    };
    Some(n * factor)
}

fn value(field: &Field, op: Op, raw: &str, at: usize) -> Result<Value, FilterError> {
    let ordered = matches!(op, Op::Lt | Op::Le | Op::Gt | Op::Ge);
    match field {
        Field::Age(_) | Field::WgHandshake => {
            if !ordered {
                return err(at, "times compare by age: use < or > with 5m, 2h, 7d, 1w");
            }
            age(raw).map(Value::Age).map_or_else(
                || err(at, format!("{raw:?} is not an age like 5m, 2h, 7d or 1w")),
                Ok,
            )
        }
        Field::Flag(_) => {
            if !matches!(op, Op::Eq | Op::Ne) {
                return err(at, "this field is true or false: use = or !=");
            }
            match raw.to_ascii_lowercase().as_str() {
                "true" => Ok(Value::Bool(true)),
                "false" => Ok(Value::Bool(false)),
                _ => err(at, format!("{raw:?} is not true or false")),
            }
        }
        Field::Param(_) if ordered => raw
            .parse::<f64>()
            .ok()
            .filter(|n| n.is_finite())
            .map_or_else(
                || err(at, format!("{raw:?} is not a number")),
                |n| Ok(Value::Number(n)),
            ),
        _ if ordered => err(at, "< and > work on parameters (numbers) and times (ages)"),
        _ => Ok(Value::Text(raw.to_owned())),
    }
}

/// `ILIKE` pattern for a substring. `%`, `_`, `\` literal.
fn contains(v: &str) -> String {
    format!(
        "%{}%",
        v.replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    )
}

impl FilterExpr {
    pub fn parse(text: &str) -> Result<Self, FilterError> {
        if text.len() > MAX_LEN {
            return err(MAX_LEN, format!("at most {MAX_LEN} characters"));
        }
        let mut p = Parser {
            toks: lex(text)?,
            pos: 0,
            end: text.len(),
            conditions: 0,
        };
        if p.toks.is_empty() {
            return err(0, "empty filter");
        }
        let node = p.or(0)?;
        if p.pos < p.toks.len() {
            return err(p.at(), "expected and, or, or the end");
        }
        Ok(Self(node))
    }

    /// Append as SQL condition on devices row `d`.
    pub fn push_sql(&self, qb: &mut QueryBuilder<Postgres>) {
        push_node(&self.0, qb);
    }
}

fn push_node(node: &Node, qb: &mut QueryBuilder<Postgres>) {
    match node {
        Node::And(parts) | Node::Or(parts) => {
            let joiner = if matches!(node, Node::And(_)) {
                " AND "
            } else {
                " OR "
            };
            qb.push("(");
            for (i, p) in parts.iter().enumerate() {
                if i > 0 {
                    qb.push(joiner);
                }
                push_node(p, qb);
            }
            qb.push(")");
        }
        Node::Not(inner) => {
            // NULL (unknown) = false -> `not` matches what inner does not.
            qb.push("NOT COALESCE(");
            push_node(inner, qb);
            qb.push(", false)");
        }
        Node::Cond(c) => push_cond(c, qb),
    }
}

fn push_text_op(qb: &mut QueryBuilder<Postgres>, lhs: &str, op: Op, v: &str) {
    match op {
        Op::Eq => {
            qb.push(format!("{lhs} = ")).push_bind(v.to_owned());
        }
        Op::Ne => {
            qb.push(format!("{lhs} IS DISTINCT FROM "))
                .push_bind(v.to_owned());
        }
        Op::Like => {
            qb.push(format!("{lhs} ILIKE ")).push_bind(contains(v));
        }
        Op::NotLike => {
            qb.push(format!("COALESCE({lhs}, '') NOT ILIKE "))
                .push_bind(contains(v));
        }
        _ => {
            qb.push(format!("{lhs} IS NOT NULL"));
        }
    }
}

fn push_cond(c: &Cond, qb: &mut QueryBuilder<Postgres>) {
    let text = match &c.value {
        Value::Text(t) => t.as_str(),
        _ => "",
    };
    match &c.field {
        Field::Column(col) => {
            qb.push("(");
            push_text_op(qb, col, c.op, text);
            qb.push(")");
        }
        Field::Tag => match c.op {
            Op::Eq => {
                qb.push("(")
                    .push_bind(text.to_owned())
                    .push(" = ANY(d.tags))");
            }
            Op::Ne => {
                qb.push("(NOT (")
                    .push_bind(text.to_owned())
                    .push(" = ANY(d.tags)))");
            }
            Op::Like | Op::NotLike => {
                if c.op == Op::NotLike {
                    qb.push("NOT ");
                }
                qb.push("EXISTS (SELECT 1 FROM unnest(d.tags) t WHERE t ILIKE ")
                    .push_bind(contains(text))
                    .push(")");
            }
            _ => {
                qb.push("(cardinality(d.tags) > 0)");
            }
        },
        Field::Attr(key) => match c.op {
            // Exact value -> GIN index.
            Op::Eq => {
                qb.push("(d.attributes @> ")
                    .push_bind(serde_json::json!({ key: text }))
                    .push(")");
            }
            Op::Ne => {
                qb.push("(NOT d.attributes @> ")
                    .push_bind(serde_json::json!({ key: text }))
                    .push(")");
            }
            Op::Exists => {
                qb.push("(d.attributes ? ").push_bind(key.clone()).push(")");
            }
            Op::NotLike => {
                qb.push("(COALESCE(d.attributes ->> ")
                    .push_bind(key.clone())
                    .push(", '') NOT ILIKE ")
                    .push_bind(contains(text))
                    .push(")");
            }
            _ => {
                qb.push("((d.attributes ->> ")
                    .push_bind(key.clone())
                    .push(") ILIKE ")
                    .push_bind(contains(text))
                    .push(")");
            }
        },
        Field::Param(path) => {
            qb.push("EXISTS (SELECT 1 FROM device_params p WHERE p.device_id = d.id AND p.path = ")
                .push_bind(path.clone())
                .push(" AND ");
            match (&c.value, c.op) {
                (Value::Number(n), op) => {
                    let sym = match op {
                        Op::Lt => "<",
                        Op::Le => "<=",
                        Op::Gt => ">",
                        _ => ">=",
                    };
                    qb.push(r"p.value ~ '^\s*-?[0-9]+(\.[0-9]+)?\s*$' AND trim(p.value)::numeric ")
                        .push(sym)
                        .push(" ")
                        .push_bind(*n)
                        .push("::float8::numeric");
                }
                // Equality via prefix index `(path, left(value, 256))`.
                // Btree cannot hold long values -> index has first 256 chars, exact compare after.
                (_, Op::Eq) => {
                    qb.push("left(p.value, 256) = left(")
                        .push_bind(text.to_owned())
                        .push("::text, 256) AND p.value = ")
                        .push_bind(text.to_owned());
                }
                (_, op) => push_text_op(qb, "p.value", op, text),
            }
            qb.push(")");
        }
        Field::Flag(condition) => {
            // `exists`: no value -> true.
            let wanted = match (c.op, &c.value) {
                (Op::Eq, Value::Bool(b)) => *b,
                (Op::Ne, Value::Bool(b)) => !*b,
                _ => true,
            };
            if wanted {
                qb.push(format!("({condition})"));
            } else {
                qb.push(format!("(NOT ({condition}))"));
            }
        }
        Field::Age(col) => {
            // `exists`: time known (device ever contacted, booted, seen).
            if c.op == Op::Exists {
                qb.push(format!("({col} IS NOT NULL)"));
                return;
            }
            let Value::Age(secs) = c.value else {
                // Every condition must write SQL -> empty one breaks the query around it.
                qb.push("FALSE");
                return;
            };
            // `<` -> within; `>` -> older or never.
            match c.op {
                Op::Lt | Op::Le => {
                    qb.push(format!("({col} > now() - make_interval(secs => "))
                        .push_bind(secs)
                        .push("))");
                }
                _ => {
                    qb.push(format!(
                        "({col} IS NULL OR {col} < now() - make_interval(secs => "
                    ))
                    .push_bind(secs)
                    .push("))");
                }
            }
        }
        Field::WgHandshake => {
            qb.push(
                "EXISTS (SELECT 1 FROM wg_members m LEFT JOIN wg_peer_status s ON s.member_id = m.id \
                 WHERE m.device_id = d.id AND m.kind = 'device' AND m.revoked_at IS NULL AND ",
            );
            match (c.op, &c.value) {
                (Op::Exists, _) => {
                    qb.push("s.latest_handshake IS NOT NULL");
                }
                // Within -> some member had a handshake that recently.
                (Op::Lt | Op::Le, Value::Age(secs)) => {
                    qb.push("s.latest_handshake > now() - make_interval(secs => ")
                        .push_bind(*secs)
                        .push(")");
                }
                // Older -> some member had none since, or never.
                (_, Value::Age(secs)) => {
                    qb.push(
                        "(s.latest_handshake IS NULL OR s.latest_handshake < now() - make_interval(secs => ",
                    )
                    .push_bind(*secs)
                    .push("))");
                }
                _ => {
                    qb.push("FALSE");
                }
            }
            qb.push(")");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sql(text: &str) -> String {
        let f = FilterExpr::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
        let mut qb = QueryBuilder::new("");
        f.push_sql(&mut qb);
        qb.into_string()
    }

    #[test]
    fn precedence_and_grouping() {
        assert_eq!(
            sql("oui = A or oui = B and tag = x"),
            "((d.oui = $1) OR ((d.oui = $2) AND ($3 = ANY(d.tags))))"
        );
        assert_eq!(
            sql("(oui = A or oui = B) and not tag = x"),
            "(((d.oui = $1) OR (d.oui = $2)) AND NOT COALESCE(($3 = ANY(d.tags)), false))"
        );
    }

    #[test]
    fn values_are_bound_never_spliced() {
        let s = sql(r#"serial = "x'); DROP TABLE devices; --" and attr.plan = gold"#);
        assert!(!s.contains("DROP"), "{s}");
        assert!(s.contains("$1") && s.contains("d.attributes @> $2"), "{s}");
    }

    #[test]
    fn fields_and_operators() {
        assert!(sql("last_contact > 1d").contains("d.last_contact_at IS NULL OR"));
        assert!(sql("last_contact < 15m").contains("d.last_contact_at > now()"));
        assert!(sql(r#"param."Device.DeviceInfo.UpTime" >= 3600"#).contains("::numeric >="));
        assert!(sql("param.Device.X ~ abc").contains("p.value ILIKE"));
        assert!(
            sql("param.Device.X = abc")
                .contains("left(p.value, 256) = left($2::text, 256) AND p.value = $3"),
            "equality must use the prefix index and still compare the whole value"
        );
        assert!(sql("attr.subscriber exists").contains("d.attributes ?"));
        assert!(sql("attr.line !~ x").contains("COALESCE(d.attributes ->> $1, '') NOT ILIKE $2"));
        assert!(sql("model !~ lab").contains("NOT ILIKE"));
        assert!(sql("version != 2.0").contains("IS DISTINCT FROM"));
    }

    #[test]
    fn flags_are_true_or_false() {
        assert_eq!(
            sql("xmpp_connected = true"),
            "(d.xmpp_connected_at IS NOT NULL)"
        );
        assert_eq!(
            sql("xmpp_connected = FALSE"),
            "(NOT (d.xmpp_connected_at IS NOT NULL))"
        );
        assert_eq!(
            sql("xmpp_connected != true"),
            "(NOT (d.xmpp_connected_at IS NOT NULL))"
        );
        assert_eq!(sql("udp_cr exists"), "(d.udp_cr_address IS NOT NULL)");
        // Times take `exists` too. Old bug: no SQL -> broken query.
        assert_eq!(
            sql("last_contact exists"),
            "(d.last_contact_at IS NOT NULL)"
        );
        assert_eq!(
            sql("tag = a and last_boot exists"),
            format!("({} AND (d.last_boot_at IS NOT NULL))", sql("tag = a"))
        );
        assert_eq!(
            sql("not udp_cr exists"),
            "NOT COALESCE((d.udp_cr_address IS NOT NULL), false)"
        );
        assert_eq!(
            sql("xmpp_connected = true and not udp_cr = true"),
            "((d.xmpp_connected_at IS NOT NULL) AND NOT COALESCE((d.udp_cr_address IS NOT NULL), false))"
        );
        let e = |t: &str| FilterExpr::parse(t).unwrap_err();
        assert!(
            e("xmpp_connected = maybe")
                .message
                .contains("true or false")
        );
        assert!(e("udp_cr > 3").message.contains("= or !="));
        assert!(e("udp_cr ~ x").message.contains("= or !="));
        assert_eq!(e("xmpp_connected = maybe").at, 17);
    }

    #[test]
    fn wireguard_fields() {
        let member = "EXISTS (SELECT 1 FROM wg_members m WHERE m.device_id = d.id AND m.kind = 'device' AND m.revoked_at IS NULL)";
        assert_eq!(sql("wg_member = true"), format!("({member})"));
        assert_eq!(sql("wg_member exists"), format!("({member})"));
        assert_eq!(sql("wg_member = false"), format!("(NOT ({member}))"));
        let handshake = "EXISTS (SELECT 1 FROM wg_members m LEFT JOIN wg_peer_status s ON s.member_id = m.id \
                         WHERE m.device_id = d.id AND m.kind = 'device' AND m.revoked_at IS NULL AND ";
        let within = format!("{handshake}s.latest_handshake > now() - make_interval(secs => $1))");
        assert_eq!(sql("wg_handshake < 3m"), within);
        assert_eq!(sql("wg_handshake <= 3m"), within);
        let older = format!(
            "{handshake}(s.latest_handshake IS NULL OR s.latest_handshake < now() - make_interval(secs => $1)))"
        );
        assert_eq!(sql("wg_handshake > 15m"), older);
        assert_eq!(sql("wg_handshake >= 15m"), older);
        assert_eq!(
            sql("wg_handshake exists"),
            format!("{handshake}s.latest_handshake IS NOT NULL)")
        );
        assert_eq!(
            sql("wg_member = true and not wg_handshake exists"),
            format!(
                "(({member}) AND NOT COALESCE({handshake}s.latest_handshake IS NOT NULL), false))"
            )
        );
        let e = |t: &str| FilterExpr::parse(t).unwrap_err();
        assert!(e("wg_handshake = 3m").message.contains("age"));
        assert!(e("wg_handshake > soon").message.contains("age"));
        assert!(e("wg_member > 3").message.contains("= or !="));
        assert!(e("wireguard = true").message.contains("wg_handshake"));
    }

    #[test]
    fn errors_point_at_the_problem() {
        let e = |t: &str| FilterExpr::parse(t).unwrap_err();
        assert_eq!(e("colour = red").at, 0);
        assert!(e("oui = A and").message.contains("condition"));
        assert_eq!(e("oui = A )").at, 8);
        assert!(e("last_contact = 1d").message.contains("age"));
        assert!(e("last_contact > soon").message.contains("age"));
        assert!(e("oui > 3").message.contains("< and >"));
        assert!(e("param.X > high").message.contains("number"));
        assert!(e("serial = \"open").message.contains("quote"));
        assert!(e("").message.contains("empty"));
        let deep = format!("{}oui = A{}", "(".repeat(30), ")".repeat(30));
        assert!(e(&deep).message.contains("deeply"));
        let many = vec!["oui = A"; 60].join(" or ");
        assert!(e(&many).message.contains("at most"));
    }
}
