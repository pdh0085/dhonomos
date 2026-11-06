//! Server output: stream header, features, stream errors, SASL results, few stanzas.
//! Every value from outside -> escaped.

use crate::Condition;

/// STARTTLS (RFC 6120 sec. 5).
pub(crate) const NS_TLS: &str = "urn:ietf:params:xml:ns:xmpp-tls";
/// SASL (RFC 6120 sec. 6).
pub(crate) const NS_SASL: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
/// Resource binding (RFC 6120 sec. 7).
pub(crate) const NS_BIND: &str = "urn:ietf:params:xml:ns:xmpp-bind";
/// Old session step (RFC 3921), still sent by some clients.
pub(crate) const NS_SESSION: &str = "urn:ietf:params:xml:ns:xmpp-session";
pub(crate) const NS_STANZAS: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";
const NS_STREAM_ERRORS: &str = "urn:ietf:params:xml:ns:xmpp-streams";
/// XMPP Ping (XEP-0199).
pub(crate) const NS_PING: &str = "urn:xmpp:ping";
/// TR-069 Annex K CR.
pub(crate) const NS_CONNREQ: &str = "urn:broadband-forum-org:cwmp:xmppConnReq-1-0";

pub(crate) const STREAM_CLOSE: &str = "</stream:stream>";

/// `s` as text or as a value in double quotes.
/// Chars not allowed in XML 1.0 -> callers drop them before ([`representable`]).
pub(crate) fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\r' => out.push_str("&#13;"),
            '\n' => out.push_str("&#10;"),
            '\t' => out.push_str("&#9;"),
            c => out.push(c),
        }
    }
    out
}

/// `s` fits in XML 1.0 text: no control chars except tab, LF, CR.
pub(crate) fn representable(s: &str) -> bool {
    s.chars().all(|c| {
        matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && c != '\u{FFFE}' && c != '\u{FFFF}')
    })
}

/// Server stream header. `id` = random, unique to this stream.
pub(crate) fn stream_header(id: &str, domain: &str) -> String {
    format!(
        "<?xml version='1.0'?><stream:stream xmlns=\"jabber:client\" \
         xmlns:stream=\"http://etherx.jabber.org/streams\" id=\"{}\" from=\"{}\" \
         version=\"1.0\" xml:lang=\"en\">",
        escape(id),
        escape(domain)
    )
}

/// Stream offer at one negotiation step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Features {
    /// Before TLS: STARTTLS, required.
    StartTls,
    /// After TLS: SASL PLAIN.
    Sasl,
    /// After SASL: resource bind + old session step as optional.
    Bind,
}

pub(crate) fn features(f: Features) -> String {
    let inner = match f {
        Features::StartTls => format!("<starttls xmlns=\"{NS_TLS}\"><required/></starttls>"),
        Features::Sasl => {
            format!("<mechanisms xmlns=\"{NS_SASL}\"><mechanism>PLAIN</mechanism></mechanisms>")
        }
        Features::Bind => format!(
            "<bind xmlns=\"{NS_BIND}\"/><session xmlns=\"{NS_SESSION}\"><optional/></session>"
        ),
    };
    format!("<stream:features>{inner}</stream:features>")
}

pub(crate) fn proceed() -> String {
    format!("<proceed xmlns=\"{NS_TLS}\"/>")
}

pub(crate) fn sasl_success() -> String {
    format!("<success xmlns=\"{NS_SASL}\"/>")
}

pub(crate) fn sasl_challenge() -> String {
    format!("<challenge xmlns=\"{NS_SASL}\"/>")
}

/// SASL failure. `condition` = name from RFC 6120 sec. 6.5.
pub(crate) fn sasl_failure(condition: &str) -> String {
    format!("<failure xmlns=\"{NS_SASL}\"><{condition}/></failure>")
}

/// Stream error + stream end.
pub(crate) fn stream_error(c: Condition) -> String {
    format!(
        "<stream:error><{} xmlns=\"{NS_STREAM_ERRORS}\"/></stream:error>{STREAM_CLOSE}",
        c.name()
    )
}

fn attr(out: &mut String, name: &str, value: Option<&str>) {
    if let Some(v) = value {
        out.push(' ');
        out.push_str(name);
        out.push_str("=\"");
        out.push_str(&escape(v));
        out.push('"');
    }
}

/// Empty `iq` of type `result`.
pub(crate) fn iq_result(id: &str, from: Option<&str>, to: &str) -> String {
    let mut out = String::from("<iq type=\"result\"");
    attr(&mut out, "id", Some(id));
    attr(&mut out, "from", from);
    attr(&mut out, "to", Some(to));
    out.push_str("/>");
    out
}

/// `iq` result of a resource bind.
pub(crate) fn bind_result(id: &str, jid: &str) -> String {
    let mut out = String::from("<iq type=\"result\"");
    attr(&mut out, "id", Some(id));
    out.push_str(&format!(
        "><bind xmlns=\"{NS_BIND}\"><jid>{}</jid></bind></iq>",
        escape(jid)
    ));
    out
}

/// Stanza error reply (RFC 6120 sec. 8.3).
///
/// `stanza` = `iq`, `message` or `presence`. `error_type` = `cancel`, `modify`, `auth`, `wait`.
/// `condition` = defined condition name. Request payload not repeated.
pub(crate) fn stanza_error(
    stanza: &str,
    id: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
    error_type: &str,
    condition: &str,
) -> String {
    let mut out = format!("<{stanza} type=\"error\"");
    attr(&mut out, "id", id);
    attr(&mut out, "from", from);
    attr(&mut out, "to", to);
    out.push_str(&format!(
        "><error type=\"{error_type}\"><{condition} xmlns=\"{NS_STANZAS}\"/></error></{stanza}>"
    ));
    out
}

/// CR (TR-069 Annex K): `iq` of type `get`, ACS -> device.
///
/// Always `id`, `from`, `to`, `type` -> else xmppc of some devices crashes.
/// Credentials escaped, never logged. `None` if one has a char XML cannot carry.
pub(crate) fn connection_request(
    id: &str,
    from: &str,
    to: &str,
    username: &str,
    password: &str,
) -> Option<String> {
    if !representable(username) || !representable(password) {
        return None;
    }
    Some(format!(
        "<iq type=\"get\" id=\"{}\" from=\"{}\" to=\"{}\"><connectionRequest xmlns=\"{NS_CONNREQ}\">\
         <username>{}</username><password>{}</password></connectionRequest></iq>",
        escape(id),
        escape(from),
        escape(to),
        escape(username),
        escape(password)
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn escaping() {
        assert_eq!(
            escape("a&b<c>\"d'\r\n\t"),
            "a&amp;b&lt;c&gt;&quot;d&apos;&#13;&#10;&#9;"
        );
        assert_eq!(escape("plain text"), "plain text");
    }

    #[test]
    fn representable_text() {
        assert!(representable("pa ss\tword\n"));
        assert!(
            !representable("a\u{0}b") && !representable("\u{1b}") && !representable("\u{FFFF}")
        );
    }

    #[test]
    fn connection_request_has_every_attribute_and_escapes() {
        let s = connection_request(
            "cr-1",
            "acs@example.net/dhonomos",
            "dev@example.net/cwmp-1",
            "us<er",
            "p&ss\"w'rd",
        )
        .unwrap_or_default();
        assert_eq!(
            s,
            "<iq type=\"get\" id=\"cr-1\" from=\"acs@example.net/dhonomos\" \
             to=\"dev@example.net/cwmp-1\"><connectionRequest \
             xmlns=\"urn:broadband-forum-org:cwmp:xmppConnReq-1-0\"><username>us&lt;er</username>\
             <password>p&amp;ss&quot;w&apos;rd</password></connectionRequest></iq>"
        );
        assert_eq!(connection_request("i", "f", "t", "u\u{0}", "p"), None);
        assert_eq!(connection_request("i", "f", "t", "u", "p\u{7}"), None);
    }

    #[test]
    fn stanza_errors_carry_no_payload() {
        assert_eq!(
            stanza_error(
                "iq",
                Some("7"),
                Some("example.net"),
                Some("d@example.net/r"),
                "cancel",
                "service-unavailable"
            ),
            "<iq type=\"error\" id=\"7\" from=\"example.net\" to=\"d@example.net/r\"><error type=\"cancel\">\
             <service-unavailable xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\"/></error></iq>"
        );
        assert!(
            stanza_error("iq", None, None, Some("x"), "modify", "bad-request")
                .starts_with("<iq type=\"error\" to=\"x\">")
        );
    }

    #[test]
    fn stream_pieces() {
        assert!(
            stream_header("abc", "example.net")
                .contains("id=\"abc\" from=\"example.net\" version=\"1.0\"")
        );
        assert_eq!(
            stream_error(Condition::RestrictedXml),
            "<stream:error><restricted-xml xmlns=\"urn:ietf:params:xml:ns:xmpp-streams\"/></stream:error></stream:stream>"
        );
        assert!(
            features(Features::StartTls).contains("<starttls")
                && features(Features::StartTls).contains("<required/>")
        );
        let sasl = features(Features::Sasl);
        assert!(
            sasl.contains("<mechanism>PLAIN</mechanism>")
                && !sasl.contains("SCRAM")
                && !sasl.contains("starttls")
        );
        let bind = features(Features::Bind);
        assert!(
            bind.contains("<bind") && bind.contains("<session") && bind.contains("<optional/>")
        );
        for f in [Features::StartTls, Features::Sasl, Features::Bind] {
            let s = features(f);
            assert!(
                !s.contains("xmpp-sm") && !s.contains("compress"),
                "no XEP-0198 or compression"
            );
        }
    }
}
