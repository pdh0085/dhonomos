//! SASL PLAIN (RFC 4616): `[authzid] NUL authcid NUL passwd`.

use ring::digest::{SHA256, digest};

/// Max PLAIN message length (RFC: each part max 255 octets).
const MAX_MESSAGE: usize = 1024;
/// Max account name length (JID local part max 1023 octets; ours = UUIDs).
pub(crate) const MAX_LOCALPART: usize = 256;

/// Why a PLAIN message is refused = SASL failure condition of the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Too long, not 3 parts, not UTF-8 or empty password.
    MalformedRequest,
    /// Authorization identity = somebody else.
    InvalidAuthzid,
    /// No such account can exist.
    NotAuthorized,
}

impl Refusal {
    /// Condition element of the `<failure/>`.
    pub(crate) fn condition(self) -> &'static str {
        match self {
            Self::MalformedRequest => "malformed-request",
            Self::InvalidAuthzid => "invalid-authzid",
            Self::NotAuthorized => "not-authorized",
        }
    }
}

/// `s` usable as local part of a device JID?
///
/// Plain chars only -> safe in lookups + logs. JID local part: no `@`, `/`, `:`, controls anyway.
pub(crate) fn valid_localpart(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_LOCALPART
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Account name + password of a PLAIN message for server `domain`.
///
/// Authorization identity must be empty or the account's own JID.
pub(crate) fn parse_plain(msg: &[u8], domain: &str) -> Result<(String, Vec<u8>), Refusal> {
    if msg.len() > MAX_MESSAGE {
        return Err(Refusal::MalformedRequest);
    }
    let mut parts = msg.split(|&b| b == 0);
    let (Some(authzid), Some(authcid), Some(password), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Refusal::MalformedRequest);
    };
    let authzid = std::str::from_utf8(authzid).map_err(|_| Refusal::MalformedRequest)?;
    let authcid = std::str::from_utf8(authcid).map_err(|_| Refusal::MalformedRequest)?;
    if password.is_empty() {
        return Err(Refusal::MalformedRequest);
    }
    if !valid_localpart(authcid) {
        return Err(Refusal::NotAuthorized);
    }
    if !authzid.is_empty() {
        let own = authzid
            .split_once('@')
            .is_some_and(|(local, d)| local == authcid && d.eq_ignore_ascii_case(domain));
        if !own {
            return Err(Refusal::InvalidAuthzid);
        }
    }
    Ok((authcid.to_owned(), password.to_vec()))
}

/// Digests equal? Every byte checked, whatever the first difference (constant time).
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Index of the candidate = `given`, if any.
///
/// Every candidate compared, as equal-length digests -> time does not show how much of a
/// password was right, nor its length.
/// No candidate (no such account) -> 1 comparison all the same.
pub(crate) fn matching(candidates: &[&[u8]], given: &[u8]) -> Option<usize> {
    let given = digest(&SHA256, given);
    let mut found = None;
    for (i, c) in candidates.iter().enumerate() {
        let ok = same(digest(&SHA256, c).as_ref(), given.as_ref());
        if ok && found.is_none() {
            found = Some(i);
        }
    }
    if candidates.is_empty() {
        let _ = same(digest(&SHA256, b"").as_ref(), given.as_ref());
    }
    found
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn plain_without_authzid() {
        let (user, pass) = parse_plain(b"\0dev-1\0s3cret", "example.net").unwrap();
        assert_eq!((user.as_str(), pass.as_slice()), ("dev-1", &b"s3cret"[..]));
    }

    #[test]
    fn authzid_is_empty_or_the_account_itself() {
        for ok in ["dev-1@example.net", "dev-1@EXAMPLE.net"] {
            let msg = format!("{ok}\0dev-1\0pw");
            assert!(parse_plain(msg.as_bytes(), "example.net").is_ok(), "{ok}");
        }
        for bad in [
            "other@example.net",
            "dev-1@other.net",
            "dev-1",
            "dev-1@example.net/res",
        ] {
            let msg = format!("{bad}\0dev-1\0pw");
            assert_eq!(
                parse_plain(msg.as_bytes(), "example.net"),
                Err(Refusal::InvalidAuthzid),
                "{bad}"
            );
        }
    }

    #[test]
    fn malformed_messages() {
        for bad in [
            &b""[..],
            b"dev\0pw",
            b"\0dev",
            b"\0dev\0pw\0more",
            b"\0dev\0",
            b"\0\xff\0pw",
        ] {
            assert_eq!(
                parse_plain(bad, "example.net"),
                Err(Refusal::MalformedRequest),
                "{bad:?}"
            );
        }
        assert_eq!(
            parse_plain(&vec![b'a'; 2000], "example.net"),
            Err(Refusal::MalformedRequest)
        );
    }

    #[test]
    fn account_names_are_plain() {
        for bad in [
            "\0\0pw",
            "\0a b\0pw",
            "\0a@b\0pw",
            "\0a/b\0pw",
            "\0a:b\0pw",
            "\0a\u{e9}\0pw",
        ] {
            assert_eq!(
                parse_plain(bad.as_bytes(), "example.net"),
                Err(Refusal::NotAuthorized),
                "{bad:?}"
            );
        }
        let long = format!("\0{}\0pw", "a".repeat(MAX_LOCALPART + 1));
        assert_eq!(
            parse_plain(long.as_bytes(), "example.net"),
            Err(Refusal::NotAuthorized)
        );
    }

    #[test]
    fn matching_checks_every_candidate() {
        let cands: [&[u8]; 2] = [b"old", b"new"];
        assert_eq!(matching(&cands, b"old"), Some(0));
        assert_eq!(matching(&cands, b"new"), Some(1));
        assert_eq!(matching(&cands, b"nope"), None);
        assert_eq!(matching(&cands, b""), None);
        assert_eq!(matching(&[], b"anything"), None);
    }
}
