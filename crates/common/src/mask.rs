//! Mask passwords + tokens in URLs shown to people (server config in the web UI).

/// Replacement for a secret.
pub const MASK: &str = "****";

/// Userinfo password + values of secret-named query params -> [`MASK`].
///
/// Secret name = contains `password`, `pwd`, `token`, `secret`, `key` or `auth` (any case).
/// Not a URL (`scheme://...`) -> `None`.
/// Userinfo ends at last `@` (password may hold a raw `@`) -> may hide more than the password,
/// never less.
pub fn mask_url(s: &str) -> Option<String> {
    let (scheme, rest) = s.split_once("://")?;
    let mut chars = scheme.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        || !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return None;
    }
    let mut out = format!("{scheme}://");
    match rest.rfind('@') {
        Some(at) => {
            let (userinfo, host) = rest.split_at(at);
            match userinfo.split_once(':') {
                Some((user, _)) => {
                    out.push_str(user);
                    out.push(':');
                    out.push_str(MASK);
                }
                None => out.push_str(userinfo),
            }
            out.push_str(host);
        }
        None => out.push_str(rest),
    }
    // `?password=` in DB URLs, webhook tokens in query -> mask these too.
    const SECRET_NAMES: [&str; 6] = ["password", "pwd", "token", "secret", "key", "auth"];
    if let Some(q) = out.find('?') {
        let query = out.split_off(q + 1);
        let params: Vec<String> = query
            .split('&')
            .map(|p| match p.split_once('=') {
                Some((name, _))
                    if SECRET_NAMES
                        .iter()
                        .any(|n| name.to_ascii_lowercase().contains(n)) =>
                {
                    format!("{name}={MASK}")
                }
                _ => p.to_owned(),
            })
            .collect();
        out.push_str(&params.join("&"));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_url_cases() {
        let m = |s: &str| mask_url(s);
        assert_eq!(m("not a url"), None);
        assert_eq!(m("host=db password=x"), None);
        assert_eq!(m("1http://u:p@h"), None);
        assert_eq!(
            m("https://a.example/x").as_deref(),
            Some("https://a.example/x")
        );
        assert_eq!(
            m("https://user@a.example").as_deref(),
            Some("https://user@a.example")
        );
        assert_eq!(
            m("https://:p@a.example").as_deref(),
            Some("https://:****@a.example")
        );
        // Raw `@` or `:` in password.
        assert_eq!(
            m("postgres://u:p@ss:w@h/db").as_deref(),
            Some("postgres://u:****@h/db")
        );
        // Tokens + keys in query.
        assert_eq!(
            m("https://hooks.example/x?token=abc&api_key=def&mode=1").as_deref(),
            Some("https://hooks.example/x?token=****&api_key=****&mode=1")
        );
        // Password in query, with or without userinfo.
        assert_eq!(
            m("postgres://h/db?sslmode=require&password=q@x").as_deref(),
            Some("postgres://h/db?sslmode=require&password=****")
        );
        assert_eq!(
            m("postgres://u:p@h/db?PassWord=q").as_deref(),
            Some("postgres://u:****@h/db?PassWord=****")
        );
    }
}
