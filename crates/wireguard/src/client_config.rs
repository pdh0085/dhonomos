//! wg-quick config file of a client member (ADR-110, stage 3).
//! Client = operator PC, phone or server -> whole network via the hub.
//!
//! With private key or PSK -> text is a secret: API sends it only in the one response
//! that made the key, nowhere else.
//! Without them -> `PrivateKey` line (and `PresharedKey` line if the member has one)
//! = comment, user fills it in.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::prefix::Ipv4Prefix;

/// Max chars of network or member name in the header comment.
const MAX_COMMENT_NAME: usize = 64;
/// Max wg-quick interface name (Linux `IFNAMSIZ` - 1 for the terminating zero).
const MAX_INTERFACE_NAME: usize = 15;
/// File name stem when nothing of the network name is usable.
const FALLBACK_STEM: &str = "dhonomos";

/// Content of a client member's wg-quick config.
#[derive(Debug, Clone, Copy)]
pub struct ClientConfig<'a> {
    /// Header comment only.
    pub network_name: &'a str,
    /// Header comment only.
    pub member_name: &'a str,
    /// None -> private key not known here (made by the user, or not shown again).
    pub private_key: Option<&'a str>,
    /// Member tunnel address.
    pub address: Ipv4Addr,
    pub mtu: u16,
    pub hub_public_key: &'a str,
    /// Member PSK. None -> not known here (not shown again), or no PSK.
    pub preshared_key: Option<&'a str>,
    /// Member has a PSK -> without `preshared_key` its line is a comment.
    pub preshared_key_enabled: bool,
    /// Hub host name or IP (IPv6 without brackets).
    pub endpoint_host: &'a str,
    /// Hub UDP port of the network.
    pub listen_port: u16,
    /// Tunnel prefix first, then site prefixes (caller sorts them).
    pub allowed_ips: &'a [Ipv4Prefix],
    /// 0 -> no PersistentKeepalive line.
    pub persistent_keepalive: u16,
}

/// Name for the header comment: no control chars or `"`, max 64 chars.
fn comment_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control() && *c != '"')
        .take(MAX_COMMENT_NAME)
        .collect()
}

/// Config text (LF line ends, final newline).
pub fn render_client_config(c: &ClientConfig<'_>) -> String {
    let mut out = String::new();
    // Write to a String cannot fail -> results ignored.
    let _ = writeln!(
        out,
        "# Dhonomos WireGuard network \"{}\", member \"{}\"",
        comment_name(c.network_name),
        comment_name(c.member_name)
    );
    out.push_str("[Interface]\n");
    match c.private_key {
        Some(k) => {
            let _ = writeln!(out, "PrivateKey = {k}");
        }
        None => out.push_str(
            "# PrivateKey = (not kept by Dhonomos: put the private key of this member here)\n",
        ),
    }
    let _ = writeln!(out, "Address = {}/32", c.address);
    let _ = writeln!(out, "MTU = {}", c.mtu);
    out.push('\n');
    out.push_str("[Peer]\n");
    let _ = writeln!(out, "PublicKey = {}", c.hub_public_key);
    match c.preshared_key {
        Some(k) => {
            let _ = writeln!(out, "PresharedKey = {k}");
        }
        None if c.preshared_key_enabled => {
            out.push_str("# PresharedKey = (shown once when it was made)\n");
        }
        None => {}
    }
    if c.endpoint_host.parse::<Ipv6Addr>().is_ok() {
        let _ = writeln!(out, "Endpoint = [{}]:{}", c.endpoint_host, c.listen_port);
    } else {
        let _ = writeln!(out, "Endpoint = {}:{}", c.endpoint_host, c.listen_port);
    }
    let allowed: Vec<String> = c.allowed_ips.iter().map(ToString::to_string).collect();
    let _ = writeln!(out, "AllowedIPs = {}", allowed.join(", "));
    if c.persistent_keepalive > 0 {
        let _ = writeln!(out, "PersistentKeepalive = {}", c.persistent_keepalive);
    }
    out
}

/// File name to save the config as.
///
/// wg-quick takes the interface name from it -> must match `[A-Za-z0-9_=+.-]{1,15}`.
/// Other chars -> `-`, runs of `-` collapse, `-` trimmed at both ends, cut to 15 chars.
/// Nothing left -> `dhonomos`.
pub fn config_file_name(network_name: &str) -> String {
    let mut stem = String::new();
    for c in network_name.chars() {
        let c = if c.is_ascii_alphanumeric() || matches!(c, '_' | '=' | '+' | '.' | '-') {
            c
        } else {
            '-'
        };
        if c == '-' && stem.ends_with('-') {
            continue;
        }
        stem.push(c);
    }
    // Only ASCII left -> bytes = chars, byte slice safe.
    let stem = stem.trim_matches('-');
    let stem = stem[..stem.len().min(MAX_INTERFACE_NAME)].trim_end_matches('-');
    if stem.is_empty() {
        format!("{FALLBACK_STEM}.conf")
    } else {
        format!("{stem}.conf")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const KEY: &str = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qga2V5ISE=";
    const HUB_KEY: &str = "SHVia2V5SHVia2V5SHVia2V5SHVia2V5SHVia2V5MDA=";
    const PSK: &str = "UFNLcHNrUFNLcHNrUFNLcHNrUFNLcHNrUFNLcHNrMDA=";

    fn prefixes() -> Vec<Ipv4Prefix> {
        ["10.77.0.0/24", "192.168.10.0/24", "192.168.20.0/24"]
            .iter()
            .map(|p| p.parse().unwrap())
            .collect()
    }

    fn sample<'a>(allowed: &'a [Ipv4Prefix]) -> ClientConfig<'a> {
        ClientConfig {
            network_name: "branches",
            member_name: "alice-laptop",
            private_key: Some(KEY),
            address: Ipv4Addr::new(10, 77, 0, 4),
            mtu: 1420,
            hub_public_key: HUB_KEY,
            preshared_key: None,
            preshared_key_enabled: false,
            endpoint_host: "hub.example.org",
            listen_port: 51820,
            allowed_ips: allowed,
            persistent_keepalive: 25,
        }
    }

    #[test]
    fn the_full_configuration() {
        let allowed = prefixes();
        let expected = format!(
            "# Dhonomos WireGuard network \"branches\", member \"alice-laptop\"\n\
             [Interface]\n\
             PrivateKey = {KEY}\n\
             Address = 10.77.0.4/32\n\
             MTU = 1420\n\
             \n\
             [Peer]\n\
             PublicKey = {HUB_KEY}\n\
             Endpoint = hub.example.org:51820\n\
             AllowedIPs = 10.77.0.0/24, 192.168.10.0/24, 192.168.20.0/24\n\
             PersistentKeepalive = 25\n"
        );
        assert_eq!(render_client_config(&sample(&allowed)), expected);
    }

    #[test]
    fn a_preshared_key_follows_the_public_key() {
        let allowed = prefixes();
        let c = ClientConfig {
            preshared_key: Some(PSK),
            preshared_key_enabled: true,
            ..sample(&allowed)
        };
        let text = render_client_config(&c);
        assert!(
            text.contains(&format!(
                "[Peer]\nPublicKey = {HUB_KEY}\nPresharedKey = {PSK}\nEndpoint = "
            )),
            "{text}"
        );
        // Not shown again -> comment in its place.
        let c = ClientConfig {
            private_key: None,
            preshared_key: None,
            preshared_key_enabled: true,
            ..sample(&allowed)
        };
        let text = render_client_config(&c);
        assert!(!text.contains(PSK));
        assert!(
            text.contains(&format!(
                "[Peer]\nPublicKey = {HUB_KEY}\n# PresharedKey = (shown once when it was made)\nEndpoint = "
            )),
            "{text}"
        );
        // No PSK -> no line.
        assert!(!render_client_config(&sample(&allowed)).contains("PresharedKey"));
    }

    #[test]
    fn without_a_private_key_the_line_is_a_comment() {
        let allowed = prefixes();
        let c = ClientConfig {
            private_key: None,
            ..sample(&allowed)
        };
        let text = render_client_config(&c);
        assert!(!text.contains("\nPrivateKey"));
        assert!(text.contains(
            "[Interface]\n# PrivateKey = (not kept by Dhonomos: put the private key of this member here)\nAddress = 10.77.0.4/32\n"
        ));
    }

    #[test]
    fn keepalive_zero_has_no_line() {
        let allowed = prefixes();
        let c = ClientConfig {
            persistent_keepalive: 0,
            ..sample(&allowed)
        };
        let text = render_client_config(&c);
        assert!(!text.contains("PersistentKeepalive"));
        assert!(text.ends_with("192.168.20.0/24\n"));
    }

    #[test]
    fn an_ipv6_endpoint_is_bracketed() {
        let allowed = prefixes();
        let c = ClientConfig {
            endpoint_host: "2001:db8::1",
            ..sample(&allowed)
        };
        assert!(render_client_config(&c).contains("\nEndpoint = [2001:db8::1]:51820\n"));
        let c = ClientConfig {
            endpoint_host: "203.0.113.7",
            ..sample(&allowed)
        };
        assert!(render_client_config(&c).contains("\nEndpoint = 203.0.113.7:51820\n"));
    }

    #[test]
    fn names_in_the_comment_are_cleaned() {
        let allowed = prefixes();
        let long = "n".repeat(80);
        let c = ClientConfig {
            network_name: "evil\n[Peer]\r\"x\"",
            member_name: &long,
            ..sample(&allowed)
        };
        let text = render_client_config(&c);
        let first = text.lines().next().unwrap();
        assert_eq!(
            first,
            format!(
                "# Dhonomos WireGuard network \"evil[Peer]x\", member \"{}\"",
                "n".repeat(64)
            )
        );
        assert_eq!(text.matches("[Peer]").count(), 2);
        assert_eq!(text.lines().count(), 11);
    }

    #[test]
    fn file_names() {
        assert_eq!(config_file_name("Branches Seoul"), "Branches-Seoul.conf");
        assert_eq!(config_file_name("서울 지점"), "dhonomos.conf");
        assert_eq!(
            config_file_name("a-very-long-network-name"),
            "a-very-long-net.conf"
        );
        assert_eq!(config_file_name("--x--"), "x.conf");
        assert_eq!(config_file_name(""), "dhonomos.conf");
        assert_eq!(config_file_name("a  /  b"), "a-b.conf");
        assert_eq!(config_file_name("lab_1=+.x"), "lab_1=+.x.conf");
        // 15 chars fit, 16th dropped.
        assert_eq!(config_file_name("abcdefghijklmno"), "abcdefghijklmno.conf");
        assert_eq!(config_file_name("abcdefghijklmnop"), "abcdefghijklmno.conf");
        // Cut ends on `-` -> trimmed again.
        assert_eq!(config_file_name("abcdefghijklmn op"), "abcdefghijklmn.conf");
    }
}
