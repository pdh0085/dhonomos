//! Command line of the hub process + its checks.

use std::path::PathBuf;

use clap::Parser;
use dhonomos_wireguard::MAX_WAIT_SECS;

/// Min resync + status interval, in s.
const MIN_INTERVAL: u64 = 5;
/// Max priority number of an iif rule (lower number = checked first).
/// 32766 = kernel `main` rule -> iif rules must come before it.
const MAX_RULE_PRIORITY: u32 = 32765;
/// Tables below this = kernel own (`local`, `main`, `default`) + usual
/// `/etc/iproute2/rt_tables` names.
const MIN_TABLE_BASE: u32 = 256;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Dhonomos WireGuard hub: applies the hub state from the Dhonomos server to the kernel"
)]
pub(crate) struct Cli {
    /// Base URL of the Dhonomos API listener, e.g. https://acs.example.org.
    /// Hub appends /api/v1/wg-hub/... Must be https:// unless --allow-http.
    #[arg(long, env = "DHONOMOS_WG_HUB_SERVER")]
    pub(crate) server: String,

    /// Allow an http:// server URL. Tests only: hub token then travels in clear text.
    #[arg(long, env = "DHONOMOS_WG_HUB_ALLOW_HTTP")]
    pub(crate) allow_http: bool,

    /// File with the hub token (dwh_...), issued by an admin for this hub.
    #[arg(
        long,
        default_value = "/etc/dhonomos/wg-hub.token",
        env = "DHONOMOS_WG_HUB_TOKEN_FILE"
    )]
    pub(crate) token_file: PathBuf,

    /// Hub WireGuard private key (base64, one line).
    /// Missing -> created (mode 0600); its directory must exist.
    #[arg(
        long,
        default_value = "/var/lib/dhonomos-wg-hub/private.key",
        env = "DHONOMOS_WG_HUB_KEY_FILE"
    )]
    pub(crate) key_file: PathBuf,

    /// Extra PEM trust anchors for the server certificate, in addition to system roots.
    #[arg(long, env = "DHONOMOS_WG_HUB_CA_FILE")]
    pub(crate) ca_file: Option<PathBuf>,

    /// Long-poll wait in seconds (1-60). State change -> server answers at once.
    #[arg(long, default_value_t = 25, env = "DHONOMOS_WG_HUB_WAIT")]
    pub(crate) wait: u64,

    /// Seconds between full kernel vs state comparisons, also without changes (min 5).
    #[arg(long, default_value_t = 60, env = "DHONOMOS_WG_HUB_RESYNC_INTERVAL")]
    pub(crate) resync_interval: u64,

    /// Seconds between peer status reports (min 5).
    #[arg(long, default_value_t = 30, env = "DHONOMOS_WG_HUB_STATUS_INTERVAL")]
    pub(crate) status_interval: u64,

    /// Routing table of a network = this + its listen port.
    /// 256 to 4294901759 -> every port fits.
    #[arg(long, default_value_t = 100_000, env = "DHONOMOS_WG_HUB_TABLE_BASE")]
    pub(crate) table_base: u32,

    /// Priority of the `iif dwg<port> lookup <table>` rules, 1-32765.
    #[arg(long, default_value_t = 10_000, env = "DHONOMOS_WG_HUB_RULE_PRIORITY")]
    pub(crate) rule_priority: u32,

    /// nft program.
    #[arg(long, default_value = "nft", env = "DHONOMOS_WG_HUB_NFT")]
    pub(crate) nft: PathBuf,

    /// Fetch state once, print planned kernel changes, exit. Changes nothing.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

/// Server base URL, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Server {
    /// true = `https`, false = `http`.
    pub(crate) https: bool,
    /// Host name or address (IPv6 without brackets).
    pub(crate) host: String,
    pub(crate) port: u16,
    /// `host[:port]` as given -> `Host` header.
    pub(crate) authority: String,
    /// Path before `/api/v1`, no trailing slash (usually empty).
    pub(crate) path: String,
}

impl Server {
    /// For logs.
    pub(crate) fn display(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        format!("{scheme}://{}{}", self.authority, self.path)
    }
}

/// Checked run config of the hub.
#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub(crate) server: Server,
    pub(crate) token_file: PathBuf,
    pub(crate) key_file: PathBuf,
    pub(crate) ca_file: Option<PathBuf>,
    pub(crate) wait: u64,
    pub(crate) resync_interval: u64,
    pub(crate) status_interval: u64,
    pub(crate) table_base: u32,
    pub(crate) rule_priority: u32,
    pub(crate) nft: PathBuf,
    pub(crate) dry_run: bool,
}

fn parse_server(url: &str, allow_http: bool) -> Result<Server, String> {
    let uri: hyper::Uri = url
        .trim()
        .parse()
        .map_err(|e| format!("--server {url:?} is not a URL: {e}"))?;
    let https = match uri.scheme_str() {
        Some("https") => true,
        Some("http") if allow_http => false,
        Some("http") => {
            return Err(
                "--server must be https:// (--allow-http allows http:// for tests; the hub token then travels in clear)"
                    .into(),
            );
        }
        _ => return Err(format!("--server {url:?} must start with https://")),
    };
    let authority = uri
        .authority()
        .ok_or_else(|| format!("--server {url:?} has no host"))?;
    if authority.as_str().contains('@') {
        return Err("--server must not contain user information".into());
    }
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    if host.is_empty() {
        return Err(format!("--server {url:?} has no host"));
    }
    if uri.query().is_some() {
        return Err("--server must not have a query".into());
    }
    let port = authority.port_u16().unwrap_or(if https { 443 } else { 80 });
    let path = uri.path().trim_end_matches('/').to_owned();
    Ok(Server {
        https,
        host,
        port,
        authority: authority.as_str().to_owned(),
        path,
    })
}

impl Config {
    /// Check the command line.
    pub(crate) fn from_cli(cli: Cli) -> Result<Self, String> {
        let server = parse_server(&cli.server, cli.allow_http)?;
        if !(1..=MAX_WAIT_SECS).contains(&cli.wait) {
            return Err(format!(
                "--wait must be between 1 and {MAX_WAIT_SECS} seconds"
            ));
        }
        if cli.resync_interval < MIN_INTERVAL {
            return Err(format!(
                "--resync-interval must be at least {MIN_INTERVAL} seconds"
            ));
        }
        if cli.status_interval < MIN_INTERVAL {
            return Err(format!(
                "--status-interval must be at least {MIN_INTERVAL} seconds"
            ));
        }
        let max_base = u32::MAX - 1 - u32::from(u16::MAX);
        if !(MIN_TABLE_BASE..=max_base).contains(&cli.table_base) {
            return Err(format!(
                "--table-base must be between {MIN_TABLE_BASE} and {max_base}"
            ));
        }
        if !(1..=MAX_RULE_PRIORITY).contains(&cli.rule_priority) {
            return Err(format!(
                "--rule-priority must be between 1 and {MAX_RULE_PRIORITY}"
            ));
        }
        Ok(Self {
            server,
            token_file: cli.token_file,
            key_file: cli.key_file,
            ca_file: cli.ca_file,
            wait: cli.wait,
            resync_interval: cli.resync_interval,
            status_interval: cli.status_interval,
            table_base: cli.table_base,
            rule_priority: cli.rule_priority,
            nft: cli.nft,
            dry_run: cli.dry_run,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn config(args: &[&str]) -> Result<Config, String> {
        let mut all = vec!["dhonomos-wg-hub"];
        all.extend_from_slice(args);
        Config::from_cli(Cli::try_parse_from(all).map_err(|e| e.to_string())?)
    }

    #[test]
    fn defaults() {
        let c = config(&["--server", "https://acs.example.org"]).unwrap();
        assert_eq!(
            c.server,
            Server {
                https: true,
                host: "acs.example.org".into(),
                port: 443,
                authority: "acs.example.org".into(),
                path: String::new(),
            }
        );
        assert_eq!(c.token_file, PathBuf::from("/etc/dhonomos/wg-hub.token"));
        assert_eq!(
            c.key_file,
            PathBuf::from("/var/lib/dhonomos-wg-hub/private.key")
        );
        assert_eq!(c.ca_file, None);
        assert_eq!((c.wait, c.resync_interval, c.status_interval), (25, 60, 30));
        assert_eq!((c.table_base, c.rule_priority), (100_000, 10_000));
        assert_eq!(c.nft, PathBuf::from("nft"));
        assert!(!c.dry_run);
    }

    #[test]
    fn server_urls() {
        let c = config(&["--server", "https://[2001:db8::1]:8443/dhonomos/"]).unwrap();
        assert_eq!(c.server.host, "2001:db8::1");
        assert_eq!(c.server.port, 8443);
        assert_eq!(c.server.authority, "[2001:db8::1]:8443");
        assert_eq!(c.server.path, "/dhonomos");
        assert_eq!(c.server.display(), "https://[2001:db8::1]:8443/dhonomos");

        let err = config(&["--server", "http://172.31.30.3:8080"]).unwrap_err();
        assert!(err.contains("--allow-http"), "{err}");
        let c = config(&["--server", "http://172.31.30.3:8080", "--allow-http"]).unwrap();
        assert!(!c.server.https);
        assert_eq!(c.server.port, 8080);

        for bad in [
            "acs.example.org",
            "ftp://acs.example.org",
            "https://user:pw@acs.example.org",
            "https://acs.example.org/?x=1",
            "",
        ] {
            assert!(config(&["--server", bad]).is_err(), "{bad:?}");
        }
        assert!(config(&[]).is_err(), "--server is required");
    }

    #[test]
    fn ranges() {
        let s = ["--server", "https://acs.example.org"];
        let with = |extra: &[&str]| {
            let mut args = s.to_vec();
            args.extend_from_slice(extra);
            config(&args)
        };
        for ok in [
            &["--wait", "1"][..],
            &["--wait", "60"],
            &["--resync-interval", "5"],
            &["--status-interval", "5"],
            &["--table-base", "256"],
            &["--table-base", "4294901759"],
            &["--rule-priority", "1"],
            &["--rule-priority", "32765"],
        ] {
            assert!(with(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            &["--wait", "0"][..],
            &["--wait", "61"],
            &["--resync-interval", "4"],
            &["--status-interval", "0"],
            &["--table-base", "255"],
            &["--table-base", "4294901760"],
            &["--rule-priority", "0"],
            &["--rule-priority", "32766"],
            &["--wait", "-1"],
        ] {
            assert!(with(bad).is_err(), "{bad:?}");
        }
    }
}
