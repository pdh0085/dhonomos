//! Server options as the web shows them (runtime settings).
//!
//! Registry: each command-line option -> group + category.
//! View: values the server runs with, built once at startup from the parsed arguments.
//! [`effective`]: config, then values stored from the web, then defaults, all through the
//! command-line parsers.
//!
//! Secrets never in the view: `secret` category -> raw value not read, only "given or not".
//! Passwords in URLs -> `****`.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;

use clap::parser::ValueSource;
use clap::{Arg, ArgAction, ArgMatches, Command, CommandFactory as _, FromArgMatches as _};
use dhonomos_api::{ServerSetting, SettingCategory, SettingKind, SettingSource};
use dhonomos_common::mask::mask_url;
use dhonomos_core::RuntimeSettings;
use serde_json::Value;

use SettingCategory::{Bootstrap, Runtime, Secret, Security};

/// Registry entry of one option.
#[derive(Debug)]
pub(crate) struct Entry {
    /// clap argument id (= `Cli` field name).
    pub(crate) key: &'static str,
    pub(crate) group: &'static str,
    pub(crate) category: SettingCategory,
}

const fn e(key: &'static str, group: &'static str, category: SettingCategory) -> Entry {
    Entry {
        key,
        group,
        category,
    }
}

/// Every `Cli` option, once, in web order.
/// Test checks it against `Cli` -> new option without a category fails the tests.
pub(crate) static REGISTRY: &[Entry] = &[
    e("role", "process_db", Bootstrap),
    e("database_url", "process_db", Bootstrap),
    e("database_max_connections", "process_db", Bootstrap),
    e("database_device_sync_commit", "process_db", Bootstrap),
    e("secrets_key_id", "process_db", Bootstrap),
    e("acs_listen", "listeners_tls", Bootstrap),
    e("acs_tls_cert", "listeners_tls", Bootstrap),
    e("acs_tls_key", "listeners_tls", Bootstrap),
    e("acs_plaintext", "listeners_tls", Bootstrap),
    e("api_listen", "listeners_tls", Bootstrap),
    e("files_listen", "listeners_tls", Bootstrap),
    e("files_tls_cert", "listeners_tls", Bootstrap),
    e("files_tls_key", "listeners_tls", Bootstrap),
    e("files_dir", "listeners_tls", Bootstrap),
    e("usp_ws_listen", "listeners_tls", Bootstrap),
    e("usp_ws_tls", "listeners_tls", Bootstrap),
    e("usp_ws_tls_cert", "listeners_tls", Bootstrap),
    e("usp_ws_tls_key", "listeners_tls", Bootstrap),
    e("usp_ws_tls_name", "listeners_tls", Bootstrap),
    e("usp_ws_client_cert", "listeners_tls", Bootstrap),
    e("usp_ws_client_ca", "listeners_tls", Bootstrap),
    e("usp_ws_allow_anonymous", "listeners_tls", Bootstrap),
    e("usp_ws_clients", "listeners_tls", Bootstrap),
    e("usp_stomp_listen", "listeners_tls", Bootstrap),
    e("usp_stomp_tls", "listeners_tls", Bootstrap),
    e("usp_stomp_allow_anonymous", "listeners_tls", Bootstrap),
    e("usp_mqtt_broker_listen", "listeners_tls", Bootstrap),
    e("usp_mqtt_broker_tls", "listeners_tls", Bootstrap),
    e(
        "usp_mqtt_broker_allow_anonymous",
        "listeners_tls",
        Bootstrap,
    ),
    e("stun_listen", "listeners_tls", Bootstrap),
    e("stun_public_address", "listeners_tls", Bootstrap),
    e("xmpp_listen", "listeners_tls", Bootstrap),
    e("xmpp_tls_cert", "listeners_tls", Bootstrap),
    e("xmpp_tls_key", "listeners_tls", Bootstrap),
    e("acs_max_concurrent", "connection_limits", Bootstrap),
    e("acs_max_connections", "connection_limits", Bootstrap),
    e("acs_max_connections_per_ip", "connection_limits", Bootstrap),
    e("usp_stomp_max_connections", "connection_limits", Bootstrap),
    e(
        "usp_stomp_max_connections_per_ip",
        "connection_limits",
        Bootstrap,
    ),
    e(
        "usp_mqtt_broker_max_connections",
        "connection_limits",
        Bootstrap,
    ),
    e(
        "usp_mqtt_broker_max_connections_per_ip",
        "connection_limits",
        Bootstrap,
    ),
    e("xmpp_max_connections", "connection_limits", Bootstrap),
    e(
        "xmpp_max_connections_per_ip",
        "connection_limits",
        Bootstrap,
    ),
    e("usp_endpoint_id", "identity", Bootstrap),
    e("usp_topic", "identity", Bootstrap),
    e("usp_agent_topic_prefix", "identity", Bootstrap),
    e("usp_stomp_controller_dest", "identity", Bootstrap),
    e("usp_stomp_agent_dest_prefix", "identity", Bootstrap),
    e("usp_mqtt_broker_controller_topic", "identity", Bootstrap),
    e("usp_mqtt_broker_agent_topic_prefix", "identity", Bootstrap),
    e("xmpp_domain", "identity", Bootstrap),
    e("usp_ca_dir", "identity", Bootstrap),
    e("usp_ca_name", "identity", Bootstrap),
    e("files_public_url", "identity", Bootstrap),
    e("public_url", "identity", Bootstrap),
    e("totp_issuer", "identity", Bootstrap),
    e("usp_mqtt_host", "external_broker", Bootstrap),
    e("usp_mqtt_port", "external_broker", Bootstrap),
    e("usp_mqtt_tls", "external_broker", Bootstrap),
    e("usp_mqtt_ca", "external_broker", Bootstrap),
    e("usp_mqtt_client_cert", "external_broker", Bootstrap),
    e("usp_mqtt_client_key", "external_broker", Bootstrap),
    e("usp_mqtt_tls_name", "external_broker", Bootstrap),
    e("usp_mqtt_username", "external_broker", Bootstrap),
    e("usp_dynsec", "external_broker", Bootstrap),
    e("usp_dynsec_username", "external_broker", Bootstrap),
    e("secure_cookies", "security_base", Bootstrap),
    e("trusted_proxies", "security_base", Bootstrap),
    e("api_allow_open", "security_base", Bootstrap),
    e("cpe_auth", "security_base", Bootstrap),
    e("cpe_username", "security_base", Bootstrap),
    e("oidc_issuer", "security_base", Bootstrap),
    e("oidc_client_id", "security_base", Bootstrap),
    e("oidc_redirect_url", "security_base", Bootstrap),
    e("oidc_scopes", "security_base", Bootstrap),
    e("otlp_endpoint", "observability", Bootstrap),
    e("otlp_service_name", "observability", Bootstrap),
    e("otlp_sample_ratio", "observability", Bootstrap),
    e("presets", "file_paths", Bootstrap),
    e("alarms", "file_paths", Bootstrap),
    e("smtp_ca", "file_paths", Bootstrap),
    e("events_retention_days", "retention", Runtime),
    e("tasks_retention_days", "retention", Runtime),
    e("alarms_retention_days", "retention", Runtime),
    e("metrics_retention_days", "retention", Runtime),
    e("metrics_raw_days", "retention", Runtime),
    e("webhook_url", "notifications", Runtime),
    e("smtp_host", "notifications", Runtime),
    e("smtp_port", "notifications", Runtime),
    e("smtp_security", "notifications", Runtime),
    e("smtp_username", "notifications", Runtime),
    e("alarm_email_from", "notifications", Runtime),
    e("alarm_email_to", "notifications", Runtime),
    e("alarm_email_min_severity", "notifications", Runtime),
    e("audit_webhook_url", "notifications", Security),
    e("session_hours", "login_session", Runtime),
    e("session_idle_minutes", "login_session", Runtime),
    e("api_rate_limit", "login_session", Runtime),
    e("require_totp_roles", "login_session", Security),
    e("require_admin_totp", "login_session", Security),
    e("oidc_username_claim", "login_session", Security),
    e("oidc_role_claim", "login_session", Security),
    e("oidc_admin_groups", "login_session", Security),
    e("oidc_operator_groups", "login_session", Security),
    e("oidc_viewer_groups", "login_session", Security),
    e("cpe_session_limit", "cpe_policy", Runtime),
    e("cpe_max_params_per_message", "cpe_policy", Runtime),
    e("cpe_max_params_per_device", "cpe_policy", Runtime),
    e("session_timeout", "cpe_policy", Runtime),
    e("onboarding", "cpe_policy", Security),
    e("allowed_oui", "cpe_policy", Security),
    e("acs_auth_per_device", "cpe_policy", Security),
    e("cpe_auth_failure_limit", "cpe_policy", Security),
    e("cpe_digest_no_qop", "cpe_policy", Security),
    e("cpe_digest_bind_client", "cpe_policy", Security),
    e("cr_allow", "connection_request", Security),
    e("cr_deny", "connection_request", Security),
    e("cr_per_device", "connection_request", Security),
    e("cr_basic_auth", "connection_request", Security),
    e("cr_username", "connection_request", Security),
    e("files_max_bytes", "file_server", Runtime),
    e("files_total_mbps", "file_server", Runtime),
    e("files_download_mbps", "file_server", Runtime),
    e("files_max_downloads", "file_server", Runtime),
    e("files_link_hours", "file_server", Runtime),
    e("usp_request_timeout", "usp", Runtime),
    e("usp_full_read_timeout", "usp", Runtime),
    e("usp_auto_subscribe", "usp", Runtime),
    e("xmpp_keepalive", "xmpp", Bootstrap),
    e("xmpp_idle_timeout", "xmpp", Runtime),
    e("wg_address_pool", "wireguard", Runtime),
    e("wg_address_reuse_delay_hours", "wireguard", Runtime),
    e("secrets_key", "secrets", Secret),
    e("secrets_old_keys", "secrets", Secret),
    e("files_secret", "secrets", Secret),
    e("cpe_password", "secrets", Secret),
    e("cr_password", "secrets", Secret),
    e("usp_stomp_login", "secrets", Secret),
    e("usp_stomp_passcode", "secrets", Secret),
    e("usp_mqtt_broker_username", "secrets", Secret),
    e("usp_mqtt_broker_password", "secrets", Secret),
    e("usp_mqtt_password", "secrets", Secret),
    e("usp_dynsec_password", "secrets", Secret),
    e("webhook_secret", "secrets", Secret),
    e("audit_webhook_secret", "secrets", Secret),
    e("smtp_password", "secrets", Secret),
    e("oidc_client_secret", "secrets", Secret),
    e("admin_password", "secrets", Secret),
    e("api_token", "secrets", Secret),
];

/// View of every registry option: value in `matches` + source.
/// Also flag, env var and help of its argument in `cmd`.
pub(crate) fn view(cmd: &Command, matches: &ArgMatches) -> Vec<ServerSetting> {
    REGISTRY
        .iter()
        .filter_map(|entry| {
            let arg = cmd.get_arguments().find(|a| a.get_id() == entry.key)?;
            let source = match matches.value_source(entry.key) {
                None => SettingSource::Unset,
                Some(ValueSource::DefaultValue) => SettingSource::Default,
                Some(ValueSource::EnvVariable) => SettingSource::Env,
                // Command line + any explicit source of a later clap.
                Some(_) => SettingSource::Cli,
            };
            let raw = matches.try_get_raw(entry.key).ok().flatten();
            // Set = non-empty value. Empty default (`--webhook-secret`) != secret set.
            let is_set = raw
                .clone()
                .is_some_and(|mut vals| vals.any(|v| !v.is_empty()));
            let value = match entry.category {
                // Never copied.
                Secret => None,
                _ => raw.and_then(|vals| {
                    let vals: Vec<String> =
                        vals.map(|v| v.to_string_lossy().into_owned()).collect();
                    if entry.key == "database_url" {
                        // Not a URL (`key=value` connection string) -> password could be
                        // anywhere -> show nothing.
                        vals.iter()
                            .map(|v| mask_url(v))
                            .collect::<Option<Vec<_>>>()
                            .map(|v| v.join(","))
                    } else {
                        Some(
                            vals.iter()
                                .map(|v| mask_url(v).unwrap_or_else(|| v.clone()))
                                .collect::<Vec<_>>()
                                .join(","),
                        )
                    }
                }),
            };
            let locked_reason = (entry.category == Runtime)
                .then(|| lock_reason(matches, entry.key))
                .flatten();
            Some(ServerSetting {
                key: entry.key.to_owned(),
                flag: arg.get_long().map(|l| format!("--{l}")).unwrap_or_default(),
                env: arg
                    .get_env()
                    .map(|v| v.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                group: entry.group.to_owned(),
                category: entry.category,
                help: arg
                    .get_help()
                    .map(|h| {
                        let h = h.to_string();
                        h.split("\n\n").next().unwrap_or_default().trim().to_owned()
                    })
                    .unwrap_or_default(),
                source,
                is_set,
                value,
                kind: kind(arg),
                editable: entry.category == Runtime && locked_reason.is_none(),
                locked_reason: locked_reason.map(str::to_owned),
                web_value: None,
            })
        })
        .collect()
}

/// Lock reason: config sets the runtime option.
pub(crate) const LOCKED_BY_CONFIG: &str =
    "set in the server's configuration (environment or command line)";
/// Lock reason of the SMTP server options when config sets the SMTP password.
/// Else the web could send that password to another server.
pub(crate) const LOCKED_BY_SMTP_PASSWORD: &str =
    "paired with the SMTP password in the server's configuration";
/// Options locked with a configured `smtp_password`.
const SMTP_PAIRED: [&str; 4] = ["smtp_host", "smtp_port", "smtp_security", "smtp_username"];

/// `key` in `matches` from env or command line (not default).
fn configured(matches: &ArgMatches, key: &str) -> bool {
    matches!(matches.value_source(key), Some(s) if s != ValueSource::DefaultValue)
}

/// Why the web cannot change runtime option `key` under config `matches`.
/// `None` -> web can change it.
pub(crate) fn lock_reason(matches: &ArgMatches, key: &str) -> Option<&'static str> {
    if configured(matches, key) {
        Some(LOCKED_BY_CONFIG)
    } else if SMTP_PAIRED.contains(&key) && configured(matches, "smtp_password") {
        Some(LOCKED_BY_SMTP_PASSWORD)
    } else {
        None
    }
}

/// Web editor of `arg`: switch or `true`/`false` -> bool, several values -> list, else text.
pub(crate) fn kind(arg: &Arg) -> SettingKind {
    let bool_values = {
        let mut names: Vec<String> = arg
            .get_possible_values()
            .iter()
            .map(|v| v.get_name().to_owned())
            .collect();
        names.sort();
        names == ["false", "true"]
    };
    match arg.get_action() {
        ArgAction::SetTrue | ArgAction::SetFalse => SettingKind::Bool,
        ArgAction::Append => SettingKind::List,
        _ if bool_values => SettingKind::Bool,
        _ => SettingKind::Text,
    }
}

/// First line of a clap error, no colours.
fn clap_message(e: &clap::Error) -> String {
    e.render()
        .to_string()
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// Effective runtime settings of this process: config (env + command line), then values
/// stored from the web (`db_values`), then defaults.
/// Each value -> command-line parser of its option -> cross-option checks.
/// Used at startup + for every change.
pub(crate) fn effective(db_values: &BTreeMap<String, Value>) -> Result<RuntimeSettings, String> {
    let argv: Vec<OsString> = std::env::args_os().collect();
    effective_with(&crate::Cli::command(), &argv, db_values)
}

/// [`effective`] for command `cmd` run as `argv` (program name first).
pub(crate) fn effective_with(
    cmd: &Command,
    argv: &[OsString],
    db_values: &BTreeMap<String, Value>,
) -> Result<RuntimeSettings, String> {
    let base = cmd
        .clone()
        .try_get_matches_from(argv)
        .map_err(|e| clap_message(&e))?;
    let mut built = cmd.clone();
    built.build();
    let mut cmd = cmd.clone();
    // Options with value from the web.
    let mut web = BTreeSet::new();
    for entry in REGISTRY.iter().filter(|e| e.category == Runtime) {
        let Some(value) = db_values.get(entry.key) else {
            continue;
        };
        if lock_reason(&base, entry.key).is_some() {
            continue;
        }
        let Some(arg) = built.get_arguments().find(|a| a.get_id() == entry.key) else {
            continue;
        };
        let key = entry.key;
        match (kind(arg), value) {
            (SettingKind::List, Value::Array(items)) => {
                let values = items
                    .iter()
                    .map(|v| v.as_str().map(str::to_owned))
                    .collect::<Option<Vec<String>>>()
                    .ok_or_else(|| format!("{key}: expected a list of strings"))?;
                cmd = cmd.mut_arg(key, |a| a.default_values(values));
            }
            (SettingKind::List, _) => return Err(format!("{key}: expected a list of strings")),
            (_, Value::String(v)) => {
                let v = v.clone();
                cmd = cmd.mut_arg(key, |a| a.default_value(v));
            }
            _ => return Err(format!("{key}: expected a string")),
        }
        web.insert(key);
    }
    let matches = cmd
        .try_get_matches_from(argv)
        .map_err(|e| clap_message(&e))?;
    let cli = crate::Cli::from_arg_matches(&matches).map_err(|e| clap_message(&e))?;
    let settings = runtime_of(&cli);
    check(&settings, &cli, &web)?;
    Ok(settings)
}

fn runtime_of(cli: &crate::Cli) -> RuntimeSettings {
    RuntimeSettings {
        events_retention_days: cli.events_retention_days,
        tasks_retention_days: cli.tasks_retention_days,
        alarms_retention_days: cli.alarms_retention_days,
        metrics_retention_days: cli.metrics_retention_days,
        metrics_raw_days: cli.metrics_raw_days,
        webhook_url: cli.webhook_url.clone(),
        smtp_host: cli.smtp_host.clone(),
        smtp_port: cli.smtp_port,
        smtp_security: match cli.smtp_security {
            crate::SmtpSecurity::Starttls => dhonomos_core::mail::Security::StartTls,
            crate::SmtpSecurity::Tls => dhonomos_core::mail::Security::Tls,
            crate::SmtpSecurity::None => dhonomos_core::mail::Security::None,
        },
        smtp_username: cli.smtp_username.clone(),
        alarm_email_from: cli.alarm_email_from.clone(),
        alarm_email_to: cli.alarm_email_to.clone(),
        alarm_email_min_severity: cli.alarm_email_min_severity.clone(),
        session_hours: cli.session_hours,
        session_idle_minutes: cli.session_idle_minutes,
        api_rate_limit: cli.api_rate_limit,
        cpe_session_limit: cli.cpe_session_limit,
        cpe_max_params_per_message: cli.cpe_max_params_per_message,
        cpe_max_params_per_device: cli.cpe_max_params_per_device,
        session_timeout: cli.session_timeout,
        files_max_bytes: cli.files_max_bytes,
        files_total_mbps: cli.files_total_mbps,
        files_download_mbps: cli.files_download_mbps,
        files_max_downloads: cli.files_max_downloads,
        files_link_hours: cli.files_link_hours,
        usp_request_timeout: cli.usp_request_timeout,
        usp_full_read_timeout: cli.usp_full_read_timeout,
        usp_auto_subscribe: cli.usp_auto_subscribe,
        xmpp_idle_timeout: cli.xmpp_idle_timeout,
        wg_address_pool: cli.wg_address_pool,
        wg_address_reuse_delay_hours: cli.wg_address_reuse_delay_hours,
    }
}

/// Cross-option checks, as at startup.
/// Fail only when one of the options has its value from the web (`web`).
/// Error from config alone -> startup handles it as before (refused or warned).
fn check(s: &RuntimeSettings, cli: &crate::Cli, web: &BTreeSet<&str>) -> Result<(), String> {
    let involves = |keys: &[&str]| keys.iter().any(|k| web.contains(k));
    if involves(&["usp_request_timeout", "usp_full_read_timeout"]) {
        crate::usp_timeouts(s.usp_request_timeout, s.usp_full_read_timeout)
            .map_err(|e| e.to_string())?;
    }
    if involves(&["wg_address_pool", "wg_address_reuse_delay_hours"]) {
        dhonomos_api::WireguardConfig::new(s.wg_address_pool, s.wg_address_reuse_delay_hours)?;
    }
    if involves(&[
        "smtp_host",
        "smtp_port",
        "smtp_security",
        "smtp_username",
        "alarm_email_from",
        "alarm_email_to",
        "alarm_email_min_severity",
    ]) {
        crate::alarm_email(s, None, None)?;
    }
    if involves(&["xmpp_idle_timeout"])
        && let Some(idle) = s.xmpp_idle_timeout
        && idle <= u64::from(cli.xmpp_keepalive)
    {
        return Err(format!(
            "--xmpp-idle-timeout ({idle} s) must be longer than --xmpp-keepalive ({} s): \
             devices would be disconnected between their pings",
            cli.xmpp_keepalive
        ));
    }
    Ok(())
}

/// API check: `db_values` (stored values after a change) accepted?
/// All values checked together, minus those `effective` refuses alone.
/// Server ignores those anyway (see [`load`]) -> must not block other changes.
/// API checks the changed value alone first.
pub(crate) fn validate(
    db_values: &BTreeMap<String, Value>,
    effective: impl Fn(&BTreeMap<String, Value>) -> Result<RuntimeSettings, String>,
) -> Result<(), String> {
    if effective(db_values).is_ok() {
        return Ok(());
    }
    let usable: BTreeMap<String, Value> = db_values
        .iter()
        .filter(|(k, v)| effective(&BTreeMap::from([((*k).clone(), (*v).clone())])).is_ok())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    effective(&usable).map(|_| ())
}

/// Runtime settings from config + stored `db_values`, as `effective` resolves them.
/// Each refused stored value -> left out + warning with option name.
/// Bad stored value never stops the server.
/// Values tried one at a time in key order, each with those taken before.
pub(crate) fn load(
    db_values: &BTreeMap<String, Value>,
    effective: impl Fn(&BTreeMap<String, Value>) -> Result<RuntimeSettings, String>,
) -> Result<RuntimeSettings, String> {
    if let Ok(s) = effective(db_values) {
        return Ok(s);
    }
    let mut taken = BTreeMap::new();
    for (key, value) in db_values {
        taken.insert(key.clone(), value.clone());
        if let Err(e) = effective(&taken) {
            tracing::warn!(key = %key, error = %e, "stored runtime setting ignored");
            taken.remove(key);
        }
    }
    effective(&taken)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use serde_json::json;

    use super::*;
    use crate::Cli;

    #[test]
    fn the_registry_names_every_option_once() {
        let cmd = Cli::command();
        let args: BTreeSet<&str> = cmd
            .get_arguments()
            .map(|a| a.get_id().as_str())
            .filter(|id| !matches!(*id, "help" | "version"))
            .collect();
        let mut keys = BTreeSet::new();
        for entry in REGISTRY {
            assert!(keys.insert(entry.key), "{} is listed twice", entry.key);
        }
        let missing: Vec<_> = args.difference(&keys).collect();
        let unknown: Vec<_> = keys.difference(&args).collect();
        assert!(
            missing.is_empty(),
            "options without a registry entry (give them a group and a category): {missing:?}"
        );
        assert!(
            unknown.is_empty(),
            "registry entries that are not options: {unknown:?}"
        );
    }

    const SECRETS: &[(&str, &str)] = &[
        ("--secrets-key", "secret-key-material-1"),
        (
            "--secrets-old-keys",
            "old-key-material-2,old-key-material-3",
        ),
        ("--files-secret", "files-secret-4"),
        ("--cpe-password", "cpe-password-5"),
        ("--cr-password", "cr-password-6"),
        ("--usp-stomp-login", "stomp-login-7"),
        ("--usp-stomp-passcode", "stomp-passcode-8"),
        ("--usp-mqtt-broker-username", "broker-user-9"),
        ("--usp-mqtt-broker-password", "broker-password-10"),
        ("--usp-mqtt-password", "mqtt-password-11"),
        ("--usp-dynsec-password", "dynsec-password-12"),
        ("--webhook-secret", "webhook-secret-13"),
        ("--audit-webhook-secret", "audit-secret-14"),
        ("--smtp-password", "smtp-password-15"),
        ("--oidc-client-secret", "oidc-secret-16"),
        ("--admin-password", "admin-password-17"),
        ("--api-token", "api-token-18"),
    ];

    /// View of `argv` (after program name).
    /// `presets` read from `PATH` -> env value testable without changing the env.
    fn view_of(argv: &[&str]) -> Vec<ServerSetting> {
        let cmd = Cli::command().mut_arg("presets", |a| a.env("PATH"));
        let matches = cmd
            .clone()
            .try_get_matches_from(std::iter::once("dhonomos").chain(argv.iter().copied()))
            .unwrap();
        view(&cmd, &matches)
    }

    fn item<'a>(items: &'a [ServerSetting], key: &str) -> &'a ServerSetting {
        items.iter().find(|i| i.key == key).unwrap()
    }

    #[test]
    fn sources_values_and_help() {
        let items = view_of(&[
            "--database-url",
            "postgres://h/db",
            "--acs-plaintext",
            "--allowed-oui",
            "001122,AABBCC",
            "--webhook-url",
            "https://a.example/x",
            "--webhook-url",
            "https://b.example/y",
        ]);
        assert_eq!(items.len(), REGISTRY.len());
        let keys: Vec<&str> = items.iter().map(|i| i.key.as_str()).collect();
        let order: Vec<&str> = REGISTRY.iter().map(|e| e.key).collect();
        assert_eq!(keys, order, "registry order");

        let i = item(&items, "acs_plaintext");
        assert_eq!((i.source, i.is_set), (SettingSource::Cli, true));
        assert_eq!(i.value.as_deref(), Some("true"));

        let i = item(&items, "acs_listen");
        assert_eq!(i.source, SettingSource::Default);
        assert!(i.is_set);
        assert_eq!(i.value.as_deref(), Some("[::]:7547"));
        assert_eq!(i.flag, "--acs-listen");
        assert_eq!(i.env, "DHONOMOS_ACS_LISTEN");
        assert_eq!(i.group, "listeners_tls");
        assert_eq!(i.category, Bootstrap);
        assert_eq!(i.help, "ACS listen address; `[::]` accepts IPv4 and IPv6");

        let i = item(&items, "presets");
        assert_eq!(i.source, SettingSource::Env);
        assert_eq!(
            i.value,
            std::env::var_os("PATH").map(|p| p.to_string_lossy().into_owned())
        );

        let i = item(&items, "oidc_issuer");
        assert_eq!(
            (i.source, i.is_set, i.value.as_deref()),
            (SettingSource::Unset, false, None)
        );

        // Several values (split by clap or given twice) -> joined.
        assert_eq!(
            item(&items, "allowed_oui").value.as_deref(),
            Some("001122,AABBCC")
        );
        assert_eq!(
            item(&items, "webhook_url").value.as_deref(),
            Some("https://a.example/x,https://b.example/y")
        );

        // Unset secret + secret with empty default -> not set.
        let i = item(&items, "api_token");
        assert_eq!(
            (i.source, i.is_set, i.value.as_deref()),
            (SettingSource::Unset, false, None)
        );
        let i = item(&items, "webhook_secret");
        assert_eq!(
            (i.source, i.is_set, i.value.as_deref()),
            (SettingSource::Default, false, None)
        );

        // Help = 1st paragraph of the doc comment, one line.
        assert!(
            !item(&items, "acs_max_connections_per_ip")
                .help
                .contains('\n')
        );
    }

    #[test]
    fn passwords_are_masked() {
        let items = view_of(&[
            "--database-url",
            "postgres://rms:db-pass-1@db.example:5432/rms?sslmode=require",
            "--webhook-url",
            "https://hook:hook-pass-2@a.example/x,https://b.example/y",
            "--otlp-endpoint",
            "http://otel:otlp-pass-3@collector:4318",
            "--usp-mqtt-host",
            "mqtt://u:mqtt-pass-4@broker.example",
        ]);
        assert_eq!(
            item(&items, "database_url").value.as_deref(),
            Some("postgres://rms:****@db.example:5432/rms?sslmode=require")
        );
        assert_eq!(
            item(&items, "webhook_url").value.as_deref(),
            Some("https://hook:****@a.example/x,https://b.example/y")
        );
        assert_eq!(
            item(&items, "otlp_endpoint").value.as_deref(),
            Some("http://otel:****@collector:4318")
        );
        assert_eq!(
            item(&items, "usp_mqtt_host").value.as_deref(),
            Some("mqtt://u:****@broker.example")
        );

        // Connection string, not a URL -> nothing shown.
        let items = view_of(&["--database-url", "host=db password=db-pass-5"]);
        let i = item(&items, "database_url");
        assert_eq!(
            (i.source, i.is_set, i.value.as_deref()),
            (SettingSource::Cli, true, None)
        );
    }

    /// No secret + no URL password anywhere in the API output.
    #[test]
    fn secrets_never_reach_the_json() {
        let mut argv: Vec<&str> = vec![
            "--database-url",
            "postgres://rms:db-pass-secret@db/rms",
            "--webhook-url",
            "https://hook:webhook-pass-secret@a.example/x",
            "--audit-webhook-url",
            "https://audit:audit-pass-secret@b.example/y",
            "--usp-stomp-listen",
            "[::]:61613",
            "--usp-mqtt-broker-listen",
            "[::]:1883",
        ];
        // All on the command line, except `--smtp-password` from env.
        for (flag, value) in SECRETS.iter().filter(|(f, _)| *f != "--smtp-password") {
            argv.extend([*flag, *value]);
        }
        let path = std::env::var("PATH").unwrap();
        let cmd = Cli::command().mut_arg("smtp_password", |a| a.env("PATH"));
        let matches = cmd
            .clone()
            .try_get_matches_from(std::iter::once("dhonomos").chain(argv.iter().copied()))
            .unwrap();
        let items = view(&cmd, &matches);
        let json = serde_json::to_string(&items).unwrap();
        let mut secrets: Vec<&str> = SECRETS.iter().flat_map(|(_, v)| v.split(',')).collect();
        secrets.extend([
            "db-pass-secret",
            "webhook-pass-secret",
            "audit-pass-secret",
            &path,
        ]);
        for s in secrets {
            assert!(!json.contains(s), "{s} in {json}");
        }
        for i in items.iter().filter(|i| i.category == Secret) {
            assert_eq!(i.value, None, "{}", i.key);
            assert!(i.is_set, "{}", i.key);
            let from = if i.key == "smtp_password" {
                SettingSource::Env
            } else {
                SettingSource::Cli
            };
            assert_eq!(i.source, from, "{}", i.key);
        }
    }

    /// Effective runtime settings: command line `argv` (after the DB URL) + stored values `db`.
    fn eff(argv: &[&str], db: &[(&str, Value)]) -> Result<RuntimeSettings, String> {
        let argv: Vec<OsString> = ["dhonomos", "--database-url", "postgres://x"]
            .iter()
            .chain(argv)
            .map(OsString::from)
            .collect();
        let db: BTreeMap<String, Value> = db
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect();
        effective_with(&Cli::command(), &argv, &db)
    }

    #[test]
    fn stored_values_apply_unless_the_configuration_sets_the_option() {
        let none = eff(&[], &[]).unwrap();
        assert_eq!((none.session_hours, none.api_rate_limit), (12, 50));
        let db = [
            ("session_hours", json!("8")),
            ("api_rate_limit", json!("0")),
            ("files_total_mbps", json!("100")),
            // Not runtime -> never taken from DB.
            ("acs_max_concurrent", json!("1")),
        ];
        let s = eff(&[], &db).unwrap();
        assert_eq!(
            (s.session_hours, s.api_rate_limit, s.files_total_mbps),
            (8, 0, Some(100))
        );
        // Command line wins -> stored value ignored, also when invalid.
        let s = eff(&["--session-hours", "4"], &db).unwrap();
        assert_eq!((s.session_hours, s.api_rate_limit), (4, 0));
        let s = eff(
            &["--session-hours", "4"],
            &[("session_hours", json!("soon"))],
        )
        .unwrap();
        assert_eq!(s.session_hours, 4);
    }

    #[test]
    fn invalid_stored_values_give_one_plain_line() {
        let err = eff(&[], &[("session_hours", json!("soon"))]).unwrap_err();
        assert!(
            err.contains("invalid value 'soon' for '--session-hours <SESSION_HOURS>'"),
            "{err}"
        );
        assert!(!err.contains('\n') && !err.contains('\u{1b}'), "{err:?}");
        let err = eff(&[], &[("xmpp_idle_timeout", json!("0"))]).unwrap_err();
        assert!(err.contains("--xmpp-idle-timeout"), "{err}");
        let err = eff(&[], &[("smtp_security", json!("ssl"))]).unwrap_err();
        assert!(err.contains("'ssl'"), "{err}");
        let err = eff(&[], &[("wg_address_pool", json!("10.77.0.1/16"))]).unwrap_err();
        assert!(err.contains("--wg-address-pool"), "{err}");
        // Wrong shape.
        assert_eq!(
            eff(&[], &[("webhook_url", json!("https://a.example"))]).unwrap_err(),
            "webhook_url: expected a list of strings"
        );
        assert_eq!(
            eff(&[], &[("webhook_url", json!(["https://a.example", 1]))]).unwrap_err(),
            "webhook_url: expected a list of strings"
        );
        assert_eq!(
            eff(&[], &[("session_hours", json!(8))]).unwrap_err(),
            "session_hours: expected a string"
        );
    }

    #[test]
    fn bools_and_lists_round_trip() {
        let s = eff(&[], &[("usp_auto_subscribe", json!("false"))]).unwrap();
        assert!(!s.usp_auto_subscribe);
        assert!(
            eff(&[], &[("usp_auto_subscribe", json!("true"))])
                .unwrap()
                .usp_auto_subscribe
        );
        assert!(eff(&[], &[("usp_auto_subscribe", json!("maybe"))]).is_err());
        let s = eff(
            &[],
            &[(
                "webhook_url",
                json!(["https://a.example/x", "https://b.example/y"]),
            )],
        )
        .unwrap();
        assert_eq!(
            s.webhook_url,
            ["https://a.example/x", "https://b.example/y"]
        );
        let s = eff(&[], &[("webhook_url", json!([]))]).unwrap();
        assert!(s.webhook_url.is_empty());
        let s = eff(&[], &[("files_max_downloads", json!("3"))]).unwrap();
        assert_eq!(s.files_max_downloads, Some(3));
    }

    #[test]
    fn checks_across_options_refuse_web_values_only() {
        // Longer than default full read (120 s).
        let err = eff(&[], &[("usp_request_timeout", json!("200"))]).unwrap_err();
        assert!(err.contains("must not be shorter than"), "{err}");
        assert!(
            eff(
                &[],
                &[
                    ("usp_request_timeout", json!("200")),
                    ("usp_full_read_timeout", json!("300"))
                ]
            )
            .is_ok()
        );
        // Same from command line only -> left to startup checks.
        assert!(eff(&["--usp-request-timeout", "200"], &[]).is_ok());
        let err = eff(&[], &[("wg_address_pool", json!("127.0.0.0/8"))]).unwrap_err();
        assert!(err.contains("--wg-address-pool 127.0.0.0/8"), "{err}");
        // Alarm e-mail.
        let mail = [
            ("smtp_host", json!("mail.example")),
            ("alarm_email_from", json!("rms@example.org")),
        ];
        let err = eff(&[], &mail).unwrap_err();
        assert!(err.contains("--alarm-email-to is required"), "{err}");
        let mut ok = mail.to_vec();
        ok.push(("alarm_email_to", json!(["noc@example.org"])));
        assert!(eff(&[], &ok).is_ok());
        let mut loud = ok.clone();
        loud.push(("alarm_email_min_severity", json!("loud")));
        let err = eff(&[], &loud).unwrap_err();
        assert!(err.contains("critical, major, minor or warning"), "{err}");
        let mut clear = ok.clone();
        clear.extend([
            ("smtp_security", json!("none")),
            ("smtp_username", json!("rms")),
        ]);
        let err = eff(&[], &clear).unwrap_err();
        assert!(err.contains("--smtp-security none cannot log in"), "{err}");
        // XMPP: idle timeout must be > keep-alive (30 s).
        let err = eff(&[], &[("xmpp_idle_timeout", json!("30"))]).unwrap_err();
        assert!(
            err.contains("must be longer than --xmpp-keepalive (30 s)"),
            "{err}"
        );
        assert!(eff(&[], &[("xmpp_idle_timeout", json!("31"))]).is_ok());
        assert!(
            eff(
                &["--xmpp-keepalive", "60"],
                &[("xmpp_idle_timeout", json!("45"))]
            )
            .is_err()
        );
        // From config -> still a startup warning.
        assert!(eff(&["--xmpp-idle-timeout", "10"], &[]).is_ok());
        // Metrics days: clamped where used, not refused.
        assert!(eff(&[], &[("metrics_raw_days", json!("50"))]).is_ok());
    }

    #[test]
    fn the_smtp_password_locks_the_smtp_server() {
        let db = [
            ("smtp_host", json!("evil.example")),
            ("smtp_port", json!("25")),
            ("alarm_email_from", json!("rms@example.org")),
        ];
        let s = eff(&[], &db).unwrap_err();
        assert!(s.contains("--alarm-email-to"), "{s}");
        let s = eff(
            &["--smtp-password", "pw-1", "--smtp-host", "mail.example"],
            &db,
        )
        .unwrap_err();
        assert!(
            s.contains("--alarm-email-to"),
            "the sender still comes from the web"
        );
        let s = eff(&["--smtp-password", "pw-1"], &db[..2]).unwrap();
        assert_eq!((s.smtp_host, s.smtp_port), (None, 587), "ignored");
        let matches = Cli::command()
            .try_get_matches_from(["dhonomos", "--database-url", "x", "--smtp-password", "p"])
            .unwrap();
        for key in SMTP_PAIRED {
            assert_eq!(
                lock_reason(&matches, key),
                Some(LOCKED_BY_SMTP_PASSWORD),
                "{key}"
            );
        }
        assert_eq!(lock_reason(&matches, "alarm_email_from"), None);
        let matches = Cli::command()
            .try_get_matches_from(["dhonomos", "--database-url", "x", "--smtp-port", "25"])
            .unwrap();
        assert_eq!(lock_reason(&matches, "smtp_port"), Some(LOCKED_BY_CONFIG));
        assert_eq!(lock_reason(&matches, "smtp_host"), None);
    }

    #[test]
    fn the_view_says_what_the_web_may_change() {
        let items = view_of(&[
            "--database-url",
            "postgres://x",
            "--session-hours",
            "4",
            "--smtp-password",
            "pw-1",
        ]);
        let i = item(&items, "session_hours");
        assert_eq!(
            (i.editable, i.locked_reason.as_deref(), i.kind),
            (false, Some(LOCKED_BY_CONFIG), SettingKind::Text)
        );
        let i = item(&items, "smtp_host");
        assert_eq!(
            (i.editable, i.locked_reason.as_deref()),
            (false, Some(LOCKED_BY_SMTP_PASSWORD))
        );
        let i = item(&items, "api_rate_limit");
        assert_eq!((i.editable, i.locked_reason.as_deref()), (true, None));
        // Not runtime -> never editable, no lock reason.
        let i = item(&items, "acs_listen");
        assert_eq!((i.editable, i.locked_reason.as_deref()), (false, None));
        let i = item(&items, "require_totp_roles");
        assert!(!i.editable);
        // Kinds.
        assert_eq!(item(&items, "usp_auto_subscribe").kind, SettingKind::Bool);
        assert_eq!(item(&items, "acs_plaintext").kind, SettingKind::Bool);
        assert_eq!(item(&items, "webhook_url").kind, SettingKind::List);
        assert_eq!(item(&items, "alarm_email_to").kind, SettingKind::List);
        assert_eq!(item(&items, "smtp_security").kind, SettingKind::Text);
        let editable: Vec<&str> = items
            .iter()
            .filter(|i| i.category == Runtime)
            .map(|i| i.key.as_str())
            .collect();
        assert_eq!(editable.len(), 31, "{editable:?}");
    }

    /// Writer into a shared buffer, for log lines.
    #[derive(Clone, Default)]
    struct Log(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Log {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn bad_stored_values_are_logged_and_left_out_at_startup() {
        let log = Log::default();
        let writer = log.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let db: BTreeMap<String, Value> = [
            ("api_rate_limit", json!("7")),
            ("session_hours", json!("soon")),
            // OK alone, not with default request timeout (30 s).
            ("usp_full_read_timeout", json!("10")),
            ("webhook_url", json!(["https://a.example"])),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        let effective = |values: &BTreeMap<String, Value>| {
            effective_with(
                &Cli::command(),
                &["dhonomos", "--database-url", "postgres://x"].map(OsString::from),
                values,
            )
        };
        let s = tracing::subscriber::with_default(subscriber, || load(&db, effective)).unwrap();
        assert_eq!(
            (s.api_rate_limit, s.session_hours, s.usp_full_read_timeout),
            (7, 12, 120)
        );
        assert_eq!(s.webhook_url, ["https://a.example"]);
        let log = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
        assert!(log.contains("WARN"), "{log}");
        assert!(log.contains("key=session_hours"), "{log}");
        assert!(log.contains("key=usp_full_read_timeout"), "{log}");
        assert!(!log.contains("key=api_rate_limit"), "{log}");
        // Value refused alone -> no block of other changes.
        // Conflict with another stored value -> block.
        let mut change = db.clone();
        change.insert("api_rate_limit".into(), json!("9"));
        change.remove("usp_full_read_timeout");
        assert_eq!(validate(&change, effective), Ok(()));
        change.insert("usp_request_timeout".into(), json!("100"));
        change.insert("usp_full_read_timeout".into(), json!("60"));
        assert!(
            validate(&change, effective)
                .unwrap_err()
                .contains("must not be shorter")
        );
        // Nothing wrong -> nothing logged, all taken.
        let fine: BTreeMap<String, Value> = [("api_rate_limit".to_owned(), json!("7"))].into();
        assert_eq!(load(&fine, effective).unwrap().api_rate_limit, 7);
    }
}
