//! Dhonomos server entry point.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context as _;
use clap::{CommandFactory as _, FromArgMatches as _, Parser, ValueEnum};
use dhonomos_api::{ApiConfig, FilesConfig};
use dhonomos_core::{CpeCredentials, CwmpBackend, FileSigner, Onboarding, OnboardingMode, Waker};
use dhonomos_cwmp_server::{AcsServer, AuthMode, Config as AcsConfig, ConnReqCredentials};
use dhonomos_store::{DEFAULT_TENANT, Store};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

mod settings;
mod telemetry;

/// Process role. One binary runs any subset of the services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Role {
    /// CWMP ACS listener.
    Acs,
    /// Northbound API.
    Api,
    /// Everything.
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OnboardingArg {
    /// Register and activate unknown devices.
    Auto,
    /// Register unknown devices as quarantined (no tasks until activated).
    Quarantine,
    /// Only accept devices pre-registered through the API.
    Preregistered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CpeAuth {
    None,
    Basic,
    Digest,
}

/// Client certificates on the USP WebSocket MTP over TLS (wss).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ClientCert {
    /// Not requested.
    None,
    /// Requested; Agent that presents one must be the EndpointID it names.
    Optional,
    /// Every Agent must present one (USP CA or --usp-ws-client-ca).
    Required,
}

#[derive(Debug, Parser)]
#[command(version, about = "Dhonomos: CWMP ACS and USP Controller")]
struct Cli {
    /// Services this process runs.
    #[arg(long, value_enum, default_value_t = Role::All, env = "DHONOMOS_ROLE")]
    role: Role,

    /// PostgreSQL connection URL.
    #[arg(long, env = "DHONOMOS_DATABASE_URL")]
    database_url: String,

    /// Max database connections.
    #[arg(long, default_value_t = 16, env = "DHONOMOS_DATABASE_MAX_CONNECTIONS")]
    database_max_connections: u32,

    /// Max ACS requests at once; more get 503 and retry (CW-17).
    #[arg(long, default_value_t = 1024, env = "DHONOMOS_ACS_MAX_CONCURRENT")]
    acs_max_concurrent: usize,

    /// Max open ACS connections; more are closed at accept. 0 = unlimited.
    #[arg(long, default_value_t = 20_000, env = "DHONOMOS_ACS_MAX_CONNECTIONS")]
    acs_max_connections: usize,

    /// Max open ACS connections per address (IPv6: /64); more are closed at accept.
    /// 0 = unlimited, e.g. TLS-terminating proxy or load generator in front
    /// (one address for all CPEs).
    #[arg(
        long,
        default_value_t = 256,
        env = "DHONOMOS_ACS_MAX_CONNECTIONS_PER_IP"
    )]
    acs_max_connections_per_ip: usize,

    /// Failed CPE authentications per address (IPv6: /64) in 10 min
    /// -> address refused for 10 min (CW-17).
    /// 0 = off, e.g. many CPEs behind one CGNAT address (ACS sees only that address).
    #[arg(long, default_value_t = 20, env = "DHONOMOS_CPE_AUTH_FAILURE_LIMIT")]
    cpe_auth_failure_limit: u32,

    /// Sessions per CPE per minute (= burst); more get fault 8005, CPE retries later.
    /// Against a CPE stuck in an Inform loop (ADR-084). 0 = off.
    #[arg(long, default_value_t = 30, env = "DHONOMOS_CPE_SESSION_LIMIT")]
    cpe_session_limit: u32,

    /// Accept RFC 2069 Digest responses (no qop) from CPEs.
    /// Challenge always offers qop=auth; answer without qop -> no replay protection.
    /// Turn off once every CPE model in the fleet uses qop=auth.
    #[arg(long, env = "DHONOMOS_CPE_DIGEST_NO_QOP", default_value_t = true, action = clap::ArgAction::Set)]
    cpe_digest_no_qop: bool,

    /// Tie Digest nonces to the address they were issued to (IPv6: its /64).
    /// Turn off if CPEs come through several proxies (address differs: challenge != answer).
    #[arg(long, env = "DHONOMOS_CPE_DIGEST_BIND_CLIENT", default_value_t = true, action = clap::ArgAction::Set)]
    cpe_digest_bind_client: bool,

    /// Max parameters stored from one CPE message (Inform, GPV or GPN response).
    /// Rest dropped and counted.
    #[arg(long, default_value_t = dhonomos_core::DEFAULT_MAX_PARAMS_PER_MESSAGE, env = "DHONOMOS_CPE_MAX_PARAMS_PER_MESSAGE")]
    cpe_max_params_per_message: usize,

    /// Max parameters stored per CPE; more new ones dropped and counted.
    #[arg(long, default_value_t = dhonomos_core::DEFAULT_MAX_PARAMS_PER_DEVICE, env = "DHONOMOS_CPE_MAX_PARAMS_PER_DEVICE")]
    cpe_max_params_per_device: usize,

    /// Commit device reports synchronously too (slower on disks with slow fsync).
    #[arg(long, env = "DHONOMOS_DATABASE_DEVICE_SYNC_COMMIT")]
    database_device_sync_commit: bool,

    /// ACS listen address; `[::]` accepts IPv4 and IPv6.
    #[arg(long, default_value = "[::]:7547", env = "DHONOMOS_ACS_LISTEN")]
    acs_listen: SocketAddr,

    /// PEM certificate chain for the ACS (HTTPS).
    /// Re-read on file change (check 1/min): renewed certificate needs no restart.
    #[arg(long, env = "DHONOMOS_ACS_TLS_CERT", requires = "acs_tls_key")]
    acs_tls_cert: Option<std::path::PathBuf>,

    /// PEM private key for the ACS certificate.
    #[arg(long, env = "DHONOMOS_ACS_TLS_KEY", requires = "acs_tls_cert")]
    acs_tls_key: Option<std::path::PathBuf>,

    /// Serve the ACS over plain HTTP (development, or behind a TLS-terminating proxy).
    #[arg(long, env = "DHONOMOS_ACS_PLAINTEXT", conflicts_with = "acs_tls_cert")]
    acs_plaintext: bool,

    /// How CPEs authenticate to the ACS.
    #[arg(long, value_enum, default_value_t = CpeAuth::Digest, env = "DHONOMOS_CPE_AUTH")]
    cpe_auth: CpeAuth,

    /// Username shared by all CPEs.
    #[arg(long, env = "DHONOMOS_CPE_USERNAME")]
    cpe_username: Option<String>,

    /// Password shared by all CPEs.
    #[arg(long, env = "DHONOMOS_CPE_PASSWORD", hide_env_values = true)]
    cpe_password: Option<String>,

    /// Handling of devices never seen before (CO-12): CWMP devices and USP Agents.
    #[arg(long, value_enum, default_value_t = OnboardingArg::Auto, env = "DHONOMOS_ONBOARDING")]
    onboarding: OnboardingArg,

    /// Only admit these OUIs (comma separated); empty = all.
    #[arg(long, value_delimiter = ',', env = "DHONOMOS_ALLOWED_OUIS")]
    allowed_oui: Vec<String>,

    /// YAML file with provisioning presets (CO-04).
    #[arg(long, env = "DHONOMOS_PRESETS")]
    presets: Option<std::path::PathBuf>,

    /// Idle seconds before a CWMP session is aborted.
    #[arg(long, default_value_t = 60, env = "DHONOMOS_SESSION_TIMEOUT")]
    session_timeout: u64,

    /// API listen address.
    #[arg(long, default_value = "127.0.0.1:8080", env = "DHONOMOS_API_LISTEN")]
    api_listen: SocketAddr,

    /// Connection request username shared by all CPEs.
    #[arg(long, env = "DHONOMOS_CR_USERNAME")]
    cr_username: Option<String>,

    /// Connection request password shared by all CPEs.
    #[arg(long, env = "DHONOMOS_CR_PASSWORD", hide_env_values = true)]
    cr_password: Option<String>,

    /// Networks connection requests may go to (repeatable, e.g. 10.0.0.0/8).
    /// Set: only these; can re-open the built-in refused ranges (loopback, link-local, multicast).
    #[arg(long, env = "DHONOMOS_CR_ALLOW", value_delimiter = ',')]
    cr_allow: Vec<dhonomos_core::Cidr>,

    /// Own random Connection Request credentials per new CPE on zero-touch (needs --secrets-key).
    /// `false`: shared --cr-username/--cr-password for all.
    #[arg(long, env = "DHONOMOS_CR_PER_DEVICE", default_value_t = true, action = clap::ArgAction::Set)]
    cr_per_device: bool,

    /// Own ACS credentials per new CPE on zero-touch (needs --secrets-key and CPE authentication).
    /// Shared --cpe-username/--cpe-password work for a device until it logs in with its own,
    /// then refused for it.
    #[arg(long, env = "DHONOMOS_ACS_AUTH_PER_DEVICE")]
    acs_auth_per_device: bool,

    /// Answer a Basic auth challenge from a CPE's connection request URL.
    /// Then: CR password in clear text over plain http; CPE (or whoever answers at its
    /// reported address) chooses what to ask for. Off: only Digest is answered.
    #[arg(long, env = "DHONOMOS_CR_BASIC_AUTH")]
    cr_basic_auth: bool,

    /// Networks connection requests never go to (repeatable), e.g. the ACS's own subnet.
    #[arg(long, env = "DHONOMOS_CR_DENY", value_delimiter = ',')]
    cr_deny: Vec<dhonomos_core::Cidr>,

    /// Directory for firmware and configuration files served to devices.
    #[arg(long, default_value = "data/files", env = "DHONOMOS_FILES_DIR")]
    files_dir: std::path::PathBuf,

    /// File server listen address (devices download from here).
    #[arg(long, default_value = "[::]:7548", env = "DHONOMOS_FILES_LISTEN")]
    files_listen: SocketAddr,

    /// PEM certificate chain for the file server (HTTPS on --files-listen).
    /// Re-read on file change (check 1/min): renewed certificate needs no restart.
    #[arg(
        long,
        visible_alias = "file-server-tls-cert",
        env = "DHONOMOS_FILES_TLS_CERT",
        requires = "files_tls_key"
    )]
    files_tls_cert: Option<std::path::PathBuf>,

    /// PEM private key for the file server certificate.
    #[arg(
        long,
        visible_alias = "file-server-tls-key",
        env = "DHONOMOS_FILES_TLS_KEY",
        requires = "files_tls_cert"
    )]
    files_tls_key: Option<std::path::PathBuf>,

    /// URL devices use to reach the file server, e.g. https://acs.example.net:7548.
    /// Default: http://127.0.0.1:7548, https:// with --files-tls-cert.
    /// Set it explicitly in processes without the file server (--role api).
    #[arg(long, env = "DHONOMOS_FILES_PUBLIC_URL")]
    files_public_url: Option<String>,

    /// Secret for signed download links; set it so links survive restarts.
    #[arg(long, env = "DHONOMOS_FILES_SECRET", hide_env_values = true)]
    files_secret: Option<String>,

    /// Max upload size in bytes.
    #[arg(long, default_value_t = 1 << 30, env = "DHONOMOS_FILES_MAX_BYTES")]
    files_max_bytes: u64,

    /// Bandwidth of all device downloads together, Mbit/s (default: unlimited).
    #[arg(long, env = "DHONOMOS_FILES_TOTAL_MBPS")]
    files_total_mbps: Option<u64>,

    /// Bandwidth per device download, Mbit/s (default: unlimited).
    #[arg(long, env = "DHONOMOS_FILES_DOWNLOAD_MBPS")]
    files_download_mbps: Option<u64>,

    /// Max device downloads at once; more get 503, retried later (default: unlimited).
    #[arg(long, env = "DHONOMOS_FILES_MAX_DOWNLOADS")]
    files_max_downloads: Option<usize>,

    /// Hours a download link stays valid.
    #[arg(long, default_value_t = 24, env = "DHONOMOS_FILES_LINK_HOURS")]
    files_link_hours: u64,

    /// Base64 32-byte key for stored secrets (CO-16). Generate: `openssl rand -base64 32`.
    /// Without it: credentials and task passwords cannot be stored.
    #[arg(long, env = "DHONOMOS_SECRETS_KEY", hide_env_values = true)]
    secrets_key: Option<String>,

    /// ID recorded with each secret (change it on key rotation).
    #[arg(long, default_value = "k1", env = "DHONOMOS_SECRETS_KEY_ID")]
    secrets_key_id: String,

    /// Keys being retired (comma-separated base64): secrets they sealed still open,
    /// re-encrypted with --secrets-key at startup (ADR-082).
    /// Remove them once the log says nothing is left under them.
    #[arg(
        long,
        env = "DHONOMOS_SECRETS_OLD_KEYS",
        hide_env_values = true,
        value_delimiter = ',',
        requires = "secrets_key"
    )]
    secrets_old_keys: Vec<String>,

    /// Address of the USP WebSocket MTP (Agents connect to ws://<addr>/usp?eid=...).
    /// Set (or --usp-mqtt-host): USP Controller on.
    #[arg(long, env = "DHONOMOS_USP_WS_LISTEN")]
    usp_ws_listen: Option<SocketAddr>,

    /// Address of the embedded STOMP broker (US-06, ADR-092): Agents use STOMP 1.2
    /// (61613; 61614 with --usp-stomp-tls). Set: USP Controller on.
    #[arg(long, env = "DHONOMOS_USP_STOMP_LISTEN")]
    usp_stomp_listen: Option<SocketAddr>,

    /// STOMP over TLS; certificate and client certificate settings as for wss
    /// (--usp-ws-tls-cert/--usp-ws-tls-key or the USP CA, --usp-ws-client-cert).
    #[arg(long, env = "DHONOMOS_USP_STOMP_TLS", requires = "usp_stomp_listen")]
    usp_stomp_tls: bool,

    /// Shared first-contact STOMP login of the Agents (their factory setting).
    #[arg(
        long,
        env = "DHONOMOS_USP_STOMP_LOGIN",
        requires = "usp_stomp_passcode"
    )]
    usp_stomp_login: Option<String>,

    /// Passcode for --usp-stomp-login.
    #[arg(
        long,
        env = "DHONOMOS_USP_STOMP_PASSCODE",
        hide_env_values = true,
        requires = "usp_stomp_login"
    )]
    usp_stomp_passcode: Option<String>,

    /// Take STOMP Agents without a login on a network address.
    /// Refused by default; isolated labs only.
    #[arg(long, env = "DHONOMOS_USP_STOMP_ALLOW_ANONYMOUS")]
    usp_stomp_allow_anonymous: bool,

    /// STOMP destination Agents send Records to (their Controller MTP STOMP.Destination).
    #[arg(
        long,
        default_value = "/queue/usp.controller",
        env = "DHONOMOS_USP_STOMP_CONTROLLER_DEST"
    )]
    usp_stomp_controller_dest: String,

    /// Agent STOMP destination = this + its EndpointID (sent in CONNECTED subscribe-dest).
    #[arg(
        long,
        default_value = "/queue/usp.agent.",
        env = "DHONOMOS_USP_STOMP_AGENT_DEST_PREFIX"
    )]
    usp_stomp_agent_dest_prefix: String,

    /// Max open STOMP connections; more are closed at accept. 0 = unlimited.
    #[arg(
        long,
        default_value_t = 20_000,
        env = "DHONOMOS_USP_STOMP_MAX_CONNECTIONS"
    )]
    usp_stomp_max_connections: usize,

    /// Max open STOMP connections per address (IPv6: /64); more are closed at accept.
    /// 0 = unlimited, e.g. TLS-terminating proxy in front (one address for all Agents).
    #[arg(
        long,
        default_value_t = 256,
        env = "DHONOMOS_USP_STOMP_MAX_CONNECTIONS_PER_IP"
    )]
    usp_stomp_max_connections_per_ip: usize,

    /// Address of the embedded MQTT broker (ADR-093): Agents use MQTT 5.0
    /// (1883; 8883 with --usp-mqtt-broker-tls). Independent of --usp-mqtt-host
    /// (client of an external broker). Set: USP Controller on.
    #[arg(long, env = "DHONOMOS_USP_MQTT_BROKER_LISTEN")]
    usp_mqtt_broker_listen: Option<SocketAddr>,

    /// MQTT broker over TLS; certificate and client certificate settings as for wss
    /// (--usp-ws-tls-cert/--usp-ws-tls-key or the USP CA, --usp-ws-client-cert).
    #[arg(
        long,
        env = "DHONOMOS_USP_MQTT_BROKER_TLS",
        requires = "usp_mqtt_broker_listen"
    )]
    usp_mqtt_broker_tls: bool,

    /// Shared first-contact MQTT user name of the Agents (their factory setting).
    #[arg(
        long,
        env = "DHONOMOS_USP_MQTT_BROKER_USERNAME",
        requires = "usp_mqtt_broker_password"
    )]
    usp_mqtt_broker_username: Option<String>,

    /// Password for --usp-mqtt-broker-username.
    #[arg(
        long,
        env = "DHONOMOS_USP_MQTT_BROKER_PASSWORD",
        hide_env_values = true,
        requires = "usp_mqtt_broker_username"
    )]
    usp_mqtt_broker_password: Option<String>,

    /// Take MQTT Agents without a user name on a network address.
    /// Refused by default; isolated labs only.
    #[arg(long, env = "DHONOMOS_USP_MQTT_BROKER_ALLOW_ANONYMOUS")]
    usp_mqtt_broker_allow_anonymous: bool,

    /// MQTT topic Agents publish Records to (their Controller MTP MQTT.Topic);
    /// also <topic>/<EndpointID>.
    #[arg(
        long,
        default_value = "usp/controller/dhonomos",
        env = "DHONOMOS_USP_MQTT_BROKER_CONTROLLER_TOPIC"
    )]
    usp_mqtt_broker_controller_topic: String,

    /// Agent MQTT topic = this + its EndpointID
    /// (sent in CONNACK subscribe-topic and Response Information).
    #[arg(
        long,
        default_value = "usp/agent/",
        env = "DHONOMOS_USP_MQTT_BROKER_AGENT_TOPIC_PREFIX"
    )]
    usp_mqtt_broker_agent_topic_prefix: String,

    /// Max open MQTT broker connections; more are closed at accept. 0 = unlimited.
    #[arg(
        long,
        default_value_t = 20_000,
        env = "DHONOMOS_USP_MQTT_BROKER_MAX_CONNECTIONS"
    )]
    usp_mqtt_broker_max_connections: usize,

    /// Max open MQTT broker connections per address (IPv6: /64); more are closed at accept.
    /// 0 = unlimited, e.g. TLS-terminating proxy in front (one address for all Agents).
    #[arg(
        long,
        default_value_t = 256,
        env = "DHONOMOS_USP_MQTT_BROKER_MAX_CONNECTIONS_PER_IP"
    )]
    usp_mqtt_broker_max_connections_per_ip: usize,

    /// Serve the USP WebSocket MTP over TLS (wss).
    /// Certificate: --usp-ws-tls-cert/--usp-ws-tls-key,
    /// or issued by the USP CA for --usp-ws-tls-name.
    #[arg(long, env = "DHONOMOS_USP_WS_TLS", requires = "usp_ws_listen")]
    usp_ws_tls: bool,

    /// PEM certificate chain for wss (also STOMP and MQTT broker over TLS).
    /// Re-read on file change (check 1/min): renewed certificate needs no restart.
    #[arg(long, env = "DHONOMOS_USP_WS_TLS_CERT", requires = "usp_ws_tls_key")]
    usp_ws_tls_cert: Option<std::path::PathBuf>,

    /// PEM private key for wss.
    #[arg(long, env = "DHONOMOS_USP_WS_TLS_KEY", requires = "usp_ws_tls_cert")]
    usp_ws_tls_key: Option<std::path::PathBuf>,

    /// Names (DNS or IP) in the wss certificate issued by the USP CA.
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "localhost,127.0.0.1",
        env = "DHONOMOS_USP_WS_TLS_NAME"
    )]
    usp_ws_tls_name: Vec<String>,

    /// Client certificates on wss (needs --usp-ca-dir or --usp-ws-client-ca unless `none`).
    #[arg(long, value_enum, default_value_t = ClientCert::Optional, env = "DHONOMOS_USP_WS_CLIENT_CERT")]
    usp_ws_client_cert: ClientCert,

    /// Take WebSocket Agents without a client certificate on a network address
    /// (any client can pose as any Agent). Refused by default unless wss with
    /// `--usp-ws-client-cert required`; isolated labs only.
    #[arg(long, env = "DHONOMOS_USP_WS_ALLOW_ANONYMOUS")]
    usp_ws_allow_anonymous: bool,

    /// More CAs (PEM file) for Agent certificates on wss, e.g. a vendor's factory CA.
    /// Certificate must still name the Agent's EndpointID.
    #[arg(long, env = "DHONOMOS_USP_WS_CLIENT_CA", requires = "usp_ws_tls")]
    usp_ws_client_ca: Option<std::path::PathBuf>,

    /// Directory of the USP CA (`ca.pem`, `ca.key`), created on first start.
    /// Enables Agent certificate issuance and client certificates on wss (US-08).
    #[arg(long, env = "DHONOMOS_USP_CA_DIR")]
    usp_ca_dir: Option<std::path::PathBuf>,

    /// Common name of the USP CA certificate; only used when the CA is created
    /// (first start with an empty `--usp-ca-dir`).
    /// Default: `Dhonomos USP CA <8 random hex digits>`,
    /// so two installations never share a CA name.
    #[arg(long, env = "DHONOMOS_USP_CA_NAME", requires = "usp_ca_dir")]
    usp_ca_name: Option<String>,

    /// MQTT broker host for USP; set: USP Controller on.
    #[arg(long, env = "DHONOMOS_USP_MQTT_HOST")]
    usp_mqtt_host: Option<String>,

    /// MQTT broker port.
    #[arg(long, default_value_t = 1883, env = "DHONOMOS_USP_MQTT_PORT")]
    usp_mqtt_port: u16,

    /// MQTT username for the Controller.
    #[arg(long, env = "DHONOMOS_USP_MQTT_USERNAME")]
    usp_mqtt_username: Option<String>,

    /// MQTT password for the Controller.
    #[arg(long, env = "DHONOMOS_USP_MQTT_PASSWORD", hide_env_values = true)]
    usp_mqtt_password: Option<String>,

    /// Connect to the MQTT broker over TLS (usually port 8883):
    /// Controller and dynamic-security connection.
    #[arg(long, env = "DHONOMOS_USP_MQTT_TLS")]
    usp_mqtt_tls: bool,

    /// Extra CA certificates (PEM file) trusted for the broker, besides the system store.
    #[arg(long, env = "DHONOMOS_USP_MQTT_CA", requires = "usp_mqtt_tls")]
    usp_mqtt_ca: Option<std::path::PathBuf>,

    /// Client certificate (PEM file) for mutual TLS with the broker.
    #[arg(long, env = "DHONOMOS_USP_MQTT_CLIENT_CERT", requires_all = ["usp_mqtt_tls", "usp_mqtt_client_key"])]
    usp_mqtt_client_cert: Option<std::path::PathBuf>,

    /// Private key (PEM file) of --usp-mqtt-client-cert.
    #[arg(
        long,
        env = "DHONOMOS_USP_MQTT_CLIENT_KEY",
        requires = "usp_mqtt_client_cert"
    )]
    usp_mqtt_client_key: Option<std::path::PathBuf>,

    /// Name the broker's certificate must carry (default: --usp-mqtt-host).
    #[arg(long, env = "DHONOMOS_USP_MQTT_TLS_NAME", requires = "usp_mqtt_tls")]
    usp_mqtt_tls_name: Option<String>,

    /// Controller EndpointID (ADR-020).
    #[arg(
        long,
        default_value = "self::dhonomos-controller",
        env = "DHONOMOS_USP_ENDPOINT_ID"
    )]
    usp_endpoint_id: String,

    /// Topic the Controller subscribes to (Agents' Controller MTP topic).
    #[arg(
        long,
        default_value = "usp/controller/dhonomos",
        env = "DHONOMOS_USP_TOPIC"
    )]
    usp_topic: String,

    /// Manage Agents' broker accounts via the Mosquitto dynamic-security plugin (US-17).
    /// Needs --usp-mqtt-host, --secrets-key, --usp-dynsec-username, --usp-dynsec-password.
    #[arg(long, env = "DHONOMOS_USP_DYNSEC", requires_all = ["usp_mqtt_host", "secrets_key", "usp_dynsec_username", "usp_dynsec_password"])]
    usp_dynsec: bool,

    /// Broker account allowed to publish to `$CONTROL/dynamic-security/#`.
    #[arg(long, env = "DHONOMOS_USP_DYNSEC_USERNAME")]
    usp_dynsec_username: Option<String>,

    /// Password of --usp-dynsec-username.
    #[arg(long, env = "DHONOMOS_USP_DYNSEC_PASSWORD", hide_env_values = true)]
    usp_dynsec_password: Option<String>,

    /// Agents subscribe to `<prefix><EndpointID>`.
    #[arg(
        long,
        default_value = "usp/agent/",
        env = "DHONOMOS_USP_AGENT_TOPIC_PREFIX"
    )]
    usp_agent_topic_prefix: String,

    /// Seconds to wait for an Agent's response to a USP request.
    /// Later response: dropped (logged at info).
    #[arg(long, default_value_t = 30, env = "DHONOMOS_USP_REQUEST_TIMEOUT")]
    usp_request_timeout: u64,

    /// Seconds to wait for an Agent's response to a whole data model request:
    /// Get with `Device.` (full read of a new device or after a firmware change) and the
    /// GetSupportedDM that learns the data model. Big or busy Agents (e.g. right after boot)
    /// answer these slowly. Not shorter than --usp-request-timeout.
    #[arg(long, default_value_t = 120, env = "DHONOMOS_USP_FULL_READ_TIMEOUT")]
    usp_full_read_timeout: u64,

    /// Add the Controller's own subscriptions (Boot!, OperationComplete, BulkData Push!) to
    /// every USP Agent that connects (US-10). `false`: nothing written into the Agent; then
    /// Boot! (last boot time, `1 BOOT` presets), OperationComplete (async commands such as
    /// Download(), else waiting until the 24 h limit) and USP BulkData only arrive via
    /// subscriptions set up on the Agent by other means.
    #[arg(long, env = "DHONOMOS_USP_AUTO_SUBSCRIBE", default_value_t = true, action = clap::ArgAction::Set)]
    usp_auto_subscribe: bool,

    /// Built-in STUN server for CPEs behind NAT (CW-08), e.g. 0.0.0.0:3478.
    /// UDP Connection Requests are sent from this socket.
    #[arg(long, env = "DHONOMOS_STUN_LISTEN")]
    stun_listen: Option<SocketAddr>,

    /// `host[:port]` CPEs use to reach the STUN server. Set: zero-touch configures STUN on
    /// new CPEs (username = device ID, active notification of the UDP address) and, at next
    /// Inform, on known TR-181 CPEs that report STUN parameters but are not set up for this
    /// server. STUN passwords derive from --files-secret, so it must be stable.
    #[arg(long, env = "DHONOMOS_STUN_PUBLIC_ADDRESS", requires_all = ["stun_listen", "files_secret"])]
    stun_public_address: Option<String>,

    /// Built-in XMPP server for TR-069 Annex K Connection Requests (ADR-104), e.g. 0.0.0.0:5222.
    /// CPEs behind NAT connect to it and take Connection Requests over that connection.
    /// Needs --xmpp-domain, --xmpp-tls-cert/--xmpp-tls-key (STARTTLS required, no plain XMPP)
    /// and --secrets-key. Runs with --role acs or all. Connections live in this process,
    /// so it must also serve the API (--role all), else API Connection Requests cannot use them.
    #[arg(
        long,
        env = "DHONOMOS_XMPP_LISTEN",
        requires_all = ["xmpp_domain", "xmpp_tls_cert", "xmpp_tls_key"]
    )]
    xmpp_listen: Option<SocketAddr>,

    /// XMPP domain: CPEs log in as `<device ID>@<domain>`, resolve it
    /// (`_xmpp-client._tcp.<domain>`, else `<domain>:5222`) and check the server certificate
    /// against it, so the certificate must name it (subjectAltName). Zero-touch sets it on CPEs.
    #[arg(long, env = "DHONOMOS_XMPP_DOMAIN", requires = "xmpp_listen")]
    xmpp_domain: Option<String>,

    /// PEM certificate chain for the XMPP server (STARTTLS).
    /// Re-read on file change (check 1/min): renewed certificate needs no restart.
    #[arg(
        long,
        env = "DHONOMOS_XMPP_TLS_CERT",
        requires_all = ["xmpp_listen", "xmpp_tls_key"]
    )]
    xmpp_tls_cert: Option<std::path::PathBuf>,

    /// PEM private key for the XMPP server certificate.
    #[arg(
        long,
        env = "DHONOMOS_XMPP_TLS_KEY",
        requires_all = ["xmpp_listen", "xmpp_tls_cert"]
    )]
    xmpp_tls_key: Option<std::path::PathBuf>,

    /// Seconds between XMPP pings of a CPE (`KeepAliveInterval`, set by zero-touch).
    /// Keep NAT mappings open; cost CPE data: ~35 MB/month at 30 s, 9 MB at 120 s.
    #[arg(
        long,
        default_value_t = 30,
        env = "DHONOMOS_XMPP_KEEPALIVE",
        value_parser = clap::value_parser!(u32).range(5..=3600)
    )]
    xmpp_keepalive: u32,

    /// Seconds without anything from a CPE before its XMPP connection is closed
    /// (default: 3 keep-alives + 30 s).
    #[arg(long, env = "DHONOMOS_XMPP_IDLE_TIMEOUT", value_parser = clap::value_parser!(u64).range(1..))]
    xmpp_idle_timeout: Option<u64>,

    /// Max open XMPP connections; more are closed at accept. 0 = unlimited.
    #[arg(long, default_value_t = 50_000, env = "DHONOMOS_XMPP_MAX_CONNECTIONS")]
    xmpp_max_connections: usize,

    /// Max open XMPP connections per address (IPv6: /64); more are closed at accept.
    /// Many CPEs share one address behind carrier-grade NAT. 0 = unlimited.
    #[arg(
        long,
        default_value_t = 1024,
        env = "DHONOMOS_XMPP_MAX_CONNECTIONS_PER_IP"
    )]
    xmpp_max_connections_per_ip: usize,

    /// IPv4 range for the tunnel prefixes of WireGuard overlay networks (ADR-110): a network
    /// without its own prefix gets the lowest free block of its size (default /24) from it.
    /// Pick a range no site LAN, ISP management network, cellular carrier-grade NAT
    /// (100.64.0.0/10) or Docker network on a hub host uses. A /8 to /29 network address.
    #[arg(long, default_value = "10.77.0.0/16", env = "DHONOMOS_WG_ADDRESS_POOL")]
    wg_address_pool: dhonomos_wireguard::Ipv4Prefix,

    /// Hours a revoked WireGuard member's tunnel address rests before reuse, so a peer
    /// with the old configuration does not meet a new owner. 0: no wait.
    #[arg(
        long,
        default_value_t = 24,
        env = "DHONOMOS_WG_ADDRESS_REUSE_DELAY_HOURS"
    )]
    wg_address_reuse_delay_hours: u64,

    /// Alarm rules (YAML, CO-07), evaluated every minute.
    /// No file: rules in the database, edited from the web. File: read-only on the web.
    #[arg(long, env = "DHONOMOS_ALARMS")]
    alarms: Option<std::path::PathBuf>,

    /// Webhook URL for alarm notifications (repeatable).
    #[arg(long, env = "DHONOMOS_WEBHOOK_URL", value_delimiter = ',')]
    webhook_url: Vec<String>,

    /// Secret for the X-Dhonomos-Signature HMAC of webhook payloads.
    #[arg(
        long,
        env = "DHONOMOS_WEBHOOK_SECRET",
        hide_env_values = true,
        default_value = ""
    )]
    webhook_secret: String,

    /// Ship the audit log to this webhook (HTTP or HTTPS), in order, in batches:
    /// copy outside the database (ADR-083).
    #[arg(long, env = "DHONOMOS_AUDIT_WEBHOOK_URL")]
    audit_webhook_url: Option<String>,

    /// Secret for the X-Dhonomos-Signature HMAC of audit batches.
    #[arg(
        long,
        env = "DHONOMOS_AUDIT_WEBHOOK_SECRET",
        hide_env_values = true,
        default_value = ""
    )]
    audit_webhook_secret: String,

    /// SMTP server for alarm e-mails (with --alarm-email-from and --alarm-email-to).
    #[arg(long, env = "DHONOMOS_SMTP_HOST")]
    smtp_host: Option<String>,

    /// SMTP port.
    #[arg(long, default_value_t = 587, env = "DHONOMOS_SMTP_PORT")]
    smtp_port: u16,

    /// `starttls` (587), `tls` (465) or `none` (a trusted relay; no login then).
    #[arg(long, value_enum, default_value_t = SmtpSecurity::Starttls, env = "DHONOMOS_SMTP_SECURITY")]
    smtp_security: SmtpSecurity,

    /// SMTP login.
    #[arg(long, env = "DHONOMOS_SMTP_USERNAME")]
    smtp_username: Option<String>,

    /// SMTP password.
    #[arg(long, env = "DHONOMOS_SMTP_PASSWORD", hide_env_values = true)]
    smtp_password: Option<String>,

    /// Extra CA certificates (PEM) trusted for the SMTP server.
    #[arg(long, env = "DHONOMOS_SMTP_CA")]
    smtp_ca: Option<std::path::PathBuf>,

    /// Sender of alarm e-mails.
    #[arg(long, env = "DHONOMOS_ALARM_EMAIL_FROM")]
    alarm_email_from: Option<String>,

    /// Recipients of alarm e-mails (repeatable).
    #[arg(long, env = "DHONOMOS_ALARM_EMAIL_TO", value_delimiter = ',')]
    alarm_email_to: Vec<String>,

    /// Least severe alarm that is e-mailed: critical, major, minor or warning.
    #[arg(
        long,
        default_value = "major",
        env = "DHONOMOS_ALARM_EMAIL_MIN_SEVERITY"
    )]
    alarm_email_min_severity: String,

    /// Days of device events kept (one per Inform); 0 = forever.
    #[arg(long, default_value_t = 30, env = "DHONOMOS_EVENTS_RETENTION_DAYS")]
    events_retention_days: i64,

    /// Days finished tasks are kept; 0 = forever.
    #[arg(long, default_value_t = 90, env = "DHONOMOS_TASKS_RETENTION_DAYS")]
    tasks_retention_days: i64,

    /// Days cleared alarms are kept; 0 = forever.
    #[arg(long, default_value_t = 90, env = "DHONOMOS_ALARMS_RETENTION_DAYS")]
    alarms_retention_days: i64,

    /// Days of device time series (BulkData) kept.
    #[arg(long, default_value_t = 30, env = "DHONOMOS_METRICS_RETENTION_DAYS")]
    metrics_retention_days: i64,

    /// Most recent days kept as raw rows (incl. today); older days compacted.
    /// Reports older than this are dropped.
    #[arg(long, default_value_t = 2, env = "DHONOMOS_METRICS_RAW_DAYS")]
    metrics_raw_days: i64,

    /// Create the operator account `admin` with this password at start if missing (NB-04).
    /// Once accounts exist, API and UI need a login, an API key or the token.
    #[arg(long, env = "DHONOMOS_ADMIN_PASSWORD", hide_env_values = true)]
    admin_password: Option<String>,

    /// Serve the API without accounts or token on a non-loopback address (anyone is admin).
    /// Refused by default; isolated labs only.
    #[arg(long, env = "DHONOMOS_API_ALLOW_OPEN")]
    api_allow_open: bool,

    /// UI session cookie: Secure and `__Host-` prefix (for a UI over HTTPS).
    /// Turning it on ends older sessions (one new login).
    #[arg(long, env = "DHONOMOS_SECURE_COOKIES")]
    secure_cookies: bool,

    /// UI session lifetime in hours.
    #[arg(long, default_value_t = 12, env = "DHONOMOS_SESSION_HOURS")]
    session_hours: i64,

    /// UI session unused this many minutes ends (lifetime above still applies).
    /// 0 = no idle limit. (ADR-103)
    #[arg(long, default_value_t = 60, env = "DHONOMOS_SESSION_IDLE_MINUTES")]
    session_idle_minutes: i64,

    /// Reverse proxies (comma-separated networks, e.g. 127.0.0.1/32) whose X-Forwarded-For,
    /// Forwarded, X-Forwarded-Proto and X-Forwarded-Host headers are believed.
    /// Request from one: client = right-most address in the forwarding header that is not
    /// one of them (rate limits, login lockouts, logs). Headers from others: ignored.
    /// Empty: no proxy trusted; every visitor behind a proxy counts as the proxy's address.
    /// (ADR-103)
    #[arg(long, env = "DHONOMOS_TRUSTED_PROXIES", value_delimiter = ',')]
    trusted_proxies: Vec<dhonomos_core::Cidr>,

    /// Address the UI is served at, e.g. https://rms.example.org (scheme, host, optional port).
    /// Browser change request accepted only with exactly this `Origin`.
    /// Unset: `Origin` must match the request's Host
    /// (from a trusted proxy: X-Forwarded-Host). (ADR-103)
    #[arg(long, env = "DHONOMOS_PUBLIC_URL")]
    public_url: Option<dhonomos_api::PublicOrigin>,

    /// Roles (comma-separated: admin, operator, viewer; `none` = no role) whose accounts
    /// must use two-factor authentication (TOTP app, ADR-100). Such an account that logs in
    /// with a password and has none set up can only set it up. Other roles: optional.
    /// Not affected: API keys, --api-token, single sign-on.
    /// Needs --secrets-key (secrets stored encrypted). (ADR-103)
    #[arg(
        long,
        env = "DHONOMOS_REQUIRE_TOTP_ROLES",
        value_delimiter = ',',
        default_value = "admin"
    )]
    require_totp_roles: Vec<String>,

    /// Older switch for the admin role, still works. `true` adds admin to
    /// --require-totp-roles, `false` removes it (`false` + default roles: no role must).
    /// Not given: --require-totp-roles alone decides.
    #[arg(long, env = "DHONOMOS_REQUIRE_ADMIN_TOTP", action = clap::ArgAction::Set)]
    require_admin_totp: Option<bool>,

    /// Name of this installation in authenticator apps (account shows as `<issuer>:<username>`).
    #[arg(long, default_value = "Dhonomos", env = "DHONOMOS_TOTP_ISSUER")]
    totp_issuer: String,

    /// OpenID Connect issuer for single sign-on (NB-04), e.g. `https://sso.example/realms/isp`.
    #[arg(long, env = "DHONOMOS_OIDC_ISSUER")]
    oidc_issuer: Option<String>,

    /// Client ID registered at the identity provider.
    #[arg(long, env = "DHONOMOS_OIDC_CLIENT_ID")]
    oidc_client_id: Option<String>,

    /// Client secret (confidential client).
    #[arg(long, env = "DHONOMOS_OIDC_CLIENT_SECRET", hide_env_values = true)]
    oidc_client_secret: Option<String>,

    /// This server's callback URL as registered at the provider, e.g.
    /// `https://dhonomos.example/api/v1/auth/oidc/callback`.
    #[arg(long, env = "DHONOMOS_OIDC_REDIRECT_URL")]
    oidc_redirect_url: Option<String>,

    /// Scopes to request.
    #[arg(
        long,
        default_value = "openid profile email",
        env = "DHONOMOS_OIDC_SCOPES"
    )]
    oidc_scopes: String,

    /// Claim naming the user (then `email`, then `sub`); users appear as `sso:<name>`.
    #[arg(
        long,
        default_value = "preferred_username",
        env = "DHONOMOS_OIDC_USERNAME_CLAIM"
    )]
    oidc_username_claim: String,

    /// Claim with the user's groups or roles.
    #[arg(long, default_value = "groups", env = "DHONOMOS_OIDC_ROLE_CLAIM")]
    oidc_role_claim: String,

    /// Claim values granting admin (comma-separated; `*` = everyone who logs in).
    #[arg(long, env = "DHONOMOS_OIDC_ADMIN_GROUPS", value_delimiter = ',')]
    oidc_admin_groups: Vec<String>,

    /// Claim values granting operator.
    #[arg(long, env = "DHONOMOS_OIDC_OPERATOR_GROUPS", value_delimiter = ',')]
    oidc_operator_groups: Vec<String>,

    /// Claim values granting viewer.
    #[arg(long, env = "DHONOMOS_OIDC_VIEWER_GROUPS", value_delimiter = ',')]
    oidc_viewer_groups: Vec<String>,

    /// Connect to USP Agents that run a WebSocket server (devices with `usp_ws_url`, US-05),
    /// also without --usp-ws-listen or MQTT.
    #[arg(long, env = "DHONOMOS_USP_WS_CLIENTS")]
    usp_ws_clients: bool,

    /// OTLP/HTTP endpoint for OpenTelemetry traces, e.g. `http://collector:4318/v1/traces`.
    #[arg(long, env = "DHONOMOS_OTLP_ENDPOINT")]
    otlp_endpoint: Option<String>,

    /// `service.name` of exported traces.
    #[arg(long, default_value = "dhonomos", env = "DHONOMOS_OTLP_SERVICE_NAME")]
    otlp_service_name: String,

    /// Fraction of requests traced (0-1); spans inside a traced request always are.
    #[arg(long, default_value_t = 0.1, env = "DHONOMOS_OTLP_SAMPLE_RATIO")]
    otlp_sample_ratio: f64,

    /// API requests per second per user, API key or (unauthenticated) client address;
    /// burst = 4x. 0 = off. (Login and single sign-on: own per-address limit, always on.)
    #[arg(long, default_value_t = 50, env = "DHONOMOS_API_RATE_LIMIT")]
    api_rate_limit: u32,

    /// Bearer token required by the API (recommended outside localhost).
    #[arg(long, env = "DHONOMOS_API_TOKEN", hide_env_values = true)]
    api_token: Option<String>,
}

/// rustls: WARN per handshake with an IP address as SNI
/// ("Illegal SNI extension: ignoring IP address presented as hostname").
/// CPEs that reach the ACS by address always do. Handshake still works -> line is only noise.
/// Source: this target (`log` record, bridged into tracing).
const RUSTLS_SNI_QUIET: &str = "rustls::msgs::handshake=error";

/// Log filter directives: `rust_log` (default `info`) + [`RUSTLS_SNI_QUIET`].
/// `rust_log` names rustls -> no quiet directive, operator can turn its warnings on.
fn log_directives(rust_log: Option<&str>) -> String {
    let user = rust_log
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .unwrap_or("info");
    let names_rustls = user.split(',').any(|directive| {
        let target = directive
            .split(['=', '['])
            .next()
            .unwrap_or_default()
            .trim();
        target == "rustls" || target.starts_with("rustls::")
    });
    if names_rustls {
        user.to_owned()
    } else {
        format!("{user},{RUSTLS_SNI_QUIET}")
    }
}

/// Log filter for `RUST_LOG`; unusable value -> `info`.
fn log_filter(rust_log: Option<&str>) -> EnvFilter {
    EnvFilter::try_new(log_directives(rust_log))
        .unwrap_or_else(|_| EnvFilter::new(log_directives(None)))
}

/// Warning: scheme of the file server public URL != TLS of the file server.
/// Devices would get links the listener cannot answer
/// (`https://` + plain HTTP: right only with a TLS-terminating proxy).
fn files_url_scheme_warning(tls: bool, public_url: &str) -> Option<&'static str> {
    let scheme_is = |scheme: &str| {
        public_url
            .get(..scheme.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(scheme))
    };
    if tls && scheme_is("http://") {
        Some(
            "the file server serves HTTPS but --files-public-url is http://: devices are given \
             plain-HTTP download links that this listener does not answer",
        )
    } else if !tls && scheme_is("https://") {
        Some(
            "--files-public-url is https:// but the file server serves plain HTTP: right only \
             behind a TLS-terminating proxy; otherwise set --files-tls-cert and --files-tls-key",
        )
    } else {
        None
    }
}

/// Min bytes of `--files-secret`. One key signs every download, upload, diagnostics and
/// BulkData link (BulkData links never expire) and derives the STUN passwords
/// -> one signed link is enough to guess a short key offline.
const MIN_FILES_SECRET_BYTES: usize = 32;

/// `value` = sample config value, not a chosen one: `change-me` + variants, `secret`, `password`.
fn is_placeholder(value: &str) -> bool {
    let v = value.trim().to_ascii_lowercase();
    matches!(v.as_str(), "secret" | "password") || v.contains("change-me") || v.contains("changeme")
}

/// `--files-secret`: long enough, not a sample value.
fn check_files_secret(secret: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        secret.len() >= MIN_FILES_SECRET_BYTES,
        "--files-secret needs at least {MIN_FILES_SECRET_BYTES} bytes (it signs every download, \
         upload and BulkData link and derives the STUN passwords): generate one with \
         `openssl rand -base64 32`"
    );
    anyhow::ensure!(
        !is_placeholder(secret),
        "--files-secret is a placeholder from a sample file: generate a real one with \
         `openssl rand -base64 32`"
    );
    Ok(())
}

/// USP response timeouts: ordinary request, whole data model read
/// (`--usp-request-timeout`, `--usp-full-read-timeout`, seconds).
fn usp_timeouts(request_secs: u64, full_read_secs: u64) -> anyhow::Result<(Duration, Duration)> {
    anyhow::ensure!(
        request_secs > 0,
        "--usp-request-timeout must be at least 1 second: with 0 every USP request would time \
         out at once"
    );
    anyhow::ensure!(
        full_read_secs > 0,
        "--usp-full-read-timeout must be at least 1 second: with 0 every full read of an \
         Agent's data model would time out at once"
    );
    anyhow::ensure!(
        full_read_secs >= request_secs,
        "--usp-full-read-timeout ({full_read_secs} s) must not be shorter than \
         --usp-request-timeout ({request_secs} s): the full read is the slower request"
    );
    Ok((
        Duration::from_secs(request_secs),
        Duration::from_secs(full_read_secs),
    ))
}

/// ACS takes unauthenticated CPEs on a non-loopback address
/// -> anyone who reaches it can pose as any device.
fn acs_open_to_the_network(auth: CpeAuth, listen: SocketAddr) -> bool {
    auth == CpeAuth::None && !listen.ip().is_loopback()
}

/// Broker with a shared login, off loopback, without TLS
/// -> login (all an Agent needs) crosses the network in clear text.
fn shared_login_in_the_clear(listen: SocketAddr, has_login: bool, tls: bool) -> bool {
    has_login && !tls && !listen.ip().is_loopback()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `Cli::parse()`, but keep the matches: they tell the source of each value.
    let cmd = Cli::command();
    let matches = cmd.clone().get_matches();
    let cli =
        Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.format(&mut Cli::command()).exit());
    let server_settings = std::sync::Arc::new(settings::view(&cmd, &matches));
    drop(matches);
    // Configuration alone, before the runtime settings stored from the web (below).
    usp_timeouts(cli.usp_request_timeout, cli.usp_full_read_timeout)?;
    let otel = cli
        .otlp_endpoint
        .as_deref()
        .map(|ep| telemetry::provider(ep, &cli.otlp_service_name, cli.otlp_sample_ratio))
        .transpose()
        .context("setting up OpenTelemetry")?;
    tracing_subscriber::registry()
        .with(log_filter(std::env::var("RUST_LOG").ok().as_deref()))
        .with(tracing_subscriber::fmt::layer())
        .with(otel.as_ref().map(telemetry::layer))
        .init();
    if let Some(ep) = &cli.otlp_endpoint {
        tracing::info!(endpoint = %ep, ratio = cli.otlp_sample_ratio, "OpenTelemetry traces enabled");
    }

    let metrics = metrics_exporter_prometheus::PrometheusBuilder::new()
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Suffix("duration_seconds".into()),
            &[
                0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
            ],
        )
        .context("configuring metrics")?
        .install_recorder()
        .context("installing the metrics recorder")?;

    let store = Store::connect(&cli.database_url, cli.database_max_connections)
        .await
        .context("connecting to the database")?;
    store.migrate().await.context("applying migrations")?;
    // Device reports (Informs, parameters, events, task results, time series): async commit.
    // Crash -> lose < 1 s of it; devices report again (ADR-049).
    // Operator actions: sync commits on `store`.
    let device_store = if cli.database_device_sync_commit {
        store.clone()
    } else {
        Store::connect_with(&cli.database_url, cli.database_max_connections, false)
            .await
            .context("connecting to the database")?
    };
    tracing::info!(role = ?cli.role, "database ready");

    // Runtime settings: configuration, then web changes by admins (stored value refused
    // by this process -> logged, left out), then defaults. Every process follows later
    // changes (see `Live`).
    let settings_seen = store
        .config_revision(DEFAULT_TENANT, dhonomos_store::RUNTIME_SETTINGS_REVISION)
        .await
        .context("reading the runtime settings revision")?;
    let rt = settings::load(
        &store
            .runtime_settings(DEFAULT_TENANT)
            .await
            .context("reading the runtime settings")?,
        settings::effective,
    )
    .map_err(anyhow::Error::msg)?;
    let (usp_request_timeout, usp_full_read_timeout) =
        usp_timeouts(rt.usp_request_timeout, rt.usp_full_read_timeout)?;

    let runs_acs = matches!(cli.role, Role::Acs | Role::All);
    let credentials = match (cli.cpe_auth, &cli.cpe_username, &cli.cpe_password) {
        // API role never authenticates CPEs.
        _ if !runs_acs => CpeCredentials::None,
        (CpeAuth::None, _, _) => CpeCredentials::None,
        (_, Some(u), Some(p)) => CpeCredentials::Shared {
            username: u.clone(),
            password: p.clone(),
        },
        _ => anyhow::bail!("--cpe-username and --cpe-password are required unless --cpe-auth none"),
    };

    std::fs::create_dir_all(&cli.files_dir)
        .with_context(|| format!("creating {}", cli.files_dir.display()))?;
    {
        // Stored files can hold device secrets (configuration backups) -> owner-only.
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&cli.files_dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {}", cli.files_dir.display()))?;
    }
    let secret = match &cli.files_secret {
        Some(s) => {
            check_files_secret(s)?;
            s.as_bytes().to_vec()
        }
        None => {
            tracing::warn!("no --files-secret: download links become invalid after a restart");
            let mut b = vec![0u8; 32];
            getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("OS RNG unavailable: {e}"))?;
            b
        }
    };
    let link_secret = secret.clone();
    let files_tls = cli.files_tls_cert.is_some();
    let files_public_url = cli.files_public_url.clone().unwrap_or_else(|| {
        format!(
            "{}://127.0.0.1:7548",
            if files_tls { "https" } else { "http" }
        )
    });
    if let Some(warning) = files_url_scheme_warning(files_tls, &files_public_url) {
        tracing::warn!(url = %files_public_url, "{warning}");
    }
    let files = FilesConfig::new(
        cli.files_dir.clone(),
        FileSigner::new(
            secret,
            files_public_url.clone(),
            Duration::from_secs(rt.files_link_hours.saturating_mul(3600)),
        ),
        rt.files_max_bytes,
        download_limits(&rt),
    );

    let secrets = match &cli.secrets_key {
        Some(k) => Some(std::sync::Arc::new(
            dhonomos_core::SecretBox::from_base64(k, cli.secrets_key_id.clone())
                .context("--secrets-key")?
                .with_old_keys(&cli.secrets_old_keys)
                .context("--secrets-old-keys")?,
        )),
        None => {
            tracing::warn!(
                "no --secrets-key: per-device credentials and task passwords are disabled"
            );
            None
        }
    };

    // Key rotation: re-encrypt what the old keys sealed, before serving.
    if let Some(s) = secrets.as_ref().filter(|s| s.has_old_keys()) {
        let done = dhonomos_core::secrets::rewrap_secrets(&store, s)
            .await
            .context("re-encrypting secrets")?;
        if done.unreadable == 0 {
            tracing::info!(credentials = done.credentials, payloads = done.payloads, presets = done.presets, totp = done.totp, wg_psks = done.wg_psks, key = %s.key_id(),
                "secrets re-encrypted; nothing is left under the old keys, so --secrets-old-keys can be removed");
        } else {
            tracing::warn!(
                credentials = done.credentials,
                payloads = done.payloads,
                presets = done.presets,
                totp = done.totp,
                wg_psks = done.wg_psks,
                unreadable = done.unreadable,
                "secrets re-encrypted, but some open with no configured key (lost key?)"
            );
        }
    }

    // Presets file -> reload on SIGHUP (below). No file -> presets in DB,
    // edited via API and UI, every process follows changes.
    if cli.presets.is_none()
        && let Some(s) = &secrets
    {
        // Presets saved before sealing -> seal their secrets.
        let done = dhonomos_core::secrets::rewrap_presets(&store, s)
            .await
            .context("sealing the secrets of stored presets")?;
        if done.presets > 0 {
            tracing::info!(
                presets = done.presets,
                "secrets of stored presets sealed or masked"
            );
        }
    }
    let presets = dhonomos_core::Shared::new(match &cli.presets {
        Some(path) => load_presets(path)?,
        None => {
            let (p, errors) =
                dhonomos_core::presets::load_stored(&store, DEFAULT_TENANT, secrets.clone())
                    .await?;
            for e in &errors {
                tracing::error!(error = %e, "stored preset left out");
            }
            tracing::info!(presets = p.len(), "presets loaded from the database");
            p
        }
    });

    let ca = match &cli.usp_ca_dir {
        Some(dir) => {
            let name = dhonomos_pki::ca_common_name(cli.usp_ca_name.as_deref())
                .context("--usp-ca-name")?;
            let (ca, created) = dhonomos_pki::Ca::load_or_create(dir, &name)
                .with_context(|| format!("USP CA in {}", dir.display()))?;
            if created {
                tracing::info!(dir = %dir.display(), name = %name, "created the USP CA; give ca.pem to Agents as their trust anchor");
            } else if let Some(requested) = cli
                .usp_ca_name
                .as_deref()
                .map(str::trim)
                .filter(|n| !n.is_empty())
                && ca.common_name().as_deref() != Some(requested)
            {
                tracing::info!(
                    dir = %dir.display(),
                    existing = ca.common_name().as_deref().unwrap_or("?"),
                    requested,
                    "the existing USP CA keeps its name; --usp-ca-name applies only when the CA is created"
                );
            }
            Some(std::sync::Arc::new(ca))
        }
        None => None,
    };

    let mqtt_tls = mqtt_tls(&cli)?;
    let broker = match (&secrets, cli.usp_dynsec) {
        (Some(secrets), true) => {
            let dynsec = dhonomos_usp_mtp::Dynsec::start(dhonomos_usp_mtp::DynsecConfig {
                host: cli.usp_mqtt_host.clone().unwrap_or_default(),
                port: cli.usp_mqtt_port,
                client_id: format!("dhonomos-dynsec-{}", std::process::id()),
                username: cli.usp_dynsec_username.clone().unwrap_or_default(),
                password: cli.usp_dynsec_password.clone().unwrap_or_default(),
                timeout: Duration::from_secs(10),
                tls: mqtt_tls.clone(),
            });
            let broker = dhonomos_core::BrokerAccess::new(
                dynsec,
                secrets.clone(),
                cli.usp_topic.clone(),
                cli.usp_agent_topic_prefix.clone(),
            );
            // Before the Controller subscribes: its account needs the Controller role.
            match broker.bootstrap(cli.usp_mqtt_username.as_deref()).await {
                Ok(()) => tracing::info!("broker roles ready (dynamic-security)"),
                Err(e) => tracing::error!(error = %e, "creating broker roles failed"),
            }
            Some(broker)
        }
        _ => None,
    };

    let metrics_ingest = dhonomos_core::MetricsIngest::new(
        device_store.clone(),
        rt.metrics_retention_days,
        rt.metrics_raw_days,
    );
    match metrics_ingest.maintain().await {
        Ok((raw_days, compacted, deleted)) => {
            tracing::info!(
                partitions = raw_days,
                compacted,
                deleted,
                "time series storage ready"
            )
        }
        Err(e) => tracing::warn!(error = %e, "preparing time series partitions failed"),
    }

    // Admission of unknown devices (CO-12), same for CWMP devices and USP Agents.
    let onboarding = Onboarding {
        mode: match cli.onboarding {
            OnboardingArg::Auto => OnboardingMode::Auto,
            OnboardingArg::Quarantine => OnboardingMode::Quarantine,
            OnboardingArg::Preregistered => OnboardingMode::Preregistered,
        },
        allowed_ouis: cli.allowed_oui.clone(),
    };
    let usp = (cli.usp_mqtt_host.is_some()
        || cli.usp_ws_listen.is_some()
        || cli.usp_ws_clients
        || cli.usp_stomp_listen.is_some()
        || cli.usp_mqtt_broker_listen.is_some())
        .then(|| {
        tracing::info!(broker = ?cli.usp_mqtt_host.as_ref().map(|h| format!("{h}:{}", cli.usp_mqtt_port)),
            websocket = ?cli.usp_ws_listen, stomp = ?cli.usp_stomp_listen,
            mqtt_broker = ?cli.usp_mqtt_broker_listen, endpoint_id = %cli.usp_endpoint_id,
            topic = %cli.usp_topic, "USP Controller enabled");
        dhonomos_core::UspService::start(
            device_store.clone(),
            dhonomos_core::UspConfig {
                mqtt: cli.usp_mqtt_host.as_ref().map(|host| dhonomos_usp_mtp::MqttConfig {
                    host: host.clone(),
                    port: cli.usp_mqtt_port,
                    client_id: format!("dhonomos-{}", std::process::id()),
                    credentials: cli.usp_mqtt_username.clone().zip(cli.usp_mqtt_password.clone()),
                    controller_topic: cli.usp_topic.clone(),
                    keep_alive: Duration::from_secs(30),
                    tls: mqtt_tls.clone(),
                }),
                // Also for Agents that run a WebSocket server.
                websocket: cli.usp_ws_listen.is_some() || cli.usp_ws_clients,
                onboarding: onboarding.clone(),
                stomp: cli.usp_stomp_listen.map(|_| dhonomos_usp_mtp::StompConfig {
                    login: cli.usp_stomp_login.clone().zip(cli.usp_stomp_passcode.clone()),
                    controller_dest: cli.usp_stomp_controller_dest.clone(),
                    agent_dest_prefix: cli.usp_stomp_agent_dest_prefix.clone(),
                    max_connections: cli.usp_stomp_max_connections,
                    max_connections_per_ip: cli.usp_stomp_max_connections_per_ip,
                    ..dhonomos_usp_mtp::StompConfig::default()
                }),
                mqtt_broker: cli.usp_mqtt_broker_listen.map(|_| dhonomos_usp_mtp::MqttBrokerConfig {
                    login: cli
                        .usp_mqtt_broker_username
                        .clone()
                        .zip(cli.usp_mqtt_broker_password.clone()),
                    controller_topic: cli.usp_mqtt_broker_controller_topic.clone(),
                    agent_topic_prefix: cli.usp_mqtt_broker_agent_topic_prefix.clone(),
                    max_connections: cli.usp_mqtt_broker_max_connections,
                    max_connections_per_ip: cli.usp_mqtt_broker_max_connections_per_ip,
                    ..dhonomos_usp_mtp::MqttBrokerConfig::default()
                }),
                endpoint_id: cli.usp_endpoint_id.clone(),
                request_timeout: usp_request_timeout,
                full_read_timeout: usp_full_read_timeout,
                tenant_id: DEFAULT_TENANT,
                presets: presets.clone(),
                metrics: Some(metrics_ingest.clone()),
                files: Some(files.signer.clone()),
                secrets: secrets.clone(),
                // wss:// Agents: system store + USP CA that issued their certificates.
                ws_client_tls: dhonomos_usp_mtp::client_tls(ca.as_ref().map(|c| c.cert_pem()))
                    .map_err(|e| tracing::warn!(error = %e, "TLS for USP WebSocket clients"))
                    .ok(),
                auto_subscribe: rt.usp_auto_subscribe,
                wg_sweep_interval: dhonomos_core::DEFAULT_WG_SWEEP_INTERVAL,
                wg_incomplete_retry: dhonomos_core::DEFAULT_WG_INCOMPLETE_RETRY,
                wg_ip_poll_interval: dhonomos_core::DEFAULT_WG_IP_POLL_INTERVAL,
                wg_ip_poll_limit: dhonomos_core::DEFAULT_WG_IP_POLL_LIMIT,
            },
        )
    });

    let stun_socket = match cli.stun_listen {
        Some(addr) => {
            let socket = std::sync::Arc::new(
                tokio::net::UdpSocket::bind(addr)
                    .await
                    .with_context(|| format!("binding STUN {addr}"))?,
            );
            let (tx, rx) = tokio::sync::mpsc::channel(4096);
            let s = socket.clone();
            // Binding updates need MESSAGE-INTEGRITY with the device's derived password.
            let passwords = dhonomos_core::nat::stun_passwords(link_secret.clone());
            tokio::spawn(async move {
                if let Err(e) = dhonomos_cwmp_server::stun::serve(s, tx, Some(passwords)).await {
                    tracing::error!(error = %e, "STUN server stopped");
                }
            });
            tokio::spawn(dhonomos_core::nat::record_bindings(
                store.clone(),
                DEFAULT_TENANT,
                rx,
            ));
            tracing::info!(%addr, "STUN server listening (UDP connection requests enabled)");
            Some(socket)
        }
        None => None,
    };

    let xmpp = xmpp_server(&cli, &rt, runs_acs, &store, secrets.as_ref()).await?;
    // API reads XMPP sessions of devices from the server's table (`xmpp_jid`).
    let xmpp_for_api = xmpp.as_ref().map(|x| x.server.clone());

    let waker = {
        let w = Waker::new(
            store.clone(),
            cli.cr_username
                .clone()
                .zip(cli.cr_password.clone())
                .map(|(username, password)| ConnReqCredentials { username, password }),
            Duration::from_secs(10),
        )
        .with_address_policy(dhonomos_core::AddressPolicy::new(
            cli.cr_allow.clone(),
            cli.cr_deny.clone(),
        ))
        .with_basic_auth(cli.cr_basic_auth);
        let w = match &secrets {
            Some(sb) => w.with_secrets(sb.clone()),
            None => w,
        };
        let w = match &stun_socket {
            Some(s) => w.with_udp(s.clone()),
            None => w,
        };
        let w = match &xmpp {
            Some(x) => w.with_xmpp(x.server.clone()),
            None => w,
        };
        match &usp {
            Some(u) => w.with_usp(u.clone()),
            None => w,
        }
    };

    let startup_rules = startup_alarm_rules(cli.alarms.as_deref(), &store).await?;
    let alarm_rules = dhonomos_core::Shared::new(startup_rules.rules);
    let alarm_rules_file = startup_rules.file;

    if let Some(password) = &cli.admin_password
        && store.user_by_name(DEFAULT_TENANT, "admin").await?.is_none()
    {
        anyhow::ensure!(
            password.chars().count() >= 10,
            "--admin-password needs at least 10 characters"
        );
        anyhow::ensure!(
            !is_placeholder(password),
            "--admin-password is a placeholder from a sample file: choose a real password \
             (for example `openssl rand -base64 18`)"
        );
        let hash = dhonomos_api::hash_password(password).map_err(anyhow::Error::msg)?;
        store
            .create_user(DEFAULT_TENANT, "admin", &hash, "admin")
            .await?;
        tracing::info!("created the operator account admin");
    }

    let mut tasks = tokio::task::JoinSet::new();
    // Wake the runtime settings watcher at once (change via this process's API).
    let settings_wake = std::sync::Arc::new(tokio::sync::Notify::new());
    // Same for the alarm rules stored in DB.
    let alarm_rules_wake = std::sync::Arc::new(tokio::sync::Notify::new());

    if let Some(u) = &usp {
        // Agents with an issued client certificate must prove themselves with it on every MTP;
        // revoked certificates refused (H-3, M-5). Load before any listener takes an Agent,
        // then keep up to date.
        dhonomos_core::usp::load_certificates(&store, DEFAULT_TENANT, u).await;
        let (store, usp) = (store.clone(), u.clone());
        tasks.spawn(async move {
            tokio::select! {
                () = dhonomos_core::usp::watch_certificates(
                    store,
                    DEFAULT_TENANT,
                    usp,
                    Duration::from_secs(10),
                ) => {}
                () = shutdown() => {}
            }
            Ok(())
        });
    }

    if cli.presets.is_none() {
        let (store, presets, secrets) = (store.clone(), presets.clone(), secrets.clone());
        tasks.spawn(async move {
            tokio::select! {
                () = dhonomos_core::presets::watch_stored(
                    store,
                    DEFAULT_TENANT,
                    presets,
                    Duration::from_secs(5),
                    secrets,
                ) => {}
                () = shutdown() => {}
            }
            Ok(())
        });
    }

    // No --alarms -> every process follows the alarm rules stored from the web.
    if alarm_rules_file.is_none() {
        let (store, rules, wake) = (store.clone(), alarm_rules.clone(), alarm_rules_wake.clone());
        let seen = startup_rules.seen;
        tasks.spawn(async move {
            tokio::select! {
                () = dhonomos_core::alarms::watch_stored(
                    store,
                    DEFAULT_TENANT,
                    rules,
                    SETTINGS_POLL,
                    wake,
                    Some(seen),
                ) => {}
                () = shutdown() => {}
            }
            Ok(())
        });
    }

    if let Some(url) = cli.audit_webhook_url.clone() {
        if cli.audit_webhook_secret.is_empty() {
            tracing::warn!(
                "--audit-webhook-secret is empty: the audit batches are not signed, so the receiver cannot tell them from forged ones"
            );
        }
        let sink = dhonomos_core::audit_export::AuditSink {
            url,
            secret: cli.audit_webhook_secret.clone(),
        };
        let store = store.clone();
        tasks.spawn(async move {
            tokio::select! {
                () = dhonomos_core::audit_export::run(store, DEFAULT_TENANT, sink) => {}
                () = shutdown() => {}
            }
            Ok(())
        });
    }

    tasks.spawn(reload_on_hangup(
        cli.presets.clone(),
        presets.clone(),
        alarm_rules_file.clone(),
        alarm_rules.clone(),
    ));

    // What `Live::apply` changes at runtime, gathered while the components are built.
    let mut live = Live {
        retention: dhonomos_core::Shared::new((
            rt.events_retention_days,
            rt.tasks_retention_days,
            rt.alarms_retention_days,
        )),
        metrics: metrics_ingest.clone(),
        files: files.clone(),
        usp: usp.clone(),
        xmpp: xmpp.as_ref().map(|x| x.server.clone()),
        xmpp_keepalive: cli.xmpp_keepalive,
        webhook_urls: None,
        email: None,
        smtp_password: cli.smtp_password.clone(),
        smtp_ca_pem: None,
        acs: None,
        api: None,
    };

    // Alarm engine in every process, one at a time (DB lock); no rules -> evaluates nothing.
    {
        if !rt.webhook_url.is_empty() && cli.webhook_secret.is_empty() {
            tracing::warn!(
                "--webhook-secret is empty: the alarm webhooks are not signed, so the receiver cannot tell them from forged ones"
            );
        }
        let engine = dhonomos_core::alarms::AlarmEngine::new(
            store.clone(),
            DEFAULT_TENANT,
            alarm_rules.clone(),
            dhonomos_core::alarms::Webhooks {
                urls: rt.webhook_url.clone(),
                secret: cli.webhook_secret.clone(),
            },
        );
        live.smtp_ca_pem = cli
            .smtp_ca
            .as_ref()
            .map(|p| std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display())))
            .transpose()?;
        let email = startup_alarm_email(
            &rt,
            cli.smtp_password.clone(),
            live.smtp_ca_pem.clone(),
            alarm_rules_file.is_some(),
        )?;
        live.webhook_urls = Some(engine.webhook_urls());
        live.email = Some(engine.email());
        let engine = match email {
            Some(email) => {
                tracing::info!(
                    host = %email.smtp.host,
                    to = email.smtp.to.len(),
                    min_severity = %email.min_severity,
                    "alarm e-mails enabled"
                );
                engine.with_email(email)
            }
            None => engine,
        };
        tasks.spawn(async move {
            engine.run(Duration::from_secs(60), shutdown()).await;
            Ok(())
        });
    }

    // Time series partitions: tomorrow's exist before midnight, expired days dropped.
    {
        let ingest = metrics_ingest.clone();
        tasks.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            tick.tick().await;
            loop {
                tokio::select! {
                    () = shutdown() => return Ok(()),
                    _ = tick.tick() => {}
                }
                if let Err(e) = ingest.maintain().await {
                    tracing::warn!(error = %e, "time series maintenance failed");
                }
            }
        });
    }

    // Bulk jobs (CO-15); one process at a time drives them (DB lock).
    {
        let mut engine =
            dhonomos_jobs::Engine::new(store.clone(), Some(waker.clone()), Duration::from_secs(2));
        if let Some(sb) = &secrets {
            engine = engine.with_secrets(sb.clone());
        }
        tasks.spawn(async move {
            engine.run(shutdown()).await;
            Ok(())
        });
    }

    // Housekeeping: transfers without completion report fail after 1 day;
    // hourly: drop old events, finished tasks, cleared alarms, expired sessions (OP-10).
    {
        let store = store.clone();
        let retention = live.retention.clone();
        tasks.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(300));
            let mut n: u64 = 0;
            loop {
                tokio::select! {
                    () = shutdown() => return Ok(()),
                    _ = tick.tick() => {}
                }
                match store.fail_stale_waiting(time::Duration::hours(24)).await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(tasks = n, "failed transfers without TransferComplete"),
                    Err(e) => tracing::warn!(error = %e, "housekeeping failed"),
                }
                n += 1;
                if n % 12 == 1 {
                    // Read on each pass: days can change at runtime.
                    let (events, done, alarms) =
                        retention_cutoffs(*retention.get(), time::OffsetDateTime::now_utc());
                    match store.apply_retention(events, done, alarms).await {
                        Ok(p) if p.events + p.tasks + p.alarms > 0 => tracing::info!(
                            events = p.events,
                            tasks = p.tasks,
                            alarms = p.alarms,
                            sessions = p.sessions,
                            "retention applied"
                        ),
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "retention failed"),
                    }
                }
            }
        });
    }
    if matches!(cli.role, Role::Acs | Role::All) {
        let mut backend = CwmpBackend::new(device_store.clone(), DEFAULT_TENANT, credentials)
            .with_files(files.signer.clone())
            .with_presets(presets.clone())
            .with_onboarding(onboarding.clone())
            .with_param_limits(rt.cpe_max_params_per_message, rt.cpe_max_params_per_device)
            // 0: off; limit can change at runtime.
            .with_session_limit(rt.cpe_session_limit);
        backend = backend.with_wg_rewake(waker.clone(), dhonomos_core::DEFAULT_WG_REWAKE_DELAY);
        if let Some(public) = &cli.stun_public_address {
            let (host, port) = match public.rsplit_once(':') {
                Some((h, p)) if !h.contains(':') || h.ends_with(']') => (
                    h.to_owned(),
                    p.parse().context("--stun-public-address port")?,
                ),
                _ => (public.clone(), cli.stun_listen.map_or(3478, |a| a.port())),
            };
            backend = backend.with_stun_provisioning(host, port, link_secret.clone());
        }
        if let Some(x) = &xmpp {
            backend = backend.with_xmpp_provisioning(dhonomos_core::XmppProvisioning {
                domain: x.server.domain().to_owned(),
                keepalive: cli.xmpp_keepalive,
            });
        }
        if let Some(sb) = &secrets {
            backend = backend.with_secrets(sb.clone());
            if cli.cr_per_device {
                backend = backend.with_per_device_connection_requests();
            }
            if cli.acs_auth_per_device {
                anyhow::ensure!(
                    !matches!(cli.cpe_auth, CpeAuth::None),
                    "--acs-auth-per-device needs --cpe-auth basic or digest"
                );
                backend = backend.with_per_device_acs_auth();
            }
        } else if cli.acs_auth_per_device {
            anyhow::bail!("--acs-auth-per-device needs --secrets-key");
        } else if cli.cr_per_device {
            tracing::info!(
                "no --secrets-key: new CPEs keep the shared connection request credentials"
            );
        }
        let config = AcsConfig {
            auth: match cli.cpe_auth {
                CpeAuth::None => AuthMode::None,
                CpeAuth::Basic => AuthMode::Basic,
                CpeAuth::Digest => AuthMode::Digest,
            },
            session_timeout: Duration::from_secs(rt.session_timeout),
            max_concurrent_requests: cli.acs_max_concurrent,
            max_connections: cli.acs_max_connections,
            max_connections_per_ip: cli.acs_max_connections_per_ip,
            auth_failure_limit: cli.cpe_auth_failure_limit,
            digest_no_qop: cli.cpe_digest_no_qop,
            digest_bind_client: cli.cpe_digest_bind_client,
            ..AcsConfig::default()
        };
        let tls = match (&cli.acs_tls_cert, &cli.acs_tls_key, cli.acs_plaintext) {
            (Some(cert), Some(key), _) => Some(
                dhonomos_cwmp_server::acceptor_from_pem(
                    cert,
                    key,
                    Some(dhonomos_pki::tls::DEFAULT_RELOAD_INTERVAL),
                )
                .context("loading the ACS certificate")?,
            ),
            (_, _, true) => None,
            _ => anyhow::bail!(
                "the ACS needs a certificate: pass --acs-tls-cert and --acs-tls-key, \
                 or --acs-plaintext for development or behind a TLS-terminating proxy"
            ),
        };
        let listener = dhonomos_cwmp_server::bind(cli.acs_listen)
            .with_context(|| format!("binding ACS listener {}", cli.acs_listen))?;
        tracing::info!(addr = %cli.acs_listen, auth = ?cli.cpe_auth, tls = tls.is_some(), "ACS listening");
        if tls.is_none() && cli.cpe_auth == CpeAuth::Basic {
            tracing::warn!("Basic authentication over plain HTTP exposes CPE passwords");
        }
        if acs_open_to_the_network(cli.cpe_auth, cli.acs_listen) {
            tracing::warn!(addr = %cli.acs_listen,
                "the ACS takes CPEs without authentication (--cpe-auth none) on a network address: anyone who can reach it can pose as any CPE; use --cpe-auth digest with --cpe-username and --cpe-password");
        }
        let server = AcsServer::new(config, backend);
        live.acs = Some(server.clone());
        tasks.spawn(async move {
            match tls {
                Some(t) => server.serve_tls(listener, t, shutdown()).await,
                None => server.serve(listener, shutdown()).await,
            }
            .map_err(anyhow::Error::from)
        });
        if let Some(x) = xmpp {
            let addr = cli.xmpp_listen.map(|a| a.to_string()).unwrap_or_default();
            tracing::info!(%addr, domain = x.server.domain(), keepalive = cli.xmpp_keepalive,
                "XMPP server listening (Connection Requests, Annex K)");
            tasks.spawn(async move {
                x.server
                    .serve(x.listener, shutdown())
                    .await
                    .map_err(anyhow::Error::from)
            });
        }

        let file_app = dhonomos_api::file_server(
            store.clone(),
            files.clone(),
            DEFAULT_TENANT,
            Some(metrics_ingest.clone()),
        );
        let file_listener = dhonomos_cwmp_server::bind(cli.files_listen)
            .with_context(|| format!("binding file server {}", cli.files_listen))?;
        tracing::info!(addr = %cli.files_listen, public = %files_public_url, tls = files_tls, "file server listening");
        // Both flags set together (clap) or neither.
        let file_tls = match (&cli.files_tls_cert, &cli.files_tls_key) {
            (Some(cert), Some(key)) => {
                let resolver = dhonomos_pki::tls::CertResolver::from_files(cert, key)
                    .context("loading the file server certificate")?;
                resolver.watch("files", dhonomos_pki::tls::DEFAULT_RELOAD_INTERVAL);
                Some(
                    dhonomos_cwmp_server::acceptor_with_resolver(resolver)
                        .context("file server TLS settings")?,
                )
            }
            _ => None,
        };
        tasks.spawn(async move {
            match file_tls {
                Some(acceptor) => {
                    let listener = dhonomos_api::TlsListener::new(file_listener, acceptor)?;
                    // Client addresses for log lines of refused requests.
                    axum::serve(
                        listener,
                        file_app.into_make_service_with_connect_info::<dhonomos_api::PeerAddr>(),
                    )
                    .with_graceful_shutdown(shutdown())
                    .await
                }
                None => {
                    axum::serve(
                        file_listener,
                        file_app.into_make_service_with_connect_info::<dhonomos_api::PeerAddr>(),
                    )
                    .with_graceful_shutdown(shutdown())
                    .await
                }
            }
            .map_err(anyhow::Error::from)
        });

        if let (Some(addr), Some(ws)) = (cli.usp_ws_listen, usp.as_ref().and_then(|u| u.ws_mtp())) {
            // No client certificates -> anyone can pose as any Agent:
            // only on loopback or when asked.
            if ws_takes_anonymous_agents(
                addr,
                cli.usp_ws_tls,
                cli.usp_ws_client_cert,
                cli.usp_ws_allow_anonymous,
            )? {
                tracing::warn!(%addr, tls = cli.usp_ws_tls, client_cert = ?cli.usp_ws_client_cert,
                    "WebSocket MTP takes Agents without a client certificate");
            }
            let ws = ws.clone();
            let ws_listener = dhonomos_cwmp_server::bind(addr)
                .with_context(|| format!("binding USP WebSocket {addr}"))?;
            if cli.usp_ws_tls {
                let acceptor = ws_tls(&cli, ca.as_ref(), "usp_wss")?;
                tracing::info!(addr = %addr, client_cert = ?cli.usp_ws_client_cert, "USP WebSocket MTP listening on /usp (TLS)");
                tasks.spawn(async move {
                    ws.serve_tls(ws_listener, acceptor, shutdown())
                        .await
                        .map_err(anyhow::Error::from)
                });
            } else {
                tracing::info!(addr = %addr, "USP WebSocket MTP listening on /usp");
                tasks.spawn(async move {
                    axum::serve(
                        ws_listener,
                        ws.router()
                            .into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .with_graceful_shutdown(shutdown())
                    .await
                    .map_err(anyhow::Error::from)
                });
            }
        }
    }
    if let (Some(addr), Some(stomp)) = (
        cli.usp_stomp_listen,
        usp.as_ref().and_then(|u| u.stomp_mtp()),
    ) {
        // No login -> anyone can pose as any Agent: only on loopback or when asked.
        if cli.usp_stomp_login.is_none() && !addr.ip().is_loopback() {
            if !cli.usp_stomp_allow_anonymous {
                anyhow::bail!(
                    "the STOMP broker on {addr} would take any client: set --usp-stomp-login/--usp-stomp-passcode, listen on loopback, or pass --usp-stomp-allow-anonymous"
                );
            }
            tracing::warn!(%addr, "STOMP broker takes Agents without a login");
        }
        let stomp = stomp.clone();
        let listener = dhonomos_cwmp_server::bind(addr)
            .with_context(|| format!("binding USP STOMP {addr}"))?;
        let tls = if cli.usp_stomp_tls {
            Some(ws_tls(&cli, ca.as_ref(), "usp_stomp")?)
        } else {
            None
        };
        if shared_login_in_the_clear(addr, cli.usp_stomp_login.is_some(), tls.is_some()) {
            tracing::warn!(%addr,
                "the STOMP broker checks a shared login on a network address without TLS: the login crosses the network in the clear and is all an Agent needs; use --usp-stomp-tls (with client certificates)");
        }
        tracing::info!(%addr, tls = cli.usp_stomp_tls, login = cli.usp_stomp_login.is_some(),
            controller_dest = %cli.usp_stomp_controller_dest, "USP STOMP broker listening");
        tasks.spawn(async move {
            stomp
                .serve(listener, tls, shutdown())
                .await
                .map_err(anyhow::Error::from)
        });
    }
    if let (Some(addr), Some(broker)) = (
        cli.usp_mqtt_broker_listen,
        usp.as_ref().and_then(|u| u.mqtt_broker_mtp()),
    ) {
        // No account -> anyone can pose as any Agent: only on loopback or when asked.
        if cli.usp_mqtt_broker_username.is_none() && !addr.ip().is_loopback() {
            if !cli.usp_mqtt_broker_allow_anonymous {
                anyhow::bail!(
                    "the MQTT broker on {addr} would take any client: set --usp-mqtt-broker-username/--usp-mqtt-broker-password, listen on loopback, or pass --usp-mqtt-broker-allow-anonymous"
                );
            }
            tracing::warn!(%addr, "MQTT broker takes Agents without a user name");
        }
        broker
            .config()
            .validate()
            .map_err(|e| anyhow::anyhow!("--usp-mqtt-broker-*: {e}"))?;
        let broker = broker.clone();
        let listener = dhonomos_cwmp_server::bind(addr)
            .with_context(|| format!("binding USP MQTT broker {addr}"))?;
        let tls = if cli.usp_mqtt_broker_tls {
            Some(ws_tls(&cli, ca.as_ref(), "usp_mqtt_broker")?)
        } else {
            None
        };
        if shared_login_in_the_clear(addr, cli.usp_mqtt_broker_username.is_some(), tls.is_some()) {
            tracing::warn!(%addr,
                "the MQTT broker checks a shared account on a network address without TLS: the account crosses the network in the clear and is all an Agent needs; use --usp-mqtt-broker-tls (with client certificates)");
        }
        tracing::info!(%addr, tls = cli.usp_mqtt_broker_tls, login = cli.usp_mqtt_broker_username.is_some(),
            controller_topic = %cli.usp_mqtt_broker_controller_topic,
            agent_topic_prefix = %cli.usp_mqtt_broker_agent_topic_prefix, "USP MQTT broker listening");
        tasks.spawn(async move {
            broker
                .serve(listener, tls, shutdown())
                .await
                .map_err(anyhow::Error::from)
        });
    }
    if matches!(cli.role, Role::Api | Role::All) {
        // No accounts or token -> anyone is admin: only on loopback or when explicitly asked.
        if cli.api_token.is_none()
            && !cli.api_listen.ip().is_loopback()
            && !store.has_users().await.unwrap_or(false)
        {
            if !cli.api_allow_open {
                anyhow::bail!(
                    "the API on {} would be open to anyone as admin: set --admin-password (or create an account) or --api-token, listen on loopback, or pass --api-allow-open",
                    cli.api_listen
                );
            }
            tracing::warn!(addr = %cli.api_listen, "API is reachable from the network without accounts or a token (open)");
        }
        // Two-factor secrets stored encrypted -> required role needs the key.
        let totp_config = dhonomos_api::TotpConfig {
            require_roles: required_totp_roles(&cli.require_totp_roles, cli.require_admin_totp)
                .map_err(anyhow::Error::msg)?,
            issuer: cli.totp_issuer.clone(),
        };
        totp_config
            .check(secrets.is_some())
            .map_err(anyhow::Error::msg)?;
        proxy_warnings(&cli);
        if store.has_users().await.unwrap_or(false) {
            tracing::info!(
                totp_required_for = %totp_config.require_roles.join(","),
                "two-factor authentication is required for these roles"
            );
        } else if cli.api_token.is_none() {
            tracing::warn!(addr = %cli.api_listen,
                "there are no accounts and no --api-token: the API is open to direct callers as admin (requests that carry proxy headers are refused with 401); create the admin account (--admin-password) before the UI is reachable from anywhere else");
        }
        // Tell long-held requests (hub long-poll, event stream) that the server stops
        // -> they do not hold up the graceful shutdown.
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            shutdown().await;
            let _ = stop_tx.send(true);
        });
        let api_live = ApiLive {
            session_hours: rt.session_hours.into(),
            session_idle_minutes: rt.session_idle_minutes.into(),
            rate_limit: rt.api_rate_limit.into(),
            wireguard: dhonomos_api::WireguardConfig::new(
                rt.wg_address_pool,
                rt.wg_address_reuse_delay_hours,
            )
            .map_err(anyhow::Error::msg)?
            .into(),
        };
        let app = dhonomos_api::router(
            store.clone(),
            ApiConfig {
                bearer_token: cli.api_token.clone(),
                tenant_id: DEFAULT_TENANT,
                waker: Some(waker.clone()),
                usp: usp.clone(),
                metrics: Some(metrics.clone()),
                metrics_ingest: Some(metrics_ingest.clone()),
                files: Some(files.clone()),
                secrets: secrets.clone(),
                broker: broker.clone(),
                ca: ca.clone(),
                presets: presets.clone(),
                presets_in_db: cli.presets.is_none(),
                alarm_rules: alarm_rules.clone(),
                alarm_rules_file: alarm_rules_file.clone(),
                secure_cookies: cli.secure_cookies,
                session_hours: api_live.session_hours.clone(),
                session_idle_minutes: api_live.session_idle_minutes.clone(),
                trusted_proxies: cli.trusted_proxies.clone(),
                public_url: cli.public_url.clone(),
                rate_limit: api_live.rate_limit.clone(),
                oidc: oidc_config(&cli)?,
                totp: totp_config,
                xmpp: xmpp_for_api,
                wireguard: api_live.wireguard.clone(),
                shutdown: Some(stop_rx),
                server_settings: server_settings.clone(),
                settings_hooks: dhonomos_api::SettingsHooks {
                    validate: std::sync::Arc::new(|values| {
                        settings::validate(values, settings::effective)
                    }),
                    apply_now: {
                        let wake = settings_wake.clone();
                        std::sync::Arc::new(move || wake.notify_one())
                    },
                    apply_alarm_rules: {
                        let wake = alarm_rules_wake.clone();
                        std::sync::Arc::new(move || wake.notify_one())
                    },
                },
            },
        );
        live.api = Some(api_live);
        let listener = tokio::net::TcpListener::bind(cli.api_listen)
            .await
            .with_context(|| format!("binding API listener {}", cli.api_listen))?;
        tracing::info!(addr = %cli.api_listen, "API listening");
        if !cli.api_listen.ip().is_loopback() && !cli.secure_cookies {
            tracing::warn!(addr = %cli.api_listen,
                "the API listens on a network address without --secure-cookies: it has no TLS of its own, so put a TLS-terminating reverse proxy in front of it and set --secure-cookies, or logins and sessions cross the network in the clear");
        }
        tasks.spawn(async move {
            // Client addresses for rate limits of unauthenticated requests.
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown())
            .await
            .map_err(anyhow::Error::from)
        });
    }
    // Every process follows runtime settings changes, from any process.
    {
        let live = std::sync::Arc::new(live);
        live.apply(&rt);
        let (store, wake) = (store.clone(), settings_wake.clone());
        tasks.spawn(async move {
            tokio::select! {
                () = dhonomos_core::runtime_settings::watch(
                    store,
                    DEFAULT_TENANT,
                    SETTINGS_POLL,
                    wake,
                    Some(settings_seen),
                    move |values| match settings::load(&values, settings::effective) {
                        Ok(rt) => live.apply(&rt),
                        Err(e) => tracing::warn!(error = %e,
                            "runtime settings not applied; keeping the running ones"),
                    },
                ) => {}
                () = shutdown() => {}
            }
            Ok(())
        });
    }
    while let Some(done) = tasks.join_next().await {
        done??;
    }
    tracing::info!("stopped");
    if let Some(p) = otel {
        // Flush buffered traces.
        let _ = tokio::task::spawn_blocking(move || p.shutdown()).await;
    }
    Ok(())
}

/// How often each process checks for runtime settings changes.
const SETTINGS_POLL: Duration = Duration::from_secs(5);

/// File server download limits (Mbit/s -> bytes/s).
fn download_limits(rt: &dhonomos_core::RuntimeSettings) -> dhonomos_api::DownloadLimits {
    let rate = |mbps: Option<u64>| mbps.map(|m| m.saturating_mul(125_000));
    dhonomos_api::DownloadLimits {
        total_rate: rate(rt.files_total_mbps),
        per_download_rate: rate(rt.files_download_mbps),
        max_concurrent: rt.files_max_downloads,
    }
}

/// Retention cutoffs at `now`: events, finished tasks, cleared alarms before them go.
/// 0 days = keep forever (cutoff at the epoch).
fn retention_cutoffs(
    (events, tasks, alarms): (i64, i64, i64),
    now: time::OffsetDateTime,
) -> (
    time::OffsetDateTime,
    time::OffsetDateTime,
    time::OffsetDateTime,
) {
    let before = |d: i64| {
        if d > 0 {
            now - time::Duration::days(d)
        } else {
            time::OffsetDateTime::UNIX_EPOCH
        }
    };
    (before(events), before(tasks), before(alarms))
}

/// XMPP idle timeout: `--xmpp-idle-timeout`, else 3 keep-alives + 30 s.
fn xmpp_idle_timeout(idle: Option<u64>, keepalive: u32) -> Duration {
    Duration::from_secs(idle.unwrap_or(3 * u64::from(keepalive) + 30))
}

/// Runtime settings the API reads at each use.
struct ApiLive {
    session_hours: dhonomos_core::Shared<i64>,
    session_idle_minutes: dhonomos_core::Shared<i64>,
    rate_limit: dhonomos_core::Shared<u32>,
    wireguard: dhonomos_core::Shared<dhonomos_api::WireguardConfig>,
}

/// Components of this process that runtime settings change at runtime, for [`Live::apply`].
/// Not run by this process -> `None`.
struct Live {
    /// Days kept: events, finished tasks, cleared alarms. Read by housekeeping.
    retention: dhonomos_core::Shared<(i64, i64, i64)>,
    metrics: dhonomos_core::MetricsIngest,
    files: FilesConfig,
    usp: Option<dhonomos_core::UspService>,
    xmpp: Option<dhonomos_xmpp::XmppServer>,
    xmpp_keepalive: u32,
    /// Of the alarm engine.
    webhook_urls: Option<dhonomos_core::Shared<Vec<String>>>,
    email: Option<dhonomos_core::Shared<Option<std::sync::Arc<dhonomos_core::alarms::AlarmEmail>>>>,
    /// Configuration only; merged into the e-mail settings at each change.
    smtp_password: Option<String>,
    smtp_ca_pem: Option<String>,
    acs: Option<AcsServer<CwmpBackend>>,
    api: Option<ApiLive>,
}

impl Live {
    /// Push runtime settings `rt` (checked by `settings::effective`) into every component.
    /// At startup and at every change.
    fn apply(&self, rt: &dhonomos_core::RuntimeSettings) {
        self.retention.replace((
            rt.events_retention_days,
            rt.tasks_retention_days,
            rt.alarms_retention_days,
        ));
        self.metrics
            .set_retention(rt.metrics_retention_days, rt.metrics_raw_days);
        if let Some(urls) = &self.webhook_urls {
            urls.replace(rt.webhook_url.clone());
        }
        if let Some(email) = &self.email {
            match alarm_email(rt, self.smtp_password.clone(), self.smtp_ca_pem.clone()) {
                Ok(e) => email.replace(e.map(std::sync::Arc::new)),
                Err(e) => {
                    tracing::warn!(error = %e, "alarm e-mail settings not applied; keeping the running ones")
                }
            }
        }
        if let Some(api) = &self.api {
            api.session_hours.replace(rt.session_hours);
            api.session_idle_minutes.replace(rt.session_idle_minutes);
            api.rate_limit.replace(rt.api_rate_limit);
            match dhonomos_api::WireguardConfig::new(
                rt.wg_address_pool,
                rt.wg_address_reuse_delay_hours,
            ) {
                Ok(w) => api.wireguard.replace(w),
                Err(e) => {
                    tracing::warn!(error = %e, "WireGuard settings not applied; keeping the running ones")
                }
            }
        }
        if let Some(acs) = &self.acs {
            let limits = acs.backend().limits();
            limits.sessions.set_per_minute(rt.cpe_session_limit);
            limits.set_param_limits(rt.cpe_max_params_per_message, rt.cpe_max_params_per_device);
            acs.set_session_timeout(Duration::from_secs(rt.session_timeout));
        }
        self.files.set_max_bytes(rt.files_max_bytes);
        self.files.set_limits(&download_limits(rt));
        self.files.signer.set_ttl(Duration::from_secs(
            rt.files_link_hours.saturating_mul(3600),
        ));
        if let Some(usp) = &self.usp {
            usp.set_timeouts(
                Duration::from_secs(rt.usp_request_timeout),
                Duration::from_secs(rt.usp_full_read_timeout),
            );
            usp.set_auto_subscribe(rt.usp_auto_subscribe);
        }
        if let Some(xmpp) = &self.xmpp {
            xmpp.set_idle_timeout(xmpp_idle_timeout(rt.xmpp_idle_timeout, self.xmpp_keepalive));
        }
    }
}

/// Resolves on stop request: SIGINT (Ctrl-C) or SIGTERM (`docker stop`, `systemctl stop`).
/// Each listener and engine awaits its own call.
/// SIGTERM listener not installable -> SIGINT only.
async fn shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

/// XMPP server + its listening socket.
struct Xmpp {
    server: dhonomos_xmpp::XmppServer,
    listener: tokio::net::TcpListener,
}

/// `domain` usable as JID domain and certificate name: a host name.
fn valid_xmpp_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && !domain.starts_with(['.', '-'])
        && !domain.ends_with(['.', '-'])
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
}

/// Built-in XMPP server (ADR-104) if `--xmpp-listen` is set and this process serves CPEs.
/// Load + check certificate, bind port, clear session times a dead process left in DB.
/// Connections live in this process -> a Waker in another one cannot use them (warned).
async fn xmpp_server(
    cli: &Cli,
    rt: &dhonomos_core::RuntimeSettings,
    runs_acs: bool,
    store: &Store,
    secrets: Option<&std::sync::Arc<dhonomos_core::SecretBox>>,
) -> anyhow::Result<Option<Xmpp>> {
    let Some(addr) = cli.xmpp_listen else {
        if cli.role == Role::Api && cli.xmpp_domain.is_some() {
            tracing::warn!(
                "XMPP Connection Requests are unavailable in this process: --role api does not run the XMPP server, so devices connected to it are woken over HTTP and UDP only"
            );
        }
        return Ok(None);
    };
    if !runs_acs {
        tracing::warn!(%addr,
            "--xmpp-listen is ignored: --role api does not run the XMPP server. Its connections live in the process that runs it, so run it with --role all (or acs, where API calls cannot use XMPP and wake devices over HTTP and UDP only)");
        return Ok(None);
    }
    // All three required by `requires_all` on --xmpp-listen.
    let (Some(domain), Some(cert), Some(key)) =
        (&cli.xmpp_domain, &cli.xmpp_tls_cert, &cli.xmpp_tls_key)
    else {
        anyhow::bail!("--xmpp-listen needs --xmpp-domain, --xmpp-tls-cert and --xmpp-tls-key");
    };
    let secrets = secrets.cloned().ok_or_else(|| {
        anyhow::anyhow!(
            "--xmpp-listen needs --secrets-key: the devices' XMPP passwords are stored encrypted"
        )
    })?;
    let domain = domain.trim().to_ascii_lowercase();
    anyhow::ensure!(
        valid_xmpp_domain(&domain),
        "--xmpp-domain {domain:?} is not a host name"
    );
    let resolver = dhonomos_pki::tls::CertResolver::from_files(cert, key)
        .context("loading the XMPP certificate")?;
    anyhow::ensure!(
        resolver.covers(&domain),
        "the certificate {} does not name {domain} in its subjectAltName: devices check the server certificate against the XMPP domain and would refuse the connection",
        cert.display()
    );
    resolver.watch("xmpp", dhonomos_pki::tls::DEFAULT_RELOAD_INTERVAL);
    let tls = dhonomos_xmpp::tls_acceptor(resolver).context("XMPP TLS settings")?;
    let mut config = dhonomos_xmpp::XmppConfig::new(domain);
    config.idle_timeout = xmpp_idle_timeout(rt.xmpp_idle_timeout, cli.xmpp_keepalive);
    config.max_connections = cli.xmpp_max_connections;
    config.max_connections_per_ip = cli.xmpp_max_connections_per_ip;
    if config.idle_timeout <= Duration::from_secs(u64::from(cli.xmpp_keepalive)) {
        tracing::warn!(idle_timeout = ?config.idle_timeout, keepalive = cli.xmpp_keepalive,
            "--xmpp-idle-timeout is not longer than the keep-alive: devices will be disconnected between their pings");
    }
    // No session survives a restart -> what an earlier process left must not show as connected.
    let stale = store
        .clear_all_xmpp_connected()
        .await
        .context("clearing stale XMPP session times")?;
    if stale > 0 {
        tracing::info!(
            devices = stale,
            "cleared XMPP session times left by an earlier process"
        );
    }
    let accounts = std::sync::Arc::new(dhonomos_core::XmppAccounts::new(
        store.clone(),
        DEFAULT_TENANT,
        secrets,
    ));
    let listener = dhonomos_cwmp_server::bind(addr)
        .with_context(|| format!("binding the XMPP listener {addr}"))?;
    Ok(Some(Xmpp {
        server: dhonomos_xmpp::XmppServer::new(config, accounts, tls),
        listener,
    }))
}

/// Roles that must use two-factor auth: `--require-totp-roles`,
/// then `--require-admin-totp` (if given) adds or removes admin.
fn required_totp_roles(roles: &[String], admin: Option<bool>) -> Result<Vec<String>, String> {
    let mut roles = dhonomos_api::TotpConfig::parse_roles(roles)?;
    match admin {
        Some(true) if !roles.iter().any(|r| r == "admin") => roles.push("admin".into()),
        Some(false) => roles.retain(|r| r != "admin"),
        _ => {}
    }
    Ok(roles)
}

/// Warn on settings too weak for a proxied, internet-facing UI (ADR-103).
fn proxy_warnings(cli: &Cli) {
    let https = cli.public_url.as_ref().is_some_and(|u| u.is_https());
    if (!cli.trusted_proxies.is_empty() || https) && !cli.secure_cookies {
        tracing::warn!(
            "trusted proxies or an https public URL are configured but --secure-cookies is off: the session cookie lacks Secure and the __Host- prefix; turn it on"
        );
    }
    if cli.public_url.is_some() && cli.trusted_proxies.is_empty() {
        tracing::warn!(
            "--public-url is set but --trusted-proxies is not: behind the proxy every visitor counts as the proxy's address, so one visitor can exhaust the rate limits and lock out every login; set --trusted-proxies 127.0.0.1/32 (the proxy's address)"
        );
    }
    for net in &cli.trusted_proxies {
        // Network this wide -> whole internet trusted to say who it is.
        let text = net.to_string();
        let prefix = text.rsplit('/').next().and_then(|p| p.parse::<u8>().ok());
        if prefix.is_some_and(|p| p < 8) {
            tracing::warn!(network = %text,
                "--trusted-proxies trusts a very wide network: anyone in it can forge the client address; list only the proxy's own address");
        }
    }
    if !cli.trusted_proxies.is_empty() {
        tracing::info!(
            networks = %cli.trusted_proxies.iter().map(ToString::to_string).collect::<Vec<_>>().join(","),
            "forwarding headers are believed from these proxies"
        );
    }
    if cli.session_idle_minutes <= 0 {
        tracing::warn!("--session-idle-minutes is 0: UI sessions never end for being idle");
    }
}

/// Single sign-on settings, if an issuer is configured.
fn oidc_config(cli: &Cli) -> anyhow::Result<Option<dhonomos_api::OidcConfig>> {
    let Some(issuer) = &cli.oidc_issuer else {
        return Ok(None);
    };
    let (Some(client_id), Some(redirect_url)) = (&cli.oidc_client_id, &cli.oidc_redirect_url)
    else {
        anyhow::bail!("--oidc-issuer needs --oidc-client-id and --oidc-redirect-url");
    };
    anyhow::ensure!(
        cli.oidc_scopes.split_whitespace().any(|s| s == "openid"),
        "--oidc-scopes must include openid"
    );
    let groups = |v: &[String]| -> Vec<String> {
        v.iter()
            .map(|g| g.trim().to_owned())
            .filter(|g| !g.is_empty())
            .collect()
    };
    let (admin, operator, viewer) = (
        groups(&cli.oidc_admin_groups),
        groups(&cli.oidc_operator_groups),
        groups(&cli.oidc_viewer_groups),
    );
    anyhow::ensure!(
        !(admin.is_empty() && operator.is_empty() && viewer.is_empty()),
        "map at least one group to a role (--oidc-admin-groups, --oidc-operator-groups, --oidc-viewer-groups)"
    );
    tracing::info!(%issuer, "single sign-on enabled");
    Ok(Some(dhonomos_api::OidcConfig {
        issuer: issuer.clone(),
        client_id: client_id.clone(),
        client_secret: cli.oidc_client_secret.clone(),
        redirect_url: redirect_url.clone(),
        scopes: cli.oidc_scopes.clone(),
        username_claim: cli.oidc_username_claim.clone(),
        role_claim: cli.oidc_role_claim.clone(),
        admin,
        operator,
        viewer,
    }))
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum SmtpSecurity {
    Starttls,
    Tls,
    None,
}

/// E-mail settings if SMTP host + sender are set: checked, with password and extra CA
/// certificates (PEM) from the server configuration (never change at runtime).
fn alarm_email(
    s: &dhonomos_core::RuntimeSettings,
    password: Option<String>,
    ca_pem: Option<String>,
) -> Result<Option<dhonomos_core::alarms::AlarmEmail>, String> {
    let (Some(host), Some(from)) = (&s.smtp_host, &s.alarm_email_from) else {
        return Ok(None);
    };
    if s.alarm_email_to.is_empty() {
        return Err("--alarm-email-to is required with --smtp-host".into());
    }
    if !matches!(
        s.alarm_email_min_severity.as_str(),
        "critical" | "major" | "minor" | "warning"
    ) {
        return Err("--alarm-email-min-severity must be critical, major, minor or warning".into());
    }
    if matches!(s.smtp_security, dhonomos_core::mail::Security::None) && s.smtp_username.is_some() {
        return Err(
            "--smtp-security none cannot log in (credentials would travel in the clear)".into(),
        );
    }
    Ok(Some(dhonomos_core::alarms::AlarmEmail {
        smtp: dhonomos_core::mail::SmtpConfig {
            host: host.clone(),
            port: s.smtp_port,
            security: s.smtp_security,
            username: s.smtp_username.clone(),
            password,
            from: from.clone(),
            to: s.alarm_email_to.clone(),
            ca_pem,
        },
        min_severity: s.alarm_email_min_severity.clone(),
    }))
}

/// Read a preset file; its scripts live next to it.
fn load_presets(path: &std::path::Path) -> anyhow::Result<dhonomos_core::Presets> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let p = dhonomos_core::Presets::from_yaml_in(&text, dir)
        .with_context(|| format!("loading {}", path.display()))?;
    tracing::info!(presets = p.len(), file = %path.display(), "presets loaded");
    Ok(p)
}

/// Alarm e-mail settings at engine start. Bad settings + `--alarms` file -> server stops
/// (as before rules could be stored). No file -> logged, e-mail off, server starts;
/// valid change from the web turns it on later.
fn startup_alarm_email(
    rt: &dhonomos_core::RuntimeSettings,
    smtp_password: Option<String>,
    smtp_ca_pem: Option<String>,
    alarms_file: bool,
) -> anyhow::Result<Option<dhonomos_core::alarms::AlarmEmail>> {
    match alarm_email(rt, smtp_password, smtp_ca_pem) {
        Ok(email) => Ok(email),
        Err(e) if !alarms_file => {
            tracing::warn!("alarm e-mail is off: {e}; fix the SMTP/alarm e-mail options");
            Ok(None)
        }
        Err(e) => Err(anyhow::Error::msg(e)),
    }
}

/// Read + validate an alarm rule file -> rules + file text.
fn load_alarm_rules(
    path: &std::path::Path,
) -> anyhow::Result<(dhonomos_core::alarms::AlarmRules, String)> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let rules = dhonomos_core::alarms::AlarmRules::from_yaml(&text)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("loading {}", path.display()))?;
    tracing::info!(rules = rules.iter().count(), file = %path.display(), "alarm rules loaded");
    Ok((rules, text))
}

/// Alarm rules at process start.
struct StartupAlarmRules {
    rules: dhonomos_core::alarms::AlarmRules,
    /// Source `--alarms` file; `None` = from DB.
    file: Option<dhonomos_api::AlarmRulesFile>,
    /// Revision of the stored rules when read (0 with a file).
    seen: i64,
}

/// Rules of the `--alarms` file (load failure -> server stops), else rules stored from the web.
/// None stored, or stored rules fail to load (logged) -> server starts with no rules.
async fn startup_alarm_rules(
    file: Option<&std::path::Path>,
    store: &Store,
) -> anyhow::Result<StartupAlarmRules> {
    if let Some(path) = file {
        let (rules, text) = load_alarm_rules(path)?;
        return Ok(StartupAlarmRules {
            rules,
            file: Some(dhonomos_api::AlarmRulesFile {
                path: path.display().to_string(),
                yaml: dhonomos_core::Shared::new(text),
            }),
            seen: 0,
        });
    }
    // Revision first -> change stored in between is applied by the watcher.
    let seen = store
        .config_revision(DEFAULT_TENANT, dhonomos_store::ALARM_RULES_REVISION)
        .await
        .context("reading the alarm rules revision")?;
    let stored = store
        .alarm_rule_set(DEFAULT_TENANT)
        .await
        .context("reading the alarm rules")?;
    Ok(StartupAlarmRules {
        rules: dhonomos_core::alarms::AlarmRules::from_stored(
            stored.as_ref().map(|s| s.yaml.as_str()),
        ),
        file: None,
        seen,
    })
}

/// SIGHUP -> reload presets (with their scripts) and alarm rules.
/// File fails to load -> running configuration kept.
async fn reload_on_hangup(
    presets_file: Option<std::path::PathBuf>,
    presets: dhonomos_core::Shared<dhonomos_core::Presets>,
    alarms_file: Option<dhonomos_api::AlarmRulesFile>,
    alarm_rules: dhonomos_core::Shared<dhonomos_core::alarms::AlarmRules>,
) -> anyhow::Result<()> {
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    loop {
        tokio::select! {
            () = shutdown() => return Ok(()),
            _ = hangup.recv() => {}
        }
        tracing::info!("SIGHUP: reloading configuration");
        if let Some(path) = &presets_file {
            match load_presets(path) {
                Ok(p) => presets.replace(p),
                Err(e) => tracing::error!(
                    error = format!("{e:#}"),
                    "presets not reloaded; keeping the running ones"
                ),
            }
        }
        if let Some(file) = &alarms_file {
            match load_alarm_rules(std::path::Path::new(&file.path)) {
                Ok((r, text)) => {
                    alarm_rules.replace(r);
                    file.yaml.replace(text);
                }
                Err(e) => tracing::error!(
                    error = format!("{e:#}"),
                    "alarm rules not reloaded; keeping the running ones"
                ),
            }
        }
    }
}

/// TLS to the MQTT broker (ADR-081), bridge sockets next to the file store.
fn mqtt_tls(cli: &Cli) -> anyhow::Result<Option<dhonomos_usp_mtp::MqttTls>> {
    if !cli.usp_mqtt_tls {
        return Ok(None);
    }
    let read = |p: &std::path::Path| {
        std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))
    };
    let ca = cli.usp_mqtt_ca.as_deref().map(read).transpose()?;
    let client = match (&cli.usp_mqtt_client_cert, &cli.usp_mqtt_client_key) {
        (Some(c), Some(k)) => Some((read(c)?, read(k)?)),
        _ => None,
    };
    let config = dhonomos_usp_mtp::tls_bridge::client_config(
        ca.as_deref(),
        client.as_ref().map(|(c, k)| (c.as_str(), k.as_str())),
    )
    .context("MQTT TLS settings")?;
    let tls = dhonomos_usp_mtp::MqttTls {
        config,
        server_name: cli.usp_mqtt_tls_name.clone(),
        socket_dir: cli.files_dir.join(".mqtt-tls"),
    };
    tls.check().context("MQTT TLS bridge directory")?;
    Ok(Some(tls))
}

/// WebSocket MTP on `addr` takes Agents that only claim their EndpointID
/// (any client can pose as any Agent), unless loopback or wss with client certs required.
/// Such a listener: refused unless `allow_anonymous`.
fn ws_takes_anonymous_agents(
    addr: SocketAddr,
    tls: bool,
    client_cert: ClientCert,
    allow_anonymous: bool,
) -> anyhow::Result<bool> {
    if addr.ip().is_loopback() || (tls && client_cert == ClientCert::Required) {
        return Ok(false);
    }
    if !allow_anonymous {
        anyhow::bail!(
            "the WebSocket MTP on {addr} would take any client that claims an EndpointID: use --usp-ws-tls with --usp-ws-client-cert required, listen on loopback, or pass --usp-ws-allow-anonymous"
        );
    }
    Ok(true)
}

/// TLS for the USP WebSocket MTP (also STOMP, MQTT broker): files or USP CA certificate.
/// `listener` labels reload metrics and log.
/// Files -> follow renewed files. CA-issued -> issued again (new key) shortly before
/// expiry; never stored -> new one at each start.
fn ws_tls(
    cli: &Cli,
    ca: Option<&std::sync::Arc<dhonomos_pki::Ca>>,
    listener: &'static str,
) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use dhonomos_pki::tls::{CertResolver, DEFAULT_RELOAD_INTERVAL, RenewPolicy};
    let resolver = match (&cli.usp_ws_tls_cert, &cli.usp_ws_tls_key, ca) {
        (Some(c), Some(k), _) => {
            let resolver = CertResolver::from_files(c, k).context("loading the wss certificate")?;
            resolver.watch(listener, DEFAULT_RELOAD_INTERVAL);
            resolver
        }
        (_, _, Some(ca)) => {
            let ips: Vec<std::net::IpAddr> = cli
                .usp_ws_tls_name
                .iter()
                .filter_map(|n| n.parse().ok())
                .collect();
            // IP also as DNS name: obuspa STOMP + MQTT TLS check the host with
            // X509_VERIFY_PARAM_set1_host only -> never looks at IP SANs.
            let profile = dhonomos_pki::Profile {
                endpoint_id: cli.usp_endpoint_id.clone(),
                dns_names: cli.usp_ws_tls_name.clone(),
                ip_addresses: ips,
                server: true,
                days: 90,
            };
            let (chain, key) = ca.issue_chain(&profile)?;
            let resolver = CertResolver::from_pem(&chain, &key)?;
            let ca = std::sync::Arc::clone(ca);
            resolver.renew(listener, RenewPolicy::default(), move || {
                ca.issue_chain(&profile)
            });
            resolver
        }
        _ => anyhow::bail!("--usp-ws-tls needs --usp-ws-tls-cert/--usp-ws-tls-key or --usp-ca-dir"),
    };
    // USP CA and/or extra CAs (e.g. vendor factory).
    let extra = cli
        .usp_ws_client_ca
        .as_deref()
        .map(|p| std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display())))
        .transpose()?;
    let client_ca = match cli.usp_ws_client_cert {
        ClientCert::None => None,
        _ => {
            let roots: String = ca
                .map(|c| c.cert_pem().to_owned())
                .into_iter()
                .chain(extra)
                .collect::<Vec<_>>()
                .join("\n");
            if roots.is_empty() {
                anyhow::bail!(
                    "client certificates need --usp-ca-dir or --usp-ws-client-ca (or --usp-ws-client-cert none)"
                );
            }
            Some(roots)
        }
    };
    Ok(dhonomos_usp_mtp::tls_acceptor_with(
        resolver,
        client_ca.as_deref(),
        cli.usp_ws_client_cert == ClientCert::Required,
    )?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn totp_roles_come_from_the_list_and_the_older_admin_switch() {
        let roles = |list: &[&str], admin: Option<bool>| {
            required_totp_roles(
                &list.iter().map(|r| (*r).to_owned()).collect::<Vec<_>>(),
                admin,
            )
            .unwrap()
        };
        // Default: admin only.
        assert_eq!(roles(&["admin"], None), ["admin"]);
        assert_eq!(roles(&["admin", "operator"], None), ["admin", "operator"]);
        // Explicit `--require-admin-totp` -> decides the admin role.
        assert_eq!(roles(&["admin"], Some(true)), ["admin"]);
        assert_eq!(roles(&["admin"], Some(false)), Vec::<String>::new());
        assert_eq!(roles(&["operator"], Some(true)), ["operator", "admin"]);
        assert_eq!(roles(&["admin", "operator"], Some(false)), ["operator"]);
        // `none`, empty list -> no role.
        assert_eq!(roles(&["none"], None), Vec::<String>::new());
        assert_eq!(roles(&[""], None), Vec::<String>::new());
        assert!(required_totp_roles(&["root".into()], None).is_err());
        // Via command line parse.
        let cli = Cli::try_parse_from([
            "dhonomos",
            "--database-url",
            "postgres://x",
            "--require-totp-roles",
            "admin,operator",
            "--require-admin-totp",
            "false",
            "--trusted-proxies",
            "127.0.0.1/32,::1",
            "--public-url",
            "https://rms.example.org",
        ])
        .unwrap();
        assert_eq!(
            required_totp_roles(&cli.require_totp_roles, cli.require_admin_totp).unwrap(),
            ["operator"]
        );
        assert_eq!(cli.trusted_proxies.len(), 2);
        assert!(cli.public_url.is_some_and(|u| u.is_https()));
        let args = |extra: &[&'static str]| {
            Cli::try_parse_from(
                ["dhonomos", "--database-url", "postgres://x"]
                    .into_iter()
                    .chain(extra.iter().copied()),
            )
        };
        let none = args(&[]).unwrap();
        assert_eq!(none.require_totp_roles, ["admin"]);
        assert_eq!(none.require_admin_totp, None);
        assert_eq!(none.session_idle_minutes, 60);
        assert!(none.trusted_proxies.is_empty() && none.public_url.is_none());
        assert!(args(&["--public-url", "rms.example.org"]).is_err());
        assert!(args(&["--trusted-proxies", "not-an-ip"]).is_err());
    }

    #[test]
    fn wireguard_settings() {
        let args = |extra: &[&'static str]| {
            Cli::try_parse_from(
                ["dhonomos", "--database-url", "postgres://x"]
                    .into_iter()
                    .chain(extra.iter().copied()),
            )
        };
        let none = args(&[]).unwrap();
        assert_eq!(none.wg_address_pool.to_string(), "10.77.0.0/16");
        assert_eq!(none.wg_address_reuse_delay_hours, 24);
        let cfg = dhonomos_api::WireguardConfig::new(
            none.wg_address_pool,
            none.wg_address_reuse_delay_hours,
        )
        .unwrap();
        assert_eq!(cfg, dhonomos_api::WireguardConfig::default());
        let set = args(&[
            "--wg-address-pool",
            "172.30.0.0/16",
            "--wg-address-reuse-delay-hours",
            "0",
        ])
        .unwrap();
        assert_eq!(set.wg_address_pool.to_string(), "172.30.0.0/16");
        assert_eq!(set.wg_address_reuse_delay_hours, 0);
        // Prefix, not address; network address, not a host in it.
        assert!(args(&["--wg-address-pool", "10.77.0.1"]).is_err());
        assert!(args(&["--wg-address-pool", "10.77.0.1/16"]).is_err());
        assert!(args(&["--wg-address-pool", "fd00::/48"]).is_err());
        // Parses, but not a usable pool.
        let loopback = args(&["--wg-address-pool", "127.0.0.0/8"]).unwrap();
        assert!(dhonomos_api::WireguardConfig::new(loopback.wg_address_pool, 24).is_err());
        let tiny = args(&["--wg-address-pool", "10.77.0.0/30"]).unwrap();
        assert!(dhonomos_api::WireguardConfig::new(tiny.wg_address_pool, 24).is_err());
    }

    #[test]
    fn usp_timeouts_default_to_30_and_120_seconds() {
        let cli = Cli::try_parse_from(["dhonomos", "--database-url", "postgres://x"]).unwrap();
        assert_eq!(
            (cli.usp_request_timeout, cli.usp_full_read_timeout),
            (30, 120)
        );
        assert_eq!(
            usp_timeouts(cli.usp_request_timeout, cli.usp_full_read_timeout).unwrap(),
            (Duration::from_secs(30), Duration::from_secs(120))
        );
        // Via command line parse.
        let cli = Cli::try_parse_from([
            "dhonomos",
            "--database-url",
            "postgres://x",
            "--usp-request-timeout",
            "10",
            "--usp-full-read-timeout",
            "300",
        ])
        .unwrap();
        assert_eq!(
            (cli.usp_request_timeout, cli.usp_full_read_timeout),
            (10, 300)
        );
        // Not a number of seconds.
        assert!(
            Cli::try_parse_from([
                "dhonomos",
                "--database-url",
                "postgres://x",
                "--usp-request-timeout",
                "30s",
            ])
            .is_err()
        );
    }

    #[test]
    fn usp_timeouts_are_positive_and_the_full_read_is_not_the_shorter() {
        // Equal OK, longer = intended.
        assert!(usp_timeouts(30, 30).is_ok());
        assert!(usp_timeouts(1, u64::MAX).is_ok());
        let err = usp_timeouts(0, 120).unwrap_err().to_string();
        assert!(
            err.contains("--usp-request-timeout must be at least 1 second"),
            "{err}"
        );
        let err = usp_timeouts(30, 0).unwrap_err().to_string();
        assert!(
            err.contains("--usp-full-read-timeout must be at least 1 second"),
            "{err}"
        );
        let err = usp_timeouts(0, 0).unwrap_err().to_string();
        assert!(err.contains("--usp-request-timeout"), "{err}");
        // Full read shorter than ordinary request.
        let err = usp_timeouts(60, 30).unwrap_err().to_string();
        assert!(
            err.contains("--usp-full-read-timeout (30 s) must not be shorter than --usp-request-timeout (60 s)"),
            "{err}"
        );
    }

    #[test]
    fn rustls_sni_warning_is_hidden_by_default() {
        assert_eq!(log_directives(None), "info,rustls::msgs::handshake=error");
        assert_eq!(
            log_directives(Some("  ")),
            "info,rustls::msgs::handshake=error"
        );
        assert_eq!(
            log_directives(Some("debug,sqlx=warn")),
            "debug,sqlx=warn,rustls::msgs::handshake=error"
        );
        // `tokio_rustls` != rustls.
        assert_eq!(
            log_directives(Some("tokio_rustls=debug")),
            "tokio_rustls=debug,rustls::msgs::handshake=error"
        );
    }

    #[test]
    fn rustls_directives_of_the_operator_win() {
        for rust_log in [
            "rustls=warn",
            "info,rustls=debug",
            "info, rustls::msgs::handshake=warn",
            "rustls::server=trace,info",
            "warn,rustls[span]=info",
        ] {
            assert_eq!(log_directives(Some(rust_log)), rust_log);
        }
    }

    #[test]
    fn every_directive_set_parses() {
        for rust_log in [None, Some("debug"), Some("info,"), Some("rustls=warn")] {
            assert!(EnvFilter::try_new(log_directives(rust_log)).is_ok());
        }
        // Broken RUST_LOG -> still a working filter.
        let _ = log_filter(Some("info,=="));
    }

    #[test]
    fn ws_listener_needs_client_certificates_off_loopback() {
        let lan: SocketAddr = "10.20.30.1:7549".parse().unwrap();
        let lan6: SocketAddr = "[2001:db8::1]:7549".parse().unwrap();
        let any: SocketAddr = "0.0.0.0:7549".parse().unwrap();
        let lo: SocketAddr = "127.0.0.1:7549".parse().unwrap();
        let lo6: SocketAddr = "[::1]:7549".parse().unwrap();
        // Loopback: OK with any settings.
        for addr in [lo, lo6] {
            for (tls, cert) in [
                (false, ClientCert::Optional),
                (true, ClientCert::None),
                (true, ClientCert::Optional),
                (true, ClientCert::Required),
            ] {
                assert!(!ws_takes_anonymous_agents(addr, tls, cert, false).unwrap());
            }
        }
        // wss + required client certs: OK anywhere, no flag needed.
        for addr in [lan, lan6, any] {
            assert!(!ws_takes_anonymous_agents(addr, true, ClientCert::Required, false).unwrap());
            assert!(!ws_takes_anonymous_agents(addr, true, ClientCert::Required, true).unwrap());
        }
        // Else off loopback: refused ...
        for addr in [lan, lan6, any] {
            for (tls, cert) in [
                (false, ClientCert::Required),
                (false, ClientCert::Optional),
                (false, ClientCert::None),
                (true, ClientCert::Optional),
                (true, ClientCert::None),
            ] {
                let err = ws_takes_anonymous_agents(addr, tls, cert, false).unwrap_err();
                let msg = err.to_string();
                assert!(
                    msg.contains("--usp-ws-client-cert required")
                        && msg.contains("--usp-ws-allow-anonymous"),
                    "{msg}"
                );
                // ... unless asked -> caller logs a warning.
                assert!(ws_takes_anonymous_agents(addr, tls, cert, true).unwrap());
            }
        }
    }

    #[test]
    fn the_files_secret_is_long_and_not_a_sample_value() {
        // Short + old sample-file values: refused.
        for weak in [
            "",
            "dev-secret",
            "nat-test-secret",
            "change-me",
            "changeme",
            "secret",
            "password",
            "Change-Me",
        ] {
            let err = check_files_secret(weak).unwrap_err().to_string();
            assert!(err.contains("at least 32 bytes"), "{weak:?}: {err}");
        }
        // Long enough, still a placeholder.
        for sample in [
            "change-me-change-me-change-me-change-me",
            "PLEASE-CHANGE-ME-PLEASE-CHANGE-ME-PLEASE",
            "changeme-changeme-changeme-changeme-changeme",
        ] {
            let err = check_files_secret(sample).unwrap_err().to_string();
            assert!(err.contains("placeholder"), "{sample:?}: {err}");
        }
        // 31 bytes short, 32 OK (bytes, not chars).
        assert!(check_files_secret(&"a".repeat(31)).is_err());
        assert!(check_files_secret(&"a".repeat(32)).is_ok());
        assert!(check_files_secret(&"ä".repeat(16)).is_ok());
        // Output of `openssl rand -base64 32`.
        assert!(check_files_secret("q3L9m0rQ1h6nE3Xc8tN2vYyZ5w7aKdPfU4sBjH1oGkI=").is_ok());
    }

    #[test]
    fn sample_passwords_are_placeholders() {
        for sample in [
            "change-me",
            "change-me-please",
            "CHANGEME",
            "  password ",
            "secret",
        ] {
            assert!(is_placeholder(sample), "{sample:?}");
        }
        for chosen in [
            "correct horse battery",
            "q3L9m0rQ1h6nE3Xc",
            "secretive-otter-42",
        ] {
            assert!(!is_placeholder(chosen), "{chosen:?}");
        }
    }

    #[test]
    fn warnings_for_open_listeners_ask_for_a_network_address() {
        let lan: SocketAddr = "10.20.30.1:7547".parse().unwrap();
        let any6: SocketAddr = "[::]:7547".parse().unwrap();
        let lo: SocketAddr = "127.0.0.1:7547".parse().unwrap();
        let lo6: SocketAddr = "[::1]:7547".parse().unwrap();
        // ACS without CPE auth.
        for addr in [lan, any6] {
            assert!(acs_open_to_the_network(CpeAuth::None, addr));
            assert!(!acs_open_to_the_network(CpeAuth::Digest, addr));
            assert!(!acs_open_to_the_network(CpeAuth::Basic, addr));
        }
        for addr in [lo, lo6] {
            assert!(!acs_open_to_the_network(CpeAuth::None, addr));
        }
        // Broker: shared login, no TLS.
        for addr in [lan, any6] {
            assert!(shared_login_in_the_clear(addr, true, false));
            assert!(!shared_login_in_the_clear(addr, true, true), "TLS");
            assert!(!shared_login_in_the_clear(addr, false, false), "no login");
        }
        for addr in [lo, lo6] {
            assert!(!shared_login_in_the_clear(addr, true, false));
        }
    }

    #[test]
    fn file_server_scheme_is_checked_against_tls() {
        assert!(files_url_scheme_warning(true, "https://acs.example.net:7548").is_none());
        assert!(files_url_scheme_warning(false, "http://acs.example.net:7548").is_none());
        assert!(files_url_scheme_warning(true, "http://acs.example.net:7548").is_some());
        assert!(files_url_scheme_warning(true, "HTTP://acs.example.net:7548").is_some());
        assert!(files_url_scheme_warning(false, "https://acs.example.net").is_some());
        assert!(files_url_scheme_warning(true, "").is_none());
    }

    #[test]
    fn retention_reads_the_days_at_each_pass() {
        let now = time::OffsetDateTime::now_utc();
        let days = dhonomos_core::Shared::new((30, 0, 90));
        let (events, tasks, alarms) = retention_cutoffs(*days.get(), now);
        assert_eq!(events, now - time::Duration::days(30));
        assert_eq!(
            tasks,
            time::OffsetDateTime::UNIX_EPOCH,
            "0 keeps them forever"
        );
        assert_eq!(alarms, now - time::Duration::days(90));
        // Changed at runtime -> next pass uses the new days.
        days.replace((7, 1, 0));
        let (events, tasks, alarms) = retention_cutoffs(*days.get(), now);
        assert_eq!(events, now - time::Duration::days(7));
        assert_eq!(tasks, now - time::Duration::days(1));
        assert_eq!(alarms, time::OffsetDateTime::UNIX_EPOCH);
    }

    /// Bad alarm e-mail settings: off + warning without `--alarms`, refused with it.
    #[test]
    fn startup_alarm_email_is_off_or_refused() {
        let argv = [
            "dhonomos",
            "--database-url",
            "postgres://x",
            "--smtp-host",
            "mail.example",
            "--alarm-email-from",
            "rms@example.org",
        ]
        .map(std::ffi::OsString::from);
        let rt = settings::effective_with(&Cli::command(), &argv, &Default::default()).unwrap();
        assert!(
            startup_alarm_email(&rt, None, None, false)
                .unwrap()
                .is_none()
        );
        let err = startup_alarm_email(&rt, None, None, true).unwrap_err();
        assert!(err.to_string().contains("--alarm-email-to"), "{err}");
    }

    /// No file: none stored, or stored rules fail to load -> no rules (server still starts).
    /// File: its rules, whatever is stored.
    #[tokio::test]
    async fn startup_alarm_rules_come_from_the_file_or_the_database() {
        use testcontainers_modules::postgres::Postgres;
        use testcontainers_modules::testcontainers::ImageExt as _;
        use testcontainers_modules::testcontainers::runners::AsyncRunner as _;

        let pg = Postgres::default()
            .with_tag("17-alpine")
            .start()
            .await
            .unwrap();
        let url = format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            pg.get_host_port_ipv4(5432).await.unwrap()
        );
        let store = Store::connect(&url, 2).await.unwrap();
        store.migrate().await.unwrap();

        let r = startup_alarm_rules(None, &store).await.unwrap();
        assert!(r.rules.is_empty() && r.file.is_none());
        assert_eq!(r.seen, 0);

        store
            .set_alarm_rule_set(DEFAULT_TENANT, "alarms: [{ name: x }]", None)
            .await
            .unwrap();
        let r = startup_alarm_rules(None, &store).await.unwrap();
        assert!(r.rules.is_empty(), "invalid stored rules: none");
        assert_eq!(r.seen, 1);

        store
            .set_alarm_rule_set(
                DEFAULT_TENANT,
                "alarms: [{ name: stored, severity: major, when: { offline_minutes: 5 } }]",
                None,
            )
            .await
            .unwrap();
        let r = startup_alarm_rules(None, &store).await.unwrap();
        assert!(r.rules.contains("stored"));
        assert_eq!(r.seen, 2);

        let path =
            std::env::temp_dir().join(format!("dhonomos-alarms-{}.yaml", std::process::id()));
        let text = "alarms: [{ name: from-file, severity: minor, when: { offline_minutes: 9 } }]\n";
        std::fs::write(&path, text).unwrap();
        let r = startup_alarm_rules(Some(&path), &store).await.unwrap();
        assert!(r.rules.contains("from-file") && !r.rules.contains("stored"));
        let file = r.file.unwrap();
        assert_eq!(file.path, path.display().to_string());
        assert_eq!(*file.yaml.get(), text);
        // File fails to load -> server still stops.
        std::fs::write(&path, "alarms: [{ name: x }]").unwrap();
        assert!(startup_alarm_rules(Some(&path), &store).await.is_err());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn apply_reaches_every_component() {
        use serde_json::json;
        use testcontainers_modules::postgres::Postgres;
        use testcontainers_modules::testcontainers::ImageExt as _;
        use testcontainers_modules::testcontainers::runners::AsyncRunner as _;

        let pg = Postgres::default()
            .with_tag("17-alpine")
            .start()
            .await
            .unwrap();
        let url = format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            pg.get_host_port_ipv4(5432).await.unwrap()
        );
        let store = Store::connect(&url, 2).await.unwrap();
        let argv = ["dhonomos", "--database-url", "postgres://x"].map(std::ffi::OsString::from);
        let effective = |db: &[(&str, serde_json::Value)]| {
            let db = db
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect();
            settings::effective_with(&Cli::command(), &argv, &db).unwrap()
        };
        let rt = effective(&[]);
        let files = FilesConfig::new(
            std::env::temp_dir(),
            FileSigner::new(b"k".to_vec(), "http://f", Duration::from_secs(3600)),
            rt.files_max_bytes,
            download_limits(&rt),
        );
        let engine = dhonomos_core::alarms::AlarmEngine::new(
            store.clone(),
            DEFAULT_TENANT,
            dhonomos_core::alarms::AlarmRules::default(),
            dhonomos_core::alarms::Webhooks::default(),
        );
        let acs = AcsServer::new(
            AcsConfig::default(),
            CwmpBackend::new(store.clone(), DEFAULT_TENANT, CpeCredentials::None),
        );
        let live = Live {
            retention: dhonomos_core::Shared::new((30, 90, 90)),
            metrics: dhonomos_core::MetricsIngest::new(store.clone(), 30, 2),
            files: files.clone(),
            usp: None,
            xmpp: None,
            xmpp_keepalive: 30,
            webhook_urls: Some(engine.webhook_urls()),
            email: Some(engine.email()),
            smtp_password: Some("smtp-pw-1".into()),
            smtp_ca_pem: None,
            acs: Some(acs.clone()),
            api: Some(ApiLive {
                session_hours: 12.into(),
                session_idle_minutes: 60.into(),
                rate_limit: 50.into(),
                wireguard: dhonomos_core::Shared::default(),
            }),
        };
        live.apply(&rt);
        assert!(engine.email().get().is_none());
        let rt = effective(&[
            ("events_retention_days", json!("7")),
            ("metrics_retention_days", json!("10")),
            ("metrics_raw_days", json!("20")),
            ("webhook_url", json!(["https://a.example/x"])),
            ("smtp_host", json!("mail.example")),
            ("alarm_email_from", json!("rms@example.org")),
            ("alarm_email_to", json!(["noc@example.org"])),
            ("session_hours", json!("4")),
            ("session_idle_minutes", json!("5")),
            ("api_rate_limit", json!("3")),
            ("cpe_session_limit", json!("2")),
            ("cpe_max_params_per_message", json!("100")),
            ("cpe_max_params_per_device", json!("1000")),
            ("session_timeout", json!("15")),
            ("files_max_bytes", json!("2048")),
            ("files_total_mbps", json!("8")),
            ("files_download_mbps", json!("1")),
            ("files_max_downloads", json!("4")),
            ("files_link_hours", json!("2")),
            ("wg_address_pool", json!("172.30.0.0/16")),
            ("wg_address_reuse_delay_hours", json!("0")),
        ]);
        live.apply(&rt);
        assert_eq!(live.retention.get().0, 7);
        assert_eq!(live.metrics.retention(), (10, 10), "raw days clamped");
        assert_eq!(*engine.webhook_urls().get(), ["https://a.example/x"]);
        let email = engine.email().get();
        let email = email.as_ref().as_ref().unwrap();
        assert_eq!(email.smtp.host, "mail.example");
        assert_eq!(
            email.smtp.password.as_deref(),
            Some("smtp-pw-1"),
            "the configuration's password is kept"
        );
        let api = live.api.as_ref().unwrap();
        assert_eq!(
            (
                *api.session_hours.get(),
                *api.session_idle_minutes.get(),
                *api.rate_limit.get()
            ),
            (4, 5, 3)
        );
        assert_eq!(
            api.wireguard.get().address_pool.to_string(),
            "172.30.0.0/16"
        );
        let limits = acs.backend().limits();
        assert_eq!(limits.sessions.per_minute(), 2);
        assert_eq!(
            (
                limits.max_params_per_message(),
                limits.max_params_per_device()
            ),
            (100, 1000)
        );
        assert_eq!(acs.session_timeout(), Duration::from_secs(15));
        assert_eq!(files.max_bytes(), 2048);
        assert_eq!(
            files.limits(),
            dhonomos_api::DownloadLimits {
                total_rate: Some(1_000_000),
                per_download_rate: Some(125_000),
                max_concurrent: Some(4),
            }
        );
        assert_eq!(files.signer.ttl(), Duration::from_secs(7200));

        // Back to defaults -> e-mail off again.
        live.apply(&effective(&[]));
        assert!(engine.email().get().is_none());
        assert!(engine.webhook_urls().get().is_empty());
        assert_eq!(files.limits(), dhonomos_api::DownloadLimits::default());
        assert_eq!(acs.backend().limits().sessions.per_minute(), 30);
    }
}
