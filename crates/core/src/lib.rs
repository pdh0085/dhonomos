//! Device registry, task kinds + protocol backends.

pub mod alarms;
pub mod audit_export;
pub mod broker;
pub mod config;
pub mod cwmp;
pub mod diagnostics;
pub mod files;
pub mod mail;
pub mod metrics;
pub mod nat;
mod param_prune;
mod param_store;
pub mod presets;
pub mod runtime_settings;
pub mod secrets;
pub mod session_limit;
pub mod shared;
pub mod task;
pub mod usp;
pub mod usp_map;
pub mod wake;
pub mod webhook;
pub mod wifi;
mod wireguard;
pub mod xmpp;

pub use broker::{BrokerAccess, BrokerError, IssuedCredentials};
pub use cwmp::{
    CpeCredentials, CwmpBackend, CwmpLimits, DEFAULT_MAX_PARAMS_PER_DEVICE,
    DEFAULT_MAX_PARAMS_PER_MESSAGE, DEFAULT_WG_REWAKE_DELAY, Onboarding, OnboardingMode,
    RunningTask, XmppProvisioning, is_retryable_fault,
};
pub use dhonomos_cwmp_server::{AddressPolicy, Cidr};
pub use files::{FileSigner, UploadKind};
pub use metrics::{MetricsIngest, Sample, parse_bulkdata_json};
pub use presets::{Conditions, MatchContext, PlannedTask, Preset, PresetError, Presets};
pub use runtime_settings::RuntimeSettings;
pub use secrets::{SecretBox, SecretError};
pub use shared::Shared;
pub use task::{SetNotification, SetValue, TaskKind};
pub use usp::{
    DEFAULT_WG_INCOMPLETE_RETRY, DEFAULT_WG_IP_POLL_INTERVAL, DEFAULT_WG_IP_POLL_LIMIT,
    DEFAULT_WG_SWEEP_INTERVAL, UspConfig, UspService,
};
pub use wake::{WakeOutcome, Waker};
pub use xmpp::{XmppAccounts, account_of};
