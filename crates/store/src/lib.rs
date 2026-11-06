//! PostgreSQL repositories + migrations (docs/design/04-store-schema.md).
//!
//! Queries checked at compile time against the schema. Offline data: `.sqlx/` at the
//! workspace root (`cargo sqlx prepare --workspace` after changes).

mod alarm_rule_sets;
mod alarms;
mod audit;
mod auth;
mod backups;
mod certificates;
mod credentials;
mod devices;
mod events;
mod files;
mod filter;
mod jobs;
mod metrics;
mod models;
mod overview;
mod params;
mod presets;
mod retention;
mod runtime_settings;
mod scope;
mod silences;
mod tasks;
mod totp;
mod wireguard;
mod wireguard_device;
mod wireguard_hub;

use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

pub use alarm_rule_sets::{ALARM_RULES_REVISION, AlarmRulesVersion, StoredAlarmRules};
pub use alarms::{Alarm, RuleHit};
pub use audit::{AuditEntry, AuditFilter};
pub use auth::{ApiKey, SessionUser, User, UserChanged};
pub use backups::{ConfigBackup, DeletedDevice};
pub use certificates::{
    AgentCertificate, CertificateTarget, FingerprintRevocation, NewCertificate,
};
pub use credentials::{AcsBinding, SealedCredential};
pub use devices::{
    CwmpIdentity, Device, DeviceFacets, DeviceInfo, DeviceSearch, FacetValue, InformUpdate,
    KnownDevice, NewUspDevice, UpsertOutcome,
};
pub use events::Event;
pub use files::{NewFile, StoredFile};
pub use filter::{FilterError, FilterExpr};
pub use jobs::{DeviceFilter, Job, JobCounts, JobMember, LeaderLock, NewJob};
pub use metrics::{DeviceMetric, MetricBucket};
pub use models::{SupportedModel, device_fingerprint};
pub use overview::Overview;
pub use params::{CappedUpsert, ParamUpdate, ParamsWritten, RejectedParam, StoredParam};
pub use presets::{PresetChange, PresetWrite, StoredPreset};
pub use retention::Purged;
pub use runtime_settings::{RUNTIME_SETTINGS_REVISION, RuntimeSettingChange};
pub use scope::DeviceScope;
pub use silences::Silence;
pub use tasks::{NewTask, Task, TaskState};
pub use totp::{ActiveTotp, PendingTotp, SealedTotp};
pub use wireguard::{
    NewWgMember, NewWgMemberKind, NewWgNetwork, RevokedClient, SealedWgPsk, WgDeviceMember,
    WgDeviceSide, WgHealthSummary, WgHub, WgMember, WgNetwork, WgNetworkHealth, WgNetworkPatch,
    WgPeerStatus, WgPrefixChoice, WgRefusal, WgResult, WgSealedPsk, WgSitePrefix, WgStateCounts,
    WgVisibility,
};
pub use wireguard_device::WgDeviceMembership;
pub use wireguard_hub::{WgHubAuth, WgPeerReport, WgReportedPeer};

/// Tenant until multi-tenancy is exposed (ADR-015).
pub const DEFAULT_TENANT: Uuid = Uuid::from_u128(1);

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// DB or connection error.
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// DB handle, cheap to clone.
#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    /// Pool of max `max_connections`.
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self> {
        Self::connect_with(url, max_connections, true).await
    }

    /// [`Self::connect`] + `synchronous_commit` switch.
    ///
    /// `false` -> commit returns before WAL is on disk.
    /// DB crash -> lose up to ~1 s of commits, never corrupt data.
    /// OK for data devices report again in their next session (ADR-049).
    pub async fn connect_with(
        url: &str,
        max_connections: u32,
        synchronous_commit: bool,
    ) -> Result<Self> {
        let mut options: sqlx::postgres::PgConnectOptions = url.parse()?;
        if !synchronous_commit {
            options = options.options([("synchronous_commit", "off")]);
        }
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            // DB down -> fail fast: CPE gets 8005 + retries, no session held open.
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_with(options)
            .await?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}
