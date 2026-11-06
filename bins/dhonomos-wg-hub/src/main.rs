//! Dhonomos WireGuard hub (ADR-110, stage 2), runs on a hub host.
//! Desired state from the Dhonomos server (long-poll) -> applied to the kernel:
//! 1 WireGuard interface per network, 1 routing table + `iif` rule per interface,
//! `inet dhonomos_wg` nftables table. Reports its public key + peer status.
//!
//! Trouble never tears anything down: server unreachable, token rejected, nonsense answer,
//! process stop -> kernel kept as it is. Only a state sent by the server changes the target.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher as _, Hasher as _};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use clap::Parser as _;
use dhonomos_wireguard::{HubState, public_from_private};
use tokio::sync::watch;
use tokio::time::Instant;
use tracing_subscriber::EnvFilter;

mod client;
mod config;
mod kernel;
mod keyfile;
mod nft;
mod observed;
mod plan;
mod status;

use client::{Client, ClientError, StateAnswer};
use config::{Cli, Config};
use kernel::{Kernel, PrivateKey};
use plan::{Action, Desired, plan};

/// Latest state, shared by the tasks.
type StateRx = watch::Receiver<Option<Arc<HubState>>>;

/// Retry delay: 1 s, x2 up to 10 s, each +-20%.
/// -> hub catches up ~10 s after the server is back.
/// 1 try per ~10 s -> far under the server limit of 2/s per address.
#[derive(Debug)]
struct Backoff {
    next: Duration,
}

impl Backoff {
    const FIRST: Duration = Duration::from_secs(1);
    const MAX: Duration = Duration::from_secs(10);

    fn new() -> Self {
        Self { next: Self::FIRST }
    }

    fn reset(&mut self) {
        self.next = Self::FIRST;
    }

    fn delay(&mut self) -> Duration {
        let base = self.next;
        self.next = (self.next * 2).min(Self::MAX);
        let mut h = RandomState::new().build_hasher();
        h.write_u128(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        );
        // Factor 0.8 to 1.2, in 1/1000.
        let factor = 800 + h.finish() % 401;
        base * u32::try_from(factor).unwrap_or(1000) / 1000
    }
}

/// Failing call -> 1 warn per error kind + 1 info when it works again.
#[derive(Debug, Default)]
struct ErrorLog {
    last: Option<String>,
}

impl ErrorLog {
    fn failed(&mut self, what: &str, e: &ClientError) {
        let kind = e.kind();
        if self.last.as_deref() == Some(kind.as_str()) {
            tracing::debug!(error = %e, "{what} failed again");
        } else {
            tracing::warn!(error = %e, "{what} failed; retrying");
            self.last = Some(kind);
        }
    }

    fn succeeded(&mut self, what: &str) {
        if self.last.take().is_some() {
            tracing::info!("{what} works again");
        }
    }
}

/// Fetch state forever -> publish each new one.
async fn fetcher(client: Arc<Client>, wait: u64, tx: watch::Sender<Option<Arc<HubState>>>) {
    let mut etag: Option<String> = None;
    let mut backoff = Backoff::new();
    let mut log = ErrorLog::default();
    loop {
        let w = if etag.is_some() { wait } else { 0 };
        match client.get_state(w, etag.as_deref()).await {
            Ok(answer) => {
                log.succeeded("fetching the hub state");
                backoff.reset();
                if let StateAnswer::Changed { state, etag: tag } = answer {
                    tracing::info!(
                        revision = state.revision,
                        networks = state.networks.len(),
                        "hub state received"
                    );
                    etag = Some(tag);
                    tx.send_replace(Some(Arc::new(state)));
                }
            }
            Err(e) => {
                log.failed("fetching the hub state", &e);
                tokio::time::sleep(backoff.delay()).await;
            }
        }
    }
}

/// Apply state to the kernel: each new state + every `resync_interval`.
async fn reconciler(config: Arc<Config>, key: PrivateKey, public_key: String, mut rx: StateRx) {
    let resync = Duration::from_secs(config.resync_interval);
    let mut next = Instant::now() + resync;
    let mut nft_applied: Option<String> = None;
    loop {
        let forced = tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() {
                    return;
                }
                false
            }
            () = tokio::time::sleep_until(next) => true,
        };
        next = Instant::now() + resync;
        let Some(state) = rx.borrow_and_update().clone() else {
            continue;
        };
        reconcile(&config, &key, &public_key, &state, &mut nft_applied, forced).await;
    }
}

/// 1 compare of kernel vs `state` -> needed changes.
async fn reconcile(
    config: &Config,
    key: &PrivateKey,
    public_key: &str,
    state: &HubState,
    nft_applied: &mut Option<String>,
    resync: bool,
) {
    let kernel = match Kernel::connect(Some(key.clone())) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "cannot reach the kernel; trying again later");
            return;
        }
    };
    let observed = match kernel.observe().await {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "reading the kernel state failed; trying again later");
            return;
        }
    };
    let desired = match Desired::from_state(
        state,
        Some(public_key.to_owned()),
        config.table_base,
        config.rule_priority,
    ) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), revision = state.revision, "the hub state cannot be applied; the kernel is left as it is");
            return;
        }
    };
    let actions = plan(&desired, &observed);
    tracing::debug!(
        revision = state.revision,
        resync,
        actions = actions.len(),
        "reconciling"
    );
    for action in &actions {
        match kernel.execute(action).await {
            Ok(()) => tracing::info!("{}", action.done()),
            Err(e) => tracing::warn!(error = %format!("{e:#}"), "{} failed", action.describe()),
        }
    }
    let script = nft::render_script(&nft::interfaces(&desired));
    if resync || nft_applied.as_deref() != Some(script.as_str()) {
        match nft::apply(&config.nft, &script).await {
            Ok(()) => {
                if nft_applied.as_deref() == Some(script.as_str()) {
                    tracing::debug!("firewall table {} applied again", nft::TABLE);
                } else {
                    tracing::info!("firewall table {} replaced", nft::TABLE);
                }
                *nft_applied = Some(script);
            }
            Err(e) => {
                tracing::warn!(error = %e, "applying the firewall failed; trying again at the next resync");
                *nft_applied = None;
            }
        }
    }
}

/// Report public key once, then peer status every `interval` s.
async fn reporter(client: Arc<Client>, public_key: String, interval: u64, rx: StateRx) {
    let mut backoff = Backoff::new();
    let mut log = ErrorLog::default();
    loop {
        match client.put_public_key(&public_key).await {
            Ok(()) => {
                log.succeeded("reporting the public key");
                tracing::info!(public_key = %public_key, "public key reported");
                break;
            }
            Err(e) => {
                log.failed("reporting the public key", &e);
                tokio::time::sleep(backoff.delay()).await;
            }
        }
    }
    let mut log = ErrorLog::default();
    let mut tick = tokio::time::interval(Duration::from_secs(interval));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let Some(state) = rx.borrow().clone() else {
            continue;
        };
        let report = status::collect(&state).await;
        match client.post_status(&report).await {
            Ok(accepted) => {
                log.succeeded("reporting peer status");
                tracing::debug!(
                    peers = report.peers.len(),
                    accepted = accepted.accepted,
                    ignored = accepted.ignored,
                    "peer status reported"
                );
            }
            Err(e) => log.failed("reporting peer status", &e),
        }
    }
}

/// Host IPv4 forwarding off -> warning. Hub never changes it.
fn check_ip_forward() {
    match std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
        Ok(v) if v.trim() == "1" => {}
        Ok(_) => tracing::warn!(
            "net.ipv4.ip_forward is 0: members cannot reach each other through this hub"
        ),
        Err(e) => tracing::warn!(error = %e, "cannot read net.ipv4.ip_forward"),
    }
}

#[allow(clippy::print_stdout, reason = "--dry-run prints the plan")]
fn print_plan(new_key_file: Option<&Path>, actions: &[Action], nft_same: bool) {
    if new_key_file.is_none() && actions.is_empty() && nft_same {
        println!("no changes");
        return;
    }
    if let Some(path) = new_key_file {
        println!("key file {} would be created", path.display());
    }
    for a in actions {
        println!("{}", a.describe());
    }
    if nft_same {
        println!("nft: unchanged");
    } else {
        println!("nft: replace table {}", nft::TABLE);
    }
}

/// `--dry-run`: 1 fetch, read-only kernel look, plan -> stdout.
async fn dry_run(config: &Config, client: &Client) -> anyhow::Result<()> {
    let state = match client.get_state(0, None).await {
        Ok(StateAnswer::Changed { state, .. }) => state,
        Ok(StateAnswer::Unchanged) => anyhow::bail!("the server answered 304 without a tag"),
        Err(e) => anyhow::bail!("fetching the hub state failed: {e}"),
    };
    let key = keyfile::load_existing_key(&config.key_file)?;
    let public_key = key
        .as_deref()
        .map(|k| public_from_private(k))
        .transpose()
        .context("the key file")?;
    drop(key);
    let missing_key = public_key.is_none();
    let desired = Desired::from_state(&state, public_key, config.table_base, config.rule_priority)?;
    let observed = Kernel::connect(None)?.observe().await?;
    let actions = plan(&desired, &observed);
    let rendered = nft::render_table(&nft::interfaces(&desired));
    let nft_same = match nft::list(&config.nft).await {
        Ok(Some(listed)) => nft::same_table(&listed, &rendered),
        Ok(None) => false,
        Err(e) => {
            tracing::warn!(error = %e, "cannot list the firewall table");
            false
        }
    };
    print_plan(
        missing_key.then_some(config.key_file.as_path()),
        &actions,
        nft_same,
    );
    Ok(())
}

/// Wait for SIGTERM or SIGINT.
async fn shutdown_signal() -> anyhow::Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("listening for SIGTERM")?;
    tokio::select! {
        r = tokio::signal::ctrl_c() => r.context("listening for SIGINT")?,
        _ = term.recv() => {}
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let config = Arc::new(Config::from_cli(cli).map_err(anyhow::Error::msg)?);
    let token = keyfile::load_token(&config.token_file)?;
    let client = Arc::new(Client::new(
        config.server.clone(),
        token,
        config.ca_file.as_deref(),
    )?);
    if config.dry_run {
        return dry_run(&config, &client).await;
    }

    let (private, created) = keyfile::load_or_create_key(&config.key_file)?;
    if created {
        tracing::info!(file = %config.key_file.display(), "created the hub's private key");
    }
    let public_key = public_from_private(&private).context("the key file")?;
    let key: PrivateKey = Arc::new(kernel::key_bytes(&private)?);
    drop(private);
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        server = %config.server.display(),
        public_key = %public_key,
        "dhonomos-wg-hub starting"
    );
    check_ip_forward();

    let (tx, rx) = watch::channel(None);
    let mut fetch = tokio::spawn(fetcher(client.clone(), config.wait, tx));
    let mut apply = tokio::spawn(reconciler(
        config.clone(),
        key,
        public_key.clone(),
        rx.clone(),
    ));
    let mut report = tokio::spawn(reporter(client, public_key, config.status_interval, rx));
    let result = tokio::select! {
        r = shutdown_signal() => r,
        r = &mut fetch => Err(anyhow::anyhow!("the fetcher stopped: {r:?}")),
        r = &mut apply => Err(anyhow::anyhow!("the reconciler stopped: {r:?}")),
        r = &mut report => Err(anyhow::anyhow!("the reporter stopped: {r:?}")),
    };
    fetch.abort();
    apply.abort();
    report.abort();
    if result.is_ok() {
        tracing::info!("stopping; the kernel is left as it is");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_ten_seconds_with_jitter() {
        let mut b = Backoff::new();
        for base in [1u64, 2, 4, 8, 10, 10, 10] {
            let d = b.delay();
            let base = Duration::from_secs(base);
            assert!(
                d >= base * 8 / 10 && d <= base * 12 / 10,
                "{d:?} for {base:?}"
            );
        }
        b.reset();
        assert!(b.delay() <= Duration::from_millis(1200));
    }
}
