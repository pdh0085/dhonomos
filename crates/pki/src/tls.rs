//! TLS server certs: follow their PEM files, or re-issued before expiry.
//!
//! Public certs renewed every 90 days -> no restart per renewal.
//! [`CertResolver`] = cert a listener presents.
//! [`CertResolver::watch`]: poll files -> renewed cert for new connections.
//! Own cert (from USP CA) has no files: [`CertResolver::renew`] -> new one close to expiry.
//! Open connections keep their cert.

use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, SystemTime};

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use time::OffsetDateTime;
use tracing::{info, warn};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer as _, X509Certificate};

/// Default poll interval of [`CertResolver::watch`].
pub const DEFAULT_RELOAD_INTERVAL: Duration = Duration::from_secs(60);

/// Own cert (issued by Dhonomos) replaced this long before expiry (7 days).
pub const RENEW_BEFORE_EXPIRY: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Default expiry check interval of [`CertResolver::renew`].
///
/// Each check reads wall clock -> clock change or host suspend noticed within this time.
pub const DEFAULT_RENEW_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// When + how often [`CertResolver::renew`] replaces a cert.
#[derive(Debug, Clone, Copy)]
pub struct RenewPolicy {
    /// Time between 2 expiry checks.
    pub interval: Duration,
    /// Expiry within this time -> replace.
    pub before_expiry: Duration,
}

impl Default for RenewPolicy {
    fn default() -> Self {
        Self {
            interval: DEFAULT_RENEW_INTERVAL,
            before_expiry: RENEW_BEFORE_EXPIRY,
        }
    }
}

/// Cert or key unreadable, or not a usable pair.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[error("{path}: {reason}")]
pub struct TlsLoadError {
    /// File, or `certificate PEM` / `private key PEM` for PEM text.
    pub path: String,
    pub reason: String,
}

fn load_err(path: &str, reason: impl std::fmt::Display) -> TlsLoadError {
    TlsLoadError {
        path: path.to_owned(),
        reason: reason.to_string(),
    }
}

/// Parse PEM cert chain + PEM key; check key = key of the first cert.
/// `cert_name`, `key_name`: error labels only.
fn parse(
    cert_pem: &[u8],
    cert_name: &str,
    key_pem: &[u8],
    key_name: &str,
) -> Result<CertifiedKey, TlsLoadError> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| load_err(cert_name, e))?;
    if certs.is_empty() {
        return Err(load_err(cert_name, "no certificates found"));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| load_err(key_name, e))?;
    let provider = rustls::crypto::ring::default_provider();
    CertifiedKey::from_der(certs, key, &provider).map_err(|e| match e {
        rustls::Error::InconsistentKeys(_) => {
            load_err(key_name, "the private key does not match the certificate")
        }
        e => load_err(key_name, e),
    })
}

fn read(path: &Path) -> Result<Vec<u8>, TlsLoadError> {
    std::fs::read(path).map_err(|e| load_err(&path.display().to_string(), e))
}

fn load_files(cert: &Path, key: &Path) -> Result<CertifiedKey, TlsLoadError> {
    let (cert_pem, key_pem) = (read(cert)?, read(key)?);
    parse(
        &cert_pem,
        &cert.display().to_string(),
        &key_pem,
        &key.display().to_string(),
    )
}

/// (mtime, size) of a file; `None` -> cannot stat.
type FileStamp = Option<(SystemTime, u64)>;

fn file_stamp(path: &Path) -> FileStamp {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    cert: FileStamp,
    key: FileStamp,
}

#[derive(Debug)]
struct Source {
    cert: PathBuf,
    key: PathBuf,
    /// File stamps when the cert in use was read.
    loaded: Stamp,
}

fn stamp_of(cert: &Path, key: &Path) -> Stamp {
    Stamp {
        cert: file_stamp(cert),
        key: file_stamp(key),
    }
}

/// Expiry of the first cert of the chain.
fn expiry(key: &CertifiedKey) -> Option<OffsetDateTime> {
    let der = key.cert.first()?;
    let (_, cert) = X509Certificate::from_der(der.as_ref()).ok()?;
    Some(cert.validity().not_after.to_datetime())
}

/// SAN DNS name `pattern` matches `host`: equal (case-insensitive), or wildcard
/// (`*.example.net`) = exactly 1 label in its place.
fn dns_name_matches(pattern: &str, host: &str) -> bool {
    let (pattern, host) = (pattern.to_ascii_lowercase(), host.to_ascii_lowercase());
    match pattern.strip_prefix("*.") {
        Some(rest) => host
            .split_once('.')
            .is_some_and(|(label, tail)| !label.is_empty() && tail == rest),
        None => pattern == host,
    }
}

/// First cert of the chain has `host` in its SAN DNS names.
/// CN does not count: clients ignore it.
fn names_host(key: &CertifiedKey, host: &str) -> bool {
    let Some(der) = key.cert.first() else {
        return false;
    };
    let Ok((_, cert)) = X509Certificate::from_der(der.as_ref()) else {
        return false;
    };
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return false;
    };
    san.value.general_names.iter().any(|n| match n {
        GeneralName::DNSName(name) => dns_name_matches(name, host),
        _ => false,
    })
}

/// Expiry date of the first cert of the chain, for the log.
fn not_after(key: &CertifiedKey) -> Option<String> {
    expiry(key).map(|t| t.date().to_string())
}

fn count_reload(listener: &'static str, result: &'static str) {
    metrics::counter!("dhonomos_tls_reload_total", "listener" => listener, "result" => result)
        .increment(1);
}

/// Cert a TLS listener presents, for `ServerConfig::with_cert_resolver`.
/// Same cert for every name.
#[derive(Debug)]
pub struct CertResolver {
    current: RwLock<Arc<CertifiedKey>>,
    /// Files to follow; `None` -> fixed PEM text.
    source: Option<Source>,
}

impl CertResolver {
    /// Resolver for PEM text; never changes.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Arc<Self>, TlsLoadError> {
        let key = parse(
            cert_pem.as_bytes(),
            "certificate PEM",
            key_pem.as_bytes(),
            "private key PEM",
        )?;
        Ok(Arc::new(Self {
            current: RwLock::new(Arc::new(key)),
            source: None,
        }))
    }

    /// Resolver for PEM cert chain + key files. [`CertResolver::watch`] -> follow them.
    pub fn from_files(cert: &Path, key: &Path) -> Result<Arc<Self>, TlsLoadError> {
        // Stamp before read -> file replaced in between is picked up at 1st poll.
        let loaded = stamp_of(cert, key);
        let certified = load_files(cert, key)?;
        Ok(Arc::new(Self {
            current: RwLock::new(Arc::new(certified)),
            source: Some(Source {
                cert: cert.to_owned(),
                key: key.to_owned(),
                loaded,
            }),
        }))
    }

    fn swap(&self, key: CertifiedKey) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(key);
    }

    fn current(&self) -> Arc<CertifiedKey> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Expiry of the cert now presented; `None` -> unreadable.
    pub fn expires(&self) -> Option<OffsetDateTime> {
        expiry(&self.current())
    }

    /// Cert now presented has DNS name `host` in its SAN (wildcard = 1 label).
    /// Devices check the name they connect to -> listener name not covered = unusable.
    pub fn covers(&self, host: &str) -> bool {
        names_host(&self.current(), host)
    }

    /// Replace the cert for new connections with PEM chain + key (e.g. freshly issued).
    /// Open connections untouched. PEM parse error or key mismatch -> no change.
    pub fn replace_pem(&self, cert_pem: &str, key_pem: &str) -> Result<(), TlsLoadError> {
        let key = parse(
            cert_pem.as_bytes(),
            "certificate PEM",
            key_pem.as_bytes(),
            "private key PEM",
        )?;
        self.swap(key);
        Ok(())
    }

    /// Poll cert + key files every `interval`; either changed -> read both again.
    /// Pair parses + key matches -> replaces current cert for new connections.
    /// Else (partial write, key of another cert, parse error) -> current cert kept,
    /// logged once per file state, retried at every poll.
    ///
    /// `listener` labels the log + `dhonomos_tls_reload_total{listener, result}`.
    /// Task ends when no listener uses the resolver any more.
    /// No-op for a [`CertResolver::from_pem`] resolver. Must run inside a tokio runtime.
    pub fn watch(
        self: &Arc<Self>,
        listener: &'static str,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        if self.source.is_none() {
            return tokio::spawn(async {});
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick =
                tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // `applied`: file state of the cert in use. `reported`: last state with logged failure.
            let mut applied = None::<Stamp>;
            let mut reported = None::<Stamp>;
            loop {
                tick.tick().await;
                let Some(this) = weak.upgrade() else { return };
                let Some(source) = &this.source else { return };
                let known = applied.clone().unwrap_or_else(|| source.loaded.clone());
                let (cert, key) = (source.cert.clone(), source.key.clone());
                let polled = tokio::task::spawn_blocking(move || {
                    let seen = stamp_of(&cert, &key);
                    (seen != known).then(|| (load_files(&cert, &key), seen))
                })
                .await;
                let Ok(Some((loaded, seen))) = polled else {
                    continue;
                };
                match loaded {
                    Ok(certified) => {
                        let expires = not_after(&certified);
                        this.swap(certified);
                        applied = Some(seen);
                        reported = None;
                        count_reload(listener, "ok");
                        info!(listener, cert = %source.cert.display(),
                            not_after = expires.as_deref().unwrap_or("unknown"),
                            "TLS certificate reloaded");
                    }
                    Err(e) => {
                        count_reload(listener, "error");
                        if reported.as_ref() != Some(&seen) {
                            warn!(listener, cert = %source.cert.display(), key = %source.key.display(),
                                error = %e, "TLS certificate reload failed; keeping the current certificate");
                            reported = Some(seen);
                        }
                    }
                }
            }
        })
    }

    /// Replace cert with a newly issued one when it expires within `policy.before_expiry`.
    /// For a cert without files to follow (issued by the USP CA).
    /// Check at start, then every `policy.interval`.
    /// `issue` -> new PEM chain + key, same names as current cert; runs on a blocking thread.
    ///
    /// `issue` fails or result unusable -> current cert kept, `warn` logged, next check retries.
    /// New connections get the new cert, open ones keep the old.
    ///
    /// `listener` labels the log + `dhonomos_tls_reload_total{listener, result}`.
    /// Task ends when no listener uses the resolver any more. Must run inside a tokio runtime.
    pub fn renew<E>(
        self: &Arc<Self>,
        listener: &'static str,
        policy: RenewPolicy,
        issue: impl Fn() -> Result<(String, String), E> + Send + Sync + 'static,
    ) -> tokio::task::JoinHandle<()>
    where
        E: std::fmt::Display + Send + 'static,
    {
        let weak = Arc::downgrade(self);
        let issue = Arc::new(issue);
        let window = i64::try_from(policy.before_expiry.as_secs()).unwrap_or(i64::MAX);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(policy.interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let Some(this) = weak.upgrade() else { return };
                // Expiry unreadable -> due.
                let due = this.expires().is_none_or(|t| {
                    t.unix_timestamp() - OffsetDateTime::now_utc().unix_timestamp() <= window
                });
                if !due {
                    continue;
                }
                let issue = Arc::clone(&issue);
                let renewed = match tokio::task::spawn_blocking(move || issue()).await {
                    Ok(Ok((cert_pem, key_pem))) => this
                        .replace_pem(&cert_pem, &key_pem)
                        .map_err(|e| e.to_string()),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(e) => Err(format!("issuing the certificate failed: {e}")),
                };
                match renewed {
                    Ok(()) => {
                        count_reload(listener, "ok");
                        let expires = not_after(&this.current());
                        info!(
                            listener,
                            not_after = expires.as_deref().unwrap_or("unknown"),
                            "TLS certificate renewed"
                        );
                    }
                    Err(e) => {
                        count_reload(listener, "error");
                        warn!(listener, error = %e,
                            "TLS certificate renewal failed; keeping the current certificate");
                    }
                }
            }
        })
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::time::Duration;

    use rustls_pki_types::ServerName;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    struct Pair {
        cert_pem: String,
        key_pem: String,
        der: CertificateDer<'static>,
    }

    fn pair(name: &str) -> Pair {
        let ck = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
        Pair {
            cert_pem: ck.cert.pem(),
            key_pem: ck.signing_key.serialize_pem(),
            der: CertificateDer::from(ck.cert.der().to_vec()),
        }
    }

    fn write(dir: &Path, p: &Pair) {
        std::fs::write(dir.join("cert.pem"), &p.cert_pem).unwrap();
        std::fs::write(dir.join("key.pem"), &p.key_pem).unwrap();
    }

    /// TLS server on a loopback port, presents the cert of `resolver`.
    /// Returned fn: new handshake -> cert the server sent.
    async fn serve(
        resolver: Arc<CertResolver>,
        trusted: &[&Pair],
    ) -> impl AsyncFn() -> CertificateDer<'static> + use<> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(tcp).await;
                });
            }
        });
        let mut roots = rustls::RootCertStore::empty();
        for p in trusted {
            roots.add(p.der.clone()).unwrap();
        }
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        async move || {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let tls = connector
                .connect(ServerName::try_from("localhost").unwrap(), tcp)
                .await
                .unwrap();
            tls.get_ref().1.peer_certificates().unwrap()[0].clone()
        }
    }

    /// Coarse file times (few ms) -> gap so 2nd write of a same-size file shows in mtime.
    async fn later() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    async fn until(mut done: impl AsyncFnMut() -> bool) {
        for _ in 0..200 {
            if done().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("condition not reached");
    }

    #[tokio::test]
    async fn renewed_certificate_is_served_to_new_connections() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (pair("localhost"), pair("localhost"));
        write(dir.path(), &a);
        let resolver =
            CertResolver::from_files(&dir.path().join("cert.pem"), &dir.path().join("key.pem"))
                .unwrap();
        let _watcher = resolver.watch("test", Duration::from_millis(50));
        let handshake = serve(resolver, &[&a, &b]).await;
        assert_eq!(handshake().await, a.der);

        // Connection made before renewal keeps its cert.
        let old = handshake().await;
        later().await;
        write(dir.path(), &b);
        until(async || handshake().await == b.der).await;
        assert_eq!(old, a.der);
    }

    #[tokio::test]
    async fn unusable_files_keep_the_current_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b, c) = (pair("localhost"), pair("localhost"), pair("localhost"));
        write(dir.path(), &a);
        let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
        let resolver = CertResolver::from_files(&cert, &key).unwrap();
        let _watcher = resolver.watch("test", Duration::from_millis(50));
        let handshake = serve(resolver, &[&a, &b, &c]).await;

        // Garbage, half-written cert, key of another pair.
        let tick = Duration::from_millis(300);
        std::fs::write(&cert, "not a certificate").unwrap();
        tokio::time::sleep(tick).await;
        assert_eq!(handshake().await, a.der, "garbage certificate");
        std::fs::write(&cert, &b.cert_pem[..b.cert_pem.len() / 2]).unwrap();
        tokio::time::sleep(tick).await;
        assert_eq!(handshake().await, a.der, "truncated certificate");
        std::fs::write(&cert, &b.cert_pem).unwrap();
        std::fs::write(&key, &c.key_pem).unwrap();
        tokio::time::sleep(tick).await;
        assert_eq!(handshake().await, a.der, "mismatched key");

        // Pair whole again -> picked up.
        std::fs::write(&key, &b.key_pem).unwrap();
        until(async || handshake().await == b.der).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_failure_is_retried_without_the_files_changing() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (pair("localhost"), pair("localhost"));
        write(dir.path(), &a);
        let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
        let resolver = CertResolver::from_files(&cert, &key).unwrap();
        let _watcher = resolver.watch("test", Duration::from_millis(50));
        let handshake = serve(resolver, &[&a, &b]).await;

        // New key not readable yet (permissions fixed after copy).
        // mtimes stay put from here, but every poll retries.
        use std::os::unix::fs::PermissionsExt as _;
        later().await;
        let staged = dir.path().join("key.staged");
        std::fs::write(&staged, &b.key_pem).unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::rename(&staged, &key).unwrap();
        if std::fs::read(&key).is_ok() {
            // Root: permissions do not apply -> nothing to show.
            return;
        }
        std::fs::write(&cert, &b.cert_pem).unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(handshake().await, a.der);
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        until(async || handshake().await == b.der).await;
    }

    #[test]
    fn the_certificate_names_are_checked_against_a_host() {
        let ck = rcgen::generate_simple_self_signed(vec![
            "acs.example.net".to_owned(),
            "*.wild.example.net".to_owned(),
        ])
        .unwrap();
        let resolver =
            CertResolver::from_pem(&ck.cert.pem(), &ck.signing_key.serialize_pem()).unwrap();
        for covered in [
            "acs.example.net",
            "ACS.Example.NET",
            "a.wild.example.net",
            "xyz.WILD.example.net",
        ] {
            assert!(resolver.covers(covered), "{covered}");
        }
        for not_covered in [
            "example.net",
            "other.example.net",
            "wild.example.net",
            "a.b.wild.example.net",
            ".wild.example.net",
            "acs.example.net.evil.test",
            "",
        ] {
            assert!(!resolver.covers(not_covered), "{not_covered}");
        }
    }

    #[test]
    fn mismatched_or_empty_material_is_refused_at_start() {
        let (a, b) = (pair("localhost"), pair("localhost"));
        assert!(CertResolver::from_pem(&a.cert_pem, &a.key_pem).is_ok());
        let e = CertResolver::from_pem(&a.cert_pem, &b.key_pem).unwrap_err();
        assert!(e.to_string().contains("does not match"), "{e}");
        let e = CertResolver::from_pem("", &a.key_pem).unwrap_err();
        assert!(e.to_string().contains("no certificates"), "{e}");
        assert!(CertResolver::from_pem(&a.cert_pem, "").is_err());
        let dir = tempfile::tempdir().unwrap();
        let e = CertResolver::from_files(&dir.path().join("x.pem"), &dir.path().join("y.pem"))
            .unwrap_err();
        assert!(e.to_string().contains("x.pem"), "{e}");
    }

    /// CA for `localhost` server certs + what a client needs to trust it.
    struct TestCa {
        ca: Arc<crate::Ca>,
        root: Pair,
    }

    impl TestCa {
        fn new() -> Self {
            let ca = crate::Ca::generate("Test CA").unwrap();
            let der = CertificateDer::from_pem_slice(ca.cert_pem().as_bytes()).unwrap();
            let root = Pair {
                cert_pem: ca.cert_pem().to_owned(),
                key_pem: String::new(),
                der,
            };
            Self {
                ca: Arc::new(ca),
                root,
            }
        }

        /// Cert chain + key, valid `days`.
        fn issue(&self, days: u32) -> Result<(String, String), crate::PkiError> {
            self.ca.issue_chain(&crate::Profile {
                endpoint_id: "urn:test:server".to_owned(),
                dns_names: vec!["localhost".to_owned()],
                ip_addresses: Vec::new(),
                server: true,
                days,
            })
        }
    }

    fn leaf(chain_pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(chain_pem.as_bytes()).unwrap()
    }

    fn not_after_secs(der: &CertificateDer<'_>) -> i64 {
        let (_, cert) = X509Certificate::from_der(der.as_ref()).unwrap();
        cert.validity().not_after.timestamp()
    }

    fn policy(before_expiry_days: u64) -> RenewPolicy {
        RenewPolicy {
            interval: Duration::from_millis(30),
            before_expiry: Duration::from_secs(before_expiry_days * 24 * 60 * 60),
        }
    }

    #[tokio::test]
    async fn certificate_close_to_expiry_is_replaced_for_new_connections() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let ca = Arc::new(TestCa::new());
        let (chain, key) = ca.issue(1).unwrap();
        let old = leaf(&chain);
        let resolver = CertResolver::from_pem(&chain, &key).unwrap();
        assert_eq!(
            resolver.expires().unwrap().unix_timestamp(),
            not_after_secs(&old)
        );

        // New cert = 30 days > 7 day window -> 1 renewal.
        let issued = Arc::new(AtomicUsize::new(0));
        let _renewer = resolver.renew("test", policy(7), {
            let (ca, issued) = (ca.clone(), issued.clone());
            move || {
                issued.fetch_add(1, Ordering::SeqCst);
                ca.issue(30)
            }
        });
        let handshake = serve(resolver.clone(), &[&ca.root]).await;
        until(async || handshake().await != old).await;
        let new = handshake().await;
        assert!(
            not_after_secs(&new) > not_after_secs(&old) + 20 * 24 * 60 * 60,
            "the new certificate must expire later"
        );
        // Outside the window -> no 2nd renewal.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(issued.load(Ordering::SeqCst), 1);
        assert_eq!(handshake().await, new);
        assert_eq!(
            resolver.expires().unwrap().unix_timestamp(),
            not_after_secs(&new)
        );
    }

    #[tokio::test]
    async fn certificate_outside_the_window_is_left_alone() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let ca = Arc::new(TestCa::new());
        let (chain, key) = ca.issue(30).unwrap();
        let resolver = CertResolver::from_pem(&chain, &key).unwrap();
        let issued = Arc::new(AtomicUsize::new(0));
        let _renewer = resolver.renew("test", policy(7), {
            let (ca, issued) = (ca.clone(), issued.clone());
            move || {
                issued.fetch_add(1, Ordering::SeqCst);
                ca.issue(30)
            }
        });
        let handshake = serve(resolver, &[&ca.root]).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(issued.load(Ordering::SeqCst), 0);
        assert_eq!(handshake().await, leaf(&chain));
    }

    #[tokio::test]
    async fn a_failing_issuer_keeps_the_certificate_and_is_tried_again() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let ca = Arc::new(TestCa::new());
        let (chain, key) = ca.issue(1).unwrap();
        let old = leaf(&chain);
        let resolver = CertResolver::from_pem(&chain, &key).unwrap();
        let (unavailable, attempts) = (
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicUsize::new(0)),
        );
        let _renewer = resolver.renew("test", policy(7), {
            let (ca, unavailable, attempts) = (ca.clone(), unavailable.clone(), attempts.clone());
            move || {
                attempts.fetch_add(1, Ordering::SeqCst);
                if unavailable.load(Ordering::SeqCst) {
                    return Err("the CA is unavailable".to_owned());
                }
                ca.issue(30).map_err(|e| e.to_string())
            }
        });
        let handshake = serve(resolver, &[&ca.root]).await;
        // Several failed attempts -> old cert still served.
        until(async || attempts.load(Ordering::SeqCst) >= 3).await;
        assert_eq!(handshake().await, old);
        // CA back -> next check renews.
        unavailable.store(false, Ordering::SeqCst);
        until(async || handshake().await != old).await;
    }

    #[tokio::test]
    async fn unusable_issued_material_is_not_swapped_in() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let ca = Arc::new(TestCa::new());
        let (chain, key) = ca.issue(1).unwrap();
        let old = leaf(&chain);
        let resolver = CertResolver::from_pem(&chain, &key).unwrap();
        // 1st: cert + key of another cert. Then garbage. Then proper pair (once test allows).
        let (attempts, proper) = (
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicBool::new(false)),
        );
        let _renewer = resolver.renew("test", policy(7), {
            let (ca, attempts, proper) = (ca.clone(), attempts.clone(), proper.clone());
            move || match attempts.fetch_add(1, Ordering::SeqCst) {
                0 => Ok((ca.issue(30).unwrap().0, ca.issue(30).unwrap().1)),
                _ if !proper.load(Ordering::SeqCst) => {
                    Ok(("not PEM".to_owned(), "nor this".to_owned()))
                }
                _ => ca.issue(30).map_err(|e| e.to_string()),
            }
        });
        let handshake = serve(resolver, &[&ca.root]).await;
        until(async || attempts.load(Ordering::SeqCst) >= 3).await;
        assert_eq!(handshake().await, old);
        proper.store(true, Ordering::SeqCst);
        until(async || handshake().await != old).await;
    }

    #[tokio::test]
    async fn renewer_ends_with_the_resolver() {
        let ca = TestCa::new();
        let (chain, key) = ca.issue(30).unwrap();
        let resolver = CertResolver::from_pem(&chain, &key).unwrap();
        let renewer = resolver.renew("test", policy(7), || {
            Err::<(String, String), _>("never called".to_owned())
        });
        drop(resolver);
        tokio::time::timeout(Duration::from_secs(2), renewer)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn default_policy_renews_seven_days_ahead() {
        let p = RenewPolicy::default();
        assert_eq!(p.before_expiry, Duration::from_secs(7 * 24 * 3600));
        assert_eq!(p.interval, Duration::from_secs(3600));
    }

    #[test]
    fn expiry_date_is_found() {
        let a = pair("localhost");
        let key = parse(a.cert_pem.as_bytes(), "c", a.key_pem.as_bytes(), "k").unwrap();
        let date = not_after(&key).unwrap();
        // rcgen default validity ends in year 4096.
        assert!(date.starts_with("4096-"), "{date}");
    }
}
