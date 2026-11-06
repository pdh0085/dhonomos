//! TLS for the ACS listener (CW-02): TLS 1.2 + 1.3, rustls.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use dhonomos_pki::tls::CertResolver;
use rustls::ServerConfig;
use rustls::server::ResolvesServerCert;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

/// Error loading TLS material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// PEM file read or parse failed.
    #[error("{path}: {reason}")]
    Pem {
        /// File path.
        path: String,
        /// Failure reason.
        reason: String,
    },
    /// Cert + key -> no valid server config.
    #[error("invalid certificate/key: {0}")]
    Config(#[from] rustls::Error),
}

/// Acceptor from PEM cert chain + PEM private key.
///
/// `reload_interval` -> poll files at that interval; renewed cert used for new connections,
/// no restart (see [`dhonomos_pki::tls::CertResolver::watch`]). Needs a tokio runtime.
pub fn acceptor_from_pem(
    cert_chain: &Path,
    key: &Path,
    reload_interval: Option<Duration>,
) -> Result<TlsAcceptor, TlsError> {
    let resolver = CertResolver::from_files(cert_chain, key).map_err(|e| TlsError::Pem {
        path: e.path,
        reason: e.reason,
    })?;
    if let Some(interval) = reload_interval {
        resolver.watch("acs", interval);
    }
    acceptor_with_resolver(resolver)
}

/// Acceptor, server cert from `resolver` per connection.
pub fn acceptor_with_resolver(
    resolver: Arc<dyn ResolvesServerCert>,
) -> Result<TlsAcceptor, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    // CWMP is HTTP/1.1.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Acceptor from DER material.
pub fn acceptor(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<TlsAcceptor, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    // CWMP is HTTP/1.1.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}
