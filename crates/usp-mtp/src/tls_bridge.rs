//! TLS to the MQTT broker (ADR-081).
//! rumqttc TLS feature -> vulnerable `rustls-webpki` (ADR-021) -> not used.
//! rumqttc -> Unix socket -> task in this process -> broker over TLS (rustls 0.23, tokio-rustls).
//! Socket dir: only this user can open. TLS with client cert = auth as the Controller.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rustls_pki_types::ServerName;
use tokio::net::{TcpStream, UnixListener};
use tracing::{debug, warn};

use crate::MtpError;

/// TLS settings for broker connections.
#[derive(Debug, Clone)]
pub struct MqttTls {
    /// Trusted CAs + client cert for mutual TLS.
    pub config: Arc<rustls::ClientConfig>,
    /// Name required in the broker cert (default: broker host).
    pub server_name: Option<String>,
    /// Private dir for bridge sockets (mode 0700).
    pub socket_dir: PathBuf,
}

/// Broker client config: system store + `extra_ca_pem`, client cert + key (PEM) for mutual TLS.
pub fn client_config(
    extra_ca_pem: Option<&str>,
    client_cert: Option<(&str, &str)>,
) -> Result<Arc<rustls::ClientConfig>, MtpError> {
    use rustls_pki_types::pem::PemObject as _;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    let bad = |e: &dyn std::fmt::Display| MtpError::Tls(e.to_string());
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if let Some(pem) = extra_ca_pem {
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots.add(cert.map_err(|e| bad(&e))?).map_err(|e| bad(&e))?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| bad(&e))?
        .with_root_certificates(roots);
    Ok(Arc::new(match client_cert {
        Some((cert, key)) => {
            let chain = CertificateDer::pem_slice_iter(cert.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| bad(&e))?;
            let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).map_err(|e| bad(&e))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| bad(&e))?
        }
        None => builder.with_no_client_auth(),
    }))
}

impl MqttTls {
    /// Socket dir can be created? Call at startup -> fail early.
    pub fn check(&self) -> Result<(), MtpError> {
        private_dir(&self.socket_dir)
            .map_err(|e| MtpError::Tls(format!("{}: {e}", self.socket_dir.display())))
    }
}

static NEXT: AtomicU64 = AtomicU64::new(0);

fn private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

/// Start TLS bridge to `host:port` -> Unix socket path for rumqttc (`Transport::Unix`).
/// Runs until process end.
pub(crate) fn start(tls: &MqttTls, host: &str, port: u16) -> Result<PathBuf, MtpError> {
    let io = |e: std::io::Error| MtpError::Tls(format!("bridge socket: {e}"));
    private_dir(&tls.socket_dir).map_err(io)?;
    let path = tls.socket_dir.join(format!(
        "mqtt-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).map_err(io)?;
    let name = tls.server_name.clone().unwrap_or_else(|| host.to_owned());
    let server_name = ServerName::try_from(name.clone())
        .map_err(|e| MtpError::Tls(format!("server name {name:?}: {e}")))?;
    let connector = tokio_rustls::TlsConnector::from(tls.config.clone());
    let host = host.to_owned();
    tokio::spawn(async move {
        loop {
            let Ok((mut local, _)) = listener.accept().await else {
                continue;
            };
            let (connector, server_name, host) =
                (connector.clone(), server_name.clone(), host.clone());
            tokio::spawn(async move {
                let tcp = match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    TcpStream::connect((host.as_str(), port)),
                )
                .await
                {
                    Ok(Ok(t)) => t,
                    Ok(Err(e)) => return debug!(broker = %host, error = %e, "broker unreachable"),
                    Err(_) => return debug!(broker = %host, "connecting to the broker timed out"),
                };
                let _ = tcp.set_nodelay(true);
                let mut remote = match connector.connect(server_name, tcp).await {
                    Ok(s) => s,
                    Err(e) => {
                        metrics::counter!("dhonomos_usp_mqtt_tls_failures_total").increment(1);
                        return warn!(broker = %host, error = %e, "TLS with the broker failed");
                    }
                };
                let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
            });
        }
    });
    Ok(path)
}

/// rumqttc options for `client_id` at `host:port`. `tls` set -> via TLS bridge.
pub(crate) fn mqtt_options(
    client_id: String,
    host: &str,
    port: u16,
    tls: Option<&MqttTls>,
) -> Result<rumqttc::v5::MqttOptions, MtpError> {
    Ok(match tls {
        None => rumqttc::v5::MqttOptions::new(client_id, host, port),
        Some(tls) => {
            let path = start(tls, host, port).inspect_err(|e| {
                tracing::error!(error = %e, "MQTT TLS bridge could not start; not connecting");
            })?;
            let mut opts =
                rumqttc::v5::MqttOptions::new(client_id, path.to_string_lossy().into_owned(), 0);
            opts.set_transport(rumqttc::Transport::Unix);
            opts
        }
    })
}
