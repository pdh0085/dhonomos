//! HTTPS for the device-facing file server: [`axum::serve::Listener`] that terminates TLS.
//! -> `axum::serve` drives plain + TLS listeners the same way (graceful shutdown included).

use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::warn;

/// Max time of a client TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Max finished handshakes not yet picked up by the server.
const BACKLOG: usize = 64;

/// TCP accept -> TLS handshake -> `axum::serve`.
/// One task per handshake -> client stalled in it blocks nobody else.
#[derive(Debug)]
pub struct TlsListener {
    local: SocketAddr,
    ready: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    accepting: tokio::task::JoinHandle<()>,
}

impl TlsListener {
    /// Start accepting on `listener`. Needs a tokio runtime.
    pub fn new(listener: TcpListener, acceptor: TlsAcceptor) -> std::io::Result<Self> {
        let local = listener.local_addr()?;
        let (tx, ready) = mpsc::channel(BACKLOG);
        let accepting = tokio::spawn(async move {
            loop {
                let (tcp, remote) = match listener.accept().await {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                        Ok(Ok(stream)) => {
                            let _ = tx.send((stream, remote)).await;
                        }
                        Ok(Err(e)) => {
                            metrics::counter!("dhonomos_file_server_tls_handshake_failures_total")
                                .increment(1);
                            dhonomos_common::connection_refused!(
                                "files",
                                "tls_handshake",
                                remote,
                                error = %e
                            );
                        }
                        Err(_) => dhonomos_common::connection_refused!(
                            "files",
                            "tls_handshake_timeout",
                            remote
                        ),
                    }
                });
            }
        });
        Ok(Self {
            local,
            ready,
            accepting,
        })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

/// Client address on the file server, plain TCP or [`TlsListener`].
///
/// `axum::serve` has connect info for `TcpListener` only -> file server uses this type
/// (`app.into_make_service_with_connect_info::<PeerAddr>()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddr(pub SocketAddr);

impl Connected<IncomingStream<'_, TcpListener>> for PeerAddr {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

impl Connected<IncomingStream<'_, TlsListener>> for PeerAddr {
    fn connect_info(stream: IncomingStream<'_, TlsListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(conn) => conn,
            // Accept task ends only by abort in `drop` -> not while `self` lives.
            // Wait forever, only to fit the type.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}
