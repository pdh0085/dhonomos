//! One-account server for tests with a real XMPP client (libstrophe = base of device `xmppc`,
//! or slixmpp). Run by `scripts/xmpp-interop.sh`.
//!
//! ```text
//! cargo run -p dhonomos-xmpp --example interop -- <dir> [port]
//! ```
//!
//! Self-signed cert for `xmpp.test` -> `<dir>/cert.pem`.
//! Account `dev-1` (password `pw`) on `0.0.0.0:<port>` (default 5222).
//! `dev-1` connected -> after 2 s one CR (5 s timeout), outcome printed. Then keep serving.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dhonomos_pki::tls::CertResolver;
use dhonomos_xmpp::{Accounts, Credential, Unavailable, XmppConfig, XmppServer, tls_acceptor};

struct OneAccount;

#[async_trait::async_trait]
impl Accounts for OneAccount {
    async fn credentials(&self, account: &str) -> Result<Vec<Credential>, Unavailable> {
        Ok(if account == "dev-1" {
            vec![Credential {
                password: b"pw".to_vec(),
                pending: false,
            }]
        } else {
            Vec::new()
        })
    }

    async fn accepted(&self, _account: &str, _credential: &Credential) {}

    async fn connected(&self, account: &str, _at: SystemTime) {
        eprintln!("connected: {account}");
    }

    async fn disconnected(&self, account: &str, _at: SystemTime) {
        eprintln!("disconnected: {account}");
    }
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("usage: interop <dir> [port]");
    let port = args.next().map_or(5222, |p| p.parse().unwrap());
    let cert = rcgen::generate_simple_self_signed(vec!["xmpp.test".to_owned()]).unwrap();
    std::fs::write(format!("{dir}/cert.pem"), cert.cert.pem()).unwrap();
    let resolver =
        CertResolver::from_pem(&cert.cert.pem(), &cert.signing_key.serialize_pem()).unwrap();
    let server = XmppServer::new(
        XmppConfig::new("xmpp.test"),
        Arc::new(OneAccount),
        tls_acceptor(resolver).unwrap(),
    );
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap();
    eprintln!("listening on {}", listener.local_addr().unwrap());
    let waker = server.clone();
    tokio::spawn(async move {
        while !waker.is_connected("dev-1") {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        let outcome = waker
            .send_connection_request("dev-1", "cr-user", "cr-pass", Duration::from_secs(5))
            .await;
        eprintln!("connection request: {outcome:?}");
    });
    server
        .serve(listener, std::future::pending())
        .await
        .unwrap();
}
