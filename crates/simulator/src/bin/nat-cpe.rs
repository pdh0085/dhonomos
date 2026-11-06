//! One CPE behind NAT (CW-08).
//!
//! Boot -> ACS zero-touch sets STUN + CR credentials.
//! STUN binding kept open from the UDP CR port.
//! Each signed UDP CR -> one session. Exit after `--expect` of them.
//!
//! `nat-cpe --acs 172.31.10.2:7547 --serial NAT0001 --expect 2`
#![allow(clippy::print_stdout)]

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use clap::Parser;
use dhonomos_simulator::nat::{UdpConnectionRequest, binding_request, mapped_address};
use dhonomos_simulator::{CpeProfile, VirtualCpe};
use tokio::net::UdpSocket;

#[derive(Debug, Parser)]
struct Args {
    /// ACS address.
    #[arg(long)]
    acs: SocketAddr,
    /// Serial number.
    #[arg(long, default_value = "NAT0001")]
    serial: String,
    /// UDP CR port.
    #[arg(long, default_value_t = 7547)]
    udp_port: u16,
    /// Seconds between STUN Binding Requests -> NAT mapping stays open.
    #[arg(long, default_value_t = 10)]
    stun_interval: u64,
    /// UDP CRs to handle, then exit.
    #[arg(long, default_value_t = 1)]
    expect: usize,
    /// Timeout in seconds.
    #[arg(long, default_value_t = 300)]
    timeout: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let start = Instant::now();
    // Local IP -> HTTP ConnectionRequestURL of the CPE: private, not reachable.
    let probe = std::net::UdpSocket::bind("0.0.0.0:0")?;
    probe.connect(args.acs)?;
    let local_ip = probe.local_addr()?.ip();
    let cpe = VirtualCpe::new(
        args.serial.clone(),
        format!("http://{local_ip}:7547/"),
        CpeProfile::default(),
    );

    // Zero-touch: ACS reads the device -> sets STUN + CR credentials.
    let mut events = vec!["0 BOOTSTRAP", "1 BOOT"];
    for _ in 0..5 {
        cpe.session(args.acs, &events)
            .await
            .context("boot session")?;
        events = vec!["2 PERIODIC"];
        if cpe.management("STUNServerAddress").is_some() {
            break;
        }
    }
    let stun_host = cpe
        .management("STUNServerAddress")
        .context("the ACS did not provision STUN (start dhonomos with --stun-public-address)")?;
    let stun_port: u16 = cpe
        .management("STUNServerPort")
        .and_then(|p| p.parse().ok())
        .unwrap_or(3478);
    let stun: SocketAddr = tokio::net::lookup_host((stun_host.as_str(), stun_port))
        .await?
        .next()
        .context("STUN server address")?;
    let stun_user = cpe.management("STUNUsername").unwrap_or_default();
    let stun_pass = cpe.management("STUNPassword").unwrap_or_default();
    let cr_user = cpe
        .management("ConnectionRequestUsername")
        .unwrap_or_default();
    let cr_pass = cpe
        .management("ConnectionRequestPassword")
        .unwrap_or_default();
    println!(
        "provisioned: STUN {stun} as {stun_user}; connection request user {:?}",
        cr_user
    );

    let socket = std::sync::Arc::new(UdpSocket::bind(("0.0.0.0", args.udp_port)).await?);
    {
        let (socket, interval) = (socket.clone(), Duration::from_secs(args.stun_interval));
        tokio::spawn(async move {
            loop {
                let mut tx = [0u8; 12];
                if getrandom::fill(&mut tx).is_ok() {
                    let req = binding_request(&stun_user, &stun_pass, tx);
                    if let Err(e) = socket.send_to(&req, stun).await {
                        eprintln!("STUN: {e}");
                    }
                }
                tokio::time::sleep(interval).await;
            }
        });
    }

    let deadline = start + Duration::from_secs(args.timeout);
    let mut seen = HashSet::new();
    let mut public = None;
    let (mut handled, mut rejected) = (0usize, 0usize);
    let mut buf = [0u8; 1500];
    while handled < args.expect {
        let left = deadline.saturating_duration_since(Instant::now());
        let Ok(r) = tokio::time::timeout(left, socket.recv_from(&mut buf)).await else {
            anyhow::bail!("timed out: {handled}/{} connection requests", args.expect);
        };
        let (n, from) = r?;
        if let Some(addr) = mapped_address(&buf[..n]) {
            if public != Some(addr) {
                println!(
                    "{:>6.1}s STUN: local {local_ip}:{} is {addr} outside",
                    start.elapsed().as_secs_f64(),
                    args.udp_port
                );
                public = Some(addr);
            }
            continue;
        }
        let Some(cr) = UdpConnectionRequest::parse(&buf[..n]) else {
            continue;
        };
        if !cr.verify(&cr_user, &cr_pass) {
            rejected += 1;
            println!("UDP connection request from {from} with a bad signature: ignored");
            continue;
        }
        // ACS repeats each request -> one session per message ID.
        if !seen.insert(cr.id.clone()) {
            continue;
        }
        let stats = cpe.session(args.acs, &["6 CONNECTION REQUEST"]).await?;
        handled += 1;
        println!(
            "{:>6.1}s UDP connection request {} from {from}: session with {} requests",
            start.elapsed().as_secs_f64(),
            cr.id,
            stats.requests
        );
    }
    println!(
        "--- results ---\nhandled {handled} UDP connection requests ({rejected} rejected) in {:.1}s",
        start.elapsed().as_secs_f64()
    );
    Ok(())
}
