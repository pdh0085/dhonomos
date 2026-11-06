//! CWMP load: many virtual CPEs, sessions at a fixed total rate.
//!
//! `cargo run --release -p dhonomos-simulator --bin cwmp-load -- --acs 127.0.0.1:7547 --devices 10000 --rate 500 --duration 600`
#![allow(clippy::print_stdout)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::Parser;
use dhonomos_simulator::{CpeProfile, VirtualCpe};
use tokio::sync::{Mutex, Semaphore};

#[derive(Debug, Parser)]
struct Args {
    /// ACS address.
    #[arg(long, default_value = "127.0.0.1:7547")]
    acs: SocketAddr,
    /// Distinct virtual CPEs (serials <prefix>000000...).
    #[arg(long, default_value_t = 1000)]
    devices: u32,
    /// Serial number prefix.
    #[arg(long, default_value = "LOAD")]
    serial_prefix: String,
    /// Product class.
    #[arg(long, default_value = "LoadBox")]
    product_class: String,
    /// Firmware at start.
    #[arg(long, default_value = "1.0.0")]
    software_version: String,
    /// Firmware after a successful Download.
    #[arg(long, default_value = "2.0.0")]
    upgrade_to: String,
    /// CPEs with a failing Download, in %.
    #[arg(long, default_value_t = 0)]
    fail_download_pct: u32,
    /// Total sessions/s.
    #[arg(long, default_value_t = 100.0)]
    rate: f64,
    /// Test duration, s.
    #[arg(long, default_value_t = 60)]
    duration: u64,
    /// Max sessions in flight.
    #[arg(long, default_value_t = 2000)]
    concurrency: usize,
    /// Event code of each Inform.
    #[arg(long, default_value = "2 PERIODIC")]
    event: String,
}

fn pct(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[i]
}

fn ms(d: Duration) -> String {
    format!("{:.1} ms", d.as_secs_f64() * 1000.0)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cpes: Arc<Vec<VirtualCpe>> = Arc::new(
        (0..args.devices)
            .map(|i| {
                VirtualCpe::new(
                    format!("{}{i:06}", args.serial_prefix),
                    format!("http://192.0.2.1:7547/{i}"),
                    CpeProfile {
                        product_class: args.product_class.clone(),
                        software_version: args.software_version.clone(),
                        upgrade_to: args.upgrade_to.clone(),
                        // Prime 7919 -> failures spread evenly over the serials.
                        fail_downloads: (i * 7919) % 100 < args.fail_download_pct,
                    },
                )
            })
            .collect(),
    );
    let informs = Arc::new(Mutex::new(Vec::<Duration>::new()));
    let sessions = Arc::new(Mutex::new(Vec::<Duration>::new()));
    let errors = Arc::new(AtomicU64::new(0));
    let requests = Arc::new(AtomicU64::new(0));
    let slots = Arc::new(Semaphore::new(args.concurrency));
    let event = Arc::new(args.event.clone());

    println!(
        "{} devices, {} sessions/s for {} s against {}",
        args.devices, args.rate, args.duration, args.acs
    );
    let start = Instant::now();
    let interval = Duration::from_secs_f64(1.0 / args.rate);
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    let mut n: u64 = 0;
    let mut dropped: u64 = 0;
    let mut handles = Vec::new();
    while start.elapsed() < Duration::from_secs(args.duration) {
        tick.tick().await;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            dropped += 1;
            continue;
        };
        let cpe = cpes[(n % cpes.len() as u64) as usize].clone();
        n += 1;
        let (inf_t, ses_t, err_t, req_t, ev_t) = (
            informs.clone(),
            sessions.clone(),
            errors.clone(),
            requests.clone(),
            event.clone(),
        );
        let acs = args.acs;
        handles.push(tokio::spawn(async move {
            match cpe.session(acs, &[ev_t.as_str()]).await {
                Ok(s) => {
                    inf_t.lock().await.push(s.inform);
                    ses_t.lock().await.push(s.session);
                    req_t.fetch_add(u64::from(s.requests), Ordering::Relaxed);
                }
                Err(e) => {
                    if err_t.fetch_add(1, Ordering::Relaxed) < 5 {
                        eprintln!("session error: {e:#}");
                    }
                }
            }
            drop(permit);
        }));
        if n.is_multiple_of((args.rate as u64 * 10).max(1)) {
            let done = sessions.lock().await.len();
            println!(
                "t={:>4}s started={n} done={done} errors={} in_flight={}",
                start.elapsed().as_secs(),
                errors.load(Ordering::Relaxed),
                args.concurrency - slots.available_permits()
            );
        }
    }
    for h in handles {
        let _ = h.await;
    }
    let elapsed = start.elapsed();
    let mut inf = informs.lock().await.clone();
    let mut ses = sessions.lock().await.clone();
    inf.sort();
    ses.sort();
    println!("--- results ---");
    println!(
        "sessions ok={} errors={} skipped(concurrency)={} acs_requests={}",
        ses.len(),
        errors.load(Ordering::Relaxed),
        dropped,
        requests.load(Ordering::Relaxed)
    );
    println!(
        "throughput {:.1} sessions/s",
        ses.len() as f64 / elapsed.as_secs_f64()
    );
    println!(
        "inform  p50 {} p95 {} p99 {} max {}",
        ms(pct(&inf, 0.50)),
        ms(pct(&inf, 0.95)),
        ms(pct(&inf, 0.99)),
        ms(inf.last().copied().unwrap_or_default())
    );
    println!(
        "session p50 {} p95 {} p99 {} max {}",
        ms(pct(&ses, 0.50)),
        ms(pct(&ses, 0.95)),
        ms(pct(&ses, 0.99)),
        ms(ses.last().copied().unwrap_or_default())
    );
    Ok(())
}
