//! BulkData load: N devices -> past reports via the collector (JSON NameValuePair, gzip).
//! One POST per device-day; then series query of one device.
//!
//! `cargo run --release -p dhonomos-simulator --bin bulkdata-load -- --devices 1000 --days 7`
#![allow(clippy::print_stdout)]

use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt as _, Full};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::sync::Semaphore;

#[derive(Debug, Parser)]
struct Args {
    /// Dhonomos API -> devices + their BulkData URLs.
    #[arg(long, default_value = "127.0.0.1:8080")]
    api: String,
    /// Product class of the reporting devices.
    #[arg(long, default_value = "FwBox")]
    product_class: String,
    /// Device count.
    #[arg(long, default_value_t = 1000)]
    devices: usize,
    /// Days of history.
    #[arg(long, default_value_t = 7)]
    days: i64,
    /// Report interval, s.
    #[arg(long, default_value_t = 300)]
    interval: i64,
    /// Parameters per report.
    #[arg(long, default_value_t = 10)]
    metrics: usize,
    /// POSTs in flight.
    #[arg(long, default_value_t = 32)]
    concurrency: usize,
}

async fn request(
    addr: &str,
    method: Method,
    path: &str,
    body: Option<(Vec<u8>, bool)>,
) -> anyhow::Result<(u16, Bytes)> {
    let io = TokioIo::new(tokio::net::TcpStream::connect(addr).await?);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", addr);
    let payload = match body {
        Some((b, gzip)) => {
            req = req.header("content-type", "application/json");
            if gzip {
                req = req.header("content-encoding", "gzip");
            }
            Bytes::from(b)
        }
        None => Bytes::new(),
    };
    let resp = sender.send_request(req.body(Full::new(payload))?).await?;
    let status = resp.status().as_u16();
    Ok((status, resp.into_body().collect().await?.to_bytes()))
}

async fn get_json(addr: &str, path: &str) -> anyhow::Result<Value> {
    let (status, body) = request(addr, Method::GET, path, None).await?;
    anyhow::ensure!(status == 200, "GET {path}: {status}");
    Ok(serde_json::from_slice(&body)?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Arc::new(Args::parse());
    let mut ids = Vec::new();
    let mut offset = 0;
    while ids.len() < args.devices {
        let page = get_json(
            &args.api,
            &format!("/api/v1/devices?limit=1000&offset={offset}"),
        )
        .await?;
        let items = page["items"].as_array().cloned().unwrap_or_default();
        if items.is_empty() {
            break;
        }
        offset += items.len();
        ids.extend(
            items
                .iter()
                .filter(|d| d["product_class"] == args.product_class.as_str())
                .filter_map(|d| d["id"].as_str().map(str::to_owned)),
        );
    }
    ids.truncate(args.devices);
    anyhow::ensure!(!ids.is_empty(), "no {} devices", args.product_class);
    let mut targets = Vec::new();
    for id in &ids {
        let v = get_json(&args.api, &format!("/api/v1/devices/{id}/bulkdata-url")).await?;
        let url = v["url"].as_str().unwrap_or_default().to_owned();
        let rest = url.split_once("://").map(|(_, r)| r).unwrap_or_default();
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        targets.push((id.clone(), host.to_owned(), format!("/{path}")));
    }
    let per_day = 86_400 / args.interval;
    println!(
        "{} devices × {} days × {} reports/day × {} metrics = {} samples",
        targets.len(),
        args.days,
        per_day,
        args.metrics,
        targets.len() as i64 * args.days * per_day * args.metrics as i64
    );

    let now = time_now();
    let start = Instant::now();
    let slots = Arc::new(Semaphore::new(args.concurrency));
    let (posted, failed, bytes_sent) = (
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
    );
    let mut handles = Vec::new();
    for (n, (_, host, path)) in targets.iter().enumerate() {
        for day in (0..args.days).rev() {
            let permit = slots.clone().acquire_owned().await?;
            let (args, host, path) = (args.clone(), host.clone(), path.clone());
            let (posted, failed, bytes_sent) = (posted.clone(), failed.clone(), bytes_sent.clone());
            handles.push(tokio::spawn(async move {
                let day_start = now - (day + 1) * 86_400;
                let reports: Vec<Value> = (0..per_day)
                    .map(|r| {
                        let t = day_start + r * args.interval;
                        let mut obj = serde_json::Map::new();
                        obj.insert("CollectionTime".into(), json!(t));
                        for k in 0..args.metrics {
                            // Smooth daily curve, own per device + metric.
                            let phase = (t as f64 / 86_400.0 + n as f64 * 0.013 + k as f64)
                                * std::f64::consts::TAU;
                            obj.insert(
                                format!("Device.X_Sim.Metric.{k}"),
                                json!((50.0 + 40.0 * phase.sin()).round()),
                            );
                        }
                        Value::Object(obj)
                    })
                    .collect();
                let body = serde_json::to_vec(&json!({ "Report": reports })).unwrap_or_default();
                let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                let _ = gz.write_all(&body);
                let gz = gz.finish().unwrap_or_default();
                bytes_sent.fetch_add(gz.len() as u64, Ordering::Relaxed);
                match request(&host, Method::POST, &path, Some((gz, true))).await {
                    Ok((204, _)) => posted.fetch_add(1, Ordering::Relaxed),
                    Ok((s, b)) => {
                        if failed.fetch_add(1, Ordering::Relaxed) < 3 {
                            eprintln!("POST {s}: {}", String::from_utf8_lossy(&b));
                        }
                        0
                    }
                    Err(e) => {
                        if failed.fetch_add(1, Ordering::Relaxed) < 3 {
                            eprintln!("POST: {e:#}");
                        }
                        0
                    }
                };
                drop(permit);
            }));
        }
    }
    for h in handles {
        let _ = h.await;
    }
    let secs = start.elapsed().as_secs_f64();
    let samples = posted.load(Ordering::Relaxed) as f64 * per_day as f64 * args.metrics as f64;
    println!("--- ingest ---");
    println!(
        "posts ok={} failed={} in {secs:.1}s; {:.0} samples/s; {:.1} MB gzip sent",
        posted.load(Ordering::Relaxed),
        failed.load(Ordering::Relaxed),
        samples / secs,
        bytes_sent.load(Ordering::Relaxed) as f64 / 1e6
    );

    // Series of 1 device over `--days`, hourly buckets, x20 -> latency.
    let id = &targets[0].0;
    let from = now - args.days * 86_400;
    let path = format!(
        "/api/v1/devices/{id}/metrics/series?path=Device.X_Sim.Metric.0&from={}&to={}&step=3600",
        rfc3339(from),
        rfc3339(now)
    );
    let mut lat = Vec::new();
    let mut points = 0;
    for _ in 0..20 {
        let t = Instant::now();
        let v = get_json(&args.api, &path).await?;
        lat.push(t.elapsed());
        points = v["points"].as_array().map_or(0, Vec::len);
    }
    lat.sort();
    println!("--- query ---");
    println!(
        "{days}-day series, hourly: {points} points; p50 {:.1} ms, max {:.1} ms",
        lat[lat.len() / 2].as_secs_f64() * 1000.0,
        lat[lat.len() - 1].as_secs_f64() * 1000.0,
        days = args.days
    );
    Ok(())
}

fn time_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Epoch seconds -> RFC 3339 UTC (`Z`, no `+` -> URL-safe).
fn rfc3339(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    // Days since 1970-01-01 -> civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}
