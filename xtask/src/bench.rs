//! `cargo xtask bench`: performance regression gate (OP-11).
//!
//! Throwaway PostgreSQL container + release `dhonomos` + `cwmp-load`:
//! zero-touch registration of all devices, then periodic Informs.
//! Each run -> appended to `docs/perf/bench/history.jsonl`, compared with
//! `docs/perf/bench/baseline.json`.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use serde_json::{Value, json};

const PG: &str = "dhonomos-bench-pg";
const ACS: &str = "127.0.0.1:27547";
const API: &str = "127.0.0.1:28080";
const HISTORY: &str = "docs/perf/bench/history.jsonl";
const BASELINE: &str = "docs/perf/bench/baseline.json";

/// Gate limits vs baseline: worse -> fail.
const MIN_THROUGHPUT: f64 = 0.90;
const MAX_P99: f64 = 1.50;

fn sh(cmd: &mut Command) -> anyhow::Result<String> {
    let out = cmd.output().with_context(|| format!("running {cmd:?}"))?;
    if !out.status.success() {
        bail!(
            "{cmd:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Stop what the run started, on any exit.
struct Cleanup(Option<Child>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(mut p) = self.0.take() {
            let _ = p.kill();
            let _ = p.wait();
        }
        let _ = Command::new("docker")
            .args(["rm", "-f", PG])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) -> anyhow::Result<()> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(90) {
        if ready() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    bail!("{what} did not become ready")
}

/// `1.2 ms` / `830 us` / `2.1 s` -> ms.
fn millis(v: &str, unit: &str) -> Option<f64> {
    let x: f64 = v.parse().ok()?;
    Some(match unit {
        "s" => x * 1000.0,
        "ms" => x,
        "µs" | "us" => x / 1000.0,
        "ns" => x / 1e6,
        _ => return None,
    })
}

/// `cwmp-load` output -> throughput, Inform p50/p99, errors.
fn parse(out: &str) -> anyhow::Result<Value> {
    let mut v = json!({});
    for line in out.lines() {
        let w: Vec<&str> = line.split_whitespace().collect();
        match w.first() {
            Some(&"throughput") => {
                v["throughput"] = json!(w.get(1).and_then(|t| t.parse::<f64>().ok()));
            }
            Some(&"inform") => {
                let at = |i: usize| w.get(i).zip(w.get(i + 1)).and_then(|(v, u)| millis(v, u));
                v["inform_p50_ms"] = json!(at(2));
                v["inform_p99_ms"] = json!(at(8));
            }
            Some(&"sessions") => {
                let errors = w
                    .iter()
                    .find_map(|x| x.strip_prefix("errors="))
                    .and_then(|x| x.parse::<u64>().ok());
                v["errors"] = json!(errors);
            }
            _ => {}
        }
    }
    if v["throughput"].is_null() || v["inform_p99_ms"].is_null() {
        bail!("unexpected cwmp-load output:\n{out}");
    }
    Ok(v)
}

fn load(devices: u32, rate: u32, secs: u32, event: &str) -> anyhow::Result<Value> {
    let out = sh(Command::new("target/release/cwmp-load").args([
        "--acs",
        ACS,
        "--devices",
        &devices.to_string(),
        "--rate",
        &rate.to_string(),
        "--duration",
        &secs.to_string(),
        "--concurrency",
        "4000",
        "--event",
        event,
        "--serial-prefix",
        "BENCH",
    ]))?;
    parse(&out)
}

pub(crate) fn run(update_baseline: bool, devices: u32) -> anyhow::Result<()> {
    println!("== building release binaries");
    sh(Command::new("cargo").env("SQLX_OFFLINE", "true").args([
        "build",
        "--release",
        "--locked",
        "-p",
        "dhonomos",
        "-p",
        "dhonomos-simulator",
        "--bin",
        "dhonomos",
        "--bin",
        "cwmp-load",
    ]))?;

    println!("== PostgreSQL 17 (throwaway container)");
    let _ = Command::new("docker")
        .args(["rm", "-f", PG])
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .status();
    let mut cleanup = Cleanup(None);
    sh(Command::new("docker").args([
        "run",
        "-d",
        "--name",
        PG,
        "-e",
        "POSTGRES_PASSWORD=bench",
        "postgres:17-alpine",
    ]))?;
    // Container address, no published port: docker-proxy = bottleneck.
    let ip = sh(Command::new("docker").args([
        "inspect",
        "-f",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        PG,
    ]))?;
    wait_for("PostgreSQL", || {
        Command::new("docker")
            .args(["exec", PG, "pg_isready", "-U", "postgres"])
            .stdout(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })?;

    println!("== dhonomos");
    let child = Command::new("target/release/dhonomos")
        .args([
            "--database-url",
            &format!("postgres://postgres:bench@{ip}:5432/postgres"),
            "--database-max-connections",
            "96",
            "--acs-max-concurrent",
            "4096",
            // Load generator = 1 address, 1000s of connections.
            "--acs-max-connections-per-ip",
            "0",
            "--acs-plaintext",
            "--cpe-auth",
            "none",
            "--acs-listen",
            ACS,
            "--api-listen",
            API,
        ])
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .spawn()
        .context("starting dhonomos")?;
    cleanup.0 = Some(child);
    wait_for("dhonomos", || std::net::TcpStream::connect(API).is_ok())?;

    println!("== zero-touch registration of {devices} devices");
    let register = load(devices, 500, devices / 500, "0 BOOTSTRAP")?;
    println!("   {register}");
    println!("== periodic Informs, {devices} devices at 1,500/s for 30 s");
    let periodic = load(devices, 1500, 30, "2 PERIODIC")?;
    println!("   {periodic}");
    drop(cleanup);

    let commit = sh(Command::new("git").args(["rev-parse", "--short", "HEAD"])).unwrap_or_default();
    let loadavg = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|l| l.split_whitespace().next().map(str::to_owned))
        .unwrap_or_default();
    let date = sh(Command::new("date").args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])).unwrap_or_default();
    let result = json!({
        "date": date,
        "commit": commit,
        "devices": devices,
        "load_average": loadavg,
        "scenarios": { "register": register, "periodic": periodic },
    });
    if let Some(dir) = Path::new(HISTORY).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut history = std::fs::read_to_string(HISTORY).unwrap_or_default();
    history.push_str(&format!("{result}\n"));
    std::fs::write(HISTORY, history)?;

    if update_baseline {
        std::fs::write(BASELINE, serde_json::to_string_pretty(&result)?)?;
        println!("baseline saved to {BASELINE}");
        return Ok(());
    }
    let Ok(text) = std::fs::read_to_string(BASELINE) else {
        println!("no {BASELINE} yet: run with --update-baseline to set one");
        return Ok(());
    };
    let base: Value = serde_json::from_str(&text)?;
    let mut failures = Vec::new();
    println!(
        "\n{:<10} {:>22} {:>22} {:>8}",
        "scenario", "throughput (base)", "Inform p99 ms (base)", "errors"
    );
    for name in ["register", "periodic"] {
        let (now, was) = (&result["scenarios"][name], &base["scenarios"][name]);
        let f = |v: &Value, k: &str| v[k].as_f64().unwrap_or(0.0);
        let (t, bt) = (f(now, "throughput"), f(was, "throughput"));
        let (p, bp) = (f(now, "inform_p99_ms"), f(was, "inform_p99_ms"));
        let errors = now["errors"].as_u64().unwrap_or(0);
        println!(
            "{name:<10} {:>22} {:>22} {errors:>8}",
            format!("{t:.0} ({bt:.0})"),
            format!("{p:.1} ({bp:.1})")
        );
        if bt > 0.0 && t < bt * MIN_THROUGHPUT {
            failures.push(format!("{name}: throughput {t:.0}/s < 90% of {bt:.0}/s"));
        }
        if bp > 0.0 && p > bp * MAX_P99 {
            failures.push(format!("{name}: Inform p99 {p:.1} ms > 150% of {bp:.1} ms"));
        }
        if errors > 0 {
            failures.push(format!("{name}: {errors} session errors"));
        }
    }
    if failures.is_empty() {
        println!("\nno regression");
        Ok(())
    } else {
        bail!("performance regression:\n  {}", failures.join("\n  "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cwmp_load_output() {
        let out = "--- results ---\nsessions ok=29980 errors=0 skipped(concurrency)=20 acs_requests=0\nthroughput 999.3 sessions/s\ninform  p50 4.2 ms p95 9.9 ms p99 1.2 s max 2.0 s\nsession p50 8.0 ms p95 20.1 ms p99 40.0 ms max 90.0 ms\n";
        let v = parse(out).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(v["throughput"], 999.3);
        assert_eq!(v["inform_p50_ms"], 4.2);
        assert_eq!(v["inform_p99_ms"], 1200.0);
        assert_eq!(v["errors"], 0);
        assert!(parse("nothing").is_err());
    }
}
