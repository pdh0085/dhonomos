//! `DataModel::from_xml` on a DM document -> load time + peak memory.
//!
//! Usage: `cargo run --release -p dhonomos-datamodel --example load_timing -- <file.xml>`
#![allow(clippy::print_stdout, clippy::unwrap_used)]

use std::time::{Duration, Instant};

use dhonomos_datamodel::DataModel;

fn peak_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().trim_end_matches(" kB").parse().ok())
        .unwrap_or(0)
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "schemas/tr-181-2-21-0-usp-full.xml".into());
    let xml = std::fs::read_to_string(&path).unwrap();
    let mut best = Duration::MAX;
    let mut dm = None;
    for _ in 0..5 {
        drop(dm.take());
        let t = Instant::now();
        dm = Some(DataModel::from_xml(&xml).unwrap());
        best = best.min(t.elapsed());
    }
    let dm = dm.unwrap();
    println!(
        "{path}: {}:{} objects={} load(best/5)={best:?} peakRSS={} KiB",
        dm.root(),
        dm.version(),
        dm.objects().len(),
        peak_rss_kib()
    );
}
