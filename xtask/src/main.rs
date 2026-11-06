//! Development tasks: `cargo xtask <command>`.
#![allow(clippy::print_stdout)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

mod bench;

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Performance regression gate (OP-11): clean PostgreSQL container, release `dhonomos`,
    /// `cwmp-load` scenarios. Results -> docs/perf/bench/history.jsonl, compared with
    /// docs/perf/bench/baseline.json; regression -> fail.
    Bench {
        /// Save this run as the new baseline.
        #[arg(long)]
        update_baseline: bool,
        /// Devices simulated.
        #[arg(long, default_value_t = 10_000)]
        devices: u32,
    },
    /// Write a CycloneDX 1.5 SBOM of the `dhonomos` binary (OP-09): runtime Rust deps +
    /// production npm packages of the UI bundle.
    Sbom {
        /// Output file.
        #[arg(long, default_value = "dist/dhonomos.cdx.json")]
        out: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Bench {
            update_baseline,
            devices,
        } => bench::run(update_baseline, devices),
        Cmd::Sbom { out } => sbom(&out),
    }
}

/// `name version -> sha256` from Cargo.lock.
fn lock_checksums() -> anyhow::Result<HashMap<(String, String), String>> {
    let text = std::fs::read_to_string("Cargo.lock").context("reading Cargo.lock")?;
    let mut out = HashMap::new();
    for block in text.split("[[package]]") {
        let field = |key: &str| {
            block.lines().find_map(|l| {
                l.strip_prefix(&format!("{key} = \""))
                    .and_then(|v| v.strip_suffix('"'))
                    .map(str::to_owned)
            })
        };
        if let (Some(n), Some(v), Some(c)) = (field("name"), field("version"), field("checksum")) {
            out.insert((n, v), c);
        }
    }
    Ok(out)
}

fn purl(name: &str, version: &str) -> String {
    format!("pkg:cargo/{name}@{version}")
}

fn sbom(out: &PathBuf) -> anyhow::Result<()> {
    let meta = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .output()
        .context("running cargo metadata")?;
    if !meta.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&meta.stderr)
        );
    }
    let meta: Value = serde_json::from_slice(&meta.stdout)?;
    let packages: HashMap<&str, &Value> = meta["packages"]
        .as_array()
        .context("no packages")?
        .iter()
        .filter_map(|p| Some((p["id"].as_str()?, p)))
        .collect();
    let nodes: HashMap<&str, &Value> = meta["resolve"]["nodes"]
        .as_array()
        .context("no resolve graph")?
        .iter()
        .filter_map(|n| Some((n["id"].as_str()?, n)))
        .collect();
    let root = packages
        .iter()
        .find(|(_, p)| p["name"] == "dhonomos")
        .map(|(id, _)| *id)
        .context("no dhonomos package")?;

    // Runtime deps only: skip dev + build edges.
    let mut seen = BTreeSet::new();
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut todo = vec![root];
    while let Some(id) = todo.pop() {
        if !seen.insert(id) {
            continue;
        }
        for dep in nodes[id]["deps"].as_array().into_iter().flatten() {
            let runtime = dep["dep_kinds"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|k| k["kind"].is_null());
            let Some(pkg) = dep["pkg"].as_str().filter(|_| runtime) else {
                continue;
            };
            edges
                .entry(id.to_owned())
                .or_default()
                .insert(pkg.to_owned());
            todo.push(pkg);
        }
    }
    let checksums = lock_checksums()?;
    let bom_ref = |id: &str| {
        let p = packages[id];
        purl(
            p["name"].as_str().unwrap_or_default(),
            p["version"].as_str().unwrap_or_default(),
        )
    };
    let mut components = Vec::new();
    for id in seen.iter().filter(|id| **id != root) {
        let p = packages[id];
        let (name, version) = (
            p["name"].as_str().unwrap_or_default(),
            p["version"].as_str().unwrap_or_default(),
        );
        let mut c = json!({
            "type": "library",
            "bom-ref": purl(name, version),
            "name": name,
            "version": version,
            "purl": purl(name, version),
        });
        if let Some(l) = p["license"].as_str() {
            c["licenses"] = json!([{ "expression": l }]);
        }
        if let Some(sum) = checksums.get(&(name.to_owned(), version.to_owned())) {
            c["hashes"] = json!([{ "alg": "SHA-256", "content": sum }]);
        }
        components.push(c);
    }
    // UI bundle is embedded in the binary. SvelteKit lists all as dev deps (bundler inlines
    // what is used) -> start from runtime packages in the bundle + follow their deps.
    let ui: Value = serde_json::from_str(
        &std::fs::read_to_string("ui/package-lock.json").context("reading ui/package-lock.json")?,
    )?;
    let lock = ui["packages"]
        .as_object()
        .context("no packages in the npm lockfile")?;
    let mut npm_seen = BTreeSet::new();
    let mut todo: Vec<String> = vec!["svelte".into(), "@sveltejs/kit".into()];
    while let Some(name) = todo.pop() {
        let Some(p) = lock.get(&format!("node_modules/{name}")) else {
            continue;
        };
        if !npm_seen.insert(name.clone()) {
            continue;
        }
        let version = p["version"].as_str().unwrap_or_default();
        let purl = format!("pkg:npm/{}@{version}", name.replace('@', "%40"));
        let mut c = json!({
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
        });
        if let Some(l) = p["license"].as_str() {
            c["licenses"] = json!([{ "expression": l }]);
        }
        components.push(c);
        for dep in p["dependencies"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(k, _)| k)
        {
            todo.push(dep.clone());
        }
    }
    let npm = npm_seen.len();
    let version = packages[root]["version"].as_str().unwrap_or_default();
    let dependencies: Vec<Value> = edges
        .iter()
        .map(|(from, to)| json!({ "ref": bom_ref(from), "dependsOn": to.iter().map(|t| bom_ref(t)).collect::<Vec<_>>() }))
        .collect();
    let doc = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": { "components": [ { "type": "application", "name": "cargo xtask sbom" } ] },
            "component": {
                "type": "application",
                "bom-ref": purl("dhonomos", version),
                "name": "dhonomos",
                "version": version,
                "licenses": [ { "license": { "id": "Apache-2.0" } } ],
            },
        },
        "components": components,
        "dependencies": dependencies,
    });
    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(out, serde_json::to_string_pretty(&doc)?)?;
    println!(
        "{}: {} Rust crates, {npm} npm packages",
        out.display(),
        seen.len() - 1
    );
    Ok(())
}
