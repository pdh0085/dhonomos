//! Spike B (Phase 0): quick-xml parse time + peak memory, BBF `-full.xml` data model.
//! Builds a minimal owned object/parameter tree.
//!
//! Usage: `cargo run --release -p dhonomos-datamodel --example spike_parse -- schemas/tr-181-2-21-0-usp-full.xml`
#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    missing_debug_implementations
)]

use std::time::Instant;

use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

struct Param {
    _name: String,
    _access: String,
    _description: String,
    _syntax: String,
}

struct Object {
    _name: String,
    params: Vec<Param>,
}

fn attr(e: &BytesStart<'_>, key: &str) -> String {
    e.try_get_attribute(key)
        .ok()
        .flatten()
        .map(|a| {
            a.normalized_value(XmlVersion::default())
                .unwrap()
                .into_owned()
        })
        .unwrap_or_default()
}

fn peak_rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().trim_end_matches(" kB").parse().ok())
        .unwrap_or(0)
}

fn parse(xml: &str) -> Vec<Object> {
    let mut reader = Reader::from_str(xml);
    let mut objects: Vec<Object> = Vec::new();
    let mut cur_param: Option<Param> = None;
    let mut in_description = false;
    let mut in_syntax = false;
    let mut desc = String::new();

    loop {
        match reader.read_event().unwrap() {
            Event::Start(e) | Event::Empty(e) => match e.local_name().as_ref() {
                "object" => objects.push(Object {
                    _name: attr(&e, "name"),
                    params: Vec::new(),
                }),
                "parameter" => {
                    cur_param = Some(Param {
                        _name: attr(&e, "name"),
                        _access: attr(&e, "access"),
                        _description: String::new(),
                        _syntax: String::new(),
                    })
                }
                "description" => {
                    in_description = true;
                    desc.clear();
                }
                "syntax" => in_syntax = true,
                other if in_syntax => {
                    if let Some(p) = cur_param.as_mut()
                        && p._syntax.is_empty()
                    {
                        p._syntax = other.to_owned();
                    }
                }
                _ => {}
            },
            Event::Text(t) if in_description => {
                desc.push_str(&t.xml_content(XmlVersion::default()))
            }
            Event::End(e) => match e.local_name().as_ref() {
                "description" => {
                    in_description = false;
                    if let Some(p) = cur_param.as_mut() {
                        p._description = std::mem::take(&mut desc);
                    }
                }
                "syntax" => in_syntax = false,
                "parameter" => {
                    if let (Some(p), Some(o)) = (cur_param.take(), objects.last_mut()) {
                        o.params.push(p);
                    }
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
    }
    objects
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "schemas/tr-181-2-21-0-usp-full.xml".into());
    let base = peak_rss_kib();

    let t0 = Instant::now();
    let xml = std::fs::read_to_string(&path).unwrap();
    let t_read = t0.elapsed();

    let mut best = std::time::Duration::MAX;
    let mut objects = Vec::new();
    for _ in 0..5 {
        drop(objects);
        let t = Instant::now();
        objects = parse(&xml);
        best = best.min(t.elapsed());
    }
    let params: usize = objects.iter().map(|o| o.params.len()).sum();

    println!("file          : {path} ({} bytes)", xml.len());
    println!("read          : {t_read:?}");
    println!("parse (best/5): {best:?}");
    println!("objects       : {}", objects.len());
    println!("parameters    : {params}");
    println!(
        "peak RSS      : {} KiB (baseline {base} KiB)",
        peak_rss_kib()
    );
}
