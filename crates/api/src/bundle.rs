//! Agent certificates in bulk -> one encrypted zip (ADR-099).
//!
//! Key + certificate per Agent -> admin downloads one AES-256 zip -> gives it to the installer.
//! Private keys never stored: only in request memory + in the zip.
//! Password = the requester's; never stored or logged either.
//!
//! Devices by ID, EndpointID, OUI + serial (EndpointID `os::<OUI>-<serial>`) or filter
//! expression; need not have connected.
//! Agent not registered yet -> pre-registered with the certificates (on request).
//! CWMP device -> stands for the Agent with EndpointID from its OUI + serial.
//! All checked first. New devices + certificates recorded together, only after the zip exists.
//!
//! Zip: `README.txt`, CA certificate `ca.pem`, `manifest.csv`, per Agent a directory named
//! after its EndpointID: `client.pem` (certificate, then private key = `obuspa -a` format),
//! `cert.pem` (certificate only).
//! Entries stored, not compressed: zip is small, plain format needs no codecs.

use std::collections::HashSet;
use std::io::{Cursor, Write as _};
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use dhonomos_pki::{Ca, Profile};
use dhonomos_store::{
    CertificateTarget, Device, DeviceSearch, FilterExpr, NewCertificate, NewUspDevice,
};
use serde::Deserialize;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;
use zip::write::SimpleFileOptions;
use zip::{AesMode, CompressionMethod, DateTime, ZipWriter};

use crate::enroll::{ENDPOINT_ID_RULE, derived_endpoint_id, usp_endpoint_id, valid_endpoint_id};
use crate::export::line;
use crate::{ApiError, AppState, actor, audit, clean_tags, ts};

/// Default validity: 3 years, as installation is manual
/// (expiry announced by the expiring list + alarms).
pub(crate) const DEFAULT_DAYS: u32 = 1095;
/// Max devices per request.
const MAX_DEVICES: usize = 1000;
/// Header: certificates in the zip.
const ISSUED_HEADER: &str = "x-certificates-issued";
/// Header: devices registered for them.
const CREATED_HEADER: &str = "x-devices-created";
/// Password length: min in chars, max in bytes.
const MIN_PASSWORD_CHARS: usize = 12;
const MAX_PASSWORD_BYTES: usize = 1024;
/// Max body: 1,000 EndpointIDs x 256 bytes + room for the rest.
const MAX_BODY_BYTES: usize = 512 << 10;
/// Max offending entries listed in a refusal.
const MAX_REPORTED: usize = 20;
/// Max EndpointID length (same limit as for WebSocket Agents).
pub(crate) const MAX_EID_BYTES: usize = 256;
/// Max directory name length in the zip.
const MAX_DIR_CHARS: usize = 100;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new().route(
        "/certificates/bundle",
        post(issue_bundle).layer(DefaultBodyLimit::max(MAX_BODY_BYTES)),
    )
}

/// `days` of a certificate request: default, or 1-3650.
pub(crate) fn check_days(days: Option<u32>) -> Result<u32, ApiError> {
    let days = days.unwrap_or(DEFAULT_DAYS);
    if (1..=3650).contains(&days) {
        Ok(days)
    } else {
        Err(unprocessable("days must be between 1 and 3650".into()))
    }
}

fn unprocessable(message: String) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, message)
}

/// Certificate, then private key = what `obuspa -a` reads.
pub(crate) fn client_pem(cert_pem: &str, key_pem: &str) -> Zeroizing<String> {
    let mut out = String::with_capacity(cert_pem.len() + key_pem.len() + 1);
    out.push_str(cert_pem);
    if !cert_pem.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(key_pem);
    Zeroizing::new(out)
}

/// Device by EndpointID, or by the OUI + serial it is derived from.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct DeviceName {
    /// USP EndpointID, `<authority-scheme>::<instance-id>`.
    #[serde(default)]
    endpoint_id: Option<String>,
    /// Manufacturer OUI, 6 hex digits (with `serial_number`).
    #[serde(default)]
    oui: Option<String>,
    /// Serial number (with `oui`) -> EndpointID `os::<OUI in capitals>-<serial>`.
    #[serde(default)]
    serial_number: Option<String>,
}

/// Body of `POST /certificates/bundle`.
/// Devices by `device_ids`, `endpoint_ids`, `targets`, `filter`, any mix; max 1,000 in all.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct BundleRequest {
    /// Devices by ID, not retired: USP devices of the tenant (registered or pre-registered),
    /// CWMP devices with OUI + serial -> Agent `os::<OUI>-<serial>`
    /// (registered with the CWMP device's tags if missing).
    #[serde(default)]
    #[schema(max_items = 1000)]
    device_ids: Vec<Uuid>,
    /// Devices by EndpointID.
    #[serde(default)]
    #[schema(max_items = 1000)]
    endpoint_ids: Vec<String>,
    /// Devices by EndpointID, or by OUI and serial number.
    #[serde(default)]
    #[schema(max_items = 1000)]
    targets: Vec<DeviceName>,
    /// All devices a filter matches (language of `GET /devices?filter=`), except retired.
    #[serde(default)]
    filter: Option<String>,
    /// Register missing Agents of `endpoint_ids` + `targets` with `tags`
    /// (default false -> refused).
    #[serde(default)]
    create_missing: bool,
    /// Tags of Agents registered by `create_missing`.
    #[serde(default)]
    tags: Vec<String>,
    /// Validity in days, 1-3650 (default 1095).
    #[serde(default)]
    #[schema(minimum = 1, maximum = 3650, default = 1095)]
    days: Option<u32>,
    /// Zip password: min 12 chars, max 1,024 bytes. Not stored.
    #[schema(format = Password, min_length = 12)]
    password: String,
}

/// Length rule of a bundle password.
fn check_password(password: &str) -> Result<(), ApiError> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(unprocessable(format!(
            "password must be at least {MIN_PASSWORD_CHARS} characters"
        )));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(unprocessable(format!(
            "password must be at most {MAX_PASSWORD_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Request value for an error message: escaped, max 80 chars.
fn quote(s: &str) -> String {
    let shown: String = s.chars().take(80).collect();
    let more = if s.chars().count() > 80 { "..." } else { "" };
    format!("{shown:?}{more}")
}

/// Device the bundle is issued for.
#[derive(Debug, Clone)]
struct Target {
    /// Device ID; new device -> its future ID.
    id: Uuid,
    /// USP EndpointID in the certificate.
    endpoint_id: String,
    /// Serial number, once the device reported it.
    serial_number: Option<String>,
    /// New device -> its tags.
    create: Option<Vec<String>>,
}

/// Resolved request target: label for errors + EndpointID or why none.
#[derive(Clone)]
struct Named {
    label: String,
    endpoint_id: Result<String, String>,
}

/// Agent of a CWMP device: `os::<OUI>-<serial>`, or why none.
fn derived_for(row: &CertificateTarget) -> Result<String, String> {
    derived_endpoint_id(
        row.oui.as_deref().unwrap_or_default(),
        row.serial_number.as_deref().unwrap_or_default(),
    )
}

/// What the request names.
struct Wanted<'a> {
    device_ids: &'a [Uuid],
    endpoint_ids: &'a [String],
    targets: &'a [Named],
    create_missing: bool,
    tags: &'a [String],
}

/// Collects the bundle devices + all problems of the request.
struct Planner<'a> {
    known: &'a [CertificateTarget],
    found: Vec<Target>,
    problems: Vec<String>,
    /// EndpointIDs taken so far.
    taken: HashSet<String>,
}

impl<'a> Planner<'a> {
    /// USP device with this EndpointID.
    fn usp(&self, eid: &str) -> Option<&'a CertificateTarget> {
        self.known
            .iter()
            .find(|r| r.protocol == "usp" && r.endpoint_id.as_deref() == Some(eid))
    }

    /// Take Agent `eid`: existing device, or new one if `create` gives tags.
    /// `quiet` -> duplicate skipped, not reported.
    fn take(&mut self, label: &str, eid: &str, create: Option<&[String]>, quiet: bool) {
        let existing = self.usp(eid);
        if existing.is_none() && create.is_none() {
            self.problems.push(format!("{label} not found"));
        } else if existing.is_some_and(|r| r.status == "retired") {
            self.problems.push(format!("{label} is retired"));
        } else if !eid.is_ascii() || eid.len() > MAX_EID_BYTES {
            self.problems.push(format!(
                "{label} has an EndpointID that cannot go into a certificate"
            ));
        } else if !self.taken.insert(eid.to_owned()) {
            if !quiet {
                self.problems
                    .push(format!("{label} duplicates another entry"));
            }
        } else {
            self.found.push(match existing {
                Some(r) => Target {
                    id: r.id,
                    endpoint_id: eid.to_owned(),
                    serial_number: r.serial_number.clone(),
                    create: None,
                },
                None => Target {
                    id: Uuid::now_v7(),
                    endpoint_id: eid.to_owned(),
                    serial_number: None,
                    create: create.map(<[String]>::to_vec),
                },
            });
        }
    }

    /// Take device `row`: USP as is, CWMP as the Agent it stands for.
    fn take_row(&mut self, label: &str, row: &CertificateTarget, quiet: bool) {
        if row.protocol == "usp" {
            match row.endpoint_id.as_deref() {
                Some(eid) => self.take(label, eid, None, quiet),
                None => self.problems.push(format!("{label} has no EndpointID")),
            }
        } else if row.status == "retired" {
            self.problems.push(format!("{label} is retired"));
        } else {
            match derived_for(row) {
                Ok(eid) => self.take(label, &eid, Some(&row.tags), quiet),
                Err(why) => self.problems.push(format!(
                    "{label} cannot be given an EndpointID: {why} (oui {}, serial_number {})",
                    quote(row.oui.as_deref().unwrap_or_default()),
                    quote(row.serial_number.as_deref().unwrap_or_default())
                )),
            }
        }
    }
}

/// Devices the request names, in request order, or all problems.
///
/// Problems: unknown, retired, listed twice, EndpointID not fit for a certificate,
/// CWMP device without usable OUI + serial, missing Agent with `create_missing` off.
/// `known` = DB rows of the given names (also of the Agents CWMP devices stand for).
/// `from_filter` = devices of the filter.
fn plan(
    wanted: &Wanted<'_>,
    known: &[CertificateTarget],
    from_filter: &[CertificateTarget],
) -> Result<Vec<Target>, Vec<String>> {
    let mut p = Planner {
        known,
        found: Vec::new(),
        problems: Vec::new(),
        taken: HashSet::new(),
    };
    for id in wanted.device_ids {
        let label = format!("device {id}");
        match known.iter().find(|r| r.id == *id) {
            Some(row) => p.take_row(&label, row, false),
            None => p.problems.push(format!("{label} not found")),
        }
    }
    let create = |p: &Planner<'_>, eid: &str| {
        (wanted.create_missing && p.usp(eid).is_none()).then_some(wanted.tags)
    };
    for eid in wanted.endpoint_ids {
        let label = format!("endpoint_id {}", quote(eid));
        let create = create(&p, eid);
        if create.is_some() && !valid_endpoint_id(eid) {
            p.problems.push(format!("{label}: {ENDPOINT_ID_RULE}"));
            continue;
        }
        p.take(&label, eid, create, false);
    }
    for t in wanted.targets {
        match &t.endpoint_id {
            Ok(eid) => {
                let create = create(&p, eid);
                p.take(&t.label, eid, create, false);
            }
            Err(why) => p.problems.push(format!("{}: {why}", t.label)),
        }
    }
    // Filter devices may overlap each other + the names above -> quiet.
    for row in from_filter {
        p.take_row(&format!("device {}", row.id), row, true);
    }
    if p.problems.is_empty() {
        Ok(p.found)
    } else {
        Err(p.problems)
    }
}

fn refusal(problems: &[String]) -> ApiError {
    let shown = problems
        .iter()
        .take(MAX_REPORTED)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("; ");
    let more = problems.len().saturating_sub(MAX_REPORTED);
    let more = if more > 0 {
        format!(" (and {more} more)")
    } else {
        String::new()
    };
    unprocessable(format!("no certificates were issued: {shown}{more}"))
}

/// Windows device names: no file may have them, with or without extension.
const RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Directory name for an EndpointID, OK on every file system.
///
/// Letters, digits, `-`, `_` kept; else (`:`, `/`, ...) -> `_`; dots only inside the name.
fn dir_stem(eid: &str) -> String {
    let mapped: String = eid
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .take(MAX_DIR_CHARS)
        .collect();
    let mut name = mapped.trim_matches('.').to_owned();
    if name.is_empty() {
        name = "device".into();
    }
    let base = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if RESERVED_NAMES.contains(&base.as_str()) {
        name.insert(0, '_');
    }
    name
}

/// One directory name per EndpointID, unique also on case-insensitive file systems
/// (clash -> `-2`, `-3`, ...).
fn dir_names<'a>(eids: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut used = HashSet::new();
    eids.into_iter()
        .map(|eid| {
            let stem = dir_stem(eid);
            let mut name = stem.clone();
            let mut n = 1;
            while !used.insert(name.to_ascii_lowercase()) {
                n += 1;
                name = format!("{stem}-{n}");
            }
            name
        })
        .collect()
}

/// Issued certificate on its way into the zip.
///
/// Private key only in `client_pem` -> wiped on drop.
struct Item {
    target: Target,
    dir: String,
    cert_pem: String,
    client_pem: Zeroizing<String>,
    serial: String,
    sha256: String,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
}

/// `manifest.csv`: which certificate belongs to which device.
fn manifest(items: &[Item]) -> String {
    let mut out = line(&[
        "endpoint_id",
        "device_id",
        "device_serial_number",
        "certificate_serial",
        "sha256_fingerprint",
        "not_before",
        "not_after",
        "directory",
    ]);
    for i in items {
        out.push_str(&line(&[
            &i.target.endpoint_id,
            &i.target.id.to_string(),
            i.target.serial_number.as_deref().unwrap_or_default(),
            &i.serial,
            &i.sha256,
            &ts(i.not_before),
            &ts(i.not_after),
            &i.dir,
        ]));
    }
    out
}

fn readme(now: OffsetDateTime, days: u32, count: usize) -> String {
    format!(
        "\
Dhonomos USP Agent certificates
===============================

Created {created} for {count} Agent(s), each valid for {days} days (see manifest.csv for the
exact dates).

Contents
  ca.pem                     The CA certificate that signed them. Every device must trust it.
  manifest.csv               EndpointID, certificate serial, SHA-256 fingerprint and validity
                             of every certificate, and the directory that holds it.
  <directory>/client.pem     The device's certificate followed by its private key (the format
                             of obuspa -a). This is the file to install.
  <directory>/cert.pem       The certificate alone, without the key.

Installing
  1. Find the device's directory in manifest.csv (by its EndpointID).
  2. Copy its client.pem to the device, for example /etc/obuspa/client.pem, with mode 0600,
     owned by the user that runs the Agent.
  3. Point the Agent at it (obuspa: -a /etc/obuspa/client.pem) and make sure the device
     trusts ca.pem.
  4. Delete this bundle and every copy of client.pem from your computer once all devices are
     done. Dhonomos does not keep the private keys; they exist only here.

A device connects with its certificate only: the EndpointID in the certificate must be the
one the device uses. If a device or a client.pem is lost or leaked, ask a Dhonomos
administrator to revoke the certificate.
",
        created = ts(now),
    )
}

/// ZIP timestamp of `t` (DOS format starts in 1980).
fn zip_time(t: OffsetDateTime) -> DateTime {
    u16::try_from(t.year())
        .ok()
        .and_then(|year| {
            DateTime::from_date_and_time(
                year,
                u8::from(t.month()),
                t.day(),
                t.hour(),
                t.minute(),
                t.second(),
            )
            .ok()
        })
        .unwrap_or_default()
}

/// The encrypted zip: each entry AES-256 under `password`.
/// Names + sizes stay readable, as in any zip.
fn build_zip(
    ca_pem: &str,
    items: &[Item],
    password: &str,
    now: OffsetDateTime,
    days: u32,
) -> Result<Vec<u8>, zip::result::ZipError> {
    let stamp = zip_time(now);
    let options = |mode: u32| {
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .last_modified_time(stamp)
            .unix_permissions(mode)
            .with_aes_encryption(AesMode::Aes256, password)
    };
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let mut put = |name: &str, mode: u32, contents: &str| -> Result<(), zip::result::ZipError> {
        zip.start_file(name, options(mode))?;
        zip.write_all(contents.as_bytes())?;
        Ok(())
    };
    put("README.txt", 0o644, &readme(now, days, items.len()))?;
    put("ca.pem", 0o644, ca_pem)?;
    put("manifest.csv", 0o644, &manifest(items))?;
    for i in items {
        put(&format!("{}/client.pem", i.dir), 0o600, &i.client_pem)?;
        put(&format!("{}/cert.pem", i.dir), 0o644, &i.cert_pem)?;
    }
    Ok(zip.finish()?.into_inner())
}

/// Built bundle: zip + what to record.
struct Built {
    zip: Vec<u8>,
    certificates: Vec<NewCertificate>,
    /// Agents to register with the certificates.
    new_devices: Vec<NewUspDevice>,
    items: Vec<Item>,
}

/// New key + certificate per target (EndpointID order) -> zip.
fn build_bundle(
    ca: &Ca,
    mut targets: Vec<Target>,
    days: u32,
    password: &str,
    now: OffsetDateTime,
) -> Result<Built, ApiError> {
    targets.sort_by(|a, b| a.endpoint_id.cmp(&b.endpoint_id));
    let dirs = dir_names(targets.iter().map(|t| t.endpoint_id.as_str()));
    let mut items = Vec::with_capacity(targets.len());
    for (target, dir) in targets.into_iter().zip(dirs) {
        let profile = Profile {
            endpoint_id: target.endpoint_id.clone(),
            days,
            ..Profile::default()
        };
        let mut issued = ca
            .issue(&profile)
            .map_err(|e| unprocessable(e.to_string()))?;
        let key = Zeroizing::new(issued.key_pem.take().ok_or_else(|| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "no private key was generated".into(),
            )
        })?);
        items.push(Item {
            client_pem: client_pem(&issued.cert_pem, &key),
            target,
            dir,
            cert_pem: issued.cert_pem,
            serial: issued.serial,
            sha256: issued.sha256,
            not_before: issued.not_before,
            not_after: issued.not_after,
        });
    }
    let zip = build_zip(ca.cert_pem(), &items, password, now, days).map_err(|e| {
        tracing::error!(error = %e, "building the certificate bundle failed");
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not build the bundle".into(),
        )
    })?;
    let certificates = items
        .iter()
        .map(|i| NewCertificate {
            device_id: i.target.id,
            serial: i.serial.clone(),
            fingerprint: i.sha256.clone(),
            not_after: i.not_after,
        })
        .collect();
    let new_devices = items
        .iter()
        .filter_map(|i| {
            i.target.create.as_ref().map(|tags| NewUspDevice {
                id: i.target.id,
                endpoint_id: i.target.endpoint_id.clone(),
                tags: tags.clone(),
            })
        })
        .collect();
    Ok(Built {
        zip,
        certificates,
        new_devices,
        items,
    })
}

/// `20261012T093045Z`, for file names.
fn compact_utc(t: OffsetDateTime) -> String {
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// Filter device `d` as a bundle target.
fn target_of(d: Device) -> CertificateTarget {
    CertificateTarget {
        id: d.id,
        protocol: d.protocol,
        endpoint_id: d.endpoint_id,
        oui: d.oui,
        serial_number: d.serial_number,
        status: d.status,
        tags: d.tags,
    }
}

/// Devices a filter selects, retired left out; refused if more than a bundle takes.
async fn filtered(s: &AppState, filter: &str) -> Result<Vec<CertificateTarget>, ApiError> {
    // Parse alone first: a stray parenthesis must not escape its group.
    FilterExpr::parse(filter).map_err(|e| unprocessable(e.to_string()))?;
    let expr = FilterExpr::parse(&format!("({filter}) and status != retired"))
        .map_err(|e| unprocessable(e.to_string()))?;
    let (devices, total) = s
        .store
        .search_devices(
            s.config.tenant_id,
            &DeviceSearch {
                filter: Some(expr),
                ..DeviceSearch::default()
            },
            MAX_DEVICES as i64 + 1,
            0,
        )
        .await?;
    if total > MAX_DEVICES as i64 {
        return Err(unprocessable(format!(
            "the filter matches {total} devices; at most {MAX_DEVICES} per request"
        )));
    }
    Ok(devices.into_iter().map(target_of).collect())
}

#[utoipa::path(
    post,
    path = "/api/v1/certificates/bundle",
    tag = "devices",
    operation_id = "issue_certificate_bundle",
    summary = "Issue Agent certificates as an encrypted zip",
    description = "ADR-099. Dhonomos generates a key and a certificate for each named device and returns them as one AES-256 encrypted zip, for the person who installs them on the devices. The devices need not have connected. Name them by `device_ids`, `endpoint_ids`, `targets` (an EndpointID, or `oui` and `serial_number`: the EndpointID is `os::<OUI in capitals>-<serial>`) and `filter` (the language of `GET /devices?filter=`; retired devices are left out), in any combination, up to 1,000 in all. A CWMP device with an OUI and a serial number stands for the Agent with that EndpointID. With `create_missing`, an Agent named by `endpoint_ids` or `targets` that does not exist yet is pre-registered with `tags`, and so is the Agent a CWMP device stands for (with the CWMP device's tags); the devices are registered together with the certificates, only once the zip exists. The zip holds `README.txt`, `ca.pem`, `manifest.csv` and, per device, a directory named after its EndpointID with `client.pem` (certificate, then private key: the format of `obuspa -a`) and `cert.pem`. The certificates are recorded like those of `POST /devices/{id}/certificate`, so each EndpointID is bound to certificates from now on; the private keys and the password are not stored. Nothing is issued or registered if any entry is unusable. The headers `X-Certificates-Issued` and `X-Devices-Created` count the certificates and the devices registered for them. Needs an account without a device scope.",
    request_body = BundleRequest,
    responses(
        (status = 200, description = "The zip (`application/zip`, `Content-Disposition: attachment`, `Cache-Control: no-store`)", content_type = "application/zip",
            headers(
                ("X-Certificates-Issued" = u32, description = "Certificates in the zip"),
                ("X-Devices-Created" = u32, description = "Devices registered together with them"),
            )),
        (status = 404, description = "Certificate issuance is disabled (`--usp-ca-dir`)"),
        (status = 413, description = "The request body is too large"),
        (status = 422, description = "No devices, more than 1,000, a password shorter than 12 characters or longer than 1,024 bytes, `days` out of range, a filter that does not parse, or devices that are unknown, retired, listed twice, cannot get an EndpointID or (without `create_missing`) do not exist (listed in the error; nothing is issued or registered)"),
    ),
)]
async fn issue_bundle(
    State(s): State<Arc<AppState>>,
    body: Result<Json<BundleRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let ca = s.config.ca.clone().ok_or_else(|| {
        ApiError(
            StatusCode::NOT_FOUND,
            "certificate issuance is not enabled (--usp-ca-dir)".into(),
        )
    })?;
    let Json(req) = body.map_err(|e| ApiError(e.status(), e.body_text()))?;
    let password = Zeroizing::new(req.password);
    check_password(&password)?;
    let days = check_days(req.days)?;
    let filter = req
        .filter
        .as_deref()
        .map(str::trim)
        .filter(|f| !f.is_empty());
    let named = req.device_ids.len() + req.endpoint_ids.len() + req.targets.len();
    if named == 0 && filter.is_none() {
        return Err(unprocessable(
            "name at least one device (device_ids, endpoint_ids, targets or filter)".into(),
        ));
    }
    if named > MAX_DEVICES {
        return Err(unprocessable(format!(
            "at most {MAX_DEVICES} devices per request"
        )));
    }
    let tags = clean_tags(&req.tags)?;
    let from_filter = match filter {
        Some(f) => filtered(&s, f).await?,
        None => Vec::new(),
    };
    let targets: Vec<Named> = req
        .targets
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let shown = match (&t.endpoint_id, &t.oui, &t.serial_number) {
                (Some(eid), None, None) => quote(eid),
                (eid, oui, serial) => quote(
                    &[eid, oui, serial]
                        .into_iter()
                        .flatten()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(" "),
                ),
            };
            Named {
                label: format!("target {} ({shown})", i + 1),
                endpoint_id: usp_endpoint_id(
                    t.endpoint_id.as_deref(),
                    t.oui.as_deref(),
                    t.serial_number.as_deref(),
                ),
            }
        })
        .collect();

    // DB rows: given names + Agents of the CWMP devices among them.
    let eids: Vec<String> = req
        .endpoint_ids
        .iter()
        .cloned()
        .chain(targets.iter().filter_map(|t| t.endpoint_id.clone().ok()))
        .collect();
    let mut known = s
        .store
        .certificate_targets(s.config.tenant_id, &req.device_ids, &eids)
        .await?;
    let twins: Vec<String> = known
        .iter()
        .chain(&from_filter)
        .filter(|r| r.protocol != "usp")
        .filter_map(|r| derived_for(r).ok())
        .collect();
    if !twins.is_empty() {
        known.extend(
            s.store
                .certificate_targets(s.config.tenant_id, &[], &twins)
                .await?,
        );
    }
    known.extend(from_filter.iter().cloned());
    let wanted = Wanted {
        device_ids: &req.device_ids,
        endpoint_ids: &req.endpoint_ids,
        targets: &targets,
        create_missing: req.create_missing,
        tags: &tags,
    };
    let targets = plan(&wanted, &known, &from_filter).map_err(|problems| refusal(&problems))?;
    if targets.is_empty() {
        return Err(unprocessable("the request names no devices".into()));
    }
    if targets.len() > MAX_DEVICES {
        return Err(unprocessable(format!(
            "at most {MAX_DEVICES} devices per request"
        )));
    }

    let now = OffsetDateTime::now_utc();
    let built =
        tokio::task::spawn_blocking(move || build_bundle(&ca, targets, days, &password, now))
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "building the certificate bundle crashed");
                ApiError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not build the bundle".into(),
                )
            })??;

    // Record only after the zip exists, all together
    // -> failure here = nothing handed out, nothing registered.
    let by = actor(&s);
    s.store
        .record_certificates_creating(
            s.config.tenant_id,
            Some(&by),
            &built.new_devices,
            &built.certificates,
        )
        .await?;
    metrics::counter!("dhonomos_usp_certificates_issued_total", "via" => "bundle")
        .increment(built.items.len() as u64);
    audit(
        &s,
        "certificate.bundle",
        "tenant",
        s.config.tenant_id,
        json!({
            "count": built.items.len(),
            "days": days,
            "created": built.new_devices.len(),
            "created_devices": built.new_devices.iter().map(|d| json!({
                "device_id": d.id,
                "endpoint_id": d.endpoint_id,
                "tags": d.tags,
            })).collect::<Vec<_>>(),
            "certificates": built.items.iter().map(|i| json!({
                "endpoint_id": i.target.endpoint_id,
                "device_id": i.target.id,
                "serial": i.serial,
                "sha256": i.sha256,
            })).collect::<Vec<_>>(),
        }),
    )
    .await;
    let name = format!("usp-agent-certificates-{}.zip", compact_utc(now));
    Ok((
        [
            (header::CONTENT_TYPE, "application/zip".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
            (header::CACHE_CONTROL, "no-store".to_owned()),
            (
                header::HeaderName::from_static(ISSUED_HEADER),
                built.items.len().to_string(),
            ),
            (
                header::HeaderName::from_static(CREATED_HEADER),
                built.new_devices.len().to_string(),
            ),
        ],
        built.zip,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Read as _;

    use super::*;

    fn row(eid: Option<&str>, protocol: &str, status: &str) -> CertificateTarget {
        CertificateTarget {
            id: Uuid::now_v7(),
            protocol: protocol.into(),
            endpoint_id: eid.map(Into::into),
            oui: (protocol == "cwmp").then(|| "b01408".to_owned()),
            serial_number: Some("SN-1".into()),
            status: status.into(),
            tags: Vec::new(),
        }
    }

    fn target(eid: &str) -> Target {
        Target {
            id: Uuid::now_v7(),
            endpoint_id: eid.into(),
            serial_number: Some("SN-1".into()),
            create: None,
        }
    }

    fn named(label: &str, eid: &str) -> Named {
        Named {
            label: label.into(),
            endpoint_id: Ok(eid.into()),
        }
    }

    /// `plan` for names, no filter.
    fn plan_names(
        device_ids: &[Uuid],
        endpoint_ids: &[String],
        known: &[CertificateTarget],
    ) -> Result<Vec<Target>, Vec<String>> {
        plan(
            &Wanted {
                device_ids,
                endpoint_ids,
                targets: &[],
                create_missing: false,
                tags: &[],
            },
            known,
            &[],
        )
    }

    #[test]
    fn directory_names_are_safe_and_unique() {
        assert_eq!(
            dir_stem("os::012345-AABBCCDDEEFF"),
            "os__012345-AABBCCDDEEFF"
        );
        assert_eq!(dir_stem("os::a/b\\c d"), "os__a_b_c_d");
        assert_eq!(dir_stem("../.."), "_", "no path tricks");
        assert_eq!(dir_stem(".."), "device");
        assert_eq!(dir_stem(".hidden."), "hidden");
        assert_eq!(dir_stem("os::ünï"), "os___n_");
        assert_eq!(dir_stem("nul"), "_nul");
        assert_eq!(dir_stem("COM1.txt"), "_COM1.txt");
        assert_eq!(dir_stem(&"x".repeat(300)).len(), MAX_DIR_CHARS);
        // Different EndpointIDs -> same name, also by case only.
        assert_eq!(
            dir_names(["os::a", "os:a", "OS::A", "os::a/", "os::b", "os::a"]),
            ["os__a", "os_a", "OS__A-2", "os__a_", "os__b", "os__a-3"]
        );
    }

    #[test]
    fn requested_devices_are_checked_before_anything_is_issued() {
        let alice = row(Some("os::alice"), "usp", "active");
        let bob = row(Some("os::bob"), "usp", "quarantined");
        let old = row(Some("os::old"), "usp", "retired");
        let mut cwmp = row(None, "cwmp", "active");
        cwmp.oui = None;
        let rows = [alice.clone(), bob.clone(), old.clone(), cwmp.clone()];

        let ok = plan_names(&[alice.id], &["os::bob".into()], &rows).unwrap();
        assert_eq!(
            ok.iter().map(|t| t.id).collect::<Vec<_>>(),
            [alice.id, bob.id]
        );
        assert!(ok.iter().all(|t| t.create.is_none()));

        let unknown = Uuid::now_v7();
        let problems = plan_names(
            &[unknown, cwmp.id, old.id, alice.id],
            &[
                "os::nobody".into(),
                "os::alice".into(),
                "os::old".into(),
                "os::bob\n".into(),
            ],
            &rows,
        )
        .unwrap_err();
        assert_eq!(
            problems,
            [
                format!("device {unknown} not found"),
                format!(
                    "device {} cannot be given an EndpointID: oui must be 6 hexadecimal digits \
                     (oui \"\", serial_number \"SN-1\")",
                    cwmp.id
                ),
                format!("device {} is retired", old.id),
                "endpoint_id \"os::nobody\" not found".to_owned(),
                "endpoint_id \"os::alice\" duplicates another entry".to_owned(),
                "endpoint_id \"os::old\" is retired".to_owned(),
                "endpoint_id \"os::bob\\n\" not found".to_owned(),
            ]
        );

        // Same device by ID + EndpointID, or same ID twice.
        assert!(plan_names(&[alice.id, alice.id], &[], &rows).is_err());
        assert!(plan_names(&[alice.id], &["os::alice".into()], &rows).is_err());
        // EndpointID a certificate cannot hold.
        let odd = row(Some("os::ünï"), "usp", "active");
        assert!(plan_names(&[odd.id], &[], &[odd]).is_err());
    }

    #[test]
    fn a_cwmp_device_stands_for_the_agent_derived_from_its_oui_and_serial_number() {
        let mut cwmp = row(None, "cwmp", "active");
        cwmp.tags = vec!["lab".into()];
        let by_id = |known: &[CertificateTarget]| plan_names(&[cwmp.id], &[], known);

        // No Agent yet -> registered with the CWMP device's tags.
        let made = by_id(std::slice::from_ref(&cwmp)).unwrap();
        assert_eq!(made.len(), 1);
        assert_eq!(made[0].endpoint_id, "os::B01408-SN-1");
        assert_eq!(made[0].create.as_deref(), Some(&["lab".to_owned()][..]));

        // Agent with that EndpointID exists -> used, nothing created.
        let twin = row(Some("os::B01408-SN-1"), "usp", "active");
        let used = by_id(&[cwmp.clone(), twin.clone()]).unwrap();
        assert_eq!((used[0].id, used[0].create.is_none()), (twin.id, true));

        // Agent retired -> refused. Retired CWMP device -> refused too.
        let gone = row(Some("os::B01408-SN-1"), "usp", "retired");
        assert!(by_id(&[cwmp.clone(), gone]).is_err());
        let mut retired = cwmp.clone();
        retired.status = "retired".into();
        assert_eq!(
            plan_names(&[retired.id], &[], &[retired.clone()]).unwrap_err(),
            [format!("device {} is retired", retired.id)]
        );

        // CWMP device + its Agent = one device named twice.
        let both = plan_names(&[cwmp.id, twin.id], &[], &[cwmp.clone(), twin.clone()]);
        assert_eq!(
            both.unwrap_err(),
            [format!("device {} duplicates another entry", twin.id)]
        );

        // Serial an EndpointID cannot hold.
        let mut odd = cwmp.clone();
        odd.serial_number = Some("S N".into());
        assert!(
            plan_names(&[odd.id], &[], &[odd]).unwrap_err()[0].contains("serial_number must be")
        );
    }

    /// `plan` for names, no IDs, no filter; tag `new` for registered Agents.
    fn plan_agents(
        create_missing: bool,
        endpoint_ids: &[String],
        targets: &[Named],
        known: &[CertificateTarget],
    ) -> Result<Vec<Target>, Vec<String>> {
        plan(
            &Wanted {
                device_ids: &[],
                endpoint_ids,
                targets,
                create_missing,
                tags: &["new".to_owned()],
            },
            known,
            &[],
        )
    }

    #[test]
    fn missing_agents_are_registered_only_when_asked() {
        let alice = row(Some("os::alice"), "usp", "active");
        let known = std::slice::from_ref(&alice);
        let bad = Named {
            label: "target 4 (\"x\")".into(),
            endpoint_id: Err("oui must be 6 hexadecimal digits".into()),
        };
        let targets = [
            named("target 1 (\"os::new\")", "os::new"),
            named("target 2 (\"b01408 S2\")", "os::B01408-S2"),
            named("target 3 (\"os::alice\")", "os::alice"),
        ];

        // Off (default): every Agent must exist; bad entry listed too.
        let mut all = vec![
            targets[0].clone(),
            targets[1].clone(),
            targets[2].clone(),
            bad,
        ];
        let problems = plan_agents(false, &[], &all, known).unwrap_err();
        assert_eq!(
            problems,
            [
                "target 1 (\"os::new\") not found",
                "target 2 (\"b01408 S2\") not found",
                "target 4 (\"x\"): oui must be 6 hexadecimal digits",
            ]
        );

        // On: bad entry still refuses all.
        let problems = plan_agents(true, &[], &all, known).unwrap_err();
        assert_eq!(
            problems,
            ["target 4 (\"x\"): oui must be 6 hexadecimal digits"]
        );
        all.pop();
        let made = plan_agents(true, &[], &all, known).unwrap();
        assert_eq!(
            made.iter()
                .map(|t| (t.endpoint_id.as_str(), t.create.is_some()))
                .collect::<Vec<_>>(),
            [
                ("os::new", true),
                ("os::B01408-S2", true),
                ("os::alice", false)
            ]
        );
        assert_eq!(made[0].create.as_deref(), Some(&["new".to_owned()][..]));
        assert_eq!(
            made[2].id, alice.id,
            "an existing Agent is used, not created"
        );

        // Raw EndpointIDs: same rule, checked before create.
        let eids = [
            "os::raw".to_owned(),
            "no-scheme".to_owned(),
            "os::a/b".to_owned(),
        ];
        let problems = plan_agents(true, &eids, &[], &[]).unwrap_err();
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems[0].starts_with("endpoint_id \"no-scheme\": endpoint_id must look like"));
        let problems = plan_agents(false, &eids, &[], &[]).unwrap_err();
        assert!(
            problems.iter().all(|p| p.ends_with("not found")),
            "{problems:?}"
        );
    }

    #[test]
    fn the_devices_of_a_filter_join_the_names_without_duplicates() {
        let alice = row(Some("os::alice"), "usp", "active");
        let bob = row(Some("os::bob"), "usp", "active");
        let mut cwmp = row(None, "cwmp", "active");
        cwmp.tags = vec!["east".into()];
        let known = [alice.clone(), bob.clone(), cwmp.clone()];
        let found = plan(
            &Wanted {
                device_ids: &[],
                endpoint_ids: &["os::alice".into()],
                targets: &[],
                create_missing: false,
                tags: &[],
            },
            &known,
            // Alice again != duplicate: a filter is a set.
            &[alice.clone(), bob.clone(), cwmp.clone()],
        )
        .unwrap();
        assert_eq!(
            found
                .iter()
                .map(|t| t.endpoint_id.as_str())
                .collect::<Vec<_>>(),
            ["os::alice", "os::bob", "os::B01408-SN-1"]
        );
        assert!(found[2].create.is_some(), "the CWMP device's Agent is new");

        // Filter CWMP device without usable name -> request refused.
        let mut bad = cwmp.clone();
        bad.id = Uuid::now_v7();
        bad.serial_number = None;
        let problems = plan(
            &Wanted {
                device_ids: &[],
                endpoint_ids: &[],
                targets: &[],
                create_missing: false,
                tags: &[],
            },
            &[],
            &[bad.clone()],
        )
        .unwrap_err();
        assert_eq!(problems.len(), 1);
        assert!(problems[0].starts_with(&format!("device {} cannot be given", bad.id)));
    }

    #[test]
    fn refusals_list_a_few_and_count_the_rest() {
        let problems: Vec<String> = (0..25).map(|i| format!("device {i} not found")).collect();
        let e = refusal(&problems);
        assert_eq!(e.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(e.1.contains("device 19 not found"), "{}", e.1);
        assert!(!e.1.contains("device 20 not found"), "{}", e.1);
        assert!(e.1.ends_with("(and 5 more)"), "{}", e.1);
        assert_eq!(quote("a\"b\nc"), "\"a\\\"b\\nc\"");
        assert!(quote(&"x".repeat(200)).ends_with("\"..."));
    }

    #[test]
    fn passwords_and_days_are_checked() {
        assert!(check_password("eleven char").is_err());
        assert!(check_password("twelve chars").is_ok());
        assert!(
            check_password("가나다라마바사아자차카타").is_ok(),
            "characters, not bytes"
        );
        assert!(check_password(&"x".repeat(MAX_PASSWORD_BYTES)).is_ok());
        assert!(check_password(&"x".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
        assert_eq!(check_days(None).unwrap(), 1095);
        assert_eq!(check_days(Some(1)).unwrap(), 1);
        assert_eq!(check_days(Some(3650)).unwrap(), 3650);
        assert!(check_days(Some(0)).is_err());
        assert!(check_days(Some(3651)).is_err());
    }

    #[test]
    fn client_pem_is_the_certificate_then_the_key() {
        assert_eq!(&*client_pem("CERT\n", "KEY\n"), "CERT\nKEY\n");
        assert_eq!(&*client_pem("CERT", "KEY\n"), "CERT\nKEY\n");
    }

    #[test]
    fn the_zip_needs_the_password_and_holds_what_the_operator_installs() {
        let ca = Ca::generate("Test CA").unwrap();
        let now = OffsetDateTime::now_utc();
        // "=" first -> spreadsheet would read the EndpointID as a formula.
        let mut new_one = target("os::b");
        new_one.create = Some(vec!["lab".into()]);
        let targets = vec![new_one, target("=cmd::a")];
        let built = build_bundle(&ca, targets, 30, "correct horse battery", now).unwrap();
        assert_eq!(built.certificates.len(), 2);
        assert_eq!(
            built
                .new_devices
                .iter()
                .map(|d| (d.endpoint_id.as_str(), d.tags.clone()))
                .collect::<Vec<_>>(),
            [("os::b", vec!["lab".to_owned()])],
            "only the Agent that does not exist is registered"
        );

        let open = || zip::ZipArchive::new(Cursor::new(built.zip.clone())).unwrap();
        let mut names: Vec<String> = open()
            .file_names()
            .map(|n| n.unwrap().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "README.txt",
                "_cmd__a/cert.pem",
                "_cmd__a/client.pem",
                "ca.pem",
                "manifest.csv",
                "os__b/cert.pem",
                "os__b/client.pem"
            ],
            "EndpointID order, so `=cmd::a` comes first"
        );
        // No password or wrong one -> nothing opens.
        assert!(open().by_name("os__b/client.pem").is_err());
        assert!(
            open()
                .by_name_decrypt("os__b/client.pem", b"wrong password!!")
                .is_err()
        );
        let mut text = String::new();
        open()
            .by_name_decrypt("os__b/client.pem", b"correct horse battery")
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(text.contains("-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\n"));
        let mut manifest = String::new();
        open()
            .by_name_decrypt("manifest.csv", b"correct horse battery")
            .unwrap()
            .read_to_string(&mut manifest)
            .unwrap();
        assert!(manifest.starts_with("endpoint_id,device_id,"), "{manifest}");
        assert!(manifest.contains("\r\n'=cmd::a,"), "{manifest}");
        assert!(manifest.contains("\r\nos::b,"), "{manifest}");
        // Audit trail + recorded rows: certificates only, never the keys.
        assert!(built.items.iter().all(|i| !i.sha256.is_empty()));
        assert!(
            !format!("{:?}", built.certificates).contains("PRIVATE KEY"),
            "recorded facts hold no key"
        );
    }
}
