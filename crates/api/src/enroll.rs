//! Device names before first connect (ADR-099): bulk pre-registration (`POST /devices/bulk`)
//! and the names the certificate bundle takes.
//!
//! USP Agent = EndpointID, or OUI + serial -> `os::<OUI>-<serial>`
//! (TR-369 `os` authority scheme = how the firmware names itself).
//! CWMP device = OUI + product class + serial.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::routing::post;
use dhonomos_store::{CwmpIdentity, KnownDevice};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{ApiError, AppState, audit, clean_tags};

/// Max devices per bulk request.
pub(crate) const MAX_BULK: usize = 10_000;
/// Max body: 10,000 entries x a few 100 bytes.
const MAX_BODY_BYTES: usize = 4 << 20;
/// Max serial chars in an EndpointID.
/// With prefix + OUI -> within the 256-byte EndpointID limit of a certificate.
const MAX_SERIAL_CHARS: usize = 200;
/// Max chars of a CWMP OUI, product class or serial.
const MAX_CWMP_CHARS: usize = 256;
/// Max names listed in the audit record of a bulk request.
const AUDIT_SAMPLE: usize = 10;

/// Error text for an EndpointID that cannot be pre-registered.
pub(crate) const ENDPOINT_ID_RULE: &str =
    "endpoint_id must look like <authority-scheme>::<instance-id> without '/', '+' or '#'";

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new().route(
        "/devices/bulk",
        post(bulk_preregister).layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES)),
    )
}

/// `eid` OK as Agent EndpointID.
/// Same rule for single pre-registration, MQTT accounts + topics.
pub(crate) fn valid_endpoint_id(eid: &str) -> bool {
    dhonomos_core::broker::valid_endpoint_id(eid) && eid.contains("::")
}

/// Agent EndpointID `os::<OUI>-<serial>` from OUI + serial, or why none.
///
/// OUI = 6 hex digits, upper case in the EndpointID.
/// Serial kept as is; only chars safe in EndpointID, certificate + MQTT topic.
pub(crate) fn derived_endpoint_id(oui: &str, serial_number: &str) -> Result<String, String> {
    let oui = oui.trim();
    if oui.len() != 6 || !oui.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("oui must be 6 hexadecimal digits".into());
    }
    let serial = serial_number.trim();
    let chars = serial.chars().count();
    if chars == 0
        || chars > MAX_SERIAL_CHARS
        || !serial
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '@' | '~'))
    {
        return Err(format!(
            "serial_number must be 1-{MAX_SERIAL_CHARS} letters, digits or . _ - : @ ~"
        ));
    }
    Ok(format!("os::{}-{serial}", oui.to_ascii_uppercase()))
}

/// Trimmed request value; blank = none.
fn given(v: Option<&str>) -> Option<&str> {
    v.map(str::trim).filter(|v| !v.is_empty())
}

/// USP Agent EndpointID from `endpoint_id`, or `oui` + `serial_number`
/// ([`derived_endpoint_id`]), or why none.
pub(crate) fn usp_endpoint_id(
    endpoint_id: Option<&str>,
    oui: Option<&str>,
    serial_number: Option<&str>,
) -> Result<String, String> {
    match (given(endpoint_id), given(oui), given(serial_number)) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            Err("give endpoint_id, or oui and serial_number, not both".into())
        }
        (Some(eid), None, None) => {
            if valid_endpoint_id(eid) {
                Ok(eid.to_owned())
            } else {
                Err(ENDPOINT_ID_RULE.into())
            }
        }
        (None, Some(oui), Some(serial)) => derived_endpoint_id(oui, serial),
        (None, _, _) => Err("endpoint_id, or oui and serial_number, is required".into()),
    }
}

/// Device of a bulk request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Named {
    /// USP Agent EndpointID.
    Usp(String),
    Cwmp(CwmpIdentity),
}

/// One device of `POST /devices/bulk`.
/// `endpoint_id` -> USP Agent. `oui` + `serial_number` alone -> USP Agent `os::<OUI>-<serial>`.
/// Also `product_class` (even empty) -> CWMP device instead.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct BulkEntry {
    /// USP EndpointID, `<authority-scheme>::<instance-id>`.
    #[serde(default)]
    endpoint_id: Option<String>,
    /// Manufacturer OUI. USP Agent: 6 hex digits.
    #[serde(default)]
    oui: Option<String>,
    /// Serial number. USP Agent: letters, digits, `. _ - : @ ~`.
    #[serde(default)]
    serial_number: Option<String>,
    /// CWMP product class (may be empty). Present -> CWMP device.
    #[serde(default)]
    product_class: Option<String>,
}

impl BulkEntry {
    fn classify(&self) -> Result<Named, String> {
        let Some(class) = &self.product_class else {
            return usp_endpoint_id(
                self.endpoint_id.as_deref(),
                self.oui.as_deref(),
                self.serial_number.as_deref(),
            )
            .map(Named::Usp);
        };
        if given(self.endpoint_id.as_deref()).is_some() {
            return Err(
                "give endpoint_id, or oui, product_class and serial_number, not both".into(),
            );
        }
        let (Some(oui), Some(serial)) = (
            given(self.oui.as_deref()),
            given(self.serial_number.as_deref()),
        ) else {
            return Err("oui and serial_number are required".into());
        };
        let class = class.trim();
        if [oui, class, serial]
            .iter()
            .any(|v| v.chars().count() > MAX_CWMP_CHARS)
        {
            return Err(format!(
                "oui, product_class and serial_number are at most {MAX_CWMP_CHARS} characters"
            ));
        }
        Ok(Named::Cwmp(CwmpIdentity {
            oui: oui.to_owned(),
            product_class: class.to_owned(),
            serial_number: serial.to_owned(),
        }))
    }
}

/// Body of `POST /devices/bulk`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct BulkRequest {
    /// Devices, 1-10,000.
    #[schema(min_items = 1, max_items = 10000)]
    devices: Vec<BulkEntry>,
    /// Tags for the added devices.
    #[serde(default)]
    tags: Vec<String>,
    /// Report only, change nothing.
    #[serde(default)]
    dry_run: bool,
}

/// Outcome for one device of a bulk request.
#[derive(Debug, Serialize, utoipa::ToSchema)]
struct BulkResult {
    /// Position in request `devices`, from 0.
    index: usize,
    /// `added` (dry run: would be added), `exists` (already registered, unchanged) or `invalid`.
    status: &'static str,
    /// `usp` or `cwmp`; absent if the entry is not understood.
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<&'static str>,
    /// USP: Agent EndpointID (from `oui` + `serial_number` if not given).
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint_id: Option<String>,
    /// CWMP: manufacturer OUI.
    #[serde(skip_serializing_if = "Option::is_none")]
    oui: Option<String>,
    /// CWMP: product class.
    #[serde(skip_serializing_if = "Option::is_none")]
    product_class: Option<String>,
    /// CWMP: serial number.
    #[serde(skip_serializing_if = "Option::is_none")]
    serial_number: Option<String>,
    /// Existing device, or the added one (not in a dry run).
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<Uuid>,
    /// Existing device: `active`, `quarantined` or `retired`.
    #[serde(skip_serializing_if = "Option::is_none")]
    device_status: Option<String>,
    /// Why invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl BulkResult {
    /// Empty result, status `invalid`.
    fn blank(index: usize) -> Self {
        Self {
            index,
            status: "invalid",
            protocol: None,
            endpoint_id: None,
            oui: None,
            product_class: None,
            serial_number: None,
            device_id: None,
            device_status: None,
            error: None,
        }
    }

    /// Result with the fields of `name`.
    fn of(index: usize, name: &Named) -> Self {
        let mut r = Self::blank(index);
        match name {
            Named::Usp(eid) => {
                r.protocol = Some("usp");
                r.endpoint_id = Some(eid.clone());
            }
            Named::Cwmp(c) => {
                r.protocol = Some("cwmp");
                r.oui = Some(c.oui.clone());
                r.product_class = Some(c.product_class.clone());
                r.serial_number = Some(c.serial_number.clone());
            }
        }
        r
    }

    fn invalid(index: usize, error: String) -> Self {
        let mut r = Self::blank(index);
        r.error = Some(error);
        r
    }

    /// Status from the lookup: `added` if `known` was created (dry run: if missing).
    fn found(mut self, known: Option<&KnownDevice>, dry_run: bool) -> Self {
        match known {
            None if dry_run => self.status = "added",
            None => {
                self.error = Some("could not be registered, try again".into());
            }
            Some(k) if k.created => {
                self.status = "added";
                self.device_id = Some(k.id);
            }
            Some(k) => {
                self.status = "exists";
                self.device_id = Some(k.id);
                self.device_status = Some(k.status.clone());
            }
        }
        self
    }
}

/// Outcome of `POST /devices/bulk`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
struct BulkReport {
    /// Nothing changed.
    dry_run: bool,
    /// Entries in the request.
    total: usize,
    /// Entries added (dry run: would be).
    added: usize,
    /// Entries already registered.
    exists: usize,
    /// Entries not usable.
    invalid: usize,
    /// One result per entry, request order.
    results: Vec<BulkResult>,
}

/// Name for the audit record.
fn label(name: &Named) -> String {
    match name {
        Named::Usp(eid) => eid.clone(),
        Named::Cwmp(c) => format!("{}/{}/{}", c.oui, c.product_class, c.serial_number),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/devices/bulk",
    tag = "devices",
    operation_id = "preregister_devices",
    summary = "Pre-register many devices",
    description = "Registers up to 10,000 devices before they connect (CO-12), each as `POST /devices` would, and reports what happened to every entry; one unusable entry does not stop the others. An entry is a USP Agent named by `endpoint_id`, or by `oui` and `serial_number` alone (EndpointID `os::<OUI in capitals>-<serial>`: the TR-369 `os` authority scheme; the OUI is 6 hexadecimal digits, the serial number letters, digits and `. _ - : @ ~`), or, with a `product_class` as well (even an empty one), a CWMP device. All devices added get `tags`. Devices that exist are left as they are. With `dry_run` nothing is written: `added` means that the entry would be added. Audited as `device.preregister_bulk`. Not for accounts with a device scope.",
    request_body = BulkRequest,
    responses(
        (status = 200, description = "What happened to each entry", body = BulkReport),
        (status = 413, description = "The request body is too large"),
        (status = 422, description = "No devices, more than 10,000, or invalid tags"),
    ),
)]
async fn bulk_preregister(
    State(s): State<Arc<AppState>>,
    body: Result<Json<BulkRequest>, JsonRejection>,
) -> Result<Json<BulkReport>, ApiError> {
    let invalid = |m: String| ApiError(StatusCode::UNPROCESSABLE_ENTITY, m);
    let Json(req) = body.map_err(|e| ApiError(e.status(), e.body_text()))?;
    if req.devices.is_empty() {
        return Err(invalid("devices must not be empty".into()));
    }
    if req.devices.len() > MAX_BULK {
        return Err(invalid(format!("at most {MAX_BULK} devices per request")));
    }
    let tags = clean_tags(&req.tags)?;

    // Name per entry, or why not. Same device twice -> counted once (later = error).
    let mut seen: HashSet<Named> = HashSet::new();
    let entries: Vec<Result<Named, String>> = req
        .devices
        .iter()
        .map(|e| {
            e.classify().and_then(|name| {
                if seen.insert(name.clone()) {
                    Ok(name)
                } else {
                    Err("duplicates an earlier entry".into())
                }
            })
        })
        .collect();
    let mut eids = Vec::new();
    let mut identities = Vec::new();
    for name in entries.iter().flatten() {
        match name {
            Named::Usp(eid) => eids.push(eid.clone()),
            Named::Cwmp(c) => identities.push(c.clone()),
        }
    }
    let tenant = s.config.tenant_id;
    let (usp, cwmp) = if req.dry_run {
        (
            s.store.find_usp_devices(tenant, &eids).await?,
            s.store.find_cwmp_devices(tenant, &identities).await?,
        )
    } else {
        let usp = if eids.is_empty() {
            HashMap::new()
        } else {
            s.store
                .preregister_usp_devices(tenant, &eids, &tags)
                .await?
        };
        let cwmp = if identities.is_empty() {
            HashMap::new()
        } else {
            s.store
                .preregister_cwmp_devices(tenant, &identities, &tags)
                .await?
        };
        (usp, cwmp)
    };

    let results: Vec<BulkResult> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| match e {
            Err(error) => BulkResult::invalid(i, error.clone()),
            Ok(name @ Named::Usp(eid)) => BulkResult::of(i, name).found(usp.get(eid), req.dry_run),
            Ok(name @ Named::Cwmp(c)) => BulkResult::of(i, name).found(cwmp.get(c), req.dry_run),
        })
        .collect();
    let count = |status: &str| results.iter().filter(|r| r.status == status).count();
    let (added, exists) = (count("added"), count("exists"));
    // Understood but not registered -> also invalid.
    let invalid_count = results.len() - added - exists;

    if !req.dry_run && added > 0 {
        let sample: Vec<String> = entries
            .iter()
            .zip(&results)
            .filter(|(_, r)| r.status == "added")
            .filter_map(|(e, _)| e.as_ref().ok().map(label))
            .take(AUDIT_SAMPLE)
            .collect();
        audit(
            &s,
            "device.preregister_bulk",
            "tenant",
            tenant,
            json!({
                "count": added,
                "exists": exists,
                "invalid": invalid_count,
                "tags": tags,
                "sample": sample,
            }),
        )
        .await;
    }
    Ok(Json(BulkReport {
        dry_run: req.dry_run,
        total: results.len(),
        added,
        exists,
        invalid: invalid_count,
        results,
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn entry(
        eid: Option<&str>,
        oui: Option<&str>,
        serial: Option<&str>,
        class: Option<&str>,
    ) -> BulkEntry {
        BulkEntry {
            endpoint_id: eid.map(Into::into),
            oui: oui.map(Into::into),
            serial_number: serial.map(Into::into),
            product_class: class.map(Into::into),
        }
    }

    #[test]
    fn endpoint_ids_are_derived_from_the_oui_and_serial_number() {
        assert_eq!(
            derived_endpoint_id("b01408", "B01408123456").unwrap(),
            "os::B01408-B01408123456"
        );
        assert_eq!(
            derived_endpoint_id(" 00a0c9 ", " ab-1_2.3:4@5~6 ").unwrap(),
            "os::00A0C9-ab-1_2.3:4@5~6",
            "the OUI in capitals, the serial number as it is"
        );
        for oui in ["", "B0140", "B014080", "B0140G", "B0 408"] {
            assert!(derived_endpoint_id(oui, "1").is_err(), "{oui:?}");
        }
        for serial in ["", "  ", "a b", "a/b", "a+b", "a#b", "a,b", "ünï", "a\nb"] {
            assert!(derived_endpoint_id("B01408", serial).is_err(), "{serial:?}");
        }
        assert!(derived_endpoint_id("B01408", &"x".repeat(200)).is_ok());
        assert!(derived_endpoint_id("B01408", &"x".repeat(201)).is_err());
    }

    #[test]
    fn a_usp_agent_is_named_by_its_endpoint_id_or_by_oui_and_serial_number() {
        let name = |e, o, s| usp_endpoint_id(e, o, s);
        assert_eq!(name(Some(" os::a-1 "), None, None).unwrap(), "os::a-1");
        assert_eq!(
            name(None, Some("B01408"), Some("S1")).unwrap(),
            "os::B01408-S1"
        );
        assert_eq!(
            name(Some(""), Some("B01408"), Some("S1")).unwrap(),
            "os::B01408-S1",
            "a blank endpoint_id is none"
        );
        for bad in ["no-scheme", "os::a/b", "os::a+b", "os::#", "os::a\nb"] {
            assert_eq!(
                name(Some(bad), None, None).unwrap_err(),
                ENDPOINT_ID_RULE,
                "{bad:?}"
            );
        }
        assert!(name(Some("os::a"), Some("B01408"), None).is_err());
        assert!(name(Some("os::a"), None, Some("S1")).is_err());
        assert!(name(None, Some("B01408"), None).is_err());
        assert!(name(None, None, Some("S1")).is_err());
        assert!(name(None, None, None).is_err());
    }

    #[test]
    fn a_product_class_makes_the_entry_a_cwmp_device() {
        let cwmp = entry(None, Some(" 00AA00 "), Some("SN1"), Some(" Box ")).classify();
        assert_eq!(
            cwmp.unwrap(),
            Named::Cwmp(CwmpIdentity {
                oui: "00AA00".into(),
                product_class: "Box".into(),
                serial_number: "SN1".into(),
            })
        );
        // Empty product class = still CWMP (CWMP devices may have none).
        assert_eq!(
            entry(None, Some("00AA00"), Some("SN1"), Some(""))
                .classify()
                .unwrap(),
            Named::Cwmp(CwmpIdentity {
                oui: "00AA00".into(),
                product_class: String::new(),
                serial_number: "SN1".into(),
            })
        );
        // CWMP identity stored as given: no upper case, no char rules.
        assert!(
            entry(None, Some("00aa00"), Some("SN 1/2"), Some("Box"))
                .classify()
                .is_ok()
        );
        assert!(
            entry(None, Some("00AA00"), None, Some("Box"))
                .classify()
                .is_err()
        );
        assert!(entry(None, None, Some("SN1"), Some("")).classify().is_err());
        assert!(
            entry(Some("os::a"), None, None, Some("Box"))
                .classify()
                .is_err()
        );
        assert!(
            entry(None, Some("00AA00"), Some(&"x".repeat(257)), Some(""))
                .classify()
                .is_err()
        );
        assert_eq!(
            entry(None, Some("00aa00"), Some("S1"), None)
                .classify()
                .unwrap(),
            Named::Usp("os::00AA00-S1".into())
        );
    }
}
