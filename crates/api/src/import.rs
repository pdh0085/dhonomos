//! Bulk attribute import from CSV (CO-13): subscriber links from an OSS/BSS export.
//!
//! ```text
//! serial_number,subscriber,pppoe,plan
//! SN0001,S-1001,kim01@isp,gold
//! SN0002,S-1002,,silver        <- an empty cell leaves that attribute unchanged
//! ```
//!
//! 1st column = device key (`serial_number`, `endpoint_id` or `id`). Others = attribute keys.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::post;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{ApiError, AppState, MAX_ATTRIBUTE_VALUE, audit, valid_attribute_key};

/// Max rows per import.
const MAX_ROWS: usize = 200_000;
/// Rows per DB lookup / update query.
const BATCH: usize = 5_000;
/// Max entries per list in the response.
const MAX_REPORTED: usize = 100;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new().route(
        "/devices/attributes/import",
        post(import).layer(axum::extract::DefaultBodyLimit::max(32 << 20)),
    )
}

/// CSV text -> records. RFC 4180: quoted fields, doubled quotes, CRLF or LF. BOM dropped.
fn parse_csv(text: &str) -> Result<Vec<Vec<String>>, String> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut chars = text.trim_start_matches('\u{feff}').chars().peekable();
    let mut quoted = false;
    let mut line = 1;
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            (true, '"') => quoted = false,
            (true, c) => {
                if c == '\n' {
                    line += 1;
                }
                field.push(c);
            }
            (false, '"') if field.is_empty() => quoted = true,
            (false, ',') => record.push(std::mem::take(&mut field)),
            (false, '\r') if chars.peek() == Some(&'\n') => {}
            (false, '\n') => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
                line += 1;
            }
            (false, c) => field.push(c),
        }
    }
    if quoted {
        return Err(format!("line {line}: unterminated quoted field"));
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    // Drop blank lines.
    records.retain(|r| !(r.len() == 1 && r[0].trim().is_empty()));
    Ok(records)
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ImportQuery {
    /// Check + report only, no change.
    #[serde(default)]
    dry_run: bool,
}

#[utoipa::path(
    post,
    path = "/api/v1/devices/attributes/import",
    tag = "devices",
    operation_id = "import_device_attributes",
    summary = "Set device attributes from CSV",
    description = "CSV body (`text/csv`, UTF-8, up to 32 MiB / 200,000 rows). The header's first column is the device key (`serial_number`, `endpoint_id` or `id`), the others attribute keys. Empty cells leave an attribute unchanged. A serial number shared by several devices is reported and skipped.",
    params(ImportQuery),
    request_body(content = String, content_type = "text/csv"),
    responses(
        (status = 200, description = "What was (or, in a dry run, would be) changed; each list holds at most 100 entries", body = crate::schemas::ImportReport),
        (status = 400, description = "Not a usable CSV: bad header or key column, invalid attribute names, too many rows"),
    ),
)]
async fn import(
    State(s): State<Arc<AppState>>,
    Query(q): Query<ImportQuery>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let bad = |m: String| ApiError(StatusCode::BAD_REQUEST, m);
    let text = std::str::from_utf8(&body).map_err(|_| bad("the CSV must be UTF-8".into()))?;
    let mut records = parse_csv(text).map_err(bad)?.into_iter();
    let header = records
        .next()
        .ok_or_else(|| bad("the CSV is empty".into()))?;
    let header: Vec<String> = header.iter().map(|h| h.trim().to_owned()).collect();
    let key_column = header.first().map(String::as_str).unwrap_or_default();
    if !matches!(key_column, "serial_number" | "endpoint_id" | "id") {
        return Err(bad(
            "the first column must be serial_number, endpoint_id or id".into(),
        ));
    }
    let keys = &header[1..];
    if keys.is_empty() {
        return Err(bad("no attribute columns".into()));
    }
    if let Some(k) = keys.iter().find(|k| !valid_attribute_key(k)) {
        return Err(bad(format!(
            "attribute {k:?}: letters, digits, _ - . and at most 64 characters"
        )));
    }
    // Device key -> attribute changes. Same device in 2 rows -> later row wins per attribute.
    let mut changes: BTreeMap<String, serde_json::Map<String, Value>> = BTreeMap::new();
    let mut invalid = Vec::new();
    let mut rows = 0usize;
    for (i, record) in records.enumerate() {
        rows += 1;
        if rows > MAX_ROWS {
            return Err(bad(format!("at most {MAX_ROWS} rows per import")));
        }
        let line = i + 2;
        let key = record.first().map(|k| k.trim()).unwrap_or_default();
        if key.is_empty() || record.len() > header.len() {
            invalid.push(json!({ "line": line, "error": "missing key or too many fields" }));
            continue;
        }
        if let Some(v) = record
            .iter()
            .skip(1)
            .find(|v| v.len() > MAX_ATTRIBUTE_VALUE)
        {
            invalid.push(json!({ "line": line, "error": format!(
                "a value is longer than {MAX_ATTRIBUTE_VALUE} characters ({}...)",
                v.chars().take(20).collect::<String>()) }));
            continue;
        }
        let entry = changes.entry(key.to_owned()).or_default();
        for (k, v) in keys.iter().zip(record.iter().skip(1)) {
            if !v.trim().is_empty() {
                entry.insert(k.clone(), json!(v.trim()));
            }
        }
    }
    changes.retain(|_, c| !c.is_empty());
    let wanted: Vec<String> = changes.keys().cloned().collect();
    let (mut found, mut ambiguous): (HashMap<String, Uuid>, Vec<String>) =
        (HashMap::new(), Vec::new());
    for chunk in wanted.chunks(BATCH) {
        let mut seen: HashMap<String, Vec<Uuid>> = HashMap::new();
        for (k, id) in s
            .store
            .devices_by_key(s.config.tenant_id, key_column, chunk)
            .await?
        {
            seen.entry(k).or_default().push(id);
        }
        for (k, ids) in seen {
            if ids.len() == 1 {
                found.insert(k, ids[0]);
            } else {
                ambiguous.push(k);
            }
        }
    }
    let unknown: Vec<&String> = wanted
        .iter()
        .filter(|k| !found.contains_key(*k) && !ambiguous.contains(k))
        .collect();
    let mut updated = 0;
    if !q.dry_run {
        let pairs: Vec<(Uuid, Value)> = changes
            .iter()
            .filter_map(|(k, c)| Some((*found.get(k)?, Value::Object(c.clone()))))
            .collect();
        for chunk in pairs.chunks(BATCH) {
            let (ids, patches): (Vec<Uuid>, Vec<Value>) = chunk.iter().cloned().unzip();
            updated += s
                .store
                .merge_attributes(s.config.tenant_id, &ids, &patches)
                .await?;
        }
        audit(
            &s,
            "device.attributes.import",
            "tenant",
            s.config.tenant_id,
            json!({ "rows": rows, "key": key_column, "attributes": keys,
                    "updated": updated, "unknown": unknown.len(), "ambiguous": ambiguous.len() }),
        )
        .await;
    }
    ambiguous.sort();
    Ok(Json(json!({
        "dry_run": q.dry_run,
        "rows": rows,
        "matched": found.len(),
        "updated": updated,
        "unknown": unknown.iter().take(MAX_REPORTED).collect::<Vec<_>>(),
        "unknown_count": unknown.len(),
        "ambiguous": ambiguous.iter().take(MAX_REPORTED).collect::<Vec<_>>(),
        "invalid": invalid.iter().take(MAX_REPORTED).collect::<Vec<_>>(),
        "invalid_count": invalid.len(),
    })))
}

#[cfg(test)]
mod tests {
    use super::parse_csv;

    #[test]
    fn csv_records() {
        let r = parse_csv("\u{feff}a,b\r\n\"x, y\",\"say \"\"hi\"\"\"\n\nlast,\"two\nlines\"")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            r,
            [
                vec!["a", "b"],
                vec!["x, y", "say \"hi\""],
                vec!["last", "two\nlines"],
            ]
        );
        assert_eq!(parse_csv("a,").unwrap_or_default(), [vec!["a", ""]]);
        assert!(parse_csv("a,\"open").is_err());
    }
}
