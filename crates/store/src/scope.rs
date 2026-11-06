//! Device scopes (NB-04, ADR-074): devices an operator or API key may see + act on.
//! All conditions must hold.
//! SQL function `device_in_scope` (migration 0018) = same rule in queries.
//! Test `device_scopes_agree_in_sql_and_rust` (`tests/store.rs`) -> both on the same cases.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Device, DeviceFilter};

/// Device scope. Optional scope `None` = every device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceScope {
    /// Device has all of these tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Attributes = these exact values (CO-13), e.g. `{region: busan}`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
    /// `cwmp` or `usp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Manufacturer OUI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oui: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_class: Option<String>,
}

/// Query parameter of an optional scope: `NULL` (every device) or the scope JSON.
pub(crate) fn scope_param(scope: Option<&DeviceScope>) -> Option<serde_json::Value> {
    scope.map(|s| serde_json::to_value(s).unwrap_or_else(|_| serde_json::json!({})))
}

/// Merge 2 optional exact conditions. Both set + different -> `Err`.
fn both(a: &Option<String>, b: &Option<String>) -> Result<Option<String>, ()> {
    match (a, b) {
        (Some(x), Some(y)) if x != y => Err(()),
        (Some(x), _) | (None, Some(x)) => Ok(Some(x.clone())),
        (None, None) => Ok(None),
    }
}

/// `inner` at least as strict as `outer` on one exact condition.
fn implies(inner: &Option<String>, outer: &Option<String>) -> bool {
    outer.is_none() || inner == outer
}

impl DeviceScope {
    /// No conditions -> matches every device.
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
            && self.attributes.is_empty()
            && self.protocol.is_none()
            && self.oui.is_none()
            && self.product_class.is_none()
    }

    pub fn matches(&self, d: &Device) -> bool {
        self.tags.iter().all(|t| d.tags.contains(t))
            && self
                .attributes
                .iter()
                .all(|(k, v)| d.attributes.get(k).and_then(|x| x.as_str()) == Some(v.as_str()))
            && self.protocol.as_ref().is_none_or(|p| *p == d.protocol)
            && self
                .oui
                .as_ref()
                .is_none_or(|o| d.oui.as_deref() == Some(o.as_str()))
            && self
                .product_class
                .as_ref()
                .is_none_or(|p| *p == d.product_class)
    }

    /// Every device `f` can match is inside the scope, from the conditions alone.
    /// Not sure -> `false`.
    pub fn covers(&self, f: &DeviceFilter) -> bool {
        self.tags.iter().all(|t| f.tags.contains(t))
            && self
                .attributes
                .iter()
                .all(|(k, v)| f.attributes.get(k) == Some(v))
            && implies(&f.protocol, &self.protocol)
            && implies(&f.oui, &self.oui)
            && implies(&f.product_class, &self.product_class)
    }

    /// `f` narrowed to the scope. No device can match both -> `None`.
    pub fn restrict(&self, f: &DeviceFilter) -> Option<DeviceFilter> {
        let mut out = f.clone();
        for t in &self.tags {
            if !out.tags.contains(t) {
                out.tags.push(t.clone());
            }
        }
        for (k, v) in &self.attributes {
            match out.attributes.get(k) {
                Some(have) if have != v => return None,
                _ => {
                    out.attributes.insert(k.clone(), v.clone());
                }
            }
        }
        out.protocol = both(&f.protocol, &self.protocol).ok()?;
        out.oui = both(&f.oui, &self.oui).ok()?;
        out.product_class = both(&f.product_class, &self.product_class).ok()?;
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(json: serde_json::Value) -> DeviceScope {
        serde_json::from_value(json).unwrap_or_default()
    }

    fn filter(json: serde_json::Value) -> DeviceFilter {
        serde_json::from_value(json).unwrap_or_default()
    }

    #[test]
    fn unknown_keys_are_refused() {
        assert!(
            serde_json::from_value::<DeviceScope>(serde_json::json!({"status": "active"})).is_err()
        );
        assert!(serde_json::from_value::<DeviceScope>(serde_json::json!({"tags": ["a"]})).is_ok());
    }

    #[test]
    fn covers_and_restrict() {
        let s = scope(
            serde_json::json!({"tags": ["east"], "attributes": {"region": "busan"}, "protocol": "cwmp"}),
        );
        // Filter narrowed by the scope -> always covered.
        let wide = filter(serde_json::json!({"product_class": "HG8245"}));
        let narrowed = s.restrict(&wide).unwrap_or_default();
        assert!(s.covers(&narrowed));
        assert!(!s.covers(&wide));
        assert_eq!(narrowed.product_class.as_deref(), Some("HG8245"));
        assert_eq!(narrowed.tags, vec!["east"]);
        // Already inside -> unchanged.
        assert_eq!(s.restrict(&narrowed), Some(narrowed.clone()));
        // Contradiction -> no match.
        assert_eq!(
            s.restrict(&filter(serde_json::json!({"protocol": "usp"}))),
            None
        );
        assert_eq!(
            s.restrict(&filter(
                serde_json::json!({"attributes": {"region": "ulsan"}})
            )),
            None
        );
        // Device IDs alone -> not known to be inside.
        let ids = filter(serde_json::json!({"device_ids": [uuid::Uuid::nil()]}));
        assert!(!s.covers(&ids));
        assert!(DeviceScope::default().is_empty());
        assert!(!s.is_empty());
    }
}
