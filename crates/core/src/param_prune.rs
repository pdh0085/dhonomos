//! Drop stored params a whole-object read no longer returns (ADR-111).
//! Snapshot otherwise upsert-only -> row the device stopped reporting (firmware change,
//! removed instance) would stay forever.
//!
//! Read of object path `P` OK -> rows stored under `P` vs every path of the response as the
//! device sent it (not the part the limits let in -> a limit never deletes anything):
//!
//! - [`Mode::Values`] (CWMP GetParameterValues, USP Get): leaf missing in response -> dropped;
//!   object row only if under a vanished instance (values reads never name objects -> empty
//!   table must stay).
//! - [`Mode::Names`] (CWMP GetParameterNames, whole subtree): object row missing -> dropped,
//!   also any row under a vanished instance; leaf of a live object stays (leaves = job of the
//!   values read).

use std::collections::HashSet;

use dhonomos_store::Store;
use tracing::{info, warn};
use uuid::Uuid;

/// Kind of read the response answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// GPV (CWMP) or Get (USP).
    Values,
    /// GPN of the whole subtree (CWMP).
    Names,
}

/// `true` -> successful read of `path` may drop rows under it.
/// = object path under a data model root, no wildcard or search expression.
pub(crate) fn prunable(path: &str) -> bool {
    path.ends_with('.')
        && (path.starts_with("Device.") || path.starts_with("InternetGatewayDevice."))
        && !path.contains(['*', '[', ']', '{', '}'])
}

/// Every path of a response + every `.`-terminated prefix of them (= still present).
pub(crate) struct Reported<'a> {
    paths: HashSet<&'a str>,
    prefixes: HashSet<&'a str>,
}

impl<'a> Reported<'a> {
    pub(crate) fn new(paths: impl IntoIterator<Item = &'a str>) -> Self {
        let mut out = Self {
            paths: HashSet::new(),
            prefixes: HashSet::new(),
        };
        for path in paths {
            out.paths.insert(path);
            for (i, _) in path.match_indices('.') {
                out.prefixes.insert(&path[..=i]);
            }
        }
        out
    }

    /// Some reported path starts with `prefix` (ends with `.`).
    fn present(&self, prefix: &str) -> bool {
        self.prefixes.contains(prefix)
    }
}

/// Instance number (`2`) or alias in brackets (`[cpe-1]`).
fn is_instance(segment: &str) -> bool {
    (!segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()))
        || (segment.len() >= 2 && segment.starts_with('[') && segment.ends_with(']'))
}

/// `path` (under `prefix`) is below an instance under `prefix` that the response no longer
/// has.
fn under_vanished_instance(prefix: &str, path: &str, reported: &Reported<'_>) -> bool {
    let rest = &path[prefix.len()..];
    let mut end = prefix.len();
    // Only segments followed by a dot: last segment of a leaf = param name.
    for (i, _) in rest.match_indices('.') {
        let start = end;
        end = prefix.len() + i + 1;
        if is_instance(&path[start..end - 1]) && !reported.present(&path[..end]) {
            return true;
        }
    }
    false
}

/// Qualifying read of `prefix` that must drop nothing.
/// Whole tree (`Device.`, `InternetGatewayDevice.`) read with nothing under it -> broken
/// answer, not an empty device. Emptied object below the root -> pruned as usual.
fn keep_all(prefix: &str, reported: &Reported<'_>) -> bool {
    prefix.matches('.').count() == 1 && !reported.present(prefix)
}

/// Rows of `stored` under `prefix` to drop after a read of `prefix` answered `reported`.
/// Never in the result: `prefix` itself, rows outside it.
pub(crate) fn stale_paths(
    prefix: &str,
    stored: &[String],
    reported: &Reported<'_>,
    mode: Mode,
) -> Vec<String> {
    stored
        .iter()
        .filter(|path| path.starts_with(prefix) && path.as_str() != prefix)
        .filter(|path| {
            let object = path.ends_with('.');
            let missing = !reported.paths.contains(path.as_str());
            let vanished = || under_vanished_instance(prefix, path, reported);
            match mode {
                Mode::Values if object => vanished(),
                Mode::Values => missing,
                Mode::Names => (object && missing) || vanished(),
            }
        })
        .cloned()
        .collect()
}

/// Drop the device's rows under `prefix` a read of it no longer returns, if [`prunable`]
/// -> count dropped. Store error -> logged, counts as 0: the read itself succeeded.
pub(crate) async fn prune(
    store: &Store,
    device: Uuid,
    prefix: &str,
    reported: &Reported<'_>,
    mode: Mode,
) -> u64 {
    if !prunable(prefix) {
        return 0;
    }
    if keep_all(prefix, reported) {
        warn!(%device, prefix, "a read of the whole tree returned nothing; keeping the stored parameters");
        return 0;
    }
    let done = async {
        let stored = store.param_paths_under(device, prefix).await?;
        let stale = stale_paths(prefix, &stored, reported, mode);
        store.delete_params_exact(device, &stale).await
    }
    .await;
    match done {
        Ok(removed) => {
            if removed > 0 {
                info!(%device, prefix, removed, "dropped stored parameters the device no longer reports");
            }
            removed
        }
        Err(error) => {
            warn!(%device, prefix, %error, "dropping parameters the device no longer reports failed");
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stale(prefix: &str, stored: &[&str], reported: &[&str], mode: Mode) -> Vec<String> {
        let stored: Vec<String> = stored.iter().map(|s| (*s).to_owned()).collect();
        let mut out = stale_paths(
            prefix,
            &stored,
            &Reported::new(reported.iter().copied()),
            mode,
        );
        out.sort();
        out
    }

    #[test]
    fn prunable_paths() {
        for p in [
            "Device.",
            "Device.Ethernet.",
            "InternetGatewayDevice.LANDevice.",
        ] {
            assert!(prunable(p), "{p}");
        }
        for p in [
            "",
            "VirtualParameters.",
            "Device.DeviceInfo.UpTime",
            "Device.Ethernet.Interface.*.",
            "Device.WiFi.SSID.[Enable==true].",
            "Device.X.{i}.",
        ] {
            assert!(!prunable(p), "{p}");
        }
    }

    #[test]
    fn an_empty_read_of_a_whole_tree_keeps_everything() {
        let none = Reported::new([]);
        assert!(keep_all("Device.", &none));
        assert!(keep_all("InternetGatewayDevice.", &none));
        assert!(!keep_all(
            "Device.",
            &Reported::new(["Device.DeviceInfo.UpTime"])
        ));
        // Paths outside the tree != answer for it.
        assert!(keep_all(
            "Device.",
            &Reported::new(["InternetGatewayDevice.DeviceInfo.UpTime"])
        ));
        // Emptied table below the root -> pruned.
        assert!(!keep_all("Device.Hosts.Host.", &none));
    }

    #[test]
    fn values_drop_missing_leaves_only_under_the_prefix() {
        let stored = [
            "Device.Ethernet.",
            "Device.Ethernet.InterfaceNumberOfEntries",
            "Device.Ethernet.Gone",
            "Device.DeviceInfo.UpTime",
            "VirtualParameters.x",
        ];
        assert_eq!(
            stale(
                "Device.Ethernet.",
                &stored,
                &["Device.Ethernet.InterfaceNumberOfEntries"],
                Mode::Values
            ),
            ["Device.Ethernet.Gone"]
        );
    }

    #[test]
    fn values_drop_a_vanished_instance_and_its_objects() {
        let stored = [
            "Device.Ethernet.Interface.1.",
            "Device.Ethernet.Interface.1.Name",
            "Device.Ethernet.Interface.1.Stats.",
            "Device.Ethernet.Interface.2.",
            "Device.Ethernet.Interface.2.Name",
            "Device.Ethernet.Interface.2.Stats.",
        ];
        assert_eq!(
            stale(
                "Device.Ethernet.",
                &stored,
                &["Device.Ethernet.Interface.1.Name"],
                Mode::Values
            ),
            [
                "Device.Ethernet.Interface.2.",
                "Device.Ethernet.Interface.2.Name",
                "Device.Ethernet.Interface.2.Stats.",
            ]
        );
    }

    #[test]
    fn values_keep_empty_tables() {
        let stored = [
            "Device.ManagementServer.ManageableDevice.",
            "Device.WiFi.AccessPoint.1.AssociatedDevice.",
        ];
        let reported = [
            "Device.ManagementServer.URL",
            "Device.WiFi.AccessPoint.1.SSIDReference",
        ];
        for prefix in ["Device.", "Device.ManagementServer.", "Device.WiFi."] {
            assert!(
                stale(prefix, &stored, &reported, Mode::Values).is_empty(),
                "{prefix}"
            );
        }
    }

    #[test]
    fn values_drop_a_vanished_alias_instance() {
        let stored = [
            "Device.X.[cpe-1].A",
            "Device.X.[cpe-2].",
            "Device.X.[cpe-2].Sub.",
        ];
        assert_eq!(
            stale("Device.X.", &stored, &["Device.X.[cpe-1].A"], Mode::Values),
            ["Device.X.[cpe-2].", "Device.X.[cpe-2].Sub."]
        );
    }

    #[test]
    fn names_drop_missing_objects_and_vanished_instances_only() {
        let stored = [
            "Device.Ethernet.Interface.",
            "Device.Ethernet.Interface.1.",
            "Device.Ethernet.Interface.1.Name",
            // Leaf of a live instance, missing in the names read.
            "Device.Ethernet.Interface.1.Enable",
            "Device.Ethernet.Interface.1.Stats.",
            "Device.Ethernet.InterfaceNumberOfEntries",
            "Device.Ethernet.Interface.2.",
            "Device.Ethernet.Interface.2.Name",
        ];
        let reported = [
            "Device.Ethernet.",
            "Device.Ethernet.Interface.",
            "Device.Ethernet.Interface.1.",
            "Device.Ethernet.Interface.1.Name",
        ];
        assert_eq!(
            stale("Device.Ethernet.", &stored, &reported, Mode::Names),
            [
                "Device.Ethernet.Interface.1.Stats.",
                "Device.Ethernet.Interface.2.",
                "Device.Ethernet.Interface.2.Name",
            ]
        );
    }
}
