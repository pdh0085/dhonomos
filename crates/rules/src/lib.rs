//! Provisioning scripts (CO-05): Rune scripts per device, in a sandbox.
//!
//! Script declares wanted state; nothing goes to the device during the run:
//!
//! ```rune
//! pub fn main(device, args) {
//!     if device.get("Device.WiFi.SSID.1.SSID") == Some("") {
//!         device.set("Device.WiFi.SSID.1.SSID", `Home-${device.serial}`);
//!     }
//!     if device.software_version != args["firmware"] {
//!         device.download(args["firmware_file"]);
//!     }
//!     device.log("checked");
//! }
//! ```
//!
//! Return -> run committed into [`Action`]s: values != stored, refreshes, reboot,
//! downloads, tag changes.
//! Script fails (error, `Err` result, instruction budget or memory limit) -> commits nothing.
//! Every run -> [`Trace`] of reads, declared values, logs.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rune::runtime::budget;
use rune::{Any, ContextError, Diagnostics, Module, Source, Sources, Unit, Value, Vm};

/// Source of device parameters for a script (stored snapshot).
pub trait Params: Send + Sync {
    /// Value + XML Schema type of one parameter.
    fn get(&self, path: &str) -> Option<(String, Option<String>)>;
    /// Parameters + values under an object path (`Device.WiFi.SSID.`).
    fn list(&self, prefix: &str) -> Vec<(String, String)>;
    /// Many parameters at once (commit). Unknown -> absent.
    fn get_many(&self, paths: &[String]) -> HashMap<String, (String, Option<String>)> {
        paths
            .iter()
            .filter_map(|p| Some((p.clone(), self.get(p)?)))
            .collect()
    }
}

/// Resource limits of one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// VM instructions.
    pub instructions: usize,
    /// Max bytes allocated by the script.
    pub memory: usize,
    /// Parameter reads (`get`, `list`); each may hit the DB.
    pub reads: usize,
    /// Max declared actions.
    pub actions: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            instructions: 1_000_000,
            memory: 16 << 20,
            reads: 1_000,
            actions: 1_000,
        }
    }
}

/// Requests of a committed run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Set a parameter (only declared values != stored).
    Set {
        path: String,
        value: String,
        /// XML Schema type.
        xsd_type: String,
    },
    /// Read parameters again.
    Refresh {
        /// Object paths end in `.`.
        path: String,
    },
    /// Firmware download of a stored file (by ID).
    Download {
        /// File ID.
        file: String,
    },
    /// Reboot, after all other actions.
    Reboot,
    /// Add a device tag.
    Tag {
        /// Tag.
        tag: String,
    },
    /// Remove a device tag.
    Untag {
        /// Tag.
        tag: String,
    },
    /// Computed value -> stored as `VirtualParameters.<name>` (CO-06), never sent to the device.
    /// Only values != stored.
    Virtual {
        /// Letters, digits, `_`.
        name: String,
        value: String,
    },
}

/// Prefix of virtual parameters in the parameter snapshot.
pub const VIRTUAL_PREFIX: &str = "VirtualParameters.";

/// Record of one run.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Trace {
    /// Parameters read + value seen.
    pub reads: Vec<(String, Option<String>)>,
    /// Values from `set`, before compare with stored values.
    pub declared: Vec<(String, String)>,
    /// `log` output.
    pub logs: Vec<String>,
    /// Wall-clock time.
    pub duration_ms: u64,
}

/// Result of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Committed actions; empty on failure.
    pub actions: Vec<Action>,
    /// Failure reason.
    pub error: Option<String>,
    pub trace: Trace,
}

/// Script compile errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScriptError {
    #[error("{0}")]
    Compile(String),
    #[error("the script has no `pub fn main(device, args)`")]
    NoMain,
    /// Runtime setup failed.
    #[error("script runtime: {0}")]
    Runtime(String),
}

/// Device data visible to the script.
#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    /// Dhonomos device ID.
    pub id: String,
    pub serial: String,
    pub oui: String,
    pub product_class: String,
    /// Firmware version.
    pub software_version: String,
    /// `cwmp` or `usp`.
    pub protocol: String,
    pub tags: Vec<String>,
    /// Events of the triggering Inform (CWMP) or notification (USP).
    pub events: Vec<String>,
    /// Device attributes (subscriber links, CO-13).
    pub attributes: BTreeMap<String, String>,
}

#[derive(Default)]
struct Recorder {
    trace: Trace,
    /// Declared values in order; later `set` of same path wins.
    sets: Vec<(String, String, Option<String>)>,
    refresh: Vec<String>,
    downloads: Vec<String>,
    reboot: bool,
    tags: Vec<(String, bool)>,
    /// Virtual parameters in order; later value of same name wins.
    virtuals: Vec<(String, String)>,
    reads_left: usize,
    actions_left: usize,
    /// First host-side error (read or action limit) -> run fails.
    error: Option<String>,
}

/// `device` argument of `main`.
#[derive(Any)]
#[rune(item = ::dhonomos)]
struct Device {
    #[rune(get)]
    id: String,
    #[rune(get)]
    serial: String,
    #[rune(get)]
    oui: String,
    #[rune(get)]
    product_class: String,
    #[rune(get)]
    software_version: String,
    #[rune(get)]
    protocol: String,
    tags: Vec<String>,
    events: Vec<String>,
    attributes: BTreeMap<String, String>,
    params: Arc<dyn Params>,
    rec: Arc<Mutex<Recorder>>,
}

/// Script value -> parameter value + type, if the value implies one.
/// Borrow, no `from_value`: that moves strings out of script variables.
fn value_text(value: &Value) -> Option<(String, Option<&'static str>)> {
    if let Ok(s) = value.borrow_string_ref() {
        return Some((s.to_string(), None));
    }
    if let Ok(b) = rune::from_value::<bool>(value.clone()) {
        return Some((b.to_string(), Some("boolean")));
    }
    if let Ok(i) = value.as_integer::<i64>() {
        return Some((
            i.to_string(),
            Some(if i < 0 { "int" } else { "unsignedInt" }),
        ));
    }
    None
}

impl Device {
    fn with<T>(&self, f: impl FnOnce(&mut Recorder) -> T) -> Option<T> {
        self.rec.lock().ok().map(|mut r| f(&mut r))
    }

    /// Take one read permit. None left -> false + error recorded.
    fn read_permit(&self) -> bool {
        self.with(|r| {
            if r.reads_left == 0 {
                r.error
                    .get_or_insert_with(|| "too many parameter reads".into());
                return false;
            }
            r.reads_left -= 1;
            true
        })
        .unwrap_or(false)
    }

    fn action_permit(&self) -> bool {
        self.with(|r| {
            if r.actions_left == 0 {
                r.error.get_or_insert_with(|| "too many actions".into());
                return false;
            }
            r.actions_left -= 1;
            true
        })
        .unwrap_or(false)
    }

    /// Stored value of a parameter.
    #[rune::function(keep, instance)]
    fn get(&self, path: &str) -> Option<String> {
        if !self.read_permit() {
            return None;
        }
        let value = self.params.get(path).map(|(v, _)| v);
        self.with(|r| r.trace.reads.push((path.to_owned(), value.clone())));
        value
    }

    /// Stored parameters under an object path, as `[path, value]` pairs.
    #[rune::function(keep, instance)]
    fn list(&self, prefix: &str) -> Vec<(String, String)> {
        if !self.read_permit() {
            return Vec::new();
        }
        let found = self.params.list(prefix);
        self.with(|r| {
            r.trace.reads.push((
                prefix.to_owned(),
                Some(format!("{} parameters", found.len())),
            ));
        });
        found
    }

    /// Declare wanted value of a parameter (string, integer or boolean).
    #[rune::function(keep, instance)]
    fn set(&self, path: &str, value: Value) {
        self.declare(path, &value, None);
    }

    /// `set` with explicit XML Schema type (`unsignedInt`, `dateTime`, ...).
    #[rune::function(keep, instance)]
    fn set_typed(&self, path: &str, value: Value, xsd_type: &str) {
        self.declare(path, &value, Some(xsd_type.to_owned()));
    }

    fn declare(&self, path: &str, value: &Value, xsd_type: Option<String>) {
        let Some((text, inferred)) = value_text(value) else {
            self.with(|r| {
                r.error.get_or_insert_with(|| {
                    format!("set({path:?}): the value must be a string, integer or boolean")
                });
            });
            return;
        };
        if !self.action_permit() {
            return;
        }
        let ty = xsd_type.or(inferred.map(str::to_owned));
        self.with(|r| {
            r.trace.declared.push((path.to_owned(), text.clone()));
            r.sets.retain(|(p, _, _)| p != path);
            r.sets.push((path.to_owned(), text, ty));
        });
    }

    /// Virtual parameter -> stored as `VirtualParameters.<name>`, never sent.
    #[rune::function(keep, instance)]
    fn set_virtual(&self, name: &str, value: Value) {
        let valid = !name.is_empty()
            && name.len() <= 64
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        let text = value_text(&value).map(|(t, _)| t);
        let (true, Some(text)) = (valid, text) else {
            self.with(|r| {
                r.error.get_or_insert_with(|| {
                    format!(
                        "set_virtual({name:?}): names are letters, digits and `_`; values strings, integers or booleans"
                    )
                });
            });
            return;
        };
        if !self.action_permit() {
            return;
        }
        self.with(|r| {
            r.trace
                .declared
                .push((format!("{VIRTUAL_PREFIX}{name}"), text.clone()));
            r.virtuals.retain(|(n, _)| n != name);
            r.virtuals.push((name.to_owned(), text));
        });
    }

    /// Read parameters again (object path ending in `.` -> subtree).
    #[rune::function(keep, instance)]
    fn refresh(&self, path: &str) {
        if self.action_permit() {
            self.with(|r| r.refresh.push(path.to_owned()));
        }
    }

    /// Install firmware: file stored in Dhonomos, by ID.
    #[rune::function(keep, instance)]
    fn download(&self, file: &str) {
        if self.action_permit() {
            self.with(|r| r.downloads.push(file.to_owned()));
        }
    }

    /// Reboot device after all other actions.
    #[rune::function(keep, instance)]
    fn reboot(&self) {
        self.with(|r| r.reboot = true);
    }

    /// Add a tag.
    #[rune::function(keep, instance)]
    fn tag(&self, tag: &str) {
        if self.action_permit() {
            self.with(|r| r.tags.push((tag.to_owned(), true)));
        }
    }

    /// Remove a tag.
    #[rune::function(keep, instance)]
    fn untag(&self, tag: &str) {
        if self.action_permit() {
            self.with(|r| r.tags.push((tag.to_owned(), false)));
        }
    }

    /// Device has this tag?
    #[rune::function(keep, instance)]
    fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }

    /// Device tags.
    #[rune::function(keep, instance)]
    fn tags(&self) -> Vec<String> {
        self.tags.clone()
    }

    /// Triggering Inform has this event? (`"1 BOOT"`, `"M Download"`, ...), case-insensitive.
    #[rune::function(keep, instance)]
    fn has_event(&self, code: &str) -> bool {
        self.events.iter().any(|e| e.eq_ignore_ascii_case(code))
    }

    /// Triggering events.
    #[rune::function(keep, instance)]
    fn events(&self) -> Vec<String> {
        self.events.clone()
    }

    /// Device attribute (subscriber link), e.g. `device.attribute("plan")`.
    #[rune::function(keep, instance)]
    fn attribute(&self, key: &str) -> Option<String> {
        self.attributes.get(key).cloned()
    }

    /// Add a line to the run trace.
    #[rune::function(keep, instance)]
    fn log(&self, message: &str) {
        self.with(|r| {
            if r.trace.logs.len() < 100 {
                r.trace.logs.push(message.chars().take(500).collect());
            }
        });
    }
}

fn module() -> Result<Module, ContextError> {
    let mut m = Module::with_crate("dhonomos")?;
    m.ty::<Device>()?;
    m.function_meta(Device::get__meta)?;
    m.function_meta(Device::list__meta)?;
    m.function_meta(Device::set__meta)?;
    m.function_meta(Device::set_typed__meta)?;
    m.function_meta(Device::set_virtual__meta)?;
    m.function_meta(Device::refresh__meta)?;
    m.function_meta(Device::download__meta)?;
    m.function_meta(Device::reboot__meta)?;
    m.function_meta(Device::tag__meta)?;
    m.function_meta(Device::untag__meta)?;
    m.function_meta(Device::has_tag__meta)?;
    m.function_meta(Device::tags__meta)?;
    m.function_meta(Device::has_event__meta)?;
    m.function_meta(Device::events__meta)?;
    m.function_meta(Device::log__meta)?;
    m.function_meta(Device::attribute__meta)?;
    Ok(m)
}

/// Compiled script; cheap to clone + share between threads.
#[derive(Clone)]
pub struct Script {
    name: String,
    unit: Arc<Unit>,
    runtime: Arc<rune::runtime::RuntimeContext>,
    paths: Arc<[String]>,
}

impl std::fmt::Debug for Script {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Script").field("name", &self.name).finish()
    }
}

impl Script {
    /// Compile `source`.
    /// No I/O for scripts: `print` & co disabled, no file, network or clock access.
    pub fn compile(name: &str, source: &str) -> Result<Self, ScriptError> {
        let runtime_err = |e: &dyn std::fmt::Display| ScriptError::Runtime(e.to_string());
        let mut context = rune::Context::with_config(false).map_err(|e| runtime_err(&e))?;
        context
            .install(module().map_err(|e| runtime_err(&e))?)
            .map_err(|e| runtime_err(&e))?;
        let runtime = Arc::new(context.runtime().map_err(|e| runtime_err(&e))?);
        let mut sources = Sources::new();
        sources
            .insert(Source::new(name, source).map_err(|e| runtime_err(&e))?)
            .map_err(|e| runtime_err(&e))?;
        let mut diagnostics = Diagnostics::new();
        let unit = rune::prepare(&mut sources)
            .with_context(&context)
            .with_diagnostics(&mut diagnostics)
            .build();
        let unit = match unit {
            Ok(u) if !diagnostics.has_error() => u,
            _ => {
                let mut out = rune::termcolor::Buffer::no_color();
                let _ = diagnostics.emit(&mut out, &sources);
                let text = String::from_utf8_lossy(out.as_slice()).trim().to_owned();
                return Err(ScriptError::Compile(if text.is_empty() {
                    "the script does not compile".into()
                } else {
                    text
                }));
            }
        };
        let script = Self {
            name: name.to_owned(),
            unit: Arc::new(unit),
            runtime,
            paths: literal_paths(source).into(),
        };
        let has_main = Vm::new(script.runtime.clone(), script.unit.clone())
            .lookup_function(["main"])
            .is_ok();
        if !has_main {
            return Err(ScriptError::NoMain);
        }
        Ok(script)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Parameter paths written literally in the source (also `set_virtual` names as
    /// `VirtualParameters.<name>`) -> worth one bulk read before a run.
    pub fn literal_paths(&self) -> &[String] {
        &self.paths
    }

    /// Run `main(device, args)` within `limits`.
    /// Blocking -> call from a blocking thread when `params` hits the DB.
    pub fn run(
        &self,
        device: &DeviceInfo,
        args: &BTreeMap<String, String>,
        params: Arc<dyn Params>,
        limits: Limits,
    ) -> Outcome {
        let start = Instant::now();
        let rec = Arc::new(Mutex::new(Recorder {
            reads_left: limits.reads,
            actions_left: limits.actions,
            ..Recorder::default()
        }));
        let dev = Device {
            id: device.id.clone(),
            serial: device.serial.clone(),
            oui: device.oui.clone(),
            product_class: device.product_class.clone(),
            software_version: device.software_version.clone(),
            protocol: device.protocol.clone(),
            tags: device.tags.clone(),
            events: device.events.clone(),
            attributes: device.attributes.clone(),
            params: params.clone(),
            rec: rec.clone(),
        };
        let args: HashMap<String, String> =
            args.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let mut vm = Vm::new(self.runtime.clone(), self.unit.clone());
        let result = budget::with(
            limits.instructions,
            rune::alloc::limit::with(limits.memory, || -> Result<(), String> {
                let out = vm.call(["main"], (dev, args)).map_err(|e| {
                    let text = e.to_string();
                    if text.contains("Limited") || text.contains("limited") {
                        "the script exceeded its instruction budget".to_owned()
                    } else if text.contains("allocation") || text.contains("memory") {
                        "the script exceeded its memory limit".to_owned()
                    } else {
                        text
                    }
                })?;
                // `main` may return `Result` -> `Err` = run failed.
                if let Ok(Err(e)) = rune::from_value::<Result<Value, Value>>(out) {
                    let why = rune::from_value::<String>(e)
                        .unwrap_or_else(|_| "the script returned an error".into());
                    return Err(why);
                }
                Ok(())
            }),
        )
        .call();
        let mut r = rec
            .lock()
            .map(|mut r| std::mem::take(&mut *r))
            .unwrap_or_default();
        r.trace.duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let error = result.err().or(r.error.take());
        let actions = if error.is_some() {
            Vec::new()
        } else {
            commit(&mut r, params.as_ref())
        };
        Outcome {
            actions,
            error,
            trace: r.trace,
        }
    }
}

/// String literals that look like parameter paths + virtual parameter names.
fn literal_paths(source: &str) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    let mut rest = source;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else {
            break;
        };
        let lit = &after[..end];
        let before = rest[..start].trim_end();
        if before.ends_with("set_virtual(") {
            out.insert(format!("{VIRTUAL_PREFIX}{lit}"));
        } else if (lit.starts_with("Device.")
            || lit.starts_with("InternetGatewayDevice.")
            || lit.starts_with(VIRTUAL_PREFIX))
            && !lit.ends_with('.')
            && !lit.contains(char::is_whitespace)
        {
            out.insert(lit.to_owned());
        }
        rest = &after[end + 1..];
    }
    out.into_iter().collect()
}

/// Declared state -> actions; only values != stored.
fn commit(r: &mut Recorder, params: &dyn Params) -> Vec<Action> {
    let mut out = Vec::new();
    // One lookup for all declared values.
    let paths: Vec<String> = r
        .sets
        .iter()
        .map(|(p, _, _)| p.clone())
        .chain(
            r.virtuals
                .iter()
                .map(|(n, _)| format!("{VIRTUAL_PREFIX}{n}")),
        )
        .collect();
    let stored_values = if paths.is_empty() {
        HashMap::new()
    } else {
        params.get_many(&paths)
    };
    for (path, value, ty) in std::mem::take(&mut r.sets) {
        let stored = stored_values.get(&path).cloned();
        if stored.as_ref().is_some_and(|(v, _)| *v == value) {
            continue;
        }
        let xsd_type = ty
            .or_else(|| stored.and_then(|(_, t)| t))
            .unwrap_or_else(|| "string".into());
        out.push(Action::Set {
            path,
            value,
            xsd_type,
        });
    }
    let mut seen = std::collections::HashSet::new();
    for path in std::mem::take(&mut r.refresh) {
        if seen.insert(path.clone()) {
            out.push(Action::Refresh { path });
        }
    }
    for file in std::mem::take(&mut r.downloads) {
        out.push(Action::Download { file });
    }
    for (name, value) in std::mem::take(&mut r.virtuals) {
        let stored = stored_values.get(&format!("{VIRTUAL_PREFIX}{name}"));
        if stored.is_some_and(|(v, _)| *v == value) {
            continue;
        }
        out.push(Action::Virtual { name, value });
    }
    for (tag, add) in std::mem::take(&mut r.tags) {
        out.push(if add {
            Action::Tag { tag }
        } else {
            Action::Untag { tag }
        });
    }
    if r.reboot {
        out.push(Action::Reboot);
    }
    out
}

/// Slow-run threshold for the whole run, measured from outside, e.g. to report slow scripts.
pub const SLOW_RUN: Duration = Duration::from_millis(200);

#[cfg(test)]
mod tests {
    use super::*;

    struct Snapshot(BTreeMap<String, (String, Option<String>)>);

    impl Params for Snapshot {
        fn get(&self, path: &str) -> Option<(String, Option<String>)> {
            self.0.get(path).cloned()
        }
        fn list(&self, prefix: &str) -> Vec<(String, String)> {
            self.0
                .iter()
                .filter(|(p, _)| p.starts_with(prefix))
                .map(|(p, (v, _))| (p.clone(), v.clone()))
                .collect()
        }
    }

    fn snapshot() -> Arc<dyn Params> {
        Arc::new(Snapshot(
            [
                ("Device.WiFi.SSID.1.SSID", "", "string"),
                ("Device.WiFi.SSID.2.SSID", "guest", "string"),
                (
                    "Device.ManagementServer.PeriodicInformInterval",
                    "3600",
                    "unsignedInt",
                ),
                ("VirtualParameters.firmware_ok", "true", "string"),
            ]
            .into_iter()
            .map(|(p, v, t)| (p.to_owned(), (v.to_owned(), Some(t.to_owned()))))
            .collect(),
        ))
    }

    fn device() -> DeviceInfo {
        DeviceInfo {
            id: "dev-1".into(),
            serial: "SN1".into(),
            oui: "00AA00".into(),
            product_class: "Box".into(),
            software_version: "1.0".into(),
            protocol: "cwmp".into(),
            tags: vec!["lab".into()],
            events: vec!["1 BOOT".into()],
            attributes: BTreeMap::from([("plan".to_owned(), "gold".to_owned())]),
        }
    }

    fn run(source: &str) -> Outcome {
        run_with(source, Limits::default())
    }

    fn run_with(source: &str, limits: Limits) -> Outcome {
        let script = Script::compile("test.rn", source).unwrap_or_else(|e| panic!("{e}"));
        let args = BTreeMap::from([("firmware".to_owned(), "2.0".to_owned())]);
        script.run(&device(), &args, snapshot(), limits)
    }

    #[test]
    fn declares_and_commits_only_changes() {
        let o = run(r#"
            pub fn main(device, args) {
                if device.get("Device.WiFi.SSID.1.SSID") == Some("") {
                    device.set("Device.WiFi.SSID.1.SSID", `Home-${device.serial}`);
                }
                device.set("Device.WiFi.SSID.2.SSID", "guest");          // unchanged
                device.set("Device.ManagementServer.PeriodicInformInterval", 600);
                if device.software_version != args["firmware"] && device.has_event("1 boot") {
                    device.download("fw-2");
                }
                if device.has_tag("lab") { device.tag("checked"); device.untag("new"); }
                device.refresh("Device.WiFi.");
                device.refresh("Device.WiFi.");
                device.reboot();
                device.log(`saw ${device.list("Device.WiFi.").len()} Wi-Fi values`);
            }
        "#);
        assert_eq!(o.error, None);
        assert_eq!(
            o.actions,
            [
                Action::Set {
                    path: "Device.WiFi.SSID.1.SSID".into(),
                    value: "Home-SN1".into(),
                    xsd_type: "string".into()
                },
                Action::Set {
                    path: "Device.ManagementServer.PeriodicInformInterval".into(),
                    value: "600".into(),
                    xsd_type: "unsignedInt".into()
                },
                Action::Refresh {
                    path: "Device.WiFi.".into()
                },
                Action::Download {
                    file: "fw-2".into()
                },
                Action::Tag {
                    tag: "checked".into()
                },
                Action::Untag { tag: "new".into() },
                Action::Reboot,
            ]
        );
        assert_eq!(o.trace.logs, ["saw 2 Wi-Fi values"]);
        assert_eq!(o.trace.declared.len(), 3);
        assert_eq!(
            o.trace.reads[0],
            ("Device.WiFi.SSID.1.SSID".to_owned(), Some(String::new()))
        );
    }

    #[test]
    fn a_later_set_wins_and_types_are_kept_or_inferred() {
        let o = run(r#"
            pub fn main(device, args) {
                device.set("Device.X.A", "1");
                device.set("Device.X.A", "2");
                device.set("Device.X.B", true);
                device.set("Device.X.C", -5);
                device.set_typed("Device.X.D", "2026-01-01T00:00:00Z", "dateTime");
            }
        "#);
        let sets: Vec<_> = o
            .actions
            .iter()
            .map(|a| match a {
                Action::Set {
                    path,
                    value,
                    xsd_type,
                } => format!("{path}={value}:{xsd_type}"),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            sets,
            [
                "Device.X.A=2:string",
                "Device.X.B=true:boolean",
                "Device.X.C=-5:int",
                "Device.X.D=2026-01-01T00:00:00Z:dateTime"
            ]
        );
    }

    #[test]
    fn failures_commit_nothing() {
        let err = run(r#"
            pub fn main(device, args) {
                device.set("Device.X", "1");
                Err("not this one")
            }
        "#);
        assert_eq!(
            (err.error.as_deref(), err.actions.len()),
            (Some("not this one"), 0)
        );
        let bad_value = run(r#"pub fn main(device, args) { device.set("Device.X", [1]); }"#);
        assert!(
            bad_value
                .error
                .is_some_and(|e| e.contains("string, integer or boolean"))
        );
        let panics =
            run(r#"pub fn main(device, args) { device.set("Device.X", "1"); let v = []; v[3] }"#);
        assert!(panics.error.is_some() && panics.actions.is_empty());
    }

    #[test]
    fn instruction_budget_stops_endless_loops() {
        let o = run(r#"pub fn main(device, args) { loop { device.log("x"); } }"#);
        assert_eq!(
            o.error.as_deref(),
            Some("the script exceeded its instruction budget")
        );
        assert!(o.actions.is_empty());
    }

    #[test]
    fn memory_limit_stops_runaway_allocations() {
        let o = run_with(
            r#"pub fn main(device, args) { let s = "xxxxxxxxxxxxxxxx"; loop { s = s + s; } }"#,
            Limits {
                memory: 1 << 20,
                ..Limits::default()
            },
        );
        let e = o.error.unwrap_or_default();
        assert!(e.contains("memory"), "{e}");
    }

    #[test]
    fn read_and_action_limits() {
        let o = run_with(
            r#"pub fn main(device, args) { for i in 0..100 { device.get("Device.X"); } }"#,
            Limits {
                reads: 10,
                ..Limits::default()
            },
        );
        assert_eq!(o.error.as_deref(), Some("too many parameter reads"));
        let o = run_with(
            r#"pub fn main(device, args) { for i in 0..100 { device.set(`Device.X.${i}`, i); } }"#,
            Limits {
                actions: 10,
                ..Limits::default()
            },
        );
        assert_eq!(o.error.as_deref(), Some("too many actions"));
    }

    #[test]
    fn guide_virtual_parameter_example() {
        // docs/guide/scripts.md, section 7.
        let o = run(r#"
            pub fn main(device, args) {
                let wan = match device.get("Device.IP.Interface.1.IPv4Address.1.IPAddress") {
                    Some(ip) => Some(ip),
                    None => device.get("Device.WiFi.SSID.2.SSID"),
                };
                if let Some(ip) = wan {
                    device.set_virtual("wan_ip", ip);
                }
                device.set_virtual("firmware_current", device.software_version == args["firmware"]);
            }
        "#);
        assert_eq!(o.error, None);
        assert_eq!(
            o.actions,
            [
                Action::Virtual {
                    name: "wan_ip".into(),
                    value: "guest".into()
                },
                Action::Virtual {
                    name: "firmware_current".into(),
                    value: "false".into()
                },
            ]
        );
    }

    #[test]
    fn literal_paths_are_found() {
        let script = Script::compile(
            "p.rn",
            r#"pub fn main(device, args) {
                let a = device.get("Device.DeviceInfo.UpTime");
                device.set("InternetGatewayDevice.X.Y", "a b");
                device.set_virtual("fw_ok", true);
                device.refresh("Device.WiFi.");
                device.log("Device. is not a path with spaces");
            }"#,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            script.literal_paths(),
            [
                "Device.DeviceInfo.UpTime",
                "InternetGatewayDevice.X.Y",
                "VirtualParameters.fw_ok"
            ]
        );
    }

    #[test]
    fn attributes_drive_provisioning() {
        let o = run(r#"
            pub fn main(device, args) {
                let rate = match device.attribute("plan") {
                    Some(plan) if plan == "gold" => 1000,
                    Some(_) => 100,
                    None => 10,
                };
                device.set("Device.QoS.Rate", rate);
                if device.attribute("missing").is_none() { device.log("no such attribute"); }
            }
        "#);
        assert_eq!(o.error, None);
        assert_eq!(
            o.actions,
            [Action::Set {
                path: "Device.QoS.Rate".into(),
                value: "1000".into(),
                xsd_type: "unsignedInt".into()
            }]
        );
        assert_eq!(o.trace.logs, ["no such attribute"]);
    }

    #[test]
    fn passing_a_value_does_not_consume_it() {
        let o = run(r#"
            pub fn main(device, args) {
                let v = args["firmware"];
                device.set("Device.X.A", v);
                device.set_virtual("again", v);
                device.log(`still ${v} ${args["firmware"]}`);
            }
        "#);
        assert_eq!(o.error, None);
        assert_eq!(o.trace.logs, ["still 2.0 2.0"]);
    }

    #[test]
    fn virtual_parameters_are_computed_values() {
        let o = run(r#"
            pub fn main(device, args) {
                let ssids = device.list("Device.WiFi.SSID.");
                device.set_virtual("ssid_count", ssids.len());
                device.set_virtual("guest_ssid", "guest");
                device.set_virtual("guest_ssid", "guest-2");
            }
        "#);
        assert_eq!(o.error, None);
        assert_eq!(
            o.actions,
            [
                Action::Virtual {
                    name: "ssid_count".into(),
                    value: "2".into()
                },
                Action::Virtual {
                    name: "guest_ssid".into(),
                    value: "guest-2".into()
                },
            ]
        );
        let same = run(r#"pub fn main(device, args) { device.set_virtual("firmware_ok", true); }"#);
        assert!(
            same.actions.is_empty(),
            "unchanged values are not rewritten"
        );
        let bad = run(r#"pub fn main(device, args) { device.set_virtual("a.b", 1); }"#);
        assert!(bad.error.is_some_and(|e| e.contains("set_virtual")));
    }

    #[test]
    fn deploy_example_script() {
        let src = include_str!("../../../deploy/wifi-defaults.rn");
        let script = Script::compile("wifi-defaults.rn", src).unwrap_or_else(|e| panic!("{e}"));
        let args = BTreeMap::from([
            ("ssid_prefix".to_owned(), "Home".to_owned()),
            ("guest_tag".to_owned(), "lab".to_owned()),
        ]);
        let o = script.run(&device(), &args, snapshot(), Limits::default());
        assert_eq!(o.error, None);
        assert_eq!(
            o.actions,
            [
                Action::Set {
                    path: "Device.WiFi.SSID.1.SSID".into(),
                    value: "Home-SN1".into(),
                    xsd_type: "string".into()
                },
                Action::Set {
                    path: "Device.WiFi.SSID.2.Enable".into(),
                    value: "true".into(),
                    xsd_type: "boolean".into()
                },
            ]
        );
        assert_eq!(o.trace.logs, ["guest network enabled"]);
    }

    #[test]
    fn compile_errors_and_missing_main() {
        let e = Script::compile("bad.rn", "pub fn main(device, args) { let = ; }")
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(e.contains("bad.rn"), "{e}");
        assert!(matches!(
            Script::compile("x.rn", "pub fn other() {}"),
            Err(ScriptError::NoMain)
        ));
        // No I/O functions -> scripts using them do not compile.
        assert!(
            Script::compile("io.rn", r#"pub fn main(device, args) { println("hi"); }"#).is_err()
        );
    }
}

#[cfg(test)]
mod bench {
    use super::*;

    /// `cargo test --release -p dhonomos-rules -- --ignored --nocapture run_cost`
    #[test]
    #[allow(clippy::print_stdout)]
    #[ignore = "timing, run by hand"]
    fn run_cost() {
        struct P;
        impl Params for P {
            fn get(&self, _: &str) -> Option<(String, Option<String>)> {
                Some(("1.0".into(), None))
            }
            fn list(&self, _: &str) -> Vec<(String, String)> {
                Vec::new()
            }
        }
        let s = Script::compile(
            "b.rn",
            r#"pub fn main(device, args) {
                let fw = device.get("Device.DeviceInfo.SoftwareVersion");
                device.set("Device.ManagementServer.PeriodicInformInterval", 3600);
                device.set_virtual("fw_major", if device.software_version.starts_with("1.") { "1" } else { "other" });
            }"#,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let (info, args, params) = (DeviceInfo::default(), BTreeMap::new(), Arc::new(P));
        let n = 20_000;
        let start = Instant::now();
        for _ in 0..n {
            let o = s.run(&info, &args, params.clone(), Limits::default());
            assert!(o.error.is_none(), "{:?}", o.error);
        }
        let per = start.elapsed() / n;
        println!("Script::run: {per:?} per run");
    }
}
