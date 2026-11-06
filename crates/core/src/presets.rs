//! Provisioning presets (CO-04): YAML rules -> queue tasks when an Inform matches.
//!
//! ```yaml
//! presets:
//!   - name: periodic-inform
//!     when:
//!       events: ["0 BOOTSTRAP", "1 BOOT"]
//!       oui: 00AA00
//!     once: true            # once per device (default: every matching Inform)
//!     run:
//!       - kind: set_parameter_values
//!         payload:
//!           values:
//!             - { name: Device.ManagementServer.PeriodicInformInterval, value: "3600", type: unsignedInt }
//!   - name: wifi-defaults
//!     when: { events: ["1 BOOT"] }
//!     script: wifi.rn          # Rune script, relative to the preset file (CO-05)
//!     args: { ssid_prefix: Home }
//! ```
//!
//! Script declares the device state it wants (see [`dhonomos_rules`]).
//! Diff to stored values -> tasks. Each run traced as a `script` device event.
//!
//! Task secrets of presets in the DB (`password`, `values[]` entries with `secret: true`)
//! -> stored sealed for the preset (`secrets::preset_context`), kept sealed in memory.
//! Preset queues a task -> sealed again for that task ([`enqueue_matching`]).
//! Presets from a file -> secrets as the file has them.

use std::sync::Arc;

use dhonomos_cwmp_codec::EventCode;
use regex::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::secrets::SecretBox;
use crate::task::TaskKind;

/// Conditions: all given ones must hold.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Conditions {
    /// Any of these Inform event codes.
    #[serde(default)]
    pub events: Vec<String>,
    /// Manufacturer OUI (case-insensitive).
    #[serde(default)]
    pub oui: Option<String>,
    /// Product class (exact).
    #[serde(default)]
    pub product_class: Option<String>,
    /// Regex, matched against the whole software version.
    #[serde(default)]
    pub software_version: Option<String>,
    /// Device must carry all of these tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// `true` -> only devices seen the first time; `false` -> only known ones.
    #[serde(default)]
    pub new_device: Option<bool>,
    /// Device attributes with these exact values (CO-13), e.g. `{plan: gold}`.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub attributes: std::collections::BTreeMap<String, String>,
}

/// One preset, as in the file.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    /// Unique name (part of the idempotency key).
    pub name: String,
    /// Disabled -> kept but never matches.
    #[serde(default = "enabled", skip_serializing_if = "is_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub when: Conditions,
    /// Once per device, not on every matching Inform.
    #[serde(default)]
    pub once: bool,
    /// Queue priority of the tasks.
    #[serde(default)]
    pub priority: i16,
    /// Tasks to queue, same form as the API.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub run: Vec<TaskKind>,
    /// Rune script file, relative to the preset file (CO-05).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// Rune script source, instead of a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_source: Option<String>,
    /// Args for the script's `main(device, args)`.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub args: std::collections::BTreeMap<String, String>,
}

fn enabled() -> bool {
    true
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_enabled(v: &bool) -> bool {
    *v
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PresetFile {
    presets: Vec<Preset>,
}

/// Error loading presets.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PresetError {
    /// Invalid YAML or schema.
    #[error("invalid presets: {0}")]
    Parse(String),
    /// Preset not usable.
    #[error("preset {name:?}: {reason}")]
    Invalid {
        /// Preset name.
        name: String,
        /// Problem.
        reason: String,
    },
}

/// Presets of a YAML document (`presets: [...]`), not yet validated.
pub fn parse_list(text: &str) -> Result<Vec<Preset>, PresetError> {
    serde_saphyr::from_str::<PresetFile>(text)
        .map(|f| f.presets)
        .map_err(|e| PresetError::Parse(e.to_string()))
}

/// Script loader for presets without a directory: no files allowed.
fn no_files(file: &str) -> Result<String, String> {
    Err(format!(
        "script files ({file}) are only for the preset file; put the source in `script_source`"
    ))
}

/// Validate a preset + compile its script; script files read with `read`.
/// Task secrets may be ciphertext only if `stored` (preset from DB, sealed by the server).
fn compile(
    preset: Preset,
    read: &dyn Fn(&str) -> Result<String, String>,
    stored: bool,
) -> Result<Compiled, PresetError> {
    let invalid = |reason: String| PresetError::Invalid {
        name: preset.name.clone(),
        reason,
    };
    if preset.name.trim().is_empty() || preset.name.len() > 100 {
        return Err(invalid("names are 1-100 characters".into()));
    }
    let source = match (&preset.script, &preset.script_source) {
        (Some(_), Some(_)) => {
            return Err(invalid("give `script` or `script_source`, not both".into()));
        }
        (Some(file), None) => Some((
            file.clone(),
            read(file).map_err(|e| invalid(format!("script {file}: {e}")))?,
        )),
        (None, Some(src)) => Some((format!("{}.rn", preset.name), src.clone())),
        (None, None) => None,
    };
    if preset.run.is_empty() && source.is_none() {
        return Err(invalid(
            "`run` lists no tasks and there is no script".into(),
        ));
    }
    if preset.once && source.is_some() {
        // Declarative script = idempotent; no "already ran" record.
        return Err(invalid(
            "scripts run on every match; use `when` conditions instead of `once`".into(),
        ));
    }
    let script = source
        .map(|(name, src)| dhonomos_rules::Script::compile(&name, &src))
        .transpose()
        .map_err(|e| invalid(e.to_string()))?;
    if let Some(e) = preset.run.iter().find_map(|t| t.validate().err()) {
        return Err(invalid(e));
    }
    // Ciphertext is never typed in -> else a copied one would be opened for the task.
    if !stored
        && let Some(e) = preset
            .run
            .iter()
            .find_map(|t| crate::secrets::reject_ciphertext_input(&t.to_row().1).err())
    {
        return Err(invalid(e));
    }
    let version = preset
        .when
        .software_version
        .as_deref()
        .map(|re| Regex::new(&format!("^(?:{re})$")))
        .transpose()
        .map_err(|e| invalid(format!("software_version: {e}")))?;
    let events = preset
        .when
        .events
        .iter()
        .map(|e| EventCode::parse(e))
        .collect();
    Ok(Compiled {
        preset,
        events,
        version,
        script,
        id: None,
    })
}

/// Load enabled presets stored for `tenant_id`; failing ones reported.
/// Task secrets stay sealed; `secrets` opens them when presets queue tasks
/// (no `secrets` -> preset with sealed secrets left out).
pub async fn load_stored(
    store: &dhonomos_store::Store,
    tenant_id: uuid::Uuid,
    secrets: Option<Arc<SecretBox>>,
) -> Result<(Presets, Vec<PresetError>), dhonomos_store::StoreError> {
    let mut parsed = Vec::new();
    let mut errors = Vec::new();
    for p in store.list_presets(tenant_id).await? {
        if !p.enabled {
            continue;
        }
        match serde_json::from_value::<Preset>(p.definition) {
            Ok(preset) => parsed.push((p.id, preset)),
            Err(e) => errors.push(PresetError::Invalid {
                name: p.name,
                reason: e.to_string(),
            }),
        }
    }
    let (presets, mut more) = Presets::from_stored(parsed, secrets);
    errors.append(&mut more);
    Ok((presets, errors))
}

/// Keep `shared` in step with stored presets: revision check every `every`, reload on change
/// -> changes from any process reach all processes.
pub async fn watch_stored(
    store: dhonomos_store::Store,
    tenant_id: uuid::Uuid,
    shared: crate::Shared<Presets>,
    every: std::time::Duration,
    secrets: Option<Arc<SecretBox>>,
) {
    let mut seen = None;
    loop {
        match store.config_revision(tenant_id, "presets").await {
            Ok(rev) if seen != Some(rev) => {
                match load_stored(&store, tenant_id, secrets.clone()).await {
                    Ok((presets, errors)) => {
                        for e in &errors {
                            tracing::error!(error = %e, "stored preset left out");
                        }
                        tracing::info!(
                            presets = presets.len(),
                            revision = rev,
                            "presets loaded from the database"
                        );
                        shared.replace(presets);
                        seen = Some(rev);
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "loading presets failed; keeping the running ones")
                    }
                }
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "checking the preset revision failed"),
        }
        tokio::time::sleep(every).await;
    }
}

#[derive(Debug, Clone)]
struct Compiled {
    preset: Preset,
    events: Vec<EventCode>,
    version: Option<Regex>,
    script: Option<dhonomos_rules::Script>,
    /// DB row of a stored preset: its task secrets are sealed for it.
    id: Option<Uuid>,
}

/// What a preset is matched against.
#[derive(Debug, Clone, Copy)]
pub struct MatchContext<'a> {
    /// Inform events.
    pub events: &'a [EventCode],
    pub oui: &'a str,
    pub product_class: &'a str,
    pub software_version: Option<&'a str>,
    pub tags: &'a [String],
    /// First contact.
    pub new_device: bool,
    /// Device attributes (JSON object of strings, CO-13).
    pub attributes: &'a serde_json::Value,
    /// Serial number (USP: EndpointID), for scripts.
    pub serial: &'a str,
    /// `cwmp` or `usp`, for scripts.
    pub protocol: &'a str,
}

/// Validated set of presets.
#[derive(Debug, Clone, Default)]
pub struct Presets {
    list: Vec<Compiled>,
    /// Opens secrets of stored presets when they queue tasks.
    secrets: Option<Arc<SecretBox>>,
}

impl Presets {
    /// Parse + validate a preset file; script files relative to the working dir
    /// (see [`Self::from_yaml_in`]).
    pub fn from_yaml(text: &str) -> Result<Self, PresetError> {
        Self::from_yaml_in(text, std::path::Path::new("."))
    }

    /// Parse + validate a preset file, compile its scripts; script paths relative to `dir`.
    pub fn from_yaml_in(text: &str, dir: &std::path::Path) -> Result<Self, PresetError> {
        let read = |file: &str| std::fs::read_to_string(dir.join(file)).map_err(|e| e.to_string());
        let mut names = std::collections::HashSet::new();
        let mut list = Vec::new();
        for preset in parse_list(text)? {
            if !names.insert(preset.name.clone()) {
                return Err(PresetError::Invalid {
                    name: preset.name,
                    reason: "names must be non-empty and unique".into(),
                });
            }
            // Mask = what API output shows instead of a secret -> as a file value it would
            // go to devices as the password.
            let masked = crate::secrets::masked_preset_slots(
                &serde_json::to_value(&preset).unwrap_or_default(),
            );
            if let Some(slot) = masked.first() {
                return Err(PresetError::Invalid {
                    name: preset.name,
                    reason: format!(
                        "{slot} is \"{}\", the mask the API shows instead of a secret; write the secret",
                        crate::secrets::REDACTED
                    ),
                });
            }
            list.push(compile(preset, &read, false)?);
        }
        Ok(Self {
            list,
            secrets: None,
        })
    }

    /// Presets from the DB (scripts inline), each with its row ID: task secrets sealed for it,
    /// opened with `secrets`.
    /// No longer compiles (e.g. after upgrade) or sealed secrets without key -> left out
    /// and reported, others still load.
    pub fn from_stored(
        presets: Vec<(Uuid, Preset)>,
        secrets: Option<Arc<SecretBox>>,
    ) -> (Self, Vec<PresetError>) {
        let mut list = Vec::new();
        let mut errors = Vec::new();
        for (id, preset) in presets {
            let sealed = preset
                .run
                .iter()
                .any(|t| crate::secrets::has_encrypted_secret(&t.to_row().1));
            if sealed && secrets.is_none() {
                errors.push(PresetError::Invalid {
                    name: preset.name,
                    reason: "its secrets are encrypted and the server runs without --secrets-key"
                        .into(),
                });
                continue;
            }
            match compile(preset, &no_files, true) {
                Ok(mut c) => {
                    c.id = Some(id);
                    list.push(c);
                }
                Err(e) => errors.push(e),
            }
        }
        (Self { list, secrets }, errors)
    }

    /// Validate one preset to be stored: scripts inline only (`script_source`).
    pub fn check(preset: &Preset) -> Result<(), PresetError> {
        compile(preset.clone(), &no_files, false).map(|_| ())
    }

    /// Set of one preset (dry runs of a draft).
    pub fn single(preset: Preset) -> Result<Self, PresetError> {
        Ok(Self {
            list: vec![compile(preset, &no_files, false)?],
            secrets: None,
        })
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// All presets, file order.
    pub fn iter(&self) -> impl Iterator<Item = &Preset> {
        self.list.iter().map(|c| &c.preset)
    }

    /// Presets whose conditions hold.
    pub fn matching<'a>(
        &'a self,
        ctx: &'a MatchContext<'a>,
    ) -> impl Iterator<Item = &'a Preset> + 'a {
        self.matching_compiled(ctx).map(|c| &c.preset)
    }

    fn matching_compiled<'a>(
        &'a self,
        ctx: &'a MatchContext<'a>,
    ) -> impl Iterator<Item = &'a Compiled> + 'a {
        self.list.iter().filter(move |c| c.matches(ctx))
    }
}

impl Compiled {
    fn matches(&self, ctx: &MatchContext<'_>) -> bool {
        let w = &self.preset.when;
        self.preset.enabled
            && (self.events.is_empty() || self.events.iter().any(|e| ctx.events.contains(e)))
            && w.oui
                .as_deref()
                .is_none_or(|o| o.eq_ignore_ascii_case(ctx.oui))
            && w.product_class
                .as_deref()
                .is_none_or(|p| p == ctx.product_class)
            && self
                .version
                .as_ref()
                .is_none_or(|re| ctx.software_version.is_some_and(|v| re.is_match(v)))
            && w.tags.iter().all(|t| ctx.tags.contains(t))
            && w.new_device.is_none_or(|n| n == ctx.new_device)
            && w.attributes.iter().all(|(k, v)| {
                ctx.attributes.get(k).and_then(serde_json::Value::as_str) == Some(v.as_str())
            })
    }
}

/// Task a preset queues for a device.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedTask {
    /// Preset name.
    pub preset: String,
    /// Position in the preset's `run` list.
    pub index: usize,
    pub task: TaskKind,
    pub priority: i16,
    /// Dedup key: per device for `once` presets, else per occurrence.
    pub idempotency_key: String,
    /// Preset runs once per device.
    pub once: bool,
    /// Binding of the task's sealed secrets (`secrets::preset_context`).
    /// Set for a task of a stored preset (payload = ciphertext, not the secrets).
    pub secret_context: Option<String>,
}

impl PlannedTask {
    /// Queue row for this task.
    pub fn to_new_task(
        &self,
        tenant_id: uuid::Uuid,
        device: uuid::Uuid,
    ) -> dhonomos_store::NewTask {
        let (kind, payload) = self.task.to_row();
        dhonomos_store::NewTask {
            priority: self.priority,
            idempotency_key: Some(self.idempotency_key.clone()),
            created_by: Some(format!("preset:{}", self.preset)),
            ..dhonomos_store::NewTask::new(tenant_id, device, kind, payload)
        }
    }
}

/// Tasks matching presets queue for one device.
/// Used by real runs ([`enqueue_matching`]) and dry runs -> dry run = exactly what a real one
/// queues.
///
/// `occurrence` separates repeated triggers of presets without `once`.
/// CWMP: Inform CurrentTime -> CPE retransmissions stay idempotent. USP: connection or event.
pub fn plan(
    presets: &Presets,
    device: uuid::Uuid,
    ctx: &MatchContext<'_>,
    occurrence: &str,
) -> Vec<PlannedTask> {
    let mut out = Vec::new();
    for compiled in presets.matching_compiled(ctx) {
        let preset = &compiled.preset;
        for (i, task) in preset.run.iter().enumerate() {
            let idempotency_key = if preset.once {
                // Kept by retention: this task = record that the preset ran.
                format!("preset-once:{}:{i}:{device}", preset.name)
            } else {
                format!("preset:{}:{i}:{device}:{occurrence}", preset.name)
            };
            out.push(PlannedTask {
                preset: preset.name.clone(),
                index: i,
                task: task.clone(),
                priority: preset.priority,
                idempotency_key,
                once: preset.once,
                secret_context: compiled.id.map(|id| crate::secrets::preset_context(id, i)),
            });
        }
    }
    out
}

/// One script run of a matching preset (CO-05).
#[derive(Debug, Clone)]
pub struct ScriptRun {
    /// Preset name.
    pub preset: String,
    /// Script name.
    pub script: String,
    /// What it committed or why it failed, + its trace.
    pub outcome: dhonomos_rules::Outcome,
    /// Tasks from its actions.
    pub tasks: Vec<PlannedTask>,
}

impl ScriptRun {
    /// Tags the run adds + removes.
    pub fn tag_changes(&self) -> (Vec<String>, Vec<String>) {
        let (mut add, mut remove) = (Vec::new(), Vec::new());
        for a in &self.outcome.actions {
            match a {
                dhonomos_rules::Action::Tag { tag } => add.push(tag.clone()),
                dhonomos_rules::Action::Untag { tag } => remove.push(tag.clone()),
                _ => {}
            }
        }
        (add, remove)
    }

    /// Virtual params the run computed, as param updates (CO-06).
    pub fn virtual_params(&self) -> Vec<dhonomos_store::ParamUpdate> {
        self.outcome
            .actions
            .iter()
            .filter_map(|a| match a {
                dhonomos_rules::Action::Virtual { name, value } => {
                    Some(dhonomos_store::ParamUpdate {
                        path: format!("{}{name}", dhonomos_rules::VIRTUAL_PREFIX),
                        value: Some(value.clone()),
                        xsd_type: Some("string".into()),
                        // Never in config backups or restores.
                        writable: Some(false),
                    })
                }
                _ => None,
            })
            .collect()
    }

    /// `script` device event recorded for the run.
    pub fn event_detail(&self) -> serde_json::Value {
        let t = &self.outcome.trace;
        let (add, remove) = self.tag_changes();
        serde_json::json!({
            "preset": self.preset,
            "script": self.script,
            "error": self.outcome.error,
            "duration_ms": t.duration_ms,
            "tasks": self.tasks.iter().map(|p| p.task.name()).collect::<Vec<_>>(),
            "tags_added": add,
            "tags_removed": remove,
            "virtual": self.virtual_params().iter().map(|p| (&p.path, &p.value)).collect::<Vec<_>>(),
            "logs": t.logs,
            "reads": t.reads.iter().take(50).collect::<Vec<_>>(),
            "declared": t.declared.iter().take(50).collect::<Vec<_>>(),
        })
    }
}

type Stored = Option<(String, Option<String>)>;

/// Stored params, read from a blocking thread; each path read once per run.
struct StoreParams {
    store: dhonomos_store::Store,
    device: uuid::Uuid,
    rt: tokio::runtime::Handle,
    cache: std::sync::Mutex<std::collections::HashMap<String, Stored>>,
}

impl StoreParams {
    fn cached(&self, path: &str) -> Option<Stored> {
        self.cache.lock().ok()?.get(path).cloned()
    }

    /// Cache rows read before; `paths` without a row = known absent.
    fn seed(&self, rows: Vec<dhonomos_store::StoredParam>, paths: &[String]) {
        if let Ok(mut cache) = self.cache.lock() {
            for p in paths {
                cache.insert(p.clone(), None);
            }
            for row in rows {
                if let Some(v) = row.value {
                    cache.insert(row.path, Some((v, row.xsd_type)));
                }
            }
        }
    }

    /// Read paths not cached yet, in one query.
    fn load(&self, paths: &[String]) {
        let missing: Vec<String> = paths
            .iter()
            .filter(|p| self.cached(p).is_none())
            .cloned()
            .collect();
        if missing.is_empty() {
            return;
        }
        let rows = self
            .rt
            .block_on(self.store.get_params_exact(self.device, &missing))
            .unwrap_or_default();
        if let Ok(mut cache) = self.cache.lock() {
            for p in &missing {
                cache.insert(p.clone(), None);
            }
            for row in rows {
                if let Some(v) = row.value {
                    cache.insert(row.path, Some((v, row.xsd_type)));
                }
            }
        }
    }
}

impl dhonomos_rules::Params for StoreParams {
    fn get(&self, path: &str) -> Option<(String, Option<String>)> {
        self.load(&[path.to_owned()]);
        self.cached(path).flatten()
    }

    fn get_many(
        &self,
        paths: &[String],
    ) -> std::collections::HashMap<String, (String, Option<String>)> {
        self.load(paths);
        paths
            .iter()
            .filter_map(|p| Some((p.clone(), self.cached(p).flatten()?)))
            .collect()
    }

    fn list(&self, prefix: &str) -> Vec<(String, String)> {
        self.rt
            .block_on(self.store.get_params(self.device, prefix))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|p| Some((p.path, p.value?)))
            .collect()
    }
}

/// Committed run -> tasks: one SPV, one GPV, downloads, then a reboot.
fn script_tasks(
    preset: &Preset,
    device: uuid::Uuid,
    actions: &[dhonomos_rules::Action],
    occurrence: &str,
) -> Result<Vec<PlannedTask>, String> {
    use dhonomos_rules::Action;
    let mut tasks = Vec::new();
    let values: Vec<crate::task::SetValue> = actions
        .iter()
        .filter_map(|a| match a {
            Action::Set {
                path,
                value,
                xsd_type,
            } => Some(crate::task::SetValue {
                name: path.clone(),
                value: value.clone(),
                xsd_type: Some(xsd_type.clone()),
                secret: false,
            }),
            _ => None,
        })
        .collect();
    if !values.is_empty() {
        tasks.push(TaskKind::SetParameterValues { values });
    }
    let names: Vec<String> = actions
        .iter()
        .filter_map(|a| match a {
            Action::Refresh { path } => Some(path.clone()),
            _ => None,
        })
        .collect();
    if !names.is_empty() {
        tasks.push(TaskKind::GetParameterValues { names });
    }
    for a in actions {
        if let Action::Download { file } = a {
            let id = file
                .parse::<uuid::Uuid>()
                .map_err(|_| format!("download({file:?}): not a file ID"))?;
            tasks.push(TaskKind::Download {
                file_id: Some(id),
                file_type: "1 Firmware Upgrade Image".into(),
                url: String::new(),
                username: String::new(),
                password: String::new(),
                file_size: 0,
                target_file_name: String::new(),
                sha256: String::new(),
                delay_seconds: 0,
            });
        }
    }
    if actions.contains(&Action::Reboot) {
        tasks.push(TaskKind::Reboot);
    }
    Ok(tasks
        .into_iter()
        .enumerate()
        .map(|(i, task)| PlannedTask {
            preset: preset.name.clone(),
            index: i,
            task,
            priority: preset.priority,
            idempotency_key: format!("preset:{}:script:{i}:{device}:{occurrence}", preset.name),
            once: false,
            secret_context: None,
        })
        .collect())
}

/// Run scripts of matching presets for one device. Nothing queued or changed
/// (that is [`enqueue_matching`]).
#[tracing::instrument(name = "presets.scripts", skip_all, fields(device = %device))]
pub async fn run_scripts(
    store: &dhonomos_store::Store,
    presets: &Presets,
    device: uuid::Uuid,
    ctx: &MatchContext<'_>,
    occurrence: &str,
) -> Result<Vec<ScriptRun>, dhonomos_store::StoreError> {
    let scripted: Vec<&Compiled> = presets
        .list
        .iter()
        .filter(|c| c.script.is_some() && c.matches(ctx))
        .collect();
    if scripted.is_empty() {
        return Ok(Vec::new());
    }
    let info = dhonomos_rules::DeviceInfo {
        id: device.to_string(),
        serial: ctx.serial.to_owned(),
        oui: ctx.oui.to_owned(),
        product_class: ctx.product_class.to_owned(),
        software_version: ctx.software_version.unwrap_or_default().to_owned(),
        protocol: ctx.protocol.to_owned(),
        tags: ctx.tags.to_vec(),
        events: ctx.events.iter().map(|e| e.as_str().to_owned()).collect(),
        attributes: ctx
            .attributes
            .as_object()
            .map(|o| {
                o.iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                    .collect()
            })
            .unwrap_or_default(),
    };
    let mut runs = Vec::new();
    for c in scripted {
        let Some(script) = c.script.clone() else {
            continue;
        };
        let params = StoreParams {
            store: store.clone(),
            device,
            rt: tokio::runtime::Handle::current(),
            cache: std::sync::Mutex::default(),
        };
        // One query for all literal paths of the script -> most runs read nothing else.
        if !script.literal_paths().is_empty() {
            params.seed(
                store
                    .get_params_exact(device, script.literal_paths())
                    .await?,
                script.literal_paths(),
            );
        }
        let params: std::sync::Arc<dyn dhonomos_rules::Params> = std::sync::Arc::new(params);
        let (info, args, name) = (
            info.clone(),
            c.preset.args.clone(),
            script.name().to_owned(),
        );
        let mut outcome = tokio::task::spawn_blocking(move || {
            script.run(&info, &args, params, dhonomos_rules::Limits::default())
        })
        .await
        .unwrap_or_else(|e| dhonomos_rules::Outcome {
            actions: Vec::new(),
            error: Some(format!("the script crashed: {e}")),
            trace: dhonomos_rules::Trace::default(),
        });
        let tasks = match script_tasks(&c.preset, device, &outcome.actions, occurrence) {
            Ok(t) => t,
            Err(e) => {
                outcome.error = Some(e);
                outcome.actions.clear();
                Vec::new()
            }
        };
        if outcome.trace.duration_ms > 200 {
            tracing::warn!(
                preset = %c.preset.name,
                %device,
                ms = outcome.trace.duration_ms,
                "slow provisioning script"
            );
        }
        runs.push(ScriptRun {
            preset: c.preset.name.clone(),
            script: name,
            outcome,
            tasks,
        });
    }
    Ok(runs)
}

/// Queue tasks of every matching preset for one device; see [`plan`].
pub async fn enqueue_matching(
    store: &dhonomos_store::Store,
    tenant_id: uuid::Uuid,
    presets: &Presets,
    device: uuid::Uuid,
    ctx: &MatchContext<'_>,
    occurrence: &str,
) -> Result<usize, dhonomos_store::StoreError> {
    let mut queued = 0;
    let mut planned = plan(presets, device, ctx, occurrence);
    for run in run_scripts(store, presets, device, ctx, occurrence).await? {
        let outcome = if run.outcome.error.is_some() {
            "failed"
        } else {
            "ok"
        };
        metrics::counter!("dhonomos_script_runs_total", "preset" => run.preset.clone(), "outcome" => outcome)
            .increment(1);
        if let Some(e) = &run.outcome.error {
            tracing::warn!(preset = %run.preset, %device, error = %e, "provisioning script failed");
        }
        let (add, remove) = run.tag_changes();
        if !add.is_empty() {
            store.add_tags(device, &add).await?;
        }
        if !remove.is_empty() {
            store.remove_tags(device, &remove).await?;
        }
        let virtuals = run.virtual_params();
        if !virtuals.is_empty() {
            let done = store
                .upsert_params(device, &virtuals)
                .await
                .inspect_err(|e| crate::param_store::report_failure(device, "presets", e))?;
            crate::param_store::report_rejected(device, "presets", &done.rejected);
        }
        // Run with no change, log or error -> only counted.
        // Else a script matching every periodic Inform -> one event per Inform.
        let noteworthy = run.outcome.error.is_some()
            || !run.tasks.is_empty()
            || !add.is_empty()
            || !remove.is_empty()
            || !virtuals.is_empty()
            || !run.outcome.trace.logs.is_empty();
        if noteworthy {
            store
                .record_event(tenant_id, Some(device), "script", &run.event_detail())
                .await?;
        }
        planned.extend(run.tasks);
    }
    for planned in planned {
        let mut new = planned.to_new_task(tenant_id, device);
        // Script tasks (built at run time) and file presets are not sealed
        // -> ciphertext in a secret field never queued for them.
        if planned.secret_context.is_none()
            && let Err(e) = crate::secrets::reject_ciphertext_input(&new.payload)
        {
            tracing::warn!(preset = %planned.preset, %device, error = %e, "preset task left out");
            continue;
        }
        // Stored preset secrets bound to the preset -> task gets its own.
        let task_id = Uuid::now_v7();
        let sealed = crate::secrets::has_encrypted_secret(&new.payload);
        if sealed || crate::secrets::has_plain_secret(&new.payload) {
            match &presets.secrets {
                Some(secrets) => {
                    if let Err(e) = secrets.seal_for_task(
                        &mut new.payload,
                        planned.secret_context.as_deref(),
                        &crate::secrets::task_context(task_id),
                    ) {
                        tracing::warn!(preset = %planned.preset, %device, error = %e,
                            "preset task left out: its secrets could not be sealed");
                        continue;
                    }
                }
                None if sealed => {
                    tracing::warn!(preset = %planned.preset, %device,
                        "preset task left out: its secrets are encrypted and there is no --secrets-key");
                    continue;
                }
                // File preset, no key -> queued as written (old behavior).
                None => {}
            }
        }
        if store.enqueue_task_with_id(task_id, &new).await?.1 {
            queued += 1;
            metrics::counter!("dhonomos_preset_tasks_total", "preset" => planned.preset.clone())
                .increment(1);
        }
    }
    Ok(queued)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
presets:
  - name: interval
    when:
      events: ["1 BOOT", "0 bootstrap"]
      oui: 00aa00
      software_version: "1\\..*"
    once: true
    run:
      - kind: set_parameter_values
        payload:
          values:
            - { name: Device.ManagementServer.PeriodicInformInterval, value: "3600", type: unsignedInt }
  - name: lab-reboot
    when: { tags: [lab], new_device: false }
    priority: 5
    run:
      - kind: reboot
"#;

    fn ctx<'a>(
        events: &'a [EventCode],
        version: Option<&'a str>,
        tags: &'a [String],
        new: bool,
    ) -> MatchContext<'a> {
        MatchContext {
            events,
            oui: "00AA00",
            product_class: "Box",
            software_version: version,
            tags,
            new_device: new,
            attributes: &serde_json::Value::Null,
            serial: "SN1",
            protocol: "cwmp",
        }
    }

    #[test]
    fn parse_and_match() {
        let p = Presets::from_yaml(FILE).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p.len(), 2);
        let boot = [EventCode::Boot];
        let periodic = [EventCode::Periodic];
        let lab = vec!["lab".to_owned()];
        let names =
            |c: &MatchContext<'_>| p.matching(c).map(|x| x.name.clone()).collect::<Vec<_>>();

        assert_eq!(names(&ctx(&boot, Some("1.2.3"), &[], true)), ["interval"]);
        assert!(
            names(&ctx(&boot, Some("2.0"), &[], true)).is_empty(),
            "version regex is anchored"
        );
        assert!(
            names(&ctx(&periodic, Some("1.0"), &[], true)).is_empty(),
            "event not listed"
        );
        assert!(
            names(&ctx(&boot, None, &[], true)).is_empty(),
            "unknown version does not match"
        );
        assert_eq!(names(&ctx(&periodic, None, &lab, false)), ["lab-reboot"]);
        assert!(
            names(&ctx(&periodic, None, &lab, true)).is_empty(),
            "new_device: false"
        );
        let reboot = p
            .matching(&ctx(&periodic, None, &lab, false))
            .next()
            .map(|x| (x.priority, x.run.clone()));
        assert_eq!(reboot, Some((5, vec![TaskKind::Reboot])));
    }

    #[test]
    fn attribute_conditions() {
        let p = Presets::from_yaml(
            "presets: [{ name: gold, when: { attributes: { plan: gold } }, run: [{kind: reboot}] }]",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let events = [EventCode::parse("1 BOOT")];
        let gold = serde_json::json!({ "plan": "gold", "subscriber": "S-1" });
        let silver = serde_json::json!({ "plan": "silver" });
        let with = |attributes| MatchContext {
            attributes,
            ..ctx(&events, None, &[], false)
        };
        assert_eq!(p.matching(&with(&gold)).count(), 1);
        assert_eq!(p.matching(&with(&silver)).count(), 0);
        assert_eq!(p.matching(&with(&serde_json::Value::Null)).count(), 0);
    }

    #[test]
    fn the_mask_is_not_a_secret_in_a_file() {
        // API output shows `********` -> as a file password it would reach devices.
        let text = "presets: [{ name: a, run: [{ kind: download, payload: { url: 'http://f', password: '********' } }] }]";
        let err = Presets::from_yaml(text)
            .map(|_| ())
            .expect_err("mask")
            .to_string();
        assert!(
            err.contains("run[0].password") && err.contains("mask"),
            "{err}"
        );
        let ok = "presets: [{ name: a, run: [{ kind: download, payload: { url: 'http://f', password: 'pw' } }] }]";
        assert!(Presets::from_yaml(ok).is_ok());
    }

    #[test]
    fn stored_presets_keep_their_secrets_sealed_and_need_the_key() {
        let key = Arc::new(
            SecretBox::from_base64("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "k1")
                .unwrap_or_else(|e| panic!("{e}")),
        );
        let id = Uuid::now_v7();
        let mut definition = serde_json::json!({ "name": "p", "when": { "events": ["1 BOOT"] },
            "run": [{ "kind": "download", "payload": { "url": "http://f", "password": "pw" } }] });
        key.seal_preset(&mut definition, id, None)
            .unwrap_or_else(|e| panic!("{e}"));
        let preset: Preset = serde_json::from_value(definition).unwrap_or_else(|e| panic!("{e}"));
        // Ciphertext via API -> refused; from DB -> normal.
        assert!(Presets::check(&preset).is_err());
        let (set, errors) = Presets::from_stored(vec![(id, preset.clone())], Some(key));
        assert!(errors.is_empty(), "{errors:?}");
        let events = [EventCode::Boot];
        let planned = plan(&set, Uuid::now_v7(), &ctx(&events, None, &[], false), "x");
        assert_eq!(planned.len(), 1);
        assert_eq!(
            planned[0].secret_context.as_deref(),
            Some(crate::secrets::preset_context(id, 0).as_str())
        );
        assert!(!planned[0].task.to_row().1.to_string().contains("\"pw\""));
        // No key -> preset left out, error says why.
        let (set, errors) = Presets::from_stored(vec![(id, preset)], None);
        assert!(set.is_empty());
        assert!(
            errors[0].to_string().contains("--secrets-key"),
            "{errors:?}"
        );
        // File presets -> task secrets bound to nothing.
        let file = Presets::from_yaml(
            "presets: [{ name: a, run: [{ kind: download, payload: { url: 'http://f', password: 'pw' } }] }]",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let any = [EventCode::Boot];
        let planned = plan(&file, Uuid::now_v7(), &ctx(&any, None, &[], false), "x");
        assert_eq!(planned[0].secret_context, None);
    }

    #[test]
    fn rejects_bad_files() {
        for (text, needle) in [
            ("presets: [{ name: a, run: [] }]", "no tasks"),
            (
                "presets: [{ name: a, run: [{kind: reboot}]}, { name: a, run: [{kind: reboot}]}]",
                "unique",
            ),
            (
                "presets: [{ name: a, when: { software_version: '(' }, run: [{kind: reboot}] }]",
                "software_version",
            ),
            (
                "presets: [{ name: a, whne: {}, run: [{kind: reboot}] }]",
                "whne",
            ),
            ("presets: [{ name: a, run: [{kind: explode}] }]", "explode"),
            (
                "presets: [{ name: a, script: x.rn, script_source: 'pub fn main(d, a) {}' }]",
                "not both",
            ),
            (
                "presets: [{ name: a, once: true, script_source: 'pub fn main(d, a) {}' }]",
                "once",
            ),
            (
                "presets: [{ name: a, script_source: 'pub fn main(d, a) { let = ; }' }]",
                "a.rn",
            ),
            ("presets: [{ name: a, script: missing.rn }]", "missing.rn"),
        ] {
            let err = Presets::from_yaml(text)
                .map(|_| ())
                .expect_err(text)
                .to_string();
            assert!(err.contains(needle), "{text}: {err}");
        }
    }
}

#[cfg(test)]
mod example_file {
    #[test]
    fn deploy_example_is_valid() {
        let text = include_str!("../../../deploy/presets.example.yaml");
        let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy"));
        let p = super::Presets::from_yaml_in(text, dir).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p.len(), 3);
    }
}
