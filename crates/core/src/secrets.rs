//! Stored secrets (CO-16): AES-256-GCM, configured master key.
//!
//! Task + job payload secrets stored as `enc:v2:<base64(nonce || ciphertext)>`.
//! AEAD associated data (AAD) binds each ciphertext to its place
//! -> copy into another row, slot or job fails to open:
//!
//! | What | AAD |
//! |---|---|
//! | Payload secret (`password`, a `values[]` entry marked `secret`) | `<context>#<slot>` |
//! | Device credential (CPE passwords, broker password) | `credential:<device uuid>` |
//! | Operator TOTP secret (ADR-100), in use or waiting for 1st code | `totp:<user uuid>` |
//! | WireGuard member PSK (ADR-110) | `wg-psk:<member uuid>` |
//!
//! Payload context: `task:<task uuid>`, `job:<job uuid>`, or for task `<i>` of a stored
//! preset's `run` list `preset:<preset uuid>:run[<i>]` ([`preset_context`]).
//! Slot: `password` or `values[<index>].value`.
//! Job secrets -> opened + sealed again for each member task ([`SecretBox::reseal_fields`]).
//! Preset secrets -> same for each task it queues ([`SecretBox::seal_for_task`]).
//! Credential AAD has no kind: promoting a pending credential only renames its row.
//!
//! Presets write-only like other secrets: output shows [`REDACTED`] ([`redact_preset`]).
//! Save with the mask in a secret slot -> keep stored value of the same slot
//! ([`SecretBox::seal_preset`]). Preset history entries: mask, never ciphertext.
//!
//! Still read: `enc:v1:` values (no AAD) + credentials sealed without AAD.
//! Rotation ([`rewrap_secrets`]) -> sealed again in current form.
//! Callers never supply ciphertext: API input starting with `enc:` refused
//! ([`reject_ciphertext_input`]); output shows [`REDACTED`] ([`redact_secrets`]).
//!
//! Key rotation (ADR-082): seal with current key; open tries current key, then old ones
//! (AES-GCM tag tells which fits). [`rewrap_secrets`] re-seals what is still under an old key.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom as _, SystemRandom};
use serde_json::Value;
use uuid::Uuid;

/// Legacy form: no AAD.
const V1: &str = "enc:v1:";
/// Current form: AAD binds ciphertext to context + slot.
const V2: &str = "enc:v2:";

/// Prefix of every stored ciphertext, any version. Refused in caller input.
pub const CIPHERTEXT_PREFIX: &str = "enc:";

/// Shown in place of a secret in API output + audit records.
pub const REDACTED: &str = "********";

/// Payload fields encrypted at rest.
pub const SECRET_FIELDS: &[&str] = &["password"];

/// Context (AAD part) of task payload ciphertexts.
pub fn task_context(id: Uuid) -> String {
    format!("task:{id}")
}

/// Context (AAD part) of bulk job payload ciphertexts.
pub fn job_context(id: Uuid) -> String {
    format!("job:{id}")
}

/// Context (AAD part) of task `index` in the `run` list of stored preset `id`.
/// Slots keep their names from the task's own payload
/// -> queued task gets its secrets via [`SecretBox::seal_for_task`].
pub fn preset_context(id: Uuid, index: usize) -> String {
    format!("preset:{id}:run[{index}]")
}

fn slot_aad(context: &str, path: &str) -> Vec<u8> {
    format!("{context}#{path}").into_bytes()
}

fn credential_aad(device: Uuid) -> Vec<u8> {
    format!("credential:{device}").into_bytes()
}

fn totp_aad(user: Uuid) -> Vec<u8> {
    format!("totp:{user}").into_bytes()
}

fn wg_psk_aad(member: Uuid) -> Vec<u8> {
    format!("wg-psk:{member}").into_bytes()
}

/// Secret store errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretError {
    /// Key != 32 bytes of base64.
    #[error("the secrets key must be 32 bytes, base64-encoded")]
    BadKey,
    /// Open failed: wrong key, ciphertext of another row, or corrupt data.
    #[error(
        "a stored secret could not be decrypted (wrong --secrets-key, or it was copied from another row)"
    )]
    Decrypt,
    /// OS random generator failed.
    #[error("random number generator failure")]
    Rng,
    /// Value to encrypt already looks like ciphertext.
    #[error("a secret value starts with \"enc:\", which is reserved for encrypted secrets")]
    Reserved,
    /// Secret slot = mask, but no stored value to keep.
    #[error(
        "{0}: the value is the mask \"********\", but no secret is stored in this place to keep; give the secret"
    )]
    NoStored(String),
    /// Secret slot = mask, but task changed where the secret goes (X-8).
    /// Keep stored secret -> hand it to a new destination.
    #[error("re-enter the secret for {slot}: {reason}")]
    Moved {
        /// Slot as `run[<i>].<name>`.
        slot: String,
        /// What changed.
        reason: String,
    },
}

/// Seal with current master key; open with it or an old one.
pub struct SecretBox {
    key: LessSafeKey,
    key_id: String,
    /// Retired keys: open only.
    old: Vec<LessSafeKey>,
    rng: SystemRandom,
}

fn key_from_base64(key: &str) -> Result<LessSafeKey, SecretError> {
    let raw = B64.decode(key.trim()).map_err(|_| SecretError::BadKey)?;
    if raw.len() != 32 {
        return Err(SecretError::BadKey);
    }
    let unbound = UnboundKey::new(&AES_256_GCM, &raw).map_err(|_| SecretError::BadKey)?;
    Ok(LessSafeKey::new(unbound))
}

fn open_with(
    key: &LessSafeKey,
    ciphertext: &[u8],
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
) -> Option<Vec<u8>> {
    let mut data = ciphertext.to_vec();
    key.open_in_place(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut data,
    )
    .ok()
    .map(|p| p.to_vec())
}

impl std::fmt::Debug for SecretBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretBox")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Opened payload secret.
struct Opened {
    plain: String,
    /// Current form (v2) + current key -> nothing to rewrap.
    current: bool,
}

impl SecretBox {
    /// Base64 32-byte key. `key_id` stored with each secret -> rotation.
    pub fn from_base64(key: &str, key_id: impl Into<String>) -> Result<Self, SecretError> {
        Ok(Self {
            key: key_from_base64(key)?,
            key_id: key_id.into(),
            old: Vec::new(),
            rng: SystemRandom::new(),
        })
    }

    /// Add retired keys (base64, 32 bytes each): open only, never seal.
    pub fn with_old_keys<S: AsRef<str>>(mut self, keys: &[S]) -> Result<Self, SecretError> {
        for k in keys {
            self.old.push(key_from_base64(k.as_ref())?);
        }
        Ok(self)
    }

    pub fn has_old_keys(&self) -> bool {
        !self.old.is_empty()
    }

    /// ID of the current key.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    fn seal_with_aad(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), SecretError> {
        let mut nonce = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce).map_err(|_| SecretError::Rng)?;
        let mut data = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut data,
            )
            .map_err(|_| SecretError::Rng)?;
        Ok((data, nonce.to_vec()))
    }

    /// Try current key, then old ones -> (plaintext, opened by current key).
    fn open_with_aad(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, bool), SecretError> {
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| SecretError::Decrypt)?;
        if let Some(p) = open_with(&self.key, ciphertext, nonce, aad) {
            return Ok((p, true));
        }
        self.old
            .iter()
            .find_map(|k| open_with(k, ciphertext, nonce, aad))
            .map(|p| (p, false))
            .ok_or(SecretError::Decrypt)
    }

    /// Seal a device credential password -> `(ciphertext with tag, nonce)`.
    pub fn seal_credential(
        &self,
        device: Uuid,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), SecretError> {
        self.seal_with_aad(plaintext, &credential_aad(device))
    }

    /// Open [`SecretBox::seal_credential`] output for `device`, current or old key.
    /// Rows older than the AAD: sealed without AAD, still open.
    pub fn open_credential(
        &self,
        device: Uuid,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, SecretError> {
        self.open_with_aad(ciphertext, nonce, &credential_aad(device))
            .or_else(|_| self.open_with_aad(ciphertext, nonce, &[]))
            .map(|(p, _)| p)
    }

    /// True = current form: bound to `device` + current key.
    /// False -> [`rewrap_secrets`] seals it again.
    pub fn credential_is_current(&self, device: Uuid, ciphertext: &[u8], nonce: &[u8]) -> bool {
        self.open_with_aad(ciphertext, nonce, &credential_aad(device))
            .is_ok_and(|(_, current)| current)
    }

    /// Seal an operator TOTP secret (ADR-100) -> `(ciphertext with tag, nonce)`.
    pub fn seal_totp(
        &self,
        user: Uuid,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), SecretError> {
        self.seal_with_aad(plaintext, &totp_aad(user))
    }

    /// Open [`SecretBox::seal_totp`] output for `user`, current or old key.
    pub fn open_totp(
        &self,
        user: Uuid,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, SecretError> {
        self.open_with_aad(ciphertext, nonce, &totp_aad(user))
            .map(|(p, _)| p)
    }

    /// True = sealed with current key. False -> [`rewrap_secrets`] seals it again.
    pub fn totp_is_current(&self, user: Uuid, ciphertext: &[u8], nonce: &[u8]) -> bool {
        self.open_with_aad(ciphertext, nonce, &totp_aad(user))
            .is_ok_and(|(_, current)| current)
    }

    /// Seal a WireGuard member PSK (ADR-110) -> `(ciphertext with tag, nonce)`.
    pub fn seal_wg_psk(&self, member: Uuid, psk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SecretError> {
        self.seal_with_aad(psk, &wg_psk_aad(member))
    }

    /// Open [`SecretBox::seal_wg_psk`] output for `member`, current or old key.
    /// Plaintext zeroed on drop.
    pub fn open_wg_psk(
        &self,
        member: Uuid,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, SecretError> {
        self.open_with_aad(ciphertext, nonce, &wg_psk_aad(member))
            .map(|(p, _)| zeroize::Zeroizing::new(p))
    }

    /// True = sealed with current key. False -> [`rewrap_secrets`] seals it again.
    pub fn wg_psk_is_current(&self, member: Uuid, ciphertext: &[u8], nonce: &[u8]) -> bool {
        self.open_with_aad(ciphertext, nonce, &wg_psk_aad(member))
            .is_ok_and(|(p, current)| {
                drop(zeroize::Zeroizing::new(p));
                current
            })
    }

    fn seal_str(&self, s: &str, context: &str, path: &str) -> Result<String, SecretError> {
        let (ct, nonce) = self.seal_with_aad(s.as_bytes(), &slot_aad(context, path))?;
        let mut blob = nonce;
        blob.extend(ct);
        Ok(format!("{V2}{}", B64.encode(blob)))
    }

    /// Open a payload secret. `None` = `s` not ciphertext (plain value).
    fn open_str(&self, s: &str, context: &str, path: &str) -> Result<Option<Opened>, SecretError> {
        let (v2, b64) = if let Some(b) = s.strip_prefix(V2) {
            (true, b)
        } else if let Some(b) = s.strip_prefix(V1) {
            (false, b)
        } else {
            return Ok(None);
        };
        let blob = B64.decode(b64).map_err(|_| SecretError::Decrypt)?;
        if blob.len() < NONCE_LEN {
            return Err(SecretError::Decrypt);
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let aad = if v2 {
            slot_aad(context, path)
        } else {
            Vec::new()
        };
        let (plain, current) = self.open_with_aad(ct, nonce, &aad)?;
        Ok(Some(Opened {
            plain: String::from_utf8(plain).map_err(|_| SecretError::Decrypt)?,
            current: v2 && current,
        }))
    }

    /// Re-seal secret fields not in current form (old key or `enc:v1:`) with current key.
    /// True = something changed.
    pub fn rewrap_fields(&self, payload: &mut Value, context: &str) -> Result<bool, SecretError> {
        let mut changed = false;
        for (path, slot) in secret_slots(payload) {
            if let Value::String(s) = slot
                && let Some(opened) = self.open_str(s, context, &path)?
                && !opened.current
            {
                *s = self.seal_str(&opened.plain, context, &path)?;
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Non-empty secret fields of a JSON object -> `enc:v2:` values bound to `context`.
    /// Fields: top-level [`SECRET_FIELDS`] + `value` of `values` entries with
    /// `"secret": true` (SPV). Value already like ciphertext -> [`SecretError::Reserved`].
    pub fn encrypt_fields(&self, payload: &mut Value, context: &str) -> Result<(), SecretError> {
        for (path, slot) in secret_slots(payload) {
            if let Value::String(s) = slot
                && !s.is_empty()
            {
                if s.starts_with(CIPHERTEXT_PREFIX) {
                    return Err(SecretError::Reserved);
                }
                *s = self.seal_str(s, context, &path)?;
            }
        }
        Ok(())
    }

    /// Open secret fields sealed by [`SecretBox::encrypt_fields`] for `context`.
    /// `enc:v1:` opens in any context. Plain values unchanged.
    pub fn decrypt_fields(&self, payload: &mut Value, context: &str) -> Result<(), SecretError> {
        for (path, slot) in secret_slots(payload) {
            if let Value::String(s) = slot
                && let Some(opened) = self.open_str(s, context, &path)?
            {
                *s = opened.plain;
            }
        }
        Ok(())
    }

    /// Secret fields sealed for `from` -> opened + sealed again for `to`.
    /// Use: job payload -> member task.
    pub fn reseal_fields(
        &self,
        payload: &mut Value,
        from: &str,
        to: &str,
    ) -> Result<(), SecretError> {
        for (path, slot) in secret_slots(payload) {
            if let Value::String(s) = slot
                && let Some(opened) = self.open_str(s, from, &path)?
            {
                *s = self.seal_str(&opened.plain, to, &path)?;
            }
        }
        Ok(())
    }

    /// Secrets of a task a preset queues -> sealed for the task `to`.
    /// Ciphertext bound to `from` (preset's [`preset_context`]) -> opened + sealed again.
    /// Plain values (preset stored before sealed secrets, or from a file) -> sealed.
    /// No `from` -> ciphertext refused.
    pub fn seal_for_task(
        &self,
        payload: &mut Value,
        from: Option<&str>,
        to: &str,
    ) -> Result<(), SecretError> {
        for (path, slot) in secret_slots(payload) {
            let Value::String(s) = slot else { continue };
            if s.is_empty() {
                continue;
            }
            let plain = if s.starts_with(CIPHERTEXT_PREFIX) {
                let from = from.ok_or(SecretError::Reserved)?;
                self.open_str(s, from, &path)?
                    .ok_or(SecretError::Reserved)?
                    .plain
            } else {
                s.clone()
            };
            *s = self.seal_str(&plain, to, &path)?;
        }
        Ok(())
    }

    /// Prepare a preset definition from the API for storage as preset `id`.
    ///
    /// Each non-empty secret slot of its tasks -> sealed for [`preset_context`].
    /// Slot = mask ([`REDACTED`]) -> keep value of the same place (task index + slot name)
    /// in `stored` (definition being replaced); none -> [`SecretError::NoStored`].
    /// Keep only while task fields that decide the destination are unchanged (`moved`):
    /// kind, download/upload URL (scheme, host, port, path) + stored file, parameter name
    /// of a secret value. Else [`SecretError::Moved`] -> secret must be typed again.
    /// Why: else an account that may edit presets could point a task at its own server or
    /// a parameter it can read -> stored secret sent there.
    /// Ciphertext-like value -> [`SecretError::Reserved`].
    pub fn seal_preset(
        &self,
        definition: &mut Value,
        id: Uuid,
        stored: Option<&Value>,
    ) -> Result<(), SecretError> {
        let mut stored = stored.cloned().unwrap_or(Value::Null);
        // Tasks as submitted, before sealing -> compare in `moved`.
        let submitted: Vec<Value> = match definition.get("run") {
            Some(Value::Array(run)) => run.clone(),
            _ => Vec::new(),
        };
        let stored_tasks: Vec<Value> = match stored.get("run") {
            Some(Value::Array(run)) => run.clone(),
            _ => Vec::new(),
        };
        let mut kept = std::collections::HashMap::new();
        for (i, payload) in run_payloads(&mut stored) {
            for (name, slot) in secret_slots(payload) {
                if let Some(s) = slot.as_str().filter(|s| !s.is_empty()) {
                    kept.insert((i, name), s.to_owned());
                }
            }
        }
        for (i, payload) in run_payloads(definition) {
            let context = preset_context(id, i);
            for (name, slot) in secret_slots(payload) {
                let Value::String(s) = slot else { continue };
                if s.is_empty() {
                    continue;
                }
                if s == REDACTED {
                    let old = kept
                        .get(&(i, name.clone()))
                        .ok_or_else(|| SecretError::NoStored(format!("run[{i}].{name}")))?;
                    if let Some(reason) = moved(stored_tasks.get(i), submitted.get(i), &name) {
                        return Err(SecretError::Moved {
                            slot: format!("run[{i}].{name}"),
                            reason: reason.into(),
                        });
                    }
                    *s = match self.open_str(old, &context, &name)? {
                        Some(opened) if opened.current => old.clone(),
                        Some(opened) => self.seal_str(&opened.plain, &context, &name)?,
                        // Plain: stored before presets sealed secrets.
                        None => self.seal_str(old, &context, &name)?,
                    };
                } else if s.starts_with(CIPHERTEXT_PREFIX) {
                    return Err(SecretError::Reserved);
                } else {
                    *s = self.seal_str(s, &context, &name)?;
                }
            }
        }
        Ok(())
    }

    /// Re-seal stored preset secrets: old key, legacy form, or plain from before presets
    /// sealed them. True = something changed.
    pub fn rewrap_preset(&self, definition: &mut Value, id: Uuid) -> Result<bool, SecretError> {
        let mut changed = false;
        for (i, payload) in run_payloads(definition) {
            let context = preset_context(id, i);
            for (name, slot) in secret_slots(payload) {
                let Value::String(s) = slot else { continue };
                if s.is_empty() || s == REDACTED {
                    continue;
                }
                match self.open_str(s, &context, &name)? {
                    Some(opened) if opened.current => {}
                    Some(opened) => {
                        *s = self.seal_str(&opened.plain, &context, &name)?;
                        changed = true;
                    }
                    None => {
                        *s = self.seal_str(s, &context, &name)?;
                        changed = true;
                    }
                }
            }
        }
        Ok(changed)
    }
}

/// Counts of [`rewrap_secrets`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rewrapped {
    /// Device credentials re-sealed.
    pub credentials: usize,
    /// Task + job payloads re-sealed.
    pub payloads: usize,
    /// Presets re-sealed + preset history entries masked.
    pub presets: usize,
    /// Operator TOTP secrets re-sealed.
    pub totp: usize,
    /// WireGuard member PSKs re-sealed.
    pub wg_psks: usize,
    /// Secrets no configured key opens (left as is).
    pub unreadable: usize,
}

/// Re-seal every stored secret not in current form + current key (ADR-082).
/// Covers: device credentials, operator TOTP secrets, WireGuard PSKs, payloads of
/// unfinished tasks + jobs, stored presets ([`rewrap_presets`]).
/// Safe in several processes at once: row changed meanwhile -> left for next run.
pub async fn rewrap_secrets(
    store: &dhonomos_store::Store,
    secrets: &SecretBox,
) -> Result<Rewrapped, dhonomos_store::StoreError> {
    let mut done = Rewrapped::default();
    let mut after = None;
    loop {
        let page = store.credentials_page(after.clone(), 1000).await?;
        let Some(last) = page.last() else { break };
        after = Some((last.device_id, last.kind.clone()));
        for c in &page {
            if secrets.credential_is_current(c.device_id, &c.ciphertext, &c.nonce) {
                continue;
            }
            let Ok(plain) = secrets.open_credential(c.device_id, &c.ciphertext, &c.nonce) else {
                done.unreadable += 1;
                continue;
            };
            let Ok((ct, nonce)) = secrets.seal_credential(c.device_id, &plain) else {
                continue;
            };
            if store
                .rewrap_credential(c, &ct, &nonce, secrets.key_id())
                .await?
            {
                done.credentials += 1;
            }
        }
    }
    let mut after = None;
    loop {
        let page = store.totp_secrets_page(after, 1000).await?;
        let Some(last) = page.last() else { break };
        after = Some(last.user_id);
        for t in &page {
            if secrets.totp_is_current(t.user_id, &t.ciphertext, &t.nonce) {
                continue;
            }
            let Ok(plain) = secrets.open_totp(t.user_id, &t.ciphertext, &t.nonce) else {
                done.unreadable += 1;
                continue;
            };
            let Ok((ct, nonce)) = secrets.seal_totp(t.user_id, &plain) else {
                continue;
            };
            if store.rewrap_totp(t, &ct, &nonce, secrets.key_id()).await? {
                done.totp += 1;
            }
        }
    }
    let mut after = None;
    loop {
        let page = store.wg_psks_page(after, 1000).await?;
        let Some(last) = page.last() else { break };
        after = Some(last.member_id);
        for p in &page {
            if secrets.wg_psk_is_current(p.member_id, &p.ciphertext, &p.nonce) {
                continue;
            }
            let Ok(plain) = secrets.open_wg_psk(p.member_id, &p.ciphertext, &p.nonce) else {
                done.unreadable += 1;
                continue;
            };
            let Ok((ct, nonce)) = secrets.seal_wg_psk(p.member_id, &plain) else {
                continue;
            };
            if store.rewrap_wg_psk(p, &ct, &nonce).await? {
                done.wg_psks += 1;
            }
        }
    }
    for (is_job, id, payload) in store.payloads_with_secrets().await? {
        let context = if is_job {
            job_context(id)
        } else {
            task_context(id)
        };
        let mut new = payload.clone();
        match secrets.rewrap_fields(&mut new, &context) {
            Ok(true) => {
                if store.replace_payload(is_job, id, &payload, &new).await? {
                    done.payloads += 1;
                }
            }
            Ok(false) => {}
            Err(_) => done.unreadable += 1,
        }
    }
    let presets = rewrap_presets(store, secrets).await?;
    done.presets = presets.presets;
    done.unreadable += presets.unreadable;
    Ok(done)
}

/// Re-seal secrets of every stored preset not in current form (old key, `enc:v1:`, or
/// plain from before presets sealed them) + mask secrets in older history entries.
/// Safe in several processes at once + at every start: row changed meanwhile -> next run.
pub async fn rewrap_presets(
    store: &dhonomos_store::Store,
    secrets: &SecretBox,
) -> Result<Rewrapped, dhonomos_store::StoreError> {
    let mut done = Rewrapped::default();
    for (id, definition) in store.presets_for_rewrap().await? {
        let mut new = definition.clone();
        match secrets.rewrap_preset(&mut new, id) {
            Ok(true) => {
                if store
                    .replace_preset_definition(id, &definition, &new)
                    .await?
                {
                    done.presets += 1;
                }
            }
            Ok(false) => {}
            Err(_) => done.unreadable += 1,
        }
    }
    for (id, definition) in store.preset_history_with_secrets().await? {
        let masked = redact_preset(&definition);
        if masked != definition
            && store
                .replace_history_definition(id, &definition, &masked)
                .await?
        {
            done.presets += 1;
        }
    }
    Ok(done)
}

/// Destination of a download/upload: URL without credentials, query, fragment;
/// scheme + host lower case. Not a URL -> the text itself.
fn url_target(url: &str) -> String {
    let url = url.trim();
    let url = url.split(['?', '#']).next().unwrap_or(url);
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            let host = authority.rsplit('@').next().unwrap_or(authority);
            format!(
                "{}://{}{path}",
                scheme.to_ascii_lowercase(),
                host.to_ascii_lowercase()
            )
        }
        None => url.to_owned(),
    }
}

/// Why a mask in `slot` may not keep the secret of the stored task it replaces.
/// `None` = same where it matters: kind; download/upload -> URL ([`url_target`]) + `file_id`;
/// secret parameter value -> name of that parameter; other tasks -> all but the secrets.
/// Other fields (user name, delay, other values) may change: secret goes nowhere new.
fn moved(old: Option<&Value>, new: Option<&Value>, slot: &str) -> Option<&'static str> {
    let (Some(old), Some(new)) = (old, new) else {
        return Some("the task is not the one that was stored");
    };
    let kind = |t: &Value| {
        t.get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    if kind(old) != kind(new) {
        return Some("the task kind changed");
    }
    let payload = |t: &Value| t.get("payload").cloned().unwrap_or(Value::Null);
    let (old_payload, new_payload) = (payload(old), payload(new));
    if let Some(index) = slot
        .strip_prefix("values[")
        .and_then(|rest| rest.strip_suffix("].value"))
        .and_then(|i| i.parse::<usize>().ok())
    {
        let name = |p: &Value| p.pointer(&format!("/values/{index}/name")).cloned();
        return (name(&old_payload) != name(&new_payload)).then_some("the parameter name changed");
    }
    match kind(new).as_str() {
        "download" | "upload" => {
            let url =
                |p: &Value| url_target(p.get("url").and_then(Value::as_str).unwrap_or_default());
            if url(&old_payload) != url(&new_payload) {
                Some("the URL changed")
            } else if old_payload.get("file_id") != new_payload.get("file_id") {
                Some("the stored file changed")
            } else {
                None
            }
        }
        _ => {
            let bare = |mut p: Value| {
                for (_, slot) in secret_slots(&mut p) {
                    *slot = Value::Null;
                }
                p
            };
            (bare(old_payload) != bare(new_payload)).then_some("the task changed")
        }
    }
}

/// `payload` objects of the tasks in a preset `run` list, with task index.
fn run_payloads(definition: &mut Value) -> Vec<(usize, &mut Value)> {
    let Some(Value::Array(run)) = definition.get_mut("run") else {
        return Vec::new();
    };
    run.iter_mut()
        .enumerate()
        .filter_map(|(i, task)| Some((i, task.get_mut("payload")?)))
        .collect()
}

/// Preset has a secret in any task, any form.
pub fn preset_has_secret(definition: &Value) -> bool {
    let mut definition = definition.clone();
    run_payloads(&mut definition).into_iter().any(|(_, p)| {
        secret_slots(p)
            .into_iter()
            .any(|(_, v)| v.as_str().is_some_and(|s| !s.is_empty()))
    })
}

/// Preset has a given secret, not a kept one: non-empty + != mask.
pub fn preset_has_new_secret(definition: &Value) -> bool {
    let mut definition = definition.clone();
    run_payloads(&mut definition).into_iter().any(|(_, p)| {
        secret_slots(p)
            .into_iter()
            .any(|(_, v)| v.as_str().is_some_and(|s| !s.is_empty() && s != REDACTED))
    })
}

/// Preset slots that hold the mask ([`REDACTED`]), as `run[<i>].<slot>`.
/// Preset file: none allowed (mask = API output in place of a secret).
pub fn masked_preset_slots(definition: &Value) -> Vec<String> {
    let mut definition = definition.clone();
    let mut out = Vec::new();
    for (i, payload) in run_payloads(&mut definition) {
        for (name, slot) in secret_slots(payload) {
            if slot.as_str() == Some(REDACTED) {
                out.push(format!("run[{i}].{name}"));
            }
        }
    }
    out
}

/// Copy of a preset, each non-empty task secret -> [`REDACTED`]. For API output + history.
pub fn redact_preset(definition: &Value) -> Value {
    let mut out = definition.clone();
    for (_, payload) in run_payloads(&mut out) {
        *payload = redact_secrets(payload);
    }
    out
}

/// Secret JSON values of a task payload + slot names (AAD part):
/// `password`, `values[<index>].value` of entries with `"secret": true`.
fn secret_slots(payload: &mut Value) -> Vec<(String, &mut Value)> {
    let Some(obj) = payload.as_object_mut() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (k, v) in obj.iter_mut() {
        if SECRET_FIELDS.contains(&k.as_str()) {
            out.push((k.clone(), v));
        } else if k == "values"
            && let Value::Array(values) = v
        {
            for (i, entry) in values.iter_mut().enumerate() {
                if let Some(e) = entry.as_object_mut()
                    && e.get("secret") == Some(&Value::Bool(true))
                    && let Some(value) = e.get_mut("value")
                {
                    out.push((format!("values[{i}].value"), value));
                }
            }
        }
    }
    out
}

/// Payload has a plain secret -> needs a key to store.
pub fn has_plain_secret(payload: &Value) -> bool {
    let mut payload = payload.clone();
    secret_slots(&mut payload).into_iter().any(|(_, v)| {
        v.as_str()
            .is_some_and(|s| !s.is_empty() && !s.starts_with(CIPHERTEXT_PREFIX))
    })
}

/// Payload has a secret stored as ciphertext.
pub fn has_encrypted_secret(payload: &Value) -> bool {
    let mut payload = payload.clone();
    secret_slots(&mut payload)
        .into_iter()
        .any(|(_, v)| v.as_str().is_some_and(|s| s.starts_with(CIPHERTEXT_PREFIX)))
}

/// Refuse API payload with a secret field starting with `enc:`.
/// Callers send plain secrets only, never ciphertext (copied one -> server decrypts it for them).
pub fn reject_ciphertext_input(payload: &Value) -> Result<(), String> {
    let mut payload = payload.clone();
    for (path, slot) in secret_slots(&mut payload) {
        if slot
            .as_str()
            .is_some_and(|s| s.starts_with(CIPHERTEXT_PREFIX))
        {
            return Err(format!(
                "{path}: secret values starting with \"enc:\" are reserved for encrypted secrets and cannot be submitted"
            ));
        }
    }
    Ok(())
}

/// Copy of `payload`, each non-empty secret field -> [`REDACTED`]. For API output + audit.
pub fn redact_secrets(payload: &Value) -> Value {
    let mut out = payload.clone();
    for (_, slot) in secret_slots(&mut out) {
        if slot.as_str().is_some_and(|s| !s.is_empty()) {
            *slot = Value::String(REDACTED.into());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="; // 32 bytes

    fn boxed(key: &str, id: &str) -> SecretBox {
        SecretBox::from_base64(key, id).unwrap_or_else(|e| panic!("{e}"))
    }

    /// `enc:v1:` value as older versions wrote it: no AAD.
    fn legacy_v1(key_b64: &str, plain: &str) -> String {
        let key = key_from_base64(key_b64).unwrap_or_else(|e| panic!("{e}"));
        let nonce = [7u8; NONCE_LEN];
        let mut data = plain.as_bytes().to_vec();
        key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut data)
            .unwrap_or_else(|e| panic!("{e}"));
        let mut blob = nonce.to_vec();
        blob.extend(data);
        format!("{V1}{}", B64.encode(blob))
    }

    #[test]
    fn rotation_opens_old_secrets_and_rewraps_them() {
        let old_key = B64.encode([1u8; 32]);
        let new_key = B64.encode([2u8; 32]);
        let old = boxed(&old_key, "k1");
        let device = Uuid::now_v7();
        let (ct, nonce) = old
            .seal_credential(device, b"hunter2")
            .unwrap_or_else(|e| panic!("{e}"));
        let ctx = task_context(Uuid::now_v7());
        let mut payload = json!({ "url": "http://x", "password": "s3cret" });
        old.encrypt_fields(&mut payload, &ctx)
            .unwrap_or_else(|e| panic!("{e}"));

        // New key alone -> cannot open; old key listed -> opens.
        let new_only = boxed(&new_key, "k2");
        assert_eq!(
            new_only.open_credential(device, &ct, &nonce),
            Err(SecretError::Decrypt)
        );
        let rotating = boxed(&new_key, "k2")
            .with_old_keys(std::slice::from_ref(&old_key))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(rotating.has_old_keys());
        assert_eq!(
            rotating.open_credential(device, &ct, &nonce),
            Ok(b"hunter2".to_vec())
        );
        assert!(!rotating.credential_is_current(device, &ct, &nonce));

        // Rewrap -> payload under new key; 2nd pass -> no change.
        let mut rewrapped = payload.clone();
        assert_eq!(rotating.rewrap_fields(&mut rewrapped, &ctx), Ok(true));
        assert_ne!(rewrapped, payload);
        assert_eq!(rotating.rewrap_fields(&mut rewrapped, &ctx), Ok(false));
        let mut plain = rewrapped.clone();
        new_only
            .decrypt_fields(&mut plain, &ctx)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(plain["password"], "s3cret");
        assert!(
            SecretBox::from_base64(&new_key, "k2")
                .and_then(|b| b.with_old_keys(&["short"]))
                .is_err()
        );
    }

    #[test]
    fn credentials_are_bound_to_their_device() {
        let b = boxed(KEY, "k1");
        let (a, c) = (Uuid::now_v7(), Uuid::now_v7());
        let (ct, nonce) = b
            .seal_credential(a, b"hunter2")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_ne!(&ct[..7], b"hunter2");
        assert_eq!(b.open_credential(a, &ct, &nonce), Ok(b"hunter2".to_vec()));
        assert!(b.credential_is_current(a, &ct, &nonce));
        // Row of another device -> fails.
        assert_eq!(b.open_credential(c, &ct, &nonce), Err(SecretError::Decrypt));
        let (ct2, nonce2) = b
            .seal_credential(a, b"hunter2")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_ne!((ct.clone(), nonce.clone()), (ct2, nonce2), "random nonces");
        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        assert_eq!(
            b.open_credential(a, &tampered, &nonce),
            Err(SecretError::Decrypt)
        );
        let other = boxed("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU=", "k2");
        assert_eq!(
            other.open_credential(a, &ct, &nonce),
            Err(SecretError::Decrypt)
        );

        // Credential sealed before AAD -> still opens, not current.
        let key = key_from_base64(KEY).unwrap_or_else(|e| panic!("{e}"));
        let n = [3u8; NONCE_LEN];
        let mut data = b"old-style".to_vec();
        key.seal_in_place_append_tag(Nonce::assume_unique_for_key(n), Aad::empty(), &mut data)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(b.open_credential(a, &data, &n), Ok(b"old-style".to_vec()));
        assert!(!b.credential_is_current(a, &data, &n));
    }

    #[test]
    fn totp_secrets_are_bound_to_their_user_and_rotate() {
        let old_key = B64.encode([1u8; 32]);
        let new_key = B64.encode([2u8; 32]);
        let old = boxed(&old_key, "k1");
        let (user, other) = (Uuid::now_v7(), Uuid::now_v7());
        let (ct, nonce) = old
            .seal_totp(user, b"01234567890123456789")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            old.open_totp(user, &ct, &nonce),
            Ok(b"01234567890123456789".to_vec())
        );
        // Row of another account -> fails; credential AAD -> fails too.
        assert_eq!(old.open_totp(other, &ct, &nonce), Err(SecretError::Decrypt));
        assert_eq!(
            old.open_credential(user, &ct, &nonce),
            Err(SecretError::Decrypt)
        );
        let rotating = boxed(&new_key, "k2")
            .with_old_keys(std::slice::from_ref(&old_key))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(!rotating.totp_is_current(user, &ct, &nonce));
        let plain = rotating
            .open_totp(user, &ct, &nonce)
            .unwrap_or_else(|e| panic!("{e}"));
        let (ct2, nonce2) = rotating
            .seal_totp(user, &plain)
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(rotating.totp_is_current(user, &ct2, &nonce2));
        assert_eq!(
            boxed(&new_key, "k2").open_totp(user, &ct2, &nonce2),
            Ok(plain)
        );
    }

    #[test]
    fn wireguard_psks_are_bound_to_their_member_and_rotate() {
        let old_key = B64.encode([1u8; 32]);
        let new_key = B64.encode([2u8; 32]);
        let old = boxed(&old_key, "k1");
        let (member, other) = (Uuid::now_v7(), Uuid::now_v7());
        let psk = [7u8; 32];
        let (ct, nonce) = old
            .seal_wg_psk(member, &psk)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            old.open_wg_psk(member, &ct, &nonce).map(|p| p.to_vec()),
            Ok(psk.to_vec())
        );
        assert!(old.wg_psk_is_current(member, &ct, &nonce));
        // Row of another member -> fails; AAD of another secret kind -> fails too.
        assert_eq!(
            old.open_wg_psk(other, &ct, &nonce).map(|p| p.to_vec()),
            Err(SecretError::Decrypt)
        );
        assert!(!old.wg_psk_is_current(other, &ct, &nonce));
        assert_eq!(
            old.open_totp(member, &ct, &nonce),
            Err(SecretError::Decrypt)
        );
        let rotating = boxed(&new_key, "k2")
            .with_old_keys(std::slice::from_ref(&old_key))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(!rotating.wg_psk_is_current(member, &ct, &nonce));
        let plain = rotating
            .open_wg_psk(member, &ct, &nonce)
            .unwrap_or_else(|e| panic!("{e}"));
        let (ct2, nonce2) = rotating
            .seal_wg_psk(member, &plain)
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(rotating.wg_psk_is_current(member, &ct2, &nonce2));
        assert_eq!(
            boxed(&new_key, "k2")
                .open_wg_psk(member, &ct2, &nonce2)
                .map(|p| p.to_vec()),
            Ok(psk.to_vec())
        );
    }

    #[test]
    fn payload_fields() {
        let b = boxed(KEY, "k1");
        let ctx = task_context(Uuid::now_v7());
        let mut p = json!({"url": "http://f", "password": "hunter2", "username": "u"});
        assert!(has_plain_secret(&p));
        assert!(!has_encrypted_secret(&p));
        b.encrypt_fields(&mut p, &ctx)
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            p["password"]
                .as_str()
                .is_some_and(|s| s.starts_with("enc:v2:"))
        );
        assert!(!has_plain_secret(&p));
        assert!(has_encrypted_secret(&p));
        assert!(!p.to_string().contains("hunter2"));
        b.decrypt_fields(&mut p, &ctx)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p["password"], "hunter2");
        let mut spv = json!({"values": [
            {"name": "A.Password", "value": "s3cret", "secret": true},
            {"name": "A.Name", "value": "visible"}
        ]});
        assert!(has_plain_secret(&spv));
        b.encrypt_fields(&mut spv, &ctx)
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(!spv.to_string().contains("s3cret"));
        assert_eq!(spv["values"][1]["value"], "visible");
        assert!(!has_plain_secret(&spv));
        b.decrypt_fields(&mut spv, &ctx)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(spv["values"][0]["value"], "s3cret");
        assert!(!has_plain_secret(
            &json!({"values": [{"name": "A", "value": "x"}]})
        ));
        let mut empty = json!({"password": ""});
        b.encrypt_fields(&mut empty, &ctx)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(empty["password"], "");
        // Ciphertext-like value -> never sealed again.
        let mut copied = json!({"password": "enc:v2:AAAA"});
        assert_eq!(
            b.encrypt_fields(&mut copied, &ctx),
            Err(SecretError::Reserved)
        );
    }

    #[test]
    fn a_ciphertext_copied_to_another_task_does_not_open() {
        let b = boxed(KEY, "k1");
        let (first, second) = (task_context(Uuid::now_v7()), task_context(Uuid::now_v7()));
        let mut p = json!({"values": [
            {"name": "A.Password", "value": "s3cret", "secret": true},
            {"name": "B.Password", "value": "other", "secret": true}
        ]});
        b.encrypt_fields(&mut p, &first)
            .unwrap_or_else(|e| panic!("{e}"));

        // Copy into another task (same payload) -> fails.
        let mut elsewhere = p.clone();
        assert_eq!(
            b.decrypt_fields(&mut elsewhere, &second),
            Err(SecretError::Decrypt)
        );
        assert!(!elsewhere.to_string().contains("s3cret"));
        // As a job secret -> fails.
        let mut as_job = p.clone();
        assert_eq!(
            b.decrypt_fields(&mut as_job, &job_context(Uuid::now_v7())),
            Err(SecretError::Decrypt)
        );
        // Into another slot of the same task -> fails.
        let mut swapped = p.clone();
        let (a, c) = (
            p["values"][0]["value"].clone(),
            p["values"][1]["value"].clone(),
        );
        swapped["values"][0]["value"] = c;
        swapped["values"][1]["value"] = a;
        assert_eq!(
            b.decrypt_fields(&mut swapped, &first),
            Err(SecretError::Decrypt)
        );
        // Own place -> opens.
        b.decrypt_fields(&mut p, &first)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p["values"][0]["value"], "s3cret");
        assert_eq!(p["values"][1]["value"], "other");
    }

    #[test]
    fn legacy_v1_still_opens_and_is_rewrapped_to_v2() {
        let b = boxed(KEY, "k1");
        let ctx = task_context(Uuid::now_v7());
        let mut p = json!({"url": "http://f", "password": legacy_v1(KEY, "hunter2")});
        assert!(has_encrypted_secret(&p));
        // Opens in any context (has none).
        let mut plain = p.clone();
        b.decrypt_fields(&mut plain, &ctx)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(plain["password"], "hunter2");

        assert_eq!(b.rewrap_fields(&mut p, &ctx), Ok(true));
        assert!(
            p["password"]
                .as_str()
                .is_some_and(|s| s.starts_with("enc:v2:"))
        );
        assert_eq!(b.rewrap_fields(&mut p, &ctx), Ok(false));
        b.decrypt_fields(&mut p, &ctx)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p["password"], "hunter2");
        // Bound after rewrap: context of another task fails.
        let mut again = json!({"password": legacy_v1(KEY, "hunter2")});
        b.rewrap_fields(&mut again, &ctx)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            b.decrypt_fields(&mut again, &task_context(Uuid::now_v7())),
            Err(SecretError::Decrypt)
        );
    }

    #[test]
    fn a_job_payload_is_resealed_for_each_task() {
        let b = boxed(KEY, "k1");
        let job = job_context(Uuid::now_v7());
        let task = task_context(Uuid::now_v7());
        let mut p = json!({"url": "http://f", "password": "hunter2"});
        b.encrypt_fields(&mut p, &job)
            .unwrap_or_else(|e| panic!("{e}"));
        let mut for_task = p.clone();
        b.reseal_fields(&mut for_task, &job, &task)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_ne!(for_task, p);
        let mut opened = for_task.clone();
        b.decrypt_fields(&mut opened, &task)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(opened["password"], "hunter2");
        // Job ciphertext does not open as task ciphertext.
        assert_eq!(b.decrypt_fields(&mut p, &task), Err(SecretError::Decrypt));
    }

    #[test]
    fn secrets_are_redacted_everywhere() {
        let p = json!({
            "url": "http://f", "username": "u", "password": "hunter2", "empty": "",
            "values": [
                {"name": "A.Password", "value": "s3cret", "secret": true},
                {"name": "A.Name", "value": "visible"},
                {"name": "A.Key", "value": "enc:v2:AAAA", "secret": true},
                {"name": "A.Blank", "value": "", "secret": true}
            ]
        });
        let r = redact_secrets(&p);
        assert_eq!(r["password"], REDACTED);
        assert_eq!(r["values"][0]["value"], REDACTED);
        assert_eq!(r["values"][2]["value"], REDACTED);
        assert_eq!(r["values"][1]["value"], "visible");
        assert_eq!(r["values"][3]["value"], "", "nothing to hide");
        assert_eq!(r["url"], "http://f");
        assert!(!r.to_string().contains("s3cret") && !r.to_string().contains("hunter2"));
        assert!(!r.to_string().contains("enc:"));
    }

    #[test]
    fn ciphertext_input_is_refused() {
        assert!(reject_ciphertext_input(&json!({"password": "hunter2"})).is_ok());
        assert!(
            reject_ciphertext_input(&json!({"values": [{"name": "A", "value": "enc:x"}]})).is_ok()
        );
        for bad in [
            json!({"password": "enc:v1:AAAA"}),
            json!({"password": "enc:v2:AAAA"}),
            json!({"password": "enc:whatever"}),
        ] {
            let e = reject_ciphertext_input(&bad).err().unwrap_or_default();
            assert!(e.contains("password") && e.contains("enc:"), "{e}");
        }
        let e = reject_ciphertext_input(
            &json!({"values": [{"name": "A", "value": "enc:v2:AAAA", "secret": true}]}),
        )
        .err()
        .unwrap_or_default();
        assert!(e.contains("values[0].value"), "{e}");
    }

    fn preset_definition() -> Value {
        json!({ "name": "p", "run": [
            { "kind": "reboot" },
            { "kind": "download", "payload": { "url": "http://f", "username": "u", "password": "file-pw" } },
            { "kind": "set_parameter_values", "payload": { "values": [
                { "name": "A.Password", "value": "s3cret", "secret": true },
                { "name": "A.Name", "value": "visible" }
            ] } },
        ] })
    }

    #[test]
    fn preset_secrets_are_sealed_for_the_preset_and_masked_in_output() {
        let b = boxed(KEY, "k1");
        let id = Uuid::now_v7();
        let mut def = preset_definition();
        assert!(preset_has_secret(&def));
        assert!(preset_has_new_secret(&def));
        b.seal_preset(&mut def, id, None)
            .unwrap_or_else(|e| panic!("{e}"));
        let text = def.to_string();
        assert!(
            !text.contains("file-pw") && !text.contains("s3cret"),
            "{text}"
        );
        assert!(text.contains("visible") && text.contains("http://f"));

        // Secrets of each task -> open for own place only.
        let mut download = def["run"][1]["payload"].clone();
        let mut spv = def["run"][2]["payload"].clone();
        b.decrypt_fields(&mut download, &preset_context(id, 1))
            .unwrap_or_else(|e| panic!("{e}"));
        b.decrypt_fields(&mut spv, &preset_context(id, 2))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(download["password"], "file-pw");
        assert_eq!(spv["values"][0]["value"], "s3cret");
        let mut elsewhere = def["run"][1]["payload"].clone();
        assert_eq!(
            b.decrypt_fields(&mut elsewhere, &preset_context(Uuid::now_v7(), 1)),
            Err(SecretError::Decrypt),
            "another preset"
        );
        let mut moved = def["run"][1]["payload"].clone();
        assert_eq!(
            b.decrypt_fields(&mut moved, &preset_context(id, 2)),
            Err(SecretError::Decrypt),
            "another task of the preset"
        );
        let mut as_task = def["run"][1]["payload"].clone();
        assert_eq!(
            b.decrypt_fields(&mut as_task, &task_context(Uuid::now_v7())),
            Err(SecretError::Decrypt),
            "another kind of owner"
        );

        // Output + history -> mask in place, rest unchanged.
        let shown = redact_preset(&def);
        assert_eq!(shown["run"][1]["payload"]["password"], REDACTED);
        assert_eq!(shown["run"][1]["payload"]["username"], "u");
        assert_eq!(shown["run"][2]["payload"]["values"][0]["value"], REDACTED);
        assert_eq!(shown["run"][2]["payload"]["values"][1]["value"], "visible");
        assert!(!shown.to_string().contains("enc:"));
        assert!(!preset_has_new_secret(&shown));
        assert_eq!(
            masked_preset_slots(&shown),
            ["run[1].password", "run[2].values[0].value"]
        );
        assert!(masked_preset_slots(&def).is_empty());
    }

    #[test]
    fn the_mask_keeps_the_stored_secret_of_the_same_place() {
        let b = boxed(KEY, "k1");
        let id = Uuid::now_v7();
        let mut stored = preset_definition();
        b.seal_preset(&mut stored, id, None)
            .unwrap_or_else(|e| panic!("{e}"));

        // Edit as UI sends it: all as shown, one visible value changed.
        let mut edit = redact_preset(&stored);
        edit["run"][2]["payload"]["values"][1]["value"] = json!("renamed");
        b.seal_preset(&mut edit, id, Some(&stored))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            edit["run"][1]["payload"]["password"],
            stored["run"][1]["payload"]["password"]
        );
        assert_eq!(
            edit["run"][2]["payload"]["values"][0]["value"],
            stored["run"][2]["payload"]["values"][0]["value"]
        );
        assert_eq!(edit["run"][2]["payload"]["values"][1]["value"], "renamed");
        let mut spv = edit["run"][2]["payload"].clone();
        b.decrypt_fields(&mut spv, &preset_context(id, 2))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(spv["values"][0]["value"], "s3cret", "the secret survived");

        // New secret next to a kept one.
        let mut change = redact_preset(&stored);
        change["run"][1]["payload"]["password"] = json!("new-pw");
        b.seal_preset(&mut change, id, Some(&stored))
            .unwrap_or_else(|e| panic!("{e}"));
        let mut download = change["run"][1]["payload"].clone();
        b.decrypt_fields(&mut download, &preset_context(id, 1))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(download["password"], "new-pw");
        assert_eq!(
            change["run"][2]["payload"]["values"][0]["value"],
            stored["run"][2]["payload"]["values"][0]["value"]
        );

        // Nothing stored for the place -> mask refused, with slot.
        let mut fresh = redact_preset(&stored);
        assert_eq!(
            b.seal_preset(&mut fresh, id, None),
            Err(SecretError::NoStored("run[1].password".into()))
        );
        // Same secret at another place != "same place".
        let mut shifted = redact_preset(&stored);
        shifted["run"].as_array_mut().map(|r| r.remove(0));
        assert!(matches!(
            b.seal_preset(&mut shifted, id, Some(&stored)),
            Err(SecretError::NoStored(_))
        ));
        // Ciphertext as input -> always refused.
        let mut copied = preset_definition();
        copied["run"][1]["payload"]["password"] = stored["run"][1]["payload"]["password"].clone();
        assert_eq!(
            b.seal_preset(&mut copied, id, Some(&stored)),
            Err(SecretError::Reserved)
        );
        // Plain secret stored before presets sealed them -> kept + sealed now.
        let plain_stored = preset_definition();
        let mut edit = redact_preset(&plain_stored);
        b.seal_preset(&mut edit, id, Some(&plain_stored))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(!edit.to_string().contains("file-pw"));
        let mut download = edit["run"][1]["payload"].clone();
        b.decrypt_fields(&mut download, &preset_context(id, 1))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(download["password"], "file-pw");
    }

    #[test]
    fn the_mask_does_not_follow_a_task_that_now_sends_elsewhere() {
        let b = boxed(KEY, "k1");
        let id = Uuid::now_v7();
        let mut stored = preset_definition();
        b.seal_preset(&mut stored, id, None)
            .unwrap_or_else(|e| panic!("{e}"));
        let moved = |edit: &dyn Fn(&mut Value)| {
            let mut def = redact_preset(&stored);
            edit(&mut def);
            b.seal_preset(&mut def, id, Some(&stored))
        };
        let refused = |r: Result<(), SecretError>, slot: &str, reason: &str| match r {
            Err(SecretError::Moved {
                slot: s,
                reason: why,
            }) => {
                assert_eq!((s.as_str(), why.as_str()), (slot, reason));
            }
            other => panic!("expected {slot} to be refused ({reason}), got {other:?}"),
        };
        // Download -> other server, path, scheme, or stored file.
        refused(
            moved(&|d| d["run"][1]["payload"]["url"] = json!("http://evil.example/fw.bin")),
            "run[1].password",
            "the URL changed",
        );
        refused(
            moved(&|d| d["run"][1]["payload"]["url"] = json!("http://f/other.bin")),
            "run[1].password",
            "the URL changed",
        );
        refused(
            moved(&|d| d["run"][1]["payload"]["url"] = json!("https://f")),
            "run[1].password",
            "the URL changed",
        );
        refused(
            moved(&|d| d["run"][1]["payload"]["file_id"] = json!(Uuid::now_v7())),
            "run[1].password",
            "the stored file changed",
        );
        // Same task, other kind.
        refused(
            moved(&|d| d["run"][1]["kind"] = json!("upload")),
            "run[1].password",
            "the task kind changed",
        );
        // Secret value -> other parameter, or its task -> other kind.
        refused(
            moved(&|d| d["run"][2]["payload"]["values"][0]["name"] = json!("A.ReadableThing")),
            "run[2].values[0].value",
            "the parameter name changed",
        );
        refused(
            moved(&|d| d["run"][2]["kind"] = json!("get_parameter_values")),
            "run[2].values[0].value",
            "the task kind changed",
        );
        // Fields that do not decide the destination may change -> secret kept.
        let mut edit = redact_preset(&stored);
        edit["run"][1]["payload"]["username"] = json!("someone-else");
        edit["run"][1]["payload"]["url"] = json!("HTTP://F?token=1#x");
        edit["run"][1]["payload"]["delay_seconds"] = json!(30);
        edit["run"][2]["payload"]["values"][1]["name"] = json!("A.OtherName");
        edit["run"][2]["payload"]["values"][1]["value"] = json!("other");
        b.seal_preset(&mut edit, id, Some(&stored))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            edit["run"][1]["payload"]["password"],
            stored["run"][1]["payload"]["password"]
        );
        // Changed destination -> accepted only with the secret typed again.
        let mut retyped = redact_preset(&stored);
        retyped["run"][1]["payload"]["url"] = json!("http://new.example/fw.bin");
        retyped["run"][1]["payload"]["password"] = json!("typed-again");
        b.seal_preset(&mut retyped, id, Some(&stored))
            .unwrap_or_else(|e| panic!("{e}"));
        let mut download = retyped["run"][1]["payload"].clone();
        b.decrypt_fields(&mut download, &preset_context(id, 1))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(download["password"], "typed-again");
        assert_eq!(
            SecretError::Moved {
                slot: "run[1].password".into(),
                reason: "the URL changed".into()
            }
            .to_string(),
            "re-enter the secret for run[1].password: the URL changed"
        );
    }

    #[test]
    fn urls_are_compared_by_where_they_point() {
        assert_eq!(
            url_target("HTTP://User:pw@Files.Example:8080/a/b?x=1#f"),
            "http://files.example:8080/a/b"
        );
        assert_eq!(url_target("https://h"), "https://h");
        assert_eq!(url_target("  ftp://h/p  "), "ftp://h/p");
        assert_eq!(url_target("not a url?x"), "not a url");
        assert_ne!(url_target("http://h/a"), url_target("http://h:81/a"));
    }

    #[test]
    fn a_secret_of_another_kind_of_task_keeps_only_while_the_rest_is_the_same() {
        let b = boxed(KEY, "k1");
        let id = Uuid::now_v7();
        let mut stored = json!({ "run": [{ "kind": "other_kind",
            "payload": { "target": "a", "password": "pw" } }] });
        b.seal_preset(&mut stored, id, None)
            .unwrap_or_else(|e| panic!("{e}"));
        let mut same = redact_preset(&stored);
        b.seal_preset(&mut same, id, Some(&stored))
            .unwrap_or_else(|e| panic!("{e}"));
        let mut changed = redact_preset(&stored);
        changed["run"][0]["payload"]["target"] = json!("b");
        assert_eq!(
            b.seal_preset(&mut changed, id, Some(&stored)),
            Err(SecretError::Moved {
                slot: "run[0].password".into(),
                reason: "the task changed".into()
            })
        );
    }

    #[test]
    fn a_preset_secret_moves_into_the_task_it_queues() {
        let b = boxed(KEY, "k1");
        let id = Uuid::now_v7();
        let mut def = preset_definition();
        b.seal_preset(&mut def, id, None)
            .unwrap_or_else(|e| panic!("{e}"));
        let from = preset_context(id, 2);
        let task = task_context(Uuid::now_v7());
        let mut payload = def["run"][2]["payload"].clone();
        b.seal_for_task(&mut payload, Some(&from), &task)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_ne!(payload, def["run"][2]["payload"]);
        let mut opened = payload.clone();
        b.decrypt_fields(&mut opened, &task)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(opened["values"][0]["value"], "s3cret");
        assert_eq!(opened["values"][1]["value"], "visible");
        // Preset ciphertext does not open as task ciphertext.
        let mut raw = def["run"][2]["payload"].clone();
        assert_eq!(b.decrypt_fields(&mut raw, &task), Err(SecretError::Decrypt));
        // Ciphertext of another place, or no place -> refused.
        let mut other = def["run"][2]["payload"].clone();
        assert_eq!(
            b.seal_for_task(&mut other, Some(&preset_context(id, 1)), &task),
            Err(SecretError::Decrypt)
        );
        let mut nowhere = def["run"][2]["payload"].clone();
        assert_eq!(
            b.seal_for_task(&mut nowhere, None, &task),
            Err(SecretError::Reserved)
        );
        // Plain secret (preset from before sealing) -> sealed for the task.
        let mut legacy = preset_definition()["run"][1]["payload"].clone();
        b.seal_for_task(&mut legacy, Some(&preset_context(id, 1)), &task)
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(!legacy.to_string().contains("file-pw"));
        b.decrypt_fields(&mut legacy, &task)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(legacy["password"], "file-pw");
    }

    #[test]
    fn stored_presets_are_sealed_again_with_the_current_key() {
        let old_key = B64.encode([1u8; 32]);
        let new_key = B64.encode([2u8; 32]);
        let old = boxed(&old_key, "k1");
        let id = Uuid::now_v7();
        let mut def = preset_definition();
        old.seal_preset(&mut def, id, None)
            .unwrap_or_else(|e| panic!("{e}"));
        let rotating = boxed(&new_key, "k2")
            .with_old_keys(&[old_key])
            .unwrap_or_else(|e| panic!("{e}"));
        let mut rewrapped = def.clone();
        assert_eq!(rotating.rewrap_preset(&mut rewrapped, id), Ok(true));
        assert_eq!(rotating.rewrap_preset(&mut rewrapped, id), Ok(false));
        let new_only = boxed(&new_key, "k2");
        let mut download = rewrapped["run"][1]["payload"].clone();
        new_only
            .decrypt_fields(&mut download, &preset_context(id, 1))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(download["password"], "file-pw");
        // Plain secrets (saved before presets sealed them) -> sealed too.
        let mut plain = preset_definition();
        assert_eq!(new_only.rewrap_preset(&mut plain, id), Ok(true));
        assert!(!plain.to_string().contains("s3cret"));
        // No key opens it -> error, not a change.
        let mut lost = def.clone();
        assert_eq!(
            new_only.rewrap_preset(&mut lost, id),
            Err(SecretError::Decrypt)
        );
    }

    #[test]
    fn bad_keys() {
        assert_eq!(
            SecretBox::from_base64("short", "k").map(|_| ()),
            Err(SecretError::BadKey)
        );
        assert_eq!(
            SecretBox::from_base64("c2hvcnQ=", "k").map(|_| ()),
            Err(SecretError::BadKey)
        );
    }
}
