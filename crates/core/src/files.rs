//! Signed file server URLs (CW-16): download, upload, diagnostic, BulkData.
//!
//! `{base}/files/{file_id}/{name}?d={device}&e={expiry}&s={hex HMAC-SHA256}`
//! -> one device, one file, until expiry. No per-file credentials in the Download RPC.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dhonomos_store::Store;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use uuid::Uuid;

/// Kind of a device upload to the file server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadKind {
    /// Vendor configuration file (backup). Stored as `3 Vendor Configuration File`.
    Config,
    /// Vendor log file. Stored as `2 Vendor Log File`.
    Log,
}

impl UploadKind {
    /// TR-069 file type asked from the device.
    pub fn upload_file_type(self) -> &'static str {
        match self {
            Self::Config => "1 Vendor Configuration File",
            Self::Log => "2 Vendor Log File",
        }
    }

    /// File type of the stored upload.
    pub fn stored_file_type(self) -> &'static str {
        match self {
            Self::Config => "3 Vendor Configuration File",
            Self::Log => "2 Vendor Log File",
        }
    }
}

/// Diagnostic test link lifetime, unless the signer link lifetime is shorter.
/// Link made at task send -> only has to outlast the test.
/// Leaked link -> anyone can transfer up to [`DIAG_MAX_BYTES`] until expiry.
pub const DIAG_LINK_TTL: Duration = Duration::from_secs(3600);

/// Create + check signed file URLs.
/// Link lifetime can change at run time ([`FileSigner::set_ttl`]); clones share it.
#[derive(Clone)]
pub struct FileSigner {
    secret: Vec<u8>,
    base_url: String,
    /// Link lifetime in s, shared by clones.
    ttl: Arc<AtomicU64>,
    /// Set by [`FileSigner::with_diag_ttl`]; else link lifetime, max [`DIAG_LINK_TTL`].
    diag_ttl: Option<Duration>,
}

impl std::fmt::Debug for FileSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSigner")
            .field("base_url", &self.base_url)
            .field("ttl", &self.ttl())
            .field("diag_ttl", &self.diag_ttl())
            .finish_non_exhaustive()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Percent-encode a path segment. RFC 3986 unreserved chars pass through.
fn encode_segment(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

impl FileSigner {
    /// `base_url` = how devices reach the file server, e.g. `http://acs.example.net:7548`.
    pub fn new(secret: impl Into<Vec<u8>>, base_url: impl Into<String>, ttl: Duration) -> Self {
        Self {
            secret: secret.into(),
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            ttl: Arc::new(AtomicU64::new(ttl.as_secs())),
            diag_ttl: None,
        }
    }

    /// Lifetime of new links.
    pub fn ttl(&self) -> Duration {
        Duration::from_secs(self.ttl.load(Ordering::Relaxed))
    }

    /// Change lifetime of new links, for this signer + all its clones.
    /// Links already handed out keep their expiry.
    pub fn set_ttl(&self, ttl: Duration) {
        self.ttl.store(ttl.as_secs(), Ordering::Relaxed);
    }

    /// Lifetime of new diagnostic test links.
    fn diag_ttl(&self) -> Duration {
        self.diag_ttl
            .unwrap_or_else(|| self.ttl().min(DIAG_LINK_TTL))
    }

    /// Set lifetime of diagnostic test links. Default: link lifetime, max [`DIAG_LINK_TTL`].
    #[must_use]
    pub fn with_diag_ttl(mut self, ttl: Duration) -> Self {
        self.diag_ttl = Some(ttl);
        self
    }

    fn mac(&self, file: Uuid, device: Uuid, expiry: u64) -> String {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.secret)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        mac.update(format!("{file}|{device}|{expiry}").as_bytes());
        hex(&mac.finalize().into_bytes())
    }

    /// URL for `device` to download `file` (named `name`). Valid for the link lifetime.
    pub fn url(&self, file: Uuid, name: &str, device: Uuid) -> String {
        let expiry = now() + self.ttl().as_secs();
        format!(
            "{}/files/{file}/{}?d={device}&e={expiry}&s={}",
            self.base_url,
            encode_segment(name),
            self.mac(file, device, expiry)
        )
    }

    fn bulkdata_mac(&self, device: Uuid) -> String {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.secret)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        mac.update(format!("bulkdata|{device}").as_bytes());
        hex(&mac.finalize().into_bytes())
    }

    /// Where `device` posts BulkData reports (its `BulkData.Profile.{i}.HTTP.URL`, DG-04).
    /// No expiry; secret change -> all revoked.
    pub fn bulkdata_url(&self, device: Uuid) -> String {
        format!(
            "{}/bulkdata/{device}/{}",
            self.base_url,
            self.bulkdata_mac(device)
        )
    }

    fn upload_mac(&self, device: Uuid, upload: Uuid, kind: UploadKind, expiry: u64) -> String {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.secret)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        // Config tag = original form -> links already handed out stay valid.
        let tag = match kind {
            UploadKind::Config => "upload",
            UploadKind::Log => "upload-log",
        };
        mac.update(format!("{tag}|{device}|{upload}|{expiry}").as_bytes());
        hex(&mac.finalize().into_bytes())
    }

    /// Where `device` uploads one file of `kind` (CWMP Upload, USP `Backup()`/`Upload()`).
    /// Valid for the link lifetime.
    /// Kind signed -> device cannot store a log as a config it could later restore from.
    pub fn upload_url(&self, device: Uuid, upload: Uuid, kind: UploadKind) -> String {
        let expiry = now() + self.ttl().as_secs();
        let k = match kind {
            UploadKind::Config => "",
            UploadKind::Log => "k=log&",
        };
        format!(
            "{}/uploads/{device}/{upload}?{k}e={expiry}&s={}",
            self.base_url,
            self.upload_mac(device, upload, kind, expiry)
        )
    }

    /// Check signature + expiry of an upload URL.
    pub fn verify_upload(
        &self,
        device: Uuid,
        upload: Uuid,
        kind: UploadKind,
        expiry: u64,
        signature: &str,
    ) -> bool {
        let expected = self.upload_mac(device, upload, kind, expiry);
        expiry >= now()
            && expected.len() == signature.len()
            && expected
                .bytes()
                .zip(signature.bytes())
                .fold(0u8, |a, (x, y)| a | (x ^ y))
                == 0
    }

    fn diag_mac(&self, what: &str, device: Uuid, expiry: u64) -> String {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.secret)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        mac.update(format!("diag-{what}|{device}|{expiry}").as_bytes());
        hex(&mac.finalize().into_bytes())
    }

    /// Where `device` gets `bytes` bytes for a download diagnostic (DG-01, TR-143).
    /// Valid for the diagnostic link lifetime. Size signed -> link serves no more than asked.
    pub fn diag_download_url(&self, device: Uuid, bytes: u64) -> String {
        let expiry = now() + self.diag_ttl().as_secs();
        format!(
            "{}/diag/{device}/{bytes}?e={expiry}&s={}",
            self.base_url,
            self.diag_mac(&format!("down-{bytes}"), device, expiry)
        )
    }

    /// Where `device` sends upload diagnostic data -> counted + dropped.
    pub fn diag_upload_url(&self, device: Uuid) -> String {
        let expiry = now() + self.diag_ttl().as_secs();
        format!(
            "{}/diag/{device}?e={expiry}&s={}",
            self.base_url,
            self.diag_mac("up", device, expiry)
        )
    }

    /// Check signature (incl. size) + expiry of a download diagnostic link.
    pub fn verify_diag_download(&self, device: Uuid, bytes: u64, expiry: u64, sig: &str) -> bool {
        expiry >= now()
            && same(
                &self.diag_mac(&format!("down-{bytes}"), device, expiry),
                sig,
            )
    }

    /// Check signature + expiry of an upload diagnostic link.
    pub fn verify_diag_upload(&self, device: Uuid, expiry: u64, sig: &str) -> bool {
        expiry >= now() && same(&self.diag_mac("up", device, expiry), sig)
    }

    /// Check signature of a BulkData URL (no expiry).
    pub fn verify_bulkdata(&self, device: Uuid, signature: &str) -> bool {
        let expected = self.bulkdata_mac(device);
        expected.len() == signature.len()
            && expected
                .bytes()
                .zip(signature.bytes())
                .fold(0u8, |a, (x, y)| a | (x ^ y))
                == 0
    }

    /// Check signature + expiry of a file download request.
    pub fn verify(&self, file: Uuid, device: Uuid, expiry: u64, signature: &str) -> bool {
        let expected = self.mac(file, device, expiry);
        expiry >= now()
            && expected.len() == signature.len()
            && expected
                .bytes()
                .zip(signature.bytes())
                .fold(0u8, |a, (x, y)| a | (x ^ y))
                == 0
    }
}

/// Constant-time compare of two hex signatures.
fn same(expected: &str, signature: &str) -> bool {
    expected.len() == signature.len()
        && expected
            .bytes()
            .zip(signature.bytes())
            .fold(0u8, |a, (x, y)| a | (x ^ y))
            == 0
}

/// Download diagnostic bytes from the file server when the task gives no `size`.
pub const DIAG_DOWNLOAD_BYTES: u64 = 10_000_000;
/// Upload diagnostic bytes to the file server when the task gives no `size`.
pub const DIAG_UPLOAD_BYTES: u64 = 5_000_000;
/// Max download/upload diagnostic bytes the file server serves or takes.
pub const DIAG_MAX_BYTES: u64 = 1_000_000_000;

/// Download/upload diagnostic without `url` -> runs against the file server.
/// Task gets a signed test link for `device` (upload: also a `size`).
/// Other tasks unchanged.
pub fn resolve_diagnostic(
    signer: Option<&FileSigner>,
    device: Uuid,
    kind: crate::TaskKind,
) -> Result<crate::TaskKind, String> {
    use crate::diagnostics::DiagTest;
    let crate::TaskKind::Diagnostic { test, mut params } = kind else {
        return Ok(kind);
    };
    if !matches!(test, DiagTest::Download | DiagTest::Upload)
        || params.get("url").is_some_and(|u| !u.trim().is_empty())
    {
        return Ok(crate::TaskKind::Diagnostic { test, params });
    }
    let signer = signer.ok_or("no url given and the file server is not configured")?;
    let default = if test == DiagTest::Download {
        DIAG_DOWNLOAD_BYTES
    } else {
        DIAG_UPLOAD_BYTES
    };
    let size = match params.get("size") {
        Some(v) => v
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("size {v:?} is not a number of bytes"))?,
        None => default,
    };
    if size == 0 || size > DIAG_MAX_BYTES {
        return Err(format!("size must be 1-{DIAG_MAX_BYTES} bytes"));
    }
    let url = if test == DiagTest::Download {
        signer.diag_download_url(device, size)
    } else {
        params.insert("size".into(), size.to_string());
        signer.diag_upload_url(device)
    };
    params.insert("url".into(), url);
    Ok(crate::TaskKind::Diagnostic { test, params })
}

/// Error text: device-uploaded file -> no download source for another device.
pub fn not_for_other_devices(file_id: Uuid) -> String {
    format!(
        "file {file_id} was uploaded by a device and can only be sent back to that device, not to another"
    )
}

/// `file_id` download -> fill in signed URL for the device + file metadata.
/// Other tasks pass through. Device-uploaded file -> refused for any other device.
pub async fn resolve_download(
    store: &Store,
    signer: Option<&FileSigner>,
    tenant_id: Uuid,
    device: Uuid,
    kind: crate::TaskKind,
) -> Result<crate::TaskKind, String> {
    let crate::TaskKind::Download {
        file_id: Some(file_id),
        file_type,
        username,
        password,
        target_file_name,
        delay_seconds,
        ..
    } = kind
    else {
        return Ok(kind);
    };
    let signer = signer.ok_or("the file server is not configured")?;
    let file = store
        .get_file(file_id)
        .await
        .map_err(|e| e.to_string())?
        .filter(|f| f.tenant_id == tenant_id)
        .ok_or_else(|| format!("file {file_id} not found"))?;
    // Device uploads (config backups, logs) may hold its secrets
    // -> back to that device only, never to another (audit M-2).
    if file.device_id.is_some_and(|owner| owner != device) {
        return Err(not_for_other_devices(file_id));
    }
    Ok(crate::TaskKind::Download {
        file_id: Some(file_id),
        file_type: if file_type.is_empty() {
            file.file_type
        } else {
            file_type
        },
        url: signer.url(file_id, &file.name, device),
        username,
        password,
        file_size: u32::try_from(file.size_bytes).unwrap_or(0),
        sha256: file.sha256.iter().map(|b| format!("{b:02x}")).collect(),
        target_file_name: if target_file_name.is_empty() {
            file.name
        } else {
            target_file_name
        },
        delay_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(url: &str) -> (u64, String) {
        let q = url.split_once('?').map(|(_, q)| q).unwrap_or_default();
        let get = |k: &str| {
            q.split('&')
                .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
                .unwrap_or_default()
                .to_owned()
        };
        (get("e").parse().unwrap_or_default(), get("s"))
    }

    #[test]
    fn diagnostic_links_are_signed_and_filled_in() {
        use crate::diagnostics::DiagTest;
        let signer = FileSigner::new(b"k".to_vec(), "http://acs:7548", Duration::from_secs(60));
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let down = signer.diag_download_url(a, 1000);
        assert!(down.starts_with(&format!("http://acs:7548/diag/{a}/1000?")));
        let (e, s) = parts(&down);
        assert!(signer.verify_diag_download(a, 1000, e, &s));
        assert!(
            !signer.verify_diag_download(a, 2000, e, &s),
            "the size is signed"
        );
        assert!(!signer.verify_diag_download(b, 1000, e, &s));
        let up = signer.diag_upload_url(a);
        let (e, s) = parts(&up);
        assert!(signer.verify_diag_upload(a, e, &s));
        assert!(!signer.verify_diag_upload(b, e, &s));

        let diag = |test, params: &[(&str, &str)]| crate::TaskKind::Diagnostic {
            test,
            params: params
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        };
        let params = |k: crate::TaskKind| match k {
            crate::TaskKind::Diagnostic { params, .. } => params,
            _ => unreachable!(),
        };
        // No url -> file server link, sized by `size` or the default.
        let Ok(k) = resolve_diagnostic(Some(&signer), a, diag(DiagTest::Download, &[])) else {
            panic!()
        };
        assert!(params(k)["url"].contains(&format!("/diag/{a}/{DIAG_DOWNLOAD_BYTES}?")));
        let Ok(k) = resolve_diagnostic(Some(&signer), a, diag(DiagTest::Upload, &[("size", "7")]))
        else {
            panic!()
        };
        let p = params(k);
        assert!(p["url"].contains(&format!("/diag/{a}?")));
        assert_eq!(p["size"], "7");
        let Ok(k) = resolve_diagnostic(Some(&signer), a, diag(DiagTest::Upload, &[])) else {
            panic!()
        };
        assert_eq!(params(k)["size"], DIAG_UPLOAD_BYTES.to_string());
        // Given url kept; other tests pass through.
        let Ok(k) = resolve_diagnostic(
            Some(&signer),
            a,
            diag(DiagTest::Download, &[("url", "http://x/f")]),
        ) else {
            panic!()
        };
        assert_eq!(params(k)["url"], "http://x/f");
        assert!(resolve_diagnostic(None, a, diag(DiagTest::IpPing, &[("host", "h")])).is_ok());
        // Errors: no file server, size out of range.
        assert!(resolve_diagnostic(None, a, diag(DiagTest::Download, &[])).is_err());
        assert!(
            resolve_diagnostic(Some(&signer), a, diag(DiagTest::Download, &[("size", "0")]))
                .is_err()
        );
        assert!(
            resolve_diagnostic(
                Some(&signer),
                a,
                diag(DiagTest::Download, &[("size", "2000000000")])
            )
            .is_err()
        );
    }

    #[test]
    fn diagnostic_links_live_shorter_than_file_links() {
        let day = Duration::from_secs(24 * 3600);
        let a = Uuid::from_u128(1);
        let signer = FileSigner::new(b"k".to_vec(), "http://acs:7548", day);
        let left = |url: &str| parts(url).0 - now();
        assert!(left(&signer.diag_download_url(a, 10)) <= DIAG_LINK_TTL.as_secs());
        assert!(left(&signer.diag_upload_url(a)) <= DIAG_LINK_TTL.as_secs());
        assert!(left(&signer.url(a, "f", a)) > DIAG_LINK_TTL.as_secs());
        // Shorter link lifetime kept; diagnostic lifetime settable.
        let short = FileSigner::new(b"k".to_vec(), "http://acs:7548", Duration::from_secs(60));
        assert!(left(&short.diag_upload_url(a)) <= 60);
        let custom = short.with_diag_ttl(Duration::from_secs(600));
        assert!((500..=600).contains(&left(&custom.diag_upload_url(a))));
    }

    #[test]
    fn the_link_lifetime_changes_for_every_clone() {
        let a = Uuid::from_u128(1);
        let signer = FileSigner::new(b"k".to_vec(), "http://acs:7548", Duration::from_secs(7200));
        let clone = signer.clone();
        let left = |url: &str| parts(url).0 - now();
        assert!(left(&clone.url(a, "f", a)) > 3600);
        assert!(left(&clone.diag_upload_url(a)) > 3000, "capped at an hour");
        signer.set_ttl(Duration::from_secs(120));
        assert_eq!(clone.ttl(), Duration::from_secs(120));
        assert!(left(&clone.url(a, "f", a)) <= 120);
        assert!(
            left(&clone.diag_upload_url(a)) <= 120,
            "the diagnostic cap follows"
        );
    }

    #[test]
    fn bulkdata_urls_are_bound_to_the_device() {
        let signer = FileSigner::new(b"k".to_vec(), "http://acs:7548/", Duration::from_secs(60));
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let url = signer.bulkdata_url(a);
        let sig = url.rsplit('/').next().unwrap_or_default();
        assert!(url.starts_with("http://acs:7548/bulkdata/"));
        assert!(signer.verify_bulkdata(a, sig));
        assert!(!signer.verify_bulkdata(b, sig));
        assert!(!signer.verify_bulkdata(a, "00"));
    }

    #[test]
    fn sign_and_verify() {
        let s = FileSigner::new(
            b"secret".to_vec(),
            "http://files:7548/",
            Duration::from_secs(3600),
        );
        let (file, dev) = (Uuid::now_v7(), Uuid::now_v7());
        let url = s.url(file, "fw v1.bin", dev);
        assert!(url.starts_with(&format!(
            "http://files:7548/files/{file}/fw%20v1.bin?d={dev}&e="
        )));
        let (e, sig) = parts(&url);
        assert!(s.verify(file, dev, e, &sig));
        assert!(
            !s.verify(file, Uuid::now_v7(), e, &sig),
            "bound to the device"
        );
        assert!(!s.verify(Uuid::now_v7(), dev, e, &sig), "bound to the file");
        assert!(!s.verify(file, dev, e + 1, &sig), "expiry is signed");
        let other = FileSigner::new(
            b"other".to_vec(),
            "http://files:7548",
            Duration::from_secs(3600),
        );
        assert!(!other.verify(file, dev, e, &sig));
        let expired = FileSigner::new(b"secret".to_vec(), "http://x", Duration::ZERO);
        let (e, sig) = parts(&expired.url(file, "a", dev));
        assert!(!expired.verify(file, dev, e.saturating_sub(10), &sig));
    }
}
