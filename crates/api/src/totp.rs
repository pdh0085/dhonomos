//! TOTP for operator accounts (ADR-100): RFC 6238, HMAC-SHA-1, 6 digits, 30 s steps
//! (= what authenticator apps implement). Also: single-use recovery codes, enrollment URI, QR code.
//! Pure functions. Storage + HTTP side -> `auth::two_factor`.

use data_encoding::BASE32_NOPAD;
use ring::hmac;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

pub(crate) const STEP_SECS: u64 = 30;
/// 160 bits, as RFC 4226 recommends (= HMAC-SHA-1 output size).
pub(crate) const SECRET_BYTES: usize = 20;
/// Steps accepted before + after the current one (clock drift phone vs server).
const WINDOW: u64 = 1;
/// Recovery codes per batch.
pub(crate) const RECOVERY_CODES: usize = 10;
/// Chars of a recovery code = 80 bits -> stored SHA-256 hashes not guessable offline
/// after a DB leak.
const RECOVERY_CHARS: usize = 16;
/// Issuer in authenticator apps when `--totp-issuer` not set.
pub(crate) const DEFAULT_ISSUER: &str = "Dhonomos";

/// Two-factor auth settings.
#[derive(Debug, Clone, Default)]
pub struct TotpConfig {
    /// Roles (`admin`, `operator`, `viewer`) that must use 2FA.
    /// Such account, password login, no 2FA set up -> can only set it up.
    /// Other roles: 2FA optional. Needs the secrets key.
    pub require_roles: Vec<String>,
    /// Name of this installation in authenticator apps (empty -> `Dhonomos`).
    pub issuer: String,
}

impl TotpConfig {
    /// Roles from `--require-totp-roles` (`admin,operator`; `none` or empty -> no role).
    /// No duplicates. Error names the word that is no role.
    pub fn parse_roles(list: &[String]) -> Result<Vec<String>, String> {
        let mut roles: Vec<String> = Vec::new();
        for word in list.iter().flat_map(|l| l.split(',')) {
            let word = word.trim().to_ascii_lowercase();
            match word.as_str() {
                "" | "none" => {}
                "admin" | "operator" | "viewer" => {
                    if !roles.contains(&word) {
                        roles.push(word);
                    }
                }
                _ => {
                    return Err(format!(
                        "--require-totp-roles: {word:?} is not a role (admin, operator, viewer, or none)"
                    ));
                }
            }
        }
        Ok(roles)
    }

    /// `true` -> accounts of `role` must use 2FA.
    pub fn requires(&self, role: &str) -> bool {
        self.require_roles.iter().any(|r| r == role)
    }

    /// Settings vs server: 2FA secrets stored encrypted -> required role needs the secrets key.
    /// Called at startup.
    pub fn check(&self, secrets_configured: bool) -> Result<(), String> {
        if !self.require_roles.is_empty() && !secrets_configured {
            return Err(format!(
                "two-factor authentication is required for {} (--require-totp-roles, default admin) \
                 but there is no --secrets-key to encrypt the two-factor secrets with: set \
                 DHONOMOS_SECRETS_KEY (`openssl rand -base64 32`), or turn the requirement off \
                 with --require-totp-roles none and --require-admin-totp false",
                self.require_roles.join(", ")
            ));
        }
        Ok(())
    }

    pub(crate) fn issuer(&self) -> &str {
        let issuer = self.issuer.trim();
        if issuer.is_empty() {
            DEFAULT_ISSUER
        } else {
            issuer
        }
    }
}

pub(crate) fn new_secret() -> Result<[u8; SECRET_BYTES], getrandom::Error> {
    let mut secret = [0u8; SECRET_BYTES];
    getrandom::fill(&mut secret)?;
    Ok(secret)
}

/// Secret as authenticator apps take it: base32, no padding.
pub(crate) fn secret_base32(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
}

/// Time step (counter) at `unix_secs`.
pub(crate) fn step_at(unix_secs: u64) -> u64 {
    unix_secs / STEP_SECS
}

/// 6-digit code for `step` (RFC 4226 dynamic truncation of HMAC-SHA-1).
pub(crate) fn code_at(secret: &[u8], step: u64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let mac = hmac::sign(&key, &step.to_be_bytes());
    let mac = mac.as_ref();
    let offset = usize::from(mac[mac.len() - 1] & 0x0f);
    let word = u32::from_be_bytes([
        mac[offset] & 0x7f,
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]);
    word % 1_000_000
}

/// Typed code -> 6 digits, spaces allowed (apps show `123 456`).
/// Else (recovery code, junk) -> `None`.
pub(crate) fn parse_code(input: &str) -> Option<String> {
    let digits: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    (digits.len() == 6 && digits.bytes().all(|b| b.is_ascii_digit())).then_some(digits)
}

/// Step that `input` is the code of, if the secret allows it now:
/// within 1 step of `now_unix` + newer than `last_step` (newest accepted step -> code good once).
/// All window steps compared, constant time, no stop on a match.
pub(crate) fn matching_step(
    secret: &[u8],
    input: &str,
    now_unix: u64,
    last_step: Option<i64>,
) -> Option<u64> {
    let given = parse_code(input)?;
    let now = step_at(now_unix);
    let mut found = None;
    for step in now.saturating_sub(WINDOW)..=now + WINDOW {
        if crate::auth::constant_eq(&format!("{:06}", code_at(secret, step)), &given) {
            found = Some(step);
        }
    }
    found.filter(|step| i64::try_from(*step).is_ok_and(|s| s > last_step.unwrap_or(-1)))
}

/// Percent-encode all but the RFC 3986 unreserved chars.
fn percent_encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// `otpauth://` URI that authenticator apps read from the QR code.
/// Label = `<issuer>:<account>`.
pub(crate) fn otpauth_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    let issuer = percent_encode(issuer);
    format!(
        "otpauth://totp/{issuer}:{}?secret={secret_b32}&issuer={issuer}&algorithm=SHA1&digits=6&period={STEP_SECS}",
        percent_encode(account)
    )
}

/// `text` -> QR code in SVG: black modules on white + quiet zone the scanners need.
/// Output: plain ASCII, no script, no external ref -> safe to show as an image.
pub(crate) fn qr_svg(text: &str) -> Result<String, qrcodegen::DataTooLong> {
    use std::fmt::Write as _;
    const BORDER: i32 = 4;
    const SCALE: i32 = 6;
    let qr = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Medium)?;
    let size = qr.size();
    let total = size + 2 * BORDER;
    // One rect per horizontal run of dark modules.
    let mut path = String::new();
    for y in 0..size {
        let mut x = 0;
        while x < size {
            if !qr.get_module(x, y) {
                x += 1;
                continue;
            }
            let start = x;
            while x < size && qr.get_module(x, y) {
                x += 1;
            }
            let _ = write!(
                path,
                "M{},{}h{}v1h-{}z",
                start + BORDER,
                y + BORDER,
                x - start,
                x - start
            );
        }
    }
    Ok(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {total} {total}\" \
         width=\"{px}\" height=\"{px}\" shape-rendering=\"crispEdges\" role=\"img\" \
         aria-label=\"QR code for the authenticator app\">\
         <rect width=\"{total}\" height=\"{total}\" fill=\"#fff\"/>\
         <path d=\"{path}\" fill=\"#000\"/></svg>",
        px = total * SCALE
    ))
}

/// New recovery codes, each `XXXX-XXXX-XXXX-XXXX` (base32, 80 random bits).
pub(crate) fn new_recovery_codes() -> Result<Vec<String>, getrandom::Error> {
    (0..RECOVERY_CODES)
        .map(|_| {
            let mut raw = [0u8; RECOVERY_CHARS * 5 / 8];
            getrandom::fill(&mut raw)?;
            let chars = BASE32_NOPAD.encode(&raw);
            Ok(chars
                .as_bytes()
                .chunks(4)
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect::<Vec<_>>()
                .join("-"))
        })
        .collect()
}

/// Typed recovery code -> form to hash: upper case, no dashes or spaces people add.
/// `None` -> cannot be a recovery code.
pub(crate) fn normalize_recovery(input: &str) -> Option<String> {
    let code: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (code.len() == RECOVERY_CHARS
        && code
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)))
    .then_some(code)
}

/// Stored form of a (normalized) recovery code: SHA-256 over account + code.
/// 80-bit codes -> plain hash not guessable offline.
pub(crate) fn recovery_hash(user: Uuid, normalized: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"dhonomos-recovery-code:");
    h.update(user.as_bytes());
    h.update(b":");
    h.update(normalized.as_bytes());
    h.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// RFC 6238 appendix B: SHA-1 secret = ASCII digits `1234567890` repeated to 20 bytes.
    /// RFC lists 8-digit codes; 6-digit code = their last 6 digits.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc_6238_test_vectors() {
        for (time, eight) in [
            (59u64, 94_287_082u32),
            (1_111_111_109, 7_081_804),
            (1_111_111_111, 14_050_471),
            (1_234_567_890, 89_005_924),
            (2_000_000_000, 69_279_037),
            (20_000_000_000, 65_353_130),
        ] {
            let step = step_at(time);
            assert_eq!(code_at(RFC_SECRET, step), eight % 1_000_000, "T={time}");
        }
        // RFC 4226 appendix D (HOTP), counter 0..=2, same secret.
        assert_eq!(
            [0, 1, 2].map(|c| code_at(RFC_SECRET, c)),
            [755_224, 287_082, 359_152]
        );
    }

    #[test]
    fn codes_are_accepted_within_one_step_only() {
        let now = 1_700_000_000u64;
        let step = step_at(now);
        let code = |s: u64| format!("{:06}", code_at(RFC_SECRET, s));
        assert_eq!(
            matching_step(RFC_SECRET, &code(step), now, None),
            Some(step)
        );
        assert_eq!(
            matching_step(RFC_SECRET, &code(step - 1), now, None),
            Some(step - 1)
        );
        assert_eq!(
            matching_step(RFC_SECRET, &code(step + 1), now, None),
            Some(step + 1)
        );
        assert_eq!(matching_step(RFC_SECRET, &code(step - 2), now, None), None);
        assert_eq!(matching_step(RFC_SECRET, &code(step + 2), now, None), None);
        // Spaces as in apps; leading zeros matter.
        let spaced = format!("{} {}", &code(step)[..3], &code(step)[3..]);
        assert_eq!(matching_step(RFC_SECRET, &spaced, now, None), Some(step));
        // Not a code.
        for junk in ["", "12345", "1234567", "12345a", "ABCD-EFGH-JKLM-NPQR"] {
            assert_eq!(matching_step(RFC_SECRET, junk, now, None), None, "{junk}");
        }
        // Code of another secret.
        assert_eq!(
            matching_step(b"another-secret-0000", &code(step), now, None),
            None
        );
    }

    #[test]
    fn a_code_is_good_once() {
        let now = 1_700_000_000u64;
        let step = step_at(now);
        let code = format!("{:06}", code_at(RFC_SECRET, step));
        let first = matching_step(RFC_SECRET, &code, now, None);
        assert_eq!(first, Some(step));
        // Step recorded -> same code + older code refused ...
        let last = i64::try_from(step).ok();
        assert_eq!(matching_step(RFC_SECRET, &code, now, last), None);
        let older = format!("{:06}", code_at(RFC_SECRET, step - 1));
        assert_eq!(matching_step(RFC_SECRET, &older, now, last), None);
        // ... next step's code accepted.
        let newer = format!("{:06}", code_at(RFC_SECRET, step + 1));
        assert_eq!(matching_step(RFC_SECRET, &newer, now, last), Some(step + 1));
    }

    #[test]
    fn secrets_are_random_base32() {
        let a = new_secret().unwrap_or_default();
        let b = new_secret().unwrap_or_default();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; SECRET_BYTES]);
        // RFC secret as given to an authenticator app.
        assert_eq!(
            secret_base32(RFC_SECRET),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
        assert_eq!(secret_base32(&a).len(), 32);
        assert_eq!(
            BASE32_NOPAD.decode(secret_base32(&a).as_bytes()).ok(),
            Some(a.to_vec())
        );
    }

    #[test]
    fn otpauth_uri_follows_the_key_uri_format() {
        assert_eq!(
            otpauth_uri("Dhonomos", "kim", "GEZDGNBV"),
            "otpauth://totp/Dhonomos:kim?secret=GEZDGNBV&issuer=Dhonomos&algorithm=SHA1&digits=6&period=30"
        );
        // Spaces, colons, non-ASCII escaped -> label stays `<issuer>:<account>`.
        assert_eq!(
            otpauth_uri("ISP: Seoul NOC", "kim@example.org", "AAAA"),
            "otpauth://totp/ISP%3A%20Seoul%20NOC:kim%40example.org?secret=AAAA&issuer=ISP%3A%20Seoul%20NOC&algorithm=SHA1&digits=6&period=30"
        );
        assert!(otpauth_uri("Dhonomos", "한글", "A").contains("%ED%95%9C%EA%B8%80"));
    }

    #[test]
    fn qr_code_is_an_svg_image() {
        let uri = otpauth_uri("Dhonomos", "kim", &secret_base32(RFC_SECRET));
        let svg = qr_svg(&uri).unwrap_or_default();
        assert!(svg.starts_with("<svg "), "{svg}");
        assert!(svg.ends_with("</svg>"));
        assert!(svg.contains("<path d=\"M"), "dark modules are drawn");
        assert!(svg.is_ascii());
        for forbidden in ["<script", "href", "onload", "<image"] {
            assert!(!svg.contains(forbidden), "{forbidden}");
        }
        // Other text -> other picture.
        assert_ne!(svg, qr_svg("otpauth://totp/x").unwrap_or_default());
        // Too much data -> error, not a broken picture.
        assert!(qr_svg(&"x".repeat(5000)).is_err());
    }

    #[test]
    fn recovery_codes_are_grouped_distinct_and_hashed_per_account() {
        let codes = new_recovery_codes().unwrap_or_default();
        assert_eq!(codes.len(), RECOVERY_CODES);
        let mut distinct = codes.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), RECOVERY_CODES);
        for c in &codes {
            assert_eq!(c.len(), 19, "{c}");
            assert_eq!(c.matches('-').count(), 3);
            assert!(normalize_recovery(c).is_some(), "{c}");
        }
        let code = &codes[0];
        let norm = normalize_recovery(code);
        assert_eq!(norm.as_deref().map(str::len), Some(16));
        // Typed in lower case, with spaces, or without dashes.
        let lower = code.to_lowercase().replace('-', " ");
        assert_eq!(normalize_recovery(&lower), norm);
        assert_eq!(normalize_recovery(&code.replace('-', "")), norm);
        // TOTP code or junk -> not a recovery code.
        for junk in [
            "123456",
            "",
            "ABCD-EFGH",
            "0000-1111-8888-9999",
            "ABCD-EFGH-JKLM-NPQ!",
        ] {
            assert_eq!(normalize_recovery(junk), None, "{junk}");
        }
        // Hash: stable, tied to the account, != code.
        let (u1, u2) = (Uuid::now_v7(), Uuid::now_v7());
        let norm = norm.unwrap_or_default();
        assert_eq!(recovery_hash(u1, &norm), recovery_hash(u1, &norm));
        assert_ne!(recovery_hash(u1, &norm), recovery_hash(u2, &norm));
        assert_ne!(
            recovery_hash(u1, &norm),
            recovery_hash(u1, "AAAAAAAAAAAAAAAA")
        );
        assert_eq!(recovery_hash(u1, &norm).len(), 32);
    }

    #[test]
    fn the_requirement_needs_the_secrets_key() {
        let on = TotpConfig {
            require_roles: vec!["admin".into(), "operator".into()],
            ..TotpConfig::default()
        };
        let err = on.check(false).unwrap_err();
        assert!(err.contains("--require-admin-totp false"), "{err}");
        assert!(err.contains("admin, operator"), "{err}");
        assert!(err.contains("--secrets-key"), "{err}");
        assert_eq!(on.check(true), Ok(()));
        // Off -> key optional (and nobody can enroll without it).
        assert_eq!(TotpConfig::default().check(false), Ok(()));
        assert_eq!(on.issuer(), "Dhonomos");
        let named = TotpConfig {
            issuer: "  ISP NOC ".into(),
            ..TotpConfig::default()
        };
        assert_eq!(named.issuer(), "ISP NOC");
    }

    #[test]
    fn roles_that_must_use_it() {
        let roles = |l: &[&str]| {
            TotpConfig::parse_roles(&l.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
        };
        assert_eq!(roles(&["admin"]), Ok(vec!["admin".into()]));
        assert_eq!(
            roles(&["Admin, operator", "operator"]),
            Ok(vec!["admin".into(), "operator".into()])
        );
        assert_eq!(roles(&["none"]), Ok(Vec::new()));
        assert_eq!(roles(&[""]), Ok(Vec::new()));
        assert_eq!(roles(&[]), Ok(Vec::new()));
        assert!(roles(&["admin", "root"]).unwrap_err().contains("root"));
        let cfg = TotpConfig {
            require_roles: vec!["admin".into(), "operator".into()],
            ..TotpConfig::default()
        };
        assert!(cfg.requires("admin") && cfg.requires("operator"));
        assert!(!cfg.requires("viewer"));
        assert!(!TotpConfig::default().requires("admin"));
    }
}
