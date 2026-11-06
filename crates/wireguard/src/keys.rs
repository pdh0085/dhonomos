//! Curve25519 key pairs, WireGuard text form: 32 bytes standard base64 = 44 chars with
//! padding (same as `wg genkey`, `wg pubkey`).
//!
//! Private keys only pass through. Never stored (ADR-110 Q7):
//! client member -> key pair made at member create, private half returned once.
//! Device member -> key made on the device, or sent to it + forgotten.
//!
//! Pre-shared key = 32 random bytes, same text form. Stored, unlike private keys
//! (sealed with server secrets key) -> hub + reset device need it again.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize as _, Zeroizing};

/// Key length, bytes.
pub const KEY_LEN: usize = 32;
/// Key length as base64 text.
pub const KEY_B64_LEN: usize = 44;

/// Why a key was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// Not 32 bytes of padded standard base64.
    #[error("a WireGuard key is 32 bytes as 44 base64 characters")]
    Format,
    /// 32 zero bytes -> never a real key.
    #[error("a WireGuard key cannot be all zeros")]
    Zero,
    /// OS random number generator failed.
    #[error("the system random number generator failed")]
    Random,
}

/// Private key + its public key.
pub struct KeyPair {
    /// Zeroed on drop; never logged or stored.
    pub private: Zeroizing<String>,
    pub public: String,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("private", &"<redacted>")
            .field("public", &self.public)
            .finish()
    }
}

/// Key text -> 32 bytes. All zeros refused.
fn decode(key: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, KeyError> {
    if key.len() != KEY_B64_LEN {
        return Err(KeyError::Format);
    }
    let mut raw = STANDARD.decode(key).map_err(|_| KeyError::Format)?;
    let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
    let fits = raw.len() == KEY_LEN;
    if fits {
        bytes.copy_from_slice(&raw);
    }
    raw.zeroize();
    if !fits {
        return Err(KeyError::Format);
    }
    if bytes.iter().all(|b| *b == 0) {
        return Err(KeyError::Zero);
    }
    Ok(bytes)
}

/// Check `key` (public or private) = WireGuard key in text form.
pub fn validate_key(key: &str) -> Result<(), KeyError> {
    decode(key).map(drop)
}

/// New key pair. Private key clamped like `wg genkey`.
pub fn generate_keypair() -> Result<KeyPair, KeyError> {
    let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(&mut bytes[..]).map_err(|_| KeyError::Random)?;
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    let secret = StaticSecret::from(*bytes);
    let public = STANDARD.encode(PublicKey::from(&secret).as_bytes());
    Ok(KeyPair {
        private: Zeroizing::new(STANDARD.encode(*bytes)),
        public,
    })
}

/// New pre-shared key: 32 random bytes (like `wg genpsk`).
pub fn generate_preshared_key() -> Result<Zeroizing<[u8; KEY_LEN]>, KeyError> {
    let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(&mut bytes[..]).map_err(|_| KeyError::Random)?;
    // 32 zero bytes = "no pre-shared key" for WireGuard (chance 1 in 2^256).
    if bytes.iter().all(|b| *b == 0) {
        return Err(KeyError::Random);
    }
    Ok(bytes)
}

/// Pre-shared key (or any key) -> text, 44 base64 chars.
pub fn key_text(bytes: &[u8; KEY_LEN]) -> Zeroizing<String> {
    Zeroizing::new(STANDARD.encode(bytes))
}

/// Pre-shared key (or any key) text -> 32 bytes. All zeros refused.
pub fn key_from_text(key: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, KeyError> {
    decode(key)
}

/// Private key -> public key (like `wg pubkey`).
pub fn public_from_private(private: &str) -> Result<String, KeyError> {
    let bytes = decode(private)?;
    let secret = StaticSecret::from(*bytes);
    Ok(STANDARD.encode(PublicKey::from(&secret).as_bytes()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn b64_of_hex(hex: &str) -> String {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        STANDARD.encode(bytes)
    }

    #[test]
    fn public_keys_follow_rfc_7748() {
        // 2 key pairs of RFC 7748 sec. 6.1.
        for (private, public) in [
            (
                "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
                "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            ),
            (
                "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
                "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
            ),
        ] {
            assert_eq!(
                public_from_private(&b64_of_hex(private)).unwrap(),
                b64_of_hex(public)
            );
        }
    }

    #[test]
    fn generated_pairs_are_valid_clamped_and_distinct() {
        let a = generate_keypair().unwrap();
        let b = generate_keypair().unwrap();
        assert_eq!(a.private.len(), KEY_B64_LEN);
        assert_eq!(a.public.len(), KEY_B64_LEN);
        assert_ne!(*a.private, *b.private);
        assert_ne!(a.public, b.public);
        validate_key(&a.private).unwrap();
        validate_key(&a.public).unwrap();
        assert_eq!(public_from_private(&a.private).unwrap(), a.public);
        let raw = STANDARD.decode(a.private.as_str()).unwrap();
        assert_eq!(raw[0] & 7, 0);
        assert_eq!(raw[31] & 0x80, 0);
        assert_eq!(raw[31] & 0x40, 0x40);
        // Private half not in Debug -> not in logs.
        let shown = format!("{a:?}");
        assert!(!shown.contains(a.private.as_str()), "{shown}");
        assert!(shown.contains(&a.public));
    }

    #[test]
    fn preshared_keys_are_random_and_round_trip_as_text() {
        let a = generate_preshared_key().unwrap();
        let b = generate_preshared_key().unwrap();
        assert_ne!(*a, *b);
        let text = key_text(&a);
        assert_eq!(text.len(), KEY_B64_LEN);
        validate_key(&text).unwrap();
        assert_eq!(*key_from_text(&text).unwrap(), *a);
        assert_eq!(
            key_from_text(&STANDARD.encode([0u8; 32])).map(|_| ()),
            Err(KeyError::Zero)
        );
    }

    #[test]
    fn keys_are_checked_strictly() {
        let good = generate_keypair().unwrap().public;
        assert_eq!(validate_key(&good), Ok(()));
        for bad in [
            "",
            "short",
            // 44 chars, not base64.
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!=",
            // No padding -> 43 chars.
            good.trim_end_matches('='),
            // Other alphabet (URL-safe), if text has + or /.
            &good.replace('+', "-").replace('/', "_"),
        ] {
            if bad == good {
                continue; // Key without + and / -> URL-safe form = same text.
            }
            assert_eq!(validate_key(bad), Err(KeyError::Format), "{bad:?}");
        }
        // 33 bytes -> also 44 base64 chars, other padding.
        assert_eq!(
            validate_key(&STANDARD.encode([1u8; 33])),
            Err(KeyError::Format)
        );
        // 31 bytes.
        assert_eq!(
            validate_key(&STANDARD.encode([1u8; 31])),
            Err(KeyError::Format)
        );
        assert_eq!(
            validate_key(&STANDARD.encode([0u8; 32])),
            Err(KeyError::Zero)
        );
        assert_eq!(
            validate_key(&format!("{good} ")),
            Err(KeyError::Format),
            "no stray whitespace"
        );
        assert_eq!(public_from_private("nope"), Err(KeyError::Format));
        // Last char of 32 bytes has 2 spare bits, must be 0 ('B' = index 1)
        // -> same key in another spelling refused.
        let mut tampered = good.clone();
        tampered.replace_range(42..43, "B");
        assert_eq!(validate_key(&tampered), Err(KeyError::Format));
    }
}
