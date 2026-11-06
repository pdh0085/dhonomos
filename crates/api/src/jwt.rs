//! OpenID Connect ID token check (JWS compact form) against a JWKS.
//! RS256 + ES256 only, via `ring`. `none`, HMAC + other algorithms refused.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::Value;

/// One key of a JWKS.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Jwk {
    #[serde(default)]
    kid: Option<String>,
    kty: String,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct Jwks {
    pub(crate) keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

fn b64(part: &str) -> Result<Vec<u8>, String> {
    B64URL
        .decode(part.trim_end_matches('='))
        .map_err(|_| "malformed token".to_owned())
}

/// Check signature -> claims. `Err` = reason (no key, bad signature, ...).
pub(crate) fn verify(token: &str, jwks: &Jwks) -> Result<Value, String> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("malformed token".into());
    };
    let header: Header =
        serde_json::from_slice(&b64(h)?).map_err(|_| "malformed token header".to_owned())?;
    let signed = format!("{h}.{p}");
    let sig = b64(s)?;
    let kty = match header.alg.as_str() {
        "RS256" => "RSA",
        "ES256" => "EC",
        other => return Err(format!("token algorithm {other:?} is not accepted")),
    };
    let candidates = jwks.keys.iter().filter(|k| {
        k.kty == kty
            && match (&header.kid, &k.kid) {
                (Some(want), Some(have)) => want == have,
                _ => true,
            }
    });
    let mut tried = false;
    for key in candidates {
        tried = true;
        let ok = match kty {
            "RSA" => {
                let (Some(n), Some(e)) = (&key.n, &key.e) else {
                    continue;
                };
                RsaPublicKeyComponents {
                    n: b64(n)?,
                    e: b64(e)?,
                }
                .verify(
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    signed.as_bytes(),
                    &sig,
                )
                .is_ok()
            }
            _ => {
                let (Some("P-256"), Some(x), Some(y)) = (key.crv.as_deref(), &key.x, &key.y) else {
                    continue;
                };
                let mut point = vec![0x04];
                point.extend(b64(x)?);
                point.extend(b64(y)?);
                UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                    .verify(signed.as_bytes(), &sig)
                    .is_ok()
            }
        };
        if ok {
            return serde_json::from_slice(&b64(p)?).map_err(|_| "malformed token claims".into());
        }
    }
    Err(if tried {
        "bad token signature".into()
    } else {
        "no matching signing key".into()
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair as _, RsaKeyPair};
    use serde_json::json;

    /// Sign `claims` with a fresh P-256 key -> (token, JWKS).
    pub(crate) fn es256(claims: &Value, kid: &str) -> (String, Jwks) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .unwrap_or_else(|_| panic!("keygen"));
        let key = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap_or_else(|_| panic!("key"));
        let header = B64URL.encode(json!({ "alg": "ES256", "kid": kid }).to_string());
        let payload = B64URL.encode(claims.to_string());
        let input = format!("{header}.{payload}");
        let sig = key
            .sign(&rng, input.as_bytes())
            .unwrap_or_else(|_| panic!("sign"));
        let point = key.public_key().as_ref();
        let jwks = Jwks {
            keys: vec![Jwk {
                kid: Some(kid.into()),
                kty: "EC".into(),
                n: None,
                e: None,
                crv: Some("P-256".into()),
                x: Some(B64URL.encode(&point[1..33])),
                y: Some(B64URL.encode(&point[33..65])),
            }],
        };
        (format!("{input}.{}", B64URL.encode(sig.as_ref())), jwks)
    }

    #[test]
    fn es256_tokens() {
        let claims = json!({ "sub": "u1", "iss": "https://idp" });
        let (token, jwks) = es256(&claims, "k1");
        assert_eq!(verify(&token, &jwks), Ok(claims.clone()));
        // Other key, tampered payload, kid mismatch.
        let (_, other) = es256(&claims, "k1");
        assert_eq!(verify(&token, &other), Err("bad token signature".into()));
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = B64URL.encode(json!({ "sub": "admin" }).to_string());
        parts[1] = &forged;
        assert!(verify(&parts.join("."), &jwks).is_err());
        let (t2, _) = es256(&claims, "k2");
        assert_eq!(verify(&t2, &jwks), Err("no matching signing key".into()));
    }

    #[test]
    fn rs256_tokens() {
        let der = include_bytes!("../tests/fixtures/oidc-test-rsa.pk8.der");
        let key = RsaKeyPair::from_pkcs8(der).unwrap_or_else(|e| panic!("{e}"));
        let header = B64URL.encode(json!({ "alg": "RS256" }).to_string());
        let payload = B64URL.encode(json!({ "sub": "u2" }).to_string());
        let input = format!("{header}.{payload}");
        let mut sig = vec![0; key.public().modulus_len()];
        key.sign(
            &signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            input.as_bytes(),
            &mut sig,
        )
        .unwrap_or_else(|_| panic!("sign"));
        let public: RsaPublicKeyComponents<Vec<u8>> = key.public().into();
        let jwks = Jwks {
            keys: vec![Jwk {
                kid: None,
                kty: "RSA".into(),
                n: Some(B64URL.encode(&public.n)),
                e: Some(B64URL.encode(&public.e)),
                crv: None,
                x: None,
                y: None,
            }],
        };
        let token = format!("{input}.{}", B64URL.encode(&sig));
        assert_eq!(verify(&token, &jwks), Ok(json!({ "sub": "u2" })));
    }

    #[test]
    fn unsafe_algorithms_are_refused() {
        let none = format!(
            "{}.{}.",
            B64URL.encode(r#"{"alg":"none"}"#),
            B64URL.encode(r#"{"sub":"admin"}"#)
        );
        assert!(verify(&none, &Jwks::default()).is_err_and(|e| e.contains("not accepted")));
        let hs = format!("{}.e30.c2ln", B64URL.encode(r#"{"alg":"HS256"}"#));
        assert!(verify(&hs, &Jwks::default()).is_err_and(|e| e.contains("not accepted")));
        assert!(verify("a.b", &Jwks::default()).is_err());
    }
}
