//! Dhonomos CA for USP Controller Trust (US-08).
//!
//! USP endpoint in a cert = subjectAltName URI `urn:bbf:usp:id:<EndpointID>`.
//! CA issues: Agent client certs (from CSR or with generated key) + own Controller
//! server/client cert.
//! [`tls`] -> listener server cert follows its PEM files, or own cert re-issued before expiry.

pub mod tls;

use std::net::IpAddr;
use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
    string::Ia5String,
};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom as _, SystemRandom};
use time::{Duration, OffsetDateTime};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer as _, X509Certificate};

/// USP EndpointID URI prefix in subjectAltName.
pub const USP_ID_PREFIX: &str = "urn:bbf:usp:id:";

/// Error of a certificate operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PkiError {
    /// Generate, parse or sign failed.
    #[error("certificate: {0}")]
    Cert(#[from] rcgen::Error),
    /// Read or write of CA files failed.
    #[error("{path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    /// Value not allowed in a cert (e.g. non-ASCII EndpointID).
    #[error("invalid certificate input: {0}")]
    Invalid(String),
    /// OS RNG failed.
    #[error("random number generator failure")]
    Rng,
}

/// Cert + private key (key only when Dhonomos generated it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    pub cert_pem: String,
    /// `None` -> issued from a CSR.
    pub key_pem: Option<String>,
    /// Hex.
    pub serial: String,
    /// SHA-256 of the DER cert, hex.
    pub sha256: String,
    /// now - 1 h -> slack for slow clocks.
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

/// Content of an end-entity cert.
#[derive(Debug, Clone, Default)]
pub struct Profile {
    /// -> SAN URI `urn:bbf:usp:id:<EndpointID>`.
    pub endpoint_id: String,
    /// For server certs.
    pub dns_names: Vec<String>,
    /// For server certs.
    pub ip_addresses: Vec<IpAddr>,
    /// true -> also ServerAuth EKU (TLS server cert). ClientAuth always.
    pub server: bool,
    /// Validity, days (min 1).
    pub days: u32,
}

/// CA cert + signing key.
pub struct Ca {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ca").finish_non_exhaustive()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn serial() -> Result<SerialNumber, PkiError> {
    let mut raw = [0u8; 16];
    SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| PkiError::Rng)?;
    raw[0] &= 0x7f; // positive INTEGER
    Ok(SerialNumber::from_slice(&raw))
}

fn ia5(s: &str) -> Result<Ia5String, PkiError> {
    Ia5String::try_from(s).map_err(|_| PkiError::Invalid(format!("{s:?} is not ASCII")))
}

/// Max CA name length, chars = X.520 common name limit.
const MAX_CA_NAME: usize = 64;

/// Common name for a new CA: `configured` (`--usp-ca-name`),
/// else `Dhonomos USP CA <8 random hex digits>`.
///
/// Random suffix -> no shared CA name between 2 installations -> certs not mistaken.
/// Empty or blank `configured` = not given.
pub fn ca_common_name(configured: Option<&str>) -> Result<String, PkiError> {
    if let Some(name) = configured.map(str::trim).filter(|n| !n.is_empty()) {
        if name.chars().count() > MAX_CA_NAME || name.chars().any(char::is_control) {
            return Err(PkiError::Invalid(format!(
                "a CA name is at most {MAX_CA_NAME} characters without control characters"
            )));
        }
        return Ok(name.to_owned());
    }
    let mut raw = [0u8; 4];
    SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| PkiError::Rng)?;
    Ok(format!("Dhonomos USP CA {}", hex(&raw)))
}

/// SHA-256 of a DER cert, hex.
pub fn fingerprint(der: &[u8]) -> String {
    hex(digest(&SHA256, der).as_ref())
}

/// EndpointIDs in the SAN URIs of a DER cert. Parse error -> empty.
pub fn endpoint_ids(der: &[u8]) -> Vec<String> {
    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return Vec::new();
    };
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .filter_map(|n| match n {
            GeneralName::URI(u) => u.strip_prefix(USP_ID_PREFIX).map(str::to_owned),
            _ => None,
        })
        .collect()
}

fn write_file(path: &Path, contents: &str, private: bool) -> Result<(), PkiError> {
    let io = |source| PkiError::Io {
        path: path.display().to_string(),
        source,
    };
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(if private { 0o600 } else { 0o644 })
            .open(path)
            .map_err(io)?;
        f.write_all(contents.as_bytes()).map_err(io)
    }
    #[cfg(not(unix))]
    {
        let _ = private;
        std::fs::write(path, contents).map_err(io)
    }
}

impl Ca {
    /// New CA: ECDSA P-256 key, valid 20 years.
    pub fn generate(common_name: &str) -> Result<Self, PkiError> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        dn.push(DnType::OrganizationName, "Dhonomos");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.serial_number = Some(serial()?);
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(20 * 365);
        let cert = params.self_signed(&key)?;
        Ok(Self {
            cert_pem: cert.pem(),
            issuer: Issuer::new(params, key),
        })
    }

    /// CA from PEM text (cert + key).
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, PkiError> {
        let key = KeyPair::from_pem(key_pem)?;
        Ok(Self {
            cert_pem: cert_pem.to_owned(),
            issuer: Issuer::from_ca_cert_pem(cert_pem, key)?,
        })
    }

    /// Load `ca.pem` + `ca.key` from `dir`; both missing -> create them (key mode 0600).
    /// Only one present -> read error. Returns (CA, created).
    pub fn load_or_create(dir: &Path, common_name: &str) -> Result<(Self, bool), PkiError> {
        let (cert_path, key_path) = (dir.join("ca.pem"), dir.join("ca.key"));
        let read = |p: &Path| {
            std::fs::read_to_string(p).map_err(|source| PkiError::Io {
                path: p.display().to_string(),
                source,
            })
        };
        if cert_path.exists() || key_path.exists() {
            return Ok((
                Self::from_pem(&read(&cert_path)?, &read(&key_path)?)?,
                false,
            ));
        }
        std::fs::create_dir_all(dir).map_err(|source| PkiError::Io {
            path: dir.display().to_string(),
            source,
        })?;
        let ca = Self::generate(common_name)?;
        write_file(&key_path, &ca.issuer_key_pem(), true)?;
        write_file(&cert_path, &ca.cert_pem, false)?;
        Ok((ca, true))
    }

    fn issuer_key_pem(&self) -> String {
        self.issuer.key().serialize_pem()
    }

    /// CN of the CA cert.
    pub fn common_name(&self) -> Option<String> {
        let (_, pem) = x509_parser::pem::parse_x509_pem(self.cert_pem.as_bytes()).ok()?;
        let (_, cert) = X509Certificate::from_der(&pem.contents).ok()?;
        cert.subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(str::to_owned)
    }

    /// CA cert (for the Agent trust store).
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    fn params(&self, profile: &Profile) -> Result<CertificateParams, PkiError> {
        if profile.endpoint_id.is_empty() {
            return Err(PkiError::Invalid("an EndpointID is required".into()));
        }
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, profile.endpoint_id.as_str());
        params.distinguished_name = dn;
        let mut san = vec![SanType::URI(ia5(&format!(
            "{USP_ID_PREFIX}{}",
            profile.endpoint_id
        ))?)];
        for d in &profile.dns_names {
            san.push(SanType::DnsName(ia5(d)?));
        }
        san.extend(profile.ip_addresses.iter().copied().map(SanType::IpAddress));
        params.subject_alt_names = san;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        if profile.server {
            params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ServerAuth);
        }
        params.use_authority_key_identifier_extension = true;
        params.serial_number = Some(serial()?);
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(i64::from(profile.days.max(1)));
        Ok(params)
    }

    fn issued(
        cert: &rcgen::Certificate,
        params: &CertificateParams,
        key_pem: Option<String>,
    ) -> Issued {
        Issued {
            cert_pem: cert.pem(),
            key_pem,
            serial: params
                .serial_number
                .as_ref()
                .map(|s| hex(s.as_ref()))
                .unwrap_or_default(),
            sha256: fingerprint(cert.der()),
            not_before: params.not_before,
            not_after: params.not_after,
        }
    }

    /// Issue a cert with a new ECDSA P-256 key.
    pub fn issue(&self, profile: &Profile) -> Result<Issued, PkiError> {
        let key = KeyPair::generate()?;
        let params = self.params(profile)?;
        let cert = params.signed_by(&key, &self.issuer)?;
        Ok(Self::issued(&cert, &params, Some(key.serialize_pem())))
    }

    /// [`Ca::issue`] -> what a TLS server needs: PEM chain (cert, then CA cert) + PEM key.
    pub fn issue_chain(&self, profile: &Profile) -> Result<(String, String), PkiError> {
        let issued = self.issue(profile)?;
        let key = issued
            .key_pem
            .ok_or_else(|| PkiError::Invalid("no private key was generated".into()))?;
        Ok((format!("{}{}", issued.cert_pem, self.cert_pem), key))
    }

    /// Issue a cert for the key of a PEM CSR.
    ///
    /// Only the CSR public key is used: names, usages + validity from `profile`.
    pub fn issue_from_csr(&self, csr_pem: &str, profile: &Profile) -> Result<Issued, PkiError> {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
        let params = self.params(profile)?;
        csr.params = params.clone();
        let cert = csr.signed_by(&self.issuer)?;
        Ok(Self::issued(&cert, &params, None))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn der(pem_str: &str) -> Vec<u8> {
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem_str.as_bytes()).unwrap();
        pem.contents
    }

    #[test]
    fn agent_certificates_carry_the_endpoint_id() {
        let ca = Ca::generate("Test CA").unwrap();
        let issued = ca
            .issue(&Profile {
                endpoint_id: "os::012345-AABBCCDDEEFF".into(),
                days: 30,
                ..Profile::default()
            })
            .unwrap();
        assert!(issued.key_pem.is_some());
        assert_eq!(
            endpoint_ids(&der(&issued.cert_pem)),
            vec!["os::012345-AABBCCDDEEFF"]
        );
        assert_eq!(issued.sha256, fingerprint(&der(&issued.cert_pem)));
        assert_eq!(
            (issued.not_after - issued.not_before).whole_days(),
            30,
            "an hour of slack before, then the days asked for"
        );
        assert!(
            Ca::generate("x")
                .unwrap()
                .issue(&Profile::default())
                .is_err()
        );
        assert!(
            ca.issue(&Profile {
                endpoint_id: "os::ünïcode".into(),
                days: 1,
                ..Profile::default()
            })
            .is_err()
        );
    }

    #[test]
    fn ca_names_are_per_installation_unless_given() {
        let a = ca_common_name(None).unwrap();
        let b = ca_common_name(Some("  ")).unwrap();
        for name in [&a, &b] {
            let suffix = name.strip_prefix("Dhonomos USP CA ").unwrap();
            assert_eq!(suffix.len(), 8, "{name}");
            assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()), "{name}");
        }
        assert_ne!(a, b, "two installations do not share a CA name");
        assert_eq!(
            ca_common_name(Some(" Acme USP CA ")).unwrap(),
            "Acme USP CA"
        );
        assert!(ca_common_name(Some(&"x".repeat(65))).is_err());
        assert!(ca_common_name(Some("bad\nname")).is_err());
        // Name -> CA cert CN. Existing CA keeps its name.
        let dir = tempfile::tempdir().unwrap();
        let (ca, created) = Ca::load_or_create(dir.path(), &a).unwrap();
        assert!(created);
        assert_eq!(ca.common_name().as_deref(), Some(a.as_str()));
        let (again, created) = Ca::load_or_create(dir.path(), "Another name").unwrap();
        assert!(!created);
        assert_eq!(again.common_name().as_deref(), Some(a.as_str()));
    }

    #[test]
    fn csr_names_are_replaced() {
        let ca = Ca::generate("Test CA").unwrap();
        let key = KeyPair::generate().unwrap();
        let mut req = CertificateParams::new(vec!["evil.example".into()]).unwrap();
        req.subject_alt_names.push(SanType::URI(
            ia5("urn:bbf:usp:id:os::someone-else").unwrap(),
        ));
        let csr = req.serialize_request(&key).unwrap().pem().unwrap();
        let issued = ca
            .issue_from_csr(
                &csr,
                &Profile {
                    endpoint_id: "os::mine".into(),
                    days: 1,
                    ..Profile::default()
                },
            )
            .unwrap();
        assert_eq!(issued.key_pem, None);
        assert_eq!(endpoint_ids(&der(&issued.cert_pem)), vec!["os::mine"]);
    }

    #[test]
    fn ca_files_are_created_once() {
        let dir = tempfile::tempdir().unwrap();
        let (a, created) = Ca::load_or_create(dir.path(), "Test CA").unwrap();
        assert!(created);
        let (b, created) = Ca::load_or_create(dir.path(), "Test CA").unwrap();
        assert!(!created);
        assert_eq!(a.cert_pem(), b.cert_pem());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.path().join("ca.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Reloaded CA -> issue works.
        let issued = b
            .issue(&Profile {
                endpoint_id: "self::ctrl".into(),
                dns_names: vec!["localhost".into()],
                ip_addresses: vec!["127.0.0.1".parse().unwrap()],
                server: true,
                days: 1,
            })
            .unwrap();
        assert_eq!(endpoint_ids(&der(&issued.cert_pem)), vec!["self::ctrl"]);
    }
}
