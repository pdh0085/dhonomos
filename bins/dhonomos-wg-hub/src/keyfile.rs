//! 2 secret files of the hub:
//! token -> auth to the server, written by the operator;
//! WireGuard private key -> made here on 1st start, never sent; server gets only the public key.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use anyhow::{Context as _, bail};
use dhonomos_wireguard::{HUB_TOKEN_PREFIX, generate_keypair, validate_key};
use zeroize::Zeroizing;

fn readable_by_others(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o077 != 0)
}

/// Token from token file text, trimmed. Must start with `dwh_` + printable ASCII, no spaces.
pub(crate) fn parse_token(text: &str) -> Result<Zeroizing<String>, String> {
    let token = text.trim();
    if !token.starts_with(HUB_TOKEN_PREFIX) || token.len() == HUB_TOKEN_PREFIX.len() {
        return Err(format!(
            "it does not hold a hub token (one line starting with {HUB_TOKEN_PREFIX})"
        ));
    }
    if !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("the token has characters a hub token does not have".into());
    }
    Ok(Zeroizing::new(token.to_owned()))
}

/// Read token file. Readable by group/others -> warning.
pub(crate) fn load_token(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let text = Zeroizing::new(
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    );
    let token = parse_token(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    if readable_by_others(path) {
        tracing::warn!(file = %path.display(), "the token file is readable by group or others; chmod 600 it");
    }
    Ok(token)
}

/// Private key from an existing key file, validated.
fn read_key(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let text = Zeroizing::new(
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    );
    let key = Zeroizing::new(text.trim().to_owned());
    if validate_key(&key).is_err() {
        bail!(
            "{} does not hold a WireGuard private key (one line of base64); it is left as it is",
            path.display()
        );
    }
    if readable_by_others(path) {
        tracing::warn!(file = %path.display(), "the key file is readable by group or others; chmod 600 it");
    }
    Ok(key)
}

/// Private key from the key file. No file -> `None` (for `--dry-run`, creates nothing).
pub(crate) fn load_existing_key(path: &Path) -> anyhow::Result<Option<Zeroizing<String>>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        Ok(_) => read_key(path).map(Some),
    }
}

/// Private key from the key file. No file -> new key written there, mode 0600.
/// 2nd value = key created.
/// File with other content -> error, never overwritten.
pub(crate) fn load_or_create_key(path: &Path) -> anyhow::Result<(Zeroizing<String>, bool)> {
    if let Some(key) = load_existing_key(path)? {
        return Ok((key, false));
    }
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !dir.is_dir() {
        bail!(
            "the directory of the key file, {}, does not exist",
            dir.display()
        );
    }
    let pair = generate_keypair().context("making the hub key")?;
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(f) => f,
        // Made by someone else in between -> use theirs.
        Err(e) if e.kind() == ErrorKind::AlreadyExists => return Ok((read_key(path)?, false)),
        Err(e) => return Err(e).with_context(|| format!("creating {}", path.display())),
    };
    let line = Zeroizing::new(format!("{}\n", pair.private.as_str()));
    file.write_all(line.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok((pair.private, true))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use dhonomos_wireguard::public_from_private;

    use super::*;

    #[test]
    fn token_files() {
        assert_eq!(
            parse_token("  dwh_abcDEF123-_x\n").unwrap().as_str(),
            "dwh_abcDEF123-_x"
        );
        for bad in [
            "",
            "\n",
            "dwh_",
            "abc",
            "Bearer dwh_abc",
            "dwh_a b",
            "dwh_ä",
        ] {
            assert!(parse_token(bad).is_err(), "{bad:?}");
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        fs::write(&path, "dwh_secret\n").unwrap();
        assert_eq!(load_token(&path).unwrap().as_str(), "dwh_secret");
        let err = load_token(&dir.path().join("missing")).unwrap_err();
        assert!(format!("{err:#}").contains("missing"), "{err:#}");
        fs::write(&path, "not a token").unwrap();
        let err = load_token(&path).unwrap_err().to_string();
        assert!(err.contains("dwh_"), "{err}");
        assert!(
            !err.contains("not a token"),
            "the content is not echoed: {err}"
        );
    }

    #[test]
    fn a_missing_key_file_is_created_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private.key");
        assert!(load_existing_key(&path).unwrap().is_none());
        let (key, created) = load_or_create_key(&path).unwrap();
        assert!(created);
        validate_key(&key).unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read_to_string(&path).unwrap(), format!("{}\n", *key));
        // Next start -> same key.
        let (again, created) = load_or_create_key(&path).unwrap();
        assert!(!created);
        assert_eq!(*again, *key);
        assert_eq!(*load_existing_key(&path).unwrap().unwrap(), *key);
        public_from_private(&again).unwrap();
    }

    #[test]
    fn a_key_file_made_elsewhere_is_reused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private.key");
        let pair = generate_keypair().unwrap();
        fs::write(&path, format!("  {}  \n\n", *pair.private)).unwrap();
        let (key, created) = load_or_create_key(&path).unwrap();
        assert!(!created);
        assert_eq!(*key, *pair.private);
    }

    #[test]
    fn a_bad_key_file_is_refused_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private.key");
        for bad in [
            "",
            "garbage\n",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
        ] {
            fs::write(&path, bad).unwrap();
            let err = load_or_create_key(&path).unwrap_err().to_string();
            assert!(err.contains("left as it is"), "{err}");
            assert!(load_existing_key(&path).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), bad, "never overwritten");
        }
    }

    #[test]
    fn the_key_directory_must_exist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope").join("private.key");
        let err = load_or_create_key(&path).unwrap_err().to_string();
        assert!(err.contains("does not exist"), "{err}");
        assert!(!dir.path().join("nope").exists());
    }
}
