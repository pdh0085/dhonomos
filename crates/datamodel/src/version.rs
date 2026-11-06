//! Data model + item version numbers (`major.minor[.patch]`).

use std::fmt;
use std::str::FromStr;

/// BBF data model version, e.g. `2.21`, `2.12.1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    /// Corrigendum; `0` when absent.
    pub patch: u16,
}

impl Version {
    /// `major.minor`, patch 0.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self {
            major,
            minor,
            patch: 0,
        }
    }
}

/// Malformed version string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid version {0:?}")]
pub struct ParseVersionError(pub String);

impl FromStr for Version {
    type Err = ParseVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseVersionError(s.to_owned());
        let mut parts = s.split('.');
        let mut next = |required: bool| -> Result<u16, ParseVersionError> {
            match parts.next() {
                Some(p) => p.parse().map_err(|_| err()),
                None if required => Err(err()),
                None => Ok(0),
            }
        };
        let v = Self {
            major: next(true)?,
            minor: next(true)?,
            patch: next(false)?,
        };
        if parts.next().is_some() {
            return Err(err());
        }
        Ok(v)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)?;
        if self.patch != 0 {
            write!(f, ".{}", self.patch)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display() {
        assert_eq!("2.21".parse(), Ok(Version::new(2, 21)));
        let v: Version = "2.12.1".parse().unwrap_or(Version::new(0, 0));
        assert_eq!((v.major, v.minor, v.patch), (2, 12, 1));
        assert_eq!(v.to_string(), "2.12.1");
        assert!("2".parse::<Version>().is_err());
        assert!("2.x".parse::<Version>().is_err());
        assert!("1.2.3.4".parse::<Version>().is_err());
    }

    #[test]
    fn ordering_is_numeric() {
        assert!(Version::new(2, 9) < Version::new(2, 21));
    }
}
