//! USP version in `Record.version` (`major.minor`).

use std::fmt;
use std::str::FromStr;

/// USP version, e.g. `1.3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UspVersion {
    /// `1` for USP 1.x.
    pub major: u16,
    pub minor: u16,
}

impl UspVersion {
    /// Version of the schemas in this crate.
    pub const CURRENT: Self = Self { major: 1, minor: 5 };

    /// Version for a peer = min(ours, theirs).
    pub fn negotiate(self, peer: Self) -> Self {
        self.min(peer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid USP version {0:?}")]
pub struct ParseVersionError(pub String);

impl FromStr for UspVersion {
    type Err = ParseVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseVersionError(s.to_owned());
        let (major, minor) = s.trim().split_once('.').ok_or_else(err)?;
        Ok(Self {
            major: major.parse().map_err(|_| err())?,
            minor: minor.parse().map_err(|_| err())?,
        })
    }
}

impl fmt::Display for UspVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}
