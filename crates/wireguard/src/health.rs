//! Tunnel health of a member from hub reports: 5 states.
//! Same thresholds in server summary, device filter + web UI (summary sends them to the UI).

/// Latest handshake age below this (s) -> `connected`.
pub const CONNECTED_SECS: i64 = 180;
/// Latest handshake age above this (s) -> `stale`.
/// [`CONNECTED_SECS`] to here -> `idle`.
pub const STALE_SECS: i64 = 900;
/// Hub silent above this (s) -> its members `unknown`.
pub const HUB_SILENT_SECS: i64 = 300;

/// Tunnel of a member, seen from its hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TunnelState {
    /// Handshake within [`CONNECTED_SECS`].
    Connected,
    /// Latest handshake [`CONNECTED_SECS`] to [`STALE_SECS`] old.
    Idle,
    /// Latest handshake older than [`STALE_SECS`].
    Stale,
    /// No handshake ever, or hub reported nothing on the member.
    Never,
    /// Hub silent above [`HUB_SILENT_SECS`] (or never reported) -> nothing known.
    /// Wins over all other states.
    Unknown,
}

impl TunnelState {
    /// All states, in UI order.
    pub const ALL: [Self; 5] = [
        Self::Connected,
        Self::Idle,
        Self::Stale,
        Self::Never,
        Self::Unknown,
    ];

    /// State from latest handshake age (`None` = never) + hub silence
    /// (`None` = never reported), both in s.
    pub fn of(handshake_age_secs: Option<i64>, hub_silent_secs: Option<i64>) -> Self {
        match (hub_silent_secs, handshake_age_secs) {
            (None, _) => Self::Unknown,
            (Some(h), _) if h > HUB_SILENT_SECS => Self::Unknown,
            (_, None) => Self::Never,
            (_, Some(a)) if a < CONNECTED_SECS => Self::Connected,
            (_, Some(a)) if a <= STALE_SECS => Self::Idle,
            _ => Self::Stale,
        }
    }

    /// Name in the API.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Idle => "idle",
            Self::Stale => "stale",
            Self::Never => "never",
            Self::Unknown => "unknown",
        }
    }

    /// Inverse of [`Self::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_follow_the_thresholds_and_a_silent_hub_wins() {
        let up = Some(10);
        assert_eq!(TunnelState::of(Some(0), up), TunnelState::Connected);
        assert_eq!(TunnelState::of(Some(179), up), TunnelState::Connected);
        assert_eq!(TunnelState::of(Some(180), up), TunnelState::Idle);
        assert_eq!(TunnelState::of(Some(900), up), TunnelState::Idle);
        assert_eq!(TunnelState::of(Some(901), up), TunnelState::Stale);
        assert_eq!(TunnelState::of(None, up), TunnelState::Never);
        assert_eq!(TunnelState::of(Some(0), Some(300)), TunnelState::Connected);
        assert_eq!(TunnelState::of(Some(0), Some(301)), TunnelState::Unknown);
        assert_eq!(TunnelState::of(None, None), TunnelState::Unknown);
    }

    #[test]
    fn names_round_trip() {
        for s in TunnelState::ALL {
            assert_eq!(TunnelState::parse(s.as_str()), Some(s));
        }
        assert_eq!(TunnelState::parse("up"), None);
    }
}
