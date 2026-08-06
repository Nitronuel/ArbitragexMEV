//! Supported blockchain profiles. Each profile selects a chain ID and the
//! environment variable names used to source its HTTPS and WebSocket endpoints.

/// Base mainnet (OP-based L2). **Temporarily disabled** while the project tracks
/// the Alchemy API budget on the active chain; the profile data is retained so it
/// can be re-enabled by adding the `from_id` arm and `all()` entry back.
pub const BASE_CHAIN_ID: u64 = 8453;
/// Robinhood Chain mainnet (Arbitrum Nitro/Orbit L2). Primary observation target.
pub const ROBINHOOD_CHAIN_ID: u64 = 4663;

/// A supported observation target chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    /// Reserved profile. Not enabled; see [`BASE_CHAIN_ID`].
    Base,
    Robinhood,
}

impl Chain {
    /// Resolves an enabled chain from its numeric chain ID, or [`None`] when
    /// unsupported or currently disabled. Only Robinhood is enabled.
    #[must_use]
    pub fn from_id(id: u64) -> Option<Self> {
        match id {
            ROBINHOOD_CHAIN_ID => Some(Self::Robinhood),
            _ => None,
        }
    }

    #[must_use]
    pub fn id(self) -> u64 {
        match self {
            Self::Base => BASE_CHAIN_ID,
            Self::Robinhood => ROBINHOOD_CHAIN_ID,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Robinhood => "robinhood",
        }
    }

    /// Environment variable holding the HTTPS JSON-RPC endpoint for this chain.
    #[must_use]
    pub const fn http_env_var(self) -> &'static str {
        match self {
            Self::Base => "BASE_HTTP_RPC_URL",
            Self::Robinhood => "ROBINHOOD_HTTP_RPC_URL",
        }
    }

    /// Environment variable holding the WebSocket JSON-RPC endpoint for this chain.
    #[must_use]
    pub const fn ws_env_var(self) -> &'static str {
        match self {
            Self::Base => "BASE_WS_RPC_URL",
            Self::Robinhood => "ROBINHOOD_WS_RPC_URL",
        }
    }

    /// Currently enabled chains. Order is canonical for tooling/debug.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Robinhood]
    }
}

#[cfg(test)]
mod tests {
    use super::{BASE_CHAIN_ID, Chain, ROBINHOOD_CHAIN_ID};

    #[test]
    fn rejects_disabled_base_and_resolves_robinhood() {
        assert_eq!(Chain::from_id(BASE_CHAIN_ID), None);
        assert_eq!(Chain::from_id(ROBINHOOD_CHAIN_ID), Some(Chain::Robinhood));
        assert_eq!(Chain::from_id(1), None);
        assert_eq!(Chain::all(), &[Chain::Robinhood]);
    }

    #[test]
    fn profiles_carry_values_and_env_names() {
        let chain = Chain::Robinhood;
        let id = ROBINHOOD_CHAIN_ID;
        assert_eq!(chain.id(), id);
        assert_eq!(Chain::from_id(id), Some(chain));
        assert!(!chain.http_env_var().ends_with('_'));
        assert!(!chain.ws_env_var().ends_with('_'));
        assert_eq!(chain.ws_env_var(), "ROBINHOOD_WS_RPC_URL");
    }
}
