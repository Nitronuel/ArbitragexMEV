//! Supported blockchain profiles. Each profile selects a chain ID and the
//! environment variable names used to source its HTTPS and WebSocket endpoints.

/// Base mainnet (OP-based L2).
pub const BASE_CHAIN_ID: u64 = 8453;
/// Robinhood Chain mainnet (Arbitrum Nitro/Orbit L2).
pub const ROBINHOOD_CHAIN_ID: u64 = 4663;

/// A supported observation target chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Base,
    Robinhood,
}

impl Chain {
    /// Resolves a chain from its numeric chain ID, or [`None`] when unsupported.
    #[must_use]
    pub fn from_id(id: u64) -> Option<Self> {
        match id {
            BASE_CHAIN_ID => Some(Self::Base),
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

    /// All supported chains. Order is canonical for tooling/debug.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Base, Self::Robinhood]
    }
}

#[cfg(test)]
mod tests {
    use super::{BASE_CHAIN_ID, Chain, ROBINHOOD_CHAIN_ID};

    #[test]
    fn resolves_supported_chain_ids() {
        assert_eq!(Chain::from_id(BASE_CHAIN_ID), Some(Chain::Base));
        assert_eq!(Chain::from_id(ROBINHOOD_CHAIN_ID), Some(Chain::Robinhood));
        assert_eq!(Chain::from_id(1), None);
    }

    #[test]
    fn profiles_carry_values_and_env_names() {
        for (chain, id) in [
            (Chain::Base, BASE_CHAIN_ID),
            (Chain::Robinhood, ROBINHOOD_CHAIN_ID),
        ] {
            assert_eq!(chain.id(), id);
            assert_eq!(Chain::from_id(id), Some(chain));
            assert!(!chain.http_env_var().ends_with('_'));
            assert!(!chain.ws_env_var().ends_with('_'));
        }
        assert_eq!(Chain::Base.http_env_var(), "BASE_HTTP_RPC_URL");
        assert_eq!(Chain::Robinhood.ws_env_var(), "ROBINHOOD_WS_RPC_URL");
    }
}
