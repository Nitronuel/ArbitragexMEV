//! Flash-loan source selection and fee modeling.
//!
//! Capital comes from flash loans, never inventory (see `SECURITY.md`
//! conventions). The gating economics therefore must charge every quote the
//! borrow fee of the provider that would actually serve it — a zero rate
//! overstates profit and lets sub-economic routes clear the submission gate.
//!
//! Fee rates are protocol-version constants, re-verified 2026-08-22 against
//! primary sources:
//!
//! - **Balancer V2**: the Vault's `flashLoan` charges the configured
//!   flash-loan fee percentage, which has been zero since deployment
//!   (`FlashLoans.sol`: `feeAmounts[i] = amounts * _getFlashLoanFeePercentage`,
//!   with the protocol percentage defaulting to zero).
//! - **Aave V3**: `Pool.flashLoanSimple` charges the total premium
//!   (`FLASHLOAN_PREMIUM_TOTAL`, 5 bps = 0.05%) on the borrowed principal.
//! - **Uniswap V4**: native flash accounting — within `unlock` a caller may
//!   `take` tokens against transient debts and must settle before returning;
//!   no fee is charged by the `PoolManager`.
//!
//! Selection is fail-closed: in `auto` mode a token without at least one
//! supporting provider has **no** borrow cost model and is screened
//! `NotEvaluated` instead of being gated at a made-up rate.

use std::collections::HashMap;

use alloy_primitives::{Address, U256};

use crate::economics::FIXED_POINT_SCALE;

/// A flash-loan source and its per-borrow fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlashLoanProvider {
    /// Balancer V2 Vault `flashLoan`; zero protocol fee percentage.
    BalancerV2,
    /// Uniswap V4 `unlock` flash accounting; free, debt settled in-lock.
    UniswapV4Flash,
    /// Aave V3 `Pool.flashLoanSimple`; 0.05% premium on principal.
    AaveV3,
}

impl FlashLoanProvider {
    /// Every provider, cheapest-fee first. Auto-selection picks the first
    /// entry of this order that supports the token.
    pub const ALL: [FlashLoanProvider; 3] = [
        FlashLoanProvider::BalancerV2,
        FlashLoanProvider::UniswapV4Flash,
        FlashLoanProvider::AaveV3,
    ];

    /// Borrow fee as a fixed-point fraction of the principal
    /// ([`FIXED_POINT_SCALE`] basis).
    #[must_use]
    pub fn fee_rate(self) -> U256 {
        // 0.05% = 5 / 10_000.
        match self {
            FlashLoanProvider::BalancerV2 | FlashLoanProvider::UniswapV4Flash => U256::ZERO,
            FlashLoanProvider::AaveV3 => {
                U256::from(FIXED_POINT_SCALE) * U256::from(5) / U256::from(10_000)
            }
        }
    }

    /// CLI/config name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            FlashLoanProvider::BalancerV2 => "balancer-v2",
            FlashLoanProvider::UniswapV4Flash => "uniswap-v4",
            FlashLoanProvider::AaveV3 => "aave-v3",
        }
    }

    /// Parses [`Self::name`].
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|provider| provider.name() == name)
    }
}

/// How a route's borrow cost is chosen.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum FlashSelection {
    /// Legacy zero-fee assumption; measurement only, never honest gating.
    #[default]
    None,
    /// One provider serves every token at its fixed rate.
    Fixed(FlashLoanProvider),
    /// Per-token provider support map (cheapest supporting provider wins).
    /// Tokens missing from the map are unsupported and never gate.
    Auto(HashMap<Address, Vec<FlashLoanProvider>>),
}

impl FlashSelection {
    /// Builds an [`FlashSelection::Auto`] map from support rows loaded by
    /// [`load_support_csv`]-style parsing: `token,provider` per line.
    #[must_use]
    pub fn auto_from_rows(rows: &[(Address, String)]) -> Self {
        let mut map: HashMap<Address, Vec<FlashLoanProvider>> = HashMap::new();
        for (token, provider) in rows {
            if let Some(provider) = FlashLoanProvider::parse(provider) {
                map.entry(*token).or_default().push(provider);
            }
        }
        for providers in map.values_mut() {
            providers.sort_by_key(|provider| provider.fee_rate());
        }
        Self::Auto(map)
    }

    /// The borrow fee rate for `anchor`, or `None` when no configured
    /// provider supports it (fail-closed: such routes are never gated).
    #[must_use]
    pub fn rate_for(&self, anchor: Address) -> Option<U256> {
        match self {
            FlashSelection::None => Some(U256::ZERO),
            FlashSelection::Fixed(provider) => Some(provider.fee_rate()),
            FlashSelection::Auto(map) => map
                .get(&anchor)
                .and_then(|providers| providers.first())
                .copied()
                .map(FlashLoanProvider::fee_rate),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        Address::new([
            0xfeu8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, n,
        ])
    }

    #[test]
    fn fee_rates_match_verified_protocol_constants() {
        assert_eq!(FlashLoanProvider::BalancerV2.fee_rate(), U256::ZERO);
        assert_eq!(FlashLoanProvider::UniswapV4Flash.fee_rate(), U256::ZERO);
        let expected = U256::from(FIXED_POINT_SCALE) * U256::from(5) / U256::from(10_000);
        assert_eq!(FlashLoanProvider::AaveV3.fee_rate(), expected);
    }

    #[test]
    fn parse_round_trips_names() {
        for provider in FlashLoanProvider::ALL {
            assert_eq!(FlashLoanProvider::parse(provider.name()), Some(provider));
        }
        assert_eq!(FlashLoanProvider::parse("nope"), None);
    }

    #[test]
    fn auto_selects_cheapest_supporting_provider() {
        let rows = vec![
            (addr(1), "aave-v3".to_owned()),
            (addr(1), "balancer-v2".to_owned()),
        ];
        let selection = FlashSelection::auto_from_rows(&rows);
        assert_eq!(selection.rate_for(addr(1)), Some(U256::ZERO));

        // Unknown provider names are dropped, not fatal.
        let rows = vec![(addr(2), "made-up".to_owned())];
        let selection = FlashSelection::auto_from_rows(&rows);
        assert_eq!(selection.rate_for(addr(2)), None);
    }

    #[test]
    fn auto_is_fail_closed_for_unsupported_tokens() {
        let rows = vec![(addr(1), "aave-v3".to_owned())];
        let selection = FlashSelection::auto_from_rows(&rows);
        assert_eq!(
            selection.rate_for(addr(1)),
            Some(FlashLoanProvider::AaveV3.fee_rate())
        );
        assert_eq!(selection.rate_for(addr(9)), None);
    }

    #[test]
    fn none_and_fixed_cover_every_token() {
        assert_eq!(FlashSelection::None.rate_for(addr(7)), Some(U256::ZERO));
        assert_eq!(
            FlashSelection::Fixed(FlashLoanProvider::AaveV3).rate_for(addr(7)),
            Some(FlashLoanProvider::AaveV3.fee_rate())
        );
    }
}
