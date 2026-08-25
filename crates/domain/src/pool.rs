use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PoolId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fee {
    pub numerator: u32,
    pub denominator: u32,
}

impl Fee {
    /// Plausibility band for any fee representation (audit C1/C39): a
    /// "fee" of zero, of the whole amount (`1/1`), or of nanoscopic size
    /// (`1/1_000_000_000`) is catalog noise or a convention mixup, never a
    /// tradeable pool. Both dialects normalize into this band.
    pub const MIN_FRACTION_NUMERATOR: u64 = 1;
    pub const MAX_FRACTION_DENOMINATOR: u64 = 1_000_000;

    /// Builds a `Fee` from a **keep-rate** fraction — the portion of the
    /// input a trader retains after the swap (Uniswap V2 catalogs: `997 /
    /// 1000`).
    ///
    /// # Errors
    ///
    /// Rejects fractions outside the plausibility band. Note the historical
    /// failure this guards against (audit C1): `data/manifest-activity.csv`
    /// stores *fee rates* (`3000 / 1_000_000`) while V2 catalogs store keep
    /// rates (`997 / 1000`) — both parsed verbatim into the same struct, and
    /// the dormant path read the former as a 99.7% fee per hop.
    pub fn keep_rate(numerator: u32, denominator: u32) -> Result<Self, String> {
        let taken = u64::from(denominator).saturating_sub(u64::from(numerator));
        Self::checked_fraction(taken, u64::from(denominator))?;
        Ok(Self {
            numerator,
            denominator,
        })
    }

    /// Builds a `Fee` from a **fee-rate** fraction — the portion taken
    /// (`3000 / 1_000_000` = 30 bps).
    ///
    /// # Errors
    ///
    /// Same band as [`Fee::keep_rate`].
    pub fn fee_rate(numerator: u32, denominator: u32) -> Result<Self, String> {
        Self::checked_fraction(u64::from(numerator), u64::from(denominator))?;
        Ok(Self {
            numerator,
            denominator,
        })
    }

    fn checked_fraction(taken: u64, total: u64) -> Result<(), String> {
        if total == 0 || taken > total {
            return Err(format!("fee fraction {taken}/{total} is not in [0, 1]"));
        }
        let kept = total - taken;
        // The kept share must sit inside the plausible trading band: strictly
        // positive and at least one part-per-million of the whole.
        if kept < Self::MIN_FRACTION_NUMERATOR {
            return Err(format!("fee keeps nothing ({kept}/{total})"));
        }
        let million = 1_000_000u64;
        if kept.saturating_mul(million) < total {
            return Err(format!(
                "fee fraction {taken}/{total} keeps less than one part-per-million"
            ));
        }
        Ok(())
    }
}

/// The automated market-maker formula a pool uses to price swaps.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub enum Profile {
    /// Constant-product (Uniswap V2, and V2-migrated launch curves). Flat reserves.
    #[default]
    ConstantProduct,
    /// Concentrated-liquidity (Uniswap V3). Tick + `sqrtPriceX96` state.
    Concentrated,
    /// Uniswap V4 `PoolManager` singleton. Tick + `sqrtPriceX96` state, hook-orientable.
    VolatileManaged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pool {
    pub id: PoolId,
    pub address: Address,
    pub token0: Address,
    pub token1: Address,
    pub fee: Fee,
    pub profile: Profile,
}

impl Pool {
    /// A constant-product pool (the historical default before cross-DEX support).
    #[must_use]
    pub const fn constant_product(
        id: PoolId,
        address: Address,
        token0: Address,
        token1: Address,
        fee: Fee,
    ) -> Self {
        Self {
            id,
            address,
            token0,
            token1,
            fee,
            profile: Profile::ConstantProduct,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StateVersion(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolState {
    pub reserve0: U256,
    pub reserve1: U256,
    pub block_number: u64,
    pub transaction_index: u64,
    pub log_index: u64,
    pub version: StateVersion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Readiness {
    Bootstrapping,
    Ready,
    Stale { reason: String },
}
