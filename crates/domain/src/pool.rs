use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PoolId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fee {
    pub numerator: u32,
    pub denominator: u32,
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
