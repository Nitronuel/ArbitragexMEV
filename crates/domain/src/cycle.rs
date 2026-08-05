use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

use crate::{Fee, PoolId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CycleId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CycleHop {
    pub pool_id: PoolId,
    pub token_in: Address,
    pub token_out: Address,
    pub fee: Fee,
    pub zero_for_one: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cycle {
    pub id: CycleId,
    pub anchor: Address,
    pub hops: Vec<CycleHop>,
}
