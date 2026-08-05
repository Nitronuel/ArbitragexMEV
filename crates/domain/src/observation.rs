use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

use crate::{CycleId, StateVersion};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub cycle_id: CycleId,
    pub state_version: StateVersion,
    pub input: U256,
    pub output: U256,
    pub estimated_profit: U256,
    pub observed_at_unix_milliseconds: u64,
}
