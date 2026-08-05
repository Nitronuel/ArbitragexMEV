use alloy_primitives::U256;
use domain::PoolId;

use crate::{StateError, SyncLog};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciledState {
    pub pool_id: PoolId,
    pub reserve0: U256,
    pub reserve1: U256,
}

pub trait RecoverySource {
    /// Fetches canonical and removed Sync logs for one inclusive block range.
    ///
    /// # Errors
    ///
    /// Returns an error if the complete range cannot be served.
    fn logs(&self, from_block: u64, to_block: u64) -> Result<Vec<SyncLog>, StateError>;

    /// Reads reserves for all active pools at the recovery head.
    ///
    /// # Errors
    ///
    /// Returns an error if a complete pinned reconciliation cannot be served.
    fn reserves(&self, block: u64) -> Result<Vec<ReconciledState>, StateError>;
}
