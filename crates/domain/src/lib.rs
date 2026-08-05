pub mod config;
pub mod cycle;
pub mod observation;
pub mod pool;

pub use config::{ConfigError, RpcUrl, ShadowConfig};
pub use cycle::{Cycle, CycleHop, CycleId};
pub use observation::Observation;
pub use pool::{Fee, Pool, PoolId, PoolState, Readiness, StateVersion};

pub const BASE_CHAIN_ID: u64 = 8453;

#[cfg(test)]
mod tests {
    #[test]
    fn chain_id_is_base_mainnet() {
        assert_eq!(super::BASE_CHAIN_ID, 8453);
    }
}
