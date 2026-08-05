use std::collections::HashMap;

use alloy_primitives::Address;
use domain::{Fee, PoolId};

use crate::VerifiedPool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectedEdge {
    pub pool_id: PoolId,
    pub pool_address: Address,
    pub token_in: Address,
    pub token_out: Address,
    pub fee: Fee,
    pub zero_for_one: bool,
}

pub(crate) fn adjacency(pools: &[VerifiedPool]) -> HashMap<Address, Vec<DirectedEdge>> {
    let mut adjacency: HashMap<Address, Vec<DirectedEdge>> = HashMap::new();
    for verified in pools {
        let pool = &verified.pool;
        adjacency
            .entry(pool.token0)
            .or_default()
            .push(DirectedEdge {
                pool_id: pool.id,
                pool_address: pool.address,
                token_in: pool.token0,
                token_out: pool.token1,
                fee: pool.fee,
                zero_for_one: true,
            });
        adjacency
            .entry(pool.token1)
            .or_default()
            .push(DirectedEdge {
                pool_id: pool.id,
                pool_address: pool.address,
                token_in: pool.token1,
                token_out: pool.token0,
                fee: pool.fee,
                zero_for_one: false,
            });
    }
    for edges in adjacency.values_mut() {
        edges.sort_unstable_by_key(|edge| (edge.token_out, edge.pool_address, edge.pool_id.0));
    }
    adjacency
}
