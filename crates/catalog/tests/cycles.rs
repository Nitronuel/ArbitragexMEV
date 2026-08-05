use std::collections::HashSet;

use alloy_primitives::{Address, U256};
use catalog::{CycleError, CycleLimits, VerifiedPool, compile_cycles};
use domain::{Fee, Pool, PoolId, PoolState, StateVersion};

const LIMITS: CycleLimits = CycleLimits {
    max_cycles: 1_000,
    max_cycles_per_pool: 1_000,
};
const FEE: Fee = Fee {
    numerator: 997,
    denominator: 1_000,
};

fn token(value: u8) -> Address {
    Address::repeat_byte(value)
}

fn pool(id: u32, address: u8, token0: u8, token1: u8) -> VerifiedPool {
    VerifiedPool {
        pool: Pool {
            id: PoolId(id),
            address: Address::repeat_byte(address),
            token0: token(token0),
            token1: token(token1),
            fee: FEE,
        },
        token0_decimals: 18,
        token1_decimals: 18,
        initial_state: PoolState {
            reserve0: U256::from(1_000),
            reserve1: U256::from(1_000),
            block_number: 1,
            transaction_index: 0,
            log_index: 0,
            version: StateVersion(0),
        },
        source: "fixture".to_owned(),
    }
}

fn anchors(values: &[u8]) -> HashSet<Address> {
    values.iter().copied().map(token).collect()
}

#[test]
fn includes_two_three_and_four_hop_cycles_in_both_directions() {
    let two = [pool(0, 10, 1, 2), pool(1, 11, 1, 2)];
    let graph = compile_cycles(&two, &anchors(&[1]), LIMITS).unwrap();
    assert_eq!(graph.cycles.len(), 2);
    assert!(graph.cycles.iter().all(|cycle| cycle.hops.len() == 2));

    let three = [pool(0, 10, 1, 2), pool(1, 11, 2, 3), pool(2, 12, 3, 1)];
    let graph = compile_cycles(&three, &anchors(&[1]), LIMITS).unwrap();
    assert_eq!(graph.cycles.len(), 2);
    assert!(graph.cycles.iter().all(|cycle| cycle.hops.len() == 3));

    let four = [
        pool(0, 10, 1, 2),
        pool(1, 11, 2, 3),
        pool(2, 12, 3, 4),
        pool(3, 13, 4, 1),
    ];
    let graph = compile_cycles(&four, &anchors(&[1]), LIMITS).unwrap();
    assert_eq!(graph.cycles.len(), 2);
    assert!(graph.cycles.iter().all(|cycle| cycle.hops.len() == 4));
}

#[test]
fn excludes_unanchored_cycles_and_routes_over_four_hops() {
    let triangle = [pool(0, 10, 1, 2), pool(1, 11, 2, 3), pool(2, 12, 3, 1)];
    assert!(
        compile_cycles(&triangle, &anchors(&[9]), LIMITS)
            .unwrap()
            .cycles
            .is_empty()
    );

    let five = [
        pool(0, 10, 1, 2),
        pool(1, 11, 2, 3),
        pool(2, 12, 3, 4),
        pool(3, 13, 4, 5),
        pool(4, 14, 5, 1),
    ];
    assert!(
        compile_cycles(&five, &anchors(&[1]), LIMITS)
            .unwrap()
            .cycles
            .is_empty()
    );
}

#[test]
fn excludes_repeated_pools_and_intermediate_tokens() {
    let single = [pool(0, 10, 1, 2)];
    assert!(
        compile_cycles(&single, &anchors(&[1]), LIMITS)
            .unwrap()
            .cycles
            .is_empty()
    );

    let repeated_token_route = [
        pool(0, 10, 1, 2),
        pool(1, 11, 2, 3),
        pool(2, 12, 3, 2),
        pool(3, 13, 2, 1),
    ];
    assert!(
        compile_cycles(&repeated_token_route, &anchors(&[1]), LIMITS)
            .unwrap()
            .cycles
            .iter()
            .all(|cycle| cycle.hops.len() == 2)
    );
}

#[test]
fn deduplicates_anchor_rotations_but_preserves_reverse_routes() {
    let triangle = [pool(0, 10, 1, 2), pool(1, 11, 2, 3), pool(2, 12, 3, 1)];
    let graph = compile_cycles(&triangle, &anchors(&[1, 2, 3]), LIMITS).unwrap();
    assert_eq!(graph.cycles.len(), 2);
    assert_ne!(
        graph.cycles[0]
            .hops
            .iter()
            .map(|hop| hop.pool_id)
            .collect::<Vec<_>>(),
        graph.cycles[1]
            .hops
            .iter()
            .map(|hop| hop.pool_id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn output_and_dirty_index_are_deterministic() {
    let pools = vec![pool(0, 12, 3, 1), pool(1, 10, 1, 2), pool(2, 11, 2, 3)];
    let mut reversed = pools.clone();
    reversed.reverse();
    let first = compile_cycles(&pools, &anchors(&[1]), LIMITS).unwrap();
    let second = compile_cycles(&reversed, &anchors(&[1]), LIMITS).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.cycles[0].id.0, 0);
    assert_eq!(first.cycles[1].id.0, 1);
    for (pool_index, cycle_ids) in first.by_pool.iter().enumerate() {
        for cycle_id in cycle_ids {
            assert!(
                first.cycles[cycle_id.0 as usize]
                    .hops
                    .iter()
                    .any(|hop| hop.pool_id.0 as usize == pool_index)
            );
        }
    }
}

#[test]
fn fails_before_exceeding_cycle_and_per_pool_limits() {
    let pools = [pool(0, 10, 1, 2), pool(1, 11, 1, 2)];
    assert!(matches!(
        compile_cycles(
            &pools,
            &anchors(&[1]),
            CycleLimits {
                max_cycles: 1,
                max_cycles_per_pool: 10,
            },
        ),
        Err(CycleError::CycleLimit { limit: 1 })
    ));
    assert!(matches!(
        compile_cycles(
            &pools,
            &anchors(&[1]),
            CycleLimits {
                max_cycles: 10,
                max_cycles_per_pool: 1,
            },
        ),
        Err(CycleError::PerPoolLimit { limit: 1, .. })
    ));
}

#[test]
fn rejects_duplicate_and_non_compact_pool_ids() {
    let duplicate = [pool(0, 10, 1, 2), pool(0, 11, 1, 2)];
    assert!(matches!(
        compile_cycles(&duplicate, &anchors(&[1]), LIMITS),
        Err(CycleError::DuplicatePoolId(0))
    ));

    let gap = [pool(0, 10, 1, 2), pool(2, 11, 1, 2)];
    assert!(matches!(
        compile_cycles(&gap, &anchors(&[1]), LIMITS),
        Err(CycleError::NonCompactPoolId {
            expected: 1,
            actual: 2
        })
    ));
}
