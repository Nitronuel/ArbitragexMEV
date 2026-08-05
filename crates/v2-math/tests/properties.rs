use alloy_primitives::{Address, U256};
use domain::{Cycle, CycleHop, CycleId, Fee, PoolId, PoolState, StateVersion};
use proptest::prelude::*;
use v2_math::{optimal_input, quote_cycle, quote_hop};

const FEE: Fee = Fee {
    numerator: 997,
    denominator: 1_000,
};

fn state(reserve0: u64, reserve1: u64) -> PoolState {
    PoolState {
        reserve0: U256::from(reserve0),
        reserve1: U256::from(reserve1),
        block_number: 1,
        transaction_index: 0,
        log_index: 0,
        version: StateVersion(1),
    }
}

fn cycle(hop_count: usize) -> Cycle {
    let anchor = Address::repeat_byte(1);
    let token = Address::repeat_byte(2);
    Cycle {
        id: CycleId(0),
        anchor,
        hops: (0..hop_count)
            .map(|index| CycleHop {
                pool_id: PoolId(u32::try_from(index).unwrap()),
                token_in: if index == 0 { anchor } else { token },
                token_out: if index + 1 == hop_count {
                    anchor
                } else {
                    token
                },
                fee: FEE,
                zero_for_one: true,
            })
            .collect(),
    }
}

proptest! {
    #[test]
    fn output_is_below_reserve_and_monotonic(
        reserve_in in 1_u64..1_000_000,
        reserve_out in 1_u64..1_000_000,
        input in 0_u64..100_000,
        increment in 0_u64..100_000,
    ) {
        let first = quote_hop(U256::from(input), U256::from(reserve_in), U256::from(reserve_out), FEE).unwrap();
        let second = quote_hop(U256::from(input + increment), U256::from(reserve_in), U256::from(reserve_out), FEE).unwrap();
        prop_assert!(first < U256::from(reserve_out));
        prop_assert!(second >= first);
    }

    #[test]
    fn optimizer_matches_small_exhaustive_search(
        hop_count in 2_usize..=4,
        outputs in prop::collection::vec(100_u64..500, 4),
    ) {
        let cycle = cycle(hop_count);
        let states: Vec<_> = outputs.into_iter().take(hop_count).map(|output| state(300, output)).collect();
        let optimized = optimal_input(&cycle, &states).unwrap();
        let exhaustive = (1_u64..=1_000)
            .map(|input| {
                let input = U256::from(input);
                let output = quote_cycle(input, &cycle, &states).unwrap();
                let profit = output.saturating_sub(input);
                (profit, input, output)
            })
            .max_by_key(|&(profit, _, _)| profit);

        match (optimized, exhaustive) {
            (None, Some((profit, _, _))) => prop_assert_eq!(profit, U256::ZERO),
            (Some(actual), Some((profit, _, _))) => prop_assert_eq!(actual.profit, profit),
            _ => prop_assert!(false, "exhaustive range is non-empty"),
        }
    }
}

#[test]
fn returns_none_for_unprofitable_cycle() {
    let cycle = cycle(2);
    let states = [state(1_000, 1_000), state(1_000, 1_000)];
    assert_eq!(optimal_input(&cycle, &states).unwrap(), None);
}

#[test]
fn finds_profitable_two_hop_input() {
    let cycle = cycle(2);
    let states = [state(1_000, 2_000), state(1_000, 1_000)];
    let quote = optimal_input(&cycle, &states).unwrap().unwrap();
    assert!(quote.output > quote.input);
    assert_eq!(quote.profit, quote.output - quote.input);
}
