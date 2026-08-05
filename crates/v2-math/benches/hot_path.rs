use alloy_primitives::{Address, U256};
use criterion::{Criterion, criterion_group, criterion_main};
use domain::{Cycle, CycleHop, CycleId, Fee, PoolId, PoolState, StateVersion};
use v2_math::{optimal_input, quote_hop};

fn benchmark_quote_hop(criterion: &mut Criterion) {
    criterion.bench_function("quote_hop", |bencher| {
        bencher.iter(|| {
            quote_hop(
                U256::from(1_000_000_u64),
                U256::from(10_000_000_u64),
                U256::from(20_000_000_u64),
                Fee {
                    numerator: 997,
                    denominator: 1_000,
                },
            )
            .unwrap()
        });
    });

    let anchor = Address::repeat_byte(1);
    let token = Address::repeat_byte(2);
    let fee = Fee {
        numerator: 997,
        denominator: 1_000,
    };
    let cycle = Cycle {
        id: CycleId(0),
        anchor,
        hops: vec![
            CycleHop {
                pool_id: PoolId(0),
                token_in: anchor,
                token_out: token,
                fee,
                zero_for_one: true,
            },
            CycleHop {
                pool_id: PoolId(1),
                token_in: token,
                token_out: anchor,
                fee,
                zero_for_one: true,
            },
        ],
    };
    let state = |reserve0, reserve1| PoolState {
        reserve0: U256::from(reserve0),
        reserve1: U256::from(reserve1),
        block_number: 1,
        transaction_index: 0,
        log_index: 0,
        version: StateVersion(1),
    };
    let states = [
        state(10_000_000_u64, 20_000_000_u64),
        state(10_000_000_u64, 10_000_000_u64),
    ];
    criterion.bench_function("optimal_input_two_hop", |bencher| {
        bencher.iter(|| optimal_input(&cycle, &states).unwrap());
    });
}

criterion_group!(benches, benchmark_quote_hop);
criterion_main!(benches);
