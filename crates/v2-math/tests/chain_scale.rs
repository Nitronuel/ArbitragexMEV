use alloy_primitives::{Address, U256};
use domain::{Cycle, CycleHop, CycleId, Fee, PoolId, PoolState, StateVersion};
use std::time::Instant;
use v2_math::optimal_input;

const FEE: Fee = Fee {
    numerator: 997,
    denominator: 1_000,
};

fn state(reserve0: U256, reserve1: U256) -> PoolState {
    PoolState {
        reserve0,
        reserve1,
        block_number: 1,
        transaction_index: 0,
        log_index: 0,
        version: StateVersion(1),
    }
}

fn pair_cycle() -> Cycle {
    let anchor = Address::repeat_byte(1);
    let token = Address::repeat_byte(2);
    Cycle {
        id: CycleId(0),
        anchor,
        hops: vec![
            CycleHop {
                pool_id: PoolId(0),
                token_in: anchor,
                token_out: token,
                fee: FEE,
                zero_for_one: true,
            },
            CycleHop {
                pool_id: PoolId(1),
                token_in: token,
                token_out: anchor,
                fee: FEE,
                zero_for_one: true,
            },
        ],
    }
}

#[test]
fn optimal_input_terminates_at_chain_scale() {
    let cycle = pair_cycle();
    for scale in [96u32, 100, 110, 120, 128] {
        let r0 = U256::from(1u64) << scale;
        let r1 = U256::from(1u64) << (scale - 2);
        let states = [state(r0, r1), state(r0, r1)];
        let t = Instant::now();
        let res = optimal_input(&cycle, &states);
        println!("scale 2^{scale}: {:?} res_ok={}", t.elapsed(), res.is_ok());
        assert!(
            t.elapsed().as_secs() < 10,
            "optimum search did not terminate at 2^{scale}"
        );
    }
}

#[test]
fn optimal_input_terminates_with_sub_wei_profit_at_chain_scale() {
    let cycle = pair_cycle();
    // Skew barely above breakeven on huge reserves: the continuous curve is
    // positive over an astronomically wide input range but every discrete
    // output rounds to <= input. best stays zero so the bound never prunes
    // and a naive recursive scan visits O(range) leaves.
    for skew_tenths in [1_u64, 5, 10, 100] {
        for scale in [96u32, 128, 160, 192] {
            let r0 = U256::from(1u64) << scale;
            let r1 = (r0 * U256::from(10u64)) / U256::from(10u64 + skew_tenths);
            if r1.is_zero() {
                continue;
            }
            let states = [state(r0, r1), state(r1, r0)];
            let t = Instant::now();
            let res = optimal_input(&cycle, &states);
            let elapsed = t.elapsed();
            let _ = res;
            println!("skew +{skew_tenths}e-1 scale 2^{scale}: {elapsed:?}");
            assert!(
                elapsed.as_secs() < 10,
                "optimum search did not terminate at skew {skew_tenths} scale 2^{scale}"
            );
        }
    }
}

#[test]
fn optimal_input_terminates_with_asymmetric_pools() {
    let cycle = pair_cycle();
    let mut worst: (u128, String) = (0, String::new());
    for r0a_log in [60_u32, 96, 128, 160] {
        for r1a_log in [60_u32, 96, 128, 160] {
            for r0b_log in [60_u32, 96, 128, 160] {
                for r1b_log in [60_u32, 96, 128, 160] {
                    let r0a = U256::from(1u64) << r0a_log;
                    let r1a = U256::from(1u64) << r1a_log;
                    let r0b = U256::from(1u64) << r0b_log;
                    let r1b = U256::from(1u64) << r1b_log;
                    let states = [state(r0a, r1a), state(r0b, r1b)];
                    let t = Instant::now();
                    let _ = optimal_input(&cycle, &states);
                    let elapsed = t.elapsed().as_micros();
                    if elapsed > worst.0 {
                        worst = (elapsed, format!("{r0a_log},{r1a_log},{r0b_log},{r1b_log}"));
                    }
                }
            }
        }
    }
    println!("worst asymmetric (micros): {:?} {}", worst.0, worst.1);
    assert!(
        worst.0 < 1_000_000,
        "one asymmetric pool case ran {}us — near-infinite search",
        worst.0
    );
}

#[test]
fn optimal_input_terminates_on_single_asymmetric_case() {
    let cycle = pair_cycle();
    let r0a = U256::from(1u64) << 160;
    let r1a = U256::from(1u64) << 60;
    let r0b = U256::from(1u64) << 96;
    let r1b = U256::from(1u64) << 128;
    let states = [state(r0a, r1a), state(r0b, r1b)];
    let t = Instant::now();
    let res = optimal_input(&cycle, &states);
    println!("single asymmetric: {:?} ok={}", t.elapsed(), res.is_ok());
}

#[test]
fn optimal_input_terminates_on_case_160_160_60_60() {
    let cycle = pair_cycle();
    let r0a = U256::from(1u64) << 160;
    let r1a = U256::from(1u64) << 160;
    let r0b = U256::from(1u64) << 60;
    let r1b = U256::from(1u64) << 60;
    let states = [state(r0a, r1a), state(r0b, r1b)];
    let t = Instant::now();
    let res = optimal_input(&cycle, &states);
    println!("case 160,160,60,60: {:?} ok={}", t.elapsed(), res.is_ok());
}

#[test]
fn optimal_input_terminates_on_case_60_60_60_96() {
    let cycle = pair_cycle();
    let r0a = U256::from(1u64) << 60;
    let r1a = U256::from(1u64) << 60;
    let r0b = U256::from(1u64) << 60;
    let r1b = U256::from(1u64) << 96;
    let states = [state(r0a, r1a), state(r0b, r1b)];
    let t = Instant::now();
    let res = optimal_input(&cycle, &states);
    println!("case 60,60,60,96: {:?} ok={}", t.elapsed(), res.is_ok());
}

#[test]
fn optimal_input_terminates_on_smaller_hang_cases() {
    let cycle = pair_cycle();
    for r1b_log in [70u32, 72, 76, 80, 88] {
        let states = [
            state(U256::from(1u64) << 60, U256::from(1u64) << 60),
            state(U256::from(1u64) << 60, U256::from(1u64) << r1b_log),
        ];
        let t = Instant::now();
        let _ = optimal_input(&cycle, &states);
        println!("r1b=2^{r1b_log}: {:?}", t.elapsed());
        assert!(t.elapsed().as_secs() < 15, "r1b=2^{r1b_log} is stuck");
    }
}

#[test]
fn optimal_input_rejects_discontinuous_route() {
    // Audit S7: a cycle whose legs come from two different token pairs is
    // structurally unpriceable, yet previously produced a quote silently.
    let anchor = Address::repeat_byte(1);
    let mid = Address::repeat_byte(2);
    let unrelated = Address::repeat_byte(3);
    let broken = Cycle {
        id: CycleId(0),
        anchor,
        hops: vec![
            CycleHop {
                pool_id: PoolId(0),
                token_in: anchor,
                token_out: mid,
                fee: FEE,
                zero_for_one: true,
            },
            CycleHop {
                pool_id: PoolId(1),
                token_in: unrelated,
                token_out: anchor,
                fee: FEE,
                zero_for_one: true,
            },
        ],
    };
    let states = [
        state(U256::from(1_000_000u64), U256::from(1_000_000u64)),
        state(U256::from(1_000_000u64), U256::from(1_000_000u64)),
    ];
    let error = optimal_input(&broken, &states).unwrap_err();
    assert!(
        matches!(error, v2_math::MathError::DiscontinuousRoute(1, _, _)),
        "expected DiscontinuousRoute at hop 1, got {error:?}"
    );

    // A route that starts off-anchor is equally invalid.
    let mut wrong_anchor = pair_cycle();
    wrong_anchor.anchor = unrelated;
    let error = optimal_input(&wrong_anchor, &states).unwrap_err();
    assert!(
        matches!(error, v2_math::MathError::DiscontinuousRoute(0, _, _)),
        "expected DiscontinuousRoute at hop 0, got {error:?}"
    );

    // The well-formed cycle still prices (equal reserves → no profit here,
    // but crucially no route error; profitability itself is covered by the
    // property tests).
    assert!(optimal_input(&pair_cycle(), &states).unwrap().is_none());
}
