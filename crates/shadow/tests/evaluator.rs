use std::collections::HashSet;

use alloy_primitives::{Address, B256, U256};
use catalog::{CompiledGraph, CycleLimits, VerifiedPool, compile_cycles};
use domain::{CycleId, Fee, Pool, PoolId, PoolState, Profile, StateVersion};
use shadow::{ClassificationReason, CostSnapshot, DirtyEvaluator, Economics, FIXED_POINT_SCALE};
use state::{CanonicalPosition, StateMachine, SyncLog};
use storage::Storage;
use tempfile::TempDir;
use v2_math::OptimalQuote;

const LIMITS: CycleLimits = CycleLimits {
    max_cycles: 1_000,
    max_cycles_per_pool: 1_000,
};
const FEE: Fee = Fee {
    numerator: 997,
    denominator: 1_000,
};
const WEI: u128 = FIXED_POINT_SCALE;

fn token(value: u8) -> Address {
    Address::repeat_byte(value)
}

fn pool(
    id: u32,
    address: u8,
    token0: u8,
    token1: u8,
    reserve0: u128,
    reserve1: u128,
) -> VerifiedPool {
    VerifiedPool {
        pool: Pool {
            id: PoolId(id),
            address: Address::repeat_byte(address),
            token0: token(token0),
            token1: token(token1),
            fee: FEE,
            profile: Profile::ConstantProduct,
        },
        token0_decimals: 18,
        token1_decimals: 18,
        initial_state: PoolState {
            reserve0: U256::from(reserve0),
            reserve1: U256::from(reserve1),
            block_number: 1,
            transaction_index: 0,
            log_index: 0,
            version: StateVersion(0),
        },
        source: "fixture".to_owned(),
    }
}

fn fixture_graph() -> CompiledGraph {
    let pools = [
        pool(0, 10, 1, 2, WEI, WEI),
        pool(1, 11, 1, 2, 3 * WEI, 3 * WEI / 10),
        pool(2, 12, 1, 4, WEI, WEI),
        pool(3, 13, 1, 4, 3 * WEI, 3 * WEI / 10),
    ];
    let anchors: HashSet<Address> = [token(1)].into_iter().collect();
    compile_cycles(&pools, &anchors, LIMITS).unwrap()
}

fn ready_machine(pool_count: usize, reserves: &[(u128, u128)]) -> StateMachine {
    let mut machine = StateMachine::new(pool_count);
    let states: Vec<_> = reserves
        .iter()
        .enumerate()
        .map(|(index, &(reserve0, reserve1))| {
            (
                PoolId(u32::try_from(index).unwrap()),
                U256::from(reserve0),
                U256::from(reserve1),
            )
        })
        .collect();
    machine.bootstrap(1, states).unwrap();
    machine
}

fn usd(amount: u128) -> U256 {
    U256::from(amount) * U256::from(WEI)
}

fn tokens(amount: u128) -> U256 {
    U256::from(amount) * U256::from(WEI)
}

fn interesting_economics() -> Economics {
    Economics {
        flash_fee_rate: U256::ZERO,
        gas_cost_usd: usd(1),
        expected_win_rate: U256::from(WEI),
        native_token_usd: U256::from(shadow::FIXED_POINT_SCALE),
        da_fee_usd: U256::ZERO,
    }
}

fn valid_reference() -> CostSnapshot {
    CostSnapshot {
        usd_per_token: U256::from(WEI),
        gas_price_age_valid: true,
        reference_price_valid: true,

        gas_price_wei: U256::from(1),
    }
}

fn fixture_reserves() -> [(u128, u128); 4] {
    [
        (WEI, WEI),
        (3 * WEI, 3 * WEI / 10),
        (WEI, WEI),
        (3 * WEI, 3 * WEI / 10),
    ]
}

fn build_evaluator(graph: CompiledGraph, queue_capacity: usize) -> (TempDir, DirtyEvaluator) {
    let machine = ready_machine(graph.by_pool.len(), &fixture_reserves());
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::open(&directory.path().join("shadow.sqlite")).unwrap();
    let mut evaluator = DirtyEvaluator::new(
        graph,
        machine,
        interesting_economics(),
        queue_capacity,
        storage,
    );
    evaluator.set_reference(valid_reference());
    (directory, evaluator)
}

fn cycle_ids(graph: &CompiledGraph, pool_index: usize) -> HashSet<CycleId> {
    graph.by_pool[pool_index].iter().copied().collect()
}

#[test]
fn evaluates_only_cycles_indexed_by_the_marked_pool() {
    let graph = fixture_graph();
    let (_directory, mut evaluator) = build_evaluator(graph.clone(), 100);

    evaluator.mark_pool(PoolId(0));
    let outcome = evaluator.run_once(1_000);

    let expected = cycle_ids(&graph, 0);
    let evaluated: HashSet<CycleId> = outcome.evaluated.iter().copied().collect();
    assert_eq!(evaluated, expected);
    assert_eq!(evaluated.len(), 2);

    let other: HashSet<CycleId> = cycle_ids(&graph, 2);
    assert!(evaluated.is_disjoint(&other));

    let recorded: HashSet<CycleId> = outcome.recorded.iter().copied().collect();
    assert!(recorded.iter().all(|id| expected.contains(id)));
    assert!(!recorded.is_empty());
}

#[test]
fn coalesces_duplicate_dirty_ids_before_evaluation() {
    let graph = fixture_graph();
    let (_directory, mut evaluator) = build_evaluator(graph.clone(), 100);

    evaluator.mark_pool(PoolId(0));
    evaluator.mark_pool(PoolId(1));
    let outcome = evaluator.run_once(1_000);

    assert_eq!(outcome.evaluated.len(), 2);
    assert_eq!(
        outcome.evaluated.iter().copied().collect::<HashSet<_>>(),
        cycle_ids(&graph, 0)
    );
}

#[test]
fn overload_degrades_without_dropping_queued_cycles() {
    let graph = fixture_graph();
    let (_directory, mut evaluator) = build_evaluator(graph.clone(), 1);

    evaluator.mark_pool(PoolId(0));
    evaluator.mark_pool(PoolId(2));
    assert!(evaluator.queue_len() > 1);

    let outcome = evaluator.run_once(1_000);
    assert!(outcome.degraded);
    assert_eq!(outcome.evaluated.len(), 4);
    assert_eq!(
        outcome.evaluated.iter().copied().collect::<HashSet<_>>(),
        cycle_ids(&graph, 0)
            .union(&cycle_ids(&graph, 2))
            .copied()
            .collect()
    );
}

#[test]
fn stale_state_suppresses_all_scoring() {
    let graph = fixture_graph();
    let (_directory, mut evaluator) = build_evaluator(graph.clone(), 100);

    evaluator.disconnect("fixture disconnect");
    evaluator.mark_pool(PoolId(0));
    let outcome = evaluator.run_once(1_000);

    assert_eq!(outcome.skipped_stale, 2);
    assert!(outcome.evaluated.is_empty());
    assert!(outcome.recorded.is_empty());
    assert!(outcome.interesting.is_empty());
}

#[test]
fn stale_gas_or_reference_prices_prevent_classification() {
    let graph = fixture_graph();
    let (_directory, mut evaluator) = build_evaluator(graph.clone(), 100);

    evaluator.set_reference(CostSnapshot {
        usd_per_token: U256::from(WEI),
        gas_price_age_valid: false,
        reference_price_valid: true,

        gas_price_wei: U256::from(1),
    });
    evaluator.mark_pool(PoolId(0));
    let outcome = evaluator.run_once(1_000);

    assert!(outcome.recorded.is_empty());
    assert!(outcome.interesting.is_empty());
    assert_eq!(outcome.not_evaluated.len(), 1);

    let (_directory, mut evaluator) = build_evaluator(graph, 100);
    evaluator.set_reference(CostSnapshot {
        usd_per_token: U256::from(WEI),
        gas_price_age_valid: true,
        reference_price_valid: false,

        gas_price_wei: U256::from(1),
    });
    evaluator.mark_pool(PoolId(0));
    let outcome = evaluator.run_once(1_000);

    assert!(outcome.recorded.is_empty());
    assert_eq!(outcome.not_evaluated.len(), 1);
}

#[test]
fn version_change_discards_and_requeues_an_in_flight_result() {
    let graph = fixture_graph();
    let (_directory, mut evaluator) = build_evaluator(graph.clone(), 100);

    evaluator.mark_pool(PoolId(0));
    let first = evaluator.run_once(1_000);
    assert!(!first.recorded.is_empty());

    let cycle = &graph.cycles[graph.by_pool[0][0].0 as usize];
    let used_versions = evaluator
        .state_snapshot(&cycle.hops.iter().map(|hop| hop.pool_id).collect::<Vec<_>>())
        .unwrap()
        .states
        .iter()
        .map(|(pool_id, state)| (*pool_id, state.version))
        .collect::<Vec<_>>();

    assert!(!evaluator.retract_on_version_change(cycle, &used_versions));
    assert_eq!(evaluator.queue_len(), 0);

    evaluator
        .apply_log(SyncLog {
            pool_id: PoolId(1),
            reserve0: U256::from(3 * WEI + 1),
            reserve1: U256::from(3 * WEI / 10 - 1),
            block_hash: B256::from(U256::from(2)),
            position: CanonicalPosition {
                block_number: 2,
                transaction_index: 0,
                log_index: 0,
            },
            removed: false,
        })
        .unwrap();

    assert!(evaluator.retract_on_version_change(cycle, &used_versions));
    assert!(evaluator.queue_len() > 0);

    let second = evaluator.run_once(2_000);
    assert!(second.evaluated.contains(&cycle.id));
}

#[test]
fn gate_uses_gas_cost_divided_by_expected_win_rate() {
    let economics = Economics {
        flash_fee_rate: U256::ZERO,
        gas_cost_usd: usd(30),
        expected_win_rate: U256::from(10 * WEI / 100),
        native_token_usd: U256::from(shadow::FIXED_POINT_SCALE),
        da_fee_usd: U256::ZERO,
    };
    let reference = valid_reference();

    let quote = OptimalQuoteFixture {
        input: tokens(400),
        output: tokens(800),
        profit: tokens(100),
    };
    let classification = economics.classify(&quote.into(), &reference);
    assert_eq!(classification.threshold_usd, usd(300));
    assert_eq!(classification.gross_profit_usd, usd(100));
    assert_eq!(classification.flash_cost_usd, U256::ZERO);
    assert_eq!(classification.gas_cost_usd, usd(30));
    assert_eq!(classification.estimated_net_profit_usd, usd(70));
    assert_eq!(classification.reason, ClassificationReason::BelowThreshold);

    let quote = OptimalQuoteFixture {
        input: tokens(400),
        output: tokens(800),
        profit: tokens(400),
    };
    let classification = economics.classify(&quote.into(), &reference);
    assert_eq!(classification.reason, ClassificationReason::AboveThreshold);

    let quote = OptimalQuoteFixture {
        input: tokens(400),
        output: tokens(730),
        profit: tokens(330),
    };
    let classification = economics.classify(&quote.into(), &reference);
    assert_eq!(classification.reason, ClassificationReason::BelowThreshold);
}

#[test]
fn classification_fails_closed_on_stale_or_invalid_inputs() {
    let economics = Economics {
        flash_fee_rate: U256::ZERO,
        gas_cost_usd: usd(30),
        expected_win_rate: U256::from(10 * WEI / 100),
        native_token_usd: U256::from(shadow::FIXED_POINT_SCALE),
        da_fee_usd: U256::ZERO,
    };
    let quote = OptimalQuoteFixture {
        input: tokens(400),
        output: tokens(800),
        profit: tokens(400),
    }
    .into();

    let stale_gas = CostSnapshot {
        gas_price_age_valid: false,
        ..valid_reference()
    };
    assert!(matches!(
        economics.classify(&quote, &stale_gas).reason,
        ClassificationReason::NotEvaluated { detail } if detail.contains("gas")
    ));

    let stale_reference = CostSnapshot {
        reference_price_valid: false,

        gas_price_wei: U256::from(1),
        ..valid_reference()
    };
    assert!(matches!(
        economics.classify(&quote, &stale_reference).reason,
        ClassificationReason::NotEvaluated { detail } if detail.contains("reference")
    ));

    let zero_price = CostSnapshot {
        usd_per_token: U256::ZERO,
        ..valid_reference()
    };
    assert!(matches!(
        economics.classify(&quote, &zero_price).reason,
        ClassificationReason::NotEvaluated { detail } if detail.contains("reference price is zero")
    ));

    let zero_win_rate = Economics {
        expected_win_rate: U256::ZERO,
        native_token_usd: U256::from(shadow::FIXED_POINT_SCALE),
        da_fee_usd: U256::ZERO,
        ..economics
    };
    assert!(matches!(
        zero_win_rate.classify(&quote, &valid_reference()).reason,
        ClassificationReason::NotEvaluated { detail } if detail.contains("win rate")
    ));

    let overflow_flash = Economics {
        flash_fee_rate: U256::MAX,
        ..economics
    };
    assert!(matches!(
        overflow_flash.classify(&quote, &valid_reference()).reason,
        ClassificationReason::NotEvaluated { detail } if detail.contains("overflow")
    ));
}

struct OptimalQuoteFixture {
    input: U256,
    output: U256,
    profit: U256,
}

impl From<OptimalQuoteFixture> for v2_math::OptimalQuote {
    fn from(fixture: OptimalQuoteFixture) -> Self {
        Self {
            input: fixture.input,
            output: fixture.output,
            profit: fixture.profit,
        }
    }
}

#[test]
fn classify_route_derives_gas_from_live_price_and_shape() {
    // Audit S4: the cost side comes from units x live gas price x native USD,
    // not a scalar. 300k pair-units at 1e30 wei and $1 native = $0.03.
    let economics = Economics {
        flash_fee_rate: U256::ZERO,
        gas_cost_usd: U256::ZERO,
        expected_win_rate: U256::from(150_000_000_000_000_000u128), // 15%
        native_token_usd: U256::from(WEI),
        da_fee_usd: U256::ZERO,
    };
    let snapshot = CostSnapshot {
        usd_per_token: U256::from(WEI),
        gas_price_age_valid: true,
        reference_price_valid: true,
        gas_price_wei: U256::from(100_000_000_000_u128),
    };
    let quote = OptimalQuote {
        input: U256::from(WEI / 10), // 0.1 tokens borrowed (flash fee zero)
        output: U256::from(WEI),     // 1.0 back -> gross $1
        profit: U256::from(WEI - WEI / 10),
    };
    let class = economics.classify_route(&quote, &snapshot, shadow::PAIR_EXECUTION_GAS_UNITS, None);
    assert_eq!(class.gas_cost_usd, U256::from(30_000_000_000_000_000u128)); // $0.03 exactly
    // Threshold = gas / win rate = $0.03/0.15 = $0.20.
    assert_eq!(class.threshold_usd, U256::from(200_000_000_000_000_000u128)); // $0.20
    assert_eq!(class.reason, ClassificationReason::AboveThreshold);
    assert_eq!(class.shortfall_usd, U256::ZERO);

    // A triangle pays more gas than a pair — never priced as one.
    let tri = economics.classify_route(
        &quote,
        &snapshot,
        shadow::TRIANGLE_EXECUTION_GAS_UNITS,
        None,
    );
    assert!(
        tri.gas_cost_usd > class.gas_cost_usd,
        "triangle gas {} must exceed pair gas {}",
        tri.gas_cost_usd,
        class.gas_cost_usd
    );
}

#[test]
fn classify_route_fails_closed_on_stale_or_missing_gas_inputs() {
    let economics = Economics {
        flash_fee_rate: U256::ZERO,
        gas_cost_usd: U256::ZERO,
        expected_win_rate: U256::from(WEI),
        native_token_usd: U256::from(WEI),
        da_fee_usd: U256::ZERO,
    };
    let quote = OptimalQuote {
        input: U256::from(WEI),
        output: U256::from(2 * WEI),
        profit: U256::from(WEI),
    };
    let stale = CostSnapshot {
        usd_per_token: U256::from(WEI),
        gas_price_age_valid: false,
        reference_price_valid: true,
        gas_price_wei: U256::from(1),
    };
    assert!(matches!(
        economics
            .classify_route(&quote, &stale, 300_000, None)
            .reason,
        ClassificationReason::NotEvaluated { .. }
    ));
    let unset = CostSnapshot {
        usd_per_token: U256::from(WEI),
        gas_price_age_valid: true,
        reference_price_valid: true,
        gas_price_wei: U256::ZERO,
    };
    assert!(matches!(
        economics
            .classify_route(&quote, &unset, 300_000, None)
            .reason,
        ClassificationReason::NotEvaluated { .. }
    ));
}

#[test]
fn classify_route_charges_the_da_fee_and_reports_shortfall() {
    // The data-availability term is wired end-to-end (audit S4/Part VI):
    // currently zero by decision, but a verified value drops in without
    // restructuring. Shortfall measures how far below the floor a near-miss
    // fell (audit E4).
    let economics = Economics {
        flash_fee_rate: U256::ZERO,
        gas_cost_usd: U256::ZERO,
        expected_win_rate: U256::from(WEI), // 100% -> threshold == total cost
        native_token_usd: U256::from(WEI),
        da_fee_usd: usd(2),
    };
    let snapshot = CostSnapshot {
        usd_per_token: U256::from(WEI),
        gas_price_age_valid: true,
        reference_price_valid: true,
        // Pair gas becomes exactly $0.10: 300k x 3.33e11 wei = 1e17 ETH-wei.
        gas_price_wei: U256::from(333_333_333_333_u128),
    };
    // Gross $0.10 against $0.10 gas + $2 DA -> unprofitable by the DA term.
    let quote = OptimalQuote {
        input: U256::ZERO,
        output: U256::from(WEI / 10),
        profit: U256::from(WEI / 10),
    };
    let class = economics.classify_route(&quote, &snapshot, shadow::PAIR_EXECUTION_GAS_UNITS, None);
    let total_cost = class.gas_cost_usd + economics.da_fee_usd;
    assert!(total_cost > quote.profit, "DA term must push it under");
    assert_eq!(class.reason, ClassificationReason::NotProfitable);
    // Shortfall = total cost - gross (audit E4).
    assert_eq!(class.shortfall_usd, total_cost - U256::from(WEI / 10));
}
