use std::{cell::RefCell, time::Duration};

use alloy_primitives::{B256, U256};
use domain::{PoolId, Readiness};
use state::{
    ApplyOutcome, CanonicalPosition, ReconciledState, RecoverySource, StateError, StateMachine,
    SyncLog,
};

fn log(block: u64, transaction: u64, index: u64, reserve0: u64, reserve1: u64) -> SyncLog {
    SyncLog {
        pool_id: PoolId(0),
        reserve0: U256::from(reserve0),
        reserve1: U256::from(reserve1),
        block_hash: B256::from(U256::from(block)),
        position: CanonicalPosition {
            block_number: block,
            transaction_index: transaction,
            log_index: index,
        },
        removed: false,
    }
}

fn ready_machine(block: u64) -> StateMachine {
    let mut machine = StateMachine::new(1);
    machine
        .bootstrap(
            block,
            vec![(PoolId(0), U256::from(1_000), U256::from(1_000))],
        )
        .unwrap();
    machine
}

fn reserves(machine: &StateMachine) -> (U256, U256, u64) {
    let snapshot = machine.snapshot(&[PoolId(0)]).unwrap();
    let state = &snapshot.states[0].1;
    (state.reserve0, state.reserve1, state.version.0)
}

#[test]
fn buffers_subscription_logs_until_pinned_snapshot_commits() {
    let mut machine = StateMachine::new(1);
    assert_eq!(
        machine.apply(log(103, 0, 0, 1_300, 700)).unwrap(),
        ApplyOutcome::Buffered
    );
    assert_eq!(
        machine.apply(log(102, 0, 0, 1_200, 800)).unwrap(),
        ApplyOutcome::Buffered
    );
    assert!(machine.snapshot(&[PoolId(0)]).is_err());
    machine
        .bootstrap(100, vec![(PoolId(0), U256::from(1_000), U256::from(1_000))])
        .unwrap();
    assert_eq!(reserves(&machine), (U256::from(1_300), U256::from(700), 2));
    assert_eq!(machine.readiness(), &Readiness::Ready);
}

#[test]
fn applies_canonical_updates_and_handles_duplicate_old_and_conflict() {
    let mut machine = ready_machine(100);
    let first = log(101, 0, 1, 1_100, 900);
    assert_eq!(machine.apply(first.clone()).unwrap(), ApplyOutcome::Applied);
    assert_eq!(
        machine.apply(first.clone()).unwrap(),
        ApplyOutcome::Duplicate
    );
    assert_eq!(
        machine.apply(log(100, 9, 9, 999, 999)).unwrap(),
        ApplyOutcome::IgnoredOld
    );
    assert_eq!(reserves(&machine).2, 1);

    let mut conflict = first;
    conflict.reserve0 = U256::from(1_101);
    assert!(matches!(
        machine.apply(conflict),
        Err(StateError::Conflict { .. })
    ));
    assert!(matches!(machine.readiness(), Readiness::Stale { .. }));
}

#[test]
fn disconnect_fails_closed() {
    let mut machine = ready_machine(100);
    machine.disconnect("dirty close");
    assert!(machine.snapshot(&[PoolId(0)]).is_err());
    assert!(matches!(machine.readiness(), Readiness::Stale { .. }));
}

struct FixtureSource {
    logs: Vec<SyncLog>,
    reserves: Vec<ReconciledState>,
    ranges: RefCell<Vec<(u64, u64)>>,
}

struct FailingSource;

impl RecoverySource for FailingSource {
    fn logs(&self, _from: u64, _to: u64) -> Result<Vec<SyncLog>, StateError> {
        Err(StateError::RecoverySource(
            "offline fixture failure".to_owned(),
        ))
    }

    fn reserves(&self, _block: u64) -> Result<Vec<ReconciledState>, StateError> {
        unreachable!()
    }
}

impl RecoverySource for FixtureSource {
    fn logs(&self, from: u64, to: u64) -> Result<Vec<SyncLog>, StateError> {
        self.ranges.borrow_mut().push((from, to));
        Ok(self
            .logs
            .iter()
            .filter(|log| (from..=to).contains(&log.position.block_number))
            .cloned()
            .collect())
    }

    fn reserves(&self, _block: u64) -> Result<Vec<ReconciledState>, StateError> {
        Ok(self.reserves.clone())
    }
}

#[test]
fn recovery_uses_ten_block_chunks_and_requires_reconciliation() {
    let fixture: Vec<SyncLog> = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/events/recovery.json"
    ))
    .unwrap();
    let source = FixtureSource {
        logs: fixture,
        reserves: vec![ReconciledState {
            pool_id: PoolId(0),
            reserve0: U256::from(1_200),
            reserve1: U256::from(800),
        }],
        ranges: RefCell::default(),
    };
    let mut machine = ready_machine(100);
    machine.disconnect("test");
    machine
        .recover(111, Duration::from_secs(1), &source)
        .unwrap();
    // Audit C7: the backfill reaches one retention window (127 blocks)
    // below the committed head so reorgs at/below it are repairable.
    assert_eq!(
        *source.ranges.borrow(),
        vec![
            (0, 9),
            (10, 19),
            (20, 29),
            (30, 39),
            (40, 49),
            (50, 59),
            (60, 69),
            (70, 79),
            (80, 89),
            (90, 99),
            (100, 109),
            (110, 111)
        ]
    );
    assert_eq!(reserves(&machine).0, U256::from(1_200));
    assert_eq!(machine.readiness(), &Readiness::Ready);
}

#[test]
fn removed_log_rolls_back_then_replays_canonical_log() {
    let mut machine = ready_machine(100);
    machine.apply(log(101, 0, 0, 1_100, 900)).unwrap();
    let mut invalidated = log(102, 0, 0, 1_200, 800);
    invalidated.block_hash = B256::repeat_byte(2);
    machine.apply(invalidated).unwrap();
    machine.disconnect("reorg");
    let fixture: Vec<SyncLog> =
        serde_json::from_slice(include_bytes!("../../../tests/fixtures/events/reorg.json"))
            .unwrap();
    let source = FixtureSource {
        logs: fixture,
        reserves: vec![ReconciledState {
            pool_id: PoolId(0),
            reserve0: U256::from(1_150),
            reserve1: U256::from(850),
        }],
        ranges: RefCell::default(),
    };
    machine
        .recover(102, Duration::from_secs(1), &source)
        .unwrap();
    assert_eq!(reserves(&machine), (U256::from(1_150), U256::from(850), 4));
}

#[test]
fn rejects_removed_log_with_mismatched_block_hash() {
    let mut machine = ready_machine(100);
    machine.apply(log(101, 0, 0, 1_100, 900)).unwrap();
    let mut removed = log(101, 0, 0, 1_100, 900);
    removed.removed = true;
    removed.block_hash = B256::repeat_byte(99);
    assert!(matches!(
        machine.apply(removed),
        Err(StateError::RemovedLogMismatch { .. })
    ));
    assert!(matches!(machine.readiness(), Readiness::Stale { .. }));
}

#[test]
fn retains_at_least_128_blocks_of_checkpoints() {
    let mut machine = ready_machine(1);
    for block in 2..=200 {
        machine.apply(log(block, 0, 0, block, block)).unwrap();
    }
    let retained = machine.checkpoint_blocks(PoolId(0));
    assert!(retained.contains(&72));
    assert!(retained.contains(&73));
    assert!(retained.contains(&200));
    assert!(retained.len() >= 128);
}

#[test]
fn recovery_rejects_timeout_oversized_gap_and_bad_reconciliation() {
    let empty = FixtureSource {
        logs: Vec::new(),
        reserves: vec![ReconciledState {
            pool_id: PoolId(0),
            reserve0: U256::from(1_000),
            reserve1: U256::from(1_000),
        }],
        ranges: RefCell::default(),
    };
    let mut machine = ready_machine(100);
    machine.disconnect("test");
    assert!(matches!(
        machine.recover(101, Duration::from_secs(61), &empty),
        Err(StateError::RecoveryTimeout)
    ));

    let mut machine = ready_machine(100);
    machine.disconnect("test");
    assert!(matches!(
        machine.recover(1_101, Duration::from_secs(1), &empty),
        Err(StateError::RecoveryGap { .. })
    ));

    let bad = FixtureSource {
        logs: Vec::new(),
        reserves: vec![ReconciledState {
            pool_id: PoolId(0),
            reserve0: U256::from(999),
            reserve1: U256::from(999),
        }],
        ranges: RefCell::default(),
    };
    let mut machine = ready_machine(100);
    machine.disconnect("test");
    // Audit C11: the fetched reserves ARE the authority — a mismatch now
    // auto-rebootstraps from them instead of leaving no path back to Ready.
    machine
        .recover(100, Duration::from_secs(1), &bad)
        .expect("reconciliation mismatch heals via re-bootstrap");
    assert!(matches!(machine.readiness(), Readiness::Ready));
    assert_eq!(reserves(&machine).0, U256::from(999));

    let mut machine = ready_machine(100);
    machine.disconnect("test");
    assert!(matches!(
        machine.recover(101, Duration::from_secs(1), &FailingSource),
        Err(StateError::RecoverySource(_))
    ));
    assert!(matches!(machine.readiness(), Readiness::Stale { .. }));
}
