//! Task 4.5 regression tests (audit findings C8/C9/C10/C12): reorg
//! handling that previously failed open or never converged.

use std::time::Duration;

use alloy_primitives::{B256, U256};
use domain::{PoolId, Readiness};
use state::{
    ApplyOutcome, CanonicalPosition, ReconciledState, RecoverySource, StateError, StateMachine,
    SyncLog,
};

const POOL: PoolId = PoolId(0);

fn sync(block: u64, tx: u64, log_idx: u64, r0: u64, r1: u64) -> SyncLog {
    SyncLog {
        pool_id: POOL,
        reserve0: U256::from(r0),
        reserve1: U256::from(r1),
        block_hash: B256::from([0xdd_u8; 32]),
        position: CanonicalPosition {
            block_number: block,
            transaction_index: tx,
            log_index: log_idx,
        },
        removed: false,
    }
}

fn removal(block: u64, tx: u64, log_idx: u64) -> SyncLog {
    SyncLog {
        removed: true,
        ..sync(block, tx, log_idx, 0, 0)
    }
}

fn ready_machine() -> StateMachine {
    let mut machine = StateMachine::new(1);
    machine
        .bootstrap(100, vec![(POOL, U256::from(1_000), U256::from(1_000))])
        .expect("bootstrap");
    machine
}

#[test]
fn multi_log_reorg_recovery_converges() {
    // Audit C8: with per-position interleaved replay, removing 102 after
    // truncating at 101 failed permanently ("RemovedLogMismatch") and
    // recovery never converged. Removals-first-descending fixes it.
    let mut machine = ready_machine();
    machine.apply(sync(101, 0, 0, 1_100, 900)).unwrap();
    machine.apply(sync(102, 0, 0, 1_200, 800)).unwrap();

    struct Source;
    impl RecoverySource for Source {
        fn logs(&self, _from: u64, _to: u64) -> Result<Vec<SyncLog>, StateError> {
            Ok(vec![
                removal(101, 0, 0),
                sync(101, 1, 0, 1_050, 950),
                removal(102, 0, 0),
                sync(102, 1, 0, 1_150, 850),
            ])
        }
        fn reserves(&self, _block: u64) -> Result<Vec<ReconciledState>, StateError> {
            Ok(vec![ReconciledState {
                pool_id: POOL,
                reserve0: U256::from(1_150u64),
                reserve1: U256::from(850u64),
            }])
        }
    }
    machine
        .recover(103, Duration::ZERO, &Source)
        .unwrap_or_else(|e| panic!("multi-log reorg recovery must converge, got {e:?}"));
    assert!(matches!(machine.readiness(), Readiness::Ready));
}

#[test]
fn missing_rollback_checkpoint_fails_closed() {
    // Audit C9: rolling back past retention previously left readiness
    // Ready while the rollback silently did not happen.
    let mut machine = ready_machine();
    machine.apply(sync(100, 0, 5, 1_100, 900)).unwrap();
    let result = machine.apply(removal(50, 0, 0));
    assert!(result.is_err(), "removal below retention must error");
    assert!(
        matches!(machine.readiness(), Readiness::Stale { .. }),
        "fail closed: readiness must be Stale, got {:?}",
        machine.readiness()
    );
}

#[test]
fn branch_flip_flop_second_removal_still_rolls_back() {
    // Audit C12: removed_seen blocked a second legitimate rollback of the
    // same (position, hash), letting orphaned state survive as canonical.
    let mut machine = ready_machine();
    machine.apply(sync(101, 0, 0, 1_100, 900)).unwrap();
    machine.apply(sync(102, 0, 0, 1_200, 800)).unwrap();
    let rem = removal(102, 0, 0);
    machine.apply(rem.clone()).unwrap();

    // Re-apply the same log on the restored branch, then remove again.
    machine.apply(sync(102, 0, 0, 1_200, 800)).unwrap();
    let outcome = machine.apply(rem);
    assert!(
        matches!(outcome, Ok(ApplyOutcome::RolledBack)),
        "second removal must roll back again, got {outcome:?}"
    );
}

#[test]
fn rollback_lowers_committed_block_so_recovery_refetches_the_gap() {
    // Audit C10a: committed_block previously never moved down on rollback,
    // leaving the stale window permanently unrequestable.
    let mut machine = ready_machine();
    machine.apply(sync(150, 0, 0, 1_100, 900)).unwrap();
    assert_eq!(machine.committed_block(), Some(150));

    machine.apply(sync(151, 0, 0, 1_200, 800)).unwrap();
    assert_eq!(machine.committed_block(), Some(151));
    machine.apply(removal(151, 0, 0)).unwrap();
    let committed = machine.committed_block();
    assert!(
        committed.map_or(false, |c| c <= 150),
        "committed must drop to the restored checkpoint, got {committed:?}"
    );
}
