use std::{
    collections::{BTreeMap, HashSet},
    time::Duration,
};

use alloy_primitives::{B256, U256};
use domain::{PoolId, PoolState, Readiness, StateVersion};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::RecoverySource;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CanonicalPosition {
    pub block_number: u64,
    pub transaction_index: u64,
    pub log_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncLog {
    pub pool_id: PoolId,
    pub reserve0: U256,
    pub reserve1: U256,
    pub block_hash: B256,
    pub position: CanonicalPosition,
    pub removed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    Buffered,
    Applied,
    Duplicate,
    IgnoredOld,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSnapshot {
    pub states: Vec<(PoolId, PoolState)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("pool state is not ready: {reason}")]
pub struct NotReady {
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StateError {
    #[error("pool ID {0:?} is out of range")]
    UnknownPool(PoolId),
    #[error("bootstrap is missing pool {0:?}")]
    MissingBootstrapPool(PoolId),
    #[error("duplicate bootstrap state for pool {0:?}")]
    DuplicateBootstrapPool(PoolId),
    #[error("conflicting log for pool {pool_id:?} at {position:?}")]
    Conflict {
        pool_id: PoolId,
        position: CanonicalPosition,
    },
    #[error("removed log for pool {pool_id:?} has no earlier checkpoint")]
    MissingRollbackCheckpoint {
        pool_id: PoolId,
        position: CanonicalPosition,
    },
    #[error("removed log for pool {pool_id:?} does not match its checkpoint")]
    RemovedLogMismatch {
        pool_id: PoolId,
        position: CanonicalPosition,
    },
    #[error("state version overflow")]
    VersionOverflow,
    #[error("recovery exceeded 60 seconds")]
    RecoveryTimeout,
    #[error("recovery gap {gap} blocks exceeds limit 1,000")]
    RecoveryGap { gap: u64 },
    #[error("recovery head {head} is older than committed block {committed}")]
    RecoveryHeadBehind { committed: u64, head: u64 },
    #[error("reconciliation mismatch for pool {0:?}")]
    ReconciliationMismatch(PoolId),
    #[error("reconciliation is missing pool {0:?}")]
    MissingReconciliationPool(PoolId),
    #[error("recovery source failed: {0}")]
    RecoverySource(String),
}

#[derive(Debug, Clone)]
struct Checkpoint {
    position: CanonicalPosition,
    block_hash: B256,
    state: PoolState,
}

#[derive(Debug, Clone)]
pub struct PoolStateStore {
    states: Vec<Option<PoolState>>,
    checkpoints: Vec<Vec<Checkpoint>>,
}

impl PoolStateStore {
    fn new(pool_count: usize) -> Self {
        Self {
            states: vec![None; pool_count],
            checkpoints: vec![Vec::new(); pool_count],
        }
    }
}

pub struct StateMachine {
    store: PoolStateStore,
    readiness: Readiness,
    buffered: Vec<SyncLog>,
    committed_block: Option<u64>,
    next_version: u64,
    removed_seen: HashSet<(PoolId, CanonicalPosition, B256)>,
}

impl StateMachine {
    #[must_use]
    pub fn new(pool_count: usize) -> Self {
        Self {
            store: PoolStateStore::new(pool_count),
            readiness: Readiness::Bootstrapping,
            buffered: Vec::new(),
            committed_block: None,
            next_version: 0,
            removed_seen: HashSet::new(),
        }
    }

    /// Applies one ordered Sync log or buffers it during bootstrap.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown pools, conflicting positions, unavailable
    /// rollback checkpoints, or state-version overflow. Conflicts fail closed.
    pub fn apply(&mut self, log: SyncLog) -> Result<ApplyOutcome, StateError> {
        self.pool_index(log.pool_id)?;
        if matches!(self.readiness, Readiness::Bootstrapping) {
            self.buffered.push(log);
            return Ok(ApplyOutcome::Buffered);
        }
        self.apply_ordered(&log)
    }

    /// Commits a complete pinned snapshot and replays buffered newer logs.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, duplicate, or unknown pool states, or when
    /// replaying a buffered log fails.
    pub fn bootstrap(
        &mut self,
        pinned_block: u64,
        states: Vec<(PoolId, U256, U256)>,
    ) -> Result<(), StateError> {
        let mut supplied = vec![false; self.store.states.len()];
        for (pool_id, reserve0, reserve1) in states {
            let index = self.pool_index(pool_id)?;
            if supplied[index] {
                return Err(StateError::DuplicateBootstrapPool(pool_id));
            }
            supplied[index] = true;
            let position = CanonicalPosition {
                block_number: pinned_block,
                transaction_index: 0,
                log_index: 0,
            };
            let state = PoolState {
                reserve0,
                reserve1,
                block_number: pinned_block,
                transaction_index: 0,
                log_index: 0,
                version: StateVersion(0),
            };
            self.store.states[index] = Some(state.clone());
            self.store.checkpoints[index] = vec![Checkpoint {
                position,
                block_hash: B256::ZERO,
                state,
            }];
        }
        if let Some(index) = supplied.iter().position(|present| !present) {
            let pool_id = u32::try_from(index)
                .map(PoolId)
                .map_err(|_| StateError::VersionOverflow)?;
            return Err(StateError::MissingBootstrapPool(pool_id));
        }
        self.committed_block = Some(pinned_block);
        self.readiness = Readiness::Ready;
        self.buffered.sort_by_key(|log| log.position);
        let buffered = std::mem::take(&mut self.buffered);
        for log in buffered {
            self.apply_ordered(&log)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn readiness(&self) -> &Readiness {
        &self.readiness
    }

    /// Captures selected pool states only while globally ready.
    ///
    /// # Errors
    ///
    /// Returns [`NotReady`] while bootstrapping or stale, or for an unknown pool.
    pub fn snapshot(&self, pool_ids: &[PoolId]) -> Result<StateSnapshot, NotReady> {
        if !matches!(self.readiness, Readiness::Ready) {
            return Err(NotReady {
                reason: readiness_reason(&self.readiness),
            });
        }
        let mut states = Vec::with_capacity(pool_ids.len());
        for &pool_id in pool_ids {
            let index = usize::try_from(pool_id.0).map_err(|_| NotReady {
                reason: format!("unknown pool {pool_id:?}"),
            })?;
            let state = self
                .store
                .states
                .get(index)
                .and_then(Option::as_ref)
                .ok_or_else(|| NotReady {
                    reason: format!("unknown pool {pool_id:?}"),
                })?;
            states.push((pool_id, state.clone()));
        }
        Ok(StateSnapshot { states })
    }

    pub fn disconnect(&mut self, reason: &str) {
        self.mark_stale(reason);
    }

    /// Recovers canonical logs in ten-block chunks and reconciles at the head.
    ///
    /// # Errors
    ///
    /// Returns an error on timeout, oversized or backward gaps, source failure,
    /// invalid log application, or incomplete reserve reconciliation.
    pub fn recover<R: RecoverySource>(
        &mut self,
        head: u64,
        elapsed: Duration,
        source: &R,
    ) -> Result<(), StateError> {
        self.mark_stale("recovery in progress");
        if elapsed > Duration::from_mins(1) {
            self.mark_stale("recovery timeout");
            return Err(StateError::RecoveryTimeout);
        }
        let committed = self.committed_block.unwrap_or(head);
        if head < committed {
            self.mark_stale("recovery head behind checkpoint");
            return Err(StateError::RecoveryHeadBehind { committed, head });
        }
        let gap = head - committed;
        if gap > 1_000 {
            self.mark_stale("recovery gap exceeds limit");
            return Err(StateError::RecoveryGap { gap });
        }

        // Audit C7: reorgs by definition invalidate blocks AT or BELOW the
        // committed head; starting the fetch at `committed` made them
        // permanently unrepairable. Reach one retention window down —
        // replaying already-known logs is harmless (Duplicate/IgnoredOld),
        // and removals-first ordering (C8) handles the branch switch.
        let backfill_from = committed.saturating_sub(RECOVERY_LOOKBACK_BLOCKS);
        let mut logs = Vec::new();
        let mut start = backfill_from;
        loop {
            let end = start.saturating_add(9).min(head);
            logs.extend(source.logs(start, end)?);
            if end == head {
                break;
            }
            start = end + 1;
        }
        // Audit C8: per-position interleaving breaks multi-log reorgs -
        // truncating at block N drops checkpoints above it, so a later
        // removal at N+1 fails permanently and recovery never converges.
        // Apply ALL removals in descending position order first (rolling
        // back to the common ancestor), then all additions ascending.
        let mut removals: Vec<_> = logs.iter().filter(|log| log.removed).collect();
        removals.sort_by_key(|log| std::cmp::Reverse(log.position));
        let mut additions: Vec<_> = logs.iter().filter(|log| !log.removed).collect();
        additions.sort_by_key(|log| log.position);
        for log in removals.iter().chain(additions.iter()) {
            self.apply_ordered(log)?;
        }

        let reconciled: BTreeMap<_, _> = source
            .reserves(head)?
            .into_iter()
            .map(|state| (state.pool_id, (state.reserve0, state.reserve1)))
            .collect();
        for (pool_id_value, index) in (0_u32..).zip(0..self.store.states.len()) {
            let pool_id = PoolId(pool_id_value);
            let expected = reconciled
                .get(&pool_id)
                .ok_or(StateError::MissingReconciliationPool(pool_id))?;
            let actual = self.store.states[index]
                .as_ref()
                .ok_or(StateError::UnknownPool(pool_id))?;
            if (actual.reserve0, actual.reserve1) != *expected {
                // Audit C11: the pinned-head reserves ARE the authority.
                // Previously they were discarded and the mismatch returned,
                // leaving no path back to Ready. Re-bootstrap from the
                // fetched truth: checkpoints collapse to one synthetic at
                // `head`, stale-branch history is dropped wholesale, and the
                // removed-seen set clears with it.
                let states: Vec<(PoolId, U256, U256)> = reconciled
                    .iter()
                    .map(|(pool_id, (r0, r1))| (*pool_id, *r0, *r1))
                    .collect();
                self.removed_seen.clear();
                self.buffered.clear();
                self.bootstrap(head, states)?;
                return Ok(());
            }
        }
        self.committed_block = Some(head);
        self.readiness = Readiness::Ready;
        Ok(())
    }

    /// Highest block such that every block at or below it is committed
    /// (audit task 4.5 observability).
    #[must_use]
    pub fn committed_block(&self) -> Option<u64> {
        self.committed_block
    }

    #[must_use]
    pub fn checkpoint_blocks(&self, pool_id: PoolId) -> Vec<u64> {
        usize::try_from(pool_id.0)
            .ok()
            .and_then(|index| self.store.checkpoints.get(index))
            .map(|checkpoints| {
                checkpoints
                    .iter()
                    .map(|checkpoint| checkpoint.position.block_number)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// How far below the committed head a recovery backfill reaches (audit
/// C7): reorgs invalidate blocks at or below the head, so repair requires
/// re-fetching history the old logic never requested. Matches the
/// checkpoint retention depth.
pub const RECOVERY_LOOKBACK_BLOCKS: u64 = 127;

impl StateMachine {
    fn apply_ordered(&mut self, log: &SyncLog) -> Result<ApplyOutcome, StateError> {
        let index = self.pool_index(log.pool_id)?;
        if log.removed {
            return self.rollback(log);
        }
        let checkpoints = &self.store.checkpoints[index];
        if let Some(existing) = checkpoints
            .iter()
            .find(|checkpoint| checkpoint.position == log.position)
        {
            if existing.block_hash == log.block_hash
                && existing.state.reserve0 == log.reserve0
                && existing.state.reserve1 == log.reserve1
            {
                return Ok(ApplyOutcome::Duplicate);
            }
            self.mark_stale("conflicting log at canonical position");
            return Err(StateError::Conflict {
                pool_id: log.pool_id,
                position: log.position,
            });
        }
        if checkpoints
            .last()
            .is_some_and(|checkpoint| log.position < checkpoint.position)
        {
            return Ok(ApplyOutcome::IgnoredOld);
        }
        self.next_version = self
            .next_version
            .checked_add(1)
            .ok_or(StateError::VersionOverflow)?;
        let state = PoolState {
            reserve0: log.reserve0,
            reserve1: log.reserve1,
            block_number: log.position.block_number,
            transaction_index: log.position.transaction_index,
            log_index: log.position.log_index,
            version: StateVersion(self.next_version),
        };
        // Audit C12: forget the prior removal of this exact log - otherwise
        // a branch flip-flop (remove, re-apply, remove again) silently
        // no-ops the second rollback and orphaned state survives as
        // canonical with readiness Ready.
        self.removed_seen
            .remove(&(log.pool_id, log.position, log.block_hash));
        self.store.states[index] = Some(state.clone());
        self.store.checkpoints[index].push(Checkpoint {
            position: log.position,
            block_hash: log.block_hash,
            state,
        });
        // Audit C10: while Stale, applying must not advance the committed
        // head - recover() starts from committed_block, so advancing past a
        // stale window makes the gap unrequestable forever.
        if matches!(self.readiness, Readiness::Ready) {
            self.committed_block = Some(
                self.committed_block
                    .unwrap_or_default()
                    .max(log.position.block_number),
            );
        }
        self.prune(index);
        Ok(ApplyOutcome::Applied)
    }

    fn rollback(&mut self, log: &SyncLog) -> Result<ApplyOutcome, StateError> {
        let removed_key = (log.pool_id, log.position, log.block_hash);
        if self.removed_seen.contains(&removed_key) {
            return Ok(ApplyOutcome::Duplicate);
        }
        let index = self.pool_index(log.pool_id)?;
        if !self.store.checkpoints[index].iter().any(|checkpoint| {
            checkpoint.position == log.position && checkpoint.block_hash == log.block_hash
        }) {
            self.mark_stale("removed log does not match checkpoint");
            return Err(StateError::RemovedLogMismatch {
                pool_id: log.pool_id,
                position: log.position,
            });
        }
        let rollback = self.store.checkpoints[index]
            .iter()
            .rposition(|checkpoint| checkpoint.position < log.position)
            .ok_or_else(|| {
                // Audit C9: this path previously failed open - readiness
                // stayed Ready while the rollback silently did not happen,
                // so callers kept pricing against orphaned reserves.
                self.mark_stale("rollback checkpoint outside retention");
                StateError::MissingRollbackCheckpoint {
                    pool_id: log.pool_id,
                    position: log.position,
                }
            })?;
        let restored = self.store.checkpoints[index][rollback].state.clone();
        self.store.checkpoints[index].truncate(rollback + 1);
        self.next_version = self
            .next_version
            .checked_add(1)
            .ok_or(StateError::VersionOverflow)?;
        self.store.states[index] = Some(PoolState {
            version: StateVersion(self.next_version),
            ..restored
        });
        self.removed_seen.insert(removed_key);
        // Audit C10: the rolled-back window is precisely what a recovery
        // must re-fetch; leaving committed_block above it made the gap
        // permanently unrequestable.
        self.committed_block = Some(
            self.committed_block
                .map_or(restored.block_number, |committed| {
                    committed.min(restored.block_number)
                }),
        );
        Ok(ApplyOutcome::RolledBack)
    }

    fn prune(&mut self, index: usize) {
        let latest = self.store.checkpoints[index]
            .last()
            .map_or(0, |checkpoint| checkpoint.position.block_number);
        let earliest = latest.saturating_sub(127);
        let first_retained = self.store.checkpoints[index]
            .iter()
            .position(|checkpoint| checkpoint.position.block_number >= earliest)
            .unwrap_or(0);
        let first_retained = first_retained.saturating_sub(1);
        if first_retained > 0 {
            self.store.checkpoints[index].drain(..first_retained);
        }
    }

    fn pool_index(&self, pool_id: PoolId) -> Result<usize, StateError> {
        let index = usize::try_from(pool_id.0).map_err(|_| StateError::UnknownPool(pool_id))?;
        if index >= self.store.states.len() {
            return Err(StateError::UnknownPool(pool_id));
        }
        Ok(index)
    }

    fn mark_stale(&mut self, reason: &str) {
        self.readiness = Readiness::Stale {
            reason: reason.to_owned(),
        };
    }
}

fn readiness_reason(readiness: &Readiness) -> String {
    match readiness {
        Readiness::Bootstrapping => "bootstrapping".to_owned(),
        Readiness::Ready => "ready".to_owned(),
        Readiness::Stale { reason } => reason.clone(),
    }
}
