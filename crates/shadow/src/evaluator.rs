use catalog::CompiledGraph;
use domain::{Cycle, CycleId, PoolId, PoolState, StateVersion};
use state::{ApplyOutcome, NotReady, StateError, StateMachine, StateSnapshot, SyncLog};
use storage::{ObservationRecord, RouteStateRecord, Storage};
use v2_math::{OptimalQuote, optimal_input};

use crate::queue::DirtyQueue;
use crate::{Classification, ClassificationReason, CostSnapshot, Economics};

/// One drained evaluation batch.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RunOutcome {
    /// Cycle IDs that entered evaluation, in queue order.
    pub evaluated: Vec<CycleId>,
    /// Cycle IDs whose gross observation was persisted.
    pub recorded: Vec<CycleId>,
    /// Cycle IDs classified above the submission-gate floor.
    pub interesting: Vec<CycleId>,
    /// Cycle IDs with no classification because inputs were invalid or stale.
    pub not_evaluated: Vec<CycleId>,
    /// In-flight results discarded after a state-version change.
    pub requeued: usize,
    /// Cycles skipped because global state was not ready.
    pub skipped_stale: usize,
    /// The dirty queue exceeded its configured capacity this batch.
    pub degraded: bool,
}

/// Applies conservative economics to indexed dirty cycles from ready local state.
///
/// This component never reads RPC state, simulates, signs, or submits. It
/// evaluates only cycles indexed by a marked pool, works from one consistent
/// state snapshot, and records gross observations to storage.
pub struct DirtyEvaluator {
    graph: CompiledGraph,
    pool_count: usize,
    state: StateMachine,
    economics: Economics,
    reference: CostSnapshot,
    queue: DirtyQueue,
    storage: Storage,
}

impl DirtyEvaluator {
    #[must_use]
    pub fn new(
        graph: CompiledGraph,
        state: StateMachine,
        economics: Economics,
        queue_capacity: usize,
        storage: Storage,
    ) -> Self {
        let pool_count = graph.by_pool.len();
        Self {
            graph,
            pool_count,
            state,
            economics,
            reference: CostSnapshot::invalid(),
            queue: DirtyQueue::new(queue_capacity),
            storage,
        }
    }

    /// Sets the current gas-price and reference-route inputs for classification.
    pub fn set_reference(&mut self, reference: CostSnapshot) {
        self.reference = reference;
    }

    /// Marks every cycle indexed by the changed pool as dirty.
    pub fn mark_pool(&mut self, pool: PoolId) {
        if let Some(cycle_ids) = self.graph.by_pool.get(pool.0 as usize) {
            for &cycle_id in cycle_ids {
                self.queue.enqueue(cycle_id);
            }
        }
    }

    /// Reads the current state of selected pools.
    ///
    /// # Errors
    ///
    /// Returns [`NotReady`] while bootstrapping or stale.
    pub fn state_snapshot(&self, pool_ids: &[PoolId]) -> Result<StateSnapshot, NotReady> {
        self.state.snapshot(pool_ids)
    }

    /// Applies one ordered Sync log to local state.
    ///
    /// # Errors
    ///
    /// Returns a [`StateError`] for unknown pools, conflicts, or failed
    /// rollbacks.
    pub fn apply_log(&mut self, log: SyncLog) -> Result<ApplyOutcome, StateError> {
        self.state.apply(log)
    }

    /// Marks global state stale, suspending opportunity classification.
    pub fn disconnect(&mut self, reason: &str) {
        self.state.disconnect(reason);
    }

    /// Requeues the cycle when any route pool advanced past `used_versions`.
    ///
    /// Returns true when the in-flight result was discarded and requeued.
    #[must_use]
    pub fn retract_on_version_change(
        &mut self,
        cycle: &Cycle,
        used_versions: &[(PoolId, StateVersion)],
    ) -> bool {
        let pool_ids: Vec<PoolId> = used_versions.iter().map(|&(pool_id, _)| pool_id).collect();
        let Ok(snapshot) = self.state.snapshot(&pool_ids) else {
            self.queue.enqueue(cycle.id);
            return true;
        };
        let current: Vec<(PoolId, StateVersion)> = snapshot
            .states
            .iter()
            .map(|(pool_id, state)| (*pool_id, state.version))
            .collect();
        if current == used_versions {
            false
        } else {
            self.queue.enqueue(cycle.id);
            true
        }
    }

    /// Number of currently queued dirty cycles.
    #[must_use]
    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// Drains one dirty batch and classifies each indexed cycle.
    ///
    /// The batch is evaluated against one consistent snapshot of all local
    /// pool states. No cycle is scored while global state is not ready.
    pub fn run_once(&mut self, now_ms: u64) -> RunOutcome {
        let degraded = self.queue.take_degraded();
        let batch = self.queue.drain();
        let mut outcome = RunOutcome {
            degraded,
            ..RunOutcome::default()
        };
        if batch.is_empty() {
            return outcome;
        }

        let Ok(pool_count) = u32::try_from(self.pool_count) else {
            outcome.skipped_stale = batch.len();
            return outcome;
        };
        let all_pools: Vec<PoolId> = (0..pool_count).map(PoolId).collect();
        let Ok(snapshot) = self.state.snapshot(&all_pools) else {
            outcome.skipped_stale = batch.len();
            return outcome;
        };
        let states: Vec<PoolState> = snapshot
            .states
            .into_iter()
            .map(|(_, state)| state)
            .collect();

        for &cycle_id in &batch {
            outcome.evaluated.push(cycle_id);
            let Some(cycle) = self.graph.cycles.get(cycle_id.0 as usize).cloned() else {
                outcome.not_evaluated.push(cycle_id);
                continue;
            };
            let Ok(Some(quote)) = optimal_input(&cycle, &states) else {
                continue;
            };

            let used_versions: Vec<(PoolId, StateVersion)> = cycle
                .hops
                .iter()
                .map(|hop| {
                    let state = &states[hop.pool_id.0 as usize];
                    (hop.pool_id, state.version)
                })
                .collect();
            if self.retract_on_version_change(&cycle, &used_versions) {
                outcome.requeued += 1;
                continue;
            }

            let classification = self.economics.classify(&quote, &self.reference);
            if let Some(record) =
                observation_record(&cycle, &quote, &states, now_ms, &classification)
                && self.storage.record_observation(&record).is_ok()
            {
                outcome.recorded.push(cycle_id);
            }

            match classification.reason {
                ClassificationReason::AboveThreshold => outcome.interesting.push(cycle_id),
                ClassificationReason::NotEvaluated { .. } => outcome.not_evaluated.push(cycle_id),
                ClassificationReason::NotProfitable | ClassificationReason::BelowThreshold => {}
            }
        }
        outcome
    }
}

fn observation_record(
    cycle: &Cycle,
    quote: &OptimalQuote,
    states: &[PoolState],
    now_ms: u64,
    classification: &Classification,
) -> Option<ObservationRecord> {
    if !matches!(
        classification.reason,
        ClassificationReason::AboveThreshold | ClassificationReason::BelowThreshold
    ) {
        return None;
    }
    let route_states = cycle
        .hops
        .iter()
        .map(|hop| {
            let state = &states[hop.pool_id.0 as usize];
            RouteStateRecord {
                pool_id: hop.pool_id,
                state_version: state.version,
                reserve0: state.reserve0,
                reserve1: state.reserve1,
                fee: hop.fee,
                zero_for_one: hop.zero_for_one,
            }
        })
        .collect::<Vec<_>>();
    Some(ObservationRecord {
        cycle_id: cycle.id,
        observed_at_unix_milliseconds: now_ms,
        input: quote.input,
        output: quote.output,
        estimated_profit: quote.profit,
        route_states,
    })
}
