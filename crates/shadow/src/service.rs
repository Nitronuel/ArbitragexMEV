use std::{collections::HashSet, io::Read, path::Path};

use alloy_primitives::{Address, U256};
use catalog::{CatalogRpc, CycleLimits, FactorySpec, VerifiedPool, compile_cycles, verify_catalog};
use domain::{Cycle, CycleHop, Fee, Pool, PoolId, PoolState, Profile, StateVersion};
use provider::ProviderBudget;
use serde::Deserialize;
use state::{StateMachine, SyncLog};
use storage::{HealthInterval, Storage, StorageError};
use thiserror::Error;

use crate::evaluator::DirtyEvaluator;
use crate::{CostSnapshot, Economics};

/// Offline, deterministic service input. It is the snapshot a live bootstrap
/// would produce: a pinned verified pool set plus a replayable event stream.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSnapshot {
    pub block: u64,
    pub anchors: Vec<Address>,
    pub pools: Vec<SnapshotPool>,
    pub events: Vec<SyncLog>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPool {
    pub address: Address,
    pub token0: Address,
    pub token1: Address,
    pub fee_numerator: u32,
    pub fee_denominator: u32,
    pub token0_decimals: u8,
    pub token1_decimals: u8,
    pub reserve0: U256,
    pub reserve1: U256,
    pub source: String,
    #[serde(default)]
    pub profile: Profile,
}

/// Aggregate outcome of one wired observation pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceReport {
    pub pool_count: usize,
    pub cycle_count: usize,
    pub quarantined: usize,
    pub evaluated: usize,
    pub recorded: usize,
    pub interesting: usize,
    pub not_evaluated: usize,
    pub requeued: usize,
    pub skipped_stale: usize,
    pub degraded: bool,
}

/// Result of reproducing one stored observation from its persisted route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayResult {
    pub observation_id: i64,
    pub cycle_id: domain::CycleId,
    pub input: U256,
    pub output: U256,
    pub estimated_profit: U256,
    /// True when the deterministic recompute exactly matches the stored row.
    pub matched: bool,
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("manifest could not be parsed: {0}")]
    Manifest(#[from] catalog::ManifestError),
    #[error("catalog verification failed: {0}")]
    Catalog(#[from] catalog::CatalogError),
    #[error("cycle compilation failed: {0}")]
    Cycle(#[from] catalog::CycleError),
    #[error("pool state failed: {0}")]
    State(#[from] state::StateError),
    #[error("storage failed: {0}")]
    Storage(#[from] StorageError),
    #[error("live transport failed: {0}")]
    Live(#[from] provider::StreamError),
    #[error("replay failed for observation {observation_id}: {source}")]
    Replay {
        observation_id: i64,
        source: ReplayError,
    },
}

#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("stored route cannot be empty")]
    EmptyRoute,
    #[error("cycle math failed: {0}")]
    Math(#[from] v2_math::MathError),
    #[error("stored observation could not be read: {0}")]
    Read(#[from] StorageError),
}

/// Wires catalog verification, graph compilation, state bootstrap, buffered log
/// apply, dirty evaluation, and persistence from a live-shaped `CatalogRpc`.
///
/// # Errors
///
/// Returns an error when any wired component fails; every error aborts before
/// any further state is persisted.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::implicit_hasher)]
pub fn observe_catalog(
    manifest: impl Read,
    factories: &[FactorySpec],
    anchors: &HashSet<Address>,
    block: u64,
    rpc: &impl CatalogRpc,
    events: Vec<SyncLog>,
    now_ms: u64,
    economics: Economics,
    reference: CostSnapshot,
    storage_path: &Path,
    database_limit_bytes: u64,
    retention: state::RetentionPolicy,
    queue_capacity: usize,
    limits: CycleLimits,
    request_cu_ceiling: u64,
    websocket_bytes_ceiling: u64,
) -> Result<ServiceReport, ServiceError> {
    let candidates = catalog::parse_manifest(manifest)?;
    let verified = verify_catalog(candidates, factories, block, rpc)?;
    let quarantined = verified.quarantined.len();
    run_pipeline(
        &verified.verified,
        anchors,
        block,
        events,
        now_ms,
        economics,
        reference,
        storage_path,
        database_limit_bytes,
        retention,
        queue_capacity,
        limits,
        request_cu_ceiling,
        websocket_bytes_ceiling,
        quarantined,
    )
}

/// Wires the same pipeline from an offline snapshot fixture.
///
/// # Errors
///
/// Returns an error when any wired component fails.
#[allow(clippy::too_many_arguments)]
pub fn observe_snapshot(
    snapshot: ServiceSnapshot,
    now_ms: u64,
    economics: Economics,
    reference: CostSnapshot,
    storage_path: &Path,
    database_limit_bytes: u64,
    retention: state::RetentionPolicy,
    queue_capacity: usize,
    limits: CycleLimits,
    request_cu_ceiling: u64,
    websocket_bytes_ceiling: u64,
) -> Result<ServiceReport, ServiceError> {
    let mut verified = Vec::with_capacity(snapshot.pools.len());
    for (index, pool) in snapshot.pools.into_iter().enumerate() {
        let id = u32::try_from(index)
            .map_err(|_| ServiceError::Catalog(catalog::CatalogError::PoolCapExceeded))?;
        verified.push(VerifiedPool {
            pool: Pool {
                id: PoolId(id),
                address: pool.address,
                token0: pool.token0,
                token1: pool.token1,
                fee: Fee {
                    numerator: pool.fee_numerator,
                    denominator: pool.fee_denominator,
                },
                profile: pool.profile,
            },
            token0_decimals: pool.token0_decimals,
            token1_decimals: pool.token1_decimals,
            initial_state: PoolState {
                reserve0: pool.reserve0,
                reserve1: pool.reserve1,
                block_number: snapshot.block,
                transaction_index: 0,
                log_index: 0,
                version: StateVersion(0),
            },
            source: pool.source,
        });
    }
    let anchors: HashSet<Address> = snapshot.anchors.into_iter().collect();
    run_pipeline(
        &verified,
        &anchors,
        snapshot.block,
        snapshot.events,
        now_ms,
        economics,
        reference,
        storage_path,
        database_limit_bytes,
        retention,
        queue_capacity,
        limits,
        request_cu_ceiling,
        websocket_bytes_ceiling,
        0,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_pipeline(
    verified: &[VerifiedPool],
    anchors: &HashSet<Address>,
    block: u64,
    events: Vec<SyncLog>,
    now_ms: u64,
    economics: Economics,
    reference: CostSnapshot,
    storage_path: &Path,
    database_limit_bytes: u64,
    retention: state::RetentionPolicy,
    queue_capacity: usize,
    limits: CycleLimits,
    request_cu_ceiling: u64,
    websocket_bytes_ceiling: u64,
    quarantined: usize,
) -> Result<ServiceReport, ServiceError> {
    let graph = compile_cycles(verified, anchors, limits)?;
    let cycle_count = graph.cycles.len();

    let evaluator_storage = Storage::open_with_limit(storage_path, database_limit_bytes)?;
    // Use default retention for now; caller may override via with_retention if config available.
    let mut machine = StateMachine::with_retention(verified.len(), retention);
    let states: Vec<(PoolId, U256, U256)> = verified
        .iter()
        .map(|pool| {
            (
                pool.pool.id,
                pool.initial_state.reserve0,
                pool.initial_state.reserve1,
            )
        })
        .collect();
    machine.bootstrap(block, states)?;

    let mut evaluator =
        DirtyEvaluator::new(graph, machine, economics, queue_capacity, evaluator_storage);
    evaluator.set_reference(reference);

    let mut admin_storage = Storage::open_with_limit(storage_path, database_limit_bytes)?;
    for log in events {
        evaluator.apply_log(log.clone())?;
        evaluator.mark_pool(log.pool_id);
    }
    let outcome = evaluator.run_once(now_ms);

    let started = now_ms.saturating_sub(60_000);
    admin_storage.record_health_interval(&HealthInterval {
        started_at_unix_milliseconds: started,
        ended_at_unix_milliseconds: now_ms,
        state: "READY".to_owned(),
        reason: "offline fixture window".to_owned(),
    })?;
    let budget = ProviderBudget::new(request_cu_ceiling, websocket_bytes_ceiling);
    admin_storage.record_usage(now_ms / 3_600_000, budget.snapshot())?;

    Ok(ServiceReport {
        pool_count: verified.len(),
        cycle_count,
        quarantined,
        evaluated: outcome.evaluated.len(),
        recorded: outcome.recorded.len(),
        interesting: outcome.interesting.len(),
        not_evaluated: outcome.not_evaluated.len(),
        requeued: outcome.requeued,
        skipped_stale: outcome.skipped_stale,
        degraded: outcome.degraded,
    })
}

/// Reproduces one stored observation and checks exact equality.
///
/// # Errors
///
/// Returns an error when the observation or its route cannot be read, or the
/// stored route cannot be replayed by the checked math.
pub fn replay_observation(storage: &Storage, id: i64) -> Result<ReplayResult, ServiceError> {
    let record = storage
        .load_observation(id)
        .map_err(|source| ServiceError::Replay {
            observation_id: id,
            source: ReplayError::Read(source),
        })?;
    if record.route_states.is_empty() {
        return Err(ServiceError::Replay {
            observation_id: id,
            source: ReplayError::EmptyRoute,
        });
    }

    let cycle = Cycle {
        id: record.cycle_id,
        anchor: Address::ZERO,
        hops: record
            .route_states
            .iter()
            .map(|route| CycleHop {
                pool_id: route.pool_id,
                token_in: Address::ZERO,
                token_out: Address::ZERO,
                fee: route.fee,
                zero_for_one: route.zero_for_one,
            })
            .collect(),
    };
    let states: Vec<PoolState> = record
        .route_states
        .iter()
        .map(|route| PoolState {
            reserve0: route.reserve0,
            reserve1: route.reserve1,
            block_number: 0,
            transaction_index: 0,
            log_index: 0,
            version: route.state_version,
        })
        .collect();

    let quote = v2_math::optimal_input(&cycle, &states).map_err(|source| ServiceError::Replay {
        observation_id: id,
        source: ReplayError::Math(source),
    })?;
    let matched = quote.is_some_and(|quote| {
        quote.input == record.input
            && quote.output == record.output
            && quote.profit == record.estimated_profit
    });

    Ok(ReplayResult {
        observation_id: id,
        cycle_id: record.cycle_id,
        input: record.input,
        output: record.output,
        estimated_profit: record.estimated_profit,
        matched,
    })
}
