//! Bounded live observation loop: a pinned verified catalog plus a WebSocket
//! `Sync` subscription, drained in-window and applied to local pool state.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use alloy_primitives::{Address, B256, U256};
use catalog::{
    CatalogRpc, CycleLimits, FactorySpec, compile_cycles, parse_manifest, verify_catalog,
};
use domain::PoolId;
use provider::{
    LogStream, ProviderBudget, RawLogEnvelope, StreamError, StreamItem, WsProbe,
    decode_sync_reserves, sync_topic,
};
use state::{CanonicalPosition, StateMachine, SyncLog};
use storage::{HealthInterval, Storage};

use crate::evaluator::DirtyEvaluator;
use crate::{CostSnapshot, Economics, ServiceError};

/// Why a live-observation window stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// A stop signal was received; buffered frames were drained before exit.
    Stopped,
    /// The configured item cap was reached and buffered frames were drained cleanly.
    CapReached,
    /// The subscription closed (cleanly or not).
    Disconnected(provider::DisconnectKind),
}

/// Aggregate outcome of one bounded live observation window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveReport {
    pub pool_count: usize,
    pub cycle_count: usize,
    pub quarantined: usize,
    /// Raw `Sync` frames observed on the socket, before filtering.
    pub sync_observed: usize,
    /// Frames dropped for an unknown (unverified) pool address.
    pub unknown_pool: usize,
    /// Frames successfully decoded and applied to local state.
    pub applied: usize,
    pub evaluated: usize,
    pub recorded: usize,
    pub interesting: usize,
    pub not_evaluated: usize,
    pub requeued: usize,
    pub skipped_stale: usize,
    pub degraded: bool,
    pub ended: EndReason,
}

/// Runs a live observation window as a continuous loop.
///
/// The catalog is verified against a pinned `block`, the compiled dirty graph is
/// bootstrapped, and a subscription probe is built from the verified pool
/// addresses via `build_probe`. The loop serves `Sync` frames until a stop
/// signal (`stop`), the `max_items` cap (`0` = unbounded), or a socket close.
/// When stopped by signal or cap, a graceful drain pass pulls already-buffered
/// frames before one dirty batch is drained and usage/health are flushed.
///
/// The loop yields with `poll` on each idle read so it can observe the `stop`
/// flag without busy-spinning. Live subscription frames carry no block hash, so
/// reorg-aware canonical ordering is deferred to the canary handler.
///
/// # Errors
///
/// Returns an error when the manifest is invalid, the pinned catalog cannot be
/// verified, graph compilation fails, storage fails, or the socket errors.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
#[allow(clippy::implicit_hasher)]
pub fn run_live<P: WsProbe>(
    manifest: impl Read,
    anchors: &HashSet<Address>,
    block: u64,
    rpc: &impl CatalogRpc,
    stream: &LogStream,
    poll: Duration,
    drain_grace: Duration,
    stop: &AtomicBool,
    max_items: usize,
    block_hash: B256,
    build_probe: &mut impl FnMut(&[Address]) -> Result<P, StreamError>,
    now_ms: u64,
    economics: Economics,
    reference: CostSnapshot,
    storage_path: &Path,
    queue_capacity: usize,
    limits: CycleLimits,
    request_cu_ceiling: u64,
    websocket_bytes_ceiling: u64,
) -> Result<LiveReport, ServiceError> {
    let candidates = parse_manifest(manifest)?;
    let factories: Vec<FactorySpec> = candidates
        .iter()
        .map(|candidate| FactorySpec {
            address: candidate.factory,
            fee: candidate.fee,
        })
        .collect();
    let verified = verify_catalog(candidates, &factories, block, rpc)?;
    let quarantined = verified.quarantined.len();
    let verified = verified.verified;

    let graph = compile_cycles(&verified, anchors, limits)?;
    let cycle_count = graph.cycles.len();

    let evaluator_storage = Storage::open(storage_path)?;
    let mut machine = StateMachine::new(verified.len());
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

    let address_to_pool: HashMap<Address, PoolId> = verified
        .iter()
        .map(|pool| (pool.pool.address, pool.pool.id))
        .collect();
    let addresses: Vec<Address> = address_to_pool.keys().copied().collect();
    let probe = build_probe(&addresses)?;

    let mut report = LiveReport {
        pool_count: verified.len(),
        cycle_count,
        quarantined,
        sync_observed: 0,
        unknown_pool: 0,
        applied: 0,
        evaluated: 0,
        recorded: 0,
        interesting: 0,
        not_evaluated: 0,
        requeued: 0,
        skipped_stale: 0,
        degraded: false,
        ended: EndReason::Stopped,
    };

    let ended: EndReason = 'serve: loop {
        if stop.load(Ordering::Relaxed) {
            break 'serve EndReason::Stopped;
        }
        if max_items != 0 && report.sync_observed >= max_items {
            break 'serve EndReason::CapReached;
        }
        match probe.next(stream, poll)? {
            Some(StreamItem::Log(envelope)) => {
                report.sync_observed += 1;
                apply_envelope(
                    &mut evaluator,
                    &envelope,
                    &address_to_pool,
                    block_hash,
                    &mut report,
                )?;
            }
            Some(StreamItem::Disconnected(kind)) => break 'serve EndReason::Disconnected(kind),
            None => {}
        }
    };

    // Graceful drain: accept frames already buffered before the stop or cap.
    if !matches!(ended, EndReason::Disconnected(_)) {
        while let Some(StreamItem::Log(envelope)) = probe.next(stream, drain_grace)? {
            report.sync_observed += 1;
            apply_envelope(
                &mut evaluator,
                &envelope,
                &address_to_pool,
                block_hash,
                &mut report,
            )?;
        }
    }
    report.ended = ended;

    let outcome = evaluator.run_once(now_ms);

    let mut admin_storage = Storage::open(storage_path)?;
    let started = now_ms.saturating_sub(60_000);
    admin_storage.record_health_interval(&HealthInterval {
        started_at_unix_milliseconds: started,
        ended_at_unix_milliseconds: now_ms,
        state: "READY".to_owned(),
        reason: "live observation window".to_owned(),
    })?;
    let budget = ProviderBudget::new(request_cu_ceiling, websocket_bytes_ceiling);
    admin_storage.record_usage(now_ms / 3_600_000, budget.snapshot())?;

    report.evaluated = outcome.evaluated.len();
    report.recorded = outcome.recorded.len();
    report.interesting = outcome.interesting.len();
    report.not_evaluated = outcome.not_evaluated.len();
    report.requeued = outcome.requeued;
    report.skipped_stale = outcome.skipped_stale;
    report.degraded = outcome.degraded;
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn apply_envelope(
    evaluator: &mut DirtyEvaluator,
    envelope: &RawLogEnvelope,
    address_to_pool: &HashMap<Address, PoolId>,
    block_hash: B256,
    report: &mut LiveReport,
) -> Result<(), ServiceError> {
    let Some(&pool_id) = address_to_pool.get(&envelope.address) else {
        report.unknown_pool += 1;
        return Ok(());
    };
    if envelope.topics.first() != Some(&sync_topic()) {
        return Ok(());
    }
    let Some((reserve0, reserve1)) = decode_sync_reserves(&envelope.data) else {
        return Ok(());
    };
    evaluator.apply_log(SyncLog {
        pool_id,
        reserve0,
        reserve1,
        block_hash,
        position: CanonicalPosition {
            block_number: envelope.block_number,
            transaction_index: envelope.transaction_index,
            log_index: envelope.log_index,
        },
        removed: envelope.removed,
    })?;
    evaluator.mark_pool(pool_id);
    report.applied += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{HashSet, VecDeque};
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use alloy_primitives::{Address, Bytes, U256};
    use catalog::{CatalogRpc, RpcError};

    use super::run_live;
    use crate::{CostSnapshot, Economics, EndReason, FIXED_POINT_SCALE};

    const BLOCK: u64 = 20_000_000;
    const FACTORY: [u8; 20] = [
        0x89, 0x09, 0xdc, 0x15, 0xe4, 0x01, 0x73, 0xff, 0x46, 0x99, 0x34, 0x3b, 0x6e, 0xb8, 0x13,
        0x2c, 0x65, 0xe1, 0x8e, 0xc6,
    ];
    const POOL: [u8; 20] = [0x10; 20];
    const TOKEN0: [u8; 20] = [0x01; 20];
    const TOKEN1: [u8; 20] = [0x02; 20];

    #[derive(Clone)]
    struct FakeRpc {
        chain_id: Result<u64, RpcError>,
        code: Result<Vec<u8>, RpcError>,
        factory: Result<Address, RpcError>,
        token0: Result<Address, RpcError>,
        token1: Result<Address, RpcError>,
        pair: Result<Address, RpcError>,
        decimals: Result<u8, RpcError>,
        reserves: Result<(U256, U256), RpcError>,
    }

    impl CatalogRpc for FakeRpc {
        fn chain_id(&self, _block: u64) -> Result<u64, RpcError> {
            self.chain_id.clone()
        }
        fn get_code(&self, _address: Address, _block: u64) -> Result<Vec<u8>, RpcError> {
            self.code.clone()
        }
        fn factory(&self, _pair: Address, _block: u64) -> Result<Address, RpcError> {
            self.factory.clone()
        }
        fn token0(&self, _pair: Address, _block: u64) -> Result<Address, RpcError> {
            self.token0.clone()
        }
        fn token1(&self, _pair: Address, _block: u64) -> Result<Address, RpcError> {
            self.token1.clone()
        }
        fn get_pair(
            &self,
            _factory: Address,
            _token0: Address,
            _token1: Address,
            _block: u64,
        ) -> Result<Address, RpcError> {
            self.pair.clone()
        }
        fn decimals(&self, _token: Address, _block: u64) -> Result<u8, RpcError> {
            self.decimals.clone()
        }
        fn get_reserves(&self, _pair: Address, _block: u64) -> Result<(U256, U256), RpcError> {
            self.reserves.clone()
        }
    }

    struct MockProbe {
        pending: RefCell<VecDeque<provider::StreamItem>>,
    }

    impl MockProbe {
        fn new(items: Vec<provider::StreamItem>) -> Self {
            Self {
                pending: RefCell::new(items.into()),
            }
        }
    }

    impl provider::WsProbe for MockProbe {
        fn next(
            &self,
            _stream: &provider::LogStream,
            _timeout: Duration,
        ) -> Result<Option<provider::StreamItem>, provider::StreamError> {
            Ok(self.pending.borrow_mut().pop_front())
        }
    }

    fn rpc() -> FakeRpc {
        FakeRpc {
            chain_id: Ok(8453),
            code: Ok(vec![1]),
            factory: Ok(Address::from_slice(&FACTORY)),
            token0: Ok(Address::from_slice(&TOKEN0)),
            token1: Ok(Address::from_slice(&TOKEN1)),
            pair: Ok(Address::from_slice(&POOL)),
            decimals: Ok(18),
            reserves: Ok((U256::from(1_000), U256::from(2_000))),
        }
    }

    fn manifest() -> String {
        let pool = Address::from_slice(&POOL).to_checksum(None);
        let factory = Address::from_slice(&FACTORY).to_checksum(None);
        let token0 = Address::from_slice(&TOKEN0).to_checksum(None);
        let token1 = Address::from_slice(&TOKEN1).to_checksum(None);
        format!(
            "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,source\n\
             8453,{pool},{factory},{token0},{token1},997,1000,fixture\n"
        )
    }

    fn sync_envelope(r0: U256, r1: U256, block: u64, log_index: u64) -> provider::StreamItem {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&r0.to_be_bytes::<32>());
        data.extend_from_slice(&r1.to_be_bytes::<32>());
        provider::StreamItem::Log(provider::RawLogEnvelope {
            address: Address::from_slice(&POOL),
            topics: vec![provider::sync_topic()],
            data: Bytes::from(data),
            block_number: block,
            transaction_index: 0,
            log_index,
            removed: false,
        })
    }

    fn economics() -> Economics {
        Economics {
            flash_fee_rate: U256::ZERO,
            gas_cost_usd: U256::from(1_000),
            expected_win_rate: U256::from(FIXED_POINT_SCALE),
        }
    }

    fn reference() -> CostSnapshot {
        CostSnapshot {
            usd_per_token: U256::from(FIXED_POINT_SCALE),
            gas_price_age_valid: true,
            reference_price_valid: true,
        }
    }

    fn run_live_test(
        items: &[provider::StreamItem],
        max_items: usize,
        stop: &AtomicBool,
    ) -> crate::LiveReport {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("live.sqlite");
        let stream = provider::LogStream::new(provider::ProviderBudget::new(1_000_000, 1_000_000));
        let mut probe = |_: &[Address]| -> Result<MockProbe, provider::StreamError> {
            Ok(MockProbe::new(items.to_vec()))
        };
        let manifest_text = manifest();
        run_live(
            manifest_text.as_bytes(),
            &HashSet::new(),
            BLOCK,
            &rpc(),
            &stream,
            Duration::from_millis(1),
            Duration::from_millis(1),
            stop,
            max_items,
            alloy_primitives::B256::ZERO,
            &mut probe,
            1_700_000_000_000,
            economics(),
            reference(),
            &db,
            1_000,
            ::catalog::CycleLimits {
                max_cycles: 1_000_000,
                max_cycles_per_pool: 10_000,
            },
            1_000_000,
            1_000_000,
        )
        .unwrap()
    }

    #[test]
    fn drains_buffered_frames_on_stop() {
        let stop = AtomicBool::new(true);
        let report = run_live_test(
            &[
                sync_envelope(U256::from(5), U256::from(6), BLOCK + 1, 0),
                sync_envelope(U256::from(7), U256::from(8), BLOCK + 1, 1),
            ],
            0,
            &stop,
        );
        assert_eq!(report.pool_count, 1);
        assert_eq!(report.sync_observed, 2);
        assert_eq!(report.applied, 2);
        assert_eq!(report.unknown_pool, 0);
        assert_eq!(report.ended, EndReason::Stopped);
    }

    #[test]
    fn stops_when_item_cap_reached() {
        let stop = AtomicBool::new(false);
        let report = run_live_test(
            &[
                sync_envelope(U256::from(5), U256::from(6), BLOCK + 1, 0),
                sync_envelope(U256::from(7), U256::from(8), BLOCK + 1, 1),
            ],
            2,
            &stop,
        );
        assert_eq!(report.sync_observed, 2);
        assert_eq!(report.applied, 2);
        assert_eq!(report.ended, EndReason::CapReached);
    }

    #[test]
    fn drops_unknown_pool_frames() {
        let mut envelope = provider::RawLogEnvelope {
            address: Address::from_slice(&POOL),
            topics: vec![provider::sync_topic()],
            data: Bytes::new(),
            block_number: BLOCK,
            transaction_index: 0,
            log_index: 0,
            removed: false,
        };
        envelope.address = Address::repeat_byte(0x99);
        let stop = AtomicBool::new(true);
        let report = run_live_test(&[provider::StreamItem::Log(envelope)], 0, &stop);
        assert_eq!(report.sync_observed, 1);
        assert_eq!(report.unknown_pool, 1);
        assert_eq!(report.applied, 0);
        assert_eq!(report.ended, EndReason::Stopped);
    }

    #[test]
    fn ends_cleanly_on_disconnect() {
        let stop = AtomicBool::new(false);
        let report = run_live_test(
            &[provider::StreamItem::Disconnected(
                provider::DisconnectKind::Clean,
            )],
            0,
            &stop,
        );
        assert_eq!(report.sync_observed, 0);
        assert_eq!(
            report.ended,
            EndReason::Disconnected(provider::DisconnectKind::Clean)
        );
    }
}
