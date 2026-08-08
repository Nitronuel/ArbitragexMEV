use std::collections::HashSet;
use std::time::Duration;

use alloy_primitives::{Address, B256};
use provider::{
    ChainReader, HttpBackend, LogFilter, RawLogEnvelope, Sleeper, TransportError,
    decode_v3_pool_created, decode_v4_initialize, v3_pool_created_topic, v4_initialize_topic,
};

/// Paces an enumeration sweep: the number of blocks covered by each
/// `eth_getLogs` request and the quiet period between requests.
#[derive(Debug, Clone, Copy)]
pub struct CrawlPace {
    pub window: u64,
    pub delay: Duration,
}

impl Default for CrawlPace {
    fn default() -> Self {
        Self {
            window: 50_000,
            delay: Duration::from_millis(600),
        }
    }
}

/// The DEX venue whose pool-creation events a cursor enumerates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VenueKind {
    V3,
    V4,
}

/// A factory (for `VenueKind::V3`, the factory contract; for
/// `VenueKind::V4`, the `PoolManager` singleton) plus its creation-event
/// signature `topic0`, used to filter an enumeration scan.
#[derive(Debug, Clone, Copy)]
pub struct Venue {
    pub address: Address,
    pub topic: B256,
    pub kind: VenueKind,
}

/// One pool-creation event decoded from a factory log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnumeratedPool {
    V3 {
        token0: Address,
        token1: Address,
        fee: u32,
        pool: Address,
    },
    V4 {
        id: B256,
        currency0: Address,
        currency1: Address,
        fee: u32,
        tick_spacing: i32,
        hooks: Address,
    },
}

impl Venue {
    #[must_use]
    pub fn v3_pools(factory: Address) -> Self {
        Self {
            address: factory,
            topic: v3_pool_created_topic(),
            kind: VenueKind::V3,
        }
    }

    #[must_use]
    pub fn v4_pools(manager: Address) -> Self {
        Self {
            address: manager,
            topic: v4_initialize_topic(),
            kind: VenueKind::V4,
        }
    }

    /// Decodes one raw `eth_getLogs` result into a pool-creation event, or
    /// `None` when the log does not carry this venue's signature topic0.
    #[must_use]
    pub fn decode(&self, raw: &serde_json::Value) -> Option<EnumeratedPool> {
        let envelope = RawLogEnvelope::from_rpc_value(raw).ok()?;
        if envelope.topics.first()? != &self.topic {
            return None;
        }
        match self.kind {
            VenueKind::V3 => decode_v3_pool_created(&envelope).map(|pool| EnumeratedPool::V3 {
                token0: pool.token0,
                token1: pool.token1,
                fee: pool.fee,
                pool: pool.pool,
            }),
            VenueKind::V4 => decode_v4_initialize(&envelope).map(|pool| EnumeratedPool::V4 {
                id: pool.id,
                currency0: pool.currency0,
                currency1: pool.currency1,
                fee: pool.fee,
                tick_spacing: pool.tick_spacing,
                hooks: pool.hooks,
            }),
        }
    }

    /// The deduplication key for a decoded pool (V3 contract address, V4
    /// `PoolId`).
    #[must_use]
    pub fn pool_key(pool: &EnumeratedPool) -> B256 {
        match pool {
            EnumeratedPool::V3 { pool, .. } => pool.into_word(),
            EnumeratedPool::V4 { id, .. } => *id,
        }
    }
}

impl EnumeratedPool {
    #[cfg(test)]
    fn fee(&self) -> u32 {
        match self {
            EnumeratedPool::V3 { fee, .. } | EnumeratedPool::V4 { fee, .. } => *fee,
        }
    }
}

/// Enumerates pool-creation events for one DEX venue by sweeping
/// `eth_getLogs` across `[from, to]` in paced windows, deduplicating by pool
/// identity (V3 contract address, V4 `PoolId`).
///
/// # Errors
///
/// Returns [`TransportError`] for invalid ranges, empty filters, budget, or
/// transport failures.
pub fn sweep_venue<B, S>(
    reader: &ChainReader<B, S>,
    venue: &Venue,
    from: u64,
    to: u64,
    pace: CrawlPace,
) -> Result<Vec<EnumeratedPool>, TransportError>
where
    B: HttpBackend,
    S: Sleeper,
{
    if from > to {
        return Err(TransportError::InvalidBlockRange);
    }
    let mut seen = HashSet::new();
    let mut all = Vec::new();
    let mut start = from;
    loop {
        let end = start.saturating_add(pace.window.saturating_sub(1)).min(to);
        let logs = reader.get_logs_windowed(
            &LogFilter {
                from_block: start,
                to_block: end,
                addresses: vec![venue.address],
                topic0: venue.topic,
            },
            pace.window,
        )?;
        for raw in &logs {
            let Some(pool) = venue.decode(raw) else {
                continue;
            };
            let key = Venue::pool_key(&pool);
            if seen.insert(key) {
                all.push(pool);
            }
        }
        if end == to {
            break;
        }
        start = end + 1;
        if !pace.delay.is_zero() {
            std::thread::sleep(pace.delay);
        }
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use provider::{HttpResponse, ProviderBudget, RpcRequest, ThreadSleeper};
    use serde_json::json;
    use std::time::Duration;

    /// A backend that answers `eth_getLogs` with the same three logs on every
    /// request: two V3 `PoolCreated` events and one unrelated log.
    #[derive(Clone, Default)]
    struct FanBackend {
        calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl HttpBackend for FanBackend {
        fn request(&self, request: &RpcRequest) -> Result<HttpResponse, TransportError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{}({})", request.method, request.params));
            let logs = vec![
                // V3 pool created (pool 0xaa).
                json!({
                    "address": format!("0x{}", alloy_primitives::hex::encode([0x10; 20])),
                    "topics": [
                        format!("{}", v3_pool_created_topic()),
                        format!("0x{}", "11".repeat(32)),
                        format!("0x{}", "22".repeat(32)),
                        format!("0x{}", "00".repeat(31) + "2c"),
                    ],
                    "data": format!("0x{}", "00".repeat(63) + "aa"),
                    "blockNumber": "0x1",
                    "transactionIndex": "0x0",
                    "logIndex": "0x0",
                    "removed": false,
                }),
                // Another V3 pool creation (pool 0xbb).
                json!({
                    "address": format!("0x{}", alloy_primitives::hex::encode([0x10; 20])),
                    "topics": [
                        format!("{}", v3_pool_created_topic()),
                        format!("0x{}", "33".repeat(32)),
                        format!("0x{}", "44".repeat(32)),
                        format!("0x{}", "00".repeat(31) + "3c"),
                    ],
                    "data": format!("0x{}", "00".repeat(63) + "bb"),
                    "blockNumber": "0x2",
                    "transactionIndex": "0x0",
                    "logIndex": "0x0",
                    "removed": false,
                }),
                // An unrelated log: must be rejected by the topic filter.
                json!({
                    "address": format!("0x{}", alloy_primitives::hex::encode([0x10; 20])),
                    "topics": [format!("0x{}", "ef".repeat(32))],
                    "data": "0x",
                    "blockNumber": "0x3",
                    "transactionIndex": "0x0",
                    "logIndex": "0x0",
                    "removed": false,
                }),
            ];
            Ok(HttpResponse {
                result: serde_json::Value::Array(logs),
                response_bytes: 0,
            })
        }
    }

    fn reader(backend: FanBackend) -> ChainReader<FanBackend, ThreadSleeper> {
        ChainReader::new(
            backend,
            ThreadSleeper,
            ProviderBudget::new(10_000_000, 10_000_000),
            provider::RetryPolicy {
                max_retries: 0,
                initial_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
            },
            4663,
        )
    }

    #[test]
    fn venue_rejects_unrelated_topic() {
        let venue = Venue::v3_pools(Address::with_last_byte(0x10));
        let envelope = RawLogEnvelope::from_rpc_value(&json!({
            "address": format!("0x{}", alloy_primitives::hex::encode([0x10; 20])),
            "topics": [format!("0x{}", "ef".repeat(32))],
            "data": "0x",
            "blockNumber": "0x1",
            "transactionIndex": "0x0",
            "logIndex": "0x0",
            "removed": false,
        }))
        .unwrap();
        assert!(decode_v3_pool_created(&envelope).is_none());
        assert!(
            venue
                .decode(&json!({
                    "address": format!("0x{}", alloy_primitives::hex::encode([0x10; 20])),
                    "topics": [format!("0x{}", "ef".repeat(32))],
                    "data": "0x",
                    "blockNumber": "0x1",
                    "transactionIndex": "0x0",
                    "logIndex": "0x0",
                    "removed": false,
                }))
                .is_none()
        );
    }

    #[test]
    fn v3_venue_decodes_pool_created() {
        let venue = Venue::v3_pools(Address::with_last_byte(0x10));
        let raw = json!({
            "address": format!("0x{}", alloy_primitives::hex::encode([0x10; 20])),
            "topics": [
                format!("{}", v3_pool_created_topic()),
                format!("0x{}", "11".repeat(32)),
                format!("0x{}", "22".repeat(32)),
                format!("0x{}", "00".repeat(31) + "2c"),
            ],
            "data": format!("0x{}", "00".repeat(63) + "aa"),
            "blockNumber": "0x1",
            "transactionIndex": "0x0",
            "logIndex": "0x0",
            "removed": false,
        });
        let pool = venue.decode(&raw).expect("decodes");
        let EnumeratedPool::V3 {
            token0,
            token1,
            fee,
            pool,
        } = pool
        else {
            panic!("expected V3");
        };
        // token0/token1 are the trailing 20 bytes of their indexed topics.
        assert_eq!(token0, Address::from_slice(&[0x11; 20]));
        assert_eq!(token1, Address::from_slice(&[0x22; 20]));
        assert_eq!(fee, 0x2c);
        assert_eq!(pool, Address::with_last_byte(0xaa));
        let key = Venue::pool_key(&EnumeratedPool::V3 {
            token0,
            token1,
            fee,
            pool,
        });
        assert_eq!(key, pool.into_word());
    }

    #[test]
    fn sweep_deduplicates_by_identity() {
        let reader = reader(FanBackend::default());
        let venue = Venue::v3_pools(Address::with_last_byte(0x10));
        // Two windows over the same fake logs; the identity set leaves exactly
        // one V3 pool per unique pool address.
        let pools = sweep_venue(
            &reader,
            &venue,
            1,
            2,
            CrawlPace {
                window: 1,
                delay: Duration::ZERO,
            },
        )
        .expect("sweeps");
        assert_eq!(pools.len(), 2);
        assert_eq!(pools[0].fee(), 0x2c);
        assert_eq!(pools[1].fee(), 0x3c);
    }
}
