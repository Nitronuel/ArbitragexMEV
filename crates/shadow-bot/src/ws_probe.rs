//! Bounded WebSocket probe core: builds per-venue filtered Swap-log
//! subscriptions from a pool manifest and aggregates tip-lag statistics.
//! The aggregation and subscription planning are pure and unit-tested; the
//! live socket lives in `provider::LiveWsClient`.

use std::collections::BTreeSet;
use std::io::Read;
use std::time::Duration;

use alloy_primitives::Address;
use catalog::parse_manifest;
use domain::Profile;
use provider::{SubscriptionFilter, v3_swap_topic, v4_swap_topic};

/// One address- and topic-filtered subscription for a single venue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VenueSubscription {
    pub label: String,
    pub filter: SubscriptionFilter,
}

/// Splits a pool manifest into one Swap-log subscription per venue profile.
///
/// V3 pools subscribe by their own addresses; V4 pools share the singleton
/// `PoolManager`, so the distinct manifest addresses (all the singleton) are
/// subscribed with the V4 Swap topic0. Constant-product rows carry no Swap
/// subscription in the current catalogs and are reported as skipped.
///
/// # Errors
///
/// Returns an error when the manifest cannot be parsed or no venue produces a
/// subscribable filter.
pub fn build_subscriptions(reader: impl Read) -> Result<(Vec<VenueSubscription>, usize), String> {
    let candidates = parse_manifest(reader).map_err(|error| error.to_string())?;
    let mut v3: BTreeSet<Address> = BTreeSet::new();
    let mut v4: BTreeSet<Address> = BTreeSet::new();
    let mut skipped = 0usize;
    for candidate in &candidates {
        match candidate.profile {
            Profile::Concentrated => {
                v3.insert(candidate.address);
            }
            Profile::VolatileManaged => {
                v4.insert(candidate.address);
            }
            Profile::ConstantProduct => skipped += 1,
        }
    }
    let mut subscriptions = Vec::new();
    if !v3.is_empty() {
        subscriptions.push(VenueSubscription {
            label: "v3-swap".to_owned(),
            filter: SubscriptionFilter {
                addresses: v3.into_iter().collect(),
                topic0: v3_swap_topic(),
            },
        });
    }
    if !v4.is_empty() {
        subscriptions.push(VenueSubscription {
            label: "v4-swap".to_owned(),
            filter: SubscriptionFilter {
                addresses: v4.into_iter().collect(),
                topic0: v4_swap_topic(),
            },
        });
    }
    if subscriptions.is_empty() {
        return Err("manifest produced no subscribable venue filters".to_owned());
    }
    Ok((subscriptions, skipped))
}

/// Aggregate probe counters for one subscription or the whole window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeStats {
    pub events: u64,
    pub duplicates: u64,
    pub reconnects: u64,
    lag_sum_blocks: i128,
    lag_max_blocks: i64,
    lag_min_blocks: Option<i64>,
    lag_samples: u64,
}

/// Detects repeated deliveries of one log identity
/// `(block_number, transaction_index, log_index)`.
#[derive(Debug, Default)]
pub struct LogDeduper {
    seen: std::collections::HashSet<(u64, u64, u64)>,
}

/// Memory bound: at ~1M identities the set is cleared rather than growing
/// without limit. A cleared window only weakens redelivery detection for a
/// probe tool; production ingestion must dedup at the transport layer.
const DEDUPER_CAP: usize = 1_000_000;

impl LogDeduper {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true when this exact log was delivered before.
    ///
    /// Subscription providers may redeliver historical ranges after internal
    /// rebalancing; the dirty path must see each swap exactly once.
    pub fn is_duplicate(&mut self, envelope: &provider::RawLogEnvelope) -> bool {
        if self.seen.len() >= DEDUPER_CAP {
            self.seen.clear();
        }
        let key = (
            envelope.block_number,
            envelope.transaction_index,
            envelope.log_index,
        );
        !self.seen.insert(key)
    }
}

impl ProbeStats {
    /// Records one delivered log's block lag against the tip observed at
    /// arrival. Negative values mean the log is *ahead* of our HTTP tip view
    /// (WS delivery leads the separate HTTP endpoint).
    pub fn observe_lag(&mut self, lag: i64) {
        self.events += 1;
        self.lag_sum_blocks += i128::from(lag);
        self.lag_samples += 1;
        self.lag_max_blocks = self.lag_max_blocks.max(lag);
        self.lag_min_blocks = Some(match self.lag_min_blocks {
            Some(min) => min.min(lag),
            None => lag,
        });
    }

    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn lag_mean_blocks(&self) -> Option<f64> {
        if self.lag_samples == 0 {
            return None;
        }
        Some(self.lag_sum_blocks as f64 / self.lag_samples as f64)
    }

    #[must_use]
    pub const fn lag_min_blocks(&self) -> Option<i64> {
        self.lag_min_blocks
    }

    #[must_use]
    pub const fn lag_max_blocks(&self) -> i64 {
        self.lag_max_blocks
    }

    /// Merges another stats object into this one (window-level rollup).
    pub fn merge(&mut self, other: &ProbeStats) {
        self.events += other.events;
        self.duplicates += other.duplicates;
        self.reconnects += other.reconnects;
        self.lag_sum_blocks += other.lag_sum_blocks;
        self.lag_samples += other.lag_samples;
        self.lag_max_blocks = self.lag_max_blocks.max(other.lag_max_blocks);
        self.lag_min_blocks = match (self.lag_min_blocks, other.lag_min_blocks) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
    }
}

/// Which transport first surfaced a block's swap logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Ws,
    Http,
    /// A second HTTP endpoint (provider comparison sidecar).
    Bench,
}

/// Earliest visibility of one block's swap logs per transport. Field names
/// intentionally share the `seen_` prefix for readability.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BlockVisibility {
    pub seen_ws: Option<u64>,
    pub seen_http: Option<u64>,
    pub seen_bench: Option<u64>,
}

/// Shared first-visibility log for the A/B harness: transports report when
/// they first surface each block's catalog swap logs; only the earliest
/// sighting per transport is kept.
#[derive(Default)]
pub struct BlockLatencyLog {
    inner: std::sync::Mutex<std::collections::HashMap<u64, BlockVisibility>>,
}

/// Sorted per-block first-visibility rows:
/// `(block, ws_first, http_first, bench_first)` in unix ms.
pub type VisibilityRow = (u64, Option<u64>, Option<u64>, Option<u64>);

impl BlockLatencyLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a sighting; keeps the earliest per transport.
    pub fn observe(&self, source: Source, block: u64, unix_ms: u64) {
        let mut map = self.inner.lock().expect("latency log poisoned");
        let entry = map.entry(block).or_default();
        let slot = match source {
            Source::Ws => &mut entry.seen_ws,
            Source::Http => &mut entry.seen_http,
            Source::Bench => &mut entry.seen_bench,
        };
        if slot.is_none_or(|seen| unix_ms < seen) {
            *slot = Some(unix_ms);
        }
    }

    /// Sorted per-block first-visibility rows (see [`VisibilityRow`]).
    #[must_use]
    pub fn snapshot_rows(&self) -> Vec<VisibilityRow> {
        let map = self.inner.lock().expect("latency log poisoned");
        let mut rows: Vec<VisibilityRow> = map
            .iter()
            .map(|(&block, v)| (block, v.seen_ws, v.seen_http, v.seen_bench))
            .collect();
        rows.sort_by_key(|(block, _, _, _)| *block);
        rows
    }
}

/// Signed delta statistics over blocks observed by both transports:
/// `http_first_ms - ws_first_ms` in milliseconds. Positive means HTTP
/// surfaced the block later than WS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbSummary {
    pub blocks: usize,
    pub p25_ms: i64,
    pub median_ms: i64,
    pub p75_ms: i64,
}

#[must_use]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn summarize_ab(deltas_ms: &mut [i64]) -> Option<AbSummary> {
    if deltas_ms.is_empty() {
        return None;
    }
    deltas_ms.sort_unstable();
    let pick = |q: f64| -> i64 {
        let idx = ((deltas_ms.len() - 1) as f64 * q).round() as usize;
        deltas_ms[idx]
    };
    Some(AbSummary {
        blocks: deltas_ms.len(),
        p25_ms: pick(0.25),
        median_ms: pick(0.5),
        p75_ms: pick(0.75),
    })
}

/// Reconnect backoff for a failed or closed subscription: doubles from
/// 250 ms and caps at 2 s, matching the provider retry policy shape.
#[must_use]
pub fn backoff_delay(attempt: u32) -> Duration {
    let shift = attempt.min(3);
    Duration::from_millis(250u64.saturating_mul(1 << shift))
}

/// Formats one progress line for the probe window.
#[must_use]
pub fn progress_line(
    elapsed_secs: u64,
    stats: &ProbeStats,
    ws_bytes: u64,
    tip_block: u64,
) -> String {
    let min_s = stats
        .lag_min_blocks()
        .map_or("-".to_owned(), |min| min.to_string());
    let mean_s = stats
        .lag_mean_blocks()
        .map_or("-".to_owned(), |mean| format!("{mean:.1}"));
    format!(
        "ws-probe: elapsed_s={} events={} dupes={} lag_blocks min/mean/max={}/{}/{} tip={} ws_bytes={} reconnects={}",
        elapsed_secs,
        stats.events,
        stats.duplicates,
        min_s,
        mean_s,
        stats.lag_max_blocks(),
        tip_block,
        ws_bytes,
        stats.reconnects,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    const ROW: &str = "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n";

    fn row(address: &str, profile: &str) -> String {
        let pool_id = match profile {
            "v4" => "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            _ => "",
        };
        row_with_pool_id(address, profile, pool_id)
    }

    fn row_with_pool_id(address: &str, profile: &str, pool_id: &str) -> String {
        format!(
            "4663,{address},0x1111111111111111111111111111111111111111,\
             0x2222222222222222222222222222222222222222,\
             0x3333333333333333333333333333333333333333,3000,1000000,\
             {profile},{pool_id},test\n"
        )
    }

    const V3_POOL_A: &str = "0x041581E21719dD203672C6dC92b9C9C4d7A2cB2C";
    const V3_POOL_B: &str = "0x0C6245651c0773516a063971eF3c517600B7C759";
    const V4_SINGLETON: &str = "0x1f7d7550B1b028f7571E69A784071F0205FD2EfA";

    #[test]
    fn subscriptions_split_venues_and_dedup_singleton() {
        let csv = format!("{ROW}{}{}", row(V3_POOL_A, "v3"), row(V3_POOL_B, "v3"))
            + &row_with_pool_id(
                V4_SINGLETON,
                "v4",
                "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )
            + &row_with_pool_id(
                V4_SINGLETON,
                "v4",
                "0xfeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
            );
        let (subs, skipped) = build_subscriptions(csv.as_bytes()).unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].label, "v3-swap");
        assert_eq!(subs[0].filter.addresses.len(), 2);
        assert_eq!(subs[0].filter.topic0, v3_swap_topic());
        assert_eq!(subs[1].label, "v4-swap");
        assert_eq!(subs[1].filter.addresses.len(), 1);
        assert_eq!(subs[1].filter.topic0, v4_swap_topic());
    }

    #[test]
    fn constant_product_only_manifest_is_an_error() {
        // A V2-only manifest offers no Swap subscriptions to open.
        let csv = ROW.to_owned() + &row(V3_POOL_A, "v2");
        assert!(build_subscriptions(csv.as_bytes()).is_err());
    }

    #[test]
    fn empty_subscription_set_is_an_error() {
        let result = build_subscriptions(ROW.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn stats_track_min_mean_max_and_merge() {
        let mut a = ProbeStats::default();
        a.observe_lag(5);
        a.observe_lag(1);
        a.observe_lag(9);
        assert_eq!(a.events, 3);
        assert_eq!(a.lag_min_blocks(), Some(1));
        assert_eq!(a.lag_max_blocks(), 9);
        let mean = a.lag_mean_blocks().unwrap();
        assert!((mean - 5.0).abs() < 1e-9);

        let mut b = ProbeStats::default();
        b.observe_lag(2);
        b.reconnects = 1;
        a.merge(&b);
        assert_eq!(a.events, 4);
        assert_eq!(a.reconnects, 1);
        assert_eq!(a.lag_min_blocks(), Some(1));
        assert_eq!(a.lag_max_blocks(), 9);
        assert!(
            a.lag_mean_blocks()
                .is_some_and(|m| (m - 17.0 / 4.0).abs() < 1e-9)
        );
    }

    #[test]
    fn empty_stats_have_no_lag_summary() {
        let stats = ProbeStats::default();
        assert_eq!(stats.lag_min_blocks(), None);
        assert_eq!(stats.lag_mean_blocks(), None);
        assert_eq!(stats.lag_max_blocks(), 0);
    }

    #[test]
    fn backoff_doubles_and_caps_at_two_seconds() {
        assert_eq!(backoff_delay(0), Duration::from_millis(250));
        assert_eq!(backoff_delay(1), Duration::from_millis(500));
        assert_eq!(backoff_delay(2), Duration::from_secs(1));
        assert_eq!(backoff_delay(3), Duration::from_secs(2));
        assert_eq!(backoff_delay(10), Duration::from_secs(2));
    }

    #[test]
    fn progress_line_renders_sparse_and_populated_states() {
        let mut stats = ProbeStats::default();
        let line = progress_line(10, &stats, 128, 100);
        assert!(line.contains("lag_blocks min/mean/max=-/-/0"));
        stats.observe_lag(3);
        let line = progress_line(20, &stats, 256, 103);
        assert!(line.contains("events=1"), "actual: {line}");
        assert!(line.contains("min/mean/max=3/3.0/3"), "actual: {line}");
        assert!(line.contains("tip=103"));
        assert!(line.contains("ws_bytes=256"));
    }

    #[test]
    fn stats_record_signed_lag_for_ws_leading_http_tip() {
        let mut stats = ProbeStats::default();
        stats.observe_lag(-12);
        stats.observe_lag(3);
        assert_eq!(stats.lag_min_blocks(), Some(-12));
        assert_eq!(stats.lag_max_blocks(), 3);
        assert!(
            stats
                .lag_mean_blocks()
                .is_some_and(|m| (m + 4.5).abs() < 1e-9)
        );
        assert_eq!(stats.events, 2);
    }

    #[test]
    fn latency_log_keeps_earliest_sighting_per_transport() {
        let log = BlockLatencyLog::new();
        log.observe(Source::Ws, 100, 1_000);
        log.observe(Source::Ws, 100, 900);
        log.observe(Source::Http, 100, 1_500);
        log.observe(Source::Http, 100, 2_000);
        assert_eq!(
            log.snapshot_rows(),
            vec![(100, Some(900), Some(1_500), None)]
        );
    }

    #[test]
    fn latency_log_rows_are_block_sorted_and_sparse() {
        let log = BlockLatencyLog::new();
        log.observe(Source::Bench, 300, 5);
        log.observe(Source::Ws, 100, 1);
        let rows = log.snapshot_rows();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], (100, Some(1), None, None));
        assert_eq!(rows[1], (300, None, None, Some(5)));
    }

    #[test]
    fn summarize_ab_reports_quartiles_and_handles_empty() {
        assert_eq!(summarize_ab(&mut []), None);
        let mut deltas = vec![100, -50, 30, 10, 0];
        let summary = summarize_ab(&mut deltas).expect("non-empty");
        assert_eq!(summary.blocks, 5);
        assert_eq!(summary.median_ms, 10);
        assert_eq!(summary.p25_ms, 0);
        assert_eq!(summary.p75_ms, 30);
    }

    #[test]
    fn deduper_flags_second_delivery_of_same_identity() {
        let envelope = |block: u64, tx: u64, log: u64| provider::RawLogEnvelope {
            address: Address::with_last_byte(0x10),
            topics: vec![],
            data: alloy_primitives::Bytes::default(),
            block_number: block,
            transaction_index: tx,
            log_index: log,
            removed: false,
            block_hash: alloy_primitives::B256::ZERO,
        };
        let mut deduper = LogDeduper::new();
        assert!(!deduper.is_duplicate(&envelope(100, 1, 2)));
        assert!(deduper.is_duplicate(&envelope(100, 1, 2)));
        assert!(!deduper.is_duplicate(&envelope(100, 1, 3)));
        assert!(!deduper.is_duplicate(&envelope(101, 1, 2)));
    }

    #[test]
    fn stats_merge_duplicates() {
        let mut a = ProbeStats {
            duplicates: 2,
            ..ProbeStats::default()
        };
        let b = ProbeStats {
            duplicates: 3,
            ..ProbeStats::default()
        };
        a.merge(&b);
        assert_eq!(a.duplicates, 5);
    }

    #[test]
    fn topic0_values_match_pinned_provider_constants() {
        // The probe must subscribe with exactly the provider-crate topics.
        let csv = ROW.to_owned() + &row(V3_POOL_A, "v3");
        let (subs, _) = build_subscriptions(csv.as_bytes()).unwrap();
        let expected: B256 = keccak256_helper();
        assert_eq!(subs[0].filter.topic0, expected);
    }

    fn keccak256_helper() -> B256 {
        use alloy_primitives::keccak256;
        keccak256("Swap(address,address,int256,int256,uint160,uint128,int24)")
    }
}
