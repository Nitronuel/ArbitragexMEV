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
    pub reconnects: u64,
    lag_sum_blocks: u128,
    lag_max_blocks: u64,
    lag_min_blocks: Option<u64>,
    lag_samples: u64,
}

impl ProbeStats {
    /// Records one delivered log observed `lag` blocks behind the chain tip.
    pub fn observe_lag(&mut self, lag: u64) {
        self.events += 1;
        self.lag_sum_blocks += u128::from(lag);
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
    pub const fn lag_min_blocks(&self) -> Option<u64> {
        self.lag_min_blocks
    }

    #[must_use]
    pub const fn lag_max_blocks(&self) -> u64 {
        self.lag_max_blocks
    }

    /// Merges another stats object into this one (window-level rollup).
    pub fn merge(&mut self, other: &ProbeStats) {
        self.events += other.events;
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
        "ws-probe: elapsed_s={} events={} lag_blocks min/mean/max={}/{}/{} tip={} ws_bytes={} reconnects={}",
        elapsed_secs,
        stats.events,
        min_s,
        mean_s,
        stats.lag_max_blocks(),
        tip_block,
        ws_bytes,
        stats.reconnects,
    )
}

/// Validates that a log envelope's block is not ahead of the observed tip by
/// more than `max_ahead` blocks (clock/branch skew guard).
#[must_use]
pub fn lag_or_skew(block_number: u64, tip: u64, max_ahead: u64) -> Option<u64> {
    if block_number > tip.saturating_add(max_ahead) {
        return None;
    }
    Some(tip.saturating_sub(block_number))
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
        let csv = format!("{ROW}{}{}", row(V3_POOL_A, "v3"), row(V3_POOL_B, "v3"),)
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
        assert_eq!(backoff_delay(2), Duration::from_millis(1000));
        assert_eq!(backoff_delay(3), Duration::from_millis(2000));
        assert_eq!(backoff_delay(10), Duration::from_millis(2000));
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
    fn lag_or_skew_rejects_absurdly_future_blocks() {
        assert_eq!(lag_or_skew(95, 100, 2), Some(5));
        assert_eq!(lag_or_skew(101, 100, 2), Some(0));
        assert_eq!(lag_or_skew(103, 100, 2), None);
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
