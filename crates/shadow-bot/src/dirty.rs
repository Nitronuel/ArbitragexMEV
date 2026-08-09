use std::collections::{HashMap, HashSet};

use shadow::{ClassificationReason, CostSnapshot, Economics};
use v2_math::OptimalQuote;

use crate::gaps::{PairQuote, PoolEntry, PoolPrice, pool_key, quote_pair};

/// A normalized cross-venue pair identity: `gaps::pair_key`'s `(lo, hi)` token
/// addresses, `lo <= hi` bytewise.
pub type PairKey = ([u8; 20], [u8; 20]);

/// Bounded dirty-pair set with deduplication and overload degradation.
///
/// A reserve update marks the pools it touched; the index expands each pool to
/// its indexed pairs, coalesces duplicates, and reports overload instead of
/// dropping state. A drained batch is returned in deterministic pair order.
#[derive(Debug)]
struct DirtyPairQueue {
    capacity: usize,
    pending: HashSet<PairKey>,
    degraded: bool,
}

impl DirtyPairQueue {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            pending: HashSet::new(),
            degraded: false,
        }
    }

    fn enqueue(&mut self, pair: PairKey) {
        self.pending.insert(pair);
        if self.pending.len() > self.capacity {
            self.degraded = true;
        }
    }

    #[must_use]
    fn take_degraded(&mut self) -> bool {
        let degraded = self.degraded;
        self.degraded = false;
        degraded
    }

    fn drain(&mut self) -> Vec<PairKey> {
        let mut keys: Vec<_> = self.pending.drain().collect();
        keys.sort_unstable();
        keys
    }
}

/// One drained dirty-pair evaluation batch.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PairRunOutcome {
    /// Pairs that produced a quote this batch (any classification).
    pub evaluated: Vec<PairKey>,
    /// Quoted pairs classified strictly above the submission-gate floor.
    pub interesting: Vec<PairKey>,
    /// Pairs whose quote failed or lacked a priced leg on either venue.
    pub not_evaluated: Vec<PairKey>,
    /// The dirty queue exceeded its configured capacity this batch.
    pub degraded: bool,
}

/// Re-quotes only the cross-venue pairs whose pools changed, from locally
/// cached prices, and classifies each through the conservative economics gate.
///
/// Pool state is kept locally as `PoolPrice` snapshots fed by `apply_swap`
/// (never an `eth_call` per quote). A swap marks only the pairs indexed by
/// that pool, never the whole graph. Quotes are screening classifications
/// only — this component never simulates, signs, or submits.
pub struct PairDirtyEvaluator {
    by_pair: HashMap<PairKey, (Vec<PoolEntry>, Vec<PoolEntry>)>,
    by_pool: HashMap<([u8; 2], [u8; 32]), HashSet<PairKey>>,
    profile_a: [u8; 2],
    profile_b: [u8; 2],
    prices_a: HashMap<[u8; 32], PoolPrice>,
    prices_b: HashMap<[u8; 32], PoolPrice>,
    queue: DirtyPairQueue,
    economics: Economics,
    reference: CostSnapshot,
}

impl PairDirtyEvaluator {
    /// Builds the pair index from the two venue pool sets. Pools are grouped
    /// into cross-venue pairs by their normalized token pair, mirroring
    /// `gaps::quote_manifest`.
    #[must_use]
    pub fn new(
        a: &[PoolEntry],
        b: &[PoolEntry],
        economics: Economics,
        queue_capacity: usize,
    ) -> Self {
        let mut by_pair: HashMap<PairKey, (Vec<PoolEntry>, Vec<PoolEntry>)> = HashMap::new();
        for entry in a {
            by_pair
                .entry(crate::gaps::pair_key(entry.token0, entry.token1))
                .or_default()
                .0
                .push(*entry);
        }
        for entry in b {
            let Some((_a, b_pools)) =
                by_pair.get_mut(&crate::gaps::pair_key(entry.token0, entry.token1))
            else {
                continue;
            };
            b_pools.push(*entry);
        }
        Self::from_indexed_pairs(by_pair, economics, queue_capacity)
    }

    /// Builds the evaluator around an already-grouped pair map, keeping only
    /// pairs with at least one pool per venue.
    fn from_indexed_pairs(
        by_pair: HashMap<PairKey, (Vec<PoolEntry>, Vec<PoolEntry>)>,
        economics: Economics,
        queue_capacity: usize,
    ) -> Self {
        let mut by_pool: HashMap<([u8; 2], [u8; 32]), HashSet<PairKey>> = HashMap::new();
        for (profile, side) in [(*b"v3", 0usize), (*b"v4", 1usize)] {
            for (pair, (a_pools, b_pools)) in &by_pair {
                let pools = if side == 0 { a_pools } else { b_pools };
                for entry in pools {
                    if entry.profile == profile {
                        by_pool
                            .entry((profile, pool_key(entry)))
                            .or_default()
                            .insert(*pair);
                    }
                }
            }
        }
        let by_pair: HashMap<PairKey, (Vec<PoolEntry>, Vec<PoolEntry>)> = by_pair
            .into_iter()
            .filter(|(_, (a, b))| !a.is_empty() && !b.is_empty())
            .collect();
        Self {
            by_pair,
            by_pool,
            profile_a: *b"v3",
            profile_b: *b"v4",
            prices_a: HashMap::new(),
            prices_b: HashMap::new(),
            queue: DirtyPairQueue::new(queue_capacity),
            economics,
            reference: CostSnapshot::invalid(),
        }
    }

    /// Sets the gas-price and reference-route inputs for classification.
    pub fn set_reference(&mut self, reference: CostSnapshot) {
        self.reference = reference;
    }

    /// Marks every pair indexed by the changed pool as dirty.
    pub fn mark_pool(&mut self, profile: [u8; 2], pool: [u8; 32]) {
        if let Some(pairs) = self.by_pool.get(&(profile, pool)) {
            for &pair in pairs {
                self.queue.enqueue(pair);
            }
        }
    }

    /// Caches one pool price locally and marks the affected pairs dirty.
    ///
    /// This is the event hook for a `Sync`/`Swap`: the price is kept in
    /// process and only pairs whose pools changed are re-quoted.
    pub fn apply_swap(&mut self, profile: [u8; 2], pool: [u8; 32], price: PoolPrice) {
        if profile == self.profile_b {
            self.prices_b.insert(pool, price);
        } else if profile == self.profile_a {
            self.prices_a.insert(pool, price);
        }
        self.mark_pool(profile, pool);
    }

    /// Number of currently queued dirty pairs.
    #[must_use]
    pub fn queue_len(&self) -> usize {
        self.queue.pending.len()
    }

    /// Seeds local prices from a sweep result, marking affected pairs dirty as
    /// each price is applied.
    ///
    /// # Errors
    ///
    /// Returns a message if a pool carries the wrong profile for its venue.
    pub fn seed_prices(
        &mut self,
        profile: [u8; 2],
        entries: &[PoolEntry],
        prices: &HashMap<[u8; 32], PoolPrice>,
    ) -> Result<(), String> {
        for entry in entries {
            if entry.profile != profile {
                return Err(format!(
                    "pool {:?} is not on the {:?} venue",
                    entry.venue, profile
                ));
            }
            let key = pool_key(entry);
            if let Some(price) = prices.get(&key) {
                self.apply_swap(profile, key, *price);
            }
        }
        Ok(())
    }

    /// Drains one dirty batch and classifies each affected pair against the
    /// locally cached prices and the conservative economics gate.
    pub fn run_once(&mut self) -> PairRunOutcome {
        let degraded = self.queue.take_degraded();
        let batch = self.queue.drain();
        let mut outcome = PairRunOutcome {
            degraded,
            ..PairRunOutcome::default()
        };
        if batch.is_empty() {
            return outcome;
        }

        for pair in batch {
            let Some((a_pools, b_pools)) = self.by_pair.get(&pair) else {
                outcome.not_evaluated.push(pair);
                continue;
            };
            let Ok(Some(quote)) = quote_pair(a_pools, b_pools, &self.prices_a, &self.prices_b)
            else {
                outcome.not_evaluated.push(pair);
                continue;
            };
            outcome.evaluated.push(pair);

            let optimal = OptimalQuote {
                input: quote.input,
                output: quote.output,
                profit: quote.profit,
            };
            let classification = self.economics.classify(&optimal, &self.reference);
            if matches!(classification.reason, ClassificationReason::AboveThreshold) {
                outcome.interesting.push(pair);
            }
        }
        outcome
    }

    /// Re-quotes one arbitrary pair from cached prices (used by tests and the
    /// unstaged CLI path). Returns the quote and its gate classification.
    #[must_use]
    pub fn quote_pair(&self, pair: PairKey) -> Option<(PairQuote, shadow::Classification)> {
        let (a_pools, b_pools) = self.by_pair.get(&pair)?;
        let quote = quote_pair(a_pools, b_pools, &self.prices_a, &self.prices_b).ok()??;
        let optimal = OptimalQuote {
            input: quote.input,
            output: quote.output,
            profit: quote.profit,
        };
        let classification = self.economics.classify(&optimal, &self.reference);
        Some((quote, classification))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use shadow::{ClassificationReason, FIXED_POINT_SCALE};

    const WEI: u128 = FIXED_POINT_SCALE;

    fn entry(
        venue: Address,
        token0: Address,
        token1: Address,
        fee: u32,
        profile: [u8; 2],
        id: [u8; 32],
    ) -> PoolEntry {
        PoolEntry {
            profile,
            venue,
            id,
            fee,
            token0,
            token1,
            fee_denominator: 1_000_000,
            factory: Address::repeat_byte(1),
            chain_id: 4663,
        }
    }

    fn price(sqrt: U256, liquidity: u128, block: u64) -> PoolPrice {
        PoolPrice {
            sqrt,
            liquidity: U256::from(liquidity),
            block,
        }
    }

    fn token_a() -> Address {
        "0x1000000000000000000000000000000000000000"
            .parse()
            .unwrap()
    }

    fn token_b() -> Address {
        "0x2000000000000000000000000000000000000000"
            .parse()
            .unwrap()
    }

    fn usd(amount: u128) -> U256 {
        U256::from(amount) * U256::from(WEI)
    }

    fn interesting_economics() -> Economics {
        Economics {
            flash_fee_rate: U256::ZERO,
            gas_cost_usd: usd(1),
            expected_win_rate: U256::from(WEI),
        }
    }

    fn valid_reference() -> CostSnapshot {
        CostSnapshot {
            usd_per_token: U256::from(WEI),
            gas_price_age_valid: true,
            reference_price_valid: true,
        }
    }

    fn one_pair_fixture() -> (Vec<PoolEntry>, Vec<PoolEntry>, [u8; 32], [u8; 32]) {
        let a = token_a();
        let b = token_b();
        let a_pool = entry(
            "0xfa00000000000000000000000000000000000001"
                .parse()
                .unwrap(),
            a,
            b,
            3000,
            *b"v3",
            [0u8; 32],
        );
        let b_pool = entry(
            "0x8366a39CC670B4001A1121B8F6A443A643e40951"
                .parse()
                .unwrap(),
            a,
            b,
            2500,
            *b"v4",
            [0x33u8; 32],
        );
        let key_a = a_pool.venue.into_word().into();
        let key_b = b_pool.id;
        (vec![a_pool], vec![b_pool], key_a, key_b)
    }

    #[test]
    fn swap_rechecks_only_pairs_indexed_by_that_pool() {
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        evaluator.set_reference(valid_reference());

        // No prices -> nothing evaluated on a run with no marks.
        assert!(evaluator.run_once().evaluated.is_empty());

        // Price one leg only: the pair still lacks a priced leg on venue B,
        // so it is not quoted.
        evaluator.apply_swap(
            *b"v3",
            key_a,
            price(U256::from(1u64) << 97, 10_000_000_000_000_000_000_000, 1),
        );
        let outcome = evaluator.run_once();
        assert!(outcome.evaluated.is_empty());
        assert_eq!(outcome.not_evaluated.len(), 1);

        // Price the second leg at a skew across the toll: the same pool mark
        // re-checks the pair, and the quote is classified above the gate.
        evaluator.apply_swap(
            *b"v4",
            key_b,
            price(U256::from(1u64) << 98, 10_000_000_000_000_000_000_000, 2),
        );
        assert_eq!(evaluator.queue_len(), 1);
        let outcome = evaluator.run_once();
        assert_eq!(outcome.evaluated.len(), 1);
        assert_eq!(outcome.interesting.len(), 1);
    }

    #[test]
    fn duplicate_marks_coalesce_before_evaluation() {
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        evaluator.set_reference(valid_reference());
        evaluator.apply_swap(
            *b"v3",
            key_a,
            price(U256::from(1u64) << 97, 10_000_000_000_000_000_000_000, 1),
        );
        evaluator.apply_swap(
            *b"v3",
            key_a,
            price(U256::from(1u64) << 97, 10_000_000_000_000_000_000_000, 2),
        );
        evaluator.apply_swap(
            *b"v4",
            key_b,
            price(U256::from(1u64) << 98, 10_000_000_000_000_000_000_000, 2),
        );

        evaluator.mark_pool(*b"v3", key_a);
        assert_eq!(evaluator.queue_len(), 1);
        let outcome = evaluator.run_once();
        assert_eq!(outcome.evaluated.len(), 1);
    }

    #[test]
    fn overload_degrades_without_dropping_queued_pairs() {
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator = PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 0);
        evaluator.set_reference(valid_reference());
        evaluator.apply_swap(
            *b"v3",
            key_a,
            price(U256::from(1u64) << 97, 10_000_000_000_000_000_000_000, 1),
        );
        evaluator.apply_swap(
            *b"v4",
            key_b,
            price(U256::from(1u64) << 98, 10_000_000_000_000_000_000_000, 2),
        );

        evaluator.mark_pool(*b"v3", key_a);
        let outcome = evaluator.run_once();
        assert!(outcome.degraded);
        assert!(!outcome.evaluated.is_empty());
    }

    #[test]
    fn stale_reference_suppresses_interesting_classification() {
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        let mut reference = valid_reference();
        reference.gas_price_age_valid = false;
        evaluator.set_reference(reference);

        evaluator.apply_swap(
            *b"v3",
            key_a,
            price(U256::from(1u64) << 97, 10_000_000_000_000_000_000_000, 1),
        );
        evaluator.apply_swap(
            *b"v4",
            key_b,
            price(U256::from(1u64) << 98, 10_000_000_000_000_000_000_000, 2),
        );

        let outcome = evaluator.run_once();
        assert_eq!(outcome.evaluated.len(), 1);
        assert!(outcome.interesting.is_empty());
    }

    #[test]
    fn gate_uses_gas_cost_over_expected_win_rate() {
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        evaluator.set_reference(valid_reference());
        evaluator.apply_swap(
            *b"v3",
            key_a,
            price(U256::from(1u64) << 97, 10_000_000_000_000_000_000_000, 1),
        );
        evaluator.apply_swap(
            *b"v4",
            key_b,
            price(U256::from(1u64) << 98, 10_000_000_000_000_000_000_000, 2),
        );

        // The gate floor is `gas_cost_usd / expected_win_rate`; the fixture
        // economics uses a $1 gate with a 1.0 win rate, so the quote is above
        // the threshold exactly when gross profit is large enough to clear it.
        let pair = crate::gaps::pair_key(token_a(), token_b());
        let (quote, classification) = evaluator.quote_pair(pair).expect("quote present");
        assert!(
            quote.profit > U256::ZERO,
            "profit must be positive: {quote:?}"
        );
        assert_eq!(classification.reason, ClassificationReason::AboveThreshold);
    }
}
