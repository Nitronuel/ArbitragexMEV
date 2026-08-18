use std::collections::{HashMap, HashSet};

use alloy_primitives::{Address, U256};
use shadow::{ClassificationReason, CostSnapshot, Economics};
use v2_math::OptimalQuote;

use crate::gaps::{PairQuote, PoolEntry, PoolPrice, pool_key, quote_pair};

/// A normalized cross-venue pair identity: `gaps::pair_key`'s `(lo, hi)` token
/// addresses, `lo <= hi` bytewise.
pub type PairKey = ([u8; 20], [u8; 20]);

/// Bounded dirty-set with deduplication and overload degradation.
///
/// A reserve update marks the items it touched (pairs or triangle indexes); the
/// index coalesces duplicates and reports overload instead of dropping state.
/// A drained batch is returned in deterministic key order.
#[derive(Debug)]
struct DirtyQueue<T>
where
    T: std::cmp::Ord + std::hash::Hash + Copy,
{
    capacity: usize,
    pending: HashSet<T>,
    degraded: bool,
}

impl<T> DirtyQueue<T>
where
    T: std::cmp::Ord + std::hash::Hash + Copy,
{
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            pending: HashSet::new(),
            degraded: false,
        }
    }

    fn enqueue(&mut self, item: T) {
        self.pending.insert(item);
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

    fn drain(&mut self) -> Vec<T> {
        let mut keys: Vec<_> = self.pending.drain().collect();
        keys.sort_unstable();
        keys
    }

    fn len(&self) -> usize {
        self.pending.len()
    }
}

type DirtyPairQueue = DirtyQueue<PairKey>;
type DirtyTriQueue = DirtyQueue<usize>;

/// One drained dirty-pair evaluation batch.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PairRunOutcome {
    /// Pairs that produced a quote this batch (any classification).
    pub evaluated: Vec<PairKey>,
    /// Quoted pairs classified strictly above the submission-gate floor.
    pub interesting: Vec<PairKey>,
    /// Pairs whose quote failed or lacked a priced leg on either venue.
    pub not_evaluated: Vec<PairKey>,
    /// Three-hop triangles (indexes into the evaluator's triangle list) that
    /// produced a quote this batch.
    pub triangle_evaluated: Vec<usize>,
    /// Triangles whose quote cleared the submission-gate floor.
    pub triangle_interesting: Vec<usize>,
    /// Triangles whose quote failed or lacked a priced edge.
    pub triangle_not_evaluated: Vec<usize>,
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
    /// Enumerated three-hop triangles; indexes shared by `by_pool_tri`.
    triangles: Vec<crate::gaps::TokenTriple>,
    /// `(profile, pool)` -> triangle indexes touching that pool.
    by_pool_tri: HashMap<([u8; 2], [u8; 32]), HashSet<usize>>,
    profile_a: [u8; 2],
    profile_b: [u8; 2],
    prices_a: HashMap<[u8; 32], PoolPrice>,
    prices_b: HashMap<[u8; 32], PoolPrice>,
    /// USD per whole token (fixed-point), keyed by normalized token address,
    /// used to value each pair's anchor token instead of the `$1` fixture.
    token_usd: HashMap<Address, U256>,
    queue: DirtyPairQueue,
    tri_queue: DirtyTriQueue,
    economics: Economics,
    reference: CostSnapshot,
    /// Maximum `|log2 skew|` a quote may carry and still be classified
    /// normally. Larger gaps come from degenerate near-empty pools that are
    /// not captureable; they are screened out of gating instead of surfacing as
    /// `AboveThreshold` at absurd USD values (same bound as `gap-vs-toll
    /// --max-skew`).
    max_log2_skew: f64,
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
    /// pairs with at least one pool per venue, and indexes the enumerated
    /// three-hop triangles by their member pools.
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
        let triangles = crate::gaps::enumerate_triangles(
            &by_pair
                .values()
                .flat_map(|(a, _)| a.iter())
                .copied()
                .collect::<Vec<_>>(),
            &by_pair
                .values()
                .flat_map(|(_, b)| b.iter())
                .copied()
                .collect::<Vec<_>>(),
        );
        // Index each triangle by every pool that could serve one of its edges.
        let mut by_pool_tri: HashMap<([u8; 2], [u8; 32]), HashSet<usize>> = HashMap::new();
        for (index, (t0, t1, t2)) in triangles.iter().enumerate() {
            let edges = [
                crate::gaps::pair_key(Address::from_slice(t0), Address::from_slice(t1)),
                crate::gaps::pair_key(Address::from_slice(t1), Address::from_slice(t2)),
                crate::gaps::pair_key(Address::from_slice(t2), Address::from_slice(t0)),
            ];
            for edge in edges {
                let Some((a_pools, b_pools)) = by_pair.get(&edge) else {
                    continue;
                };
                for (profile, pools) in [(*b"v3", a_pools), (*b"v4", b_pools)] {
                    for entry in pools {
                        by_pool_tri
                            .entry((profile, pool_key(entry)))
                            .or_default()
                            .insert(index);
                    }
                }
            }
        }
        Self {
            by_pair,
            by_pool,
            triangles,
            by_pool_tri,
            profile_a: *b"v3",
            profile_b: *b"v4",
            prices_a: HashMap::new(),
            prices_b: HashMap::new(),
            token_usd: HashMap::new(),
            queue: DirtyPairQueue::new(queue_capacity),
            tri_queue: DirtyTriQueue::new(queue_capacity),
            economics,
            reference: CostSnapshot::invalid(),
            max_log2_skew: 0.5,
        }
    }

    /// Sets the gas-price and reference-route inputs for classification.
    pub fn set_reference(&mut self, reference: CostSnapshot) {
        self.reference = reference;
    }

    /// Bounds the `|log2 skew|` a quote may carry and still be classified
    /// normally (default `0.5`, matching `gap-vs-toll --max-skew`). Quotes
    /// above the cap are screened out of gating instead of surfacing as
    /// `AboveThreshold` at degenerate empty-pool USD values.
    pub fn set_max_log2_skew(&mut self, max_log2_skew: f64) {
        self.max_log2_skew = max_log2_skew;
    }

    /// Sets per-token USD prices (fixed-point) used to value each pair's
    /// anchor token, replacing the `$1` fixture for known tokens. Unknown
    /// tokens fall back to the reference's `usd_per_token`.
    pub fn set_token_prices(&mut self, prices: HashMap<Address, U256>) {
        self.token_usd = prices;
    }

    /// Classifies one pair's quote against the pair's anchor-token USD price.
    fn classify_pair(&self, pair: PairKey, quote: &PairQuote) -> shadow::Classification {
        if quote.log2_skew > self.max_log2_skew {
            return self.skew_screened(quote);
        }
        let mut reference = self.reference;
        let anchor = Address::from_slice(&pair.0);
        if let Some(usd) = self.token_usd.get(&anchor)
            && !usd.is_zero()
        {
            reference.usd_per_token = *usd;
        }
        let optimal = OptimalQuote {
            input: quote.input,
            output: quote.output,
            profit: quote.profit,
        };
        self.economics.classify(&optimal, &reference)
    }

    /// Marks every pair and triangle indexed by the changed pool as dirty.
    pub fn mark_pool(&mut self, profile: [u8; 2], pool: [u8; 32]) {
        if let Some(pairs) = self.by_pool.get(&(profile, pool)) {
            for &pair in pairs {
                self.queue.enqueue(pair);
            }
        }
        if let Some(tris) = self.by_pool_tri.get(&(profile, pool)) {
            for &tri in tris {
                self.tri_queue.enqueue(tri);
            }
        }
    }

    /// Caches one pool price locally and marks the affected pairs/triangles
    /// dirty.
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

    /// Number of currently queued dirty pairs and triangles.
    #[must_use]
    pub fn queue_len(&self) -> usize {
        self.queue.len() + self.tri_queue.len()
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

    /// Drains one dirty batch and classifies each affected pair and triangle
    /// against the locally cached prices and the conservative economics gate.
    pub fn run_once(&mut self) -> PairRunOutcome {
        let degraded = self.queue.take_degraded() | self.tri_queue.take_degraded();
        let batch = self.queue.drain();
        let mut outcome = PairRunOutcome {
            degraded,
            ..PairRunOutcome::default()
        };
        if batch.is_empty() && self.tri_queue.pending.is_empty() {
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

            let classification = self.classify_pair(pair, &quote);
            if matches!(classification.reason, ClassificationReason::AboveThreshold) {
                outcome.interesting.push(pair);
            }
        }

        let tri_batch = self.tri_queue.drain();
        for tri in tri_batch {
            if tri >= self.triangles.len() {
                outcome.triangle_not_evaluated.push(tri);
                continue;
            }
            let (t0, t1, t2) = self.triangles[tri];
            let t0 = Address::from_slice(&t0);
            let t1 = Address::from_slice(&t1);
            let t2 = Address::from_slice(&t2);
            let Ok(Some(quote)) = crate::gaps::quote_triangle(
                t0,
                t1,
                t2,
                &self.by_pair,
                &self.prices_a,
                &self.prices_b,
            ) else {
                outcome.triangle_not_evaluated.push(tri);
                continue;
            };
            outcome.triangle_evaluated.push(tri);

            let classification = self.classify_anchor(t0, &quote);
            if matches!(classification.reason, ClassificationReason::AboveThreshold) {
                outcome.triangle_interesting.push(tri);
            }
        }
        outcome
    }

    /// Classifies a quote against an anchor token's USD price (triangles use
    /// their `p0` anchor).
    fn classify_anchor(&self, anchor: Address, quote: &PairQuote) -> shadow::Classification {
        if quote.log2_skew > self.max_log2_skew {
            return self.skew_screened(quote);
        }
        let mut reference = self.reference;
        if let Some(usd) = self.token_usd.get(&anchor)
            && !usd.is_zero()
        {
            reference.usd_per_token = *usd;
        }
        let optimal = OptimalQuote {
            input: quote.input,
            output: quote.output,
            profit: quote.profit,
        };
        self.economics.classify(&optimal, &reference)
    }

    /// Screens a quote whose `|log2 skew|` exceeds the captureable bound.
    /// Degenerate near-empty-pool gaps are not tradeable, so they never reach
    /// economic gating (which would otherwise label them `AboveThreshold` at
    /// meaningless USD values).
    fn skew_screened(&self, quote: &PairQuote) -> shadow::Classification {
        shadow::Classification {
            gross_profit: quote.profit,
            gross_profit_usd: U256::ZERO,
            flash_cost_usd: U256::ZERO,
            gas_cost_usd: U256::ZERO,
            estimated_net_profit_usd: U256::ZERO,
            threshold_usd: U256::ZERO,
            reason: shadow::ClassificationReason::NotEvaluated {
                detail: format!(
                    "skew {} exceeds max {:.2}",
                    quote.log2_skew, self.max_log2_skew
                ),
            },
        }
    }

    /// Re-quotes one arbitrary pair from cached prices (used by tests and the
    /// unstaged CLI path). Returns the quote and its gate classification.
    #[must_use]
    pub fn quote_pair(&self, pair: PairKey) -> Option<(PairQuote, shadow::Classification)> {
        let (a_pools, b_pools) = self.by_pair.get(&pair)?;
        let quote = quote_pair(a_pools, b_pools, &self.prices_a, &self.prices_b).ok()??;
        Some((quote, self.classify_pair(pair, &quote)))
    }

    /// The enumerated triangle triple at `index`.
    #[must_use]
    pub fn triangle(&self, index: usize) -> ([u8; 20], [u8; 20], [u8; 20]) {
        self.triangles[index]
    }

    /// Re-quotes one triangle (by index) from cached prices.
    #[must_use]
    pub fn quote_triangle(&self, tri: usize) -> Option<(PairQuote, shadow::Classification)> {
        let (t0, t1, t2) = *self.triangles.get(tri)?;
        let t0 = Address::from_slice(&t0);
        let t1 = Address::from_slice(&t1);
        let t2 = Address::from_slice(&t2);
        let quote =
            crate::gaps::quote_triangle(t0, t1, t2, &self.by_pair, &self.prices_a, &self.prices_b)
                .ok()??;
        Some((quote, self.classify_anchor(t0, &quote)))
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
        evaluator.set_max_log2_skew(4.0);

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
        evaluator.set_max_log2_skew(4.0);
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
        evaluator.set_max_log2_skew(4.0);
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
        evaluator.set_max_log2_skew(4.0);
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
        evaluator.set_max_log2_skew(4.0);
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

    #[test]
    fn token_price_can_collapse_a_fixture_gated_quote() {
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        evaluator.set_reference(valid_reference());
        evaluator.set_max_log2_skew(4.0);
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
        let pair = crate::gaps::pair_key(token_a(), token_b());

        // At the $1 fixture the quote clears the gate; at a sub-cent anchor
        // price the same gross profit is dust and falls below the floor.
        let mut token_prices = HashMap::new();
        token_prices.insert(token_a(), U256::from(1_000_000));
        evaluator.set_token_prices(token_prices);
        let (_, classification) = evaluator.quote_pair(pair).expect("quote present");
        assert_ne!(classification.reason, ClassificationReason::AboveThreshold);
        // Same quote, lower anchor price: gross profit collapses proportionally.
        assert!(
            classification.gross_profit_usd < U256::from(FIXED_POINT_SCALE),
            "sub-cent anchor must not clear the gate: {classification:?}"
        );
    }

    #[test]
    fn degenerate_skew_is_screened_before_economic_gating() {
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

        // Default `max_log2_skew` is 0.5 but the 2x fixture skew is ~1.0, so
        // the same quote that clears the gate above is screened out here.
        let pair = crate::gaps::pair_key(token_a(), token_b());
        let (quote, classification) = evaluator.quote_pair(pair).expect("quote present");
        assert!(
            quote.log2_skew > evaluator.max_log2_skew,
            "fixture must exceed the default bound for this test to mean anything"
        );
        assert!(
            matches!(
                &classification.reason,
                ClassificationReason::NotEvaluated { detail }
                    if detail.contains("skew") && detail.contains("max")
            ),
            "degenerate skew must be screened with a skew detail, not gated: {classification:?}"
        );

        // Raising the bound restores normal economic gating for the same quote.
        evaluator.set_max_log2_skew(4.0);
        let (_, classification) = evaluator.quote_pair(pair).expect("quote present");
        assert_eq!(classification.reason, ClassificationReason::AboveThreshold);
    }

    /// Three cross-venue triangles on tokens `(a,b,c)`: each pool is a
    /// different venue per edge so the cyclic round trip crosses venues.
    fn triangle_fixture() -> (Vec<PoolEntry>, Vec<PoolEntry>, (Address, Address, Address)) {
        let a = token_a();
        let b = token_b();
        let c: Address = "0xc000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let v3_pools = vec![
            entry(
                "0xf300000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
                a,
                b,
                3000,
                *b"v3",
                [0u8; 32],
            ),
            entry(
                "0xf300000000000000000000000000000000000002"
                    .parse()
                    .unwrap(),
                b,
                c,
                3000,
                *b"v3",
                [0u8; 32],
            ),
            entry(
                "0xf300000000000000000000000000000000000003"
                    .parse()
                    .unwrap(),
                c,
                a,
                3000,
                *b"v3",
                [0u8; 32],
            ),
        ];
        let v4_pools = vec![
            entry(
                "0x8366a39CC670B4001A1121B8F6A443A643e40951"
                    .parse()
                    .unwrap(),
                a,
                b,
                2500,
                *b"v4",
                [0x01u8; 32],
            ),
            entry(
                "0x8366a39CC670B4001A1121B8F6A443A643e40951"
                    .parse()
                    .unwrap(),
                b,
                c,
                2500,
                *b"v4",
                [0x02u8; 32],
            ),
            entry(
                "0x8366a39CC670B4001A1121B8F6A443A643e40951"
                    .parse()
                    .unwrap(),
                c,
                a,
                2500,
                *b"v4",
                [0x03u8; 32],
            ),
        ];
        (v3_pools, v4_pools, (a, b, c))
    }

    #[test]
    fn swap_marks_touching_triangles_dirty_and_evaluates_them() {
        let (v3_pools, v4_pools, (a, b, _c)) = triangle_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&v3_pools, &v4_pools, interesting_economics(), 100);
        evaluator.set_reference(valid_reference());
        evaluator.set_max_log2_skew(200.0);
        assert_eq!(evaluator.triangles.len(), 1, "one triangle expected");
        let tri = evaluator.triangles[0];
        assert_eq!(
            Address::from_slice(&tri.0),
            a,
            "triangle sorted by normalized address (token_a) is the anchor"
        );
        assert_eq!(Address::from_slice(&tri.1), b);

        // Nothing priced -> the single triangle cannot be quoted.
        assert!(evaluator.run_once().triangle_evaluated.is_empty());

        // Price all three v3 legs; the cheapest cross-venue leg per edge now
        // exists, so the triangle is quoted even on one venue alone.
        for (i, pool) in v3_pools.iter().enumerate() {
            let shift = u32::try_from(i).unwrap_or(0);
            evaluator.apply_swap(
                *b"v3",
                pool.venue.into_word().into(),
                price(
                    U256::from(1u64) << (96 + shift),
                    10_000_000_000_000_000_000_000,
                    1,
                ),
            );
        }
        let outcome = evaluator.run_once();
        assert_eq!(outcome.triangle_evaluated.len(), 1, "triangle quoted");

        // Re-quote via the accessor; the closed-form optimal input returns a
        // quote and classification is computed through the economics gate.
        let (quote, classification) = evaluator.quote_triangle(0).expect("triangle re-quote");
        assert!(quote.profit > U256::ZERO, "profitable drift expected");
        assert_eq!(classification.reason, ClassificationReason::AboveThreshold);
    }
}
