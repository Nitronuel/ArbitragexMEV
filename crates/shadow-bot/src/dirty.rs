use std::collections::{HashMap, HashSet};

use alloy_primitives::{Address, U256};
use shadow::{ClassificationReason, CostSnapshot, Economics};
use v2_math::OptimalQuote;

use crate::gaps::{PairQuote, PoolEntry, PoolPrice, pool_key};

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

/// Backstop age bound: a cached price this many blocks behind the tip screens
/// even when sweep coverage claims continuity. Generous by design — under
/// complete coverage an untraded pool's price stays economically valid, so
/// this only catches pathological cases (multi-day stalls, restarts against a
/// moved chain).
pub const DEFAULT_MAX_LEG_AGE_BLOCKS: u64 = 50_000;

/// Default maximum `|block_a - block_b|` across the priced candidate pools of
/// one quote. Wider spreads compose leg prices from disjoint market states —
/// the time-mosaic that fabricated canary gate-passes.
pub const DEFAULT_MAX_LEG_AGE_SPREAD_BLOCKS: u64 = 2_000;

/// Default capacity-overshoot bound: a quote whose unclamped optimal input
/// exceeds every leg's single-tick capacity by more than this factor is
/// screened rather than gated on its clamped remainder (audit S1). The
/// canary's recorded gate-passers overshot by ~60–400×; the model behind
/// those numbers cannot see tick boundaries, so large overshoots are fiction,
/// not opportunity.
pub const DEFAULT_MAX_CAPACITY_OVERSHOOT: f64 = 4.0;

/// One drained dirty-pair evaluation batch.
#[derive(Debug, Default)]
pub struct PairRunOutcome {
    /// Pairs that produced a quote this batch (any classification).
    pub evaluated: Vec<PairKey>,
    /// Quotes and classifications parallel to [`Self::evaluated`] (same
    /// order), so callers never re-quote to inspect or log a result.
    pub pair_results: Vec<(crate::gaps::PairQuote, shadow::Classification)>,
    /// Quoted pairs classified strictly above the submission-gate floor.
    pub interesting: Vec<PairKey>,
    /// Pairs whose quote failed or lacked a priced leg on either venue.
    pub not_evaluated: Vec<PairKey>,
    /// Three-hop triangles (indexes into the evaluator's triangle list) that
    /// produced a quote this batch.
    pub triangle_evaluated: Vec<usize>,
    /// Quotes and classifications parallel to [`Self::triangle_evaluated`]
    /// (same order).
    pub triangle_results: Vec<(crate::gaps::PairQuote, shadow::Classification)>,
    /// Triangles whose quote cleared the submission-gate floor.
    pub triangle_interesting: Vec<usize>,
    /// Triangles whose quote failed or lacked a priced edge.
    pub triangle_not_evaluated: Vec<usize>,
    /// Pairs screened because a priced candidate pool's sweep coverage is
    /// broken (or its price breached the age backstop). Each entry carries the
    /// screening detail. These pairs are *not* evaluated economically.
    pub stale_screened: Vec<(PairKey, String)>,
    /// Triangles screened for the same reason, parallel semantics.
    pub triangle_stale_screened: Vec<(usize, String)>,
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
    /// How each quote's borrow cost is selected. Quotes whose anchor has no
    /// configured flash-loan source are never gated.
    flash: shadow::flash_loan::FlashSelection,
    /// Chain tip as of the latest poll. `None` (fixtures) disables staleness
    /// screening entirely; the live loop always sets it.
    tip: Option<u64>,
    /// Block through which each venue-A pool's sweep coverage is known
    /// continuous: the pool's chunk was swept up to this block, so absence of
    /// events really does mean unchanged reserves.
    covered_a: HashMap<[u8; 32], u64>,
    /// Same guarantee for venue B.
    covered_b: HashMap<[u8; 32], u64>,
    /// Backstop age bound: a cached price older than this many blocks behind
    /// the tip screens even when coverage claims continuity.
    max_leg_age_blocks: u64,
    /// Capacity-overshoot factor above which a quote is screened (see the
    /// `DEFAULT_MAX_CAPACITY_OVERSHOOT` doc).
    max_capacity_overshoot: f64,
    /// Maximum `|block_a - block_b|` across the priced candidate pools of one
    /// quote; wider spreads compose prices from disjoint market states.
    max_leg_age_spread_blocks: u64,
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
            flash: shadow::flash_loan::FlashSelection::None,
            tip: None,
            covered_a: HashMap::new(),
            covered_b: HashMap::new(),
            max_leg_age_blocks: DEFAULT_MAX_LEG_AGE_BLOCKS,
            max_leg_age_spread_blocks: DEFAULT_MAX_LEG_AGE_SPREAD_BLOCKS,
            max_capacity_overshoot: DEFAULT_MAX_CAPACITY_OVERSHOOT,
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

    /// Sets how each quote's borrow cost is selected. In
    /// [`FlashSelection::Auto`] mode a quote whose anchor token has no
    /// supporting provider is screened `NotEvaluated` (fail-closed) instead of
    /// gating at an assumed rate.
    pub fn set_flash_selection(&mut self, flash: shadow::flash_loan::FlashSelection) {
        self.flash = flash;
    }

    /// Records the chain tip as of the latest poll. Enables staleness
    /// screening: without a tip there is no age or coverage reference, so the
    /// screens stay dormant (legacy fixture behaviour).
    pub fn set_tip(&mut self, tip: u64) {
        self.tip = Some(tip);
    }

    /// Overrides the staleness bounds (defaults
    /// [`DEFAULT_MAX_LEG_AGE_BLOCKS`] / [`DEFAULT_MAX_LEG_AGE_SPREAD_BLOCKS`]).
    pub fn set_staleness_bounds(
        &mut self,
        max_leg_age_blocks: u64,
        max_leg_age_spread_blocks: u64,
    ) {
        self.max_leg_age_blocks = max_leg_age_blocks;
        self.max_leg_age_spread_blocks = max_leg_age_spread_blocks;
    }

    /// Overrides the single-tick capacity overshoot bound (default
    /// [`DEFAULT_MAX_CAPACITY_OVERSHOOT`]). `f64::INFINITY` disables the
    /// screen — used by fixtures exercising the gating paths, whose thin
    /// synthetic ranges overshoot by design.
    pub fn set_max_capacity_overshoot(&mut self, max_capacity_overshoot: f64) {
        self.max_capacity_overshoot = max_capacity_overshoot;
    }

    /// Marks every pool in `entries` as observed through `through` on its
    /// venue. The live loop calls this once per poll with the pools whose
    /// address-chunk (V3) or singleton stream (V4) the sweep actually covered,
    /// *including* pools that emitted no events: under complete local
    /// coverage, no events means unchanged reserves.
    ///
    /// A sweep that returned an error must not mark — partial coverage is no
    /// coverage.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn mark_swept(&mut self, profile: [u8; 2], entries: &[PoolEntry], through: u64) {
        let covered = if profile == self.profile_b {
            &mut self.covered_b
        } else if profile == self.profile_a {
            &mut self.covered_a
        } else {
            return;
        };
        for entry in entries {
            covered.insert(pool_key(entry), through);
        }
    }

    /// Same as [`Self::mark_swept`] but takes precomputed pool keys with
    /// their individual covered-through blocks — the shape
    /// [`crate::gaps::RingSweepOutcome::covered_keys`] reports when catch-up
    /// capping leaves chunks at different depths.
    pub fn mark_swept_keys(&mut self, profile: [u8; 2], covered: &[([u8; 32], u64)]) {
        let covered_map = if profile == self.profile_b {
            &mut self.covered_b
        } else if profile == self.profile_a {
            &mut self.covered_a
        } else {
            return;
        };
        for (key, through) in covered {
            covered_map.insert(*key, *through);
        }
    }

    /// Screens one pair's priced candidate pools against sweep coverage, the
    /// age backstop, and the leg-spread bound.
    ///
    /// Rationale: `quote_pair`'s best-leg selection picks among *priced*
    /// pools, so a quote is only as trustworthy as the least-vouched pool it
    /// could select. If any priced candidate's chunk was not continuously
    /// swept through the tip, its cached price may silently miss trades (the
    /// ring sweep, WS drops, decode failures all look identical to "no
    /// events"), and the pair is screened instead of quoted.
    ///
    /// Returns `None` when screening is disabled (no tip set) or everything
    /// passes; `Some(detail)` explains the screen.
    fn staleness_screen(&self, pair: PairKey) -> Option<String> {
        let tip = self.tip?;
        let (a_pools, b_pools) = self.by_pair.get(&pair)?;
        let mut oldest: Option<u64> = None;
        let mut newest: Option<u64> = None;
        let mut check = |pools: &[PoolEntry],
                         prices: &HashMap<[u8; 32], PoolPrice>,
                         covered: &HashMap<[u8; 32], u64>,
                         venue: &str|
         -> Result<(), String> {
            for entry in pools {
                let key = pool_key(entry);
                let Some(price) = prices.get(&key) else {
                    continue;
                };
                let swept_through = covered.get(&key).copied().unwrap_or(0);
                if swept_through < tip {
                    return Err(format!(
                        "coverage gap: {venue} pool 0x{} swept through {swept_through}, tip {tip}",
                        alloy_primitives::hex::encode(key)
                    ));
                }
                let age = tip.saturating_sub(price.block);
                if age > self.max_leg_age_blocks {
                    return Err(format!(
                        "leg age {age} blocks exceeds max {}",
                        self.max_leg_age_blocks
                    ));
                }
                oldest = Some(oldest.map_or(price.block, |o: u64| o.min(price.block)));
                newest = Some(newest.map_or(price.block, |n: u64| n.max(price.block)));
            }
            Ok(())
        };
        if let Err(detail) = check(a_pools, &self.prices_a, &self.covered_a, "v3") {
            return Some(detail);
        }
        if let Err(detail) = check(b_pools, &self.prices_b, &self.covered_b, "v4") {
            return Some(detail);
        }
        if let (Some(oldest), Some(newest)) = (oldest, newest) {
            let spread = newest.saturating_sub(oldest);
            if spread > self.max_leg_age_spread_blocks {
                return Some(format!(
                    "leg spread {spread} blocks exceeds max {}",
                    self.max_leg_age_spread_blocks
                ));
            }
        }
        None
    }

    /// Sets per-token USD prices (fixed-point) used to value each pair's
    /// anchor token, replacing the `$1` fixture for known tokens. Unknown
    /// tokens fall back to the reference's `usd_per_token`.
    pub fn set_token_prices(&mut self, prices: HashMap<Address, U256>) {
        self.token_usd = prices;
    }

    /// Whether the token carries a non-zero USD price in the loaded prices
    /// table. `false` means classification fell back to the `$1` fixture —
    /// such rows are flagged in the canary CSV so stale-reference artifacts
    /// priced at a meaningless `$1`/token are visible instead of silent.
    #[must_use]
    pub fn token_is_priced(&self, token: Address) -> bool {
        self.token_usd.get(&token).is_some_and(|usd| !usd.is_zero())
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
            if let Some(detail) = self.staleness_screen(pair) {
                outcome.stale_screened.push((pair, detail));
                continue;
            }
            // Audit S3a: anchor by executability — flash-borrowable AND
            // USD-priced wins; deterministic lower-address tiebreak. The
            // legacy lexicographic choice excluded native-anchored pairs (the
            // chain's highest-volume) from honest gating entirely.
            let anchor = self.select_anchor(pair);
            let Ok(Some(quote)) = crate::gaps::quote_pair_anchored(
                a_pools,
                b_pools,
                &self.prices_a,
                &self.prices_b,
                Some(anchor),
            ) else {
                outcome.not_evaluated.push(pair);
                continue;
            };
            outcome.evaluated.push(pair);

            let classification = self.classify_anchor(anchor, &quote);
            if matches!(classification.reason, ClassificationReason::AboveThreshold) {
                outcome.interesting.push(pair);
            }
            outcome.pair_results.push((quote, classification));
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
            let edges = [
                crate::gaps::pair_key(t0, t1),
                crate::gaps::pair_key(t1, t2),
                crate::gaps::pair_key(t2, t0),
            ];
            if let Some(detail) = edges.iter().find_map(|edge| self.staleness_screen(*edge)) {
                outcome.triangle_stale_screened.push((tri, detail));
                continue;
            }
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
            outcome.triangle_results.push((quote, classification));
        }
        outcome
    }

    /// Classifies a quote against an anchor token's USD price (triangles use
    /// their `p0` anchor). Pairs delegate here after resolving their anchor.
    fn classify_anchor(&self, anchor: Address, quote: &PairQuote) -> shadow::Classification {
        if quote.log2_skew > self.max_log2_skew {
            return self.skew_screened(quote);
        }
        let mut reference = self.reference;
        self.classify_with_flash(
            anchor,
            quote,
            &mut reference,
            shadow::TRIANGLE_EXECUTION_GAS_UNITS,
        )
    }

    /// Shared classification body once skew/age screens have passed and the
    /// anchor is known. Charges the selected flash-loan rate against the
    /// gross profit; fail-closed when no provider supports the anchor.
    fn classify_with_flash(
        &self,
        anchor: Address,
        quote: &PairQuote,
        reference: &mut CostSnapshot,
        gas_units: u64,
    ) -> shadow::Classification {
        // Audit A8: `NaN > x` is false, so a NaN skew silently PASSED the
        // skew screen and gated on garbage. Reject anything non-finite
        // before any magnitude comparison.
        if !quote.log2_skew.is_finite() {
            return shadow::Classification {
                gross_profit: quote.profit,
                gross_profit_usd: U256::ZERO,
                flash_cost_usd: U256::ZERO,
                gas_cost_usd: U256::ZERO,
                estimated_net_profit_usd: U256::ZERO,
                threshold_usd: U256::ZERO,
                shortfall_usd: U256::ZERO,
                reason: ClassificationReason::NotEvaluated {
                    detail: format!("skew {} is not finite", quote.log2_skew),
                },
            };
        }
        // Single-tick capacity screen (audit S1): the constant-product model
        // is exact only inside the sampled liquidity cell. A quote whose
        // optimum demands far more than any leg can absorb there is priced
        // by liquidity that may not exist — screen instead of gate.
        if quote.optimal_unclamped > U256::ZERO {
            // Quotients of U256s, saturating to u128 — plenty of dynamic
            // range for a screening ratio, and no panic path.
            let cap = quote.input_capacity.min(U256::from(u128::MAX)).to::<u128>();
            let unc = quote
                .optimal_unclamped
                .min(U256::from(u128::MAX))
                .to::<u128>();
            let ratio = if cap == 0 {
                f64::INFINITY
            } else {
                // Precision loss is irrelevant for a screening ratio.
                #[allow(clippy::cast_precision_loss)]
                {
                    unc as f64 / cap as f64
                }
            };
            if ratio > self.max_capacity_overshoot {
                return shadow::Classification {
                    gross_profit: quote.profit,
                    gross_profit_usd: U256::ZERO,
                    flash_cost_usd: U256::ZERO,
                    gas_cost_usd: U256::ZERO,
                    estimated_net_profit_usd: U256::ZERO,
                    threshold_usd: U256::ZERO,
                    shortfall_usd: U256::ZERO,
                    reason: shadow::ClassificationReason::NotEvaluated {
                        detail: format!(
                            "optimal input {} exceeds single-tick capacity {} by {ratio:.1}x",
                            quote.optimal_unclamped, quote.input_capacity
                        ),
                    },
                };
            }
        }
        if let Some(usd) = self.token_usd.get(&anchor)
            && !usd.is_zero()
        {
            reference.usd_per_token = *usd;
        }
        let Some(flash_fee_rate) = self.flash.rate_for(anchor) else {
            return Self::unsupported_flash_screened(anchor, quote);
        };
        let economics = Economics {
            flash_fee_rate,
            ..self.economics
        };
        let optimal = OptimalQuote {
            input: quote.input,
            output: quote.output,
            profit: quote.profit,
        };
        let mut classification = economics.classify_route(&optimal, reference, gas_units, None);
        if matches!(classification.reason, ClassificationReason::AboveThreshold)
            && !self.token_is_priced(anchor)
        {
            // Audit S3c/A12: the gate passed only at the `$1` fixture
            // valuation — a fabricated price. An anchor that cannot be priced
            // means the opportunity cannot be valued; say so instead of
            // passing it at a made-up number.
            classification.reason = ClassificationReason::NotEvaluated {
                detail: format!("anchor {anchor} unpriced; opportunity cannot be valued"),
            };
            // Every USD figure above was computed at the $1 fixture — fiction.
            // Zero them so no consumer reads a valued number out of a screen.
            classification.gross_profit_usd = U256::ZERO;
            classification.flash_cost_usd = U256::ZERO;
            classification.gas_cost_usd = U256::ZERO;
            classification.estimated_net_profit_usd = U256::ZERO;
            classification.threshold_usd = U256::ZERO;
            classification.shortfall_usd = U256::ZERO;
        }
        classification
    }

    /// Screens a quote whose anchor token has no configured flash-loan
    /// source. Without a borrow-cost model the gate would silently assume
    /// free capital, so such quotes are never classified economically.
    fn unsupported_flash_screened(anchor: Address, quote: &PairQuote) -> shadow::Classification {
        shadow::Classification {
            gross_profit: quote.profit,
            gross_profit_usd: U256::ZERO,
            flash_cost_usd: U256::ZERO,
            gas_cost_usd: U256::ZERO,
            estimated_net_profit_usd: U256::ZERO,
            threshold_usd: U256::ZERO,
            shortfall_usd: U256::ZERO,
            reason: shadow::ClassificationReason::NotEvaluated {
                detail: format!("no flash source for anchor {anchor}"),
            },
        }
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
            shortfall_usd: U256::ZERO,
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
        let anchor = self.select_anchor(pair);
        let quote = crate::gaps::quote_pair_anchored(
            a_pools,
            b_pools,
            &self.prices_a,
            &self.prices_b,
            Some(anchor),
        )
        .ok()??;
        Some((quote, self.classify_anchor(anchor, &quote)))
    }

    /// Picks the cycle anchor for one pair by executability (audit S3a /
    /// A3): a token that both has a configured flash-loan source and carries
    /// a non-zero USD price outranks one that lacks either. Ties break to the
    /// lower address deterministically; when neither is executable the pair
    /// still quotes at the lower address so classification can name the
    /// specific failure instead of hiding it.
    ///
    /// Borrow-source depth ranking (A3 item 3) needs per-provider depth data
    /// that does not exist yet; the tiebreak stands in until it does.
    fn select_anchor(&self, pair: PairKey) -> Address {
        let lo = Address::from_slice(&pair.0);
        let hi = Address::from_slice(&pair.1);
        let executable =
            |token: Address| self.flash.rate_for(token).is_some() && self.token_is_priced(token);
        if executable(lo) || !executable(hi) {
            lo
        } else {
            hi
        }
    }

    /// The enumerated triangle triple at `index`.
    #[must_use]
    pub fn triangle(&self, index: usize) -> ([u8; 20], [u8; 20], [u8; 20]) {
        self.triangles[index]
    }

    /// Re-quotes one triangle (by index) from cached prices. Used by tests;
    /// the poll loop consumes `PairRunOutcome::triangle_results` directly.
    #[cfg_attr(not(test), allow(dead_code))]
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
            native_token_usd: U256::from(shadow::FIXED_POINT_SCALE),
            da_fee_usd: U256::ZERO,
        }
    }

    fn valid_reference() -> CostSnapshot {
        // Gas price chosen so PAIR_EXECUTION_GAS_UNITS costs exactly the
        // historical $0.03 scalar under the route-shaped model:
        // 300_000 units x 1e11 wei = 3e16 ETH-wei; x $1 / 1e18 -> 3e16.
        CostSnapshot {
            usd_per_token: U256::from(WEI),
            gas_price_age_valid: true,
            reference_price_valid: true,

            gas_price_wei: U256::from(100_000_000_000_u128),
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

    /// Prices the fixture anchor at $1 so gate passes classify honestly
    /// instead of demoting to `Provisional`.
    fn price_anchor(evaluator: &mut PairDirtyEvaluator) {
        let mut prices = HashMap::new();
        prices.insert(token_a(), usd(1));
        evaluator.set_token_prices(prices);
    }

    #[test]
    fn swap_rechecks_only_pairs_indexed_by_that_pool() {
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
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
        price_anchor(&mut evaluator);
        assert_eq!(evaluator.queue_len(), 1);
        let outcome = evaluator.run_once();
        assert_eq!(outcome.evaluated.len(), 1);
        assert_eq!(outcome.interesting.len(), 1);
    }

    #[test]
    fn token_is_priced_reflects_price_table() {
        let (a_pools, b_pools, _key_a, _key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);

        // Unknown tokens fall back to the $1 fixture: unpriced.
        assert!(!evaluator.token_is_priced(token_a()));

        // A non-zero entry prices the token.
        let mut prices = HashMap::new();
        prices.insert(token_a(), usd(2));
        evaluator.set_token_prices(prices);
        assert!(evaluator.token_is_priced(token_a()));
        assert!(!evaluator.token_is_priced(token_b()));

        // A zero entry is treated as unpriced, same as absent.
        let mut prices = HashMap::new();
        prices.insert(token_b(), U256::ZERO);
        evaluator.set_token_prices(prices);
        assert!(!evaluator.token_is_priced(token_b()));
    }

    #[test]
    fn run_once_returns_results_parallel_to_evaluated() {
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
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

        let outcome = evaluator.run_once();
        assert_eq!(outcome.evaluated.len(), outcome.pair_results.len());
        assert!(outcome.triangle_evaluated.is_empty());
        assert!(outcome.triangle_results.is_empty());
        // The retained classification matches a direct re-quote of the pair.
        let pair = outcome.evaluated[0];
        let (quote, classification) = &outcome.pair_results[0];
        assert_eq!(quote.profit, {
            let (re_quote, _) = evaluator.quote_pair(pair).expect("quote present");
            re_quote.profit
        });
        assert_eq!(
            matches!(classification.reason, ClassificationReason::AboveThreshold),
            outcome.interesting.contains(&pair)
        );
    }

    #[test]
    fn duplicate_marks_coalesce_before_evaluation() {
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
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
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
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
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
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

    /// Prices both legs of the one-pair fixture and marks the pair dirty.
    fn price_one_pair(
        evaluator: &mut PairDirtyEvaluator,
        key_a: [u8; 32],
        key_b: [u8; 32],
    ) -> PairKey {
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
        let pair: PairKey = (*token_a().0, *token_b().0);
        evaluator.mark_pool(*b"v3", key_a);
        pair
    }

    #[test]
    fn auto_flash_screens_unsupported_anchor_fail_closed() {
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
        evaluator.set_reference(valid_reference());
        evaluator.set_max_log2_skew(4.0);
        // Support map names a different token entirely.
        let mut support = std::collections::HashMap::new();
        support.insert(
            Address::repeat_byte(9),
            vec![shadow::flash_loan::FlashLoanProvider::AaveV3],
        );
        evaluator.set_flash_selection(shadow::flash_loan::FlashSelection::Auto(support));
        let pair = price_one_pair(&mut evaluator, key_a, key_b);

        let (_, classification) = evaluator.quote_pair(pair).expect("quote present");
        match classification.reason {
            ClassificationReason::NotEvaluated { detail } => {
                assert!(detail.starts_with("no flash source for anchor"), "{detail}");
            }
            other => panic!("expected flash-screened NotEvaluated, got {other:?}"),
        }
    }

    #[test]
    fn auto_flash_selects_cheapest_supporting_provider() {
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
        evaluator.set_reference(valid_reference());
        evaluator.set_max_log2_skew(4.0);
        let mut support = std::collections::HashMap::new();
        support.insert(
            token_a(),
            vec![
                shadow::flash_loan::FlashLoanProvider::AaveV3,
                shadow::flash_loan::FlashLoanProvider::BalancerV2,
            ],
        );
        evaluator.set_flash_selection(shadow::flash_loan::FlashSelection::Auto(support));
        price_anchor(&mut evaluator);
        let pair = price_one_pair(&mut evaluator, key_a, key_b);

        // Balancer is free: the quote still clears the gate exactly as with
        // the legacy zero-fee assumption.
        let outcome = evaluator.run_once();
        assert_eq!(outcome.interesting.len(), 1);
        let _ = pair;
    }

    #[test]
    fn fixed_flash_fee_is_charged_at_the_gate() {
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();

        // Zero-fee baseline gates above the floor...
        let mut free = PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        free.set_max_capacity_overshoot(f64::INFINITY);
        free.set_reference(valid_reference());
        free.set_max_log2_skew(4.0);
        price_anchor(&mut free);
        free.apply_swap(
            *b"v3",
            key_a,
            price(U256::from(1u64) << 97, 10_000_000_000_000_000_000_000, 1),
        );
        free.apply_swap(
            *b"v4",
            key_b,
            price(U256::from(1u64) << 98, 10_000_000_000_000_000_000_000, 2),
        );
        let pair = *free.run_once().evaluated.first().expect("pair evaluated");
        let (_, free_class) = free.quote_pair(pair).expect("quote present");
        assert!(matches!(
            free_class.reason,
            ClassificationReason::AboveThreshold
        ));
        assert_eq!(free_class.flash_cost_usd, U256::ZERO);

        // ...while the same route at Aave's 0.05% premium pays
        // input_usd * rate at the gate, strictly reducing net profit.
        let mut premium = PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        premium.set_max_capacity_overshoot(f64::INFINITY);
        premium.set_reference(valid_reference());
        premium.set_max_log2_skew(4.0);
        price_anchor(&mut premium);
        premium.set_flash_selection(shadow::flash_loan::FlashSelection::Fixed(
            shadow::flash_loan::FlashLoanProvider::AaveV3,
        ));
        premium.apply_swap(
            *b"v3",
            key_a,
            price(U256::from(1u64) << 97, 10_000_000_000_000_000_000_000, 1),
        );
        premium.apply_swap(
            *b"v4",
            key_b,
            price(U256::from(1u64) << 98, 10_000_000_000_000_000_000_000, 2),
        );
        let (_, premium_class) = premium.quote_pair(pair).expect("quote present");
        assert!(premium_class.flash_cost_usd > U256::ZERO);
        assert!(
            premium_class.estimated_net_profit_usd + premium_class.flash_cost_usd
                <= free_class.estimated_net_profit_usd
        );
    }

    #[test]
    fn gate_uses_gas_cost_over_expected_win_rate() {
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
        evaluator.set_reference(valid_reference());
        evaluator.set_max_log2_skew(4.0);
        price_anchor(&mut evaluator);
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
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
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
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
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
        let mut token_prices = HashMap::new();
        token_prices.insert(token_a(), usd(1));
        evaluator.set_token_prices(token_prices);
        let (_, classification) = evaluator.quote_pair(pair).expect("quote present");
        assert_eq!(classification.reason, ClassificationReason::AboveThreshold);
    }

    #[test]
    fn stale_but_untraded_legs_still_evaluate() {
        // A leg cached once and never re-priced carries a correct price as
        // long as its pool's sweep coverage is continuous: under complete
        // local coverage "no events" means "no state change", so an old
        // block number alone is not staleness. The live loop vouches for
        // that continuity via `mark_swept`; with both venues marked through
        // the tip the legs evaluate economically instead of screening.
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
        evaluator.set_reference(valid_reference());
        evaluator.set_max_log2_skew(4.0);
        // Legs priced at blocks 1 and 2; the tip is 2 and both chunks were
        // swept through it.
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
        evaluator.set_tip(2);
        evaluator.mark_swept(*b"v3", &a_pools, 2);
        evaluator.mark_swept(*b"v4", &b_pools, 2);
        let mut token_prices = HashMap::new();
        token_prices.insert(token_a(), usd(1));
        evaluator.set_token_prices(token_prices);
        let pair = crate::gaps::pair_key(token_a(), token_b());
        let (_, classification) = evaluator.quote_pair(pair).expect("quote present");
        assert_eq!(classification.reason, ClassificationReason::AboveThreshold);
    }

    #[test]
    fn nan_skew_is_screened_not_gated() {
        // Audit A8: `NaN > x` is false, so a NaN skew would silently PASS
        // the skew screen (`if skew > max` never fires) and reach the gate
        // on garbage. Any non-finite skew must screen explicitly.
        //
        // Constructed directly: through the public quoting path a NaN
        // cannot currently be produced (degenerate prices fail reserve
        // validation first), which is precisely why the guard needs a
        // pinned test — nothing else would notice it regressing.
        let (a_pools, b_pools, _key_a, _key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        evaluator.set_reference(valid_reference());
        evaluator.set_max_log2_skew(4.0);
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
        price_anchor(&mut evaluator);
        let fake = PairQuote {
            token_lo: token_a(),
            token_hi: token_b(),
            input: U256::from(WEI),
            output: U256::from(2 * WEI),
            profit: U256::from(WEI),
            toll: 0.006,
            log2_skew: f64::NAN,
            optimal_unclamped: U256::from(WEI),
            input_capacity: U256::from(WEI),
        };
        let classification = evaluator.classify_anchor(token_a(), &fake);
        assert!(
            matches!(&classification.reason, ClassificationReason::NotEvaluated { detail }
                if detail.contains("not finite")),
            "a NaN skew must screen with an explicit detail: {classification:?}"
        );

        // Infinity screens identically.
        let mut fake = fake;
        fake.log2_skew = f64::INFINITY;
        let classification = evaluator.classify_anchor(token_a(), &fake);
        assert!(matches!(
            &classification.reason,
            ClassificationReason::NotEvaluated { .. }
        ));
    }

    #[test]
    fn anchor_follows_executability_not_address_order() {
        // Audit S3a: with both tokens priced, the lower address anchors.
        // Price only the higher-address token and the anchor flips — the
        // legacy lexicographic choice would have kept quoting (and valuing)
        // from an unpriced token forever.
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        evaluator.set_reference(valid_reference());
        evaluator.set_max_log2_skew(4.0);
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
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
        let lo = token_a(); // fixture's lower-address token
        let hi = token_b();
        assert!(lo < hi, "fixture premise");

        // Both priced: deterministic tiebreak keeps `lo`.
        let mut prices = HashMap::new();
        prices.insert(lo, usd(1));
        prices.insert(hi, usd(1));
        evaluator.set_token_prices(prices.clone());
        let (quote, _) = evaluator
            .quote_pair(crate::gaps::pair_key(lo, hi))
            .expect("quote");
        assert_eq!(quote.token_lo, lo, "tiebreak anchors at the lower address");

        // Only `hi` priced: the anchor flips to the executable token.
        let mut prices = HashMap::new();
        prices.insert(hi, usd(1));
        evaluator.set_token_prices(prices);
        let (quote, classification) = evaluator
            .quote_pair(crate::gaps::pair_key(lo, hi))
            .expect("quote");
        assert_eq!(
            quote.token_lo, hi,
            "anchor must follow the executable token"
        );
        assert!(
            !matches!(&classification.reason, ClassificationReason::NotEvaluated { detail }
                if detail.contains("unpriced")),
            "the unpriced counterparty must not screen an anchored-at-hi quote: {classification:?}"
        );
    }

    #[test]
    fn capacity_overshoot_screens_before_gating() {
        // Audit S1: a thin concentrated pool's constant-product optimum
        // demands far more than one tick-spacing cell of liquidity can
        // absorb. With the default bound the quote screens with an explicit
        // overshoot detail; disabling the screen restores gating on the
        // clamped remainder.
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        evaluator.set_reference(valid_reference());
        evaluator.set_max_log2_skew(4.0);
        price_anchor(&mut evaluator);
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

        let (_, screened) = evaluator.quote_pair(pair).expect("quote present");
        assert!(
            matches!(&screened.reason, ClassificationReason::NotEvaluated { detail }
                if detail.contains("single-tick capacity")),
            "default bound must screen a ~220x overshoot: {screened:?}"
        );

        // Disabling the screen exposes the clamped economics underneath.
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
        let (_, gated) = evaluator.quote_pair(pair).expect("quote present");
        assert_ne!(
            gated.reason,
            ClassificationReason::NotEvaluated {
                detail: String::new()
            },
            "disabled screen must not produce NotEvaluated: {gated:?}"
        );
    }

    #[test]
    fn unswept_pool_screens_pair_even_when_price_is_recent() {
        // The ring sweep means "no events observed" can also mean "we were
        // not looking". A pool whose chunk was not swept through the tip has
        // no coverage voucher, so its pair screens regardless of how recent
        // the cached price looks — a missed trade is indistinguishable from
        // an absent one.
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
        evaluator.set_reference(valid_reference());
        evaluator.set_max_log2_skew(4.0);
        let tip = 10_000u64;
        // Both legs priced one block behind the tip — recent by any raw-age
        // standard.
        evaluator.apply_swap(
            *b"v3",
            key_a,
            price(
                U256::from(1u64) << 97,
                10_000_000_000_000_000_000_000,
                tip - 1,
            ),
        );
        evaluator.apply_swap(
            *b"v4",
            key_b,
            price(
                U256::from(1u64) << 98,
                10_000_000_000_000_000_000_000,
                tip - 1,
            ),
        );
        evaluator.set_tip(tip);
        // Venue B covered; venue A's chunk was NOT in this poll's ring slice.
        evaluator.mark_swept(*b"v4", &b_pools, tip);
        let pair = crate::gaps::pair_key(token_a(), token_b());

        // Direct evaluation path (`run_once` consumes the same screen).
        let outcome = {
            evaluator.mark_pool(*b"v3", key_a);
            evaluator.run_once()
        };
        assert!(
            outcome.evaluated.is_empty() && outcome.interesting.is_empty(),
            "an unswept-leg pair must not evaluate: {outcome:?}"
        );
        assert_eq!(outcome.stale_screened.len(), 1, "{outcome:?}");
        assert!(
            outcome.stale_screened[0].1.contains("coverage gap"),
            "screen detail must name the coverage gap: {:?}",
            outcome.stale_screened[0].1
        );

        // Marking the missing chunk restores evaluation on the next batch.
        evaluator.mark_swept(*b"v3", &a_pools, tip);
        evaluator.mark_pool(*b"v3", key_a);
        let outcome = evaluator.run_once();
        assert_eq!(outcome.stale_screened.len(), 0, "{outcome:?}");
        assert!(!outcome.pair_results.is_empty(), "{outcome:?}");
    }

    #[test]
    fn age_backstop_boundary() {
        // Even with full coverage a price older than the backstop screens;
        // exactly at the bound passes.
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let max_age = 500u64;
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
        evaluator.set_reference(valid_reference());
        evaluator.set_max_log2_skew(4.0);
        evaluator.set_staleness_bounds(max_age, DEFAULT_MAX_LEG_AGE_SPREAD_BLOCKS);
        let tip = 100_000u64;
        evaluator.apply_swap(
            *b"v3",
            key_a,
            price(
                U256::from(1u64) << 97,
                10_000_000_000_000_000_000_000,
                tip - max_age,
            ),
        );
        evaluator.apply_swap(
            *b"v4",
            key_b,
            price(U256::from(1u64) << 98, 10_000_000_000_000_000_000_000, tip),
        );
        evaluator.set_tip(tip);
        evaluator.mark_swept(*b"v3", &a_pools, tip);
        evaluator.mark_swept(*b"v4", &b_pools, tip);
        let pair = crate::gaps::pair_key(token_a(), token_b());
        assert!(
            evaluator.quote_pair(pair).is_some(),
            "age == bound must pass"
        );

        // One block older breaches the backstop despite full coverage.
        evaluator.apply_swap(
            *b"v3",
            key_a,
            price(
                U256::from(1u64) << 97,
                10_000_000_000_000_000_000_000,
                tip - max_age - 1,
            ),
        );
        let outcome = {
            evaluator.mark_pool(*b"v3", key_a);
            evaluator.run_once()
        };
        assert_eq!(outcome.stale_screened.len(), 1, "{outcome:?}");
        assert!(
            outcome.stale_screened[0].1.contains("leg age"),
            "{:?}",
            outcome.stale_screened[0].1
        );
    }

    #[test]
    fn leg_spread_boundary() {
        // Priced pools whose observation blocks differ by more than the
        // spread bound compose disjoint market states and screen; at the
        // bound they pass.
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let spread_max = 1_000u64;
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
        evaluator.set_reference(valid_reference());
        evaluator.set_max_log2_skew(4.0);
        evaluator.set_staleness_bounds(DEFAULT_MAX_LEG_AGE_BLOCKS, spread_max);
        let tip = 50_000u64;
        evaluator.apply_swap(
            *b"v3",
            key_a,
            price(
                U256::from(1u64) << 97,
                10_000_000_000_000_000_000_000,
                tip - spread_max,
            ),
        );
        evaluator.apply_swap(
            *b"v4",
            key_b,
            price(U256::from(1u64) << 98, 10_000_000_000_000_000_000_000, tip),
        );
        evaluator.set_tip(tip);
        evaluator.mark_swept(*b"v3", &a_pools, tip);
        evaluator.mark_swept(*b"v4", &b_pools, tip);
        let pair = crate::gaps::pair_key(token_a(), token_b());
        assert!(
            evaluator.quote_pair(pair).is_some(),
            "spread == bound must pass"
        );

        // Widen the spread by one block: screened.
        evaluator.apply_swap(
            *b"v3",
            key_a,
            price(
                U256::from(1u64) << 97,
                10_000_000_000_000_000_000_000,
                tip - spread_max - 1,
            ),
        );
        let outcome = {
            evaluator.mark_pool(*b"v3", key_a);
            evaluator.run_once()
        };
        assert_eq!(outcome.stale_screened.len(), 1, "{outcome:?}");
        assert!(
            outcome.stale_screened[0].1.contains("leg spread"),
            "{:?}",
            outcome.stale_screened[0].1
        );
    }

    #[test]
    fn unpriced_anchor_is_screened_as_unvaluable() {
        let (a_pools, b_pools, key_a, key_b) = one_pair_fixture();
        let mut evaluator =
            PairDirtyEvaluator::new(&a_pools, &b_pools, interesting_economics(), 100);
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
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

        // Audit S3c/A12: an unpriced anchor cannot be valued, so the quote is
        // not gated at the $1 fixture — it screens with an explicit detail.
        let (_, classification) = evaluator.quote_pair(pair).expect("quote present");
        assert!(
            matches!(
                &classification.reason,
                ClassificationReason::NotEvaluated { detail }
                    if detail.contains("unpriced") && detail.contains("cannot be valued")
            ),
            "an unpriced-anchor gate pass must screen, not value at $1: {classification:?}"
        );
        assert_eq!(classification.estimated_net_profit_usd, U256::ZERO);

        // Pricing the anchor restores the honest classification on the same
        // quote economics.
        let mut token_prices = HashMap::new();
        token_prices.insert(token_a(), usd(1));
        evaluator.set_token_prices(token_prices);
        let (_, classification) = evaluator.quote_pair(pair).expect("quote present");
        assert_eq!(classification.reason, ClassificationReason::AboveThreshold);

        // And a sub-cent anchor price makes the same gross profit dust, so
        // the honest path classifies below the floor instead of gating.
        let mut token_prices = HashMap::new();
        token_prices.insert(token_a(), U256::from(1_000_000));
        evaluator.set_token_prices(token_prices);
        let (_, classification) = evaluator.quote_pair(pair).expect("quote present");
        assert_eq!(classification.reason, ClassificationReason::NotProfitable);
    }

    #[test]
    fn triple_hop_stale_leg_evaluates_economically() {
        // Cheapest leg per edge wins, so a stale lower-fee v3 leg is chosen
        // over a fresh v4 leg with a higher toll. The stale v3 price is still
        // correct (its pool has not traded), so the triangle evaluates
        // economically instead of being screened by leg age. The anchor IS
        // priced (audit S3c: an unpriced anchor screens as unvaluable, which
        // would defeat this test's purpose).
        let cheap_v3 = |token0: Address, token1: Address, id: u8| {
            entry(
                "0xf300000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
                token0,
                token1,
                100,
                *b"v3",
                [id; 32],
            )
        };
        let a = token_a();
        let b = token_b();
        let c: Address = "0xc000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let v3_pools = vec![
            cheap_v3(a, b, 0x10),
            cheap_v3(b, c, 0x11),
            cheap_v3(c, a, 0x12),
        ];
        // Rebuild the v4 side on the same `(a,b,c)` tokens with higher toll.
        let pricey_v4 = |token0: Address, token1: Address, id: u8| {
            entry(
                "0x8366a39CC670B4001A1121B8F6A443A643e40951"
                    .parse()
                    .unwrap(),
                token0,
                token1,
                2500,
                *b"v4",
                [id; 32],
            )
        };
        let v4_pools = vec![
            pricey_v4(a, b, 0x20),
            pricey_v4(b, c, 0x21),
            pricey_v4(c, a, 0x22),
        ];
        let mut evaluator =
            PairDirtyEvaluator::new(&v3_pools, &v4_pools, interesting_economics(), 100);
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
        let mut anchor_price = HashMap::new();
        anchor_price.insert(token_a(), usd(1));
        evaluator.set_token_prices(anchor_price);
        evaluator.set_reference(valid_reference());
        evaluator.set_max_log2_skew(200.0);
        let tip = 1_000_000u64;
        for (i, pool) in v3_pools.iter().enumerate() {
            let shift = u32::try_from(i).unwrap_or(0);
            // Stale v3 legs (priced once early), fresh v4 legs at the tip.
            evaluator.apply_swap(
                *b"v3",
                pool.venue.into_word().into(),
                price(
                    U256::from(1u64) << (96 + shift),
                    10_000_000_000_000_000_000_000,
                    tip - 999_000,
                ),
            );
        }
        for (i, pool) in v4_pools.iter().enumerate() {
            let shift = u32::try_from(i).unwrap_or(0);
            evaluator.apply_swap(
                *b"v4",
                pool.id,
                price(
                    U256::from(2u64) << (96 + shift),
                    10_000_000_000_000_000_000_000,
                    tip,
                ),
            );
        }
        let (_, classification) = evaluator.quote_triangle(0).expect("triangle re-quote");
        assert!(
            matches!(
                &classification.reason,
                ClassificationReason::AboveThreshold
                    | ClassificationReason::BelowThreshold
                    | ClassificationReason::NotProfitable
            ),
            "a stale-leg triangle must evaluate economically (anchor is priced), \
             not screen on staleness or capacity: {classification:?}"
        );
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
        // Gating-path fixture: disable the single-tick capacity screen
        // (thin synthetic ranges overshoot by design; capacity screening has
        // its own dedicated tests).
        evaluator.set_max_capacity_overshoot(f64::INFINITY);
        evaluator.set_reference(valid_reference());
        evaluator.set_max_log2_skew(200.0);
        price_anchor(&mut evaluator);
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
