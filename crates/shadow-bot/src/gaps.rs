use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use alloy_primitives::{Address, U256};
use provider::{
    ChainReader, HttpBackend, LogFilter, RawLogEnvelope, Sleeper, TransportError, decode_v3_swap,
    decode_v4_swap, v3_swap_topic, v4_swap_topic,
};

/// Uniswap V4 marks a `PoolKey.fee` as dynamic (fee set by the hook, not the
/// encoded scalar) when the high bit is set; a fee of `0` is likewise not a
/// literal zero-fee pool. Round-trip toll accounting must drop such pools
/// unless their dynamic fee is observable.
pub const V4_DYNAMIC_FEE_FLAG: u32 = 0x0080_0000;

/// RHC encodes the wrapped native token in v2/v3 pool addresses with its real
/// contract address, while v4 `PoolKey`s use the `0x0..0` sentinel for the
/// native currency. Cross-venue matching must normalize the sentinel to the
/// native contract.
pub const RHC_NATIVE: Address =
    alloy_primitives::address!("0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73");

/// Derives the out ratio `amountOut / amountIn` from a pool's `sqrtPriceX96`.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn price_out(sqrt_price_x96: U256) -> f64 {
    let s = f64_of(sqrt_price_x96);
    let scaled = s / (1u64 << 48) as f64;
    scaled * scaled
}

/// A bias-free `f64` decode of a `U256`, valid because the inputs are bounded
/// by 32 bytes and we only ever compare prices in the same units.
fn f64_of(v: U256) -> f64 {
    let mut out = 0.0f64;
    for byte in v.to_be_bytes::<32>() {
        out = out.mul_add(256.0, f64::from(byte));
    }
    out
}

/// Normalizes one token for cross-venue matching: the v4 null sentinel maps
/// onto the RHC wrapped-native contract.
#[must_use]
pub fn normalize_currency(token: Address) -> Address {
    if token.is_zero() { RHC_NATIVE } else { token }
}

/// The skew-detectable quota toll of a round trip through one pool leg.
/// Returns `None` for V4 rows whose fee is a dynamic sentinel or an
/// "uninitialized" zero, where the quoted scalar is not the charged fee.
#[must_use]
pub fn leg_toll(fee: u32, profile: [u8; 2]) -> Option<f64> {
    if profile == *b"v4" && (fee == 0 || fee & V4_DYNAMIC_FEE_FLAG != 0) {
        return None;
    }
    Some(f64::from(fee) / 1_000_000.0)
}

/// One enumerated pool kept in a form the measurement can price and toll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolEntry {
    /// Venue profile: `*v3` or `*v4`.
    pub profile: [u8; 2],
    /// V3 pool contract address, or V4 `PoolManager` (the v4 singleton).
    pub venue: Address,
    /// V4 `PoolId` for V4 rows (zero for V3 rows).
    pub id: [u8; 32],
    /// Raw encoded fee field (V3 bps-scaled, V4 as encoded incl. sentinels).
    pub fee: u32,
    /// Pool token0 (normalized, never zero).
    pub token0: Address,
    /// Pool token1 (normalized, never zero).
    pub token1: Address,
    /// Fee denominator carried through from the catalog row (`1_000_000`).
    pub fee_denominator: u32,
    /// Factory / pool-manager contract for this pool.
    pub factory: Address,
    /// Source chain ID from the catalog row.
    pub chain_id: u64,
}

/// Loads a venue catalog CSV written by `enumerate-pools` into a map keyed by
/// normalized pool identity (V3 address, V4 `PoolId`).
///
/// # Errors
///
/// Returns the parser's message on a malformed row.
pub fn load_catalog(path: &Path) -> Result<HashMap<[u8; 32], PoolEntry>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut reader = csv::Reader::from_reader(file);
    let mut out = HashMap::new();
    // Expected header (see `enumerate-pools` writer):
    // `chain_id,pool_address,factory_address,token0,token1,fee_numerator,
    //  fee_denominator,profile,pool_id,source`
    for record in reader.records() {
        let record = record.map_err(|e| e.to_string())?;
        let chain_id = record
            .get(0)
            .ok_or_else(|| "row lacks chain_id".to_owned())?
            .trim()
            .parse::<u64>()
            .map_err(|_| "bad chain_id".to_owned())?;
        let venue = record
            .get(1)
            .ok_or_else(|| "row lacks pool_address".to_owned())?
            .parse::<Address>()
            .map_err(|_| "bad pool_address".to_owned())?;
        let factory = record
            .get(2)
            .ok_or_else(|| "row lacks factory_address".to_owned())?
            .parse::<Address>()
            .map_err(|_| "bad factory_address".to_owned())?;
        let token0 = normalize_currency(
            record
                .get(3)
                .ok_or_else(|| "row lacks token0".to_owned())?
                .parse::<Address>()
                .map_err(|_| "bad token0".to_owned())?,
        );
        let token1 = normalize_currency(
            record
                .get(4)
                .ok_or_else(|| "row lacks token1".to_owned())?
                .parse::<Address>()
                .map_err(|_| "bad token1".to_owned())?,
        );
        let fee = record
            .get(5)
            .ok_or_else(|| "row lacks fee".to_owned())?
            .parse::<u32>()
            .map_err(|_| "bad fee".to_owned())?;
        let fee_denominator = record
            .get(6)
            .ok_or_else(|| "row lacks fee_denominator".to_owned())?
            .parse::<u32>()
            .map_err(|_| "bad fee_denominator".to_owned())?;
        let profile_bytes = record
            .get(7)
            .ok_or_else(|| "row lacks profile".to_owned())?
            .as_bytes();
        if profile_bytes.len() != 2 {
            return Err("bad profile".to_owned());
        }
        let profile = [profile_bytes[0], profile_bytes[1]];
        let id = if profile == *b"v4" {
            match record.get(8).map(str::trim) {
                Some("") | None => [0u8; 32],
                Some(s) => parse_b256(s)?,
            }
        } else {
            [0u8; 32]
        };
        let key = if profile == *b"v4" {
            id
        } else {
            venue.into_word().into()
        };
        out.insert(
            key,
            PoolEntry {
                profile,
                venue,
                id,
                fee,
                token0,
                token1,
                fee_denominator,
                factory,
                chain_id,
            },
        );
    }
    Ok(out)
}

/// Loads a token-price CSV mapping each token address to its USD price per
/// whole token, fixed-point scaled by the economics scale. Rows are
/// `token,usd_per_token`.
///
/// # Errors
///
/// Returns the parser's message on a malformed row.
pub fn load_prices(path: &Path) -> Result<HashMap<Address, U256>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut reader = csv::Reader::from_reader(file);
    let mut out = HashMap::new();
    for record in reader.records() {
        let record = record.map_err(|e| e.to_string())?;
        let token = record
            .get(0)
            .ok_or_else(|| "row lacks token".to_owned())?
            .parse::<Address>()
            .map_err(|_| "bad token".to_owned())?;
        let usd: U256 = record
            .get(1)
            .ok_or_else(|| "row lacks usd_per_token".to_owned())?
            .parse::<U256>()
            .map_err(|_| "bad usd_per_token".to_owned())?;
        out.insert(normalize_currency(token), usd);
    }
    Ok(out)
}

/// Loads a manifest-seed CSV and returns the pools split by venue profile —
/// the two sweep sets for `quote-manifest`. Rows whose profile is neither
/// `*a` nor `*b` are dropped.
///
/// # Errors
///
/// Returns the parser's message on a malformed row.
pub fn restrict_to_manifest(
    path: &Path,
    profile_a: [u8; 2],
    profile_b: [u8; 2],
) -> Result<(Vec<PoolEntry>, Vec<PoolEntry>), String> {
    let catalog = load_catalog(path)?;
    let mut a = Vec::new();
    let mut b = Vec::new();
    for entry in catalog.into_values() {
        if entry.profile == profile_a {
            a.push(entry);
        } else if entry.profile == profile_b {
            b.push(entry);
        }
    }
    Ok((a, b))
}

/// The canonical ordered pair for cross-venue matching: `(token0, token1)`
/// sorted by normalized address, so both venues quote the same orientation.
#[must_use]
pub fn pair_key(a: Address, b: Address) -> ([u8; 20], [u8; 20]) {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut x = [0u8; 20];
    let mut y = [0u8; 20];
    x.copy_from_slice(lo.as_slice());
    y.copy_from_slice(hi.as_slice());
    (x, y)
}

/// A single observed post-swap price for one pool in one window.
#[derive(Debug, Clone, Copy)]
pub struct PoolPrice {
    pub sqrt: U256,
    /// Post-swap in-range liquidity, carried so concentrated (v3/v4) pools can
    /// be reduced to virtual constant-product reserves at the sampled price.
    pub liquidity: U256,
    pub block: u64,
}

/// Sweeps `Swap` events for a bounded set of pool keys over one inclusive
/// block window and returns the latest observed `sqrtPriceX96` per pool, so the
/// caller can price pools fully locally with zero `eth_call`.
///
/// `keys` states which pools to keep: for V3 it is the pool-address list the
/// filter must carry (the only cheap way to scope a V3 `Swap` filter); for V4
/// it is the `PoolId`s kept from the singleton's full `Swap` stream after
/// matching `topic1`.
///
/// Maximum number of pool addresses per `eth_getLogs` filter request. RHC caps
/// combined address+topic selectors at 1000, so keep 1 slot free for the swap
/// `topic0`.
const MAX_ADDRESS_CHUNK: usize = 999;

/// Keeps only the [`PoolEntry`]s whose normalized pair appears in *either*
/// catalog, i.e. the cross-venue pair overlap. Used to bound the live price
/// sweep to pools the measurement can actually price on both venues.
#[must_use]
pub fn restrict_to_cross(
    a: &HashMap<[u8; 32], PoolEntry>,
    b: &HashMap<[u8; 32], PoolEntry>,
) -> (Vec<PoolEntry>, Vec<PoolEntry>) {
    let mut mask: HashMap<([u8; 20], [u8; 20]), u8> = HashMap::new();
    for e in a.values() {
        *mask.entry(pair_key(e.token0, e.token1)).or_default() |= 1;
    }
    for e in b.values() {
        *mask.entry(pair_key(e.token0, e.token1)).or_default() |= 2;
    }
    let select = |entries: &HashMap<[u8; 32], PoolEntry>| -> Vec<PoolEntry> {
        entries
            .values()
            .filter(|e| mask.get(&pair_key(e.token0, e.token1)).copied() == Some(3))
            .copied()
            .collect()
    };
    let (sa, sb) = (select(a), select(b));
    (sa, sb)
}

/// Samples the latest `sqrtPriceX96` per pool from `Swap` logs over
/// `from..=to`. V3 rows are keyed by pool address; V4 rows by `PoolId` (the
/// swap topic1), emitted from the single `pool_manager` singleton.
/// `keys` must be the pools whose prices the caller wants (typically the
/// [`restrict_to_cross`] subset).
///
/// # Errors
///
/// Returns a [`TransportError`] on an empty filter or a transport/budget
/// failure.
#[allow(clippy::too_many_arguments)]
pub fn sweep_swap_prices<B, S>(
    reader: &ChainReader<B, S>,
    profile: [u8; 2],
    pool_manager: Address,
    keys: &[PoolEntry],
    from: u64,
    to: u64,
    window: u64,
    request_delay: Duration,
) -> Result<HashMap<[u8; 32], PoolPrice>, TransportError>
where
    B: HttpBackend,
    S: Sleeper,
{
    let topic = if profile == *b"v4" {
        v4_swap_topic()
    } else {
        v3_swap_topic()
    };
    // V3: filter by the pool-address list (contracts emit at their own
    // address), chunked to stay under provider address limits. V4: filter by
    // the single PoolManager and deselect by topic1 id.
    let mut latest: HashMap<[u8; 32], PoolPrice> = HashMap::new();
    let mut start = from;
    let mut ingest = |logs: &[serde_json::Value], keep_ids: Option<&HashSet<[u8; 32]>>| {
        for raw in logs {
            let Ok(envelope) = RawLogEnvelope::from_rpc_value(raw) else {
                continue;
            };
            let (key, parsed): (Option<[u8; 32]>, Option<(U256, U256)>) = if profile == *b"v4" {
                if envelope.topics.len() < 2 {
                    (None, None)
                } else {
                    let id = envelope.topics[1].0;
                    if keep_ids.is_some_and(|m| m.contains(&id)) {
                        (
                            Some(id),
                            decode_v4_swap(&envelope).map(|s| (s.sqrt_price_x96, s.liquidity)),
                        )
                    } else {
                        (None, None)
                    }
                }
            } else {
                let key = envelope.address.into_word().into();
                (
                    Some(key),
                    decode_v3_swap(&envelope).map(|s| (s.sqrt_price_x96, s.liquidity)),
                )
            };
            if let (Some(key), Some((sqrt, liquidity))) = (key, parsed) {
                let entry = latest.entry(key).or_insert(PoolPrice {
                    sqrt,
                    liquidity,
                    block: 0,
                });
                if envelope.block_number >= entry.block {
                    entry.sqrt = sqrt;
                    entry.liquidity = liquidity;
                    entry.block = envelope.block_number;
                }
            }
        }
    };
    loop {
        let end = start.saturating_add(window.saturating_sub(1)).min(to);
        match &profile {
            b"v4" => {
                let logs = reader.get_logs_windowed(
                    &LogFilter {
                        from_block: start,
                        to_block: end,
                        addresses: vec![pool_manager],
                        topic0: topic,
                    },
                    window,
                )?;
                let ids: HashSet<[u8; 32]> = keys.iter().map(|e| e.id).collect();
                ingest(&logs, Some(&ids));
                if !request_delay.is_zero() {
                    std::thread::sleep(request_delay);
                }
            }
            _ => {
                for chunk in keys.chunks(MAX_ADDRESS_CHUNK) {
                    let addresses: Vec<Address> = chunk.iter().map(|e| e.venue).collect();
                    let logs = reader.get_logs_windowed(
                        &LogFilter {
                            from_block: start,
                            to_block: end,
                            addresses,
                            topic0: topic,
                        },
                        window,
                    )?;
                    ingest(&logs, None);
                    if !request_delay.is_zero() {
                        std::thread::sleep(request_delay);
                    }
                }
            }
        }
        if end == to {
            break;
        }
        start = end + 1;
    }
    Ok(latest)
}

fn parse_b256(s: &str) -> Result<[u8; 32], String> {
    let v: alloy_primitives::B256 = s
        .trim_start_matches("0x")
        .parse()
        .map_err(|_| format!("bad b256 {s:?}"))?;
    Ok(v.0)
}

/// A per-pair gap-vs-toll observation: for one cross-venue token pair, the
/// price observed on venue A and venue B and the combined round-trip toll of
/// the two legs used.
#[derive(Debug, Clone, Copy)]
pub struct GapObservation {
    pub log2_skew: f64,
    pub round_trip_toll: f64,
}

/// A ranked cross-venue pair carrying the tokens that define the round trip
/// (`lo` sorts before `hi`), its observed skew, and the combined toll of the
/// two legs it crosses. Selection for the Task B manifest sorts by profit
/// margin (`skew - toll`), not raw skew.
#[derive(Debug, Clone, Copy)]
pub struct PairRank {
    pub token_lo: Address,
    pub token_hi: Address,
    pub log2_skew: f64,
    pub toll: f64,
    pub margin: f64,
}

/// A distribution summary of gap-vs-toll observations across cross pairs.
#[derive(Debug, Clone, Copy, Default)]
pub struct GapSummary {
    /// Pairs with an observed price on both venues.
    pub observed_pairs: usize,
    /// Pairs whose log2 skew exceeds the round-trip toll.
    pub above_toll: usize,
    /// Pairs whose skew exceeds 1% (an aggressive but safe crossing).
    pub above_1pct: usize,
    /// The fraction of observed pairs with skew > 0 (direction-agnostic).
    pub pct_skewed: f64,
    /// Median log2 skew across observed pairs.
    pub median_log2_skew: f64,
    /// Median round-trip toll across observed pairs.
    pub median_toll: f64,
}

/// The normalized pool identity used as the price-map key (V3 address as a
/// word; V4 `PoolId`).
#[must_use]
pub fn pool_key(entry: &PoolEntry) -> [u8; 32] {
    if entry.profile == *b"v4" {
        entry.id
    } else {
        entry.venue.into_word().into()
    }
}

/// The normalized sorted-pair key used to match a pool across venues
/// (canonical `pair_key`; see [`pair_key`]).
pub type PairSet = HashSet<([u8; 20], [u8; 20])>;

/// Loads a `gap-vs-toll --csv` selection file (one pair per row,
/// `token_lo,token_hi,...`) into a set of canonical pair keys.
///
/// # Errors
///
/// Returns the parser's message on a malformed row.
pub fn load_selected_pairs(path: &Path) -> Result<PairSet, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut reader = csv::Reader::from_reader(file);
    let mut out = HashSet::new();
    for record in reader.records() {
        let record = record.map_err(|e| e.to_string())?;
        let token_lo: Address = record
            .get(0)
            .ok_or_else(|| "row lacks token_lo".to_owned())?
            .parse::<Address>()
            .map_err(|_| "bad token_lo".to_owned())?;
        let token_hi: Address = record
            .get(1)
            .ok_or_else(|| "row lacks token_hi".to_owned())?
            .parse::<Address>()
            .map_err(|_| "bad token_hi".to_owned())?;
        out.insert(pair_key(token_lo, token_hi));
    }
    Ok(out)
}

/// Selects the subset of two venue catalogs whose normalized pair is in
/// `selected`, yielding the concrete pools a Task B manifest must load to
/// quote those pairs. Rows keep their catalog venue/factory/chain metadata so
/// the manifest can round-trip through `enumerate-pools` catalog readers.
/// Rows whose fee cannot be represented in a candidate list (zero, sentinel,
/// or exceeding the fee denominator) are dropped, since the manifest validator
/// rejects them.
///
/// # Errors
///
/// Returns an error when the expanded manifest exceeds `pool_cap`.
pub fn expand_manifest_catalog(
    a: &[PoolEntry],
    b: &[PoolEntry],
    selected: &PairSet,
    pool_cap: usize,
) -> Result<Vec<PoolEntry>, String> {
    let mut out = Vec::new();
    for (label, entries) in [("a", a), ("b", b)] {
        for entry in entries {
            if !selected.contains(&pair_key(entry.token0, entry.token1)) {
                continue;
            }
            if entry.fee == 0
                || entry.fee > entry.fee_denominator
                || leg_toll(entry.fee, entry.profile).is_none()
            {
                continue;
            }
            if out.len() >= pool_cap {
                return Err(format!(
                    "manifest exceeds the {pool_cap}-pool cap while expanding catalog {label}"
                ));
            }
            out.push(*entry);
        }
    }
    Ok(out)
}

/// Combines the latest per-pool prices on both venues with the catalog pair
/// overlap and ranks every cross-venue pair by observed skew-vs-toll margin.
/// A pair is priced by averaging the `sqrtPriceX96`-derived prices across all
/// its pools on each venue (orientated into the canonical pair direction); the
/// toll is the sum of the minimum `leg_toll` per venue for that pair. Pairs
/// with a price on only one venue, or with only dynamic/zero-fee v4 pools, are
/// omitted.
#[must_use]
#[allow(clippy::cast_precision_loss, clippy::type_complexity)]
pub fn gap_rankings(
    a: &[PoolEntry],
    b: &[PoolEntry],
    prices_a: &HashMap<[u8; 32], PoolPrice>,
    prices_b: &HashMap<[u8; 32], PoolPrice>,
) -> Vec<PairRank> {
    // pair -> (sum_price_a, count_a, min_toll_a, sum_price_b, count_b,
    //          min_toll_b)
    let mut per_pair: HashMap<([u8; 20], [u8; 20]), (f64, u64, f64, f64, u64, f64)> =
        HashMap::new();
    let mut accumulate =
        |entries: &[PoolEntry], prices: &HashMap<[u8; 32], PoolPrice>, side: usize| {
            for entry in entries {
                let Some(price) = prices.get(&pool_key(entry)) else {
                    continue;
                };
                let k = pair_key(entry.token0, entry.token1);
                let Some(toll) = leg_toll(entry.fee, entry.profile) else {
                    continue;
                };
                // Orient each pool's price into the canonical pair direction
                // (`token0` = sorted lo), so a venue quoting X/Y lines up with
                // one quoting Y/X for the same pair.
                let out = price_out(price.sqrt);
                let quoted = if entry.token0 == k.0 {
                    out
                } else {
                    1.0 / out.max(1e-30)
                };
                let cell = per_pair
                    .entry(k)
                    .or_insert((0.0, 0, f64::MAX, 0.0, 0, f64::MAX));
                if side == 0 {
                    cell.0 += quoted;
                    cell.1 += 1;
                    cell.2 = cell.2.min(toll);
                } else {
                    cell.3 += quoted;
                    cell.4 += 1;
                    cell.5 = cell.5.min(toll);
                }
            }
        };
    accumulate(a, prices_a, 0);
    accumulate(b, prices_b, 1);

    let mut ranks = Vec::new();
    for (k, (pa, ca, ta, pb, cb, tb)) in per_pair {
        // `f64::MAX` marks an unobservable toll (only dynamic/zero-fee v4
        // pools on that venue for the pair).
        if ca == 0 || cb == 0 || !ta.is_finite() || !tb.is_finite() {
            continue;
        }
        let avg_a = pa / ca as f64;
        let avg_b = pb / cb as f64;
        let skew = (avg_b / avg_a.max(1e-30)).max(1e-30).log2().abs();
        let toll = ta + tb;
        ranks.push(PairRank {
            token_lo: Address::from_slice(&k.0),
            token_hi: Address::from_slice(&k.1),
            log2_skew: skew,
            toll,
            margin: skew - toll,
        });
    }
    ranks.sort_by(|x, y| {
        y.margin
            .partial_cmp(&x.margin)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    ranks
}

/// A single pair-level closed-form optimal quote over one cross-venue cycle:
/// buy on the cheaper venue, sell on the dearer, sized so profit is maximal.
#[derive(Debug, Clone, Copy)]
pub struct PairQuote {
    pub token_lo: Address,
    pub token_hi: Address,
    /// Optimal amount of `token_lo` to put in.
    pub input: U256,
    /// `token_lo` returned after the round trip.
    pub output: U256,
    /// `output - input` in `token_lo` units.
    pub profit: U256,
    /// Combined round-trip toll (fees) of the two used legs.
    pub toll: f64,
    /// Observed log2 price skew across the two legs.
    pub log2_skew: f64,
}

/// Reduces a concentrated pool's sampled state to the virtual constant-product
/// reserves at the sampled price, at which `x*y = L²` and `y/x = price` hold.
/// `sqrt` is the `Q64.96` post-swap price, `liquidity` the in-range `L`.
#[must_use]
pub fn virtual_reserves(sqrt: U256, liquidity: U256) -> (U256, U256) {
    const ONE: U256 = U256::from_limbs([1, 0, 0, 0]);
    let two_96: U256 = ONE << 96;
    let reserve0 = liquidity * two_96 / sqrt.max(U256::from(1));
    let reserve1 = liquidity * sqrt / two_96;
    (reserve0, reserve1)
}

/// Builds the 2-hop cycle for one cross-venue pair and solves the closed-form
/// optimal input with the sampled virtual reserves. Picks the tighter
/// (cheaper-fee) pool per venue for the legs.
///
/// # Errors
///
/// Returns a message describing malformed cycles or missing state.
pub fn quote_pair(
    a_entries: &[PoolEntry],
    b_entries: &[PoolEntry],
    prices_a: &HashMap<[u8; 32], PoolPrice>,
    prices_b: &HashMap<[u8; 32], PoolPrice>,
) -> Result<Option<PairQuote>, String> {
    use domain::{Cycle, CycleHop, CycleId, Fee, PoolId, PoolState, StateVersion};
    use v2_math::{OptimalQuote, optimal_input};

    let best_leg = |entries: &[PoolEntry],
                    prices: &HashMap<[u8; 32], PoolPrice>|
     -> Option<(PoolEntry, PoolPrice, f64)> {
        let mut best: Option<(PoolEntry, PoolPrice, f64)> = None;
        for entry in entries {
            let Some(price) = prices.get(&pool_key(entry)) else {
                continue;
            };
            let Some(toll) = leg_toll(entry.fee, entry.profile) else {
                continue;
            };
            if best.as_ref().is_none_or(|(_, _, t)| toll < *t) {
                best = Some((*entry, *price, toll));
            }
        }
        best
    };
    let (leg_a, leg_price_a, toll_a) =
        best_leg(a_entries, prices_a).ok_or("venue A has no priced leg")?;
    let (leg_b, leg_price_b, toll_b) =
        best_leg(b_entries, prices_b).ok_or("venue B has no priced leg")?;

    let pair = pair_key(leg_a.token0, leg_a.token1);
    let anchor = Address::from_slice(&pair.0);
    let other = Address::from_slice(&pair.1);

    let make_cycle =
        |first: PoolEntry, first_price: PoolPrice, second: PoolEntry, second_price: PoolPrice| {
            let (r0a, r1a) = virtual_reserves(first_price.sqrt, first_price.liquidity);
            let (r0b, r1b) = virtual_reserves(second_price.sqrt, second_price.liquidity);
            let states = vec![
                PoolState {
                    reserve0: r0a,
                    reserve1: r1a,
                    block_number: first_price.block,
                    transaction_index: 0,
                    log_index: 0,
                    version: StateVersion(first_price.block),
                },
                PoolState {
                    reserve0: r0b,
                    reserve1: r1b,
                    block_number: second_price.block,
                    transaction_index: 0,
                    log_index: 0,
                    version: StateVersion(second_price.block),
                },
            ];
            // The manifest fee is the fraction *taken* (e.g. 3000/1_000_000);
            // v2-math expects the fraction *retained* as its numerator.
            let fee = |entry: PoolEntry| Fee {
                numerator: entry.fee_denominator.saturating_sub(entry.fee),
                denominator: entry.fee_denominator,
            };
            let cycle = Cycle {
                id: CycleId(0),
                anchor,
                hops: vec![
                    CycleHop {
                        pool_id: PoolId(0),
                        token_in: anchor,
                        token_out: other,
                        fee: fee(first),
                        zero_for_one: first.token0 == anchor,
                    },
                    CycleHop {
                        pool_id: PoolId(1),
                        token_in: other,
                        token_out: anchor,
                        fee: fee(second),
                        zero_for_one: second.token0 == other,
                    },
                ],
            };
            optimal_input(&cycle, &states)
        };

    let mut best: Option<(OptimalQuote, f64)> = make_cycle(leg_a, leg_price_a, leg_b, leg_price_b)
        .map_err(|e| format!("optimal input failed: {e}"))?
        .map(|quote| (quote, toll_a + toll_b));
    if best.is_none() {
        best = make_cycle(leg_b, leg_price_b, leg_a, leg_price_a)
            .ok()
            .flatten()
            .map(|quote| (quote, toll_a + toll_b));
    }
    let Some((quote, toll)) = best else {
        return Ok(None);
    };
    let skew = (price_out(leg_price_b.sqrt) / price_out(leg_price_a.sqrt).max(1e-30))
        .max(1e-30)
        .log2()
        .abs();
    Ok(Some(PairQuote {
        token_lo: anchor,
        token_hi: other,
        input: quote.input,
        output: quote.output,
        profit: quote.profit,
        toll,
        log2_skew: skew,
    }))
}

/// Quotes every cross-venue pair that has at least one priced leg on each
/// venue and returns the captureable quotes (positive-profit round trips),
/// sorted by profit in input-token units, largest first.
type PoolByPair = HashMap<([u8; 20], [u8; 20]), (Vec<PoolEntry>, Vec<PoolEntry>)>;
#[must_use]
pub fn quote_manifest(
    a: &[PoolEntry],
    b: &[PoolEntry],
    prices_a: &HashMap<[u8; 32], PoolPrice>,
    prices_b: &HashMap<[u8; 32], PoolPrice>,
) -> Vec<PairQuote> {
    let mut by_pair: PoolByPair = HashMap::new();
    for entry in a {
        by_pair
            .entry(pair_key(entry.token0, entry.token1))
            .or_default()
            .0
            .push(*entry);
    }
    for entry in b {
        if let Some((_a_pools, b_pools)) = by_pair.get_mut(&pair_key(entry.token0, entry.token1)) {
            b_pools.push(*entry);
        }
    }
    let mut out: Vec<PairQuote> = Vec::new();
    for (a_pools, b_pools) in by_pair.into_values() {
        if a_pools.is_empty() || b_pools.is_empty() {
            continue;
        }
        if let Ok(Some(quote)) = quote_pair(&a_pools, &b_pools, prices_a, prices_b) {
            out.push(quote);
        }
    }
    out.sort_by_key(|quote| quote.profit);
    out.reverse();
    out
}

/// Combines the latest per-pool prices and computes gap-vs-toll aggregate
/// statistics over the cross-venue pairs (see [`gap_rankings`] for the
/// per-pair ranking it summarizes).
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn gap_distribution(
    a: &[PoolEntry],
    b: &[PoolEntry],
    prices_a: &HashMap<[u8; 32], PoolPrice>,
    prices_b: &HashMap<[u8; 32], PoolPrice>,
) -> GapSummary {
    let ranks = gap_rankings(a, b, prices_a, prices_b);
    let observations: Vec<GapObservation> = ranks
        .iter()
        .map(|r| GapObservation {
            log2_skew: r.log2_skew,
            round_trip_toll: r.toll,
        })
        .collect();
    let observed_pairs = observations.len();
    if observed_pairs == 0 {
        return GapSummary::default();
    }
    let above_toll = observations
        .iter()
        .filter(|o| o.log2_skew > o.round_trip_toll)
        .count();
    let above_1pct = observations.iter().filter(|o| o.log2_skew > 0.01).count();
    let pct_skewed = (observations.iter().filter(|o| o.log2_skew > 0.0).count() as f64)
        / (observed_pairs as f64);
    let mut skews: Vec<f64> = observations.iter().map(|o| o.log2_skew).collect();
    skews.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
    let median_log2_skew = skews[skews.len() / 2];
    let mut tolls: Vec<f64> = observations.iter().map(|o| o.round_trip_toll).collect();
    tolls.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
    let median_toll = tolls[tolls.len() / 2];

    GapSummary {
        observed_pairs,
        above_toll,
        above_1pct,
        pct_skewed,
        median_log2_skew,
        median_toll,
    }
}

/// Cross-venue cycle counts (pair overlap + 3-hop triangles).
#[derive(Debug, Clone, Copy, Default)]
pub struct CrossMeasure {
    pub cross_pairs: usize,
    pub toll_free_cross_pairs: usize,
    pub three_hop_cycles: usize,
    pub cross_tokens: usize,
}

/// Counts cross-venue opportunities from two enumerated catalogs by bucketing
/// pools on their normalized pair and intersecting venue membership.
#[must_use]
pub fn cross_measure(
    a: &HashMap<[u8; 32], PoolEntry>,
    b: &HashMap<[u8; 32], PoolEntry>,
) -> CrossMeasure {
    use std::collections::BTreeMap;
    let mut per_pair: BTreeMap<([u8; 20], [u8; 20]), (u8, bool)> = BTreeMap::new();
    let mut feed = |entries: &HashMap<[u8; 32], PoolEntry>, bit: u8| {
        for entry in entries.values() {
            let k = pair_key(entry.token0, entry.token1);
            let quoted_toll = leg_toll(entry.fee, entry.profile).is_some();
            let set = per_pair.entry(k).or_insert((0, false));
            set.0 |= bit;
            set.1 |= quoted_toll;
        }
    };
    feed(a, 0b01);
    feed(b, 0b10);
    let cross_pairs = per_pair
        .iter()
        .filter(|(_, (mask, _))| *mask == 0b11)
        .count();
    let toll_cross_pairs = per_pair
        .iter()
        .filter(|(_, (mask, tolled))| *mask == 0b11 && *tolled)
        .count();
    let mut adj: HashMap<[u8; 20], Vec<[u8; 20]>> = HashMap::new();
    for ((token_lo, token_hi), (mask, _)) in &per_pair {
        if *mask != 0b11 {
            continue;
        }
        adj.entry(*token_lo).or_default().push(*token_hi);
        adj.entry(*token_hi).or_default().push(*token_lo);
    }
    for v in adj.values_mut() {
        v.sort_unstable();
        v.dedup();
    }
    let mut keys: Vec<[u8; 20]> = adj.keys().copied().collect();
    keys.sort_unstable();
    let index: HashMap<[u8; 20], usize> = keys.iter().enumerate().map(|(i, k)| (*k, i)).collect();
    let mut three_hop_cycles = 0usize;
    for (u_idx, u) in keys.iter().enumerate() {
        let u_adj = &adj[u];
        for v_neighbor in u_adj {
            let v_idx = index[v_neighbor];
            if v_idx <= u_idx {
                continue;
            }
            let v_adj = &adj[v_neighbor];
            let (small, large) = if u_adj.len() <= v_adj.len() {
                (u_adj, v_adj)
            } else {
                (v_adj, u_adj)
            };
            for w in small {
                if index.get(w).is_none_or(|i| *i <= v_idx) {
                    continue;
                }
                if large.binary_search(w).is_ok() {
                    three_hop_cycles += 1;
                }
            }
        }
    }
    CrossMeasure {
        cross_pairs,
        toll_free_cross_pairs: toll_cross_pairs,
        three_hop_cycles,
        cross_tokens: adj.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_native_sentinel() {
        let sentinel = "0x0000000000000000000000000000000000000000"
            .parse::<Address>()
            .unwrap();
        assert_eq!(normalize_currency(sentinel), RHC_NATIVE);
        let token = "0x2090c829EC979271889967D7c91D6CEE37249e6A"
            .parse::<Address>()
            .unwrap();
        assert_eq!(normalize_currency(token), token);
    }

    #[test]
    fn leg_toll_handles_dynamic_sentinels() {
        assert_eq!(leg_toll(10_000, *b"v3"), Some(0.01));
        assert_eq!(leg_toll(50, *b"v3"), Some(0.00005));
        assert_eq!(leg_toll(0, *b"v4"), None);
        assert_eq!(leg_toll(V4_DYNAMIC_FEE_FLAG, *b"v4"), None);
        assert_eq!(leg_toll(10_000, *b"v4"), Some(0.01));
    }

    #[test]
    fn price_out_derives_xyk_ratio() {
        let sqrt = U256::from(1u64 << 48);
        assert!((price_out(sqrt) - 1.0).abs() < 1e-9);
        let sqrt = U256::from((1u64 << 48) * 2);
        assert!((price_out(sqrt) - 4.0).abs() < 1e-9);
    }

    #[test]
    fn pair_key_orders_by_normalized_address() {
        let native = RHC_NATIVE;
        let other: Address = "0x2000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let (x, y) = pair_key(native, other);
        assert_eq!(x, native.0);
        assert_eq!(y, other.0);
        assert!(x <= y);
        assert_eq!(pair_key(native, other), pair_key(other, native));
        let third: Address = "0xcccccccccccccccccccccccccccccccccccccccc"
            .parse()
            .unwrap();
        assert_ne!(pair_key(native, other), pair_key(native, third));
    }

    #[test]
    fn load_prices_reads_token_price_csv_and_normalizes_native() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prices.csv");
        let native: Address = "0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73"
            .parse()
            .unwrap();
        let other: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            "token,usd_per_token\n{other},1800000000000000000\n0x0000000000000000000000000000000000000000,2900000000000000000\n"
        )
        .unwrap();
        drop(f);
        let map = load_prices(&path).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get(&other).copied(),
            Some(U256::from(18) * U256::from(10u128.pow(17)))
        );
        // The v4 native sentinel normalizes onto the RHC native contract.
        assert_eq!(
            map.get(&native).copied(),
            Some(U256::from(29) * U256::from(10u128.pow(17)))
        );
    }

    #[test]
    fn load_catalog_reads_enumerated_csv() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pools.csv");
        let mut f = std::fs::File::create(&path).unwrap();
        let pool: Address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .unwrap();
        let token: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let id = "22".repeat(32);
        write!(
            f,
            "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
             4663,{pool},0x0000000000000000000000000000000000000000,0x0000000000000000000000000000000000000000,{token},8388608,1000000,v4,0x{id},\n"
        )
        .unwrap();
        drop(f);
        let map = load_catalog(&path).unwrap();
        assert_eq!(map.len(), 1);
        let entry = map.values().next().unwrap();
        assert_eq!(entry.profile, *b"v4");
        assert_eq!(entry.token0, RHC_NATIVE);
        assert_eq!(entry.token1, token);
        assert_eq!(entry.fee, V4_DYNAMIC_FEE_FLAG);
        assert!(leg_toll(entry.fee, entry.profile).is_none());
        assert_eq!(entry.venue, pool);
    }

    #[test]
    fn cross_measure_counts_cycles_on_shared_pairs() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let a = "0x1000000000000000000000000000000000000000";
        let b = "0x2000000000000000000000000000000000000000";
        let c = "0x3000000000000000000000000000000000000000";
        let p3 = dir.path().join("v3.csv");
        let p4 = dir.path().join("v4.csv");
        {
            let mut f = std::fs::File::create(&p3).unwrap();
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0xfa00000000000000000000000000000000000001,0x0000000000000000000000000000000000000000,{a},{b},3000,1000000,v3,,\n\
                 4663,0xfa00000000000000000000000000000000000002,0x0000000000000000000000000000000000000000,{b},{c},3000,1000000,v3,,\n\
                 4663,0xfa00000000000000000000000000000000000003,0x0000000000000000000000000000000000000000,{c},{a},3000,1000000,v3,,\n"
            )
            .unwrap();
        }
        {
            let mut f = std::fs::File::create(&p4).unwrap();
            let id1 = "11".repeat(32);
            let id2 = "22".repeat(32);
            let id3 = "33".repeat(32);
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0x8366a39CC670B4001A1121B8F6A443A643e40951,0x0000000000000000000000000000000000000000,{a},{b},2500,1000000,v4,0x{id1},\n\
                 4663,0x8366a39CC670B4001A1121B8F6A443A643e40951,0x0000000000000000000000000000000000000000,{b},{c},2500,1000000,v4,0x{id2},\n\
                 4663,0x8366a39CC670B4001A1121B8F6A443A643e40951,0x0000000000000000000000000000000000000000,{c},{a},2500,1000000,v4,0x{id3},\n"
            )
            .unwrap();
        }
        let m3 = load_catalog(&p3).unwrap();
        let m4 = load_catalog(&p4).unwrap();
        let report = cross_measure(&m3, &m4);
        assert_eq!(report.cross_pairs, 3);
        assert_eq!(report.toll_free_cross_pairs, 3);
        assert_eq!(report.three_hop_cycles, 1);
        assert_eq!(report.cross_tokens, 3);
    }

    #[test]
    fn cross_measure_needs_both_venues() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let a = "0x1000000000000000000000000000000000000000";
        let b = "0x2000000000000000000000000000000000000000";
        let c = "0x3000000000000000000000000000000000000000";
        let p3 = dir.path().join("v3.csv");
        let p4 = dir.path().join("v4.csv");
        {
            let mut f = std::fs::File::create(&p3).unwrap();
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0xfa00000000000000000000000000000000000001,0x0000000000000000000000000000000000000000,{a},{b},3000,1000000,v3,,\n\
                 4663,0xfa00000000000000000000000000000000000002,0x0000000000000000000000000000000000000000,{b},{c},3000,1000000,v3,,\n"
            )
            .unwrap();
        }
        {
            let mut f = std::fs::File::create(&p4).unwrap();
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0xfa0000000000000000000000000000000000000a,0x0000000000000000000000000000000000000000,{a},{b},10000,1000000,v4,,\n"
            )
            .unwrap();
        }
        let m3 = load_catalog(&p3).unwrap();
        let m4 = load_catalog(&p4).unwrap();
        let report = cross_measure(&m3, &m4);
        assert_eq!(report.cross_pairs, 1);
        assert_eq!(report.three_hop_cycles, 0);
    }

    #[test]
    fn gap_distribution_measures_skew_above_toll() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let a_tok = "0x1000000000000000000000000000000000000000";
        let b_tok = "0x2000000000000000000000000000000000000000";
        let p3 = dir.path().join("v3.csv");
        let p4 = dir.path().join("v4.csv");
        {
            let mut f = std::fs::File::create(&p3).unwrap();
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0xfa00000000000000000000000000000000000001,0x0000000000000000000000000000000000000000,{a_tok},{b_tok},3000,1000000,v3,,\n"
            )
            .unwrap();
        }
        {
            let mut f = std::fs::File::create(&p4).unwrap();
            let id = "22".repeat(32);
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0x8366a39CC670B4001A1121B8F6A443A643e40951,0x0000000000000000000000000000000000000000,{a_tok},{b_tok},2500,1000000,v4,0x{id},\n"
            )
            .unwrap();
        }
        let m3 = load_catalog(&p3).unwrap();
        let m4 = load_catalog(&p4).unwrap();
        let (a_entries, b_entries) = restrict_to_cross(&m3, &m4);
        assert_eq!(a_entries.len(), 1);
        assert_eq!(b_entries.len(), 1);
        let key3 = a_entries[0].venue.into_word().into();
        let key4 = b_entries[0].id;
        // v3 pool price price_out = 4.0, v4 pool price_out = 16.0 (log2 skew 2).
        let mut pa = HashMap::new();
        pa.insert(
            key3,
            PoolPrice {
                sqrt: U256::from(1u64) << 97,
                liquidity: U256::from(1_000u64),
                block: 1,
            },
        );
        let mut pb = HashMap::new();
        pb.insert(
            key4,
            PoolPrice {
                sqrt: U256::from(1u64) << 98,
                liquidity: U256::from(1_000u64),
                block: 1,
            },
        );
        let summary = gap_distribution(&a_entries, &b_entries, &pa, &pb);
        assert_eq!(summary.observed_pairs, 1);
        assert!(summary.above_toll >= 1);
        assert!(summary.above_1pct >= 1);
        assert!((summary.median_log2_skew - 2.0).abs() < 1e-9);
        assert!((summary.median_toll - 0.0055).abs() < 1e-9);
        let ranks = gap_rankings(&a_entries, &b_entries, &pa, &pb);
        assert_eq!(ranks.len(), 1);
        assert_eq!(ranks[0].token_lo, a_entries[0].token0);
        assert_eq!(ranks[0].token_hi, a_entries[0].token1);
        assert!((ranks[0].margin - (2.0 - 0.0055)).abs() < 1e-9);
    }

    #[test]
    fn gap_distribution_orientes_opposing_token_order() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let a_tok = "0x1000000000000000000000000000000000000000";
        let b_tok = "0x2000000000000000000000000000000000000000";
        let p3 = dir.path().join("v3.csv");
        let p4 = dir.path().join("v4.csv");
        // v3 quotes (token0=a, token1=b); v4 quotes the SAME pair but with the
        // tokens swapped (token0=b, token1=a). Both quote the same price of 4.0,
        // so after orientation the skew must be ~0, not doubled.
        {
            let mut f = std::fs::File::create(&p3).unwrap();
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0xfa00000000000000000000000000000000000001,0x0000000000000000000000000000000000000000,{a_tok},{b_tok},3000,1000000,v3,,\n"
            )
            .unwrap();
        }
        {
            let mut f = std::fs::File::create(&p4).unwrap();
            let id = "33".repeat(32);
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0x8366a39CC670B4001A1121B8F6A443A643e40951,0x0000000000000000000000000000000000000000,{b_tok},{a_tok},2500,1000000,v4,0x{id},\n"
            )
            .unwrap();
        }
        let m3 = load_catalog(&p3).unwrap();
        let m4 = load_catalog(&p4).unwrap();
        let (a_entries, b_entries) = restrict_to_cross(&m3, &m4);
        let key3 = a_entries[0].venue.into_word().into();
        let key4 = b_entries[0].id;
        // identical sqrt on both venues -> identical price_out (4.0).
        let mut pa = HashMap::new();
        pa.insert(
            key3,
            PoolPrice {
                sqrt: U256::from(2u64.pow(48) << 1),
                liquidity: U256::from(1_000u64),
                block: 1,
            },
        );
        // The v4 pool quotes (b, a): the same 4.0 canonical price of a/b
        // requires a reciprocal sqrt (price_out 0.25 -> orientation flips it
        // back to 4.0).
        let mut pb = HashMap::new();
        pb.insert(
            key4,
            PoolPrice {
                sqrt: U256::from(1u64 << 47),
                liquidity: U256::from(1_000u64),
                block: 1,
            },
        );
        let summary = gap_distribution(&a_entries, &b_entries, &pa, &pb);
        assert_eq!(summary.observed_pairs, 1);
        assert!(summary.median_log2_skew < 1e-9);
    }

    #[test]
    fn restrict_to_manifest_splits_by_profile() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.csv");
        let a = "0x1000000000000000000000000000000000000000";
        let b = "0x2000000000000000000000000000000000000000";
        {
            let mut f = std::fs::File::create(&path).unwrap();
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0xfa00000000000000000000000000000000000001,0x1111111111111111111111111111111111111111,{a},{b},3000,1000000,v3,,\n\
                 4663,0x8366a39CC670B4001A1121B8F6A443A643e40951,0x2222222222222222222222222222222222222222,{a},{b},0,1000000,v4,0x{},\n",
                "99".repeat(32)
            )
            .unwrap();
        }
        let (a_pools, b_pools) = restrict_to_manifest(&path, *b"v3", *b"v4").unwrap();
        assert_eq!(a_pools.len(), 1);
        assert_eq!(b_pools.len(), 1);
        assert_eq!(a_pools[0].profile, *b"v3");
        assert_eq!(b_pools[0].profile, *b"v4");
    }

    #[test]
    fn load_selected_pairs_reads_gap_csv_output() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("selection.csv");
        let a = "0x1000000000000000000000000000000000000000";
        let b = "0x2000000000000000000000000000000000000000";
        let c = "0x3000000000000000000000000000000000000000";
        {
            let mut f = std::fs::File::create(&path).unwrap();
            write!(
                f,
                "token_lo,token_hi,log2_skew,toll,margin\n\
                 {a},{b},0.100000,0.005000,0.095000\n\
                 {b},{c},0.200000,0.010000,0.190000\n"
            )
            .unwrap();
        }
        let selected = load_selected_pairs(&path).unwrap();
        assert_eq!(selected.len(), 2);
        assert!(selected.contains(&pair_key(a.parse().unwrap(), b.parse().unwrap())));
        assert!(selected.contains(&pair_key(b.parse().unwrap(), c.parse().unwrap())));
    }

    #[test]
    fn expand_manifest_catalog_keeps_selected_pairs_and_caps() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let a = "0x1000000000000000000000000000000000000000";
        let b = "0x2000000000000000000000000000000000000000";
        let c = "0x3000000000000000000000000000000000000000";
        let p3 = dir.path().join("v3.csv");
        let p4 = dir.path().join("v4.csv");
        {
            let mut f = std::fs::File::create(&p3).unwrap();
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0xfa00000000000000000000000000000000000001,0x1111111111111111111111111111111111111111,{a},{b},3000,1000000,v3,,\n\
                 4663,0xfa00000000000000000000000000000000000002,0x1111111111111111111111111111111111111111,{b},{c},3000,1000000,v3,,\n"
            )
            .unwrap();
        }
        {
            let mut f = std::fs::File::create(&p4).unwrap();
            let id = "22".repeat(32);
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0x8366a39CC670B4001A1121B8F6A443A643e40951,0x2222222222222222222222222222222222222222,{a},{b},2500,1000000,v4,0x{id},\n"
            )
            .unwrap();
        }
        let m3 = load_catalog(&p3).unwrap();
        let m4 = load_catalog(&p4).unwrap();
        let all_a: Vec<_> = m3.into_values().collect();
        let all_b: Vec<_> = m4.into_values().collect();

        let selected = HashSet::from([pair_key(a.parse().unwrap(), b.parse().unwrap())]);
        let kept = expand_manifest_catalog(&all_a, &all_b, &selected, 2_000).unwrap();
        // Only the a/b pool on each venue survives.
        assert_eq!(kept.len(), 2);
        let a_addr: Address = a.parse().unwrap();
        let b_addr: Address = b.parse().unwrap();
        assert!(kept.iter().all(|e| {
            (e.token0 == a_addr && e.token1 == b_addr) || (e.token0 == b_addr && e.token1 == a_addr)
        }));

        // A cap of 1 must fail once the second venue row is reached.
        let err = expand_manifest_catalog(&all_a, &all_b, &selected, 1).unwrap_err();
        assert!(err.contains("pool cap"));
    }

    #[test]
    fn expand_manifest_catalog_drops_unrepresentable_fees() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let a = "0x1000000000000000000000000000000000000000";
        let b = "0x2000000000000000000000000000000000000000";
        let p3 = dir.path().join("v3.csv");
        let p4 = dir.path().join("v4.csv");
        {
            let mut f = std::fs::File::create(&p3).unwrap();
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0xfa00000000000000000000000000000000000001,0x1111111111111111111111111111111111111111,{a},{b},3000,1000000,v3,,\n"
            )
            .unwrap();
        }
        {
            let mut f = std::fs::File::create(&p4).unwrap();
            let id = "22".repeat(32);
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0x8366a39CC670B4001A1121B8F6A443A643e40951,0x2222222222222222222222222222222222222222,{a},{b},0,1000000,v4,0x{id},\n"
            )
            .unwrap();
        }
        let m3 = load_catalog(&p3).unwrap();
        let m4 = load_catalog(&p4).unwrap();
        let all_a: Vec<_> = m3.into_values().collect();
        let all_b: Vec<_> = m4.into_values().collect();
        let selected = HashSet::from([pair_key(a.parse().unwrap(), b.parse().unwrap())]);
        let kept = expand_manifest_catalog(&all_a, &all_b, &selected, 2_000).unwrap();
        // The zero-fee v4 row must be dropped; only the v3 leg survives.
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].profile, *b"v3");
    }

    #[test]
    fn virtual_reserves_is_consistent_with_liquidity() {
        // At Q64.96 sqrt == 2^96 the price is 1.0, so virtual reserves equal L.
        let (r0, r1) = virtual_reserves(U256::from(1u64) << 96, U256::from(1_000_000u64));
        assert_eq!(r0, U256::from(1_000_000u64));
        assert_eq!(r1, U256::from(1_000_000u64));

        // Doubling sqrt halves reserve0 and doubles reserve1 (price moves up).
        let (r0b, r1b) = virtual_reserves(U256::from(1u64) << 97, U256::from(1_000_000u64));
        assert_eq!(r0b, U256::from(500_000u64));
        assert_eq!(r1b, U256::from(2_000_000u64));
    }

    #[test]
    fn quote_pair_profits_when_skew_exceeds_toll() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let a = "0x1000000000000000000000000000000000000000";
        let b = "0x2000000000000000000000000000000000000000";
        let p3 = dir.path().join("v3.csv");
        let p4 = dir.path().join("v4.csv");
        {
            let mut f = std::fs::File::create(&p3).unwrap();
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0xfa00000000000000000000000000000000000001,0x1111111111111111111111111111111111111111,{a},{b},3000,1000000,v3,,\n"
            )
            .unwrap();
        }
        {
            let mut f = std::fs::File::create(&p4).unwrap();
            let id = "33".repeat(32);
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0x8366a39CC670B4001A1121B8F6A443A643e40951,0x2222222222222222222222222222222222222222,{a},{b},2500,1000000,v4,0x{id},\n"
            )
            .unwrap();
        }
        let m3 = load_catalog(&p3).unwrap();
        let m4 = load_catalog(&p4).unwrap();
        let a_entries: Vec<_> = m3.into_values().collect();
        let b_entries: Vec<_> = m4.into_values().collect();

        let mut pa = HashMap::new();
        pa.insert(
            a_entries[0].venue.into_word().into(),
            PoolPrice {
                sqrt: U256::from(1u64) << 97,
                liquidity: U256::from(1_000_000_000u64),
                block: 1,
            },
        );
        let mut pb = HashMap::new();
        pb.insert(
            b_entries[0].id,
            PoolPrice {
                sqrt: U256::from(1u64) << 98,
                liquidity: U256::from(1_000_000_000u64),
                block: 1,
            },
        );

        let quote = quote_pair(&a_entries, &b_entries, &pa, &pb)
            .unwrap()
            .expect("profitable pair must produce a quote");
        assert_eq!(quote.token_lo, a_entries[0].token0);
        assert_eq!(quote.token_hi, a_entries[0].token1);
        assert!(quote.profit > U256::ZERO);
        assert!(quote.log2_skew >= 1.9); // ~2 as built above.
        assert!(quote.toll > 0.0);
    }

    #[test]
    fn quote_pair_requires_a_priced_leg_on_both_venues() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let a = "0x1000000000000000000000000000000000000000";
        let b = "0x2000000000000000000000000000000000000000";
        let p3 = dir.path().join("v3.csv");
        let p4 = dir.path().join("v4.csv");
        {
            let mut f = std::fs::File::create(&p3).unwrap();
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0xfa00000000000000000000000000000000000001,0x1111111111111111111111111111111111111111,{a},{b},3000,1000000,v3,,\n"
            )
            .unwrap();
        }
        {
            let mut f = std::fs::File::create(&p4).unwrap();
            let id = "33".repeat(32);
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0x8366a39CC670B4001A1121B8F6A443A643e40951,0x2222222222222222222222222222222222222222,{a},{b},2500,1000000,v4,0x{id},\n"
            )
            .unwrap();
        }
        let m3 = load_catalog(&p3).unwrap();
        let m4 = load_catalog(&p4).unwrap();
        let a_entries: Vec<_> = m3.into_values().collect();
        let b_entries: Vec<_> = m4.into_values().collect();

        // No prices on either side -> no legs to quote.
        let pa = HashMap::new();
        let pb = HashMap::new();
        assert!(quote_pair(&a_entries, &b_entries, &pa, &pb).is_err());

        // Price only on one venue -> no cycle forms.
        let mut pa = HashMap::new();
        pa.insert(
            a_entries[0].venue.into_word().into(),
            PoolPrice {
                sqrt: U256::from(1u64) << 97,
                liquidity: U256::from(1_000_000u64),
                block: 1,
            },
        );
        assert!(quote_pair(&a_entries, &b_entries, &pa, &pb).is_err());
    }

    #[test]
    fn quote_manifest_returns_only_captureable_pairs() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let a = "0x1000000000000000000000000000000000000000";
        let b = "0x2000000000000000000000000000000000000000";
        let red = "0x3000000000000000000000000000000000000000";
        let p3 = dir.path().join("v3.csv");
        let p4 = dir.path().join("v4.csv");
        {
            let mut f = std::fs::File::create(&p3).unwrap();
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0xfa00000000000000000000000000000000000001,0x1111111111111111111111111111111111111111,{a},{b},3000,1000000,v3,,\n\
                 4663,0xfb00000000000000000000000000000000000002,0x1111111111111111111111111111111111111111,{a},{red},3000,1000000,v3,,\n"
            )
            .unwrap();
        }
        {
            let mut f = std::fs::File::create(&p4).unwrap();
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0x8366a39CC670B4001A1121B8F6A443A643e40951,0x2222222222222222222222222222222222222222,{a},{b},2500,1000000,v4,0x{},\n"
                , "11".repeat(32)
            )
            .unwrap();
        }
        let m3 = load_catalog(&p3).unwrap();
        let m4 = load_catalog(&p4).unwrap();
        let a_entries: Vec<_> = m3.into_values().collect();
        let b_entries: Vec<_> = m4.into_values().collect();
        assert!(a_entries.len() == 2 && b_entries.len() == 1);

        let mut pa = HashMap::new();
        for entry in &a_entries {
            pa.insert(
                entry.venue.into_word().into(),
                PoolPrice {
                    sqrt: U256::from(1u64) << 97,
                    liquidity: U256::from(1_000_000_000u64),
                    block: 1,
                },
            );
        }
        let mut pb = HashMap::new();
        pb.insert(
            b_entries[0].id,
            PoolPrice {
                sqrt: U256::from(1u64) << 98,
                liquidity: U256::from(1_000_000_000u64),
                block: 1,
            },
        );

        let quotes = quote_manifest(&a_entries, &b_entries, &pa, &pb);
        // Only the (a,b) pair has a leg on venue B, so only it can quote.
        assert_eq!(quotes.len(), 1);
        let a_addr: Address = a.parse().unwrap();
        let b_addr: Address = b.parse().unwrap();
        let wanted = pair_key(a_addr, b_addr);
        assert_eq!(pair_key(quotes[0].token_lo, quotes[0].token_hi), wanted);
        assert!(quotes[0].profit > U256::ZERO);
    }

    #[test]
    fn quote_pair_skips_unpriced_legs_on_a_venue() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let a = "0x1000000000000000000000000000000000000000";
        let b = "0x2000000000000000000000000000000000000000";
        let p3 = dir.path().join("v3.csv");
        let p4 = dir.path().join("v4.csv");
        {
            let mut f = std::fs::File::create(&p3).unwrap();
            // Two v3 pools for the same pair; the first listed one will be
            // left unpriced, the second carries the live price.
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0xfa00000000000000000000000000000000000001,0x1111111111111111111111111111111111111111,{a},{b},3000,1000000,v3,,\n\
                 4663,0xfb00000000000000000000000000000000000002,0x1111111111111111111111111111111111111111,{a},{b},3000,1000000,v3,,\n"
            )
            .unwrap();
        }
        {
            let mut f = std::fs::File::create(&p4).unwrap();
            let id = "33".repeat(32);
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0x8366a39CC670B4001A1121B8F6A443A643e40951,0x2222222222222222222222222222222222222222,{a},{b},2500,1000000,v4,0x{id},\n"
            )
            .unwrap();
        }
        let m3 = load_catalog(&p3).unwrap();
        let m4 = load_catalog(&p4).unwrap();
        let a_entries: Vec<_> = m3.into_values().collect();
        let b_entries: Vec<_> = m4.into_values().collect();
        assert_eq!(a_entries.len(), 2);
        assert_eq!(b_entries.len(), 1);

        // Price only the second v3 pool (venue door `fb`).
        let mut pa = HashMap::new();
        pa.insert(
            "0xfb00000000000000000000000000000000000002"
                .parse::<Address>()
                .unwrap()
                .into_word()
                .into(),
            PoolPrice {
                sqrt: U256::from(1u64) << 97,
                liquidity: U256::from(1_000_000_000u64),
                block: 1,
            },
        );
        let mut pb = HashMap::new();
        pb.insert(
            b_entries[0].id,
            PoolPrice {
                sqrt: U256::from(1u64) << 98,
                liquidity: U256::from(1_000_000_000u64),
                block: 1,
            },
        );

        // The unpriced leg must be skipped, not treated as "venue has no leg".
        let quote = quote_pair(&a_entries, &b_entries, &pa, &pb)
            .unwrap()
            .expect("priced leg must be found despite an unpriced sibling");
        assert_eq!(quote.token_lo, a_entries[0].token0);
        assert!(quote.profit > U256::ZERO);
    }
}
