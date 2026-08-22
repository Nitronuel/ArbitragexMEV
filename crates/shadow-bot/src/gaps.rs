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

/// Legs charging more than half the output per swap are unquotable placeholders
/// (honeypots, "rejected" high-fee pools, or catalog noise), never viable round
/// trips. `leg_toll` yields `None` for them so selection, ranking, and quoting
/// all exclude the dead tail instead of paying its toll inside `margin`.
pub const MAX_QUOTABLE_FEE: f64 = 0.5;

/// The sqrtPriceX96 convention factor in [`price_out`]: raw wei price × K.
const SQRT_PRICE_CONVENTION_K: f64 = 79_228_162_514_264_337_593_543_950_336.0;

/// RHC encodes the wrapped native token in v2/v3 pool addresses with its real
/// contract address, while v4 `PoolKey`s use the `0x0..0` sentinel for the
/// native currency. Cross-venue matching must normalize the sentinel to the
/// native contract.
pub const RHC_NATIVE: Address =
    alloy_primitives::address!("0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73");

/// USDG, the $1.00 base stablecoin anchor used to derive per-token USD prices
/// from a direct `(USG, token)` leg. 6 decimals, 1:1 USD-backed by Paxos;
/// re-verified 2026-08-06 from the catalog suppliers. The persistent cross
/// pairs anchor on [`RHC_NATIVE`], so USD values derived against USDG are
/// then revalued through the WETH/USDG legs where needed.
pub const RHC_USDG: Address =
    alloy_primitives::address!("0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168");

/// Upper bound on a plausible `usd_per_token` price row (~$2.5M per whole
/// token at 18 decimals). `derive-prices` output stays 3-4 orders below this;
/// a hand-planted or corrupted row far above it (e.g. the 2.5e24 native row
/// that silently gated every native pair) is rejected so a bad price can never
/// flip quotes to `AboveThreshold`. The USDG anchor pin (`1e30`) exceeds this
/// bound by construction and is exempted.
pub const MAX_USD_PER_TOKEN: U256 = U256::from_limbs([0x1bce_cced_a100_0000, 0xd3c2, 0, 0]);

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
pub fn f64_of(v: U256) -> f64 {
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
pub fn leg_toll(fee: u32, fee_denominator: u32, profile: [u8; 2]) -> Option<f64> {
    if profile == *b"v4" && (fee == 0 || fee & V4_DYNAMIC_FEE_FLAG != 0) {
        return None;
    }
    if fee_denominator == 0 {
        return None;
    }
    let toll = f64::from(fee) / f64::from(fee_denominator);
    if toll > MAX_QUOTABLE_FEE {
        return None;
    }
    Some(toll)
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
        let normalized = normalize_currency(token);
        if !usd.is_zero() && normalized != RHC_USDG && usd > MAX_USD_PER_TOKEN {
            return Err(format!(
                "implausible usd_per_token {usd} for {token} (max {MAX_USD_PER_TOKEN}); \
                 reject a hand-planted or mis-derived price that would over-gate quotes"
            ));
        }
        out.insert(normalized, usd);
    }
    Ok(out)
}

/// USDG base-10 decimals. Only the *anchor's* scale appears in the derived
/// fixed-point price because the token side's decimals cancel in the `USD per
/// whole token × 10^(36-dec)` conversion (see [`derive_usd_prices`]).
pub const RHC_USDG_DECIMALS: u8 = 6;

/// Keeps only the catalog pools that can price a token in USD terms: a direct
/// `(USG, token)` leg, or a `(native WETH, token)` leg used to revalue a token
/// that had no priced USG leg in the window. When `seeds` is present the
/// non-anchor side must be one of the seed tokens.
#[must_use]
pub fn usd_legs_for(
    a: &[PoolEntry],
    b: &[PoolEntry],
    seeds: Option<&HashSet<Address>>,
) -> (Vec<PoolEntry>, Vec<PoolEntry>) {
    let is_anchor = |t: Address| t == RHC_USDG || t == RHC_NATIVE;
    let keep = |e: &PoolEntry| {
        let anchored = is_anchor(e.token0) ^ is_anchor(e.token1);
        if !anchored {
            return false;
        }
        let other = if is_anchor(e.token0) {
            e.token1
        } else {
            e.token0
        };
        seeds.is_none_or(|set| set.contains(&other)) && !other.is_zero()
    };
    let pick = |entries: &[PoolEntry]| {
        entries
            .iter()
            .copied()
            .filter(keep)
            .collect::<Vec<PoolEntry>>()
    };
    (pick(a), pick(b))
}

/// `10^exp` as a `U256`.
#[must_use]
fn factor_ten(exp: usize) -> U256 {
    let mut factor = U256::from(1_u8);
    for _ in 0..exp {
        factor *= U256::from(10_u8);
    }
    factor
}

/// `numerator × factor / denominator`, i.e. the USD per token when the
/// numerator is the USDG-side reserve and the denominator the token-side one.
#[must_use]
fn scale_over(
    numerator: U256,
    denominator: U256,
    factor: U256,
    token: Address,
) -> Option<(Address, U256)> {
    if denominator.is_zero() {
        return None;
    }
    numerator
        .checked_mul(factor)
        .and_then(|value| value.checked_div(denominator))
        .map(|value| (token, value))
}

/// A fixed-point USD price per whole token for each token priced by a USG leg
/// (or a native-leg revalue), matching the `load_prices`/economics scale.
#[must_use]
pub fn derive_usd_prices(
    a: &[PoolEntry],
    b: &[PoolEntry],
    prices_a: &HashMap<[u8; 32], PoolPrice>,
    prices_b: &HashMap<[u8; 32], PoolPrice>,
) -> HashMap<Address, U256> {
    let usd_factor_exp = 36usize.saturating_sub(usize::from(RHC_USDG_DECIMALS));
    let usd_factor = factor_ten(usd_factor_exp);
    let mut usg_samples: HashMap<Address, Vec<U256>> = HashMap::new();
    let mut weth_ratio: HashMap<Address, Vec<(U256, U256)>> = HashMap::new();
    let mut accumulate = |entries: &[PoolEntry], prices: &HashMap<[u8; 32], PoolPrice>| {
        for entry in entries {
            let Some(price) = prices.get(&pool_key(entry)) else {
                continue;
            };
            let (r0, r1) = virtual_reserves(price.sqrt, price.liquidity);
            match (entry.token0, entry.token1) {
                (RHC_USDG, token) => {
                    if let Some((token, sample)) = scale_over(r0, r1, usd_factor, token) {
                        usg_samples.entry(token).or_default().push(sample);
                    }
                }
                (token, RHC_USDG) => {
                    if let Some((token, sample)) = scale_over(r1, r0, usd_factor, token) {
                        usg_samples.entry(token).or_default().push(sample);
                    }
                }
                (RHC_NATIVE, token) if !r1.is_zero() => {
                    // Ratio stored as (WETH side, token side) reserves and
                    // only scaled once WETH's USD price is known; dividing
                    // the raw ratio here truncates sub-1 values to zero.
                    weth_ratio.entry(token).or_default().push((r0, r1));
                }
                (token, RHC_NATIVE) if !r0.is_zero() => {
                    weth_ratio.entry(token).or_default().push((r1, r0));
                }
                _ => {}
            }
        }
    };
    accumulate(a, prices_a);
    accumulate(b, prices_b);

    let mut out: HashMap<Address, U256> = HashMap::new();
    out.insert(RHC_USDG, usd_factor);

    // WETH first: its USD price feeds every native-leg fallback below.
    let weth_usd = usg_samples
        .get(&RHC_NATIVE)
        .and_then(|samples| median_u256(samples))
        .unwrap_or_default();

    for (token, samples) in &usg_samples {
        if let Some(usd) = median_u256(samples) {
            out.insert(*token, usd);
        }
    }
    for (token, pairs) in &weth_ratio {
        if out.contains_key(token) {
            continue;
        }
        let samples = pairs
            .iter()
            .filter_map(|(num, den)| weth_usd.checked_mul(*num).and_then(|v| v.checked_div(*den)))
            .collect::<Vec<U256>>();
        if let Some(usd) = median_u256(&samples) {
            out.insert(*token, usd);
        }
    }
    out
}

/// Median of sorted fixed-point samples.
#[must_use]
fn median_u256(samples: &[U256]) -> Option<U256> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    Some(sorted[sorted.len() / 2])
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
/// `chunk_window` bounds how many V3 address chunks are swept per block-window
/// iteration this call: the full universe exceeds Alchemy's per-request filter
/// limits, so a caller on a budget ring-swings through the universe over
/// consecutive polls while V4 (a single singleton stream) is always swept
/// complete. `None` sweeps the whole key set. The ring offset skips
/// `start_chunk` chunks and wraps; the count is clamped to the chunk list so a
/// single call never issues a duplicate request.
///
/// # Errors
///
/// Returns a [`TransportError`] on an empty filter or a transport/budget
/// failure.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub fn sweep_swap_prices<B, S>(
    reader: &ChainReader<B, S>,
    profile: [u8; 2],
    pool_manager: Address,
    keys: &[PoolEntry],
    from: u64,
    to: u64,
    window: u64,
    request_delay: Duration,
    chunk_window: Option<(u64, u64)>,
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
        if profile == *b"v4" {
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
        } else {
            let chunks: Vec<&[PoolEntry]> = keys.chunks(MAX_ADDRESS_CHUNK).collect();
            let chunk_count = chunks.len().max(1);
            let (skip, take) = match chunk_window {
                Some((start_chunk, count)) if count > 0 => (
                    usize::try_from(start_chunk).map_or(0, |s| s % chunk_count),
                    usize::try_from(count).map_or(chunks.len(), |c| c.min(chunks.len())),
                ),
                _ => (0, chunks.len()),
            };
            for chunk in chunks.into_iter().cycle().skip(skip).take(take) {
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
                || leg_toll(entry.fee, entry.fee_denominator, entry.profile).is_none()
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
                let Some(toll) = leg_toll(entry.fee, entry.fee_denominator, entry.profile) else {
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
    /// Block number of the oldest (`PoolPrice.block`) among the legs used by
    /// this quote. A quote whose reference leg is refresh-starved — cached
    /// once and never re-priced by the ring sweep — carries a stale price, so
    /// its skew is not a live cross-venue gap. The evaluator screens quotes
    /// older than its `max_price_age` bound instead of gating them.
    pub oldest_leg_block: u64,
}

/// Reduces a concentrated pool's sampled state to the virtual constant-product
/// reserves at the sampled price, at which `x*y = L²` and `y/x = price` hold.
/// `sqrt` is the `Q64.96` post-swap price, `liquidity` the in-range `L`.
#[must_use]
pub fn virtual_reserves(sqrt: U256, liquidity: U256) -> (U256, U256) {
    use ruint::{Uint, UintTryFrom};
    const ONE: U256 = U256::from_limbs([1, 0, 0, 0]);
    let two_96: U256 = ONE << 96;
    // Provider-controlled values (sqrtPriceX96 up to ~2^250, liquidity up to
    // 2^128) can overflow 256-bit products on extreme-ratio longtail pools.
    // Widen to 512 bits and saturate: a saturated reserve only makes the leg
    // look deeper, never panics or wraps.
    let wide_sqrt = Uint::<512, 8>::from(sqrt);
    let wide_liquidity = Uint::<512, 8>::from(liquidity);
    let wide_two_96 = Uint::<512, 8>::from(two_96);
    let saturate = |value: Uint<512, 8>| U256::uint_try_from(value).unwrap_or(U256::MAX);
    let reserve0 = wide_liquidity * wide_two_96 / wide_sqrt.max(Uint::<512, 8>::from(1));
    let reserve1 = wide_liquidity * wide_sqrt / wide_two_96;
    (saturate(reserve0), saturate(reserve1))
}

/// Builds the 2-hop cycle for one cross-venue pair and solves the closed-form
/// optimal input with the sampled virtual reserves. Picks the tighter
/// (cheaper-fee) pool per venue for the legs.
///
/// # Errors
///
/// Returns a message describing malformed cycles or missing state.
/// Oriented cross-venue skew for a pair: `|log2(q_b / q_a)|`, where each
/// venue's pool price is first re-expressed as the canonical-direction
/// (`hi per lo`) wei ratio scaled by the 2^96 sqrtPriceX96 convention.
///
/// V4 native pools carry the zero address as currency0; after normalization
/// to the wrapped native the two venues can list the same pair in opposite
/// orders. Comparing raw prices directly makes the ratio — and therefore the
/// skew screen — meaningless for exactly the most liquid native pairs.
#[must_use]
pub fn oriented_pair_skew(
    entry_a: &PoolEntry,
    price_a: &PoolPrice,
    entry_b: &PoolEntry,
    price_b: &PoolPrice,
    canonical_lo: Address,
) -> f64 {
    // `price_out` = raw_price × K with K = 2^96 and raw_price = t1/t0.
    // A pool listing the canonical-lo token as token1 inverts the ratio;
    // invert it back while keeping the K scaling so the convention cancels
    // between venues.
    let orient = |entry: &PoolEntry, price: &PoolPrice| -> f64 {
        let raw_conventioned = price_out(price.sqrt);
        if entry.token0 == canonical_lo {
            raw_conventioned
        } else {
            SQRT_PRICE_CONVENTION_K * SQRT_PRICE_CONVENTION_K
                / raw_conventioned.max(f64::MIN_POSITIVE)
        }
    };
    let qa = orient(entry_a, price_a);
    let qb = orient(entry_b, price_b);
    (qb / qa).log2().abs()
}

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
            let Some(toll) = leg_toll(entry.fee, entry.fee_denominator, entry.profile) else {
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
    // See `oriented_pair_skew`: raw pool prices must be re-expressed in the
    // canonical pair direction before comparing venues.
    let skew = oriented_pair_skew(&leg_a, &leg_price_a, &leg_b, &leg_price_b, anchor);
    Ok(Some(PairQuote {
        token_lo: anchor,
        token_hi: other,
        input: quote.input,
        output: quote.output,
        profit: quote.profit,
        toll,
        log2_skew: skew,
        oldest_leg_block: leg_price_a.block.min(leg_price_b.block),
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

/// A three-hop token cycle (triangle) over cross-venue pairs: every `(a,b)`,
/// `(b,c)`, `(c,a)` edge is present on both venues, so a cyclic round trip
/// through the three legs is affordable in principle.
pub type TokenTriple = ([u8; 20], [u8; 20], [u8; 20]);

/// Enumerates every cross-venue triangle whose three edges all carry a
/// quotable leg on both venues (structural overlap only — independent of any
/// observed prices). The triples are sorted (`lo <= mid <= hi` bytewise) and
/// returned in deterministic order.
///
/// The caller pairs each edge with the cheapest priced leg (see
/// [`best_leg_for_pair`]) to build a concrete three-hop cycle.
#[must_use]
pub fn enumerate_triangles(a: &[PoolEntry], b: &[PoolEntry]) -> Vec<TokenTriple> {
    // A triangle edge must be a canonical token pair with a quotable leg on
    // BOTH venues, so the cyclic round trip can actually cross venues.
    let mut quotable_both: HashSet<([u8; 20], [u8; 20])> = HashSet::new();
    let mut per_pair: HashMap<([u8; 20], [u8; 20]), u8> = HashMap::new();
    let usable = |e: &PoolEntry| leg_toll(e.fee, e.fee_denominator, e.profile).is_some();
    for e in a.iter().filter(|e| usable(e)) {
        let k = pair_key(e.token0, e.token1);
        *per_pair.entry(k).or_default() |= 1;
    }
    for e in b.iter().filter(|e| usable(e)) {
        let k = pair_key(e.token0, e.token1);
        *per_pair.entry(k).or_default() |= 2;
    }
    for (k, mask) in &per_pair {
        if *mask == 0b11 {
            quotable_both.insert(*k);
        }
    }
    let mut adj: HashMap<[u8; 20], Vec<[u8; 20]>> = HashMap::new();
    for (lo, hi) in &quotable_both {
        adj.entry(*lo).or_default().push(*hi);
        adj.entry(*hi).or_default().push(*lo);
    }
    for v in adj.values_mut() {
        v.sort_unstable();
        v.dedup();
    }
    let mut keys: Vec<[u8; 20]> = adj.keys().copied().collect();
    keys.sort_unstable();
    let index: HashMap<[u8; 20], usize> = keys.iter().enumerate().map(|(i, k)| (*k, i)).collect();
    let mut triples = Vec::new();
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
                    triples.push((*u, *v_neighbor, *w));
                }
            }
        }
    }
    triples
}

/// One leg of a cyclic quote: the concrete pool used.
struct CycleLeg {
    entry: PoolEntry,
    price: PoolPrice,
}

/// Picks the cheapest-toll priced leg for a canonical token pair across both
/// venues from pre-bucketed pool sets (the evaluator's `by_pair` index),
/// orientated so the leg runs `from -> to`.
fn cheapest_leg_in(
    pair: ([u8; 20], [u8; 20]),
    buckets: &PoolByPair,
    prices_a: &HashMap<[u8; 32], PoolPrice>,
    prices_b: &HashMap<[u8; 32], PoolPrice>,
) -> Option<CycleLeg> {
    let (a_pools, b_pools) = buckets.get(&pair)?;
    let mut best: Option<(CycleLeg, f64)> = None;
    for (entries, prices) in [(a_pools, prices_a), (b_pools, prices_b)] {
        for entry in entries {
            let Some(toll) = leg_toll(entry.fee, entry.fee_denominator, entry.profile) else {
                continue;
            };
            let Some(price) = prices.get(&pool_key(entry)) else {
                continue;
            };
            if best.as_ref().is_none_or(|(_, t)| toll < *t) {
                best = Some((
                    CycleLeg {
                        entry: *entry,
                        price: *price,
                    },
                    toll,
                ));
            }
        }
    }
    best.map(|(leg, _)| leg)
}

/// Quotes a three-hop triangle cycle `p0 -> p1 -> p2 -> p0`, choosing the
/// cheapest-toll priced leg per edge across both venues from pre-bucketed
/// pools. Returns the closed-form `input`/`output`/`profit`, the compounded
/// round-trip toll, and the observed log2 price drift.
///
/// # Errors
///
/// Returns a message describing malformed cycles or missing state.
pub fn quote_triangle(
    p0: Address,
    p1: Address,
    p2: Address,
    buckets: &PoolByPair,
    prices_a: &HashMap<[u8; 32], PoolPrice>,
    prices_b: &HashMap<[u8; 32], PoolPrice>,
) -> Result<Option<PairQuote>, String> {
    use domain::{Cycle, CycleHop, CycleId, Fee, PoolId, PoolState, StateVersion};
    use v2_math::optimal_input;

    let leg01 = cheapest_leg_in(pair_key(p0, p1), buckets, prices_a, prices_b)
        .ok_or("triangle edge p0-p1 unpriced")?;
    let leg12 = cheapest_leg_in(pair_key(p1, p2), buckets, prices_a, prices_b)
        .ok_or("triangle edge p1-p2 unpriced")?;
    let leg20 = cheapest_leg_in(pair_key(p2, p0), buckets, prices_a, prices_b)
        .ok_or("triangle edge p2-p0 unpriced")?;

    let states: Vec<PoolState> = [&leg01, &leg12, &leg20]
        .into_iter()
        .map(|leg| {
            let (r0, r1) = virtual_reserves(leg.price.sqrt, leg.price.liquidity);
            PoolState {
                reserve0: r0,
                reserve1: r1,
                block_number: leg.price.block,
                transaction_index: 0,
                log_index: 0,
                version: StateVersion(leg.price.block),
            }
        })
        .collect();
    let fee = |leg: &CycleLeg| Fee {
        numerator: leg.entry.fee_denominator.saturating_sub(leg.entry.fee),
        denominator: leg.entry.fee_denominator,
    };
    let cycle = Cycle {
        id: CycleId(0),
        anchor: p0,
        hops: vec![
            CycleHop {
                pool_id: PoolId(0),
                token_in: p0,
                token_out: p1,
                fee: fee(&leg01),
                zero_for_one: leg01.entry.token0 == p0,
            },
            CycleHop {
                pool_id: PoolId(1),
                token_in: p1,
                token_out: p2,
                fee: fee(&leg12),
                zero_for_one: leg12.entry.token0 == p1,
            },
            CycleHop {
                pool_id: PoolId(2),
                token_in: p2,
                token_out: p0,
                fee: fee(&leg20),
                zero_for_one: leg20.entry.token0 == p2,
            },
        ],
    };
    let Some(quote) =
        optimal_input(&cycle, &states).map_err(|e| format!("optimal input failed: {e}"))?
    else {
        return Ok(None);
    };
    let keep = |leg: &CycleLeg| {
        1.0 - leg_toll(leg.entry.fee, leg.entry.fee_denominator, leg.entry.profile).unwrap_or(0.0)
    };
    let toll = 1.0 - keep(&leg01) * keep(&leg12) * keep(&leg20);
    // Orient each leg into its cycle direction (`token_out per token_in`,
    // convention-scaled) so the product is 2^288 at parity regardless of
    // each pool's internal token ordering; the baseline is subtracted below.
    let oriented_cycle_price = |leg: &CycleLeg, token_in: Address| -> f64 {
        let raw_conventioned = price_out(leg.price.sqrt);
        if leg.entry.token0 == token_in {
            raw_conventioned
        } else {
            SQRT_PRICE_CONVENTION_K * SQRT_PRICE_CONVENTION_K
                / raw_conventioned.max(f64::MIN_POSITIVE)
        }
    };
    let cycle_product = oriented_cycle_price(&leg01, p0)
        * oriented_cycle_price(&leg12, p1)
        * oriented_cycle_price(&leg20, p2);
    // Each `price_out` carries the ×2^96 sqrtPriceX96 convention factor
    // (price_out = raw-wei price × 2^96). Raw-wei prices telescope to 1 at
    // economic parity around a closed cycle (decimal exponents cancel), so
    // the expected product is 2^(96·3); subtract that baseline before taking
    // the magnitude, or every triangle is screened by a decimals-driven
    // constant instead of real dislocation.
    let log2_skew = (cycle_product.log2() - 288.0).abs();
    Ok(Some(PairQuote {
        token_lo: p0,
        token_hi: p2,
        input: quote.input,
        output: quote.output,
        profit: quote.profit,
        toll,
        log2_skew,
        oldest_leg_block: leg01
            .price
            .block
            .min(leg12.price.block)
            .min(leg20.price.block),
    }))
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
            let quoted_toll = leg_toll(entry.fee, entry.fee_denominator, entry.profile).is_some();
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
        assert_eq!(leg_toll(10_000, 1_000_000, *b"v3"), Some(0.01));
        assert_eq!(leg_toll(50, 1_000_000, *b"v3"), Some(0.00005));
        assert_eq!(leg_toll(0, 1_000_000, *b"v4"), None);
        assert_eq!(leg_toll(V4_DYNAMIC_FEE_FLAG, 1_000_000, *b"v4"), None);
        assert_eq!(leg_toll(10_000, 1_000_000, *b"v4"), Some(0.01));
    }

    #[test]
    fn oriented_pair_skew_handles_opposite_token_orders() {
        // Parity price in both venues: sqrt = 2^96 (price_out = 2^96).
        let parity = U256::from(1u64) << 96;
        let price = |sqrt: U256| PoolPrice {
            sqrt,
            liquidity: U256::from(1_000_000_u64),
            block: 1,
        };
        let lo: Address = "0x1000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let hi: Address = "0x2000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let venue_a = price_entry(
            "0xaa00000000000000000000000000000000000001"
                .parse()
                .unwrap(),
            lo,
            hi,
        );
        let venue_b_sorted = price_entry(
            "0xaa00000000000000000000000000000000000002"
                .parse()
                .unwrap(),
            lo,
            hi,
        );
        // Same pair, opposite internal order (as normalized V4 native pools).
        let venue_b_reversed = price_entry(
            "0xaa00000000000000000000000000000000000003"
                .parse()
                .unwrap(),
            hi,
            lo,
        );

        // Sorted-vs-sorted at parity: zero skew.
        assert_eq!(
            oriented_pair_skew(
                &venue_a,
                &price(parity),
                &venue_b_sorted,
                &price(parity),
                lo
            ),
            0.0
        );
        // Opposite order at parity must ALSO be zero — the old raw-ratio
        // skew reported ~192 here and screened every native pair.
        assert!(
            (oriented_pair_skew(
                &venue_a,
                &price(parity),
                &venue_b_reversed,
                &price(parity),
                lo
            ) - 0.0)
                .abs()
                < 1e-9
        );
        // A genuine 4× dislocation reads as log2(4) = 2 regardless of order
        // (price_out scales with sqrt²).
        let moved = U256::from(1u64) << 98;
        assert!(
            (oriented_pair_skew(&venue_a, &price(parity), &venue_b_sorted, &price(moved), lo)
                - 4.0)
                .abs()
                < 1e-6
        );
    }

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
    fn load_prices_rejects_implausible_price_row() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad-prices.csv");
        let other: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        // The corrupted native row that silently gated every native pair
        // (2.5e24 = ~$2.5M/token at 18 decimals) must be rejected.
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            "token,usd_per_token\n0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73,2500000000000000000000000\n{other},1800000000000000000\n"
        )
        .unwrap();
        drop(f);
        let error = load_prices(&path).unwrap_err();
        assert!(
            error.contains("implausible usd_per_token"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn load_prices_allows_usdg_anchor_pin() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prices.csv");
        let usdg: Address = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168"
            .parse()
            .unwrap();
        let mut f = std::fs::File::create(&path).unwrap();
        // USDG's 1e30 pin ($1 at 6 decimals) exceeds the general bound by
        // construction and is the anchor, so it must stay accepted.
        write!(
            f,
            "token,usd_per_token\n{usdg},1000000000000000000000000000000\n"
        )
        .unwrap();
        drop(f);
        let map = load_prices(&path).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(&usdg).copied(), Some(U256::from(10u128.pow(30))));
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
        assert!(leg_toll(entry.fee, entry.fee_denominator, entry.profile).is_none());
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
    fn virtual_reserves_saturates_instead_of_panicking_on_extreme_inputs() {
        use alloy_primitives::U256;
        // Near-max sqrtPriceX96 with maximal liquidity: the old 256-bit
        // `liquidity * sqrt` product overflowed (panic in debug builds).
        let sqrt = U256::MAX >> 8;
        let liquidity = U256::MAX;
        let (r0, r1) = super::virtual_reserves(sqrt, liquidity);
        assert!(r0 > U256::ZERO);
        assert!(r1 > U256::ZERO);
        // realistic values must remain exact
        let sqrt_r = U256::from(1_000_000_000_000_000_000_u64);
        let liq = U256::from(1_000_000_000_000_u64);
        let two_96 = U256::from(1) << 96;
        let (r0, r1) = super::virtual_reserves(sqrt_r, liq);
        assert_eq!(r0, liq * two_96 / sqrt_r);
        assert_eq!(r1, liq * sqrt_r / two_96);
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

    fn price_entry(venue: Address, token0: Address, token1: Address) -> PoolEntry {
        PoolEntry {
            profile: *b"v4",
            venue,
            id: venue.into_word().into(),
            fee: 500,
            token0,
            token1,
            fee_denominator: 1_000_000,
            factory: Address::ZERO,
            chain_id: 4663,
        }
    }

    fn price_map(entry: &PoolEntry, sqrt: U256, liquidity: U256) -> HashMap<[u8; 32], PoolPrice> {
        let mut prices = HashMap::new();
        prices.insert(
            pool_key(entry),
            PoolPrice {
                sqrt,
                liquidity,
                block: 1,
            },
        );
        prices
    }

    #[test]
    fn derive_usd_prices_prices_from_usg_leg() {
        let usg: Address = RHC_USDG;
        let token: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();

        // At sqrt = 2^97 the virtual-reserve ratio (sqrt/2^96)^2 = 4, so
        // reserve1 = 4×reserve0. For a (USG, token) pool, token1 is the token:
        // usd_per_token = (r0/r1) × 10^30 = (1/4) × 1e30 = 2.5e29.
        let sqrt = U256::from(1u64) << 97;
        let liquidity = U256::from(1_000_000_000u64);
        let entry = price_entry(Address::ZERO, usg, token);
        let prices = price_map(&entry, sqrt, liquidity);
        let out = derive_usd_prices(&[], &[entry], &HashMap::new(), &prices);
        assert_eq!(
            out[&token],
            U256::from(250_000_000_000_000_000_000_000_000_000_u128)
        );
    }

    #[test]
    fn derive_usd_prices_inverts_opposite_orientation() {
        let usg: Address = RHC_USDG;
        let token: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();

        // Reverse orientation: (token, USG), token0 = token. Then token1 is USG,
        // so usd_per_token = (r1/r0) × 10^30 = 4 × 1e30 = 4e30.
        let sqrt = U256::from(1u64) << 97;
        let liquidity = U256::from(1_000_000_000u64);
        let entry = price_entry(Address::ZERO, token, usg);
        let prices = price_map(&entry, sqrt, liquidity);
        let out = derive_usd_prices(&[], &[entry], &HashMap::new(), &prices);
        assert_eq!(
            out[&token],
            U256::from(4_000_000_000_000_000_000_000_000_000_000_u128)
        );
    }

    #[test]
    fn derive_usd_prices_pins_usg_to_one_dollar_and_uses_median() {
        let usg: Address = RHC_USDG;
        let token: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let other: Address = "0x2000000000000000000000000000000000000000"
            .parse()
            .unwrap();

        // Two distinct USG legs for the same token, same underlying ratio
        // range: pool1 gives usd=(1/4)*1e30, pool2 gives usd=(1/4)*1e30 at the
        // same sqrt but twice the liquidity (same price, more depth). The
        // median must equal the single-leg value and USG is pinned at $1.00.
        let e1 = price_entry(
            "0x2000000000000000000000000000000000000001"
                .parse()
                .unwrap(),
            usg,
            token,
        );
        let e2 = price_entry(
            "0x2000000000000000000000000000000000000002"
                .parse()
                .unwrap(),
            usg,
            token,
        );
        let mut priced = HashMap::new();
        for (entry, liquidity) in [
            (e1, U256::from(1_000_000_000u64)),
            (e2, U256::from(2_000_000_000u64)),
        ] {
            priced.insert(
                pool_key(&entry),
                PoolPrice {
                    sqrt: U256::from(1u64) << 97,
                    liquidity,
                    block: 1,
                },
            );
        }
        let out = derive_usd_prices(&[], &[e1, e2], &HashMap::new(), &priced);
        assert_eq!(
            out[&usg],
            U256::from(1_000_000_000_000_000_000_000_000_000_000_u128)
        );
        assert_eq!(
            out[&token],
            U256::from(250_000_000_000_000_000_000_000_000_000_u128)
        );
        assert!(!out.contains_key(&other));
    }

    #[test]
    fn derive_usd_prices_revalues_through_native_weth_leg() {
        let usg: Address = RHC_USDG;
        let token: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let native: Address = RHC_NATIVE;

        // WETH priced via a USG leg at sqrt=2^97: reserve ratio (1/4), so
        // weth_usd = (r0/r1) × 1e30 = 0.25e30 = 2.5e29.
        let weth = price_entry(
            "0x3000000000000000000000000000000000000001"
                .parse()
                .unwrap(),
            usg,
            native,
        );
        // Token priced only against WETH at sqrt=2^98: reserve_WETH/reserve_token
        // = r0/r1 = (L/4)/(4L) = 1/16, so usd = 2.5e29 / 16.
        let ratio = price_entry(
            "0x3000000000000000000000000000000000000002"
                .parse()
                .unwrap(),
            native,
            token,
        );

        let mut priced = HashMap::new();
        priced.insert(
            pool_key(&weth),
            PoolPrice {
                sqrt: U256::from(1u64) << 97,
                liquidity: U256::from(1_000_000_000u64),
                block: 1,
            },
        );
        priced.insert(
            pool_key(&ratio),
            PoolPrice {
                sqrt: U256::from(1u64) << 98,
                liquidity: U256::from(1_000_000_000u64),
                block: 1,
            },
        );

        let out = derive_usd_prices(&[], &[weth, ratio], &HashMap::new(), &priced);
        assert_eq!(
            out[&usg],
            U256::from(1_000_000_000_000_000_000_000_000_000_000_u128)
        );
        assert_eq!(
            out[&native],
            U256::from(250_000_000_000_000_000_000_000_000_000_u128)
        );
        // 250e27 / 16 = 15.625e27.
        assert_eq!(
            out[&token],
            U256::from(15_625_000_000_000_000_000_000_000_000_u128)
        );
    }

    #[test]
    fn usd_legs_for_restricts_by_seed_tokens() {
        let usg: Address = RHC_USDG;
        let native: Address = RHC_NATIVE;
        let seed: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let stranger: Address = "0xDeaDDeaDDeaDDeaDDeaDDeaDDeaDDeaDDeaDDeaD"
            .parse()
            .unwrap();

        let a = [
            price_entry(
                "0x1000000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
                usg,
                seed,
            ),
            price_entry(
                "0x1000000000000000000000000000000000000002"
                    .parse()
                    .unwrap(),
                usg,
                stranger,
            ),
            price_entry(
                "0x1000000000000000000000000000000000000003"
                    .parse()
                    .unwrap(),
                seed,
                seed,
            ),
        ];
        let seeds: HashSet<Address> = [seed, native].into_iter().collect();
        let (legs, b) = usd_legs_for(&a, &[], Some(&seeds));
        assert_eq!(legs.len(), 1);
        assert_eq!(legs[0].token0, usg);
        assert_eq!(legs[0].token1, seed);
        assert!(b.is_empty());

        // Without a seed restriction both anchored legs survive.
        let (all_legs, _) = usd_legs_for(&a, &[], None);
        assert_eq!(all_legs.len(), 2);
    }
}
