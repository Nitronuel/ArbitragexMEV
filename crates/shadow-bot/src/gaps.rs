use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use alloy_primitives::{Address, B256, U256};
use provider::{
    ChainReader, HttpBackend, LogFilter, RawLogEnvelope, Sleeper, TransportError, decode_v3_swap,
    decode_v4_swap, v3_swap_topic, v4_swap_topic,
};
use ruint::Uint;

/// Uniswap V4 marks a `PoolKey.fee` as dynamic (fee set by the hook, not the
/// encoded scalar) when the high bit is set; a fee of `0` is likewise not a
/// literal zero-fee pool. Round-trip toll accounting must drop such pools
/// unless their dynamic fee is observable.
pub const V4_DYNAMIC_FEE_FLAG: u32 = 0x0080_0000;

/// Legs charging more than half the output per swap are unquotable placeholders
/// (honeypots, "rejected" high-fee pools, or catalog noise), never viable round
/// trips. `leg_toll` yields `None` for them so selection, ranking, and quoting
/// all exclude the dead tail instead of paying its toll inside `margin`.
/// V4 fee gate for the quoter and the manifest hooks screen: the maximum
/// static toll a leg may carry and still be quoted (90%). Dynamic-fee
/// sentinels (`0` / `0x800000`) bypass this screen and resolve through
/// observed Swap fees instead; anything above the bound is refused, never
/// averaged in. Rationale (Phase 3 of
/// docs/plans/2026-09-09-v4-quoter-hook-hardening.md): an 89% toll still
/// screens at economics (dust output → `BelowThreshold`), while 90%+ is
/// predatory-by-construction and refused up front.
pub const MAX_QUOTABLE_FEE: f64 = 0.9; // was 0.5 (50%) — lifted for full range (was filtering >50% fee honeypots, now 90%)

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

/// Toll for one priced pool: the catalog fee when quotable, else the
/// **observed** fee from the pool's most recent V4 swap (audit task 3.1).
///
/// This is what re-admits the ~101k dynamic/zero-fee v4 pools that
/// `leg_toll` alone excludes: their hooks set the fee per swap, and every
/// swap event reports the fee actually charged. The observation rides in
/// [`PoolPrice`], so the same staleness screens that bound prices bound it;
/// a hook can still change the fee between swaps, so any submission built
/// on an observed fee must pass simulation first (Phase 2).
///
/// `None` = unquotable (no catalog fee AND no observed fee).
#[must_use]
pub fn effective_leg_toll(entry: &PoolEntry, price: &PoolPrice) -> Option<f64> {
    match leg_toll(entry.fee, entry.fee_denominator, entry.profile) {
        Some(toll) => Some(toll),
        None if entry.profile == *b"v4" => {
            let observed = f64::from(price.observed_fee?);
            let denominator = f64::from(entry.fee_denominator.max(1));
            let toll = observed / denominator;
            if observed <= 0.0 || toll > MAX_QUOTABLE_FEE {
                None
            } else {
                Some(toll)
            }
        }
        None => None,
    }
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
pub fn load_catalog(
    path: &Path,
    min_liq_usd: Option<U256>,
    max_liq_usd: Option<U256>,
) -> Result<HashMap<[u8; 32], PoolEntry>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut reader = csv::Reader::from_reader(file);
    let mut out = HashMap::new();
    // Expected header (see `enumerate-pools` writer):
    // `chain_id,pool_address,factory_address,token0,token1,fee_numerator,
    //  fee_denominator,profile,pool_id,source,liquidity_usd`
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

        // Parse optional liquidity_usd (column 10, index 10 after source)
        let liquidity_usd = record.get(10).and_then(|s| {
            let s = s.trim();
            if s.is_empty() {
                None
            } else {
                s.parse::<U256>().ok()
            }
        });

        // Apply liquidity filter
        if let Some(min) = min_liq_usd {
            if let Some(liq) = liquidity_usd {
                if liq < min {
                    continue; // skip this pool
                }
            }
        }
        if let Some(max) = max_liq_usd {
            if let Some(liq) = liquidity_usd {
                if liq > max {
                    continue; // skip this pool
                }
            }
        }

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

/// One opportunity's make/loss ledger: what the closed-form quote produced
/// from freshly re-read chain truth at the pinned block, with every cost a
/// live execution would carry.
#[derive(Debug, Clone, PartialEq)]
pub struct CaptureLedger {
    pub token_lo: Address,
    pub token_hi: Address,
    /// Cheapest-leg quote recomputed at the pinned block.
    pub input: U256,
    pub output: U256,
    pub profit: U256,
    pub log2_skew: f64,
    /// Net after gas only (measurement mode, no borrow fee).
    pub net_usd_none: U256,
    /// Net after Aave V3's 0.05% premium on the borrowed input.
    pub net_usd_aave: U256,
}

/// Builds the capture ledger from re-read leg prices. `gas_cost_usd` is the
/// per-attempt spend floor; `usd_per_anchor` values the anchor token under
/// the `load_prices` fixed-point convention.
///
/// # Errors
///
/// Returns an error when either venue lacks a priced leg at the pinned block
/// or the pair is not captureable.
pub fn verify_capture_ledger(
    a: &[PoolEntry],
    b: &[PoolEntry],
    prices_a: &HashMap<[u8; 32], PoolPrice>,
    prices_b: &HashMap<[u8; 32], PoolPrice>,
    anchor: Address,
    usd_per_anchor: U256,
    gas_cost_usd: U256,
) -> Result<CaptureLedger, String> {
    let Some(quote) = quote_pair_anchored(a, b, prices_a, prices_b, Some(anchor))? else {
        return Err("pair has no priced leg on both venues at the pinned block".to_owned());
    };
    let scale = U256::from(shadow::FIXED_POINT_SCALE);
    // The anchored quote denominates in the anchor (token_lo) by
    // construction; convert like the economics path does.
    debug_assert_eq!(quote.token_lo, anchor);
    let gross_usd = quote
        .profit
        .checked_mul(usd_per_anchor)
        .ok_or("gross conversion overflow")?
        / scale;
    let input_usd = quote
        .input
        .checked_mul(usd_per_anchor)
        .ok_or("input conversion overflow")?
        / scale;
    // Aave V3 premium: 5 bps of the borrowed principal.
    let aave_fee = input_usd * U256::from(5) / U256::from(100_000);
    let net = |cost: U256| gross_usd.saturating_sub(cost);
    Ok(CaptureLedger {
        token_lo: quote.token_lo,
        token_hi: quote.token_hi,
        input: quote.input,
        output: quote.output,
        profit: quote.profit,
        log2_skew: quote.log2_skew,
        net_usd_none: net(gas_cost_usd),
        net_usd_aave: net(aave_fee + gas_cost_usd),
    })
}

/// Decodes a `uint8`-style `eth_call` return (a right-aligned 32-byte word)
/// into its scalar value. Returns `None` for empty or oversized payloads —
/// callers fail closed rather than guessing a decimals constant.
#[must_use]
pub fn decode_word_decimals(data: &[u8]) -> Option<u8> {
    if data.is_empty() || data.len() > 32 {
        return None;
    }
    // Audit A21: reject any word with non-zero bytes beyond the last — the
    // old loop shifted through a u64 and silently kept only the final 8
    // bytes, so `2^64` truncated to `Some(0)` and a mis-scaled price table
    // by 10^18 would have looked valid.
    if data.iter().rev().skip(1).any(|byte| *byte != 0) {
        return None;
    }
    data.last().copied()
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
    let catalog = load_catalog(path, None, None)?;
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

/// Normalizes a pool-id hex string the way the overrides loader does:
/// trims whitespace, strips one `0x`/`0X` prefix, lowercases.
#[must_use]
pub fn normalize_pool_id_hex(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_lowercase()
}

/// Loads a hook allow-list file (one pool_id per line, `0x` optional,
/// `#` comments and `pool_id` headers skipped) into normalized ids.
pub fn load_hook_allowlist(path: &Path) -> Result<std::collections::HashSet<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("allowlist unreadable: {e}"))?;
    let mut out = std::collections::HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("pool_id") {
            continue;
        }
        out.insert(normalize_pool_id_hex(line));
    }
    Ok(out)
}

/// Scans manifest V4 rows against overrides hooks (Phase 3 of
/// docs/plans/2026-09-09-v4-quoter-hook-hardening.md): returns the pool
/// ids (hex, `0x`-prefixed) whose hooks address is nonzero and which are
/// NOT on the allow-list. Hook pricing needs hook logic — vanilla math on
/// hook pools produces ghosts — so callers must refuse or loudly exempt
/// these pools, never quote them silently.
pub fn find_nonzero_hook_pools(
    entries: &[PoolEntry],
    overrides: &std::collections::HashMap<String, (i32, Address)>,
    allowlist: &std::collections::HashSet<String>,
) -> Vec<String> {
    let mut flagged = Vec::new();
    for entry in entries {
        if entry.profile != *b"v4" {
            continue;
        }
        let id_hex = alloy_primitives::hex::encode(entry.id);
        let nonzero = overrides
            .get(&id_hex)
            .is_some_and(|(_, hooks)| *hooks != Address::ZERO);
        if nonzero && !allowlist.contains(&id_hex) {
            flagged.push(format!("0x{id_hex}"));
        }
    }
    flagged.sort();
    flagged
}

/// Loads the canonical quote-token table (`token,symbol,decimals,...`;
/// `#` comments and headers skipped) into a set of addresses.
pub fn load_quote_table(path: &Path) -> Result<std::collections::HashSet<Address>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("quote table unreadable: {e}"))?;
    let mut out = std::collections::HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("token") {
            continue;
        }
        let addr = line
            .split(',')
            .next()
            .unwrap_or_default()
            .trim()
            .parse::<Address>()
            .map_err(|_| format!("bad quote-table address {line:?}"))?;
        out.insert(addr);
    }
    Ok(out)
}

/// Tokens in `legs` with no route of ≤2 pools to a quote-table token
/// (Phase 6): their USD values cannot anchor honestly, so callers warn.
/// Table tokens themselves are never reported.
pub fn tokens_without_quote_route(
    legs: &[PoolEntry],
    table: &std::collections::HashSet<Address>,
) -> Vec<Address> {
    use std::collections::HashSet;
    let mut reached: HashSet<Address> = legs
        .iter()
        .flat_map(|e| [e.token0, e.token1])
        .filter(|t| table.contains(t))
        .collect();
    // Two hops: tokens sharing a pool with a reached token, twice.
    for _ in 0..2 {
        let mut frontier = HashSet::new();
        for e in legs {
            if reached.contains(&e.token0) {
                frontier.insert(e.token1);
            }
            if reached.contains(&e.token1) {
                frontier.insert(e.token0);
            }
        }
        reached.extend(frontier);
    }
    let mut unrouted: Vec<Address> = legs
        .iter()
        .flat_map(|e| [e.token0, e.token1])
        .filter(|t| !table.contains(t) && !reached.contains(t))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    unrouted.sort_by_key(|a| a.as_slice().to_owned());
    unrouted
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
    /// Fee actually charged by the pool's most recent V4 swap (audit task
    /// 3.1). `None` for v3 rows and for v4 rows whose swap predates the
    /// field. Lets dynamic/zero-fee v4 pools re-enter quoting with an
    /// observed toll instead of being excluded wholesale — subject to the
    /// same age screens as the price, and to simulation confirmation before
    /// any submission (a hook can change the fee between swaps).
    pub observed_fee: Option<u32>,
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

/// Resolves which V3 address chunks one [`sweep_swap_prices`] call covers for
/// `keys` under the same ring semantics (`skip` chunks, `take` chunks,
/// wrapping), so callers that must know a call's *coverage* — not just its
/// returned prices — derive it from the same selection the sweep issues.
///
/// `None` (or a zero count) selects every chunk: the caller swept (or intends
/// to sweep) the whole universe. The returned slices borrow `keys`.
///
/// Coverage semantics: a pool whose chunk is selected is observed through the
/// call's `to` block even when it emitted no `Swap` — absence of events under
/// complete local coverage means unchanged reserves. A pool whose chunk is
/// *not* selected carries no such guarantee for that window.
#[must_use]
pub fn swept_v3_chunks(keys: &[PoolEntry], chunk_window: Option<(u64, u64)>) -> Vec<&[PoolEntry]> {
    let chunks: Vec<&[PoolEntry]> = keys.chunks(MAX_ADDRESS_CHUNK).collect();
    let chunk_count = chunks.len().max(1);
    let (skip, take) = match chunk_window {
        Some((start_chunk, count)) if count > 0 => (
            usize::try_from(start_chunk).map_or(0, |s| s % chunk_count),
            usize::try_from(count).map_or(chunks.len(), |c| c.min(chunks.len())),
        ),
        _ => (0, chunks.len()),
    };
    chunks.into_iter().cycle().skip(skip).take(take).collect()
}

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
    let ids: Option<HashSet<[u8; 32]>> = if profile == *b"v4" {
        Some(keys.iter().map(|e| e.id).collect())
    } else {
        None
    };
    {
        let mut ingest = swap_price_ingest(profile, &mut latest);
        loop {
            let end = start.saturating_add(window.saturating_sub(1)).min(to);
            if profile == *b"v4" {
                let logs = reader.get_logs_windowed(
                    &LogFilter {
                        from_block: start,
                        to_block: end,
                        addresses: vec![pool_manager],
                        topic0: topic,
                        topic0_alternates: Vec::new(),
                    },
                    window,
                )?;
                ingest(&logs, ids.as_ref());
                if !request_delay.is_zero() {
                    std::thread::sleep(request_delay);
                }
            } else {
                for chunk in swept_v3_chunks(keys, chunk_window) {
                    let addresses: Vec<Address> = chunk.iter().map(|e| e.venue).collect();
                    let logs = reader.get_logs_windowed(
                        &LogFilter {
                            from_block: start,
                            to_block: end,
                            addresses,
                            topic0: topic,
                            topic0_alternates: Vec::new(),
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
    }
    Ok(latest)
}

/// Global `Swap` sweep — 1 req/venue/poll on public RHC, no address chunking.
///
/// V4 filters by the singleton `pool_manager` (all `PoolId`s via `topic1`);
/// V3/Up use an empty address filter (all pools) and rely on the local
/// `keys` whitelist to drop unrelated logs. `window 10` (not `1000`) keeps
/// each `eth_getLogs` narrow for the gateway `10k cap` + `1-2 min` horizon;
/// the dirty-set still only re-quotes `pair←pool`.
///
/// # Errors
///
/// Returns `TransportError` on empty filter or transport/budget failure.
pub fn sweep_global_swaps<B, S>(
    reader: &ChainReader<B, S>,
    profile: [u8; 2],
    pool_manager: Address,
    keys: &[PoolEntry],
    from: u64,
    to: u64,
    window: u64,
    request_delay: Duration,
) -> Result<RingSweepOutcome, TransportError>
where
    B: HttpBackend,
    S: Sleeper,
{
    let topic = if profile == *b"v4" {
        v4_swap_topic()
    } else {
        v3_swap_topic()
    };
    let alternates: Vec<B256> = if profile == *b"v4" {
        vec![provider::v4_modify_liquidity_topic()]
    } else {
        vec![provider::v3_mint_topic(), provider::v3_burn_topic()]
    };
    let liquidity_topics: HashSet<[u8; 32]> = alternates.iter().map(|t| t.0).collect();
    let mut outcome = RingSweepOutcome::default();
    let ids: Option<HashSet<[u8; 32]>> = if profile == *b"v4" {
        Some(keys.iter().map(|e| e.id).collect())
    } else {
        None
    };
    let mut start = from;
    {
        let mut ingest = swap_price_ingest(profile, &mut outcome.prices);
        loop {
            let end = start.saturating_add(window.saturating_sub(1)).min(to);
            let addresses = if profile == *b"v4" {
                vec![pool_manager]
            } else {
                Vec::new() // empty = no address filter → all Swaps in window
            };
            let logs = reader.get_logs_windowed(
                &LogFilter {
                    from_block: start,
                    to_block: end,
                    addresses,
                    topic0: topic,
                    topic0_alternates: alternates.clone(),
                },
                window,
            )?;
            // Liquidity-change invalidated keys (Mint/Burn/Modify without Swap)
            for raw in &logs {
                let Ok(envelope) = RawLogEnvelope::from_rpc_value(raw) else {
                    continue;
                };
                if envelope
                    .topics
                    .first()
                    .is_some_and(|t| liquidity_topics.contains(&t.0))
                {
                    let key = if profile == *b"v4" {
                        envelope.topics.get(1).map_or([0u8; 32], |t| t.0)
                    } else {
                        envelope.address.into_word().into()
                    };
                    outcome.invalidated_keys.push(key);
                }
            }
            ingest(&logs, ids.as_ref());
            if !request_delay.is_zero() {
                std::thread::sleep(request_delay);
            }
            if end == to {
                break;
            }
            start = end + 1;
        }
    }
    // Global covers every pool through `to` (no chunk gaps)
    outcome.covered_keys = keys.iter().map(|e| (pool_key(e), to)).collect();
    Ok(outcome)
}

/// Ingests one decoded Swap-log envelope into latest pool prices, shared by
/// the HTTP sweeps and the WebSocket event lane. V3 rows key on the
/// emitting pool address; V4 rows key on the swap `topic1` `PoolId`, kept
/// only when listed in `keep_ids`. Envelopes that do not decode into a
/// price (foreign layout, unlisted pool) leave `latest` untouched.
/// Newer-or-equal blocks overwrite; older blocks never clobber fresher state.
pub fn ingest_envelope(
    profile: [u8; 2],
    latest: &mut HashMap<[u8; 32], PoolPrice>,
    envelope: &RawLogEnvelope,
    keep_ids: Option<&HashSet<[u8; 32]>>,
) {
    let (key, parsed): (Option<[u8; 32]>, Option<(U256, U256)>) = if profile == *b"v4" {
        if envelope.topics.len() < 2 {
            (None, None)
        } else {
            let id = envelope.topics[1].0;
            if keep_ids.is_some_and(|m| m.contains(&id)) {
                (
                    Some(id),
                    decode_v4_swap(envelope).map(|s| (s.sqrt_price_x96, s.liquidity)),
                )
            } else {
                (None, None)
            }
        }
    } else {
        let key = envelope.address.into_word().into();
        (
            Some(key),
            decode_v3_swap(envelope).map(|s| (s.sqrt_price_x96, s.liquidity)),
        )
    };
    let observed_fee = if profile == *b"v4" {
        decode_v4_swap(envelope).map(|swap| swap.fee)
    } else {
        None
    };
    if let (Some(key), Some((sqrt, liquidity))) = (key, parsed) {
        let entry = latest.entry(key).or_insert(PoolPrice {
            sqrt,
            liquidity,
            block: 0,
            observed_fee: None,
        });
        if envelope.block_number >= entry.block {
            entry.sqrt = sqrt;
            entry.liquidity = liquidity;
            entry.block = envelope.block_number;
            entry.observed_fee = observed_fee;
        }
    }
}

/// Builds the shared `Swap`-log → latest-`PoolPrice` ingest closure used by
/// the price sweeps. V3 rows key on the emitting pool address; V4 rows key on
/// the swap `topic1` `PoolId`, kept only when listed in `keep_ids`.
fn swap_price_ingest(
    profile: [u8; 2],
    latest: &mut HashMap<[u8; 32], PoolPrice>,
) -> impl FnMut(&[serde_json::Value], Option<&HashSet<[u8; 32]>>) + '_ {
    move |logs: &[serde_json::Value], keep_ids: Option<&HashSet<[u8; 32]>>| {
        for raw in logs {
            let Ok(envelope) = RawLogEnvelope::from_rpc_value(raw) else {
                continue;
            };
            ingest_envelope(profile, latest, &envelope, keep_ids);
        }
    }
}

/// Number of sweep chunks a venue's key set divides into under the provider's
/// address-filter cap. V4 sweeps the singleton stream as one pseudo-chunk.
#[must_use]
pub fn sweep_chunk_count(profile: [u8; 2], keys: &[PoolEntry]) -> usize {
    if profile == *b"v4" {
        1
    } else {
        keys.chunks(MAX_ADDRESS_CHUNK).count().max(1)
    }
}

/// Per-chunk catch-up cap for [`sweep_swap_prices_ring`]: one call advances a
/// stalled chunk by at most this many blocks, bounding worst-case latency and
/// CU burn per poll after a long stall. The next call continues from there.
pub const DEFAULT_MAX_CATCHUP_BLOCKS: u64 = 20_000;

/// Catch-up cap for the global topic-only sweep (`sweep_global_swaps`):
/// one poll covers at most this many blocks behind the lagged tip. Without
/// it, a stalled water mark turns every poll into an unbounded catch-up
/// burst (hundreds of `eth_getLogs` in seconds), which trips provider
/// throttling and wedges the loop in a retry storm that never advances —
/// observed 2026-09-07. The cap also keeps single polls inside Chainstack
/// free's getLogs recency window (~50-100 blocks measured 2026-09-07;
/// older ranges fail `-32002` archive-gating). Skipped ranges are
/// fail-closed downstream: pools whose only recent swap falls in the gap
/// keep their older observed price and trip the swap-age screen.
pub const DEFAULT_GLOBAL_CATCHUP_BLOCKS: u64 = 50;

/// True when a sweep failure is archive-gating (`-32002`) rather than
/// throttling: the requested range predates the free plan's getLogs
/// recency window (~50-100 blocks on Chainstack, measured 2026-09-07).
/// Callers skip the stale range forward instead of retry-storming a wall
/// that can never succeed.
#[must_use]
pub fn is_archive_walled(error: &TransportError) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("-32002") || message.contains("archive")
}

/// One [`sweep_swap_prices_ring`] call's result.
#[derive(Debug, Default)]
pub struct RingSweepOutcome {
    /// Latest observed post-swap price per pool that traded in the covered
    /// ranges.
    pub prices: HashMap<[u8; 32], PoolPrice>,
    /// `(pool key, through block)` for every pool whose chunk this call
    /// covered — including pools that emitted no events. Feeds the evaluator's
    /// coverage voucher (`PairDirtyEvaluator::mark_swept_keys`).
    pub covered_keys: Vec<([u8; 32], u64)>,
    /// Pools whose cached virtual reserves went stale: a liquidity-change
    /// event arrived without a Swap, so sampled `liquidity`
    /// changed invisibly (audit task 1.3). The caller must drop these from
    /// its price cache; conservative cost is losing one pool's quotes until
    /// its next Swap.
    pub invalidated_keys: Vec<[u8; 32]>,
}

/// Incremental Swap-price sweep with **per-chunk high-water marks**.
///
/// This is the run-pairs poll loop's sweep. Unlike [`sweep_swap_prices`],
/// which takes one global `from..=to` window and silently loses every block a
/// ring-skipped chunk did not observe, each address chunk here carries its own
/// water mark: a call covers `[water + 1 ..= min(to, water + catchup)]` for
/// the chunks it selects and advances only those marks. No block is ever
/// passed over permanently — an unswept chunk stays behind and is picked up
/// when the ring reaches it.
///
/// Chunk selection picks the `max_chunks_per_poll` chunks with the *lowest*
/// water marks (most behind first, index tie-break), so there is no separate
/// cursor to drift and a failed or stalled chunk is prioritized on the next
/// call. `0` selects every chunk.
///
/// A mid-chunk failure propagates as [`TransportError`] *after* advancing the
/// water marks of windows that did succeed, so paid-for work is never
/// re-fetched and never skipped.
///
/// `chunk_water` must have [`sweep_chunk_count`] entries for this key set;
/// it is resized to that length, filling new slots with `initial_water`
/// (pass `start.saturating_sub(1)` where `start` is the first block the
/// caller wants observed).
///
/// # Errors
///
/// Returns a [`TransportError`] on an empty filter or a transport/budget
/// failure; already-covered progress is retained in `chunk_water`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn sweep_swap_prices_ring<B, S>(
    reader: &ChainReader<B, S>,
    profile: [u8; 2],
    pool_manager: Address,
    keys: &[PoolEntry],
    chunk_water: &mut Vec<u64>,
    initial_water: u64,
    max_chunks_per_poll: usize,
    to: u64,
    window: u64,
    request_delay: Duration,
    max_catchup_blocks: u64,
) -> Result<RingSweepOutcome, TransportError>
where
    B: HttpBackend,
    S: Sleeper,
{
    let topic = if profile == *b"v4" {
        v4_swap_topic()
    } else {
        v3_swap_topic()
    };
    let chunk_count = sweep_chunk_count(profile, keys);
    if chunk_water.len() != chunk_count {
        chunk_water.resize(chunk_count, initial_water);
    }
    // Build the chunk list once: V3 = consecutive MAX_ADDRESS_CHUNK slices of
    // the catalog; V4 = a single pseudo-chunk covering the whole singleton
    // stream (ingest filters by `PoolId`).
    let all_chunks: Vec<&[PoolEntry]> = if profile == *b"v4" {
        vec![keys]
    } else {
        keys.chunks(MAX_ADDRESS_CHUNK).collect()
    };
    // Most-behind chunks first: lowest water mark wins, index breaks ties.
    let mut order: Vec<usize> = (0..chunk_count).collect();
    order.sort_by_key(|&c| (chunk_water[c], c));
    let take = if max_chunks_per_poll == 0 {
        chunk_count
    } else {
        max_chunks_per_poll.min(chunk_count)
    };

    let ids: Option<HashSet<[u8; 32]>> = if profile == *b"v4" {
        Some(keys.iter().map(|e| e.id).collect())
    } else {
        None
    };
    let mut outcome = RingSweepOutcome::default();
    {
        let mut ingest = swap_price_ingest(profile, &mut outcome.prices);
        for &c in order.iter().take(take) {
            let water = chunk_water[c];
            let from = water.saturating_add(1);
            if from > to {
                continue; // already current through `to`
            }
            let to_c = to.min(water.saturating_add(max_catchup_blocks.max(1)));
            let chunk = all_chunks[c];
            let addresses: Vec<Address> = if profile == *b"v4" {
                vec![pool_manager]
            } else {
                chunk.iter().map(|e| e.venue).collect()
            };
            // Audit B12/B13: progress-returning fetch — a mid-range
            // failure keeps every completed window's logs AND advances the
            // water mark through the last contiguously covered block, so
            // paid work is neither re-fetched nor skipped.
            // Audit task 1.3: accept liquidity-change events alongside
            // Swaps so a Mint/Burn without an intervening Swap still marks
            // the pool's cached price stale instead of quoting reserves
            // that silently changed.
            let alternates: Vec<B256> = if profile == *b"v4" {
                vec![provider::v4_modify_liquidity_topic()]
            } else {
                vec![provider::v3_mint_topic(), provider::v3_burn_topic()]
            };
            let progress = reader.get_logs_with_progress(
                &LogFilter {
                    from_block: from,
                    to_block: to_c,
                    addresses: addresses.clone(),
                    topic0: topic,
                    topic0_alternates: alternates.clone(),
                },
                window,
            );
            let liquidity_topics: HashSet<[u8; 32]> = alternates.iter().map(|t| t.0).collect();
            // Pull liquidity-event keys out of the raw logs before swap
            // ingestion ignores them.
            let mut invalidated: Vec<[u8; 32]> = Vec::new();
            for raw in &progress.logs {
                let Ok(envelope) = RawLogEnvelope::from_rpc_value(raw) else {
                    continue;
                };
                if envelope
                    .topics
                    .first()
                    .is_some_and(|t| liquidity_topics.contains(&t.0))
                {
                    let key = if profile == *b"v4" {
                        envelope.topics.get(1).map_or([0u8; 32], |t| t.0)
                    } else {
                        envelope.address.into_word().into()
                    };
                    invalidated.push(key);
                }
            }
            outcome.invalidated_keys.extend(invalidated);
            ingest(
                &progress.logs,
                if profile == *b"v4" {
                    ids.as_ref()
                } else {
                    None
                },
            );
            let covered_through = progress.last_covered_block.max(water);
            chunk_water[c] = covered_through;
            if covered_through >= from {
                outcome
                    .covered_keys
                    .extend(chunk.iter().map(|e| (pool_key(e), covered_through)));
            }
            if let Some(error) = progress.error {
                return Err(error);
            }
            if !request_delay.is_zero() {
                std::thread::sleep(request_delay);
            }
        }
    }
    Ok(outcome)
}
///
/// Same transport shape as [`sweep_swap_prices`]: V3 scopes each request by a
/// chunked pool-address list; V4 filters the single `pool_manager` singleton
/// and keeps only logs whose `topic1` matches a requested `PoolId`. Unlike the
/// price sweep this needs no payload decode — a log with the right topic
/// shape *is* a swap — so it only tallies.
///
/// # Errors
///
/// Refetches fresh `slot0`/`liquidity` for pools invalidated by a
/// liquidity-change event (audit task 1.3 completion): instead of pausing
/// quotes until the pool's next Swap, immediate reads restore the cache.
/// V3 pools use `slot0()`/`liquidity()` on the pool address; V4 pools have
/// no address, so their price root and liquidity come from the PoolManager
/// V4 state source for [`refetch_invalidated_prices`]: raw
/// `eth_getStorageAt` against the `PoolManager` mapping, or the canonical
/// `StateView` lens contract (Phase 1 of
/// docs/plans/2026-09-09-v4-quoter-hook-hardening.md). `StateView` falls
/// back to the mapping per pool on any error, counted in `fallbacks`.
#[allow(clippy::doc_markdown)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V4Reads {
    Extsload,
    StateView,
}

/// Re-reads slot0/liquidity for pools invalidated by Mint/Burn-type events
/// through the canonical V4 path — the `PoolManager` `pools`
/// mapping (`pool_v4_state`) — calling the V3 selectors on the manager
/// reverts and used to leave V4 pools paused forever (fixed 2026-09-07).
/// Returns only pools that refreshed successfully; failures simply stay
/// paused.
///
/// Bounded by `max_refetch` so a liquidity-change storm cannot dominate
/// poll CU spend. `block` is stamped as [`u64::MAX`] — the freshest possible
/// observation, immune to age screens.
#[allow(clippy::doc_markdown)]
#[allow(clippy::too_many_arguments)]
pub fn refetch_invalidated_prices<B, S>(
    reader: &ChainReader<B, S>,
    entries: &[PoolEntry],
    keys: &[[u8; 32]],
    max_refetch: usize,
    pool_manager: Address,
    v4_reads: V4Reads,
    state_view: Address,
    read_block: u64,
    fallbacks: &mut u64,
) -> HashMap<[u8; 32], PoolPrice>
where
    B: HttpBackend,
    S: Sleeper,
{
    let mut refreshed = HashMap::new();
    for key in keys.iter().take(max_refetch) {
        let Some(entry) = entries.iter().find(|e| pool_key(e) == *key) else {
            continue;
        };
        let refreshed_price = if entry.profile == *b"v4" {
            let state = match v4_reads {
                V4Reads::StateView
                    if let Ok(state) =
                        reader.pool_v4_state_view(state_view, entry.id, read_block) =>
                {
                    Some(state)
                }
                V4Reads::StateView => {
                    // Canonical lens failed (rate limit, revert, decode):
                    // fall back to the mapping, counted.
                    *fallbacks += 1;
                    reader.pool_v4_state(pool_manager, entry.id).ok()
                }
                V4Reads::Extsload => reader.pool_v4_state(pool_manager, entry.id).ok(),
            };
            match state {
                Some((sqrt, liquidity)) if !sqrt.is_zero() && !liquidity.is_zero() => {
                    Some(PoolPrice {
                        sqrt,
                        liquidity,
                        block: u64::MAX,
                        // slot0 carries no fee; a dynamic pool refreshed here stays
                        // excluded from tolling until its next Swap re-observes one.
                        observed_fee: None,
                    })
                }
                _ => None,
            }
        } else {
            let (Ok((sqrt, _tick)), Ok(liquidity)) = (
                reader.pool_slot0(entry.venue),
                reader.pool_liquidity(entry.venue),
            ) else {
                continue;
            };
            if sqrt.is_zero() || liquidity.is_zero() {
                continue;
            }
            Some(PoolPrice {
                sqrt,
                liquidity,
                block: u64::MAX,
                // slot0 carries no fee; a dynamic pool refreshed here stays
                // excluded from tolling until its next Swap re-observes one.
                observed_fee: None,
            })
        };
        if let Some(price) = refreshed_price {
            refreshed.insert(*key, price);
        }
    }
    refreshed
}

/// Returns a [`TransportError`] on an empty filter or a transport/budget
/// failure.
#[allow(clippy::too_many_arguments)]
pub fn sweep_swap_activity<B, S>(
    reader: &ChainReader<B, S>,
    profile: [u8; 2],
    pool_manager: Address,
    keys: &[PoolEntry],
    from: u64,
    to: u64,
    window: u64,
    request_delay: Duration,
) -> Result<HashMap<[u8; 32], u64>, TransportError>
where
    B: HttpBackend,
    S: Sleeper,
{
    let topic = if profile == *b"v4" {
        v4_swap_topic()
    } else {
        v3_swap_topic()
    };
    let mut counts: HashMap<[u8; 32], u64> = HashMap::new();
    let mut start = from;
    loop {
        let end = start.saturating_add(window.saturating_sub(1)).min(to);
        if profile == *b"v4" {
            let logs = reader.get_logs_windowed(
                &LogFilter {
                    from_block: start,
                    to_block: end,
                    addresses: vec![pool_manager],
                    topic0: topic,
                    topic0_alternates: Vec::new(),
                },
                window,
            )?;
            let ids: HashSet<[u8; 32]> = keys.iter().map(|e| e.id).collect();
            for raw in &logs {
                let Ok(envelope) = RawLogEnvelope::from_rpc_value(raw) else {
                    continue;
                };
                if envelope.topics.len() < 2 {
                    continue;
                }
                let id = envelope.topics[1].0;
                if ids.contains(&id) {
                    *counts.entry(id).or_default() += 1;
                }
            }
        } else {
            for chunk in keys.chunks(MAX_ADDRESS_CHUNK) {
                let addresses: Vec<Address> = chunk.iter().map(|e| e.venue).collect();
                let logs = reader.get_logs_windowed(
                    &LogFilter {
                        from_block: start,
                        to_block: end,
                        addresses,
                        topic0: topic,
                        topic0_alternates: Vec::new(),
                    },
                    window,
                )?;
                for raw in &logs {
                    let Ok(envelope) = RawLogEnvelope::from_rpc_value(raw) else {
                        continue;
                    };
                    *counts
                        .entry(envelope.address.into_word().into())
                        .or_default() += 1;
                }
                if !request_delay.is_zero() {
                    std::thread::sleep(request_delay);
                }
            }
        }
        if !request_delay.is_zero() && profile == *b"v4" {
            std::thread::sleep(request_delay);
        }
        if end == to {
            break;
        }
        start = end + 1;
    }
    Ok(counts)
}

/// One cross-venue pair's measured swap activity: per-venue counts of the
/// most-active single pool on that venue for the pair, and the ranking score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairActivityRanking {
    pub token_lo: Address,
    pub token_hi: Address,
    /// Swap count of the most-active venue-A pool carrying this pair.
    pub swaps_a: u64,
    /// Swap count of the most-active venue-B pool carrying this pair.
    pub swaps_b: u64,
    /// Ranking score: `min(swaps_a, swaps_b)`. A cross-venue quote needs a
    /// priced leg on both venues during the live window, so the quieter side
    /// bounds how often the pair can actually be evaluated; one-sided activity
    /// never makes a pair quotable and must not outrank two-sided activity.
    pub score: u64,
}

/// Ranks every cross-venue token pair by observed swap activity. Pairs whose
/// quieter side saw zero swaps cannot be evaluated live and are dropped.
#[must_use]
pub fn pair_activity_rankings(
    a: &[PoolEntry],
    b: &[PoolEntry],
    activity_a: &HashMap<[u8; 32], u64>,
    activity_b: &HashMap<[u8; 32], u64>,
) -> Vec<PairActivityRanking> {
    let mut best_a: HashMap<([u8; 20], [u8; 20]), u64> = HashMap::new();
    for entry in a {
        let count = activity_a.get(&pool_key(entry)).copied().unwrap_or(0);
        let slot = best_a
            .entry(pair_key(entry.token0, entry.token1))
            .or_default();
        *slot = (*slot).max(count);
    }
    let mut best_b: HashMap<([u8; 20], [u8; 20]), u64> = HashMap::new();
    for entry in b {
        let count = activity_b.get(&pool_key(entry)).copied().unwrap_or(0);
        let slot = best_b
            .entry(pair_key(entry.token0, entry.token1))
            .or_default();
        *slot = (*slot).max(count);
    }
    let mut rankings: Vec<PairActivityRanking> = best_a
        .into_iter()
        .filter_map(|(key, swaps_a)| {
            let swaps_b = *best_b.get(&key)?;
            Some(PairActivityRanking {
                token_lo: Address::new(key.0),
                token_hi: Address::new(key.1),
                swaps_a,
                swaps_b,
                score: swaps_a.min(swaps_b),
            })
        })
        .filter(|ranking| ranking.score > 0)
        .collect();
    rankings.sort_by(|x, y| {
        y.score.cmp(&x.score).then_with(|| {
            (y.swaps_a + y.swaps_b)
                .cmp(&(x.swaps_a + x.swaps_b))
                .then_with(|| (y.token_lo, y.token_hi).cmp(&(x.token_lo, x.token_hi)))
        })
    });
    rankings
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
/// Returns an error when the expanded manifest exceeds `pool_cap` (0 = unlimited).
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
            if pool_cap != 0 && out.len() >= pool_cap {
                return Err(format!(
                    "manifest exceeds the {pool_cap}-pool cap while expanding catalog {label}"
                ));
            }
            // Catalog loading normalizes the v4 native sentinel to the
            // wrapped-native contract, which can un-sort the token pair
            // (sentinel 0x0 sorts first; the contract address usually does
            // not). Written manifests must keep canonical ordering, so sort
            // here; pool identity is unaffected (v4 keys by `pool_id`, V3 by
            // address) and every consumer pairs via the sorting `pair_key`.
            let mut entry = *entry;
            if entry.token0 > entry.token1 {
                std::mem::swap(&mut entry.token0, &mut entry.token1);
            }
            out.push(entry);
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
                // Task 3.1: priced v4 dynamic-fee pools re-enter via their
                // observed swap fee.
                let Some(toll) = effective_leg_toll(entry, prices.get(&pool_key(entry)).unwrap())
                else {
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
        // pools on that venue for the pair). Audit A27: the old
        // `!ta.is_finite()` test was dead — f64::MAX *is* finite, so pairs
        // with no tollable pool on a venue slipped through ranked at MAX.
        // Exact comparison is correct: f64::MAX is an exact assigned
        // sentinel, never a computed value.
        #[allow(clippy::float_cmp)]
        if ca == 0 || cb == 0 || ta == f64::MAX || tb == f64::MAX {
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

/// One executable leg of a quoted pair: the exact pool the quote used, its
/// swap direction, and the venue routing fields the payload builder needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegRoute {
    /// Venue profile: `*v3` or `*v4`.
    pub profile: [u8; 2],
    /// V3 pool contract address, or the V4 `PoolManager` singleton.
    pub pool: Address,
    /// V4 `PoolId` (zero for V3 legs).
    pub pool_id: [u8; 32],
    /// Token sold into this leg.
    pub token_in: Address,
    /// Token received from this leg.
    pub token_out: Address,
    /// Raw fee field as carried by the catalog row.
    pub fee_raw: u32,
}

impl LegRoute {
    /// `<profile>:<pool>:<pool_id_hex>:<token_in>:<token_out>:<fee>` — the
    /// CSV-serializable form consumed by the `trade` command.
    #[must_use]
    pub fn encode_csv(&self) -> String {
        let profile = std::str::from_utf8(&self.profile).unwrap_or("??");
        format!(
            "{profile}:{:#x}:{}:{:#x}:{:#x}:{}",
            self.pool,
            alloy_primitives::hex::encode(self.pool_id),
            self.token_in,
            self.token_out,
            self.fee_raw
        )
    }
}

/// A single pair-level closed-form optimal quote over one cross-venue cycle:
/// buy on the cheaper venue, sell on the dearer, sized so profit is maximal.
#[derive(Debug, Clone)]
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
    /// The optimiser's input before the single-tick capacity clamp (audit
    /// S1): what the constant-product model *wanted* to trade.
    pub optimal_unclamped: U256,
    /// Largest cycle input every leg can absorb within one tick-spacing
    /// cell — the bound inside which the constant-product model stays
    /// credible. `input <= optimal_unclamped`, equal when unclamped.
    pub input_capacity: U256,
    /// The chosen legs in execution order (hop 0, hop 1, ...) — exactly what
    /// the `trade` command encodes into router calldata.
    pub legs: Vec<LegRoute>,
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

/// Tick spacing implied by a V3 fee tier. The canonical Uniswap V3 factory
/// maps 100→1, 500→10, 3000→60, 10000→200; anything else (V4 pools, forks,
/// dynamic-fee placeholders) falls back to 60.
///
/// Catalogs do not carry `tickSpacing` yet (the enumeration CSV omits it and
/// the deploy-time `Initialize` decode discarded it — audit B58), so this
/// mapping is the pricing path's source until the column lands.
#[must_use]
pub fn tick_spacing_from_fee(fee: u32) -> i32 {
    match fee {
        100 => 1,
        500 => 10,
        10000 => 200,
        // 3000 and every unknown tier (V4 pools, forks, dynamic-fee
        // placeholders) share the middle spacing as the fallback.
        _ => 60,
    }
}

/// Maximum `token_in` a concentrated pool can absorb before its price moves
/// one full tick-spacing cell — the largest trade for which at most one
/// liquidity transition can occur.
///
/// This is the interim bound for audit finding S1: the constant-product
/// reduction of a concentrated pool is exact only while the sampled in-range
/// liquidity persists, and without tick data the system cannot see where that
/// persistence ends. One cell guarantees at most one boundary crossing, so
/// model error stays bounded instead of unbounded; trades beyond it are
/// screened rather than trusted.
///
/// Exact within-range amounts (`getAmount0Delta`/`getAmount1Delta`):
/// - selling token0 (price down by factor `r = √(1.0001^ts)`):
///   `Δx = L · (√P − √P/r)`
/// - selling token1 (price up): `Δy = L · (√P·r − √P)`
///
/// The cell ratio itself is computed in `f64` (relative error ~1e-12,
/// negligible against the unknown distance-to-boundary, which dominates);
/// the amount math is exact 512-bit, saturating to [`U256::MAX`].
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
pub fn single_tick_capacity(
    sqrt_price_x96: U256,
    liquidity: U256,
    tick_spacing: i32,
    zero_for_one: bool,
) -> U256 {
    const TWO_96_F64: f64 = 79_228_162_514_264_337_593_543_950_336.0;
    let spacing = tick_spacing.max(1);
    // r = sqrt(1.0001^spacing) = exp(spacing · ln(1.0001) / 2)
    let ratio = (f64::from(spacing) * 0.000_099_995_000_333_308_35 / 2.0).exp();
    if !ratio.is_finite() || ratio <= 1.0 {
        return U256::ZERO;
    }
    if liquidity.is_zero() || sqrt_price_x96.is_zero() {
        return U256::ZERO;
    }
    let two_96 = Uint::<512, 8>::from(U256::from(1u64) << 96);
    let wide_l = Uint::<512, 8>::from(liquidity);
    let wide_sqrt = Uint::<512, 8>::from(sqrt_price_x96);
    let saturate = |value: Uint<512, 8>| {
        use ruint::UintTryFrom;
        U256::uint_try_from(value).unwrap_or(U256::MAX)
    };
    if zero_for_one {
        // Selling token0 (price down by r):
        // Δx = L · (√P − √P/r) = L · (1/√P) · (1 − 1/r)
        // With sqrt_x96 = √P·2^96 and factor_x96 = (1 − 1/r)·2^96, the 2^96
        // scalings cancel in one division:
        // Δx = L · factor_x96 / sqrt_x96
        let factor_x96 = ((1.0 - 1.0 / ratio) * TWO_96_F64) as u128;
        if factor_x96 == 0 {
            return U256::ZERO;
        }
        saturate(wide_l * Uint::<512, 8>::from(factor_x96) / wide_sqrt)
    } else {
        // Selling token1 (price up by r):
        // Δy = L · √P · (r − 1) = L · (sqrt_x96/2^96) · (r − 1)
        // = L · sqrt_x96 · factor_x96 / 2^192
        let factor_x96 = ((ratio - 1.0) * TWO_96_F64) as u128;
        if factor_x96 == 0 {
            return U256::ZERO;
        }
        saturate(wide_l * wide_sqrt * Uint::<512, 8>::from(factor_x96) / (two_96 * two_96))
    }
}

/// Constant-product leg output for an input on virtual reserves, net of the
/// static toll: the independent model the quoter comparison checks.
/// `r_in`/`r_out` are the directional virtual reserves.
#[must_use]
pub fn cp_output(r_in: f64, r_out: f64, dx: f64, toll: f64) -> Option<f64> {
    if !r_in.is_finite() || !r_out.is_finite() || !dx.is_finite() {
        return None;
    }
    if r_in <= 0.0 || r_out <= 0.0 || dx <= 0.0 {
        return None;
    }
    if !(0.0..1.0).contains(&toll) {
        return None;
    }
    Some(r_out * dx / (r_in + dx) * (1.0 - toll))
}

/// Exact integer constant-product leg output, net of toll
/// (`fee_num`/`fee_den`): `out = r1·dx/(r0+dx) · (den-num)/den`, 512-bit
/// products saturating to [`U256::MAX`]. Used for V3 legs inside quoter
/// chains, where concentrated ticks don't exist and the model is exact.
#[must_use]
pub fn cp_output_exact(
    r_in: U256,
    r_out: U256,
    dx: U256,
    fee_num: u64,
    fee_den: u64,
) -> Option<U256> {
    use ruint::{Uint, UintTryFrom};
    if r_in.is_zero() || r_out.is_zero() || dx.is_zero() || fee_den == 0 {
        return None;
    }
    if fee_num >= fee_den {
        return None;
    }
    let gross = Uint::<512, 8>::from(r_out) * Uint::<512, 8>::from(dx)
        / (Uint::<512, 8>::from(r_in) + Uint::<512, 8>::from(dx));
    let net = gross * Uint::<512, 8>::from(fee_den - fee_num) / Uint::<512, 8>::from(fee_den);
    Some(U256::uint_try_from(net).unwrap_or(U256::MAX))
}

/// Verdict of chaining one candidate cycle through the on-chain `V4Quoter`
/// (V4 legs) and exact constant-product math (V3 legs, full-range exact).
#[derive(Debug, Clone, PartialEq)]
pub enum QuoterVerdict {
    /// Every leg verified and executable output is within `max_divergence`
    /// of the model. Carries the chained output, the divergence
    /// (`1 - exec/math`, positive = model overstates), and summed quoter
    /// gas estimates.
    Agree {
        exec_output: U256,
        divergence: f64,
        gas: U256,
    },
    /// Executable output trails the model beyond tolerance (tick crossing,
    /// wrong key, ...) — caller screens. Carries the same numbers.
    Diverge {
        exec_output: U256,
        divergence: f64,
        gas: U256,
    },
    /// Nothing quotable (V3-only cycle, inexact keys, hooks, oversize
    /// input): caller keeps math, with the counted reason.
    Skipped { reason: &'static str },
    /// A quoter call failed: fail-closed, caller screens.
    Error { detail: String },
}

/// Chains one candidate cycle leg-by-leg in execution order: V4 legs
/// through `quoteExactInputSingle` (multi-tick traversal, live LP fee),
/// V3 legs through exact [`cp_output_exact`] math. Returns the executable
/// output against the model's `math_output`.
///
/// Fail-closed throughout: inexact PoolKeys (dynamic/zero fees, nonzero
/// hooks, missing overrides), over-`u128` inputs, token mismatches, and
/// quoter errors all screen instead of guessing. `calls_left` bounds the
/// per-poll `eth_call` spend; exhaustion skips the rest.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub fn quoter_verify_cycle<B, S>(
    reader: &ChainReader<B, S>,
    quoter: Address,
    overrides: &std::collections::HashMap<String, (i32, Address)>,
    entries: &[PoolEntry],
    legs: &[LegRoute],
    states: &std::collections::HashMap<[u8; 32], PoolPrice>,
    input: U256,
    math_output: U256,
    max_divergence: f64,
    tip: u64,
    calls_left: &mut u64,
) -> QuoterVerdict
where
    B: HttpBackend,
    S: Sleeper,
{
    if legs.is_empty() {
        return QuoterVerdict::Skipped { reason: "no-legs" };
    }
    if legs.iter().all(|leg| leg.profile != *b"v4") {
        return QuoterVerdict::Skipped { reason: "v3-only" };
    }
    let Ok(mut amount) = u128::try_from(input) else {
        return QuoterVerdict::Skipped { reason: "oversize" };
    };
    if amount == 0 {
        return QuoterVerdict::Skipped {
            reason: "zero-input",
        };
    }
    let mut gas = U256::ZERO;
    for leg in legs {
        if leg.profile == *b"v4" {
            let Some(entry) = entries
                .iter()
                .find(|e| e.profile == *b"v4" && e.id == leg.pool_id)
            else {
                return QuoterVerdict::Skipped { reason: "no-entry" };
            };
            // Exact static fee only: sentinels and zeros resolve through
            // observed fees, which a pre-swap quoter call cannot know.
            if entry.fee == 0 || entry.fee & V4_DYNAMIC_FEE_FLAG != 0 {
                return QuoterVerdict::Skipped {
                    reason: "inexact-fee",
                };
            }
            let id_hex = alloy_primitives::hex::encode(leg.pool_id);
            let Some((tick_spacing, hooks)) = overrides.get(&id_hex) else {
                return QuoterVerdict::Skipped {
                    reason: "no-overrides",
                };
            };
            if *hooks != Address::ZERO {
                return QuoterVerdict::Skipped { reason: "hooks" };
            }
            let (c0, c1) = if leg.token_in <= leg.token_out {
                (leg.token_in, leg.token_out)
            } else {
                (leg.token_out, leg.token_in)
            };
            let zero_for_one = leg.token_in == c0;
            if *calls_left == 0 {
                return QuoterVerdict::Skipped { reason: "budget" };
            }
            *calls_left -= 1;
            match reader.quote_v4_exact_input(
                quoter,
                c0,
                c1,
                entry.fee,
                *tick_spacing,
                *hooks,
                zero_for_one,
                amount,
                tip,
            ) {
                Ok((out, est)) => {
                    gas = gas.saturating_add(est);
                    let Ok(next) = u128::try_from(out) else {
                        return QuoterVerdict::Skipped { reason: "oversize" };
                    };
                    if next == 0 {
                        return QuoterVerdict::Error {
                            detail: "quoter dust".to_owned(),
                        };
                    }
                    amount = next;
                }
                Err(error) => {
                    return QuoterVerdict::Error {
                        detail: format!("{error:?}").chars().take(120).collect(),
                    };
                }
            }
        } else {
            // V3 leg: exact math on virtual reserves.
            let key: [u8; 32] = leg.pool.into_word().into();
            let Some(state) = states.get(&key) else {
                return QuoterVerdict::Skipped { reason: "no-state" };
            };
            let Some(entry) = entries
                .iter()
                .find(|e| e.profile != *b"v4" && e.venue == leg.pool)
            else {
                return QuoterVerdict::Skipped { reason: "no-entry" };
            };
            let (r0, r1) = virtual_reserves(state.sqrt, state.liquidity);
            let (rin, rout) = if leg.token_in == entry.token0 {
                (r0, r1)
            } else if leg.token_in == entry.token1 {
                (r1, r0)
            } else {
                return QuoterVerdict::Skipped {
                    reason: "token-mismatch",
                };
            };
            let amount_u256 = U256::from(amount);
            let Some(out) = cp_output_exact(
                rin,
                rout,
                amount_u256,
                entry.fee.into(),
                entry.fee_denominator.into(),
            ) else {
                return QuoterVerdict::Skipped {
                    reason: "math-failed",
                };
            };
            let Ok(next) = u128::try_from(out) else {
                return QuoterVerdict::Skipped { reason: "oversize" };
            };
            if next == 0 {
                return QuoterVerdict::Skipped { reason: "dust" };
            }
            amount = next;
        }
    }
    let exec_output = U256::from(amount);
    let divergence = if math_output.is_zero() {
        f64::NAN
    } else {
        1.0 - f64_of(exec_output) / f64_of(math_output)
    };
    // NaN (degenerate model output) vetoes: nothing to compare against.
    if divergence.is_finite() && divergence <= max_divergence {
        QuoterVerdict::Agree {
            exec_output,
            divergence,
            gas,
        }
    } else {
        QuoterVerdict::Diverge {
            exec_output,
            divergence,
            gas,
        }
    }
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

/// Largest cycle input for which every leg stays within its single-tick
/// capacity (audit S1 interim bound).
///
/// Per-hop amounts are monotone in the cycle input, so the feasible set is an
/// interval starting at zero; binary search its right edge. Returns
/// `unclamped` unchanged when it is already feasible, and `0` when even a
/// one-unit input breaches a leg.
fn capacity_bounded_input(
    cycle: &domain::Cycle,
    states: &[domain::PoolState],
    leg_caps: &[U256],
    unclamped: U256,
) -> U256 {
    let feasible = |x: U256| match v2_math::hop_inputs(x, cycle, states) {
        Ok(amounts) => amounts.iter().zip(leg_caps).all(|(amt, cap)| amt <= cap),
        Err(_) => false,
    };
    if feasible(unclamped) {
        return unclamped;
    }
    if !feasible(U256::from(1u64)) {
        return U256::ZERO;
    }
    let mut low = U256::from(1u64);
    let mut high = unclamped;
    while low < high {
        // Invariant: low feasible, high infeasible. Midpoint biased up so the
        // loop terminates on adjacent integers.
        let mid = (low + high + U256::from(1u64)) / U256::from(2u64);
        if mid == high {
            break;
        }
        if feasible(mid) {
            low = mid;
        } else {
            high = mid - U256::from(1u64);
        }
    }
    low
}

/// Applies the single-tick capacity clamp to an optimiser result and
/// re-quotes the round trip at the clamped input.
///
/// Returns `(input, output, profit)`: the clamped input (equal to
/// `unclamped.input` when already feasible), the exact cycle output there,
/// and the resulting profit in anchor-token units.
///
/// # Errors
///
/// Propagates re-quote failures as messages.
fn finalize_capacity_checked(
    cycle: &domain::Cycle,
    states: &[domain::PoolState],
    leg_caps: &[U256],
    unclamped: v2_math::OptimalQuote,
) -> Result<(U256, U256, U256), String> {
    let input = capacity_bounded_input(cycle, states, leg_caps, unclamped.input);
    if input == unclamped.input {
        return Ok((input, unclamped.output, unclamped.profit));
    }
    if input.is_zero() {
        return Ok((U256::ZERO, U256::ZERO, U256::ZERO));
    }
    let output = v2_math::quote_cycle(input, cycle, states)
        .map_err(|e| format!("capacity-clamped quote failed: {e}"))?;
    let profit = output.saturating_sub(input);
    Ok((input, output, profit))
}

/// Rejects a cross-venue quote whose two selected legs are not the same
/// normalized token pair.
///
/// `best_leg` picks each venue's cheapest priced pool independently, so
/// mismatched inputs would silently compose a cycle across two unrelated
/// token pairs — structurally unpriceable, yet the optimiser would return a
/// number for it (audit finding S7). Hard-error instead of quoting.
fn ensure_same_pair(leg_a: &PoolEntry, leg_b: &PoolEntry) -> Result<(), String> {
    let pair_a = pair_key(leg_a.token0, leg_a.token1);
    if pair_a == pair_key(leg_b.token0, leg_b.token1) {
        Ok(())
    } else {
        Err(format!(
            "quote_pair: legs are not the same pair (venue A {:#?}, venue B {:#?})",
            (leg_a.token0, leg_a.token1),
            (leg_b.token0, leg_b.token1)
        ))
    }
}

/// Builds one orientation of the 2-hop cross-venue cycle: reserve states,
/// per-hop single-tick capacities, and the optimiser's unclamped result.
///
/// # Errors
///
/// Propagates `optimal_input` failures.
#[allow(clippy::too_many_lines)]
fn build_pair_cycle(
    anchor: Address,
    other: Address,
    first: PoolEntry,
    first_price: PoolPrice,
    second: PoolEntry,
    second_price: PoolPrice,
) -> Result<Option<BestPick>, String> {
    use domain::{Cycle, CycleHop, CycleId, Fee, PoolId, PoolState, StateVersion};
    use v2_math::optimal_input;
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
    // Per-leg single-tick capacity in each hop's own token_in units
    // (audit S1 interim bound): how much that pool can absorb before its
    // price leaves the sampled liquidity cell.
    let leg_caps = vec![
        single_tick_capacity(
            first_price.sqrt,
            first_price.liquidity,
            tick_spacing_from_fee(first.fee),
            first.token0 == anchor,
        ),
        single_tick_capacity(
            second_price.sqrt,
            second_price.liquidity,
            tick_spacing_from_fee(second.fee),
            second.token0 == other,
        ),
    ];
    optimal_input(&cycle, &states)
        .map(|opt| opt.map(|quote| (quote, cycle, states, leg_caps)))
        .map_err(|e| format!("optimal input failed: {e}"))
}

pub fn quote_pair(
    a_entries: &[PoolEntry],
    b_entries: &[PoolEntry],
    prices_a: &HashMap<[u8; 32], PoolPrice>,
    prices_b: &HashMap<[u8; 32], PoolPrice>,
) -> Result<Option<PairQuote>, String> {
    quote_pair_anchored(a_entries, b_entries, prices_a, prices_b, None)
}

/// [`quote_pair`] with an explicit cycle anchor — the token that is flash-
/// borrowed at the start of the round trip and in which profit is denominated.
///
/// Audit S3a: the legacy path always anchored at the lexicographically lower
/// address, which is arbitrary — it need not be borrowable or priceable, and
/// the chain's highest-volume pair was structurally excluded from honest
/// gating because its lower-address token is native (deliberately absent from
/// the price table). Callers that know executability pass the anchor here.
/// `PairQuote::token_lo` is the chosen anchor and `token_hi` its counterparty
/// in every construction, so consumers reading `token_lo` as "the anchor"
/// stay correct.
///
/// # Errors
///
/// Same as [`quote_pair`], plus an error when `preferred_anchor` is not one
/// of the quoted pair's two tokens.
#[allow(clippy::too_many_lines)]
pub fn quote_pair_anchored(
    a_entries: &[PoolEntry],
    b_entries: &[PoolEntry],
    prices_a: &HashMap<[u8; 32], PoolPrice>,
    prices_b: &HashMap<[u8; 32], PoolPrice>,
    preferred_anchor: Option<Address>,
) -> Result<Option<PairQuote>, String> {
    let Some(sel) = select_pair_cycle(a_entries, b_entries, prices_a, prices_b, preferred_anchor)?
    else {
        return Ok(None);
    };
    // Clamp the trade to what every leg can absorb within one liquidity
    // cell; beyond it the constant-product model is fiction (audit S1).
    let (input, output, profit) =
        finalize_capacity_checked(&sel.cycle, &sel.states, &sel.leg_caps, sel.unclamped)?;
    Ok(Some(finish_pair_quote(&sel, input, output, profit)))
}

/// One solved orientation: unclamped optimiser quote, its cycle, reserve
/// states, and per-hop single-tick capacities.
type BestPick = (
    v2_math::OptimalQuote,
    domain::Cycle,
    Vec<domain::PoolState>,
    Vec<U256>,
);

/// Selected pair cycle with everything needed to price it at any input:
/// the solved orientation, reserve states, per-leg capacities, legs, tolls,
/// and the optimiser's unclamped quote.
pub struct PairCycleSel {
    pub anchor: Address,
    pub other: Address,
    pub first_leg: PoolEntry,
    pub second_leg: PoolEntry,
    pub toll_a: f64,
    pub toll_b: f64,
    pub leg_price_a: PoolPrice,
    pub leg_price_b: PoolPrice,
    pub cycle: domain::Cycle,
    pub states: Vec<domain::PoolState>,
    pub leg_caps: Vec<U256>,
    pub unclamped: v2_math::OptimalQuote,
}

/// Cheapest-priced leg per venue plus same-pair enforcement and orientation
/// solving, shared by [`quote_pair_anchored`] and the small-size probes.
/// Returns `Ok(None)` when no orientation solves.
pub fn select_pair_cycle(
    a_entries: &[PoolEntry],
    b_entries: &[PoolEntry],
    prices_a: &HashMap<[u8; 32], PoolPrice>,
    prices_b: &HashMap<[u8; 32], PoolPrice>,
    preferred_anchor: Option<Address>,
) -> Result<Option<PairCycleSel>, String> {
    let best_leg = |entries: &[PoolEntry],
                    prices: &HashMap<[u8; 32], PoolPrice>|
     -> Option<(PoolEntry, PoolPrice, f64)> {
        let mut best: Option<(PoolEntry, PoolPrice, f64)> = None;
        for entry in entries {
            let Some(price) = prices.get(&pool_key(entry)) else {
                continue;
            };
            // Task 3.1: priced v4 dynamic-fee pools re-enter via their
            // observed swap fee.
            let Some(toll) = effective_leg_toll(entry, prices.get(&pool_key(entry)).unwrap())
            else {
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

    ensure_same_pair(&leg_a, &leg_b)?;
    let pair = pair_key(leg_a.token0, leg_a.token1);
    let lo = Address::from_slice(&pair.0);
    let hi = Address::from_slice(&pair.1);
    let anchor = match preferred_anchor {
        Some(hint) if hint == lo || hint == hi => hint,
        Some(hint) => return Err(format!("anchor {hint} is not in the quoted pair")),
        None => lo,
    };
    let other = if anchor == lo { hi } else { lo };

    let make_cycle =
        |first: PoolEntry, first_price: PoolPrice, second: PoolEntry, second_price: PoolPrice| {
            build_pair_cycle(anchor, other, first, first_price, second, second_price)
        };

    let mut first_leg = leg_a;
    let mut second_leg = leg_b;
    let mut best: Option<BestPick> = make_cycle(leg_a, leg_price_a, leg_b, leg_price_b)
        .map_err(|e| format!("optimal input failed: {e}"))?;
    if best.is_none() {
        first_leg = leg_b;
        second_leg = leg_a;
        best = make_cycle(leg_b, leg_price_b, leg_a, leg_price_a)
            .ok()
            .flatten();
    }
    let Some((unclamped_quote, cycle, states, leg_caps)) = best else {
        return Ok(None);
    };
    Ok(Some(PairCycleSel {
        anchor,
        other,
        first_leg,
        second_leg,
        toll_a,
        toll_b,
        leg_price_a,
        leg_price_b,
        cycle,
        states,
        leg_caps,
        unclamped: unclamped_quote,
    }))
}

/// Price the selected cycle at the optimiser's input (clamped to capacity).
/// This is the long-standing optimal-row math, shared by
/// [`quote_pair_anchored`] and the dirty hot path.
pub fn price_optimal(sel: &PairCycleSel) -> Result<(U256, U256, U256), String> {
    finalize_capacity_checked(&sel.cycle, &sel.states, &sel.leg_caps, sel.unclamped)
}

/// Price the selected cycle at an explicit input (at or below capacity),
/// reusing the capacity clamp + `quote_cycle` machinery. Returns zeros when
/// the requested size is empty or fully capacity-blocked.
pub fn finalize_at_input(
    cycle: &domain::Cycle,
    states: &[domain::PoolState],
    leg_caps: &[U256],
    probe: U256,
) -> Result<(U256, U256, U256), String> {
    if probe.is_zero() {
        return Ok((U256::ZERO, U256::ZERO, U256::ZERO));
    }
    let clamped = capacity_bounded_input(cycle, states, leg_caps, probe);
    if clamped.is_zero() {
        return Ok((U256::ZERO, U256::ZERO, U256::ZERO));
    }
    let output = v2_math::quote_cycle(clamped, cycle, states)
        .map_err(|e| format!("probe quote failed: {e}"))?;
    let profit = output.saturating_sub(clamped);
    Ok((clamped, output, profit))
}

/// Assemble the final [`PairQuote`] for a priced input on the selected cycle.
pub fn finish_pair_quote(sel: &PairCycleSel, input: U256, output: U256, profit: U256) -> PairQuote {
    let leg_route = |entry: PoolEntry, token_in: Address, token_out: Address| LegRoute {
        profile: entry.profile,
        pool: entry.venue,
        pool_id: entry.id,
        token_in,
        token_out,
        fee_raw: entry.fee,
    };
    let legs = vec![
        leg_route(sel.first_leg, sel.anchor, sel.other),
        leg_route(sel.second_leg, sel.other, sel.anchor),
    ];
    PairQuote {
        token_lo: sel.anchor,
        token_hi: sel.other,
        input,
        output,
        profit,
        toll: sel.toll_a + sel.toll_b,
        log2_skew: oriented_pair_skew(
            &sel.first_leg,
            &sel.leg_price_a,
            &sel.second_leg,
            &sel.leg_price_b,
            sel.anchor,
        ),
        optimal_unclamped: sel.unclamped.input,
        input_capacity: input.min(sel.unclamped.input),
        legs,
    }
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
    // Full-range: use effective_leg_toll (observed_fee re-admits ~101k V4 dynamic) was leg_toll that censored 101k dynamic + 99% fee >0.9
    let usable = |e: &PoolEntry| {
        // For enumeration we consider a pool quotable if its static toll is quotable
        // OR it is V4 dynamic (fee sentinel) that could be quoted via observed_fee later.
        // Keep high-fee >0.9 still filtered (honeypot), but admit dynamic.
        if e.profile == *b"v4" && (e.fee == 0 || e.fee == 8_388_608) {
            return true;
        }
        leg_toll(e.fee, e.fee_denominator, e.profile).is_some()
    };
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
            let Some(price) = prices.get(&pool_key(entry)) else {
                continue;
            };
            // Task 3.1: priced v4 dynamic-fee pools re-enter via observed fee.
            let Some(toll) = effective_leg_toll(entry, price) else {
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
/// Oriented three-leg dislocation for one triangle (audit note): each leg's
/// price is re-expressed in its cycle direction so the raw-wei product
/// telescopes to `2^(96·3)` at parity; the log-magnitude of the deviation is
/// the comparable skew.
fn triangle_log2_skew(
    leg01: &CycleLeg,
    leg12: &CycleLeg,
    leg20: &CycleLeg,
    p0: Address,
    p1: Address,
    p2: Address,
) -> f64 {
    let oriented_cycle_price = |leg: &CycleLeg, token_in: Address| -> f64 {
        let raw_conventioned = price_out(leg.price.sqrt);
        if leg.entry.token0 == token_in {
            raw_conventioned
        } else {
            SQRT_PRICE_CONVENTION_K * SQRT_PRICE_CONVENTION_K
                / raw_conventioned.max(f64::MIN_POSITIVE)
        }
    };
    let cycle_product = oriented_cycle_price(leg01, p0)
        * oriented_cycle_price(leg12, p1)
        * oriented_cycle_price(leg20, p2);
    (cycle_product.log2() - 288.0).abs()
}

#[allow(clippy::too_many_lines)]
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
    let leg_caps: Vec<U256> = [(&leg01, p0), (&leg12, p1), (&leg20, p2)]
        .into_iter()
        .map(|(leg, hop_in)| {
            single_tick_capacity(
                leg.price.sqrt,
                leg.price.liquidity,
                tick_spacing_from_fee(leg.entry.fee),
                leg.entry.token0 == hop_in,
            )
        })
        .collect();
    let Some(unclamped) =
        optimal_input(&cycle, &states).map_err(|e| format!("optimal input failed: {e}"))?
    else {
        return Ok(None);
    };
    let (input, output, profit) = finalize_capacity_checked(&cycle, &states, &leg_caps, unclamped)?;
    // Audit A9: an unquotable leg must abort the triangle rather than be
    // priced fee-free (`unwrap_or(0.0)` here was a fail-open default in a
    // cost path).
    let keep = |leg: &CycleLeg| -> Result<f64, String> {
        // Task 3.1: observed-fee fallback for v4 dynamic pools.
        effective_leg_toll(&leg.entry, &leg.price)
            .map(|toll| 1.0 - toll)
            .ok_or_else(|| "triangle edge has no quotable toll".to_owned())
    };
    let keep_product = keep(&leg01)? * keep(&leg12)? * keep(&leg20)?;
    let toll = 1.0 - keep_product;
    let log2_skew = triangle_log2_skew(&leg01, &leg12, &leg20, p0, p1, p2);
    let tri_leg = |leg: &CycleLeg, tin: Address, tout: Address| LegRoute {
        profile: leg.entry.profile,
        pool: leg.entry.venue,
        pool_id: leg.entry.id,
        token_in: tin,
        token_out: tout,
        fee_raw: leg.entry.fee,
    };
    Ok(Some(PairQuote {
        token_lo: p0,
        token_hi: p2,
        input,
        output,
        profit,
        toll,
        log2_skew,
        optimal_unclamped: unclamped.input,
        input_capacity: input.min(unclamped.input),
        legs: vec![
            tri_leg(&leg01, p0, p1),
            tri_leg(&leg12, p1, p2),
            tri_leg(&leg20, p2, p0),
        ],
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
    use alloy_primitives::Bytes;

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
    fn effective_leg_toll_readmits_v4_dynamic_pools_via_observed_fee() {
        // Audit task 3.1 / S6: dynamic-fee v4 pools (~101k rows) were
        // excluded wholesale even though every swap event reports the fee
        // actually charged.
        let mut entry = catalog_entry(*b"v4", Address::repeat_byte(1), [7u8; 32]);
        entry.fee = V4_DYNAMIC_FEE_FLAG; // hook-set fee sentinel
        entry.fee_denominator = 1_000_000;
        let mut price = PoolPrice {
            sqrt: U256::from(1u64) << 96,
            liquidity: U256::from(1u64),
            block: 1,
            observed_fee: None,
        };
        assert_eq!(
            effective_leg_toll(&entry, &price),
            None,
            "no observation yet: still excluded"
        );

        // Observed 30 bps -> quotable at exactly that toll.
        price.observed_fee = Some(3_000);
        let toll = effective_leg_toll(&entry, &price).expect("observed");
        assert!((toll - 0.003).abs() < 1e-9);

        // Observed zero means the hook charged nothing — legitimate free leg.
        price.observed_fee = Some(0);
        assert_eq!(
            effective_leg_toll(&entry, &price),
            None,
            "free pools stay excluded from toll math but are not errors"
        );

        // Absurd observed fee stays rejected by the band (ceiling is now
        // 90%, lifted from 50% for full range — so the probe must clear it).
        price.observed_fee = Some(950_000);
        assert_eq!(effective_leg_toll(&entry, &price), None);

        // Canonical catalog fees still take the legacy path untouched.
        entry.profile = *b"v3";
        entry.fee = 3_000;
        entry.fee_denominator = 1_000_000;
        assert_eq!(effective_leg_toll(&entry, &price), Some(0.003));
    }

    /// Scripted quoter backend: every `eth_call` returns the same fixed
    /// (amount, gas) pair, or a short payload when `payload` is empty.
    struct QuoterBackend {
        amount: u64,
        gas: u64,
        empty: bool,
    }

    impl provider::HttpBackend for QuoterBackend {
        fn request(
            &self,
            request: &provider::RpcRequest,
        ) -> Result<provider::HttpResponse, TransportError> {
            assert_eq!(request.method, "eth_call");
            let payload = if self.empty {
                "0x".to_owned()
            } else {
                let mut bytes = vec![0u8; 64];
                bytes[24..32].copy_from_slice(&self.amount.to_be_bytes());
                bytes[56..64].copy_from_slice(&self.gas.to_be_bytes());
                format!("0x{}", alloy_primitives::hex::encode(&bytes))
            };
            Ok(provider::HttpResponse {
                result: serde_json::Value::String(payload),
                response_bytes: 10,
            })
        }
    }

    fn quoter_reader(backend: QuoterBackend) -> ChainReader<QuoterBackend, NoSleeper> {
        ChainReader::new(
            backend,
            NoSleeper,
            provider::ProviderBudget::new(u64::MAX, 1 << 24),
            provider::RetryPolicy {
                max_retries: 0,
                initial_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
            },
            4663,
        )
    }

    fn quoter_leg(
        pool_id: [u8; 32],
        token_in: Address,
        token_out: Address,
        fee_raw: u32,
    ) -> LegRoute {
        LegRoute {
            profile: *b"v4",
            pool: Address::repeat_byte(0x83),
            pool_id,
            token_in,
            token_out,
            fee_raw,
        }
    }

    #[test]
    fn quoter_chain_agrees_diverges_and_skips() {
        let tok_a = Address::repeat_byte(0x11);
        let tok_b = Address::repeat_byte(0x22);
        let id0 = [0x90u8; 32];
        let id1 = [0x91u8; 32];
        let mut e0 = catalog_entry(*b"v4", Address::repeat_byte(0x83), id0);
        e0.token0 = tok_a;
        e0.token1 = tok_b;
        let mut e1 = catalog_entry(*b"v4", Address::repeat_byte(0x83), id1);
        e1.token0 = tok_a;
        e1.token1 = tok_b;
        let legs = vec![
            quoter_leg(id0, tok_a, tok_b, 3000),
            quoter_leg(id1, tok_b, tok_a, 3000),
        ];
        let mut overrides = std::collections::HashMap::new();
        overrides.insert(alloy_primitives::hex::encode(id0), (60, Address::ZERO));
        overrides.insert(alloy_primitives::hex::encode(id1), (60, Address::ZERO));
        let states = std::collections::HashMap::new();
        let reader = quoter_reader(QuoterBackend {
            amount: 900,
            gas: 50_000,
            empty: false,
        });
        let mut calls = 10u64;
        // Chained 1000 -> 900 -> 900 against math 905: div ≈ 0.0055.
        match quoter_verify_cycle(
            &reader,
            Address::ZERO,
            &overrides,
            &[e0.clone(), e1.clone()],
            &legs,
            &states,
            U256::from(1000u64),
            U256::from(905u64),
            0.01,
            1,
            &mut calls,
        ) {
            QuoterVerdict::Agree {
                exec_output,
                divergence,
                gas,
            } => {
                assert_eq!(exec_output, U256::from(900u64));
                assert!((divergence - (1.0 - 900.0 / 905.0)).abs() < 1e-9);
                assert_eq!(gas, U256::from(100_000u64));
            }
            other => panic!("expected Agree, got {other:?}"),
        }
        assert_eq!(calls, 8, "two quoter calls consumed");
        // Same chain against math 2000: div 0.55 > 0.01 → Diverge.
        let mut calls = 10u64;
        match quoter_verify_cycle(
            &reader,
            Address::ZERO,
            &overrides,
            &[e0.clone(), e1.clone()],
            &legs,
            &states,
            U256::from(1000u64),
            U256::from(2000u64),
            0.01,
            1,
            &mut calls,
        ) {
            QuoterVerdict::Diverge { exec_output, .. } => {
                assert_eq!(exec_output, U256::from(900u64));
            }
            other => panic!("expected Diverge, got {other:?}"),
        }
        // Dynamic-fee leg: unquotable, math kept.
        let mut e_dyn = e0.clone();
        e_dyn.fee = V4_DYNAMIC_FEE_FLAG;
        assert_eq!(
            quoter_verify_cycle(
                &reader,
                Address::ZERO,
                &overrides,
                &[e_dyn, e1.clone()],
                &legs,
                &states,
                U256::from(1000u64),
                U256::from(905u64),
                0.01,
                1,
                &mut 10u64,
            ),
            QuoterVerdict::Skipped {
                reason: "inexact-fee"
            }
        );
        // V3-only cycle: model is exact, nothing to verify.
        let v3_leg = LegRoute {
            profile: *b"v3",
            ..legs[0].clone()
        };
        assert_eq!(
            quoter_verify_cycle(
                &reader,
                Address::ZERO,
                &overrides,
                &[e0, e1],
                &[v3_leg.clone(), v3_leg],
                &states,
                U256::from(1000u64),
                U256::from(905u64),
                0.01,
                1,
                &mut 10u64,
            ),
            QuoterVerdict::Skipped { reason: "v3-only" }
        );
        // Reverting quoter fails closed.
        let dead = quoter_reader(QuoterBackend {
            amount: 0,
            gas: 0,
            empty: true,
        });
        assert!(matches!(
            quoter_verify_cycle(
                &dead,
                Address::ZERO,
                &overrides,
                &[catalog_entry(*b"v4", Address::repeat_byte(0x83), id0)],
                &legs[..1],
                &states,
                U256::from(1000u64),
                U256::from(905u64),
                0.01,
                1,
                &mut 10u64,
            ),
            QuoterVerdict::Error { .. }
        ));
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
    fn fee_policy_boundaries_predatory_refused_sub_predatory_gated() {
        // Phase 3 codification: 89% passes the screen (economics kills it:
        // dust output → BelowThreshold) while 90%+ is refused up front.
        assert_eq!(leg_toll(890_000, 1_000_000, *b"v4"), Some(0.89));
        assert_eq!(leg_toll(900_000, 1_000_000, *b"v4"), Some(0.9));
        assert_eq!(leg_toll(900_001, 1_000_000, *b"v4"), None);
        assert_eq!(leg_toll(1_000_000, 1_000_000, *b"v4"), None);
        assert_eq!(leg_toll(1_000_000, 1_000_000, *b"v3"), None);
        // Standard tiers always quotable on both venues.
        for fee in [100, 500, 3_000, 10_000] {
            assert_eq!(leg_toll(fee, 1_000_000, *b"v4"), Some(f64::from(fee) / 1e6));
            assert_eq!(leg_toll(fee, 1_000_000, *b"v3"), Some(f64::from(fee) / 1e6));
        }
    }

    #[test]
    fn hook_scan_flags_only_nonzero_non_allowlisted() {
        use std::collections::{HashMap, HashSet};
        let mut overrides = HashMap::new();
        let hooked = [0xabu8; 32];
        let clean = [0xcdu8; 32];
        overrides.insert(
            alloy_primitives::hex::encode(hooked),
            (60, Address::repeat_byte(0x42)),
        );
        overrides.insert(alloy_primitives::hex::encode(clean), (60, Address::ZERO));
        let entry =
            |profile: [u8; 2], id: [u8; 32]| catalog_entry(profile, Address::repeat_byte(1), id);
        let entries = vec![
            entry(*b"v4", hooked),
            entry(*b"v4", clean),
            entry(*b"v4", [0xefu8; 32]),
            entry(*b"v3", hooked),
        ];
        // Empty allow-list: only the hooked V4 pool flags.
        let flagged = find_nonzero_hook_pools(&entries, &overrides, &HashSet::new());
        assert_eq!(
            flagged,
            vec![format!("0x{}", alloy_primitives::hex::encode(hooked))]
        );
        // Allow-listed: nothing flags (missing overrides never flag).
        let mut allowed = HashSet::new();
        allowed.insert(alloy_primitives::hex::encode(hooked));
        assert!(find_nonzero_hook_pools(&entries, &overrides, &allowed).is_empty());
    }

    #[test]
    fn quote_route_finds_two_hop_tokens_only() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("quotes.csv");
        let mut file = std::fs::File::create(&path).expect("create");
        writeln!(file, "token,symbol,decimals,usd_source").expect("header");
        writeln!(file, "# anchored stable").expect("comment");
        writeln!(
            file,
            "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168,USDG,6,anchor"
        )
        .expect("row");
        drop(file);
        let table = load_quote_table(&path).expect("parses");
        assert_eq!(table.len(), 1);
        let usdg: Address = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168"
            .parse()
            .unwrap();
        let mid = Address::repeat_byte(0xab);
        let far = Address::repeat_byte(0xcd);
        let lone = Address::repeat_byte(0xef);
        let leg = |t0: Address, t1: Address| {
            let mut e = catalog_entry(*b"v4", Address::repeat_byte(1), [9u8; 32]);
            e.token0 = t0;
            e.token1 = t1;
            e
        };
        // USDG--mid direct, mid--far two-hop, lone isolated.
        let legs = vec![leg(usdg, mid), leg(mid, far), leg(lone, lone)];
        let unrouted = tokens_without_quote_route(&legs, &table);
        assert_eq!(unrouted, vec![lone]);
    }

    #[test]
    fn hook_allowlist_parsing_skips_noise() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allow.csv");
        let mut file = std::fs::File::create(&path).expect("create");
        writeln!(file, "pool_id").expect("header");
        writeln!(file, "# comment").expect("comment");
        writeln!(file).expect("blank");
        writeln!(file, "0xABCDEF").expect("prefixed");
        writeln!(file, "123456").expect("bare");
        drop(file);
        let allowlist = load_hook_allowlist(&path).expect("parses");
        assert!(allowlist.contains("abcdef"));
        assert!(allowlist.contains("123456"));
        assert_eq!(allowlist.len(), 2);
        assert_eq!(
            normalize_pool_id_hex("  0XAbC  "),
            "abc",
            "trims, strips, lowercases"
        );
    }

    #[test]
    fn oriented_pair_skew_handles_opposite_token_orders() {
        // Parity price in both venues: sqrt = 2^96 (price_out = 2^96).
        let parity = U256::from(1u64) << 96;
        let price = |sqrt: U256| PoolPrice {
            sqrt,
            liquidity: U256::from(1_000_000_u64),
            block: 1,
            observed_fee: None,
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
        assert!(
            oriented_pair_skew(
                &venue_a,
                &price(parity),
                &venue_b_sorted,
                &price(parity),
                lo
            )
            .abs()
                < 1e-9
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
        let map = load_catalog(&path, None, None).unwrap();
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
        let m3 = load_catalog(&p3, None, None).unwrap();
        let m4 = load_catalog(&p4, None, None).unwrap();
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
        let m3 = load_catalog(&p3, None, None).unwrap();
        let m4 = load_catalog(&p4, None, None).unwrap();
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
        let m3 = load_catalog(&p3, None, None).unwrap();
        let m4 = load_catalog(&p4, None, None).unwrap();
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
                observed_fee: None,
            },
        );
        let mut pb = HashMap::new();
        pb.insert(
            key4,
            PoolPrice {
                sqrt: U256::from(1u64) << 98,
                liquidity: U256::from(1_000u64),
                block: 1,
                observed_fee: None,
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
        let m3 = load_catalog(&p3, None, None).unwrap();
        let m4 = load_catalog(&p4, None, None).unwrap();
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
                observed_fee: None,
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
                observed_fee: None,
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
        let m3 = load_catalog(&p3, None, None).unwrap();
        let m4 = load_catalog(&p4, None, None).unwrap();
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
        let m3 = load_catalog(&p3, None, None).unwrap();
        let m4 = load_catalog(&p4, None, None).unwrap();
        let all_a: Vec<_> = m3.into_values().collect();
        let all_b: Vec<_> = m4.into_values().collect();
        let selected = HashSet::from([pair_key(a.parse().unwrap(), b.parse().unwrap())]);
        let kept = expand_manifest_catalog(&all_a, &all_b, &selected, 2_000).unwrap();
        // The zero-fee v4 row must be dropped; only the v3 leg survives.
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].profile, *b"v3");
    }

    #[test]
    fn expand_manifest_catalog_reorders_native_sentinel_pairs() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        // A v4 native pool stored sentinel-first (0x0 as token0); after
        // normalization the sentinel becomes the wrapped-native contract,
        // whose address sorts ABOVE most tokens. The expanded row must be
        // re-sorted so written manifests satisfy canonical ordering.
        let a = "0x0000000000000000000000000000000000000000";
        let b = "0x2000000000000000000000000000000000000000";
        let p4 = dir.path().join("v4.csv");
        let id = "33".repeat(32);
        {
            let mut f = std::fs::File::create(&p4).unwrap();
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0x8366a39CC670B4001A1121B8F6A443A643e40951,0x2222222222222222222222222222222222222222,{a},{b},2500,1000000,v4,0x{id},\n"
            )
            .unwrap();
        }
        let m4 = load_catalog(&p4, None, None).unwrap();
        let all_b: Vec<_> = m4.into_values().collect();
        let selected = HashSet::from([pair_key(RHC_NATIVE, b.parse().unwrap())]);
        let kept = expand_manifest_catalog(&[], &all_b, &selected, 2_000).unwrap();
        assert_eq!(kept.len(), 1);
        assert!(
            kept[0].token0 < kept[0].token1,
            "expanded row must be canonically ordered: {:?}",
            kept[0]
        );
        // Identity is untouched by the reorder.
        assert_eq!(kept[0].id, [0x33; 32]);
    }

    #[test]
    fn single_tick_capacity_matches_hand_computed_amounts() {
        // P = 4 (sqrt_x96 = 2·2^96), L = 1e22, ts = 60 → r ≈ 1.00300435.
        // Hand-computed (see scripts in audit task 0.4):
        //   sell token0: Δx = L·(1/√P)·(1 − 1/r) ≈ 1.4977e19
        //   sell token1: Δy = L·√P·(r − 1)      ≈ 6.0087e19
        use super::{single_tick_capacity, tick_spacing_from_fee};
        let sqrt = U256::from(2u64) * (U256::from(1u64) << 96);
        let liquidity = U256::from(10_000_000_000_000_000_000_000u128);
        let ts = tick_spacing_from_fee(3000);
        assert_eq!(ts, 60);
        let cap0 = single_tick_capacity(sqrt, liquidity, ts, true);
        let cap1 = single_tick_capacity(sqrt, liquidity, ts, false);
        let expect0 = 1.497_677_5e19;
        let expect1 = 6.008_708_1e19;
        // The 1% tolerance dwarfs f64 mantissa loss at these magnitudes.
        #[allow(clippy::cast_precision_loss)]
        let got0 = cap0.to::<u128>() as f64;
        #[allow(clippy::cast_precision_loss)]
        let got1 = cap1.to::<u128>() as f64;
        assert!(
            (got0 - expect0).abs() / expect0 < 0.01,
            "token0 capacity {got0:e} vs expected {expect0:e}"
        );
        assert!(
            (got1 - expect1).abs() / expect1 < 0.01,
            "token1 capacity {got1:e} vs expected {expect1:e}"
        );

        // Monotone in liquidity; zero liquidity → zero capacity.
        assert!(
            single_tick_capacity(
                sqrt,
                liquidity.checked_mul(U256::from(2u64)).unwrap(),
                ts,
                true
            ) > cap0
        );
        assert!(single_tick_capacity(sqrt, U256::ZERO, ts, true).is_zero());

        // Wider spacing → larger cell → larger capacity.
        assert!(single_tick_capacity(sqrt, liquidity, tick_spacing_from_fee(10000), true) > cap0);
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
        let m3 = load_catalog(&p3, None, None).unwrap();
        let m4 = load_catalog(&p4, None, None).unwrap();
        let a_entries: Vec<_> = m3.into_values().collect();
        let b_entries: Vec<_> = m4.into_values().collect();

        let mut pa = HashMap::new();
        pa.insert(
            a_entries[0].venue.into_word().into(),
            PoolPrice {
                sqrt: U256::from(1u64) << 97,
                liquidity: U256::from(1_000_000_000u64),
                block: 1,
                observed_fee: None,
            },
        );
        let mut pb = HashMap::new();
        pb.insert(
            b_entries[0].id,
            PoolPrice {
                sqrt: U256::from(1u64) << 98,
                liquidity: U256::from(1_000_000_000u64),
                block: 1,
                observed_fee: None,
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
        let m3 = load_catalog(&p3, None, None).unwrap();
        let m4 = load_catalog(&p4, None, None).unwrap();
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
                observed_fee: None,
            },
        );
        assert!(quote_pair(&a_entries, &b_entries, &pa, &pb).is_err());
    }

    #[test]
    fn quote_pair_rejects_mismatched_pair_legs() {
        // Audit S7: venue A priced on pair (a,b), venue B priced on pair
        // (a,c). best_leg selects each venue's cheapest priced pool
        // independently; before the guard this composed a cycle across two
        // unrelated pairs and priced it.
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
                 4663,0xfa00000000000000000000000000000000000001,0x1111111111111111111111111111111111111111,{a},{b},3000,1000000,v3,,\n"
            )
            .unwrap();
        }
        {
            let mut f = std::fs::File::create(&p4).unwrap();
            let id = "44".repeat(32);
            write!(
                f,
                "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n\
                 4663,0x8366a39CC670B4001A1121B8F6A443A643e40951,0x2222222222222222222222222222222222222222,{b},{c},2500,1000000,v4,0x{id},\n"
            )
            .unwrap();
        }
        let m3 = load_catalog(&p3, None, None).unwrap();
        let m4 = load_catalog(&p4, None, None).unwrap();
        let a_entries: Vec<_> = m3.into_values().collect();
        let b_entries: Vec<_> = m4.into_values().collect();

        let mut pa = HashMap::new();
        pa.insert(
            a_entries[0].venue.into_word().into(),
            PoolPrice {
                sqrt: U256::from(1u64) << 97,
                liquidity: U256::from(1_000_000_000u64),
                block: 1,
                observed_fee: None,
            },
        );
        let mut pb = HashMap::new();
        pb.insert(
            b_entries[0].id,
            PoolPrice {
                sqrt: U256::from(1u64) << 98,
                liquidity: U256::from(1_000_000_000u64),
                block: 1,
                observed_fee: None,
            },
        );

        let error = quote_pair(&a_entries, &b_entries, &pa, &pb)
            .expect_err("mismatched-pair legs must hard-error");
        assert!(
            error.contains("not the same pair"),
            "guard detail must name the violation: {error}"
        );
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
        let m3 = load_catalog(&p3, None, None).unwrap();
        let m4 = load_catalog(&p4, None, None).unwrap();
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
                    observed_fee: None,
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
                observed_fee: None,
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
        let m3 = load_catalog(&p3, None, None).unwrap();
        let m4 = load_catalog(&p4, None, None).unwrap();
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
                observed_fee: None,
            },
        );
        let mut pb = HashMap::new();
        pb.insert(
            b_entries[0].id,
            PoolPrice {
                sqrt: U256::from(1u64) << 98,
                liquidity: U256::from(1_000_000_000u64),
                block: 1,
                observed_fee: None,
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
                observed_fee: None,
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
    fn decode_word_decimals_rejects_over_wide_values() {
        // Audit A21: the old loop shifted through a u64, silently keeping
        // only the last 8 bytes — a `2^64` decimals return truncated to
        // Some(0) and would have mis-scaled every price by 10^18.
        let mut word = vec![0u8; 32];
        word[0] = 1; // value = 2^248: far beyond u8, high byte non-zero
        assert_eq!(decode_word_decimals(&word), None);
        word[0] = 0;
        word[24] = 1; // still beyond the final byte the old loop kept
        assert_eq!(decode_word_decimals(&word), None);
    }

    #[test]
    fn decode_word_decimals_parses_and_fails_closed() {
        // `decimals()` on a 6-dec token: right-aligned word.
        let mut word = vec![0u8; 32];
        word[31] = 6;
        assert_eq!(decode_word_decimals(&word), Some(6));
        assert_eq!(decode_word_decimals(&[18]), Some(18));
        // Malformed: empty or wider than a word must not guess.
        assert_eq!(decode_word_decimals(&[]), None);
        assert_eq!(decode_word_decimals(&[0u8; 33]), None);
        // Values beyond u8 are rejected rather than truncated.
        let mut big = vec![0u8; 32];
        big[30] = 1;
        assert_eq!(decode_word_decimals(&big), None);
    }

    #[test]
    fn usd_derivation_cancels_token_decimals() {
        // The `x10^(36-d_usdg)` factor is only correct because the token
        // side's decimals cancel against the fixed-point convention
        // (`V = P x 1e36/10^d_tok`). Two tokens with different decimals,
        // each in a USG leg at human parity ($1 per whole token), must
        // derive to V values whose implied human prices are both $1.
        //
        // Parity for an (usg=tok0, x=tok1) pool: whole-X per whole-USG
        // = (r1/r0) * 10^(d_usg-d_x) = 1 => r0/r1 = 10^(d_x-d_usg).
        let six_dec: Address = "0x6000000000000000000000000000000000000006"
            .parse()
            .unwrap();
        let eighteen_dec: Address = "0x1800000000000000000000000000000000000018"
            .parse()
            .unwrap();
        let usg = RHC_USDG;
        let two_96: U256 = U256::from(1u64) << 96;
        // Six-dec token: r0/r1 = 10^0 = 1.
        let e6 = price_entry(Address::repeat_byte(0xa1), usg, six_dec);
        // Eighteen-dec token: r0/r1 = 1e12 => sqrt = 2^96 * 1e6.
        let e18 = price_entry(Address::repeat_byte(0xa2), usg, eighteen_dec);
        let mut priced = HashMap::new();
        priced.insert(
            pool_key(&e6),
            PoolPrice {
                sqrt: two_96,
                liquidity: U256::from(1_000_000_000_000_u64),
                block: 1,
                observed_fee: None,
            },
        );
        priced.insert(
            pool_key(&e18),
            PoolPrice {
                sqrt: two_96.checked_mul(U256::from(1_000_000_u64)).unwrap(),
                liquidity: U256::from(1_000_000_000_000_u64),
                block: 1,
                observed_fee: None,
            },
        );
        let out = derive_usd_prices(&[], &[e6, e18], &HashMap::new(), &priced);
        // Implied human price: P = V * 10^d_tok / 1e36. Both legs are at $1.
        let implied = |v: U256, d: u32| f64_of(v) * 10f64.powi(d.cast_signed()) / 1e36;
        assert!(
            (implied(out[&six_dec], 6) - 1.0).abs() < 1e-6
                && (implied(out[&eighteen_dec], 18) - 1.0).abs() < 1e-6,
            "$1 tokens with different decimals must imply $1 after derivation: \
             v6={} v18={}",
            out[&six_dec],
            out[&eighteen_dec]
        );
    }

    #[test]
    fn verify_capture_ledger_prices_costs_and_requires_priced_legs() {
        let usg = RHC_USDG;
        let tok: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let leg = price_entry(Address::repeat_byte(0xa1), usg, tok);
        // sqrt 2^97 ⇒ token trades at $4 per whole (see the derive test).
        let mut priced = HashMap::new();
        priced.insert(
            pool_key(&leg),
            PoolPrice {
                sqrt: U256::from(1u64) << 97,
                liquidity: U256::from(1_000_000_000_000_u64),
                block: 7,
                observed_fee: None,
            },
        );
        // Same price both venues: zero skew, but a cross-venue round trip
        // still pays two tolls, so profit is negative and net floors at gas.
        let gas = U256::from(30_000_000_000_000_000_u64); // $0.03
        let leg_a = price_entry(Address::repeat_byte(0xb1), usg, tok);
        let mut priced_a = HashMap::new();
        priced_a.insert(
            pool_key(&leg_a),
            PoolPrice {
                sqrt: U256::from(1u64) << 96,
                liquidity: U256::from(1_000_000_000_000_u64),
                block: 7,
                observed_fee: None,
            },
        );
        let ledger = verify_capture_ledger(
            std::slice::from_ref(&leg_a),
            std::slice::from_ref(&leg),
            &priced_a,
            &priced,
            tok,
            // token_lo is `tok` ($4/whole at this sqrt): V = P × 1e36/10^d.
            U256::from(4) * usd_factor(),
            gas,
        )
        .expect("both legs priced");
        // The 4x venue skew is captureable: positive net after gas, and the
        // Aave premium strictly reduces it.
        assert!(
            ledger.net_usd_none > U256::ZERO,
            "profitable route: {ledger:?}"
        );
        assert!(ledger.net_usd_aave < ledger.net_usd_none);
        assert_eq!(ledger.token_lo, tok);
        assert!(ledger.log2_skew > 0.0);
        // A missing opposite-venue leg must fail closed.
        assert!(
            verify_capture_ledger(
                &[],
                &[],
                &HashMap::new(),
                &HashMap::new(),
                usg,
                usd_factor(),
                gas
            )
            .is_err()
        );
    }

    fn usd_factor() -> U256 {
        factor_ten(36 - usize::from(RHC_USDG_DECIMALS))
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
                    observed_fee: None,
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
                observed_fee: None,
            },
        );
        priced.insert(
            pool_key(&ratio),
            PoolPrice {
                sqrt: U256::from(1u64) << 98,
                liquidity: U256::from(1_000_000_000u64),
                block: 1,
                observed_fee: None,
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

    /// Canned `eth_getLogs` backend: returns one queued result per request.
    struct ActivityBackend {
        results: std::cell::RefCell<std::collections::VecDeque<Vec<serde_json::Value>>>,
    }

    /// Records every `eth_getLogs` request range and returns scripted
    /// responses (or a transient error) per request, to drive the ring sweep.
    /// The request log is shared via `Rc` so the test can inspect it after
    /// the backend is moved into the [`ChainReader`].
    type ScriptedResponse = Result<Vec<serde_json::Value>, TransportError>;

    struct RingBackend {
        requests: std::rc::Rc<std::cell::RefCell<Vec<(u64, u64)>>>,
        responses: std::rc::Rc<std::cell::RefCell<std::collections::VecDeque<ScriptedResponse>>>,
    }

    impl provider::HttpBackend for RingBackend {
        fn request(
            &self,
            request: &provider::RpcRequest,
        ) -> Result<provider::HttpResponse, TransportError> {
            assert_eq!(request.method, "eth_getLogs");
            let filter = &request.params[0];
            let parse = |field: &str| -> u64 {
                u64::from_str_radix(
                    filter[field]
                        .as_str()
                        .expect("hex quantity")
                        .trim_start_matches("0x"),
                    16,
                )
                .unwrap()
            };
            self.requests
                .borrow_mut()
                .push((parse("fromBlock"), parse("toBlock")));
            self.responses
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Ok(Vec::new()))
                .map(|logs| provider::HttpResponse {
                    result: serde_json::Value::Array(logs),
                    response_bytes: 10,
                })
        }
    }

    fn ring_reader(backend: RingBackend) -> ChainReader<RingBackend, NoSleeper> {
        ChainReader::new(
            backend,
            NoSleeper,
            provider::ProviderBudget::new(u64::MAX, 1 << 24),
            provider::RetryPolicy {
                max_retries: 0,
                initial_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
            },
            4663,
        )
    }

    impl provider::HttpBackend for ActivityBackend {
        fn request(
            &self,
            _request: &provider::RpcRequest,
        ) -> Result<provider::HttpResponse, TransportError> {
            let logs = self.results.borrow_mut().pop_front().unwrap_or_default();
            Ok(provider::HttpResponse {
                result: serde_json::Value::Array(logs),
                response_bytes: 10,
            })
        }
    }

    struct NoSleeper;

    impl provider::Sleeper for NoSleeper {
        fn sleep(&self, _duration: Duration) {}
    }

    fn activity_reader(backend: ActivityBackend) -> ChainReader<ActivityBackend, NoSleeper> {
        ChainReader::new(
            backend,
            NoSleeper,
            provider::ProviderBudget::new(u64::MAX, 1 << 24),
            provider::RetryPolicy {
                max_retries: 0,
                initial_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
            },
            4663,
        )
    }

    fn swap_log(address: Address, topic1: Option<[u8; 32]>) -> serde_json::Value {
        let mut log_topics = vec![v3_swap_topic()];
        if let Some(id) = topic1 {
            log_topics.push(alloy_primitives::B256::new(id));
        }
        serde_json::json!({
            "address": format!("{address:?}"),
            "topics": log_topics,
            "data": "0x00",
            "blockNumber": "0x10",
            "transactionIndex": "0x1",
            "logIndex": "0x2",
            "removed": false,
        })
    }

    fn catalog_entry(profile: [u8; 2], venue: Address, id: [u8; 32]) -> PoolEntry {
        PoolEntry {
            profile,
            venue,
            id,
            fee: 3000,
            token0: Address::repeat_byte(0x11),
            token1: Address::repeat_byte(0x22),
            fee_denominator: 1_000_000,
            factory: Address::ZERO,
            chain_id: 4663,
        }
    }

    #[test]
    fn sweep_swap_activity_counts_events_per_pool() {
        // V3 path: one address chunk; the mock returns two swaps on pool A
        // and one on an unknown address (still counted — the filter scoped
        // the request to catalog pools).
        let pool_a = Address::repeat_byte(0xaa);
        let pool_b = Address::repeat_byte(0xbb);
        let entries = vec![
            catalog_entry(*b"v3", pool_a, [1u8; 32]),
            catalog_entry(*b"v3", pool_b, [2u8; 32]),
        ];
        let backend = ActivityBackend {
            results: std::cell::RefCell::new(std::collections::VecDeque::from([vec![
                swap_log(pool_a, None),
                swap_log(pool_a, None),
                swap_log(pool_b, None),
            ]])),
        };
        let reader = activity_reader(backend);
        let counts = sweep_swap_activity(
            &reader,
            *b"v3",
            Address::ZERO,
            &entries,
            1,
            10,
            50,
            Duration::ZERO,
        )
        .unwrap();
        let key_a: [u8; 32] = pool_a.into_word().into();
        let key_b: [u8; 32] = pool_b.into_word().into();
        assert_eq!(counts.get(&key_a), Some(&2));
        assert_eq!(counts.get(&key_b), Some(&1));

        // V4 path: the singleton stream is filtered by topic1 id; a foreign
        // pool's swap must not be counted.
        let id_known = [7u8; 32];
        let id_foreign = [9u8; 32];
        let v4_entries = vec![catalog_entry(*b"v4", V4_MANAGER_TEST, id_known)];
        let singleton = V4_MANAGER_TEST;
        let backend_v4 = ActivityBackend {
            results: std::cell::RefCell::new(std::collections::VecDeque::from([vec![
                swap_log(singleton, Some(id_known)),
                swap_log(singleton, Some(id_known)),
                swap_log(singleton, Some(id_foreign)),
            ]])),
        };
        let reader_v4 = activity_reader(backend_v4);
        let counts_v4 = sweep_swap_activity(
            &reader_v4,
            *b"v4",
            singleton,
            &v4_entries,
            1,
            10,
            50,
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(counts_v4.get(&id_known), Some(&2));
        assert!(!counts_v4.contains_key(&id_foreign));
    }

    #[test]
    fn ring_sweep_covers_every_block_exactly_once_across_polls() {
        // The S2a regression: with a global high-water mark, chunks not in a
        // poll's ring slice permanently lost their block range. Per-chunk
        // water marks mean every block in [start..=to] is requested by
        // exactly one chunk across the poll sequence, regardless of cadence.
        let pool_a = Address::repeat_byte(0xaa);
        let pool_b = Address::repeat_byte(0xbb);
        let entries = vec![
            catalog_entry(*b"v3", pool_a, [1u8; 32]),
            catalog_entry(*b"v3", pool_b, [2u8; 32]),
        ];
        let requests_log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let responses: std::rc::Rc<
            std::cell::RefCell<std::collections::VecDeque<ScriptedResponse>>,
        > = std::rc::Rc::new(std::cell::RefCell::new(std::collections::VecDeque::new()));
        let reader = ring_reader(RingBackend {
            requests: std::rc::Rc::clone(&requests_log),
            responses: std::rc::Rc::clone(&responses),
        });
        let mut chunk_water = vec![0u64; sweep_chunk_count(*b"v3", &entries)];
        assert_eq!(chunk_water.len(), 1, "two pools share one 999-wide chunk");

        // Three "polls" advancing the tip; one chunk per poll is moot with a
        // single chunk — exercise multi-chunk via catch-up capping instead:
        // cap = 5 blocks per call against tips advancing by 7.
        let mut covered: Vec<(u64, u64)> = Vec::new();
        let mut tip = 0u64;
        for _ in 0..3 {
            tip += 7;
            let outcome = sweep_swap_prices_ring(
                &reader,
                *b"v3",
                Address::ZERO,
                &entries,
                &mut chunk_water,
                0,
                0,
                tip,
                50,
                Duration::ZERO,
                5,
            )
            .unwrap();
            covered.extend(
                outcome
                    .covered_keys
                    .iter()
                    .map(|(_, through)| (*through, *through)),
            );
        }
        // Water marks: after each capped call the chunk advanced exactly 5.
        assert_eq!(chunk_water, vec![15], "3 calls x 5-block cap from 0");
        // The requested ranges must tile [1..=15] with no gaps and no overlap.
        let tiled: Vec<(u64, u64)> = requests_log.borrow().clone();
        let mut expected = vec![(1u64, 5), (6, 10), (11, 15)];
        expected.sort_unstable();
        assert_eq!(
            tiled, expected,
            "every block covered exactly once: {tiled:?}"
        );
        // Coverage vouchers report through each call's effective depth — one
        // entry per pool in the covered chunk (two pools here).
        let mut depths: Vec<u64> = covered.into_iter().map(|(t, _)| t).collect();
        depths.sort_unstable();
        depths.dedup();
        assert_eq!(depths, vec![5, 10, 15]);
    }

    #[test]
    fn ring_sweep_failure_keeps_water_mark_and_retries_range() {
        // A mid-chunk failure must advance only through windows that actually
        // succeeded, so the failed range is retried — never skipped (B12).
        let pool_a = Address::repeat_byte(0xaa);
        let entries = vec![catalog_entry(*b"v3", pool_a, [1u8; 32])];
        let requests_log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let responses: std::rc::Rc<
            std::cell::RefCell<std::collections::VecDeque<ScriptedResponse>>,
        > = std::rc::Rc::new(std::cell::RefCell::new(std::collections::VecDeque::new()));
        // First request succeeds for window [1..=2]; second fails.
        responses
            .borrow_mut()
            .push_back(Ok(vec![swap_log(pool_a, None)]));
        responses
            .borrow_mut()
            .push_back(Err(TransportError::Transient("scripted".to_owned())));
        let reader = ring_reader(RingBackend {
            requests: std::rc::Rc::clone(&requests_log),
            responses: std::rc::Rc::clone(&responses),
        });
        let mut chunk_water = vec![0u64];
        let error = sweep_swap_prices_ring(
            &reader,
            *b"v3",
            Address::ZERO,
            &entries,
            &mut chunk_water,
            0,
            0,
            4,
            2, // window width 2 → two windows over [1..=4]
            Duration::ZERO,
            DEFAULT_MAX_CATCHUP_BLOCKS,
        )
        .unwrap_err();
        assert!(matches!(error, TransportError::Transient(_)));
        assert_eq!(
            chunk_water,
            vec![2],
            "only the succeeded window's blocks are marked"
        );

        // Retry covers exactly the remaining range.
        responses.borrow_mut().push_back(Ok(Vec::new()));
        let outcome = sweep_swap_prices_ring(
            &reader,
            *b"v3",
            Address::ZERO,
            &entries,
            &mut chunk_water,
            0,
            0,
            4,
            2,
            Duration::ZERO,
            DEFAULT_MAX_CATCHUP_BLOCKS,
        )
        .unwrap();
        assert_eq!(chunk_water, vec![4]);
        assert_eq!(
            requests_log.borrow().last(),
            Some(&(3, 4)),
            "retry resumes after the covered block"
        );
        assert_eq!(outcome.covered_keys.len(), 1);
    }

    #[test]
    fn ring_sweep_advances_chunks_independently() {
        // The literal canary shape: >999 pools split into two chunks, one
        // chunk per poll. Each chunk's water mark advances only when its own
        // chunk is swept; the unswept chunk's range stays pending instead of
        // being skipped by a global high-water mark.
        let entries: Vec<PoolEntry> = (0..1_500u32)
            .map(|i| {
                catalog_entry(
                    *b"v3",
                    Address::repeat_byte(u8::try_from(i % 251).unwrap_or(0) + 1),
                    alloy_primitives::B256::from(U256::from(i + 1)).into(),
                )
            })
            .collect();
        assert_eq!(sweep_chunk_count(*b"v3", &entries), 2);
        let requests_log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let responses: std::rc::Rc<
            std::cell::RefCell<std::collections::VecDeque<ScriptedResponse>>,
        > = std::rc::Rc::new(std::cell::RefCell::new(std::collections::VecDeque::new()));
        let reader = ring_reader(RingBackend {
            requests: std::rc::Rc::clone(&requests_log),
            responses: std::rc::Rc::clone(&responses),
        });
        let mut chunk_water = vec![0u64; 2];

        // Poll 1 at tip=10 sweeps the most-behind chunk (index tie-break
        // picks chunk 0): covers [1..=10] for chunk 0 only.
        let outcome = sweep_swap_prices_ring(
            &reader,
            *b"v3",
            Address::ZERO,
            &entries,
            &mut chunk_water,
            0,
            1,
            10,
            50,
            Duration::ZERO,
            DEFAULT_MAX_CATCHUP_BLOCKS,
        )
        .unwrap();
        assert_eq!(chunk_water, vec![10, 0]);
        assert_eq!(outcome.covered_keys.len(), 999);
        assert_eq!(
            requests_log.borrow().as_slice(),
            &[(1, 10)],
            "only chunk 0's range was requested"
        );

        // Poll 2 at tip=20: chunk 1 is now most behind and is selected.
        let _ = sweep_swap_prices_ring(
            &reader,
            *b"v3",
            Address::ZERO,
            &entries,
            &mut chunk_water,
            0,
            1,
            20,
            50,
            Duration::ZERO,
            DEFAULT_MAX_CATCHUP_BLOCKS,
        )
        .unwrap();
        assert_eq!(chunk_water, vec![10, 20]);
        assert_eq!(
            requests_log.borrow().last(),
            Some(&(1, 20)),
            "chunk 1 covered its full pending range [1..=20]"
        );
    }

    const V4_MANAGER_TEST: Address =
        alloy_primitives::address!("0x8366a39CC670B4001A1121B8F6A443A643e40951");

    #[test]
    fn pair_activity_rankings_scores_two_sided_minimum() {
        let lo: Address = "0x1000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let hi: Address = "0x2000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let other: Address = "0x3000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let entry_with = |profile: [u8; 2], venue: Address, id: [u8; 32]| PoolEntry {
            profile,
            venue,
            id,
            fee: 3000,
            token0: lo,
            token1: hi,
            fee_denominator: 1_000_000,
            factory: Address::ZERO,
            chain_id: 4663,
        };

        // Pair (lo,hi): active venue-A pool (5) + two venue-B fee tiers whose
        // best leg traded 3 times. Pair (lo,other): wildly active on A only.
        let mut a_entries = vec![
            entry_with(*b"v3", Address::repeat_byte(0xa1), [1u8; 32]),
            entry_with(*b"v3", Address::repeat_byte(0xa2), [2u8; 32]),
        ];
        a_entries[1].token1 = other;
        let b_entries = vec![
            entry_with(*b"v4", V4_MANAGER_TEST, [3u8; 32]),
            entry_with(*b"v4", V4_MANAGER_TEST, [4u8; 32]),
        ];
        // Venue-A pools are keyed by address; venue-B by PoolId.
        let activity_a: HashMap<[u8; 32], u64> = HashMap::from([
            (Address::repeat_byte(0xa1).into_word().into(), 5),
            (Address::repeat_byte(0xa2).into_word().into(), 50),
        ]);
        let activity_b: HashMap<[u8; 32], u64> = HashMap::from([([3u8; 32], 3), ([4u8; 32], 1)]);

        let rankings = pair_activity_rankings(&a_entries, &b_entries, &activity_a, &activity_b);

        // The one-sided (lo,other) pair must be dropped entirely: it can
        // never be evaluated without a priced B leg.
        assert_eq!(
            rankings.len(),
            1,
            "one-sided pairs are dropped: {rankings:?}"
        );
        let top = &rankings[0];
        assert_eq!(top.token_lo, lo);
        assert_eq!(top.token_hi, hi);
        assert_eq!(top.swaps_a, 5);
        assert_eq!(top.swaps_b, 3);
        assert_eq!(top.score, 3, "score is the quieter side");
    }

    fn v3_swap_envelope(pool: Address, block: u64, sqrt: u16, liquidity: u64) -> RawLogEnvelope {
        let mut data = vec![0u8; 160];
        data[94..96].copy_from_slice(&sqrt.to_be_bytes());
        data[96..128].copy_from_slice(&U256::from(liquidity).to_be_bytes::<32>());
        RawLogEnvelope {
            address: pool,
            topics: vec![provider::v3_swap_topic(), B256::default()],
            data: Bytes::from(data),
            block_number: block,
            transaction_index: 0,
            log_index: 0,
            removed: false,
            block_hash: B256::default(),
        }
    }

    fn v4_swap_envelope(id: [u8; 32], block: u64, sqrt: u16, fee: u32) -> RawLogEnvelope {
        let mut data = vec![0u8; 192];
        data[94..96].copy_from_slice(&sqrt.to_be_bytes());
        data[96..128].copy_from_slice(&U256::from(7u64).to_be_bytes::<32>());
        data[188..192].copy_from_slice(&fee.to_be_bytes());
        RawLogEnvelope {
            address: Address::repeat_byte(0x83),
            topics: vec![provider::v4_swap_topic(), B256::from(id), B256::default()],
            data: Bytes::from(data),
            block_number: block,
            transaction_index: 0,
            log_index: 0,
            removed: false,
            block_hash: B256::default(),
        }
    }

    #[test]
    fn ingest_envelope_keys_v3_by_pool_address() {
        let pool = Address::repeat_byte(0x11);
        let mut latest = HashMap::new();
        ingest_envelope(
            *b"v3",
            &mut latest,
            &v3_swap_envelope(pool, 100, 0xDEAD, 500),
            None,
        );
        let key: [u8; 32] = pool.into_word().into();
        let price = latest.get(&key).expect("v3 pool priced");
        assert_eq!(price.sqrt, U256::from(0xDEAD_u64));
        assert_eq!(price.liquidity, U256::from(500u64));
        assert_eq!(price.block, 100);
        assert_eq!(price.observed_fee, None);
    }

    #[test]
    fn ingest_envelope_filters_v4_by_listed_id_and_keeps_fee() {
        let listed = [7u8; 32];
        let keep: HashSet<[u8; 32]> = HashSet::from([listed]);
        let mut latest = HashMap::new();
        ingest_envelope(
            *b"v4",
            &mut latest,
            &v4_swap_envelope(listed, 200, 0xBEEF, 3000),
            Some(&keep),
        );
        let price = latest.get(&listed).expect("listed v4 pool priced");
        assert_eq!(price.sqrt, U256::from(0xBEEF_u64));
        assert_eq!(price.block, 200);
        assert_eq!(price.observed_fee, Some(3000));
        // Unlisted PoolId is dropped even with a decodable body.
        ingest_envelope(
            *b"v4",
            &mut latest,
            &v4_swap_envelope([9u8; 32], 201, 0xBEEF, 3000),
            Some(&keep),
        );
        assert_eq!(latest.len(), 1, "unlisted id must not price");
    }

    #[test]
    fn ingest_envelope_never_clobbers_fresher_state() {
        let pool = Address::repeat_byte(0x22);
        let mut latest = HashMap::new();
        ingest_envelope(
            *b"v3",
            &mut latest,
            &v3_swap_envelope(pool, 300, 0xAAAA, 1),
            None,
        );
        ingest_envelope(
            *b"v3",
            &mut latest,
            &v3_swap_envelope(pool, 299, 0xBBBB, 2),
            None,
        );
        let key: [u8; 32] = pool.into_word().into();
        let price = latest.get(&key).unwrap();
        assert_eq!(
            price.sqrt,
            U256::from(0xAAAA_u64),
            "older block must not win"
        );
        assert_eq!(price.block, 300);
        // Same-block redelivery overwrites (matches sweep semantics).
        ingest_envelope(
            *b"v3",
            &mut latest,
            &v3_swap_envelope(pool, 300, 0xCCCC, 3),
            None,
        );
        assert_eq!(latest.get(&key).unwrap().sqrt, U256::from(0xCCCC_u64));
    }

    #[test]
    fn ingest_envelope_ignores_undecodable_body() {
        let pool = Address::repeat_byte(0x33);
        let mut latest = HashMap::new();
        let mut short = v3_swap_envelope(pool, 400, 0xDEAD, 1);
        short.data = Bytes::from(vec![0u8; 32]);
        ingest_envelope(*b"v3", &mut latest, &short, None);
        assert!(latest.is_empty(), "short body must not price");
    }

    #[test]
    fn archive_gating_detected_by_code_or_keyword() {
        // 2026-09-07: Chainstack free serves getLogs ~50-100 blocks back;
        // older ranges fail `-32002` (HTTP 403 with body) and must skip
        // forward, never retry-storm.
        assert!(is_archive_walled(&TransportError::Transient(
            "HTTP status 403: {\"code\":-32002,\"message\":\"Archive, Debug and Trace\"}"
                .to_owned(),
        )));
        assert!(is_archive_walled(&TransportError::Permanent(
            "HTTP status 403: archive not available".to_owned(),
        )));
        assert!(!is_archive_walled(&TransportError::Transient(
            "HTTP status 429: Too Many Requests".to_owned(),
        )));
        assert!(!is_archive_walled(&TransportError::Permanent(
            "HTTP status 400: invalid range".to_owned(),
        )));
    }

    /// Scripted backend for refetch tests: `eth_getStorageAt` serves the
    /// V4 mapping words by slot; `eth_call` serves V3 `slot0()`/`liquidity()`.
    struct RefetchBackend {
        storage_words: std::collections::HashMap<String, String>,
        v3_sqrt: &'static str,
        v3_liquidity: &'static str,
    }

    impl provider::HttpBackend for RefetchBackend {
        fn request(
            &self,
            request: &provider::RpcRequest,
        ) -> Result<provider::HttpResponse, TransportError> {
            let word = if request.method == "eth_getStorageAt" {
                let slot = request.params[1].as_str().unwrap().to_owned();
                self.storage_words
                    .get(&slot)
                    .cloned()
                    .unwrap_or_else(|| format!("0x{}", "00".repeat(32)))
            } else if request.params[0]["data"]
                .as_str()
                .unwrap_or_default()
                .ends_with("3850c7bd")
            {
                self.v3_sqrt.to_owned()
            } else {
                self.v3_liquidity.to_owned()
            };
            Ok(provider::HttpResponse {
                result: serde_json::Value::String(word),
                response_bytes: 10,
            })
        }
    }

    fn refetch_reader(backend: RefetchBackend) -> ChainReader<RefetchBackend, NoSleeper> {
        ChainReader::new(
            backend,
            NoSleeper,
            provider::ProviderBudget::new(u64::MAX, 1 << 24),
            provider::RetryPolicy {
                max_retries: 0,
                initial_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
            },
            4663,
        )
    }

    #[test]
    fn refetch_routes_v4_through_pool_manager_mapping() {
        let pm = Address::repeat_byte(0x83);
        let v4_id = [0x9cu8; 32];
        let v3_venue = Address::repeat_byte(0x71);
        // V4 slot0 word: sqrt = 2^100, tick = 100; liquidity word: 777.
        let sqrt_v4: U256 = U256::from(1u64) << 100;
        let mut slot_bytes = [0u8; 32];
        slot_bytes[12..].copy_from_slice(&sqrt_v4.to_be_bytes::<32>()[12..]);
        slot_bytes[9..12].copy_from_slice(&[0x00, 0x00, 0x64]);
        let base = provider::v4_pool_slot(v4_id);
        let hex_slot = |slot: U256| format!("0x{slot:064x}");
        let hex_word = |bytes: [u8; 32]| format!("0x{}", alloy_primitives::hex::encode(bytes));
        let mut liq_bytes = [0u8; 32];
        liq_bytes[24..].copy_from_slice(&777u64.to_be_bytes());
        let mut words = std::collections::HashMap::new();
        words.insert(hex_slot(base), hex_word(slot_bytes));
        words.insert(
            hex_slot(base.wrapping_add(U256::from(3u64))),
            hex_word(liq_bytes),
        );
        // V3 slot0 ABI tuple: sqrt word + tick word (tick 200 in low 3 bytes).
        let sqrt_v3: U256 = U256::from(1u64) << 110;
        let mut tick_word = [0u8; 32];
        tick_word[29..].copy_from_slice(&[0x00, 0x00, 0xc8]);
        // NOTE: pool_slot0 needs a 64-byte ABI response; emulate by
        // concatenating both words (result_bytes accepts byte data).
        let v3_response = {
            let mut both = vec![0u8; 64];
            both[..32].copy_from_slice(&sqrt_v3.to_be_bytes::<32>());
            both[32..].copy_from_slice(&tick_word);
            format!("0x{}", alloy_primitives::hex::encode(both))
        };
        let backend = RefetchBackend {
            storage_words: words,
            v3_sqrt: Box::leak(v3_response.into_boxed_str()),
            v3_liquidity: "0x309",
        };
        let reader = refetch_reader(backend);
        let v4_entry = catalog_entry(*b"v4", pm, v4_id);
        let v3_key: [u8; 32] = v3_venue.into_word().into();
        let v3_entry = catalog_entry(*b"v3", v3_venue, [0u8; 32]);
        let out = refetch_invalidated_prices(
            &reader,
            &[v4_entry, v3_entry],
            &[v4_id, v3_key, [0xabu8; 32]],
            10,
            pm,
            V4Reads::Extsload,
            Address::ZERO,
            1,
            &mut 0,
        );
        // V4 key refreshes through the manager mapping (block MAX).
        let v4_price = out.get(&v4_id).expect("v4 pool refetches");
        assert_eq!(v4_price.sqrt, sqrt_v4);
        assert_eq!(v4_price.liquidity, U256::from(777u64));
        assert_eq!(v4_price.block, u64::MAX);
        // V3 key refreshes through the pool contract as before.
        let v3_price = out.get(&v3_key).expect("v3 pool refetches");
        assert_eq!(v3_price.sqrt, sqrt_v3);
        assert_eq!(v3_price.block, u64::MAX);
        // Unknown keys and uninitialized pools are skipped.
        assert!(!out.contains_key(&[0xabu8; 32]));
        assert_eq!(out.len(), 2);
    }
}
