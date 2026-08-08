use std::collections::{HashMap, HashSet};
use std::path::Path;

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
        let venue = record
            .get(1)
            .ok_or_else(|| "row lacks pool_address".to_owned())?
            .parse::<Address>()
            .map_err(|_| "bad pool_address".to_owned())?;
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
            },
        );
    }
    Ok(out)
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
/// Maximum number of pool addresses per `eth_getLogs` filter request. Some
/// providers limit the address-OR list; chunking keeps filters portable.
const MAX_ADDRESS_CHUNK: usize = 1_000;

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
pub fn sweep_swap_prices<B, S>(
    reader: &ChainReader<B, S>,
    profile: [u8; 2],
    pool_manager: Address,
    keys: &[PoolEntry],
    from: u64,
    to: u64,
    window: u64,
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
            let (key, sqrt): (Option<[u8; 32]>, Option<U256>) = if profile == *b"v4" {
                if envelope.topics.len() < 2 {
                    (None, None)
                } else {
                    let id = envelope.topics[1].0;
                    if keep_ids.is_some_and(|m| m.contains(&id)) {
                        (
                            Some(id),
                            decode_v4_swap(&envelope).map(|s| s.sqrt_price_x96),
                        )
                    } else {
                        (None, None)
                    }
                }
            } else {
                let key = envelope.address.into_word().into();
                (
                    Some(key),
                    decode_v3_swap(&envelope).map(|s| s.sqrt_price_x96),
                )
            };
            if let (Some(key), Some(sqrt)) = (key, sqrt) {
                let entry = latest.entry(key).or_insert(PoolPrice { sqrt, block: 0 });
                if envelope.block_number >= entry.block {
                    entry.sqrt = sqrt;
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

/// Combines the latest per-pool prices on both venues with the catalog pair
/// overlap and computes gap-vs-toll per cross-venue pair. A pair is priced by
/// averaging the `sqrtPriceX96`-derived prices across all its pools on each
/// venue; the toll is the sum of the minimum `leg_toll` per venue for that
/// pair.
#[must_use]
#[allow(clippy::cast_precision_loss, clippy::type_complexity)]
pub fn gap_distribution(
    a: &[PoolEntry],
    b: &[PoolEntry],
    prices_a: &HashMap<[u8; 32], PoolPrice>,
    prices_b: &HashMap<[u8; 32], PoolPrice>,
) -> GapSummary {
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

    let mut observations = Vec::new();
    for (_, (pa, ca, ta, pb, cb, tb)) in per_pair {
        // `f64::MAX` marks an unobservable toll (only dynamic/zero-fee v4
        // pools on that venue for the pair).
        if ca == 0 || cb == 0 || !ta.is_finite() || !tb.is_finite() {
            continue;
        }
        let avg_a = pa / ca as f64;
        let avg_b = pb / cb as f64;
        let skew = (avg_b / avg_a.max(1e-30)).max(1e-30).log2().abs();
        observations.push(GapObservation {
            log2_skew: skew,
            round_trip_toll: ta + tb,
        });
    }

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
                sqrt: U256::from(2u64.pow(48) << 1),
                block: 1,
            },
        );
        let mut pb = HashMap::new();
        pb.insert(
            key4,
            PoolPrice {
                sqrt: U256::from(2u64.pow(48) << 2),
                block: 1,
            },
        );
        let summary = gap_distribution(&a_entries, &b_entries, &pa, &pb);
        assert_eq!(summary.observed_pairs, 1);
        assert!(summary.above_toll >= 1);
        assert!(summary.above_1pct >= 1);
        assert!((summary.median_log2_skew - 2.0).abs() < 1e-9);
        assert!((summary.median_toll - 0.0055).abs() < 1e-9);
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
                block: 1,
            },
        );
        let summary = gap_distribution(&a_entries, &b_entries, &pa, &pb);
        assert_eq!(summary.observed_pairs, 1);
        assert!(summary.median_log2_skew < 1e-9);
    }
}
