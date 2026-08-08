use std::collections::HashMap;
use std::path::Path;

use alloy_primitives::Address;

/// Uniswap V4 marks a `PoolKey.fee` as dynamic (fee set by the hook, not the
/// encoded scalar) when the high bit is set; a fee of `0` is likewise not a
/// literal zero-fee pool. Encoding either as a strategy fee corrupts
/// round-trip toll accounting, so the measurement drops such pools.
pub const V4_DYNAMIC_FEE_FLAG: u32 = 0x0080_0000;

/// RHC encodes the wrapped native token in v2/v3 pool addresses with its real
/// contract address, while v4 `PoolKey`s use the `0x0..0` sentinel for the
/// native currency. Cross-venue matching must normalize the sentinel to the
/// native contract.
pub const RHC_NATIVE: Address =
    alloy_primitives::address!("0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73");

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

/// Normalizes one token for cross-venue matching: the v4 null sentinel maps
/// onto the RHC wrapped-native contract.
#[must_use]
pub fn normalize_currency(token: Address) -> Address {
    if token.is_zero() { RHC_NATIVE } else { token }
}

/// The skew-detectable toll of a round trip through one pool leg, derived from
/// its encoded fee. Returns `None` for V4 rows whose fee is a dynamic sentinel
/// or an "uninitialized" zero, where the quoted scalar is not the charged fee.
#[must_use]
pub fn leg_toll(fee: u32, profile: [u8; 2]) -> Option<f64> {
    if profile == *b"v4" && (fee == 0 || fee & V4_DYNAMIC_FEE_FLAG != 0) {
        return None;
    }
    Some(f64::from(fee) / 1_000_000.0)
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

fn parse_b256(s: &str) -> Result<[u8; 32], String> {
    let v: alloy_primitives::B256 = s
        .trim_start_matches("0x")
        .parse()
        .map_err(|_| format!("bad b256 {s:?}"))?;
    Ok(v.0)
}

/// A closed cross-venue opportunity counts: how many distinct token pairs are
/// priced on both venues, how many 2-hop and 3-hop cross-DEX cycles exist on
/// those pairs, and how many legs can clear a round-trip toll.
#[derive(Debug, Clone, Copy, Default)]
pub struct CrossMeasure {
    /// Distinct token pairs present on both venues (each a 2-hop cycle
    /// candidate: route one direction on a, the same pair back on the other).
    pub cross_pairs: usize,
    /// How many cross pairs sit on at least one venue where the quoted fee
    /// admits a finite toll (`leg_toll` is `Some`).
    pub toll_free_cross_pairs: usize,
    /// 3-hop cycles: three distinct token pairs `(a,b),(b,c),(c,a)` each
    /// priced on both venues, counted as undirected triangles.
    pub three_hop_cycles: usize,
    /// Number of distinct tokens participating in any cross pair.
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
    // (token0, token1) -> venue bitmask (bit0 = a, bit1 = b) + whether either
    // venue carries a toll-free quoted fee.
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
    // Undirected triangles among cross pairs: for each token, its cross-pair
    // neighbors; a (u,v) pair appears once by adjacency.
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
    // Orient excludes using a deterministic global order on token bytes to
    // count each triangle once; per edge we iterate the smaller adjacency list
    // (bounded by min(deg(u), deg(v))), so a native-star hub cannot drive an
    // O(deg^2) inner loop regardless of hash iteration order.
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
    fn pair_key_orders_by_normalized_address() {
        let native = RHC_NATIVE;
        let other: Address = "0x2000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let (x, y) = pair_key(native, other);
        // RHC_NATIVE starts 0x0B…, other starts 0x20…, so native sorts first.
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
        // v3: pairs (A,B),(B,C),(C,A); v4: same three pairs. All fee set.
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
}
