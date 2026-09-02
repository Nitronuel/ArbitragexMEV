use std::collections::HashSet;
use std::io::Read;

use alloy_primitives::{Address, B256, U256};
use domain::{Chain, Fee, Profile};
use serde::Deserialize;
use thiserror::Error;

const MAX_POOLS: usize = 0; // 0 = unlimited (covers full ~1M universe on public global sweep)

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePool {
	pub chain_id: u64,
	pub address: Address,
	pub factory: Address,
	pub token0: Address,
	pub token1: Address,
	pub fee: Fee,
	pub profile: Profile,
	/// Uniswap V4 `PoolId` (keccak of the pool key) for singleton-based pools.
	/// Present when `profile` is `VolatileManaged`; a conventional address key
	/// otherwise identifies the pool.
	pub pool_id: Option<B256>,
	pub source: String,
	/// Total liquidity in USD (fixed-point scale: 1 USD = 1e18).
	/// None if not yet priced / not yet swept.
	pub liquidity_usd: Option<U256>,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("failed to decode manifest row: {0}")]
    Csv(#[from] csv::Error),
    #[error("manifest exceeds the pool cap (unlimited when MAX_POOLS=0)")]
    PoolCapExceeded,
    #[error("row {row} has unsupported chain ID {chain_id}")]
    InvalidChainId { row: usize, chain_id: u64 },
    #[error("row {row} has invalid {field} address")]
    InvalidAddress { row: usize, field: &'static str },
    #[error("row {row} contains a zero address in {field}")]
    ZeroAddress { row: usize, field: &'static str },
    #[error("row {row} uses the same address for token0 and token1")]
    EqualTokens { row: usize },
    #[error("row {row} has token0 > token1 (Uniswap canonical ordering violated)")]
    UnsortedTokens { row: usize },
    #[error("row {row} has unsupported fee {numerator}/{denominator}")]
    UnsupportedFee {
        row: usize,
        numerator: u32,
        denominator: u32,
    },
    #[error("row {row} is missing source metadata")]
    MissingSource { row: usize },
    #[error("row {row} has unsupported profile {profile:?}")]
    UnsupportedProfile { row: usize, profile: String },
    #[error("row {row} has an invalid pool_id")]
    InvalidPoolId { row: usize },
    #[error("row {row} is a v4 pool missing a pool_id")]
    MissingPoolId { row: usize },
    #[error("row {row} duplicates pool identity {identity}")]
    DuplicatePool { row: usize, identity: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestRow {
	chain_id: u64,
	pool_address: String,
	factory_address: String,
	token0: String,
	token1: String,
	fee_numerator: u32,
	fee_denominator: u32,
	#[serde(default)]
	profile: Option<String>,
	#[serde(default)]
	pool_id: Option<String>,
	source: String,
	#[serde(default)]
	liquidity_usd: Option<String>,
}

/// Parses and strictly validates a candidate-pool CSV manifest.
///
/// # Errors
///
/// Returns an error for malformed CSV, invalid or duplicate addresses, invalid
/// chain or fee data, missing source metadata, or a capped manifest when
/// `MAX_POOLS != 0` and the cap is exceeded.
pub fn parse_manifest(reader: impl Read) -> Result<Vec<CandidatePool>, ManifestError> {
    let mut pools = Vec::new();
    let mut identities: HashSet<B256> = HashSet::new();
    for (index, record) in csv::Reader::from_reader(reader).deserialize().enumerate() {
        let row_number = index + 2;
        if MAX_POOLS != 0 && pools.len() == MAX_POOLS {
            return Err(ManifestError::PoolCapExceeded);
        }
        let row: ManifestRow = record?;
        if Chain::from_id(row.chain_id).is_none() {
            return Err(ManifestError::InvalidChainId {
                row: row_number,
                chain_id: row.chain_id,
            });
        }
        let address = parse_address(&row.pool_address, row_number, "pool_address")?;
        let factory = parse_address(&row.factory_address, row_number, "factory_address")?;
        let source = row.source.trim().to_owned();
        if source.is_empty() {
            return Err(ManifestError::MissingSource { row: row_number });
        }
        let profile = match row.profile.as_deref() {
            None | Some("v2" | "constant_product" | "ConstantProduct") => Profile::ConstantProduct,
            Some("v3" | "concentrated" | "Concentrated") => Profile::Concentrated,
            Some("v4" | "volatile_managed" | "VolatileManaged") => Profile::VolatileManaged,
            Some("up" | "Up" | "UP") => Profile::Concentrated,
            Some(other) => {
                return Err(ManifestError::UnsupportedProfile {
                    row: row_number,
                    profile: other.to_owned(),
                });
            }
        };
        // V4 uses the native sentinel 0x000...000 on one side; allow zero only there.
        let allow_zero_token = profile == Profile::VolatileManaged;
        let token0 = parse_token_address(&row.token0, row_number, "token0", allow_zero_token)?;
        let token1 = parse_token_address(&row.token1, row_number, "token1", allow_zero_token)?;
        if token0 == token1 {
            return Err(ManifestError::EqualTokens { row: row_number });
        }
        let is_v4_dynamic_sentinel = profile == Profile::VolatileManaged
            && (row.fee_numerator == 0x80_0000 || row.fee_numerator == 0)
            && row.fee_denominator == 1_000_000;
        if !is_v4_dynamic_sentinel
            && (row.fee_numerator == 0
                || row.fee_denominator == 0
                || row.fee_numerator > row.fee_denominator)
        {
            return Err(ManifestError::UnsupportedFee {
                row: row_number,
                numerator: row.fee_numerator,
                denominator: row.fee_denominator,
            });
        }
        // The orientation of every downstream price/skew computation assumes
        // the Uniswap canonical ordering (`token0` = lower address, enforced
        // by V3 factories and the V4 PoolManager). Fail fast on catalogs that
        // violate it.
        if token0 > token1 {
            return Err(ManifestError::UnsortedTokens { row: row_number });
        }
        let pool_id = match (&row.pool_id, profile) {
            (Some(raw), Profile::VolatileManaged) => {
                let trimmed = raw.trim();
                let parsed = parse_pool_id(trimmed)
                    .ok_or(ManifestError::InvalidPoolId { row: row_number })?;
                if parsed.is_zero() {
                    return Err(ManifestError::InvalidPoolId { row: row_number });
                }
                Some(parsed)
            }
            (None, Profile::VolatileManaged) => {
                return Err(ManifestError::MissingPoolId { row: row_number });
            }
            (Some(_), _) => {
                return Err(ManifestError::InvalidPoolId { row: row_number });
            }
            (None, _) => None,
        };
        let identity = pool_id.unwrap_or_else(|| address.into_word());
        if !identities.insert(identity) {
            return Err(ManifestError::DuplicatePool {
                row: row_number,
                identity: format!("{identity}"),
            });
        }
        // Audit C1/C39: the CSV dialect is ambiguous (V2 catalogs store keep
        // rates, build-manifest output stores fee rates) — both were accepted
        // verbatim, and a `1/1` or nanoscopic row parsed silently. Require the
        // fraction to be plausible under at least one reading.
        // V4 dynamic sentinels (0 and 0x800000) bypass plausibility — their toll
        // is resolved via observed swap fee at quote time (effective_leg_toll).
        let fee = if is_v4_dynamic_sentinel {
            Fee {
                numerator: row.fee_numerator,
                denominator: row.fee_denominator,
            }
        } else {
            Fee::keep_rate(row.fee_numerator, row.fee_denominator)
                .or_else(|_| Fee::fee_rate(row.fee_numerator, row.fee_denominator))
                .map_err(|_| ManifestError::UnsupportedFee {
                    row: row_number,
                    numerator: row.fee_numerator,
                    denominator: row.fee_denominator,
                })?
        };
pools.push(CandidatePool {
			chain_id: row.chain_id,
			address,
			factory,
			token0,
			token1,
			fee,
			profile,
			pool_id,
			source,
			liquidity_usd: row.liquidity_usd
				.and_then(|s| s.parse::<U256>().ok()),
		});
    }
    Ok(pools)
}

/// Filters candidate pools by liquidity USD thresholds.
/// Keeps pools with `liquidity_usd >= min_liq` and `liquidity_usd <= max_liq`.
/// Pools with `liquidity_usd = None` are filtered out when a min threshold is set
/// (tradeoff: aggressive dust filter cuts 50k→5-10k active; set min=None to revert
///  to conservative where unknown liquidity passes). Recommended: min=$5k/max=$200k
///  + trade_cap 0.5% V2 / 1% V3V4 (VPS 6×/11Gi validated, 5k manifest ~600M RAM).
#[must_use]
pub fn filter_by_liquidity(
	pools: Vec<CandidatePool>,
	min_liq_usd: Option<U256>,
	max_liq_usd: Option<U256>,
) -> Vec<CandidatePool> {
	pools
		.into_iter()
		.filter(|p| {
			match p.liquidity_usd {
				Some(liq) => {
					if let Some(min) = min_liq_usd {
						if liq < min {
							return false;
						}
					}
					if let Some(max) = max_liq_usd {
						if liq > max {
							return false;
						}
					}
					true
				}
				None => min_liq_usd.is_none(), // None liquidity only passes if no min threshold
			}
		})
		.collect()
}

fn parse_pool_id(raw: &str) -> Option<B256> {
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = alloy_primitives::hex::decode(hex).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    Some(B256::from_slice(&bytes))
}

fn parse_address(value: &str, row: usize, field: &'static str) -> Result<Address, ManifestError> {
    let address = Address::parse_checksummed(value.trim(), None)
        .map_err(|_| ManifestError::InvalidAddress { row, field })?;
    if address.is_zero() {
        return Err(ManifestError::ZeroAddress { row, field });
    }
    Ok(address)
}

fn parse_token_address(
    value: &str,
    row: usize,
    field: &'static str,
    allow_zero: bool,
) -> Result<Address, ManifestError> {
    let address = Address::parse_checksummed(value.trim(), None)
        .map_err(|_| ManifestError::InvalidAddress { row, field })?;
    if address.is_zero() && !allow_zero {
        return Err(ManifestError::ZeroAddress { row, field });
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use std::fmt::Write;

    use alloy_primitives::{Address, U256};
    use domain::{Fee, Profile};

    use super::{filter_by_liquidity, ManifestError, parse_manifest, CandidatePool};

    const HEADER: &str = "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,source\n";

    fn row(pool: &str, token0: &str, token1: &str, source: &str) -> String {
        format!(
            "4663,{pool},0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6,{token0},{token1},997,1000,{source}\n"
        )
    }

    #[test]
    fn parses_valid_fixture() {
        let input = include_bytes!("../../../tests/fixtures/catalog/valid.csv");
        let pools = parse_manifest(Cursor::new(input)).unwrap();
        assert_eq!(pools.len(), 2);
        assert_eq!(pools[0].chain_id, 4663);
        assert_eq!(pools[0].fee.numerator, 997);
    }

    #[test]
    fn rejects_invalid_fixture() {
        let input = include_bytes!("../../../tests/fixtures/catalog/invalid.csv");
        assert!(parse_manifest(Cursor::new(input)).is_err());
    }

    #[test]
    fn rejects_duplicate_pool_addresses() {
        let pool = "0x0000000000000000000000000000000000000010";
        let token0 = "0x0000000000000000000000000000000000000001";
        let token1 = "0x0000000000000000000000000000000000000002";
        let input = format!(
            "{HEADER}{}{}",
            row(pool, token0, token1, "one"),
            row(pool, token0, token1, "two")
        );
        assert!(parse_manifest(input.as_bytes()).is_err());
    }

    #[test]
    fn rejects_equal_tokens_and_missing_source() {
        let token = "0x0000000000000000000000000000000000000001";
        let equal = format!(
            "{HEADER}{}",
            row(
                "0x0000000000000000000000000000000000000010",
                token,
                token,
                "source"
            )
        );
        assert!(parse_manifest(equal.as_bytes()).is_err());

        let missing = format!(
            "{HEADER}{}",
            row(
                "0x0000000000000000000000000000000000000010",
                token,
                "0x0000000000000000000000000000000000000002",
                ""
            )
        );
        assert!(parse_manifest(missing.as_bytes()).is_err());
    }

    #[test]
    fn defaults_absent_profile_to_constant_product() {
        let input = include_bytes!("../../../tests/fixtures/catalog/valid.csv");
        let pools = parse_manifest(Cursor::new(input)).unwrap();
        for pool in &pools {
            assert_eq!(pool.profile, domain::Profile::ConstantProduct);
        }
    }

    #[test]
    fn parses_explicit_profiles() {
        let mut input = String::from(
            "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n",
        );
        for (profile, pool, pool_id) in [
            ("v2", "0x0000000000000000000000000000000000000010", None),
            (
                "concentrated",
                "0x0000000000000000000000000000000000000011",
                None,
            ),
            (
                "v4",
                "0x0000000000000000000000000000000000000012",
                Some("0x1111111111111111111111111111111111111111111111111111111111111111"),
            ),
        ] {
            let id = pool_id.unwrap_or_default();
            writeln!(
                input,
                "4663,{pool},0x8bcEaA40B9AcdfAedF85AdF4FF01F5Ad6517937f,0x0000000000000000000000000000000000000001,0x0000000000000000000000000000000000000002,997,1000,{profile},{id},src"
            )
            .unwrap();
        }
        let pools = parse_manifest(input.as_bytes()).unwrap();
        assert_eq!(pools.len(), 3);
        assert_eq!(pools[0].profile, domain::Profile::ConstantProduct);
        assert_eq!(pools[1].profile, domain::Profile::Concentrated);
        assert_eq!(pools[2].profile, domain::Profile::VolatileManaged);
        assert!(pools[2].pool_id.is_some());
    }

    #[test]
    fn v4_requires_and_validates_pool_id() {
        let header = "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n";
        let base = "0x0000000000000000000000000000000000000010,0x8bcEaA40B9AcdfAedF85AdF4FF01F5Ad6517937f,0x0000000000000000000000000000000000000001,0x0000000000000000000000000000000000000002,997,1000,v4";
        // v4 without pool_id is rejected.
        let missing = format!("{header}4663,{base},,src\n");
        assert!(matches!(
            parse_manifest(missing.as_bytes()),
            Err(ManifestError::MissingPoolId { row: 2 })
        ));
        // Non-v4 rows cannot carry a pool_id.
        let non_v4 = format!(
            "{header}4663,0x0000000000000000000000000000000000000010,0x8bcEaA40B9AcdfAedF85AdF4FF01F5Ad6517937f,0x0000000000000000000000000000000000000001,0x0000000000000000000000000000000000000002,997,1000,v2,0x1111111111111111111111111111111111111111111111111111111111111111,src\n"
        );
        assert!(matches!(
            parse_manifest(non_v4.as_bytes()),
            Err(ManifestError::InvalidPoolId { .. })
        ));
        // Malformed pool_id hex is rejected.
        let malformed = format!("{header}4663,{base},0xzz,src\n");
        assert!(matches!(
            parse_manifest(malformed.as_bytes()),
            Err(ManifestError::InvalidPoolId { .. })
        ));
    }

    #[test]
    fn v4_pool_ids_must_be_unique() {
        let header = "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source\n";
        let id = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let row = |pool: &str, id: &str| {
            format!(
                "4663,{pool},0x8bcEaA40B9AcdfAedF85AdF4FF01F5Ad6517937f,0x0000000000000000000000000000000000000001,0x0000000000000000000000000000000000000002,997,1000,v4,{id},src\n"
            )
        };
        let dup = format!(
            "{header}{}{}",
            row("0x0000000000000000000000000000000000000010", id),
            row("0x0000000000000000000000000000000000000011", id)
        );
        assert!(matches!(
            parse_manifest(dup.as_bytes()),
            Err(ManifestError::DuplicatePool { .. })
        ));
    }

    #[test]
    fn rejects_unknown_profile() {
        let input = format!(
            "{HEADER}4663,0x0000000000000000000000000000000000000010,\
             0x8bcEaA40B9AcdfAedF85AdF4FF01F5Ad6517937f,\
             0x0000000000000000000000000000000000000001,\
             0x0000000000000000000000000000000000000002,997,1000,v5,src\n"
        );
        assert!(parse_manifest(input.as_bytes()).is_err());
    }

    #[test]
    fn rejects_more_than_pool_cap() {
        // Cap is now 0 = unlimited (public global sweep covers full ~1M). The
        // 5001-row manifest must now parse successfully.
        let mut input = String::from(HEADER);
        for index in 1..=5_001_u64 {
            let mut bytes = [0u8; 32];
            bytes[24..].copy_from_slice(&index.to_be_bytes());
            let pool = Address::from_slice(&bytes[12..32]).to_checksum(None);
            input.push_str(&row(
                &pool,
                "0x0000000000000000000000000000000000003001",
                "0x0000000000000000000000000000000000003002",
                "source",
            ));
        }
        let pools = parse_manifest(input.as_bytes()).unwrap();
        assert_eq!(pools.len(), 5_001);
    }

    #[test]
    fn cap_zero_means_unlimited() {
        assert_eq!(super::MAX_POOLS, 0);
    }

    #[test]
    fn rejects_wrong_chain_and_invalid_fee() {
        let valid = row(
            "0x0000000000000000000000000000000000000010",
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
            "source",
        );
        let wrong_chain = format!("{HEADER}{}", valid.replacen("4663", "1", 1));
        assert!(parse_manifest(wrong_chain.as_bytes()).is_err());

        let disabled_base = format!("{HEADER}{}", valid.replacen("4663", "8453", 1));
        assert!(parse_manifest(disabled_base.as_bytes()).is_err());

        let invalid_fee = format!("{HEADER}{}", valid.replace(",997,1000,", ",1001,1000,"));
        assert!(parse_manifest(invalid_fee.as_bytes()).is_err());
    }

    #[test]
    fn accepts_robinhood_chain_rows() {
        let input = format!(
            "{HEADER}4663,0x0000000000000000000000000000000000000010,\
             0x8bcEaA40B9AcdfAedF85AdF4FF01F5Ad6517937f,\
             0x0000000000000000000000000000000000000001,\
             0x0000000000000000000000000000000000000002,997,1000,rhc\n"
        );
        let pools = parse_manifest(input.as_bytes()).unwrap();
        assert_eq!(pools.len(), 1);
        assert_eq!(pools[0].chain_id, domain::ROBINHOOD_CHAIN_ID);
        assert_eq!(pools[0].chain_id, 4663);
    }

    #[test]
    fn filter_by_liquidity_thresholds() {
        use alloy_primitives::U256;
        use super::filter_by_liquidity;

        let pools = vec![
            CandidatePool {
                chain_id: 4663,
                address: Address::repeat_byte(1),
                factory: Address::repeat_byte(2),
                token0: Address::repeat_byte(3),
                token1: Address::repeat_byte(4),
                fee: domain::Fee::keep_rate(3000, 1000000).unwrap(),
                profile: domain::Profile::Concentrated,
                pool_id: None,
                source: "test".to_owned(),
                liquidity_usd: Some(U256::from(10000000000000000000000u128)), // 10k
            },
            CandidatePool {
                chain_id: 4663,
                address: Address::repeat_byte(5),
                factory: Address::repeat_byte(6),
                token0: Address::repeat_byte(7),
                token1: Address::repeat_byte(8),
                fee: domain::Fee::keep_rate(3000, 1000000).unwrap(),
                profile: domain::Profile::Concentrated,
                pool_id: None,
                source: "test".to_owned(),
                liquidity_usd: Some(U256::from(5000000000000000000000u128)), // 5k
            },
            CandidatePool {
                chain_id: 4663,
                address: Address::repeat_byte(9),
                factory: Address::repeat_byte(10),
                token0: Address::repeat_byte(11),
                token1: Address::repeat_byte(12),
                fee: domain::Fee::keep_rate(3000, 1000000).unwrap(),
                profile: domain::Profile::Concentrated,
                pool_id: None,
                source: "test".to_owned(),
                liquidity_usd: Some(U256::from(200000000000000000000000u128)), // 200k
            },
            CandidatePool {
                chain_id: 4663,
                address: Address::repeat_byte(13),
                factory: Address::repeat_byte(14),
                token0: Address::repeat_byte(15),
                token1: Address::repeat_byte(16),
                fee: domain::Fee::keep_rate(3000, 1000000).unwrap(),
                profile: domain::Profile::Concentrated,
                pool_id: None,
                source: "test".to_owned(),
                liquidity_usd: None, // no liquidity data
            },
        ];

        // Filter min=10k, max=100k
        let filtered = filter_by_liquidity(pools.clone(), Some(U256::from(10000000000000000000000u128)), Some(U256::from(100000000000000000000000u128)));
        assert_eq!(filtered.len(), 1); // only the 10k pool (5k too low, 200k too high, None is kept but 5k filtered)
        assert_eq!(filtered[0].liquidity_usd, Some(U256::from(10000000000000000000000u128)));

        // Filter min=10k only (no max)
        let filtered = filter_by_liquidity(pools.clone(), Some(U256::from(10000000000000000000000u128)), None);
        assert_eq!(filtered.len(), 2); // 10k and 200k (5k filtered, None kept)
        assert_eq!(filtered[0].liquidity_usd, Some(U256::from(10000000000000000000000u128)));

        // No filter
        let filtered = filter_by_liquidity(pools, None, None);
        assert_eq!(filtered.len(), 4); // all pools including None liquidity
    }
}
