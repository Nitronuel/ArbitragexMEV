use std::collections::HashSet;
use std::io::Read;

use alloy_primitives::{Address, B256};
use domain::{Chain, Fee, Profile};
use serde::Deserialize;
use thiserror::Error;

const MAX_POOLS: usize = 2_000;

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
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("failed to decode manifest row: {0}")]
    Csv(#[from] csv::Error),
    #[error("manifest exceeds the {MAX_POOLS}-pool cap")]
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
}

/// Parses and strictly validates a bounded candidate-pool CSV manifest.
///
/// # Errors
///
/// Returns an error for malformed CSV, invalid or duplicate addresses, invalid
/// chain or fee data, missing source metadata, or a manifest over 2,000 pools.
pub fn parse_manifest(reader: impl Read) -> Result<Vec<CandidatePool>, ManifestError> {
    let mut pools = Vec::new();
    let mut identities: HashSet<B256> = HashSet::new();
    for (index, record) in csv::Reader::from_reader(reader).deserialize().enumerate() {
        let row_number = index + 2;
        if pools.len() == MAX_POOLS {
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
        let token0 = parse_address(&row.token0, row_number, "token0")?;
        let token1 = parse_address(&row.token1, row_number, "token1")?;
        if token0 == token1 {
            return Err(ManifestError::EqualTokens { row: row_number });
        }
        if row.fee_numerator == 0
            || row.fee_denominator == 0
            || row.fee_numerator > row.fee_denominator
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
        let source = row.source.trim().to_owned();
        if source.is_empty() {
            return Err(ManifestError::MissingSource { row: row_number });
        }
        let profile = match row.profile.as_deref() {
            None | Some("v2" | "constant_product" | "ConstantProduct") => Profile::ConstantProduct,
            Some("v3" | "concentrated" | "Concentrated") => Profile::Concentrated,
            Some("v4" | "volatile_managed" | "VolatileManaged") => Profile::VolatileManaged,
            Some(other) => {
                return Err(ManifestError::UnsupportedProfile {
                    row: row_number,
                    profile: other.to_owned(),
                });
            }
        };
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
        pools.push(CandidatePool {
            chain_id: row.chain_id,
            address,
            factory,
            token0,
            token1,
            fee: Fee {
                numerator: row.fee_numerator,
                denominator: row.fee_denominator,
            },
            profile,
            pool_id,
            source,
        });
    }
    Ok(pools)
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use std::fmt::Write;

    use super::{ManifestError, parse_manifest};

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
        let mut input = String::from(HEADER);
        for index in 1..=2_001_u64 {
            let pool = format!("0x{index:040x}");
            input.push_str(&row(
                &pool,
                "0x0000000000000000000000000000000000003001",
                "0x0000000000000000000000000000000000003002",
                "source",
            ));
        }
        assert!(parse_manifest(input.as_bytes()).is_err());
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
}
