use std::collections::HashSet;
use std::io::Read;

use alloy_primitives::Address;
use domain::{Chain, Fee};
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
    #[error("row {row} has unsupported fee {numerator}/{denominator}")]
    UnsupportedFee {
        row: usize,
        numerator: u32,
        denominator: u32,
    },
    #[error("row {row} is missing source metadata")]
    MissingSource { row: usize },
    #[error("row {row} duplicates pool address {address}")]
    DuplicatePool { row: usize, address: Address },
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
    let mut addresses = HashSet::new();
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
        let source = row.source.trim().to_owned();
        if source.is_empty() {
            return Err(ManifestError::MissingSource { row: row_number });
        }
        if !addresses.insert(address) {
            return Err(ManifestError::DuplicatePool {
                row: row_number,
                address,
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
            source,
        });
    }
    Ok(pools)
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

    use super::parse_manifest;

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
