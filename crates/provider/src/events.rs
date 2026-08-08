//! AMM factory-event topic0 derivation and log decoding for catalog
//! enumeration (Uniswap V2 / V3 / V4 on Robinhood Chain).
//!
//! Topic0 values are derived from signature strings with `keccak256` at
//! runtime, never hard-coded from memory. The constants are pinned in tests
//! against independently verified primary sources.

use alloy_primitives::{Address, B256, U256, keccak256};

use crate::ws::RawLogEnvelope;

#[must_use]
pub fn v2_pair_created_topic() -> B256 {
    keccak256("PairCreated(address,address,address,uint256)")
}

#[must_use]
pub fn v3_pool_created_topic() -> B256 {
    keccak256("PoolCreated(address,address,uint24,int24,address)")
}

#[must_use]
pub fn v4_initialize_topic() -> B256 {
    keccak256("Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2PairCreated {
    pub token0: Address,
    pub token1: Address,
    pub pair: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3PoolCreated {
    pub token0: Address,
    pub token1: Address,
    pub fee: u32,
    pub pool: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V4PoolInitialize {
    pub id: B256,
    pub currency0: Address,
    pub currency1: Address,
    pub fee: u32,
    pub tick_spacing: i32,
    pub hooks: Address,
    pub sqrt_price_x96: U256,
    pub tick: i32,
}

/// Decodes a V2 `PairCreated` log. The indexed `token0`/`token1` are the two
/// topics after the signature; the pair address is the right-aligned first
/// data word.
#[must_use]
pub fn decode_v2_pair_created(envelope: &RawLogEnvelope) -> Option<V2PairCreated> {
    if envelope.topics.len() < 3 {
        return None;
    }
    let data = envelope.data.as_ref();
    if data.len() < 32 {
        return None;
    }
    Some(V2PairCreated {
        token0: word_address(&envelope.topics[1]),
        token1: word_address(&envelope.topics[2]),
        pair: right_aligned_address(&data[..32]),
    })
}

/// Decodes a V3 `PoolCreated` event. `token0`/`token1`/`fee` are the three
/// topics after the signature; the pool address is right-aligned in the second
/// data word.
#[must_use]
pub fn decode_v3_pool_created(envelope: &RawLogEnvelope) -> Option<V3PoolCreated> {
    if envelope.topics.len() < 4 {
        return None;
    }
    let data = envelope.data.as_ref();
    if data.len() < 64 {
        return None;
    }
    let fee = uint24(&envelope.topics[3][..]);
    Some(V3PoolCreated {
        token0: word_address(&envelope.topics[1]),
        token1: word_address(&envelope.topics[2]),
        fee,
        pool: right_aligned_address(&data[32..64]),
    })
}

/// Decodes the V4 `PoolManager` `Initialize` event. The pool `id`, `currency0`,
/// and `currency1` are the three topics after the signature; the fee, tick
/// spacing, hooks, pool price, and price tick are right-aligned in the data
/// words.
#[must_use]
pub fn decode_v4_initialize(envelope: &RawLogEnvelope) -> Option<V4PoolInitialize> {
    if envelope.topics.len() < 4 {
        return None;
    }
    let data = envelope.data.as_ref();
    if data.len() < 160 {
        return None;
    }
    Some(V4PoolInitialize {
        id: envelope.topics[1],
        currency0: word_address(&envelope.topics[2]),
        currency1: word_address(&envelope.topics[3]),
        fee: uint24(&data[..32]),
        tick_spacing: int24(&data[32..64]),
        hooks: right_aligned_address(&data[64..96]),
        sqrt_price_x96: uint160(&data[96..128]),
        tick: int24(&data[128..160]),
    })
}

/// The address occupying the final 20 bytes of a 32-byte word.
fn word_address(word: &impl AsRef<[u8]>) -> Address {
    let bytes = word.as_ref();
    right_aligned_address(bytes)
}

fn right_aligned_address(word: &[u8]) -> Address {
    Address::from_slice(&word[word.len() - 20..])
}

/// The `uint24` value packed in the trailing three bytes of a 32-byte word.
fn uint24(word: &[u8]) -> u32 {
    u32::from_be_bytes([0, word[29], word[30], word[31]])
}

/// The `int24` value packed in the trailing three bytes of a 32-byte word,
/// sign-extended to `i32`. ABI packs `int24` into the full 32-byte word with
/// sign extension, so the fourth trailing byte carries the sign bits.
fn int24(word: &[u8]) -> i32 {
    i32::from_be_bytes([word[28], word[29], word[30], word[31]])
}

/// The `uint160` value packed in the trailing 20 bytes of a 32-byte word.
fn uint160(word: &[u8]) -> U256 {
    U256::from_be_slice(&word[word.len() - 20..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(topics: Vec<B256>, data: Vec<u8>) -> RawLogEnvelope {
        RawLogEnvelope {
            address: Address::default(),
            topics,
            data: data.into(),
            block_number: 1,
            transaction_index: 0,
            log_index: 0,
            removed: false,
        }
    }

    fn padded(addr: Address) -> B256 {
        let mut word = [0u8; 32];
        word[12..32].copy_from_slice(addr.as_slice());
        B256::from(word)
    }

    #[test]
    fn topic0_pinned_to_verified_primary_source() {
        let v3 = format!("{}", v3_pool_created_topic());
        assert_eq!(
            v3.as_str(),
            "0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118"
        );
        let v2 = format!("{}", v2_pair_created_topic());
        assert_eq!(
            v2.as_str(),
            "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9"
        );
    }

    #[test]
    fn topic0_signatures_are_distinct() {
        assert_ne!(v2_pair_created_topic(), v3_pool_created_topic());
        assert_ne!(v3_pool_created_topic(), v4_initialize_topic());
    }

    #[test]
    fn decodes_v2_pair_created() {
        let token0 = padded(Address::with_last_byte(0xaa));
        let token1 = padded(Address::with_last_byte(0xbb));
        let pair = Address::with_last_byte(0xcc);
        let mut data = vec![0u8; 32];
        data[12..32].copy_from_slice(pair.as_slice());
        let log = envelope(vec![v2_pair_created_topic(), token0, token1], data);
        let parsed = decode_v2_pair_created(&log).unwrap();
        assert_eq!(parsed.token0, Address::with_last_byte(0xaa));
        assert_eq!(parsed.token1, Address::with_last_byte(0xbb));
        assert_eq!(parsed.pair, pair);
    }

    #[test]
    fn decodes_v3_pool_created() {
        let token0 = padded(Address::with_last_byte(0xaa));
        let token1 = padded(Address::with_last_byte(0xbb));
        let fee_word: [u8; 32] = {
            let mut word = [0u8; 32];
            word[30] = 0x13;
            word[31] = 0x88; // 0x1388 = 5000
            word
        };
        let pool = Address::with_last_byte(0xcc);
        let mut data = vec![0u8; 64];
        data[44..64].copy_from_slice(pool.as_slice());
        let log = envelope(
            vec![
                v3_pool_created_topic(),
                token0,
                token1,
                B256::from(fee_word),
            ],
            data,
        );
        let parsed = decode_v3_pool_created(&log).unwrap();
        assert_eq!(parsed.token0, Address::with_last_byte(0xaa));
        assert_eq!(parsed.token1, Address::with_last_byte(0xbb));
        assert_eq!(parsed.fee, 5000);
        assert_eq!(parsed.pool, pool);
    }

    #[test]
    fn decodes_v4_initialize() {
        let id = B256::with_last_byte(0x11);
        let currency0 = padded(Address::with_last_byte(0xaa));
        let currency1 = padded(Address::with_last_byte(0xbb));
        let hooks = Address::with_last_byte(0xcc);

        let mut data = vec![0u8; 160];
        data[31] = 0x64; // fee 100 (0.01%)
        // tickSpacing -1: full 32-byte word sign-extended
        data[60] = 0xFF;
        data[61] = 0xFF;
        data[62] = 0xFF;
        data[63] = 0xFF;
        // sqrtPriceX96 = 0xDE (uint160, right-aligned in word 96..128)
        data[127] = 0xDE;
        data[76..96].copy_from_slice(hooks.as_slice());
        // tick = 500 (int24)
        data[158] = 0x01;
        data[159] = 0xF4;

        let log = envelope(vec![v4_initialize_topic(), id, currency0, currency1], data);
        let parsed = decode_v4_initialize(&log).unwrap();
        assert_eq!(parsed.id, id);
        assert_eq!(parsed.currency0, Address::with_last_byte(0xaa));
        assert_eq!(parsed.currency1, Address::with_last_byte(0xbb));
        assert_eq!(parsed.fee, 100);
        assert_eq!(parsed.tick_spacing, -1);
        assert_eq!(parsed.hooks, hooks);
        assert_eq!(parsed.sqrt_price_x96, U256::from(0xDE));
        assert_eq!(parsed.tick, 500);
    }

    #[test]
    fn decodes_are_length_safe() {
        let empty = envelope(vec![], Vec::new());
        assert!(decode_v2_pair_created(&empty).is_none());
        assert!(decode_v3_pool_created(&empty).is_none());
        assert!(decode_v4_initialize(&empty).is_none());
    }
}
