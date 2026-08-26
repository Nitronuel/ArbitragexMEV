//! AMM factory-event topic0 derivation and log decoding for catalog
//! enumeration (Uniswap V2 / V3 / V4 on Robinhood Chain).
//!
//! Topic0 values are derived from signature strings with `keccak256` at
//! runtime, never hard-coded from memory. The constants are pinned in tests
//! against independently verified primary sources.

use alloy_primitives::{Address, B256, I256, U256, keccak256};

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

#[must_use]
pub fn v3_swap_topic() -> B256 {
    keccak256("Swap(address,address,int256,int256,uint160,uint128,int24)")
}

#[must_use]
pub fn v4_swap_topic() -> B256 {
    keccak256("Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)")
}

/// The two RHC V3 liquidity-change topics (audit task 1.3).
///
/// RHC's V3 fork emits **non-canonical** liquidity events: neither hash
/// equals the canonical Uniswap V3 `Mint`/`Burn` topics despite the
/// verified contract ABI showing the canonical shapes (consistent with the
/// chain's non-standard pool init-code — see audit Part VI.0 3c). Values
/// are taken from live logs 2026-08-26 (`eth_getLogs` over catalog pools);
/// exact Mint-vs-Burn assignment is unconfirmed and irrelevant for cache
/// invalidation — either event means cached virtual reserves went stale.
#[must_use]
pub fn v3_mint_topic() -> B256 {
    B256::from([
        0x0c, 0x39, 0x6c, 0xd9, 0x89, 0xa3, 0x9f, 0x44, 0x59, 0xb5, 0xfa, 0x1a, 0xed, 0x6a, 0x9a,
        0x8d, 0xcd, 0xbc, 0x45, 0x90, 0x8a, 0xcf, 0xd6, 0x7e, 0x02, 0x8c, 0xd5, 0x68, 0xda, 0x98,
        0x98, 0x2c,
    ])
}

#[must_use]
pub fn v3_burn_topic() -> B256 {
    B256::from([
        0x70, 0x93, 0x53, 0x38, 0xe6, 0x97, 0x75, 0x45, 0x6a, 0x85, 0xdd, 0xef, 0x22, 0x6c, 0x39,
        0x5f, 0xb6, 0x68, 0xb6, 0x3f, 0xa0, 0x11, 0x5f, 0x5f, 0x20, 0x61, 0x0b, 0x38, 0x8e, 0x6c,
        0xa9, 0xc0,
    ])
}

/// V4 `ModifyLiquidity` — the V4 Mint/Burn equivalent (observed live).
#[must_use]
pub fn v4_modify_liquidity_topic() -> B256 {
    keccak256("ModifyLiquidity(bytes32,address,int24,int24,int256,uint256)")
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

/// The price-observable fields of a V3 `Swap` event. `amount0`/`amount1` are
/// the signed deltas of the swap; `sqrt_price_x96` is the pool price immediately
/// after the swap, and `tick` is the post-swap price tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3Swap {
    pub amount0: I256,
    pub amount1: I256,
    pub sqrt_price_x96: U256,
    pub liquidity: U256,
    pub tick: i32,
}

/// The price-observable fields of one V4 `Swap` event. Signed amounts, the
/// post-swap pool price in `sqrt_price_x96`, the post-swap `liquidity`, the
/// price `tick`, and the `fee` charged for the swap are all data words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V4Swap {
    pub amount0: I256,
    pub amount1: I256,
    pub sqrt_price_x96: U256,
    pub liquidity: U256,
    pub tick: i32,
    pub fee: u32,
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

/// Decodes the V3 `Swap` event from a pool address. `amount0` and `amount1`
/// are the first two data words; `sqrt_price_x96`, `liquidity`, and `tick` are
/// the trailing right-aligned words.
#[must_use]
pub fn decode_v3_swap(envelope: &RawLogEnvelope) -> Option<V3Swap> {
    let data = envelope.data.as_ref();
    if data.len() < 160 {
        return None;
    }
    Some(V3Swap {
        amount0: signed_word(&data[..32]),
        amount1: signed_word(&data[32..64]),
        sqrt_price_x96: uint160(&data[64..96]),
        liquidity: U256::from_be_slice(&data[96..128]),
        tick: int24(&data[128..160]),
    })
}

/// Decodes the V4 `Swap` event from the `PoolManager` across a pool `id`. The
/// data layout matches V3 with an extra `uint24` fee word.
#[must_use]
pub fn decode_v4_swap(envelope: &RawLogEnvelope) -> Option<V4Swap> {
    if envelope.topics.len() < 3 {
        return None;
    }
    let data = envelope.data.as_ref();
    if data.len() < 192 {
        return None;
    }
    Some(V4Swap {
        amount0: signed_word(&data[..32]),
        amount1: signed_word(&data[32..64]),
        sqrt_price_x96: uint160(&data[64..96]),
        liquidity: U256::from_be_slice(&data[96..128]),
        tick: int24(&data[128..160]),
        fee: uint24(&data[160..192]),
    })
}

/// The two's-complement `int256` value in a full 32-byte word.
fn signed_word(word: &[u8]) -> I256 {
    I256::from_raw(U256::from_be_slice(word))
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
        assert!(decode_v3_swap(&empty).is_none());
        assert!(decode_v4_swap(&empty).is_none());
    }

    #[test]
    fn decodes_v3_swap() {
        let mut data = vec![0u8; 160];
        // amount0 = -1_000_000_000_000_000_000 (two's complement in a full word)
        let negative = I256::from_raw(U256::from(1_000_000_000_000_000_000_u64)).wrapping_neg();
        data[..32].copy_from_slice(negative.to_be_bytes::<32>().as_slice());
        // amount1 = +5_000_000
        let amount1 = U256::from(5_000_000_u64);
        let amount1_bytes = amount1.to_be_bytes::<32>();
        data[32..64].copy_from_slice(&amount1_bytes);
        // sqrtPriceX96 = 0xDEAD (uint160, right-aligned: last two bytes)
        data[94] = 0xDE;
        data[95] = 0xAD;
        // liquidity = 123456 (uint128, full word)
        let liquidity = U256::from(123_456_u64).to_be_bytes::<32>();
        data[96..128].copy_from_slice(&liquidity);
        // tick = 200 (int24)
        data[159] = 0xC8;

        let log = envelope(vec![v3_swap_topic(), B256::default()], data);
        let parsed = decode_v3_swap(&log).unwrap();
        assert_eq!(
            parsed.amount0,
            I256::from_raw(U256::from(1_000_000_000_000_000_000_u64)).wrapping_neg()
        );
        assert_eq!(parsed.amount1, I256::from_raw(U256::from(5_000_000_u64)));
        assert_eq!(parsed.sqrt_price_x96, U256::from(0xDEAD_u64));
        assert_eq!(parsed.liquidity, U256::from(123_456_u64));
        assert_eq!(parsed.tick, 200);
    }

    #[test]
    fn topic0_values_match_canonical_deployments_and_live_chain() {
        // Audit B38: only two of five were pinned; a wrong topic0 presents
        // as "no opportunities found". Values verified against live RHC
        // logs 2026-08-26 (eth_getLogs on the catalog pool/PoolManager)
        // and cast sig-event/keccak.
        assert_eq!(
            hex_of(v2_pair_created_topic()),
            "0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9"
        );
        assert_eq!(
            hex_of(v3_pool_created_topic()),
            "783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118"
        );
        assert_eq!(
            hex_of(v3_swap_topic()),
            "c42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67"
        );
        assert_eq!(
            hex_of(v4_swap_topic()),
            "40e9cecb9f5f1f1c5b9c97dec2917b7ee92e57ba5563708daca94dd84ad7112f"
        );
        assert_eq!(
            hex_of(v4_initialize_topic()),
            "dd466e674ea557f56295e2d0218a125ea4b4f0f6f3307b95f85e6110838d6438"
        );
        // Liquidity-change events (task 1.3): observed live at 40x/14x per
        // 256-block window on the PoolManager.
        assert_eq!(
            hex_of(v3_mint_topic()),
            "0c396cd989a39f4459b5fa1aed6a9a8dcdbc45908acfd67e028cd568da98982c"
        );
        assert_eq!(
            hex_of(v3_burn_topic()),
            "70935338e69775456a85ddef226c395fb668b63fa0115f5f20610b388e6ca9c0"
        );
        assert_eq!(
            hex_of(v4_modify_liquidity_topic()),
            "f29efab2cc6f754bd298db4305708beb05a1278f40e21cbd10a972df4c57e91b"
        );
    }

    fn hex_of(t: B256) -> String {
        alloy_primitives::hex::encode(t)
    }
    #[test]
    fn decodes_v4_swap() {
        let mut data = vec![0u8; 192];
        // amount0 = -1 (two's complement: all ones)
        data[..32].copy_from_slice(B256::repeat_byte(0xFF).as_slice());
        // amount1 = +3_000_000
        let amount1 = U256::from(3_000_000_u64).to_be_bytes::<32>();
        data[32..64].copy_from_slice(&amount1);
        // sqrtPriceX96 = 0x11 (uint160, right-aligned)
        data[95] = 0x11;
        // liquidity = 7 (uint128)
        data[127] = 0x07;
        // tick = -3 (int24, sign-extended word: 0xFFFF...FFFD)
        data[156] = 0xFF;
        data[157] = 0xFF;
        data[158] = 0xFF;
        data[159] = 0xFD;
        // fee = 3000 (uint24)
        data[190] = 0x0B;
        data[191] = 0xB8;

        let log = envelope(
            vec![
                v4_swap_topic(),
                B256::with_last_byte(0x42),
                padded(Address::with_last_byte(0x01)),
            ],
            data,
        );
        let parsed = decode_v4_swap(&log).unwrap();
        assert_eq!(parsed.amount0, I256::from_raw(U256::MAX));
        assert_eq!(parsed.amount1, I256::from_raw(U256::from(3_000_000_u64)));
        assert_eq!(parsed.sqrt_price_x96, U256::from(0x11_u64));
        assert_eq!(parsed.liquidity, U256::from(7_u64));
        assert_eq!(parsed.tick, -3);
        assert_eq!(parsed.fee, 3000);
    }
}
