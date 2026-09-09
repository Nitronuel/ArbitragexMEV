//! Minimal Uniswap V2 ABI helpers. Selectors are derived from signature strings
//! with `keccak256` at runtime, never hard-coded from memory.

use alloy_primitives::{Address, Bytes, U256, keccak256};

/// First four bytes of `keccak256(signature)`.
#[must_use]
pub fn selector(signature: &str) -> [u8; 4] {
    let digest = keccak256(signature.as_bytes());
    [digest[0], digest[1], digest[2], digest[3]]
}

/// Builds calldata for a no-argument call.
#[must_use]
pub fn calldata(signature: &str) -> Bytes {
    Bytes::copy_from_slice(&selector(signature))
}

/// Builds calldata for a two-`address` call (e.g. `getPair`).
#[must_use]
pub fn calldata_with_addresses(signature: &str, a: Address, b: Address) -> Bytes {
    let mut out = Vec::with_capacity(4 + 64);
    out.extend_from_slice(&selector(signature));
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(&a[..]);
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(&b[..]);
    Bytes::from(out)
}

/// Builds calldata for a single-`bytes32` call (`StateView` `getSlot0`,
/// `getLiquidity`: `fn(bytes32)`).
#[must_use]
pub fn calldata_with_bytes32(signature: &str, id: &[u8; 32]) -> Bytes {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&selector(signature));
    out.extend_from_slice(id);
    Bytes::from(out)
}

/// Decodes `StateView` `getSlot0` (4 words: `uint160 sqrtPriceX96`, `int24`
/// tick, `uint24` protocolFee, `uint24` lpFee) into
/// `(sqrt, tick, protocol_fee, lp_fee)`. Rejects short payloads, zero roots,
/// and non-canonical high bits (fail-closed on provider-controlled input).
#[must_use]
pub fn decode_slot0_view(result: &Bytes) -> Option<(U256, i32, u32, u32)> {
    if result.len() < 128 {
        return None;
    }
    let sqrt = U256::try_from_be_slice(&result[..32])?;
    if sqrt.is_zero() {
        return None;
    }
    // int24: low 3 bytes of word 1, sign-extended. ABI sign-extends
    // negative values (high bytes 0xFF), so accept all-0x00 or all-0xFF.
    let negative = result[61] & 0x80 != 0;
    let pad_ok = result[32..61]
        .iter()
        .all(|b| *b == if negative { 0xff } else { 0x00 });
    if !pad_ok {
        return None;
    }
    let sign = if negative { 0xff_u8 } else { 0x00_u8 };
    let tick = i32::from_be_bytes([sign, result[61], result[62], result[63]]);
    // uint24: low 3 bytes of words 2 and 3.
    if result[64..93].iter().any(|b| *b != 0) || result[96..125].iter().any(|b| *b != 0) {
        return None;
    }
    let protocol_fee = u32::from_be_bytes([0, result[93], result[94], result[95]]);
    let lp_fee = u32::from_be_bytes([0, result[125], result[126], result[127]]);
    Some((sqrt, tick, protocol_fee, lp_fee))
}

/// Decodes `StateView` `getLiquidity` (one `uint128` word). Rejects short
/// payloads, zero liquidity, and values wider than 128 bits.
#[must_use]
pub fn decode_liquidity_view(result: &Bytes) -> Option<U256> {
    if result.len() < 32 {
        return None;
    }
    if result[..16].iter().any(|b| *b != 0) {
        return None;
    }
    let liquidity = U256::try_from_be_slice(&result[result.len() - 32..])?;
    if liquidity.is_zero() {
        return None;
    }
    Some(liquidity)
}

/// Decodes the trailing 20 bytes of a return payload as an address.
#[must_use]
pub fn decode_address(result: &Bytes) -> Option<Address> {
    if result.len() < 20 {
        return None;
    }
    Some(Address::from_slice(&result[result.len() - 20..]))
}

/// Decodes the low byte of the first word as a `uint8`.
#[must_use]
pub fn decode_u8(result: &Bytes) -> Option<u8> {
    if result.len() < 32 {
        return None;
    }
    Some(result[31])
}

/// Decodes the first two words as reserve0 and reserve1.
#[must_use]
pub fn decode_reserves(result: &Bytes) -> Option<(U256, U256)> {
    if result.len() < 64 {
        return None;
    }
    Some((
        // Audit B7: slices are already bounded to 32 bytes each here, but
        // use the non-panicking constructor so a future slice change cannot
        // abort the process on provider-controlled input.
        U256::try_from_be_slice(&result[..32]).unwrap_or(U256::ZERO),
        U256::try_from_be_slice(&result[32..64]).unwrap_or(U256::ZERO),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_is_four_bytes() {
        assert_eq!(selector("mint(uint256)").len(), 4);
        assert_eq!(calldata("mint(uint256)").len(), 4);
    }

    #[test]
    fn get_pair_calldata_has_selector_and_padding() {
        let a = Address::with_last_byte(0xaa);
        let b = Address::with_last_byte(0xbb);
        let data = calldata_with_addresses("getPair(address,address)", a, b);
        assert_eq!(data.len(), 4 + 64);
        assert!(data.as_ref()[4..16].iter().all(|b| *b == 0));
        assert_eq!(&data.as_ref()[16..36], a.as_slice());
        assert_eq!(&data.as_ref()[36..48].iter().all(|byte| *byte == 0), &true);
        assert_eq!(&data.as_ref()[48..], b.as_slice());
    }

    #[test]
    fn decodes_uint8_and_address() {
        let mut payload = vec![0u8; 32];
        payload[31] = 6;
        assert_eq!(decode_u8(&Bytes::from(payload)), Some(6));
        let address = Address::with_last_byte(0x5c);
        let mut padded = vec![0u8; 12];
        padded.extend_from_slice(address.as_slice());
        assert_eq!(decode_address(&Bytes::from(padded)), Some(address));
    }

    #[test]
    fn decodes_reserves_words() {
        let mut padded = vec![0u8; 96];
        padded[31] = 1;
        padded[63] = 2;
        assert_eq!(
            decode_reserves(&Bytes::from(padded)),
            Some((U256::from(1), U256::from(2)))
        );
    }

    #[test]
    fn short_payloads_decode_to_none() {
        assert_eq!(decode_address(&Bytes::from(vec![0u8; 19])), None);
        assert_eq!(decode_u8(&Bytes::from(vec![0u8; 31])), None);
        assert_eq!(decode_reserves(&Bytes::from(vec![0u8; 63])), None);
    }

    #[test]
    fn stateview_calldata_is_selector_plus_pool_id() {
        let id = [0xabu8; 32];
        let data = calldata_with_bytes32("getSlot0(bytes32)", &id);
        assert_eq!(data.len(), 4 + 32);
        assert_eq!(&data.as_ref()[4..], &id);
        // Selectors derive from signatures, never memory.
        assert_eq!(
            &data.as_ref()[..4],
            &selector("getSlot0(bytes32)"),
            "selector must equal keccak256(signature)[..4]"
        );
    }

    #[test]
    fn decodes_stateview_slot0_and_liquidity() {
        // getSlot0: sqrt=2^96 (price 1.0), tick=60, protocolFee=0, lpFee=3000.
        let mut payload = vec![0u8; 128];
        let sqrt: U256 = U256::from(1u64) << 96;
        payload[..32].copy_from_slice(&sqrt.to_be_bytes::<32>());
        payload[61] = 0x00;
        payload[62] = 0x00;
        payload[63] = 60;
        payload[95] = 0x00;
        payload[126] = 0x0b;
        payload[127] = 0xb8; // 3000
        assert_eq!(
            decode_slot0_view(&Bytes::from(payload)),
            Some((sqrt, 60, 0, 3000))
        );
        // Negative tick (-60): ABI sign-extends int24, so the word's
        // high bytes are 0xFF, not 0x00 (live RHC pools hit this).
        let mut neg = vec![0xffu8; 128];
        neg[..32].copy_from_slice(&sqrt.to_be_bytes::<32>());
        neg[61] = 0xff;
        neg[62] = 0xff;
        neg[63] = 0xc4; // -60 low byte
        // uint24 words stay zero-padded even for negative ticks.
        neg[64..96].copy_from_slice(&[0u8; 32]);
        neg[96..128].copy_from_slice(&[0u8; 32]);
        assert_eq!(
            decode_slot0_view(&Bytes::from(neg)).map(|(_, t, _, _)| t),
            Some(-60)
        );
        // Zero root, short payload, garbage high bits all fail closed.
        assert_eq!(decode_slot0_view(&Bytes::from(vec![0u8; 128])), None);
        assert_eq!(decode_slot0_view(&Bytes::from(vec![0u8; 127])), None);
        let mut bad = vec![0u8; 128];
        bad[..32].copy_from_slice(&sqrt.to_be_bytes::<32>());
        bad[40] = 0x01; // non-canonical tick high bit
        assert_eq!(decode_slot0_view(&Bytes::from(bad)), None);
        // getLiquidity: uint128 word.
        let mut liq = vec![0u8; 32];
        liq[24..].copy_from_slice(&12345u64.to_be_bytes());
        assert_eq!(
            decode_liquidity_view(&Bytes::from(liq)),
            Some(U256::from(12345u64))
        );
        assert_eq!(decode_liquidity_view(&Bytes::from(vec![0u8; 32])), None);
        assert_eq!(decode_liquidity_view(&Bytes::from(vec![0u8; 31])), None);
    }
}
