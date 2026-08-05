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
        U256::from_be_slice(&result[..32]),
        U256::from_be_slice(&result[32..64]),
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
        assert_eq!(data.as_ref()[4..16].iter().all(|b| *b == 0), true);
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
}
