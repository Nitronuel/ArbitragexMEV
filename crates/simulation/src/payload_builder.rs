use alloy_primitives::{Address, U256};

/// Exact calldata layout of the RHC router entry `0x4d819a2a`
/// `swap((uint8,address,address,address,uint24,int24,address,bytes,address,bytes32)[],address,uint256,uint256,uint256)`,
/// decoded and round-trip verified against live txs (2026-08-28):
/// tx `0x104ce1e5…` (1 elem), tx `0x67afe83e…` (3 elems), tx `0xdb736e1d…`.
///
/// Top level: `[arrayOffset=0xa0][recipient][amountIn][minOut][deadline][n][elemOffsets…][elements…]`.
/// Real txs set `recipient = 0x0` (output returns to the caller).
///
/// Element head = 10 words, then the dynamic `bytes` tail (length word +
/// payload; empty in every observed tx):
/// 0: `venueType` — **1 = V3 pool, 2 = V4 pool**
/// 1: `currency0` — swap input token; V4 native is `0x0`
/// 2: `currency1` — swap output token
/// 3: `pool` — V3: pool address; V4: zero
/// 4: `fee` — V3: actual fee (100, 3000, …); V4: `0x80_0000` dynamic sentinel
/// 5: `tickSpacing` — V3: actual (1, 60, …); V4: observed 8
/// 6: `hooks` — V3: zero; V4: hook address (e.g. `0x4e346895…`)
/// 7: `bytes` offset — always `0x140` (data follows the head)
/// 8: `poolManager` — V4: `0x8366a39CC670B4001A1121B8F6A443A643e40951`; V3: zero
/// 9: `poolKey` — zero in every observed tx
///
/// Element stride = 352 bytes (11 words) when `hook_data` is empty.
pub const V4_DYNAMIC_FEE_SENTINEL: u32 = 0x80_0000;
pub const RHC_POOL_MANAGER: Address = Address::new([
    0x83, 0x66, 0xa3, 0x9c, 0xc6, 0x70, 0xb4, 0x00, 0x1a, 0x11, 0x21, 0xb8, 0xf6, 0xa4, 0x43, 0xa6,
    0x43, 0xe4, 0x09, 0x51,
]);

/// Venue type for a V3 pool route element.
pub const VENUE_V3: u8 = 1;
/// Venue type for a V4 pool route element.
pub const VENUE_V4: u8 = 2;

/// One route element (single hop) of the router swap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteElement {
    pub venue_type: u8,
    pub currency0: Address,
    pub currency1: Address,
    pub pool: Address,
    pub fee: u32,
    pub tick_spacing: i32,
    pub hooks: Address,
    pub pool_manager: Address,
    pub pool_key: [u8; 32],
    pub hook_data: Vec<u8>,
}

impl RouteElement {
    /// A V3 hop through `pool` selling `currency0` for `currency1`.
    #[must_use]
    pub fn v3(
        currency0: Address,
        currency1: Address,
        pool: Address,
        fee: u32,
        tick_spacing: i32,
    ) -> Self {
        Self {
            venue_type: VENUE_V3,
            currency0,
            currency1,
            pool,
            fee,
            tick_spacing,
            hooks: Address::ZERO,
            pool_manager: Address::ZERO,
            pool_key: [0u8; 32],
            hook_data: Vec::new(),
        }
    }

    /// A V4 hop (pool derived from the key components by the PoolManager).
    #[must_use]
    pub fn v4(
        currency0: Address,
        currency1: Address,
        fee: u32,
        tick_spacing: i32,
        hooks: Address,
    ) -> Self {
        Self {
            venue_type: VENUE_V4,
            currency0,
            currency1,
            pool: Address::ZERO,
            fee,
            tick_spacing,
            hooks,
            pool_manager: RHC_POOL_MANAGER,
            pool_key: [0u8; 32],
            hook_data: Vec::new(),
        }
    }
}

fn word(out: &mut Vec<u8>, value: &[u8; 32]) {
    out.extend_from_slice(value);
}

fn addr_word(a: Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..32].copy_from_slice(a.as_slice());
    w
}

/// Encode the full router `swap` calldata.
///
/// Mirrors the live-tx layout exactly (see the module docs). `recipient` is
/// encoded as `0x0` — the value every observed router tx uses, which returns
/// the output to the caller.
///
/// # Errors
/// Returns an error when a V4 element omits the pool manager or the route is empty.
pub fn encode_swap_calldata(
    routes: &[RouteElement],
    amount_in: U256,
    min_out: U256,
    deadline: U256,
) -> Result<Vec<u8>, String> {
    if routes.is_empty() {
        return Err("route must contain at least one element".to_owned());
    }
    for r in routes {
        if r.venue_type == VENUE_V4 && r.pool_manager == Address::ZERO {
            return Err("V4 element requires the PoolManager address".to_owned());
        }
    }

    let mut cd = Vec::with_capacity(4 + 5 * 32 + (1 + routes.len()) * 32 + routes.len() * 352);
    cd.extend_from_slice(&[0x4d, 0x81, 0x9a, 0x2a]);

    // Static head: array offset (5 words in), recipient=0, amountIn, minOut, deadline.
    word(&mut cd, &U256::from(0xa0u32).to_be_bytes::<32>());
    word(&mut cd, &addr_word(Address::ZERO));
    word(&mut cd, &amount_in.to_be_bytes::<32>());
    word(&mut cd, &min_out.to_be_bytes::<32>());
    word(&mut cd, &deadline.to_be_bytes::<32>());

    // Array length + per-element offsets. Data begins after the offset words.
    word(&mut cd, &U256::from(routes.len()).to_be_bytes::<32>());
    let mut elem_sizes: Vec<usize> = Vec::with_capacity(routes.len());
    for r in routes {
        // 10 head words + bytes length word + padded payload.
        elem_sizes.push(352 + r.hook_data.len().next_multiple_of(32));
    }
    let mut offset = routes.len() * 32;
    for size in &elem_sizes {
        word(&mut cd, &U256::from(offset).to_be_bytes::<32>());
        offset += size;
    }

    // Element bodies.
    for r in routes {
        word(&mut cd, &U256::from(r.venue_type).to_be_bytes::<32>());
        word(&mut cd, &addr_word(r.currency0));
        word(&mut cd, &addr_word(r.currency1));
        word(&mut cd, &addr_word(r.pool));
        word(&mut cd, &U256::from(r.fee).to_be_bytes::<32>());
        word(
            &mut cd,
            &U256::from((r.tick_spacing & 0x00FF_FFFF).cast_unsigned()).to_be_bytes::<32>(),
        );
        word(&mut cd, &addr_word(r.hooks));
        word(&mut cd, &U256::from(0x140u32).to_be_bytes::<32>()); // bytes offset
        word(&mut cd, &addr_word(r.pool_manager));
        word(&mut cd, &r.pool_key);
        // Dynamic bytes tail.
        word(&mut cd, &U256::from(r.hook_data.len()).to_be_bytes::<32>());
        let padded = r.hook_data.len().next_multiple_of(32);
        cd.extend_from_slice(&r.hook_data);
        cd.resize(cd.len() + (padded - r.hook_data.len()), 0);
    }
    Ok(cd)
}

#[cfg(test)]
mod tests {
    use super::{RouteElement, V4_DYNAMIC_FEE_SENTINEL, encode_swap_calldata};
    use alloy_primitives::{Address, U256};

    fn a(hex: &str) -> Address {
        hex.parse().unwrap()
    }

    /// Round-trip against live tx `0x104ce1e5…7e` (1 element, native in via V4).
    #[test]
    fn round_trips_live_single_element_tx() {
        let expected = include_str!("../tests/fixtures/router_tx1.hex");
        let elements = [RouteElement::v4(
            Address::ZERO,
            a("0xccf14ec1f58b04baa52ce0c562899c26db7d1e18"),
            V4_DYNAMIC_FEE_SENTINEL,
            8,
            a("0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544"),
        )];
        let cd = encode_swap_calldata(
            &elements,
            U256::from(0x0047_0de4_df82_0000_u64),
            U256::from(0xb030_57aa_12b0_8c95_6886_u128),
            U256::from(1_788_075_969_u64),
        )
        .unwrap();
        assert_eq!(alloy_primitives::hex::encode(&cd), expected.trim());
    }

    /// Round-trip against live tx `0x67afe83e…5af` (3 elements: V3, V3, V4).
    #[test]
    fn round_trips_live_three_element_tx() {
        let expected = include_str!("../tests/fixtures/router_tx2.hex");
        let elements = [
            RouteElement::v3(
                a("0x0bd7d308f8e1639fab988df18a8011f41eacad73"),
                a("0x5fc5360d0400a0fd4f2af552add042d716f1d168"),
                a("0x52e65b17fb6e5ba00ed806f37afcd2daa50271ca"),
                100,
                1,
            ),
            RouteElement::v3(
                a("0x5fc5360d0400a0fd4f2af552add042d716f1d168"),
                a("0xc9a981fee1f9dec688bb123ccdecc63d0debfc4e"),
                a("0x7a6a053eccf1446a2633e05aa6d40d09381997ec"),
                3000,
                60,
            ),
            RouteElement::v4(
                a("0xc9a981fee1f9dec688bb123ccdecc63d0debfc4e"),
                a("0x42afa2124ca5a2b83898e46b2da9a190995b1e18"),
                V4_DYNAMIC_FEE_SENTINEL,
                8,
                a("0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544"),
            ),
        ];
        let cd = encode_swap_calldata(
            &elements,
            U256::from(20_000_000_000_000_000_u64),
            U256::from(0x092a_395a_ce83_3e33_17b4_u128),
            U256::from(1_788_075_969_u64),
        )
        .unwrap();
        assert_eq!(alloy_primitives::hex::encode(&cd), expected.trim());
    }

    #[test]
    fn rejects_empty_route_and_v4_without_pm() {
        assert!(encode_swap_calldata(&[], U256::ONE, U256::ZERO, U256::ONE).is_err());
        let bad = [RouteElement {
            venue_type: 2,
            ..RouteElement::v4(Address::ZERO, Address::ZERO, 0x80_0000, 8, Address::ZERO)
        }
        .clone()];
        let bad = [RouteElement {
            pool_manager: Address::ZERO,
            ..bad[0].clone()
        }];
        assert!(encode_swap_calldata(&bad, U256::ONE, U256::ZERO, U256::ONE).is_err());
    }
}
