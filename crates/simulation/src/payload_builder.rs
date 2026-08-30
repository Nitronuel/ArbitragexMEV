use alloy_primitives::{Address, U256};

/// Encode a single route element struct for the V4 PoolManager `swap` call.
///
/// The struct has 10 fields matching the Openchain router ABI:
/// (uint8 venueType, address currency0, address currency1, address pool,
///  uint24 fee, int24 tickSpacing, address bytes hooks, address poolManager,
///  bytes32 poolKey)
///
/// Each field is encoded as a 32-byte ABI word. The PM address (poolManager)
/// is embedded inside each element as a runtime argument, not at the top level.
///
/// # Fields (index → type → encoding)
/// 0: uint8 venueType   → 1 byte value, padded to 32 bytes (LSB)
/// 1: address currency0 → via `into_word().0` → 32 bytes (ABI pattern from v4_data_words)
/// 2: address currency1 → same as currency0
/// 3: address pool      → same as currency0
/// 4: uint24 fee        → fee value padded to 32 bytes; dynamic-fee pools
///                           use sentinel `0x80_0000`
/// 5: int24 tickSpacing → signed 24-bit value, padded to 32 bytes
/// 6: address bytes hooks → via `into_word().0` → 32 bytes
/// 7: address poolManager → via `into_word().0` → 32 bytes
/// 8: bytes32 poolKey   → 32 bytes (raw [u8; 32])
///
/// # Encoding note
/// The `into_word()` method on `Address` returns a wrapper with a `.0` field
/// that is a `U256`. The `.0 .to_be_bytes::<32>()` pattern on a `U256` yields 32 bytes in
/// big-endian order, which is the ABI encoding used by the router.
/// For `[u8; 32]` values (like pool_key), no conversion is needed — just copy.
///
/// # Example (single-pool route, V3-style)
/// ```ignore
/// let elem = encode_route_element(
///     venue_type: 1,                           // V4 dynamic-fee pool
///     currency0: WETH,
///     currency1: USDG,
///     pool: 0x52e65b17...,
///     fee: 100,                                // 0.1% fee; use 0x80_0000 for dynamic fee
///     tick_spacing: 312,
///     hooks: Address::zero(),                  // no hooks → zero address
///     pool_manager: PM_ADDR,
///     pool_key: [0u8; 32],
/// );
/// ```
pub fn encode_route_element(
    venue_type: u8,
    currency0: Address,
    currency1: Address,
    pool: Address,
    fee: u32,
    tick_spacing: i32,
    hooks: Address,
    pool_manager: Address,
    pool_key: [u8; 32],
) -> [u8; 320] {
    let mut data = [0u8; 320];

    // Field 0: uint8 venueType → 1 byte value, padded to 32 bytes (LSB)
    data[0] = venue_type;

    // Field 1: currency0 via into_word().0 → U256 → 32 bytes
    let c0 = currency0.into_word().0;
    data[32..64].copy_from_slice(&c0);

    // Field 2: currency1 via into_word().0 → U256 → 32 bytes
    let c1 = currency1.into_word().0;
    data[64..96].copy_from_slice(&c1);

    // Field 3: pool via into_word().0 → U256 → 32 bytes
    let p = pool.into_word().0;
    data[96..128].copy_from_slice(&p);

    // Field 4: uint24 fee → 32 bytes; dynamic-fee sentinel `0x80_0000`
    let f = if fee == 0x80_0000 {
        U256::from(0x80_0000u32).to_be_bytes::<32>()
    } else {
        U256::from(fee).to_be_bytes::<32>()
    };
    data[128..160].copy_from_slice(&f);

    // Field 5: int24 tickSpacing → signed, padded to 32 bytes
    let ts = U256::from((tick_spacing & 0x00FF_FFFF).cast_unsigned()).to_be_bytes::<32>();
    data[160..192].copy_from_slice(&ts);

    // Field 6: hooks via into_word().0 → U256 → 32 bytes
    let h = hooks.into_word().0;
    data[192..224].copy_from_slice(&h);

    // Field 7: poolManager via into_word().0 → U256 → 32 bytes
    let pm = pool_manager.into_word().0;
    data[224..256].copy_from_slice(&pm);

    // Field 8: bytes32 poolKey → 32 bytes (raw copy, no conversion needed)
    data[256..288].copy_from_slice(&pool_key);

    data
}

/// Encode the full calldata for the V4 PoolManager `swap` function.
///
/// Constructs: `0x4d819a2a` + dynamic array of route structs + top-level args.
///
/// # Arguments
/// - `routes`: list of route elements, each encoding a pool/currency pair
/// - `recipient`: the address that receives the output
/// - `amount_in`: the input amount (wei), as `U256`
/// - `min_out`: the minimum output amount (wei), as `U256`; use 0 if unspecified
/// - `deadline`: Unix timestamp deadline for the transaction, as `U256`
///
/// # Returns
/// A `Vec<u8>` containing the full calldata bytes, ready to be used as the
/// `data` field of an EVM transaction calling the `PoolManager` at the target
/// router address.
///
/// # Encoding layout (total bytes = 4 + 32 + n*320 + 128)
/// ```text
/// [0..4]   : function selector 0x4d819a2a
/// [4..36]   : dynamic array length as uint256 (32 bytes), value = routes.len()
/// [36..356]: route structs, each 320 bytes (10 fields × 32 bytes)
/// [300..332]: recipient address (32 bytes, ABI padded via into_word().0 .to_be_bytes::<32>())
/// [332..364]: amountIn (uint256, 32 bytes)
/// [364..396]: amountOutMinimum (uint256, 32 bytes)
/// [396..428]: deadline (uint256, 32 bytes)
/// ```
pub fn encode_swap_calldata(
    routes: &[RouteElement],
    recipient: Address,
    amount_in: U256,
    min_out: U256,
    deadline: U256,
) -> Vec<u8> {
    let mut cd = Vec::with_capacity(4 + 32 + routes.len() * 320 + 128);

    // 1. Function selector (4 bytes)
    cd.extend_from_slice(&[0x4d, 0x81, 0x9a, 0x2a]);

    // 2. Dynamic array length as uint256 (32 bytes)
    let num_routes = routes.len() as u64;
    // Encode as 32-byte big-endian uint256: upper 24 bytes zero, lower 8 bytes = length
    let mut len_bytes = [0u8; 32];
    len_bytes[24..32].copy_from_slice(&num_routes.to_be_bytes());
    cd.extend_from_slice(&len_bytes);

    // 3. Route struct elements (each 320 bytes)
    for route in routes {
        let elem = encode_route_element(
            route.venue_type,
            route.currency0,
            route.currency1,
            route.pool,
            route.fee,
            route.tick_spacing,
            route.hooks,
            route.pool_manager,
            route.pool_key,
        );
        cd.extend_from_slice(&elem);
    }

    // 4. Top-level arguments after the array
    // address recipient (32 bytes, ABI padded via into_word().0 .to_be_bytes::<32>())
    let mut recv_words = [0u8; 32];
    let recv_encoded = recipient.into_word().0;
    recv_words.copy_from_slice(&recv_encoded);
    cd.extend_from_slice(&recv_words);

    // uint256 amountIn
    cd.extend_from_slice(&amount_in.to_be_bytes::<32>());

    // uint256 amountOutMinimum
    cd.extend_from_slice(&min_out.to_be_bytes::<32>());

    // uint256 deadline
    cd.extend_from_slice(&deadline.to_be_bytes::<32>());

    cd
}

/// A route element (single pool) for the V4 swap calldata.
#[derive(Clone, Debug)]
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
}
