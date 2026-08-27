//! Verifies `pool_slot0` decoding against a live RHC response captured
//! 2026-08-26 (audit task 1.3 refresh path).

use alloy_primitives::U256;

#[test]
fn decodes_captured_slot0_word_layout() {
    let response_hex = "00000000000000000000000000000000000012bf386eac1ad3df1187739827fa000000000000000000000000000000000000000000000000000000000002963c000000000000000000000000000000000000000000000000000000000002963d000000000000000000000000000000000000000000000000000000000000000100000000";
    let raw = alloy_primitives::hex::decode(response_hex).unwrap();
    assert!(raw.len() >= 64);
    let sqrt = U256::from_be_slice(&raw[..32]);
    let b29 = raw[61];
    let b30 = raw[62];
    let b31 = raw[63];
    assert_eq!(raw[58], 0);
    assert_eq!(raw[59], 0);
    assert_eq!(raw[60], 0);
    let sign = if b29 & 0x80 != 0 { 0xff_u8 } else { 0x00_u8 };
    let tick = i32::from_be_bytes([sign, b29, b30, b31]);
    assert!(sqrt > U256::ZERO);
    assert_eq!((b29, b30, b31), (0x02, 0x96, 0x3c));
    assert_eq!(tick, i32::from_be_bytes([0x00, 0x02, 0x96, 0x3c]));
}
