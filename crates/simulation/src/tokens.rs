//! Minimal fixture ERC-20 bytecode assembled directly (no compiler, no
//! deploy). Four variants exercise exactly the behaviors the honeypot filter
//! must detect:
//!
//! - [`TokenKind::Standard`]: `transferFrom(from, to, amount)` subtracts
//!   `amount` from `from` and credits `to`.
//! - [`TokenKind::FeeOnTransfer`]: `amount` is pulled from `from` but only
//!   `amount * (1 - fee)` reaches `to` (the fee is burned) — the net-output
//!   basis of the quote is wrong and revm sees the shortfall.
//! - [`TokenKind::RevertOnTransfer`]: transfers always `REVERT`.
//! - [`TokenKind::Drain`]: `to` is credited `amount` then immediately
//!   skimmed `drain_amount` (credited to a fixed siphon address) — the
//!   executor's net check catches the silent outflow.
//!
//! Both `transferFrom(from, to, amount)` and `transfer(to, amount)` (the
//! caller debits itself) exercise the same behavior halves — the V3
//! settlement callback pays pools via plain `transfer`, so the honeypot
//! screens must see fee-on-transfer, revert, and drain semantics on that
//! path too.
//!
//! ## Storage layout
//!
//! `balanceOf(holder)` lives at `storage[holder]` where `holder` is the raw
//! 20-byte address as a right-aligned storage word — a fixture layout, not
//! canonical ERC-20 — so both `CacheDB` seeding ([`crate::db::balance_slot`])
//! and `SLOAD`/`SSTORE` in the assembled contract agree without any keccak
//! indirection.
//!
//! ## Stack conventions (revm 42)
//!
//! Binary stack ops pop the top of stack as `op1` and the second element as
//! `op2`, write the result back into `op2`: `mstore`/`sstore`/`return` pop the
//! *index/offset* (and `len`) from the top, `jumpi` pops the *destination*
//! from the top, and `shr`/`shl` take the *shift count* from the top. Every
//! emission below is annotated with the stack it expects.

use revm::bytecode::Bytecode;

use alloy_primitives::Bytes;

/// The four token behaviors the honeypot fixtures cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Standard,
    FeeOnTransfer,
    RevertOnTransfer,
    Drain,
}

/// Fee/drain parameters for the non-standard variants (ignored by
/// [`TokenKind::Standard`] and [`TokenKind::RevertOnTransfer`]).
#[derive(Debug, Clone, Copy)]
pub struct TokenSpec {
    pub kind: TokenKind,
    /// Fee basis points (`0` = none); used by [`TokenKind::FeeOnTransfer`].
    pub fee_bps: u32,
    /// Extra tokens skimmed from `to` per transfer; used by [`TokenKind::Drain`].
    pub drain_amount: u64,
}

impl Default for TokenSpec {
    fn default() -> Self {
        Self {
            kind: TokenKind::Standard,
            fee_bps: 0,
            drain_amount: 0,
        }
    }
}

/// Address the [`TokenKind::Drain`] variant siphons tokens to.
///
/// Outside the precompile range so the drain leg executes contract code
/// rather than dispatching to a builtin (see
/// [`crate::test_util::fixture_addr`]).
#[must_use]
pub const fn siphon_address() -> alloy_primitives::Address {
    alloy_primitives::address!("0xfe0000000000000000000000000000000000000d")
}

const SEL_BALANCE_OF: u32 = 0x70a0_8231;
const SEL_TRANSFER: u32 = 0xa905_9cbb;
const SEL_TRANSFER_FROM: u32 = 0x23b8_72dd;

/// Returns the assembled fixture bytecode for [`TokenSpec`].
#[must_use]
pub fn token_bytecode(spec: TokenSpec) -> Bytecode {
    Bytecode::new_legacy(Bytes::copy_from_slice(&assemble(spec)))
}

// ---------------------------------------------------------------------------
// Tiny assembler. Every emission is annotated with the stack it expects and
// produces so the bytecode can be audited instruction by instruction. Jump
// targets are patched in a final pass.
// ---------------------------------------------------------------------------

struct Asm {
    out: Vec<u8>,
}

/// A pending jump whose destination is fixed when the target site is known.
struct Jump {
    operand: usize,
}

impl Asm {
    fn new() -> Self {
        Self { out: Vec::new() }
    }

    fn op(&mut self, byte: u8) {
        self.out.push(byte);
    }

    /// `PUSHn` from `bytes` (length 1..=32).
    fn push(&mut self, bytes: &[u8]) {
        let len = u8::try_from(bytes.len()).expect("push length 1..=32");
        assert!((1..=32).contains(&bytes.len()), "push length");
        self.out.push(0x5f + len);
        self.out.extend_from_slice(bytes);
    }

    fn push1(&mut self, value: u8) {
        self.push(&[value]);
    }

    fn push2(&mut self, value: u16) {
        self.push(&value.to_be_bytes());
    }

    fn push4(&mut self, value: u32) {
        self.push(&value.to_be_bytes());
    }

    fn push20(&mut self, value: alloy_primitives::Address) {
        self.push(&value.into_array());
    }

    /// `DUPn` — `DUP1` is `0x80`, so the encoding base is `0x7f`.
    fn dup(&mut self, n: u8) {
        assert!((1..=16).contains(&n));
        self.out.push(0x7f + n);
    }

    /// `SWAPn` — `SWAP1` is `0x90`, so the encoding base is `0x8f`.
    fn swap(&mut self, n: u8) {
        assert!((1..=16).contains(&n));
        self.out.push(0x8f + n);
    }

    fn jumpdest(&mut self) -> usize {
        self.op(0x5b);
        self.out.len()
    }

    /// `PUSH2 <placeholder> JUMPI`; the destination is fixed by
    /// [`Self::bind`]. Expects `[.., cond, dest]`, `dest` on top.
    fn jumpi_placeholder(&mut self) -> Jump {
        self.out.push(0x61);
        self.out.push(0);
        self.out.push(0);
        let operand = self.out.len() - 2;
        self.op(0x57);
        Jump { operand }
    }

    fn bind(&mut self, jump: &Jump, site: usize) {
        let offset = u16::try_from(site - 1).expect("fixture under 64 KiB");
        self.out[jump.operand] = offset.to_be_bytes()[0];
        self.out[jump.operand + 1] = offset.to_be_bytes()[1];
    }

    fn into_vec(self) -> Vec<u8> {
        self.out
    }
}

/// `REVERT(0, 0)` — the fixture's unconditional failure and unknown-selector
/// fallback.
fn emit_revert(a: &mut Asm) {
    a.push1(0x00);
    a.push1(0x00);
    a.op(0xfd);
}

/// Calldata offsets for the two transfer shapes.
///
/// - `transferFrom(from, to, amount)`: from@0x04, to@0x24, amount@0x44.
/// - `transfer(to, amount)`: to@0x04, amount@0x24 (from = CALLER).
struct Offsets {
    to: u8,
    amount: u8,
}

const TRANSFER_FROM_OFFSETS: Offsets = Offsets {
    to: 0x24,
    amount: 0x44,
};

const TRANSFER_OFFSETS: Offsets = Offsets {
    to: 0x04,
    amount: 0x24,
};

/// Debit half: require `balance_from >= amount`, then
/// `balance_from -= amount`.
///
/// `transferFrom` reads `from` from calldata; `transfer` debits `CALLER`.
fn emit_discharge(a: &mut Asm, from_caller: bool, offsets: &Offsets) {
    // stack: [selector]
    if from_caller {
        a.op(0x33); // CALLER -> [selector, from]
    } else {
        a.push1(0x04);
        a.op(0x35); // CALLDATALOAD -> [selector, from]
    }
    a.op(0x54); // SLOAD -> [selector, balance_from]
    a.push1(offsets.amount);
    a.op(0x35); // CALLDATALOAD -> [selector, balance_from, amount]
    a.dup(1); // [selector, balance_from, amount, amount]
    if from_caller {
        a.op(0x33); // [selector, balance_from, amount, from]
    } else {
        a.push1(0x04);
        a.op(0x35); // [selector, balance_from, amount, from]
    }
    a.op(0x54); // [selector, balance_from, amount, balance_from]
    a.op(0x10); // LT: balance_from < amount -> [selector, balance_from, amount, insufficient]
    a.op(0x15); // ISZERO -> [selector, balance_from, amount, sufficient]
    let j_sufficient = a.jumpi_placeholder(); // pops dest+flag -> [selector, balance_from, amount]
    emit_revert(a); // REVERT(0,0) when insufficient
    let site_sufficient = a.jumpdest();
    a.bind(&j_sufficient, site_sufficient);
    // stack: [selector, balance_from, amount] — want balance_from - amount
    a.swap(1); // [selector, amount, balance_from]
    a.op(0x03); // SUB -> [selector, new_balance_from]
    if from_caller {
        a.op(0x33); // [selector, new_balance_from, from]
    } else {
        a.push1(0x04);
        a.op(0x35); // [selector, new_balance_from, from]
    }
    a.op(0x55); // SSTORE(from, new_balance_from) -> [selector]
}

/// Credit half: `balance_to += credit` where `credit` is `amount` for a plain
/// transfer or `amount * (10000 - fee_bps) / 10000` for the fee variant (fee
/// burned).
fn emit_credit(a: &mut Asm, fee_bps: u32, offsets: &Offsets) {
    assert!(fee_bps <= 10_000, "fee_bps out of range");
    // stack: [selector]
    a.push1(offsets.to);
    a.op(0x35); // CALLDATALOAD -> [selector, to]
    a.op(0x54); // SLOAD -> [selector, balance_to]
    let numerator = u16::try_from(10_000 - fee_bps).expect("numerator fits u16");
    if numerator == 10_000 {
        a.push1(offsets.amount);
        a.op(0x35); // CALLDATALOAD -> [selector, balance_to, amount]
    } else {
        a.push1(offsets.amount);
        a.op(0x35); // CALLDATALOAD -> [selector, balance_to, amount]
        a.push2(numerator); // [selector, balance_to, amount, numerator]
        a.op(0x02); // MUL -> [selector, balance_to, amount * numerator]
        a.push2(10_000); // [selector, balance_to, amount*numerator, 10000]
        a.swap(1); // [selector, balance_to, 10000, amount*numerator]
        a.op(0x04); // DIV -> [selector, balance_to, credit]
    }
    a.op(0x01); // ADD -> [selector, new_balance_to]
    a.push1(offsets.to);
    a.op(0x35); // [selector, new_balance_to, to]
    a.op(0x55); // SSTORE(to, new_balance_to) -> [selector]
}

/// Skims `drain_amount` from `to` and credits it to the siphon address.
fn emit_drain(a: &mut Asm, drain_amount: u64, offsets: &Offsets) {
    let drain = drain_amount.to_be_bytes();
    let siphon = siphon_address();
    // stack: [selector]
    a.push1(offsets.to);
    a.op(0x35); // [selector, to]
    a.op(0x54); // [selector, balance_to]
    a.push(&drain); // [selector, balance_to, drain]
    a.swap(1); // [selector, drain, balance_to]
    a.op(0x03); // SUB -> [selector, new_balance_to]
    a.push1(offsets.to);
    a.op(0x35); // [selector, new_balance_to, to]
    a.op(0x55); // SSTORE(to, new_balance_to) -> [selector]
    // siphon += drain_amount
    a.push20(siphon);
    a.op(0x54); // [selector, balance_siphon]
    a.push(&drain); // [selector, balance_siphon, drain]
    a.op(0x01); // ADD -> [selector, new_balance_siphon]
    a.push20(siphon);
    a.op(0x55); // SSTORE(siphon, new_balance_siphon) -> [selector]
}

fn assemble(spec: TokenSpec) -> Vec<u8> {
    let mut a = Asm::new();

    // --- dispatch on calldata[0..4] ---
    // stack: []
    a.push1(0x00);
    a.op(0x35); // CALLDATALOAD -> [word]
    a.push1(0xe0);
    a.op(0x1c); // SHR (shift count on top) -> [selector]
    a.dup(1); // [selector, selector]
    a.push4(SEL_BALANCE_OF);
    a.op(0x14); // EQ -> [selector, is_balance]
    let j_balance = a.jumpi_placeholder(); // pops dest, is_balance -> [selector]
    a.dup(1); // [selector, selector]
    a.push4(SEL_TRANSFER);
    a.op(0x14); // EQ -> [selector, is_plain_transfer]
    let j_plain = a.jumpi_placeholder();
    a.dup(1); // [selector, selector]
    a.push4(SEL_TRANSFER_FROM);
    a.op(0x14); // EQ -> [selector, is_transfer]
    let j_transfer = a.jumpi_placeholder();
    // stack: [selector]
    emit_revert(&mut a); // unknown selector

    // --- balanceOf(address) -> SLOAD(calldataload(4)) ---
    let site_balance = a.jumpdest();
    a.bind(&j_balance, site_balance);
    a.push1(0x04);
    a.op(0x35); // CALLDATALOAD -> [selector, holder]
    a.op(0x54); // SLOAD -> [selector, balance]
    a.push1(0x00);
    a.op(0x52); // MSTORE(offset=0, value=balance) -> [selector]
    a.push1(0x20);
    a.push1(0x00);
    a.op(0xf3); // RETURN(offset=0, len=32)

    // --- transferFrom(from, to, amount) ---
    let site_transfer = a.jumpdest();
    a.bind(&j_transfer, site_transfer);
    if matches!(spec.kind, TokenKind::RevertOnTransfer) {
        emit_revert(&mut a);
        return a.into_vec();
    }
    emit_discharge(&mut a, false, &TRANSFER_FROM_OFFSETS);
    emit_credit(&mut a, spec.fee_bps, &TRANSFER_FROM_OFFSETS);
    if matches!(spec.kind, TokenKind::Drain) {
        emit_drain(&mut a, spec.drain_amount, &TRANSFER_FROM_OFFSETS);
    }

    // return true (shared with the plain-transfer branch, which jumps here)
    a.push1(0x01);
    a.push1(0x00);
    a.op(0x52); // MSTORE(offset=0, value=1) -> [selector]
    a.push1(0x20);
    a.push1(0x00);
    a.op(0xf3); // RETURN(offset=0, len=32)

    // --- transfer(to, amount): from = CALLER ---
    let site_plain = a.jumpdest();
    a.bind(&j_plain, site_plain);
    if matches!(spec.kind, TokenKind::RevertOnTransfer) {
        emit_revert(&mut a);
        return a.into_vec();
    }
    emit_discharge(&mut a, true, &TRANSFER_OFFSETS);
    emit_credit(&mut a, spec.fee_bps, &TRANSFER_OFFSETS);
    if matches!(spec.kind, TokenKind::Drain) {
        emit_drain(&mut a, spec.drain_amount, &TRANSFER_OFFSETS);
    }
    // return true — duplicated epilogue (5 bytes) keeps both branches linear
    a.push1(0x01);
    a.push1(0x00);
    a.op(0x52);
    a.push1(0x20);
    a.push1(0x00);
    a.op(0xf3);

    a.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::balance_slot;
    use crate::test_util::{
        CACHE_CALLER, Cache, balance_of, cache, deploy_token, fixture_addr as addr, seed_balance,
        transfer, transfer_from,
    };
    use alloy_primitives::{Address, U256};

    const FROM: Address = CACHE_CALLER;
    const TO: Address = addr(2);

    fn seed(cache: &mut Cache, token: Address) {
        deploy_token(cache, token, TokenSpec::default());
        seed_balance(cache, token, FROM, U256::from(1000));
        seed_balance(cache, token, TO, U256::from(500));
    }

    #[test]
    fn standard_transfer_moves_full_amount() {
        let cache = &mut cache();
        let token = addr(1);
        seed(cache, token);

        let result = transfer_from(cache, token, FROM, TO, U256::from(100));
        assert!(result.is_ok());
        assert_eq!(balance_of(cache, token, FROM), U256::from(900));
        assert_eq!(balance_of(cache, token, TO), U256::from(600));
    }

    #[test]
    fn standard_transfer_reverts_on_insufficient_balance() {
        let cache = &mut cache();
        let token = addr(1);
        seed(cache, token);

        let result = transfer_from(cache, token, FROM, TO, U256::from(2000));
        assert!(result.is_err());
        assert_eq!(balance_of(cache, token, FROM), U256::from(1000));
        assert_eq!(balance_of(cache, token, TO), U256::from(500));
    }

    #[test]
    fn revert_token_never_moves() {
        let cache = &mut cache();
        let token = addr(1);
        seed(cache, token);
        deploy_token(
            cache,
            token,
            TokenSpec {
                kind: TokenKind::RevertOnTransfer,
                ..Default::default()
            },
        );

        let result = transfer_from(cache, token, FROM, TO, U256::from(100));
        assert!(result.is_err());
        assert_eq!(balance_of(cache, token, FROM), U256::from(1000));
        assert_eq!(balance_of(cache, token, TO), U256::from(500));
    }

    #[test]
    fn fee_on_transfer_credits_reduced_amount() {
        let cache = &mut cache();
        let token = addr(1);
        seed(cache, token);
        deploy_token(
            cache,
            token,
            TokenSpec {
                kind: TokenKind::FeeOnTransfer,
                fee_bps: 1000, // 10%
                ..Default::default()
            },
        );

        let result = transfer_from(cache, token, FROM, TO, U256::from(100));
        assert!(result.is_ok());
        assert_eq!(balance_of(cache, token, FROM), U256::from(900));
        assert_eq!(balance_of(cache, token, TO), U256::from(590));
    }

    #[test]
    fn drain_token_siphons_from_recipient() {
        let cache = &mut cache();
        let token = addr(1);
        seed(cache, token);
        deploy_token(
            cache,
            token,
            TokenSpec {
                kind: TokenKind::Drain,
                drain_amount: 25,
                ..Default::default()
            },
        );

        let result = transfer_from(cache, token, FROM, TO, U256::from(100));
        assert!(result.is_ok());
        assert_eq!(balance_of(cache, token, FROM), U256::from(900));
        assert_eq!(balance_of(cache, token, TO), U256::from(575));
        assert_eq!(balance_of(cache, token, siphon_address()), U256::from(25));
    }

    #[test]
    fn balance_of_reads_seeded_slot() {
        let cache = &mut cache();
        let token = addr(1);
        seed(cache, token);

        // `balance_slot` and the assembled SLOAD agree on the layout.
        assert_eq!(balance_of(cache, token, FROM), U256::from(1000));
        let direct = crate::db::read_slot(&cache.db, token, balance_slot(FROM));
        assert_eq!(direct, Some(U256::from(1000)));
    }

    // --- transfer(to, amount): caller debits itself ---

    #[test]
    fn plain_transfer_moves_full_amount_from_caller() {
        let cache = &mut cache();
        let token = addr(1);
        seed(cache, token);

        let result = transfer(cache, token, TO, U256::from(100));
        assert!(result.is_ok());
        assert_eq!(balance_of(cache, token, FROM), U256::from(900));
        assert_eq!(balance_of(cache, token, TO), U256::from(600));
    }

    #[test]
    fn plain_transfer_reverts_on_insufficient_balance() {
        let cache = &mut cache();
        let token = addr(1);
        seed(cache, token);

        let result = transfer(cache, token, TO, U256::from(2000));
        assert!(result.is_err());
        assert_eq!(balance_of(cache, token, FROM), U256::from(1000));
        assert_eq!(balance_of(cache, token, TO), U256::from(500));
    }

    #[test]
    fn plain_transfer_fee_on_transfer_credits_reduced_amount() {
        let cache = &mut cache();
        let token = addr(1);
        seed(cache, token);
        deploy_token(
            cache,
            token,
            TokenSpec {
                kind: TokenKind::FeeOnTransfer,
                fee_bps: 1000, // 10%
                ..Default::default()
            },
        );

        let result = transfer(cache, token, TO, U256::from(100));
        assert!(result.is_ok());
        assert_eq!(balance_of(cache, token, FROM), U256::from(900));
        assert_eq!(balance_of(cache, token, TO), U256::from(590));
    }

    #[test]
    fn plain_transfer_drain_token_siphons_from_recipient() {
        let cache = &mut cache();
        let token = addr(1);
        seed(cache, token);
        deploy_token(
            cache,
            token,
            TokenSpec {
                kind: TokenKind::Drain,
                drain_amount: 25,
                ..Default::default()
            },
        );

        let result = transfer(cache, token, TO, U256::from(100));
        assert!(result.is_ok());
        assert_eq!(balance_of(cache, token, FROM), U256::from(900));
        assert_eq!(balance_of(cache, token, TO), U256::from(575));
        assert_eq!(balance_of(cache, token, siphon_address()), U256::from(25));
    }

    #[test]
    fn plain_transfer_revert_token_never_moves() {
        let cache = &mut cache();
        let token = addr(1);
        seed(cache, token);
        deploy_token(
            cache,
            token,
            TokenSpec {
                kind: TokenKind::RevertOnTransfer,
                ..Default::default()
            },
        );

        let result = transfer(cache, token, TO, U256::from(100));
        assert!(result.is_err());
        assert_eq!(balance_of(cache, token, FROM), U256::from(1000));
        assert_eq!(balance_of(cache, token, TO), U256::from(500));
    }
}
