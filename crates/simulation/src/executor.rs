//! The injected route-executor stub for forked replays.
//!
//! Uniswap V3 pools settle swaps through `uniswapV3SwapCallback` on
//! `msg.sender`, so a fork replay cannot execute a real `swap()` from a
//! plain account: the pool's callback call would hit an EOA and revert.
//! This module assembles the minimal settlement contract the simulator
//! injects at a synthetic address (`executor_address()`), alongside seeded
//! balances so it can pay.
//!
//! This stub exists **only inside simulated forks** — it never holds real
//! funds, has no access-control surface, and is not the Stage-11 production
//! executor.

use alloy_primitives::{Address, Bytes};

/// Synthetic executor address: outside the precompile range, unmistakable in
/// traces (`0xfe00…0001`).
#[must_use]
pub fn executor_address() -> Address {
    let mut bytes = [0u8; 20];
    bytes[0] = 0xfe;
    bytes[19] = 0x01;
    Address::new(bytes)
}

/// `uniswapV3SwapCallback(int256,int256,bytes)` — the pool calls this on the
/// swapper with the owed deltas; exactly one is positive.
const SEL_V3_CALLBACK: u32 = 0xfa46_1e33;

/// `transfer(address,uint256)` — what the callback uses to pay the pool.
pub(crate) const SEL_TRANSFER: u32 = 0xa905_9cbb;

// V4 PoolManager interface. Selectors derived with keccak256, never memory.
/// `unlock(bytes)`.
const SEL_V4_UNLOCK: u32 = 0x48c8_9491;
/// `unlockCallback(bytes)` — the `PoolManager` calls this on the swapper.
const SEL_V4_UNLOCK_CALLBACK: u32 = 0x91dd_7346;
/// `swap(PoolKey, SwapParams, bytes)` — v4.1 shape: `SwapParams` =
/// `(bool zeroForOne, int256 amountSpecified, uint160 sqrtPriceLimitX96)`;
/// returns a packed `BalanceDelta` (amount0 high, amount1 low).
const SEL_V4_SWAP: u32 = 0xf3cd_914c;
/// `sync(Currency)` — refreshes the reserves snapshot before `settle`.
const SEL_V4_SYNC: u32 = 0xa584_1194;
/// `settle()` — credits the caller's payment against its delta.
const SEL_V4_SETTLE: u32 = 0x11da_60b4;
/// `take(Currency,address,uint256)` — pulls an owed credit out.
const SEL_V4_TAKE: u32 = 0x0b0d_9c09;

/// The RHC V4 `PoolManager` singleton (per the activity manifest).
pub const V4_POOL_MANAGER: &str = "0x8366a39CC670B4001A1121B8F6A443A643e40951";

/// Assembler for small runtime contracts (same shape as `tokens::Asm`).
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
    fn push(&mut self, bytes: &[u8]) {
        let len = u8::try_from(bytes.len()).expect("push length 1..=32");
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
    /// `PUSH32` of a 32-byte word (e.g. a selector left-aligned at word
    /// start, or the int256 sign bit).
    fn push32(&mut self, word: &[u8; 32]) {
        self.push(word);
    }
    /// `PUSH20` from an address.
    fn push20(&mut self, value: alloy_primitives::Address) {
        self.push(&value.into_array());
    }
    /// `CALLDATACOPY(dest, src, len)` — dest on top: push len, src, dest.
    fn calldatacopy(&mut self, dest: u16, src: u16, len: u16) {
        self.push2(len);
        self.push2(src);
        self.push2(dest);
        self.op(0x37);
    }
    /// `DUPn` — `DUP1` is `0x80`, so the encoding base is `0x7f`.
    fn dup(&mut self, n: u8) {
        assert!((1..=16).contains(&n));
        self.out.push(0x7f + n);
    }
    /// `PUSH32` int256 sign bit: unsigned `LT` against this decides whether
    /// a delta is negative.
    fn push_sign_bit(&mut self) {
        let mut word = [0u8; 32];
        word[0] = 0x80;
        self.push(&word);
    }
    /// `PUSH2 <placeholder> JUMPI`; fixed by [`Self::bind`]. Expects
    /// `[.., cond, dest]`, `dest` on top.
    fn jumpi_placeholder(&mut self) -> Jump {
        self.out.push(0x61);
        self.out.push(0);
        self.out.push(0);
        let operand = self.out.len() - 2;
        self.op(0x57);
        Jump { operand }
    }
    /// `PUSH2 <placeholder> JUMP` — expects `[dest]` on top.
    fn jump_placeholder(&mut self) -> Jump {
        self.out.push(0x61);
        self.out.push(0);
        self.out.push(0);
        let operand = self.out.len() - 2;
        self.op(0x56);
        Jump { operand }
    }
    fn jumpdest(&mut self) -> usize {
        self.op(0x5b);
        self.out.len()
    }
    fn bind(&mut self, jump: &Jump, site: usize) {
        let offset = u16::try_from(site - 1).expect("stub under 64 KiB");
        self.out[jump.operand] = offset.to_be_bytes()[0];
        self.out[jump.operand + 1] = offset.to_be_bytes()[1];
    }
    fn into_vec(self) -> Vec<u8> {
        self.out
    }
}

/// `PUSH32 (1<<128)-1` — mask for the low 128 bits of a `BalanceDelta`.
fn push_u256_low128_mask(a: &mut Asm) {
    let mut word = [0u8; 32];
    for b in &mut word[16..32] {
        *b = 0xff;
    }
    a.push32(&word);
}

fn emit_revert(a: &mut Asm) {
    a.push1(0x00);
    a.push1(0x00);
    a.op(0xfd);
}

/// Runtime bytecode for the V3 settlement stub.
///
/// `uniswapV3SwapCallback(amount0Delta, amount1Delta, data)` where `data`
/// carries exactly one 32-byte word: the token to pay (address
/// left-padded). Pays the positive delta to `msg.sender` (the calling pool)
/// via `transfer`; reverts if the transfer fails.
///
/// # Panics
///
/// Panics if assembled jump targets are out of range — a build error in
/// this file, not a runtime possibility.
#[must_use]
pub fn v3_callback_runtime() -> Bytes {
    let mut a = Asm::new();
    // free-memory-pointer = 0x80 (value pushed first, offset second: MSTORE
    // pops the offset from the top — see tokens.rs conventions).
    a.push1(0x80);
    a.push1(0x40);
    a.op(0x52);

    // amount0Delta = CALLDATALOAD(4); negative iff >= 2^255.
    a.push1(0x04);
    a.op(0x35); // [a0]
    a.dup(1); // [a0, a0]
    a.push_sign_bit();
    // LT: top < second (see emit_discharge) → sign < a0, i.e. 1 iff a0 is
    // negative as int256. No ISZERO: JUMPI must take the negative path when
    // this is 1.
    a.op(0x10);
    let j_negative = a.jumpi_placeholder(); // leaves [a0]

    // positive path falls through with amount = a0
    let use_amount = a.jumpdest(); // [amount]

    // Packed `transfer(to, amount)` calldata in memory: selector(4) at
    // 0x60..0x64, to(32) at 0x64..0x84, amount(32) at 0x84..0xA4. The
    // selector word is stored at 0x44 because PUSH4 places the selector in
    // the LOW 4 bytes of a 32-byte word (0x44 + 28 = 0x60).
    a.op(0x33); // CALLER → [amount, pool]
    a.push1(0x64); // [amount, pool, 0x64]
    a.op(0x52); // MSTORE(0x64, pool) → [amount]
    a.push4(SEL_TRANSFER); // [amount, sel]
    a.push1(0x44); // [amount, sel, 0x44]
    a.op(0x52); // MSTORE(0x44, sel) → selector bytes land at 0x60..0x64
    a.push1(0x84); // [amount, 0x84]
    a.op(0x52); // MSTORE(0x84, amount) → []
    // CALL(gas, token, 0, 0x60, 0x44, 0, 0) — CALL pops gas, addr, value,
    // argsOffset, argsSize, retOffset, retSize, so the pushes below leave
    // [retSize, retOffset, inSize, inOffset, value, token, gas(top)].
    a.push1(0x00); // retSize
    a.push1(0x00); // retOffset
    a.push1(0x44); // inSize = 4 + 32 + 32
    a.push1(0x60); // inOffset
    a.push1(0x00); // value
    a.push1(0x84); // token = CALLDATALOAD(132): the single word inside `data`
    a.op(0x35);
    a.op(0x5a); // GAS
    a.op(0xf1); // CALL → [ok]
    a.op(0x15); // ISZERO → [failed]
    let j_fail = a.jumpi_placeholder();
    a.push1(0x00);
    a.push1(0x00);
    a.op(0xf3); // RETURN(0,0): successful no-data return

    // negative path: swap in amount1Delta, jump back to payment
    let else_site = a.jumpdest();
    a.bind(&j_negative, else_site);
    a.op(0x50); // POP stale a0
    a.push1(0x24);
    a.op(0x35); // [a1]
    let j_back = a.jump_placeholder();

    let fail_site = a.jumpdest();
    a.bind(&j_fail, fail_site);
    emit_revert(&mut a);

    // Bind the backward jump last (targets use_amount, earlier in code).
    a.bind(&j_back, use_amount);
    Bytes::from(a.into_vec())
}

/// Calldata invoking the settlement stub the way a V3 pool would.
///
/// `uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes
/// data)` where `data` carries one word: the token the positive delta is
/// paid in. The positive delta encodes `amount`; `amount1Delta` is the -1
/// sentinel (negative) so the stub always settles via `amount0Delta`.
#[must_use]
pub fn encode_v3_callback(token: Address, amount: alloy_primitives::U256) -> Vec<u8> {
    use alloy_primitives::U256;
    let mut cd = Vec::with_capacity(164);
    cd.extend_from_slice(&SEL_V3_CALLBACK.to_be_bytes());
    // amount0Delta = amount (positive → pay token0-side i.e. our data word)
    cd.extend_from_slice(amount.to_be_bytes::<32>().as_ref());
    // amount1Delta = -1 sentinel negative (never selected while amount > 0)
    cd.extend_from_slice(U256::MAX.to_be_bytes::<32>().as_ref());
    // data offset = 0x60 (relative to args start)
    cd.extend_from_slice(U256::from(96).to_be_bytes::<32>().as_ref());
    // data length = 32
    cd.extend_from_slice(U256::from(32).to_be_bytes::<32>().as_ref());
    // data: token address left-padded
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&token.into_array());
    cd.extend_from_slice(&word);
    cd
}

/// Runtime bytecode for the V4 settlement stub.
///
/// `unlockCallback(bytes data)` where `data` carries ten words (offset 0x44
/// in the callback calldata):
///
/// - w0..w4: the `PoolKey` (`currency0`, `currency1`, `fee`,
///   `tickSpacing`, `hooks`)
/// - w5: `zeroForOne` (0/1)
/// - w6: `amountSpecified` (exact input, positive)
/// - w7: `sqrtPriceLimitX96`
/// - w8: currency owed by the swapper (paid via transfer + `settle`)
/// - w9: currency owed to the swapper (pulled via `take`)
///
/// Flow: `swap` (return deltas at memory 0x200), `sync(currencyIn)`,
/// `transfer` + `settle` for the input, `take(currencyOut, self,
/// deltaOut)` where deltaOut is the positive swap-return delta selected by
/// `zeroForOne`. The whole `unlock` reverts unless the deltas net to zero,
/// so the precomputed amounts must match the pool's real behavior — the
/// verification property this stub exists to test.
///
/// # Panics
///
/// Panics if assembled jump targets are out of range — a build error in
/// this file, not a runtime possibility.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn v4_unlock_callback_runtime() -> Bytes {
    let mut a = Asm::new();

    // --- swap(PoolKey, SwapParams, hookData) into the PoolManager ---
    // v4.1: SwapParams = (bool zeroForOne, int256 amountSpecified,
    // uint160 sqrtPriceLimitX96); hookData is a separate trailing `bytes`
    // (empty here). Selector as the first 4 bytes at 0x00: PUSH32 word
    // with the selector in the HIGH 4 bytes.
    let mut sel_word = [0u8; 32];
    sel_word[..4].copy_from_slice(&SEL_V4_SWAP.to_be_bytes());
    a.push32(&sel_word);
    a.push1(0x00);
    a.op(0x52); // MSTORE(0x00, sel<<224)
    // PoolKey: copy w0..w4 (callback calldata 0x44..0xC4) to 0x04..0xA4.
    a.calldatacopy(0x04, 0x44, 0xA0);
    // SwapParams: zeroForOne w5, amountSpecified w6, sqrtLimit w7 ->
    // 0xA4..0x124.
    a.calldatacopy(0xA4, 0xE4, 0x60);
    // hookData offset (relative to the args block start 0x04): the tail
    // begins after 5 + 3 head words at 0x104, so offset = 0x100.
    a.push2(0x100);
    a.push2(0x104);
    a.op(0x52);
    // hookData length = 0.
    a.push1(0x00);
    a.push2(0x124);
    a.op(0x52);
    // CALL(gas, PM, 0, 0x00, 0x144, 0x200, 0x20) — BalanceDelta at 0x200.
    a.push1(0x20); // retSize
    a.push2(0x200); // retOffset
    a.push2(0x144); // inSize
    a.push1(0x00); // inOffset
    a.push1(0x00); // value
    a.push20(pool_manager_address());
    a.op(0x5a); // GAS
    a.op(0xf1); // CALL -> [ok]
    a.op(0x15); // ISZERO
    let j_fail = a.jumpi_placeholder();

    // --- sync(currencyIn) ---
    a.push4(SEL_V4_SYNC);
    a.push2(0x1A4);
    a.op(0x52); // selector lands at 0x1C0..0x1C4
    a.calldatacopy(0x1C4, 0x144, 0x20); // w8 currencyIn
    a.push1(0x00); // retSize
    a.push1(0x00); // retOffset
    a.push1(0x24); // inSize
    a.push2(0x1C0); // inOffset
    a.push1(0x00); // value
    a.push20(pool_manager_address());
    a.op(0x5a);
    a.op(0xf1);
    a.op(0x15);
    let j_fail2 = a.jumpi_placeholder();

    // --- transfer(currencyIn, PoolManager, amountSpecified) ---
    a.push4(SEL_TRANSFER);
    a.push2(0x1A4);
    a.op(0x52);
    a.push20(pool_manager_address());
    a.push2(0x1C4);
    a.op(0x52); // to = PM
    a.calldatacopy(0x1E4, 0x104, 0x20); // w6 amountSpecified
    a.push1(0x00);
    a.push1(0x00);
    a.push1(0x44); // inSize
    a.push2(0x1C0); // inOffset
    a.push1(0x00); // value
    a.push2(0x144);
    a.op(0x35); // addr = CALLDATALOAD(0x144) = currencyIn
    a.op(0x5a);
    a.op(0xf1);
    a.op(0x15);
    let j_fail3 = a.jumpi_placeholder();

    // --- settle() ---
    a.push4(SEL_V4_SETTLE);
    a.push2(0x1A4);
    a.op(0x52);
    a.push1(0x00);
    a.push1(0x00);
    a.push1(0x04); // inSize = selector only
    a.push2(0x1C0);
    a.push1(0x00);
    a.push20(pool_manager_address());
    a.op(0x5a);
    a.op(0xf1);
    a.op(0x15);
    let j_fail4 = a.jumpi_placeholder();

    // --- take(currencyOut, executor, deltaOut) ---
    a.push4(SEL_V4_TAKE);
    a.push2(0x1A4);
    a.op(0x52);
    a.calldatacopy(0x1C4, 0x164, 0x20); // w9 currencyOut
    a.op(0x30); // ADDRESS = executor
    a.push2(0x1E4);
    a.op(0x52); // to = executor
    // BalanceDelta (single word at 0x200): amount0 = high 128 bits,
    // amount1 = low 128. For zeroForOne the received delta is amount1;
    // mask the low 128 bits (positive when the pool owes currency1).
    a.push2(0x200);
    a.op(0x51); // MLOAD BalanceDelta
    push_u256_low128_mask(&mut a);
    a.op(0x16); // AND -> deltaOut (amount1, positive)
    a.push2(0x204);
    a.op(0x52); // MSTORE(0x204, deltaOut)
    a.push1(0x00);
    a.push1(0x00);
    a.push1(0x64); // inSize = 4 + 32*3
    a.push2(0x1C0);
    a.push1(0x00);
    a.push20(pool_manager_address());
    a.op(0x5a);
    a.op(0xf1);
    a.op(0x15);
    let j_fail5 = a.jumpi_placeholder();

    // --- return abi-encoded empty bytes (offset 0x40, length 0) ---
    a.push1(0x40);
    a.push2(0x200);
    a.op(0x52); // MSTORE(0x200, 0x40)
    a.push1(0x00);
    a.push2(0x220);
    a.op(0x52); // MSTORE(0x220, 0)
    a.push1(0x40); // len
    a.push2(0x200); // offset
    a.op(0xf3); // RETURN

    let fail_site = a.jumpdest();
    a.bind(&j_fail, fail_site);
    a.bind(&j_fail2, fail_site);
    a.bind(&j_fail3, fail_site);
    a.bind(&j_fail4, fail_site);
    a.bind(&j_fail5, fail_site);
    emit_revert(&mut a);
    Bytes::from(a.into_vec())
}

/// The V4 `PoolManager` singleton address.
///
/// # Panics
///
/// Panics if the compiled-in address literal is invalid — a build error.
#[must_use]
pub fn pool_manager_address() -> Address {
    V4_POOL_MANAGER.parse().expect("valid PoolManager address")
}

/// Everything the V4 settlement stub needs, resolved off-chain before the
/// simulated unlock.
#[derive(Debug, Clone, Copy)]
pub struct V4SwapIntent {
    pub currency0: Address,
    pub currency1: Address,
    pub fee: u32,
    pub tick_spacing: i32,
    pub hooks: Address,
    pub zero_for_one: bool,
    pub amount_specified: alloy_primitives::U256,
    pub sqrt_price_limit: alloy_primitives::U256,
    pub currency_in: Address,
    pub currency_out: Address,
}

fn v4_data_words(intent: &V4SwapIntent) -> Vec<u8> {
    use alloy_primitives::U256;
    let mut data = Vec::with_capacity(320);
    data.extend_from_slice(&intent.currency0.into_word().0);
    data.extend_from_slice(&intent.currency1.into_word().0);
    data.extend_from_slice(&U256::from(intent.fee).to_be_bytes::<32>());
    data.extend_from_slice(&U256::from(intent.tick_spacing.cast_unsigned()).to_be_bytes::<32>());
    data.extend_from_slice(&intent.hooks.into_word().0);
    data.extend_from_slice(&U256::from(u8::from(intent.zero_for_one)).to_be_bytes::<32>());
    data.extend_from_slice(&intent.amount_specified.to_be_bytes::<32>());
    data.extend_from_slice(&intent.sqrt_price_limit.to_be_bytes::<32>());
    data.extend_from_slice(&intent.currency_in.into_word().0);
    data.extend_from_slice(&intent.currency_out.into_word().0);
    data
}

/// `unlock(bytes)` calldata carrying the [`V4SwapIntent`] for the stub.
///
/// # Panics
///
/// Panics if `intent.tick_spacing` does not fit `u32` — impossible for
/// real tick spacings, and a caller error otherwise.
#[must_use]
pub fn encode_v4_unlock(intent: &V4SwapIntent) -> Vec<u8> {
    use alloy_primitives::U256;
    let data = v4_data_words(intent);
    let mut cd = Vec::with_capacity(4 + 64 + data.len());
    cd.extend_from_slice(&SEL_V4_UNLOCK.to_be_bytes());
    cd.extend_from_slice(&U256::from(0x20).to_be_bytes::<32>()); // bytes offset
    cd.extend_from_slice(&U256::from(data.len()).to_be_bytes::<32>());
    cd.extend_from_slice(&data);
    cd
}

/// Callback-shaped calldata: what the `PoolManager` passes to
/// `unlockCallback(bytes)` (selector, offset, length, data).
///
/// # Panics
///
/// Panics if `intent.tick_spacing` does not fit `u32` — impossible for
/// real tick spacings, and a caller error otherwise.
#[must_use]
pub fn encode_v4_unlock_callback(intent: &V4SwapIntent) -> Vec<u8> {
    use alloy_primitives::U256;
    let data = v4_data_words(intent);
    let mut cd = Vec::with_capacity(4 + 64 + data.len());
    cd.extend_from_slice(&SEL_V4_UNLOCK_CALLBACK.to_be_bytes());
    cd.extend_from_slice(&U256::from(0x20).to_be_bytes::<32>());
    cd.extend_from_slice(&U256::from(data.len()).to_be_bytes::<32>());
    cd.extend_from_slice(&data);
    cd
}

/// `MIN_SQRT_RATIO + 1` — the tightest legal zeroForOne price limit.
#[must_use]
pub fn min_sqrt_ratio_plus_1() -> alloy_primitives::U256 {
    alloy_primitives::U256::from(4_295_128_741_u64 + 1)
}

/// `MAX_SQRT_RATIO - 1` — the tightest legal oneForZero price limit.
///
/// # Panics
///
/// Panics if the compiled-in constant literal is invalid — a build error.
#[must_use]
pub fn max_sqrt_ratio_minus_1() -> alloy_primitives::U256 {
    "1461446703485210103287273052203988822378723970341"
        .parse::<alloy_primitives::U256>()
        .expect("valid MAX_SQRT_RATIO")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::{TokenSpec, token_bytecode};
    use alloy_primitives::{TxKind, U256};
    use revm::bytecode::Bytecode;
    use revm::context::TxEnv;
    use revm::database::CacheDB;
    use revm::database_interface::EmptyDB;
    use revm::handler::{ExecuteCommitEvm, MainBuilder};
    use revm::primitives::hardfork::SpecId;

    const POOL: Address = Address::new([
        0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ]);
    const TOKEN: Address = Address::new([
        0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03,
    ]);

    #[test]
    fn callback_pays_positive_delta_to_pool() {
        let amount = U256::from(500_u64);
        let mut db = CacheDB::<EmptyDB>::default();
        // Deploy the stub and the fixture token.
        let exec = executor_address();
        let bytecode = Bytecode::new_legacy(v3_callback_runtime());
        db.insert_account_info(exec, revm::state::AccountInfo::from_bytecode(bytecode));
        let token_code = token_bytecode(TokenSpec::default());
        db.insert_account_info(TOKEN, revm::state::AccountInfo::from_bytecode(token_code));
        // Executor holds 1000 units of the fixture token.
        db.insert_account_storage(TOKEN, crate::db::balance_slot(exec), U256::from(1000))
            .unwrap();

        let tx = TxEnv::builder()
            .caller(POOL)
            .kind(TxKind::Call(exec))
            .data(Bytes::from(encode_v3_callback(TOKEN, amount)))
            .gas_limit(200_000)
            .build()
            .unwrap();
        let mut evm = <crate::engine::SimContext<CacheDB<EmptyDB>>>::new(db, SpecId::PRAGUE)
            .modify_cfg_chained(|cfg| cfg.disable_nonce_check = true)
            .build_mainnet();
        let result = evm.transact_commit(tx).expect("evm runs");
        assert!(result.is_success(), "callback reverted: {result:?}");
        let db = evm.ctx.journaled_state.database;
        let paid = read_balance(&db, POOL);
        assert_eq!(paid, amount, "pool must be paid the positive delta");
        assert_eq!(
            read_balance(&db, exec),
            U256::from(1000) - amount,
            "executor debited"
        );
    }

    #[test]
    fn callback_selects_amount1_when_amount0_is_negative() {
        // amount0Delta = -700 (two's complement), amount1Delta = +700: the
        // stub must settle via amount1Delta.
        let amount = U256::from(700_u64);
        let neg = (U256::MAX - amount)
            .checked_add(U256::from(1))
            .expect("two's complement");
        let mut db = CacheDB::<EmptyDB>::default();
        let exec = executor_address();
        let bytecode = Bytecode::new_legacy(v3_callback_runtime());
        db.insert_account_info(exec, revm::state::AccountInfo::from_bytecode(bytecode));
        let token_code = token_bytecode(TokenSpec::default());
        db.insert_account_info(TOKEN, revm::state::AccountInfo::from_bytecode(token_code));
        db.insert_account_storage(TOKEN, crate::db::balance_slot(exec), U256::from(1000))
            .unwrap();

        let mut cd = Vec::with_capacity(164);
        cd.extend_from_slice(&SEL_V3_CALLBACK.to_be_bytes());
        cd.extend_from_slice(&neg.to_be_bytes::<32>());
        cd.extend_from_slice(&amount.to_be_bytes::<32>());
        cd.extend_from_slice(&U256::from(96).to_be_bytes::<32>());
        cd.extend_from_slice(&U256::from(32).to_be_bytes::<32>());
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(&TOKEN.into_array());
        cd.extend_from_slice(&word);

        let tx = TxEnv::builder()
            .caller(POOL)
            .kind(TxKind::Call(exec))
            .data(Bytes::from(cd))
            .gas_limit(200_000)
            .build()
            .unwrap();
        let mut evm = <crate::engine::SimContext<CacheDB<EmptyDB>>>::new(db, SpecId::PRAGUE)
            .modify_cfg_chained(|cfg| cfg.disable_nonce_check = true)
            .build_mainnet();
        let result = evm.transact_commit(tx).expect("evm runs");
        assert!(result.is_success(), "callback reverted: {result:?}");
        let db = evm.ctx.journaled_state.database;
        assert_eq!(read_balance(&db, POOL), amount, "paid via amount1Delta");
        assert_eq!(read_balance(&db, exec), U256::from(1000) - amount);
    }

    #[test]
    fn callback_reverts_when_transfer_fails() {
        // No seeded balance: the debit half reverts, so the pool call must
        // fail closed.
        let amount = U256::from(500_u64);
        let mut db = CacheDB::<EmptyDB>::default();
        let exec = executor_address();
        let bytecode = Bytecode::new_legacy(v3_callback_runtime());
        db.insert_account_info(exec, revm::state::AccountInfo::from_bytecode(bytecode));
        let token_code = token_bytecode(TokenSpec::default());
        db.insert_account_info(TOKEN, revm::state::AccountInfo::from_bytecode(token_code));
        let tx = TxEnv::builder()
            .caller(POOL)
            .kind(TxKind::Call(exec))
            .data(Bytes::from(encode_v3_callback(TOKEN, amount)))
            .gas_limit(200_000)
            .build()
            .unwrap();
        let mut evm = <crate::engine::SimContext<CacheDB<EmptyDB>>>::new(db, SpecId::PRAGUE)
            .modify_cfg_chained(|cfg| cfg.disable_nonce_check = true)
            .build_mainnet();
        let result = evm.transact_commit(tx).expect("evm runs");
        assert!(!result.is_success(), "unfunded payment must fail closed");
    }

    fn read_balance(db: &CacheDB<EmptyDB>, holder: Address) -> U256 {
        crate::db::read_slot(db, TOKEN, crate::db::balance_slot(holder)).unwrap_or_default()
    }

    // --- live fork replay (operator-run; ignored by default) ---

    /// `swap(address recipient, bool zeroForOne, int256 amountSpecified,
    /// uint160 sqrtPriceLimitX96, bytes data)`.
    const SEL_V3_SWAP: u32 = 0x128a_cb08;

    /// `Transfer(address,address,uint256)` topic0.
    const TRANSFER_TOPIC: alloy_primitives::B256 = alloy_primitives::B256::new([
        0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d,
        0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23,
        0xb3, 0xef,
    ]);

    /// `MIN_SQRT_RATIO + 1` — the tightest legal limit for zeroFor-one swaps.
    const MIN_SQRT_RATIO_PLUS_1: u64 = 4_295_128_741;

    /// A live V3 pool from the activity manifest (USDG/a30F, 0.3% fee).
    const LIVE_V3_POOL: &str = "0x02175608F1b5E6b5ed221cCFdC7Be197D111D915";
    const LIVE_TOKEN0: &str = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168"; // USDG
    const LIVE_TOKEN1: &str = "0xa30FA36Db767ad9eD3f7a60fC79526fB4d56D344";

    /// Replays a real RHC V3 pool `swap()` through the settlement stub on a
    /// block-pinned fork and cross-checks the executor's received output
    /// against the in-range constant-product-equivalent formula.
    ///
    /// Funding is a seeded token0 balance (flash simulation is a later
    /// phase); the stub pays the pool's positive delta exactly as in
    /// production. Read-only against the chain; nothing is broadcast.
    #[test]
    #[ignore = "live: needs the RHC gateway; run with --ignored"]
    #[allow(clippy::too_many_lines)]
    fn fork_v3_leg_replay_matches_local_quote() {
        use provider::{ChainReader, LiveHttp, ProviderBudget, RetryPolicy, ThreadSleeper};
        use revm::database::CacheDB;
        use revm::handler::{ExecuteCommitEvm, MainBuilder};
        use std::time::Duration;

        let rpc = std::env::var("ROBINHOOD_HTTP_RPC_URL")
            .unwrap_or_else(|_| "https://rpc.mainnet.chain.robinhood.com".to_owned());
        let reader = ChainReader::new(
            LiveHttp::new(rpc.parse().expect("valid rpc url")),
            ThreadSleeper,
            ProviderBudget::new(40_000, 1 << 24),
            RetryPolicy {
                max_retries: 3,
                initial_delay: Duration::from_millis(250),
                max_delay: Duration::from_secs(2),
            },
            4663,
        );
        reader.validate_chain_id().expect("chain id");
        let head = reader.current_block().expect("head");
        let block = head - 2;

        let pool: Address = LIVE_V3_POOL.parse().unwrap();
        let token0: Address = LIVE_TOKEN0.parse().unwrap();
        let token1: Address = LIVE_TOKEN1.parse().unwrap();

        // Pool state at the pinned block: slot0 = sqrtPriceX96 | tick<<160,
        // slot 1 = in-range liquidity.
        let slot0 = reader.storage_at(pool, U256::ZERO, block).expect("slot0");
        let mask = (U256::from(1) << U256::from(160)) - U256::from(1);
        let sqrt_p = slot0 & mask;
        let liquidity = reader.storage_at(pool, U256::from(1), block).expect("L");
        assert!(!sqrt_p.is_zero() && !liquidity.is_zero(), "pool is idle");
        let sqrt_p_f = f64_of_sqrt(sqrt_p);
        let l_f = u256_to_f64(liquidity);

        // Discover the real token's `balances` mapping slot from the pool's
        // own known balance: find N such that storage[keccak(pool ++ N)]
        // equals balanceOf(pool). Fixture-layout seeding is invisible to a
        // real ERC-20, so the executor must be funded at the derived slot.
        let balance_of = |token: Address, who: Address| -> U256 {
            let mut cd = Vec::with_capacity(36);
            cd.extend_from_slice(&0x70a0_8231_u32.to_be_bytes()); // balanceOf
            cd.extend_from_slice(&who.into_word().0);
            let out = reader
                .call(token, &Bytes::from(cd), block)
                .expect("balanceOf");
            U256::from_be_slice(&out)
        };
        let pool_token0 = balance_of(token0, pool);
        assert!(!pool_token0.is_zero(), "pool holds no token0");
        let token1_balance = balance_of(token1, pool);
        assert!(!token1_balance.is_zero(), "pool holds no token1");
        let exec = executor_address();
        let exec_token0 = balance_of(token0, exec);
        assert!(exec_token0.is_zero(), "executor unexpectedly funded");
        let balances_slot_of = |token: Address, pool_balance: U256| -> U256 {
            (0u64..=10)
                .find(|n| {
                    let key = mapping_slot(pool.into_array(), U256::from(*n));
                    reader
                        .storage_at(token, key, block)
                        .is_ok_and(|v| v == pool_balance)
                })
                .map_or(U256::MAX, U256::from)
        };
        let balances_slot = balances_slot_of(token0, pool_token0);
        assert_ne!(balances_slot, U256::MAX, "token0 balances slot not found");
        // token1's storage layout may not be discoverable; the received
        // amount is read from its Transfer log instead.
        // Size the input from the pool's REAL token1 balance: the tick's
        // virtual liquidity can be unbacked (the honeypot signature), so a
        // purely in-range sizing would demand an output the pool cannot
        // pay. Target 0.1% of the real balance, i.e. move the price by
        // f = target/(L*sqrtP), and fall back to the 0.01% in-range sizing
        // when the balance backs more than that.
        assert!(!token1_balance.is_zero(), "pool holds no token1");
        let l_sqrt = l_f * sqrt_p_f;
        let target_out_f = u256_to_f64(token1_balance) / 1000.0;
        let f = (target_out_f / l_sqrt).min(5.0e-5);
        let input_f = l_f * f / sqrt_p_f;
        // Diagnostic input sizing; f64 rounding cannot move the price out of
        // the in-range band this targets.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let input = U256::from(input_f.max(1_000.0) as u128);

        // In-range expected output with the 0.3% fee taken from the input,
        // first order in the (dust-sized) price move: dy = aIn * P.
        let fee_den = 1_000_000.0;
        let fee_num = 3000.0;
        let a_in = input_f * (fee_den - fee_num) / fee_den;
        let expected_out_f = a_in * sqrt_p_f * sqrt_p_f;

        // Fork overlay: the stub at the executor address, funded with the
        // input token at the real mapping slot.
        let mut db = CacheDB::new(crate::fork::ForkDb::new(reader, block));
        db.insert_account_info(
            exec,
            revm::state::AccountInfo::from_bytecode(Bytecode::new_legacy(v3_callback_runtime())),
        );
        let exec_key = mapping_slot(exec.into_array(), balances_slot) + exec_token0;
        db.insert_account_storage(token0, exec_key, input).unwrap();

        // swap(recipient=exec, zeroForOne, amountSpecified=input,
        //      sqrtLimit=MIN+1, data=token0)
        let mut cd = Vec::with_capacity(4 + 32 * 7);
        cd.extend_from_slice(&SEL_V3_SWAP.to_be_bytes());
        cd.extend_from_slice(&exec.into_word().0);
        cd.extend_from_slice(&U256::from(1).to_be_bytes::<32>()); // true
        cd.extend_from_slice(&input.to_be_bytes::<32>());
        cd.extend_from_slice(&U256::from(MIN_SQRT_RATIO_PLUS_1).to_be_bytes::<32>());
        cd.extend_from_slice(&U256::from(0xA0).to_be_bytes::<32>()); // data offset
        cd.extend_from_slice(&U256::from(32).to_be_bytes::<32>()); // data len
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(&token0.into_array());
        cd.extend_from_slice(&word);

        let tx = TxEnv::builder()
            .caller(exec)
            .kind(TxKind::Call(pool))
            .data(Bytes::from(cd))
            .gas_limit(5_000_000)
            .build()
            .unwrap();
        let mut evm = <crate::engine::SimContext<
            CacheDB<crate::fork::ForkDb<provider::LiveHttp, provider::ThreadSleeper>>,
        >>::new(db, SpecId::PRAGUE)
        .modify_cfg_chained(|cfg| {
            cfg.disable_nonce_check = true;
            cfg.disable_eip3607 = true; // the caller is a contract by design
        })
        .build_mainnet();
        let result = evm.transact_commit(tx).expect("evm runs");
        assert!(result.is_success(), "forked swap reverted: {result:?}");
        let db = evm.ctx.journaled_state.database;

        let slot_of =
            |db: &CacheDB<crate::fork::ForkDb<provider::LiveHttp, provider::ThreadSleeper>>,
             token: Address,
             slot: U256|
             -> U256 {
                db.cache
                    .accounts
                    .get(&token)
                    .and_then(|account| account.storage.get(&slot))
                    .copied()
                    .unwrap_or_default()
            };
        let paid_in = slot_of(&db, token0, mapping_slot(exec.into_array(), balances_slot));
        // received: the token1 Transfer(pool -> exec) log's data word.
        let exec_word = exec.into_word();
        let received = result
            .logs()
            .iter()
            .filter(|log| {
                log.address == token1
                    && log.topics().len() == 3
                    && log.topics()[0] == TRANSFER_TOPIC
                    && log.topics()[2] == exec_word
            })
            .map(|log| U256::from_be_slice(&log.data.data))
            .fold(U256::ZERO, |a, v| a.checked_add(v).unwrap_or(U256::MAX));
        assert_eq!(paid_in, U256::ZERO, "input fully spent via the callback");
        let received_f = u256_to_f64(received);
        let rel = (received_f - expected_out_f).abs() / expected_out_f;
        eprintln!(
            "fork replay: block={block} input={input} received={received} expected~{expected_out_f:.0} rel_err={rel:.4}"
        );
        assert!(
            received > U256::ZERO,
            "executor must receive the output token"
        );
        assert!(
            rel < 0.05,
            "received {received_f:.0} vs in-range expectation {expected_out_f:.0} (rel {rel:.4})"
        );
    }

    /// `keccak256(abi.encode(key, slot))` — the standard Solidity mapping
    /// slot derivation.
    fn mapping_slot(key: [u8; 20], slot: U256) -> U256 {
        let mut buf = [0u8; 64];
        buf[12..32].copy_from_slice(&key);
        buf[32..64].copy_from_slice(&slot.to_be_bytes::<32>());
        U256::from_be_bytes(alloy_primitives::keccak256(buf).0)
    }

    #[test]
    #[ignore = "live: needs the RHC gateway; run with --ignored"]
    fn fork_stub_callback_with_real_token() {
        use provider::{ChainReader, LiveHttp, ProviderBudget, RetryPolicy, ThreadSleeper};
        use revm::database::CacheDB;
        use revm::handler::{ExecuteCommitEvm, MainBuilder};
        use std::time::Duration;

        let rpc = std::env::var("ROBINHOOD_HTTP_RPC_URL")
            .unwrap_or_else(|_| "https://rpc.mainnet.chain.robinhood.com".to_owned());
        let reader = ChainReader::new(
            LiveHttp::new(rpc.parse().expect("valid rpc url")),
            ThreadSleeper,
            ProviderBudget::new(40_000, 1 << 24),
            RetryPolicy {
                max_retries: 3,
                initial_delay: Duration::from_millis(250),
                max_delay: Duration::from_secs(2),
            },
            4663,
        );
        let head = reader.current_block().expect("head");
        let block = head - 2;
        let token0: Address = LIVE_TOKEN0.parse().unwrap();
        let pool: Address = LIVE_V3_POOL.parse().unwrap();
        let exec = executor_address();

        let balance_of = |who: Address| -> U256 {
            let mut cd = Vec::with_capacity(36);
            cd.extend_from_slice(&0x70a0_8231_u32.to_be_bytes());
            cd.extend_from_slice(&who.into_word().0);
            let out = reader
                .call(token0, &Bytes::from(cd), block)
                .expect("balanceOf");
            U256::from_be_slice(&out)
        };
        let pool_token0 = balance_of(pool);
        let balances_slot: U256 = (0u64..=10)
            .find(|n| {
                let key = mapping_slot(pool.into_array(), U256::from(*n));
                reader
                    .storage_at(token0, key, block)
                    .is_ok_and(|v| v == pool_token0)
            })
            .map(U256::from)
            .expect("slot");
        let amount = U256::from(1_000u64); // 0.001 USDG
        let mut db = CacheDB::new(crate::fork::ForkDb::new(reader, block));
        db.insert_account_info(
            exec,
            revm::state::AccountInfo::from_bytecode(Bytecode::new_legacy(v3_callback_runtime())),
        );
        let key = mapping_slot(exec.into_array(), balances_slot);
        db.insert_account_storage(token0, key, amount).unwrap();

        // Top-level call: EOA pays the pool directly through the stub.
        let tx = TxEnv::builder()
            .caller(Address::with_last_byte(0xE1))
            .kind(TxKind::Call(exec))
            .data(Bytes::from(encode_v3_callback(token0, amount)))
            .gas_limit(1_000_000)
            .build()
            .unwrap();
        let mut evm = <crate::engine::SimContext<
            CacheDB<crate::fork::ForkDb<provider::LiveHttp, provider::ThreadSleeper>>,
        >>::new(db, SpecId::PRAGUE)
        .modify_cfg_chained(|cfg| {
            cfg.disable_nonce_check = true;
            cfg.disable_eip3607 = true;
        })
        .build_mainnet();
        let result = evm.transact_commit(tx).expect("evm runs");
        eprintln!("DEBUG direct-callback result: {result:?}");
        let db = evm.ctx.journaled_state.database;
        let paid = db
            .cache
            .accounts
            .get(&token0)
            .and_then(|a| {
                a.storage
                    .get(&mapping_slot(pool.into_array(), balances_slot))
            })
            .copied()
            .unwrap_or_default();
        assert!(result.is_success(), "stub callback on fork reverted");
        assert_eq!(paid, amount, "pool must be paid on the fork");
    }

    /// Bisection: does `unlock` + a no-op `unlockCallback` succeed at all?
    #[test]
    #[ignore = "live: needs the RHC gateway; run with --ignored"]
    fn fork_v4_unlock_noop() {
        use provider::{ChainReader, LiveHttp, ProviderBudget, RetryPolicy, ThreadSleeper};
        use revm::database::CacheDB;
        use revm::handler::{ExecuteCommitEvm, MainBuilder};
        use revm::primitives::hardfork::SpecId;
        use std::time::Duration;

        let rpc = std::env::var("ROBINHOOD_HTTP_RPC_URL")
            .unwrap_or_else(|_| "https://rpc.mainnet.chain.robinhood.com".to_owned());
        let reader = ChainReader::new(
            LiveHttp::new(rpc.parse().expect("valid rpc url")),
            ThreadSleeper,
            ProviderBudget::new(20_000_000, 1 << 24),
            RetryPolicy {
                max_retries: 6,
                initial_delay: Duration::from_secs(2),
                max_delay: Duration::from_secs(30),
            },
            4663,
        );
        let head = reader.current_block().expect("head");
        let block = head - 2;
        let pm = pool_manager_address();
        let exec = executor_address();

        // A no-op callback: return abi-encoded empty bytes.
        // MSTORE(0x200,0x40); MSTORE(0x220,0); RETURN(0x200,0x40)
        let mut a: Vec<u8> = Vec::new();
        let word = |out: &mut Vec<u8>, hi: u8, lo: u16| {
            out.push(hi);
            out.extend_from_slice(&lo.to_be_bytes());
        };
        word(&mut a, 0x61, 0x40);
        word(&mut a, 0x61, 0x200);
        a.push(0x52);
        a.push(0x60);
        a.push(0x00);
        word(&mut a, 0x61, 0x220);
        a.push(0x52);
        word(&mut a, 0x61, 0x40);
        word(&mut a, 0x61, 0x200);
        a.push(0xf3);

        let mut db = CacheDB::new(crate::fork::ForkDb::new(reader, block));
        db.insert_account_info(
            exec,
            revm::state::AccountInfo::from_bytecode(Bytecode::new_legacy(Bytes::from(a))),
        );
        // unlock(bytes) with any data — the no-op callback settles nothing.
        let mut cd = Vec::new();
        cd.extend_from_slice(&0x48c8_9491_u32.to_be_bytes());
        cd.extend_from_slice(&alloy_primitives::U256::from(0x20).to_be_bytes::<32>());
        cd.extend_from_slice(&alloy_primitives::U256::from(0).to_be_bytes::<32>());
        let tx = TxEnv::builder()
            .caller(exec)
            .kind(TxKind::Call(pm))
            .data(Bytes::from(cd))
            .gas_limit(1_000_000)
            .build()
            .unwrap();
        let mut evm = <crate::engine::SimContext<
            CacheDB<crate::fork::ForkDb<provider::LiveHttp, provider::ThreadSleeper>>,
        >>::new(db, SpecId::PRAGUE)
        .modify_cfg_chained(|cfg| {
            cfg.disable_nonce_check = true;
            cfg.disable_eip3607 = true;
        })
        .build_mainnet();
        let result = evm.transact_commit(tx).expect("evm runs");
        eprintln!("DEBUG v4 noop unlock: {result:?}");
        assert!(result.is_success(), "noop unlock failed: {result:?}");
    }

    /// Replays a real RHC V4 pool swap through the unlock/settlement stub on
    /// a block-pinned fork. The `PoolManager` executes its real `unlock`;
    /// the stub performs the re-entrant `swap`, pays the input via
    /// `transfer`+`settle`, and pulls the output via `take` with the
    /// swap's own return delta. Read-only; nothing is broadcast.
    #[test]
    #[ignore = "live: needs the RHC gateway; run with --ignored"]
    #[allow(clippy::too_many_lines)]
    fn fork_v4_leg_replay_matches_local_quote() {
        use provider::{ChainReader, LiveHttp, ProviderBudget, RetryPolicy, ThreadSleeper};
        use revm::database::CacheDB;
        use revm::handler::{ExecuteCommitEvm, MainBuilder};
        use revm::primitives::hardfork::SpecId;
        use std::time::Duration;

        use crate::fork::{ForkTx, fork_transact};

        let rpc = std::env::var("ROBINHOOD_HTTP_RPC_URL")
            .unwrap_or_else(|_| "https://rpc.mainnet.chain.robinhood.com".to_owned());
        let reader = ChainReader::new(
            LiveHttp::new(rpc.parse().expect("valid rpc url")),
            ThreadSleeper,
            // Diagnostic test on the unmetered public gateway: a generous
            // budget because candidate probing reads several pools.
            ProviderBudget::new(20_000_000, 1 << 24),
            RetryPolicy {
                max_retries: 6,
                initial_delay: Duration::from_secs(2),
                max_delay: Duration::from_secs(30),
            },
            4663,
        );
        reader.validate_chain_id().expect("chain id");
        let head = reader.current_block().expect("head");
        let block = head - 2;
        let pm = pool_manager_address();

        // Manifest V4 candidates with key immutables resolved from each
        // pool's Initialize event (raw eth_getLogs 2026-08-27; the manifest
        // fee_numerator is an OBSERVED fee and differs from the key fee on
        // several pools). The event's hooks word is a non-key artifact; the
        // key derives canonically with hooks = address(0) for every pool
        // probed. Native-currency pools are skipped (payment path differs).
        // Active pools (recent Swap events) resolve to dynamic-fee keys
        // (sentinel 0x800000): the fee charged comes from the hook at swap
        // time, so the output check below uses a sanity band, and the stub
        // pulls the pool's own return delta via take().
        let candidates: [(alloy_primitives::B256, Address, Address, u32, i32, Address); 3] = [
            (
                "0xab044f2db051cd39aecb7ed0d2f9facd5731ff9387f9648e72e9e5803257be79"
                    .parse()
                    .unwrap(),
                "0x1c338e6b0e02a8212544f962d3cc619b53fbbd6d"
                    .parse()
                    .unwrap(),
                "0xd0601ce157db5bdc3162bbac2a2c8af5320d9eec"
                    .parse()
                    .unwrap(),
                0,
                200,
                "0xe5e702641ea86f4ae6cc3cdaed2b886f976be044"
                    .parse()
                    .unwrap(),
            ),
            (
                "0x23bcbfacd38446f8beaeb3af134e7028a2c385149b2fae415fe83775bb9a404b"
                    .parse()
                    .unwrap(),
                "0xafe41f4356c24f716111de1fbbc84e061d291e18"
                    .parse()
                    .unwrap(),
                "0xB90A19ff0Af67F7779aFF50a882A9CFF42446400"
                    .parse()
                    .unwrap(),
                8_388_608,
                8,
                "0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544"
                    .parse()
                    .unwrap(),
            ),
            (
                "0x001cf1577c95c4dc5d85a3e57157781247d4aca8964dab1bc2a3cfebe400aa52"
                    .parse()
                    .unwrap(),
                "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168"
                    .parse()
                    .unwrap(),
                "0x8e62F281f282686fCa6dCB39288069a93fC23F1c"
                    .parse()
                    .unwrap(),
                15_600,
                312,
                Address::ZERO,
            ),
        ];

        // Canonical poolId derivation — must reproduce the Initialize
        // topic1 for every candidate (verified live 2026-08-27).
        let derive_id = |c0: Address,
                         c1: Address,
                         fee: u32,
                         ts: i32,
                         hooks: Address|
         -> alloy_primitives::B256 {
            let mut buf = Vec::with_capacity(160);
            buf.extend_from_slice(c0.into_word().as_slice());
            buf.extend_from_slice(c1.into_word().as_slice());
            buf.extend_from_slice(&U256::from(fee).to_be_bytes::<32>());
            buf.extend_from_slice(&U256::from(ts.cast_unsigned()).to_be_bytes::<32>());
            buf.extend_from_slice(hooks.into_word().as_slice());
            alloy_primitives::keccak256(buf)
        };

        let mut pool_id = alloy_primitives::B256::ZERO;
        let mut currency0 = Address::ZERO;
        let mut currency1 = Address::ZERO;
        let mut fee: u32 = 0;
        let mut tick_spacing: i32 = 0;
        let mut hooks = Address::ZERO;
        let mut sqrt_p = U256::ZERO;
        let mut liquidity = U256::ZERO;
        let mut last_swap_fee: Option<u32> = None;
        for (id, c0, c1, f, ts, hk) in candidates {
            assert_eq!(
                derive_id(c0, c1, f, ts, hk).as_slice(),
                id.as_slice(),
                "key derivation must reproduce the Initialize poolId"
            );
            let state_slot = |slot: u64| -> U256 {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(id.as_slice());
                buf[32..].copy_from_slice(&U256::from(slot).to_be_bytes::<32>());
                U256::from_be_bytes(alloy_primitives::keccak256(buf).0)
            };
            // In-range liquidity: the fork's State layout hides it from
            // plain storage probes, so take it from the pool's most recent
            // Swap event (word 4 = liquidity, canonical V4 Swap data).
            let swap_topic: alloy_primitives::B256 =
                "0x40e9cecb9f5f1f1c5b9c97dec2917b7ee92e57ba5563708daca94dd84ad7112f"
                    .parse()
                    .unwrap();
            let swaps = reader
                .get_logs(&provider::LogFilter {
                    from_block: block.saturating_sub(2_000),
                    to_block: block,
                    addresses: vec![pm],
                    topic0: swap_topic,
                    topic0_alternates: Vec::new(),
                })
                .unwrap_or_default();
            let id_hex = id.to_string().to_ascii_lowercase();
            let swap_log = swaps.iter().find(|log| {
                log["topics"].as_array().is_some_and(|t| {
                    t.len() >= 2
                        && t[1]
                            .as_str()
                            .is_some_and(|v| v.to_ascii_lowercase() == id_hex)
                })
            });
            let Some(swap_log) = swap_log else {
                eprintln!("DEBUG v4 cand fee={f} ts={ts}: no recent swap");
                continue;
            };
            let Some(sd) = swap_log["data"]
                .as_str()
                .and_then(|d| alloy_primitives::hex::decode(d.trim_start_matches("0x")).ok())
            else {
                continue;
            };
            if sd.len() < 192 {
                continue;
            }
            // Canonical V4 Swap data: [amount0, amount1, sqrtP, liquidity,
            // tick, fee]. Word 3 = liquidity; word 5 = the fee the hook
            // charged (the dynamic-fee observation task 3.1 needs).
            let liq = U256::from_be_slice(&sd[96..128])
                & ((U256::from(1) << U256::from(128)) - U256::from(1));
            last_swap_fee = Some(u32::try_from(U256::from_be_slice(&sd[160..192])).unwrap_or(fee));
            let slot0 = reader
                .storage_at(pm, state_slot(6), block)
                .unwrap_or_default()
                & ((U256::from(1) << U256::from(160)) - U256::from(1));
            eprintln!("DEBUG v4 cand fee={f} ts={ts} swap_liq={liq}");
            if !slot0.is_zero() && !liq.is_zero() {
                pool_id = id;
                currency0 = c0;
                currency1 = c1;
                fee = f;
                tick_spacing = ts;
                hooks = hk;
                sqrt_p = slot0;
                liquidity = liq;
                break;
            }
            eprintln!("DEBUG v4 cand fee={f} ts={ts} slot0={slot0} liq={liq}");
            if !slot0.is_zero() && !liq.is_zero() {
                pool_id = id;
                currency0 = c0;
                currency1 = c1;
                fee = f;
                tick_spacing = ts;
                hooks = hk;
                sqrt_p = slot0;
                liquidity = liq;
                break;
            }
        }
        assert!(
            !pool_id.is_zero() && !liquidity.is_zero(),
            "no candidate pool is live (key resolved + in-range liquidity)"
        );
        let sqrt_p_f = f64_of_sqrt(sqrt_p);
        let l_f = u256_to_f64(liquidity);
        eprintln!(
            "DEBUG v4 pool fee={fee} tickSpacing={tick_spacing} hooks={hooks} sqrtP={sqrt_p} L={liquidity}"
        );

        let balance_of = |token: Address, who: Address| -> U256 {
            let mut cd = Vec::with_capacity(36);
            cd.extend_from_slice(&0x70a0_8231_u32.to_be_bytes()); // balanceOf
            cd.extend_from_slice(&who.into_word().0);
            let out = reader
                .call(token, &Bytes::from(cd), block)
                .expect("balanceOf");
            U256::from_be_slice(&out)
        };
        // The PoolManager holds every V4 reserve; size the input from its
        // REAL currency1 balance (unbacked virtual liquidity would revert).
        let pm_out_balance = balance_of(currency1, pm);
        assert!(!pm_out_balance.is_zero(), "PM holds no currency1");
        let exec = executor_address();
        let pm_in_balance = balance_of(currency0, pm);
        assert!(!pm_in_balance.is_zero(), "PM holds no currency0");
        let exec_in = balance_of(currency0, exec);
        assert!(exec_in.is_zero(), "executor unexpectedly funded");

        // Input: target 0.1% of the PM's real currency1 balance.
        let l_sqrt = l_f * sqrt_p_f;
        let target_out_f = u256_to_f64(pm_out_balance) / 1000.0;
        let f = (target_out_f / l_sqrt).min(5.0e-5);
        let input_f = l_f * f / sqrt_p_f;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let input = U256::from(input_f.max(1_000.0) as u128);
        // First-order expected output: dy = aIn * P with the fee on input.
        // The key fee may be the dynamic sentinel; the OBSERVED fee from the
        // pool's last swap is the best estimate of what the hook will charge.
        let observed_fee = last_swap_fee.unwrap_or(fee);
        eprintln!("DEBUG v4 observed fee={observed_fee} (key fee {fee})");
        let expected_out_f =
            input_f * (1_000_000.0 - f64::from(observed_fee)) / 1_000_000.0 * sqrt_p_f * sqrt_p_f;

        // Fund the executor by replaying a real ERC-20 transfer FROM the
        // PoolManager (which holds currency0 reserves) — no storage-layout
        // probing needed. Simulation only: nothing is broadcast. The
        // settlement stub is then deployed into the post-funding overlay.
        let ForkTx {
            db,
            result: fund_result,
        } = fork_transact(
            reader,
            block,
            pm,
            currency0,
            crate::engine::encode_transfer(exec, input),
        )
        .expect("fork db");
        assert!(
            fund_result
                .as_ref()
                .is_ok_and(revm::context_interface::result::ExecutionResult::is_success),
            "executor funding transfer reverted: {fund_result:?}"
        );
        let mut db = db;
        db.insert_account_info(
            exec,
            revm::state::AccountInfo::from_bytecode(Bytecode::new_legacy(
                v4_unlock_callback_runtime(),
            )),
        );

        let intent = V4SwapIntent {
            currency0,
            currency1,
            fee,
            tick_spacing,
            hooks,
            zero_for_one: true,
            amount_specified: input,
            sqrt_price_limit: min_sqrt_ratio_plus_1(),
            currency_in: currency0,
            currency_out: currency1,
        };
        let tx = TxEnv::builder()
            .caller(exec)
            .kind(TxKind::Call(pm))
            .data(Bytes::from(encode_v4_unlock(&intent)))
            .gas_limit(5_000_000)
            .build()
            .unwrap();
        let mut evm = <crate::engine::SimContext<
            CacheDB<crate::fork::ForkDb<provider::LiveHttp, provider::ThreadSleeper>>,
        >>::new(db, SpecId::PRAGUE)
        .modify_cfg_chained(|cfg| {
            cfg.disable_nonce_check = true;
            cfg.disable_eip3607 = true;
        })
        .build_mainnet();
        let result = evm.transact_commit(tx).expect("evm runs");
        assert!(result.is_success(), "forked v4 swap reverted: {result:?}");

        // Received: the currency1 Transfer(PM -> exec) log's data word.
        let exec_word = exec.into_word();
        let received = result
            .logs()
            .iter()
            .filter(|log| {
                log.address == currency1
                    && log.topics().len() == 3
                    && log.topics()[0] == TRANSFER_TOPIC
                    && log.topics()[2] == exec_word
            })
            .map(|log| U256::from_be_slice(&log.data.data))
            .fold(U256::ZERO, |a, v| a.checked_add(v).unwrap_or(U256::MAX));
        let received_f = u256_to_f64(received);
        // Dynamic fee: the hook sets the fee at swap time, so the received
        // amount must fall in [50%, 100%] of the zero-fee first-order
        // expectation; the implied fee is reported as a diagnostic.
        let implied_fee_pct = (1.0 - received_f / expected_out_f) * 100.0;
        eprintln!(
            "v4 fork replay: block={block} input={input} received={received} expected~{expected_out_f:.0} implied_fee={implied_fee_pct:.3}%"
        );
        assert!(received > U256::ZERO, "executor must receive currency1");
        assert!(
            received_f <= expected_out_f * 1.001 && received_f >= expected_out_f * 0.5,
            "received {received_f:.0} outside the dynamic-fee band [50%,100%] of {expected_out_f:.0}"
        );
    }
    fn f64_of_sqrt(sqrt: U256) -> f64 {
        u256_to_f64(sqrt) / 2f64.powi(96)
    }

    /// Lossy f64 conversion for diagnostic math only (never the gate).
    #[allow(clippy::cast_precision_loss)]
    fn u256_to_f64(value: U256) -> f64 {
        let bits = value.to_be_bytes::<32>();
        let high = u128::from_be_bytes(bits[..16].try_into().unwrap());
        let low = u128::from_be_bytes(bits[16..].try_into().unwrap());
        high as f64 * 2f64.powi(128) + low as f64
    }
}

#[cfg(test)]
mod gate_probes {
    use alloy_primitives::keccak256;
    #[test]
    #[ignore = "diagnostic"]
    fn probe_swap_signature_wide() {
        let key = "(address,address,uint24,int24,address)";
        let fields = [
            "bool", "int256", "int128", "uint160", "uint128", "uint24", "address", "bytes",
            "bytes32", "uint256",
        ];
        // Selectors forwarded inside a real router swap tx (decoded
        // 2026-08-28): the router passes the PM address + inner payloads.
        let targets = [
            "b56079fd", "6a90e8e3", "a50271ca",
            // earlier dispatcher unknowns, kept for coverage
            "5750565b", "708daca9", "c7d39266", "efd1fc6a", "96168273", "18c639ce", "d76453e0",
            "988d2681", "4549b62c", "18c6db6d",
        ];
        let want: Vec<[u8; 4]> = targets
            .iter()
            .map(|t| {
                let mut b = [0u8; 4];
                for i in 0..4 {
                    b[i] = u8::from_str_radix(&t[2 * i..2 * i + 2], 16).unwrap();
                }
                b
            })
            .collect();
        for a in fields {
            for b in fields {
                for c in fields {
                    for d in fields {
                        for tail in ["", ",bytes", ",bytes,bytes"] {
                            for pr in [
                                format!("({a},{b},{c},{d})"),
                                format!("({a},{b},{c},{d},bytes)"),
                                format!("({a},{b},{c},{d},bytes,bytes)"),
                                format!("({a},{b},{c},{d},bytes32)"),
                            ] {
                                let sig = format!("swap({key},{pr}{tail})");
                                let h = keccak256(sig.as_bytes());
                                if want.iter().any(|w| *w == h[..4]) {
                                    println!(
                                        "SWAPSIG 0x{} {sig}",
                                        alloy_primitives::hex::encode(&h[..4])
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        println!("wide brute done");
    }

    #[test]
    #[ignore = "diagnostic"]
    fn probe_gpo_selectors() {
        for sig in [
            "baseFee()",
            "scalar()",
            "overhead()",
            "l1BaseFee()",
            "gasPrice()",
            "l1Fee(uint256)",
        ] {
            let h = keccak256(sig.as_bytes());
            println!("GPO {sig} = 0x{}", alloy_primitives::hex::encode(&h[..4]));
        }
    }
}
