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
    fn push4(&mut self, value: u32) {
        self.push(&value.to_be_bytes());
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

    /// `sqrtPriceX96` (Q64.96) as f64.
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
