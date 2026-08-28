//! Offline EVM harness shared by the crate's tests.
//!
//! Seeds a `CacheDB<EmptyDB>` with assembled fixture bytecode, runs single
//! `transferFrom`/`balanceOf` transactions through the same revm-42 `Context`
//! pipeline the engine uses, and reads committed storage back out. No RPC, no
//! network — mirrors the engine's [`crate::engine::run_tx`].

use crate::db::balance_slot;
use crate::tokens::{TokenSpec, token_bytecode};
use alloy_primitives::{Address, Bytes, U256};
use revm::database::CacheDB;
use revm::database_interface::EmptyDB;
use revm::state::AccountInfo;

/// Address used as the `msg.sender` — and default `from` — in the harness.
pub const CACHE_CALLER: Address = Address::with_last_byte(0xC0);

/// Distinct fixture address whose last byte is `n`.
///
/// Fixture accounts must live **outside the precompile range**
/// (`0x01..=0x1f` under recent forks): a call to a precompile address
/// dispatches to the builtin implementation and never reaches seeded
/// bytecode, which manifests as transfers "succeeding" with empty output
/// and no state change. Prefixing with `0xfe` keeps every fixture address
/// far above the precompile window.
pub(crate) const fn fixture_addr(n: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[0] = 0xfe;
    bytes[19] = n;
    Address::new(bytes)
}

/// A seeded in-memory database plus the surrounding bookkeeping the fixture
/// tests drive.
pub struct Cache {
    pub db: CacheDB<EmptyDB>,
}

/// A fresh, empty `CacheDB<EmptyDB>`.
#[must_use]
pub fn cache() -> Cache {
    Cache {
        db: CacheDB::default(),
    }
}

/// Installs the assembled [`token_bytecode`] for `token` as its account code.
pub fn deploy_token(cache: &mut Cache, token: Address, spec: TokenSpec) {
    let info = AccountInfo::from_bytecode(token_bytecode(spec));
    cache.db.insert_account_info(token, info);
}

/// Sets `balanceOf(holder)` of `token` to `amount` in the fixture layout.
pub fn seed_balance(cache: &mut Cache, token: Address, holder: Address, amount: U256) {
    cache
        .db
        .insert_account_storage(token, balance_slot(holder), amount)
        .expect("EmptyDB error type is infallible");
}

/// Runs one committed `transferFrom(from, to, amount)` against the assembled
/// token. `Err(reason)` when the transfer reverts or halts.
pub fn transfer_from(
    cache: &mut Cache,
    token: Address,
    from: Address,
    to: Address,
    amount: U256,
) -> Result<(), String> {
    let data = crate::engine::encode_transfer_from(from, to, amount);
    let db = std::mem::take(&mut cache.db);
    let (outcome, db) = crate::engine::run_tx(db, CACHE_CALLER, token, data);
    cache.db = db;
    let result = outcome?;
    if result.is_success() {
        Ok(())
    } else {
        Err(format!("{result:?}"))
    }
}

/// Runs one committed `transfer(to, amount)` against the assembled token —
/// the caller (`CACHE_CALLER`) debits itself. `Err(reason)` when the transfer
/// reverts or halts.
pub fn transfer(
    cache: &mut Cache,
    token: Address,
    to: Address,
    amount: U256,
) -> Result<(), String> {
    let data = crate::engine::encode_transfer(to, amount);
    let db = std::mem::take(&mut cache.db);
    let (outcome, db) = crate::engine::run_tx(db, CACHE_CALLER, token, data);
    cache.db = db;
    let result = outcome?;
    if result.is_success() {
        Ok(())
    } else {
        Err(format!("{result:?}"))
    }
}

/// Queries `balanceOf(who)` of `token` through the assembled `balanceOf` path
/// (side-effect-free: runs on a throwaway clone).
#[must_use]
pub fn balance_of(cache: &Cache, token: Address, who: Address) -> U256 {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&0x70a0_8231_u32.to_be_bytes());
    data.extend_from_slice(&who.into_word().0);
    let (outcome, _db) =
        crate::engine::run_tx(cache.db.clone(), CACHE_CALLER, token, Bytes::from(data));
    match outcome {
        Ok(result) if result.is_success() => result
            .into_output()
            .map(|out| U256::from_be_slice(&out))
            .unwrap_or_default(),
        _ => U256::ZERO,
    }
}
