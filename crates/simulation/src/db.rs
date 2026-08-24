//! Builds an in-memory revm `CacheDB<EmptyDB>` for one quoted round trip.
//!
//! Everything comes from local state the shadow loop already caches — pair
//! reserves reduced to constant-product form and the pool/token addresses — so
//! no `eth_getCode`, fork, or provider is ever touched.

use alloy_primitives::{Address, U256};
use revm::bytecode::Bytecode;
use revm::database::CacheDB;
use revm::database_interface::EmptyDB;
use revm::primitives::StorageKey;
use revm::state::AccountInfo;
use std::collections::BTreeMap;

/// `balanceOf(holder)` lives at `storage[holder]` (the holder's raw 20-byte
/// address right-aligned in a storage word), so a pool's reserve of a token is
/// that token's storage at slot `pool`. This matches the `SLOAD`/`SSTORE`
/// lookups in [`crate::tokens`], so seeding is a plain storage write.
#[must_use]
pub fn balance_slot(holder: Address) -> StorageKey {
    StorageKey::from_be_bytes(holder.into_word().0)
}

/// One leg of the round trip: the pool account and its two token addresses and
/// the pool's pair reserves (constant-product, after virtual-reserve
/// reduction).
#[derive(Debug, Clone, Copy)]
pub struct Reserves {
    pub pool: Address,
    pub token_in: Address,
    pub token_out: Address,
    pub reserve_in: U256,
    pub reserve_out: U256,
}

/// Builds the `CacheDB` for a two-hop round trip through `[leg0, leg1]`.
///
/// `tokens` is the full set of token accounts (addresses); `seed` maps each
/// token to its starting `holder -> balance`. The pools' reserves are seeded
/// as those tokens' balances at the pool address (see [`balance_slot`]).
/// Every token gets its assembled bytecode from `code`; pools and the
/// executor get plain nonce-0 accounts.
///
/// # Panics
///
/// Panics if the underlying `EmptyDB` reports a storage-insert error, which
/// is infallible in practice.
pub fn build_cache(
    leg0: Reserves,
    leg1: Reserves,
    tokens: &[Address],
    seed: &BTreeMap<Address, BTreeMap<Address, U256>>,
    code: impl Fn(Address) -> Bytecode,
    executor: Address,
) -> CacheDB<EmptyDB> {
    let mut cache = CacheDB::default();

    // One token account per token: assembled code + `balanceOf(holder) =
    // seed[token][holder]`.
    for token in tokens {
        cache.insert_account_info(*token, AccountInfo::from_bytecode(code(*token)));
        if let Some(balances) = seed.get(token) {
            for (holder, amount) in balances {
                // `insert_account_storage` needs `ExtDB: DatabaseRef`; `EmptyDB`
                // has `Error = Infallible`.
                cache
                    .insert_account_storage(*token, balance_slot(*holder), *amount)
                    .expect("EmptyDB error type is infallible");
            }
        }
    }

    // A pool's reserve of a token is that token's balance at the pool address.
    for leg in [leg0, leg1] {
        cache
            .insert_account_storage(leg.token_in, balance_slot(leg.pool), leg.reserve_in)
            .expect("EmptyDB error type is infallible");
        cache
            .insert_account_storage(leg.token_out, balance_slot(leg.pool), leg.reserve_out)
            .expect("EmptyDB error type is infallible");
    }

    // Pool and executor accounts: funded callers/holders with no code.
    cache.insert_account_info(leg0.pool, AccountInfo::default());
    cache.insert_account_info(leg1.pool, AccountInfo::default());
    cache.insert_account_info(executor, AccountInfo::default());
    cache
}

/// Reads `storage[slot]` for an address from a `CacheDB` (the committed
/// cached state the interpreter writes into).
#[must_use]
pub fn read_slot(cache: &CacheDB<EmptyDB>, address: Address, slot: StorageKey) -> Option<U256> {
    let account = cache.cache.accounts.get(&address)?;
    account.storage.get(&slot).copied()
}
