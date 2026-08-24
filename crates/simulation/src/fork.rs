//! A revm `Database` implementation backed by read-only JSON-RPC reads at
//! one pinned block.
//!
//! This is the fork half of the pre-broadcast simulator: pool and token
//! contracts execute their *real* bytecode against the chain's *real* state
//! at a chosen block, while overrides (executor bytecode, seeded balances)
//! layer on top via `CacheDB<ForkDb>` exactly as fixtures do over
//! `CacheDB<EmptyDB>`. Reads are lazily fetched, cached per run, and never
//! broadcast anything.
use std::collections::HashMap;

use alloy_primitives::{Address, B256, U256};
use provider::{ChainReader, HttpBackend, Sleeper, TransportError};
use revm::database_interface::{DBErrorMarker, Database};
use revm::state::{AccountInfo, Bytecode};

#[cfg(test)]
use serde_json::Value;

/// Errors a forked read can fail with.
#[derive(Debug, thiserror::Error)]
pub enum ForkDbError {
    /// The underlying JSON-RPC transport failed (transient or permanent).
    #[error("fork transport error: {0}")]
    Transport(#[from] TransportError),
    /// revm asked for code by hash that no fetched account carries. `ForkDb`
    /// always attaches code in `basic`, so this indicates an inconsistent
    /// provider rather than missing state.
    #[error("code hash {0} was never fetched by basic()")]
    UnknownCodeHash(B256),
}

impl DBErrorMarker for ForkDbError {}

/// A lazily-fetched view of one block's state.
///
/// Generic over the transport backend and sleeper so tests can drive it from
/// canned responses; production wires `ChainReader<LiveHttp, ThreadSleeper>`.
pub struct ForkDb<B: HttpBackend, S: Sleeper> {
    reader: ChainReader<B, S>,
    block: u64,
    accounts: HashMap<Address, AccountInfo>,
    storage: HashMap<(Address, U256), U256>,
    block_hashes: HashMap<u64, B256>,
}

impl<B: HttpBackend, S: Sleeper> ForkDb<B, S> {
    /// Pins the database to `block`; every read targets that state root.
    #[must_use]
    pub fn new(reader: ChainReader<B, S>, block: u64) -> Self {
        Self {
            reader,
            block,
            accounts: HashMap::new(),
            storage: HashMap::new(),
            block_hashes: HashMap::new(),
        }
    }

    /// The pinned block every read targets.
    #[must_use]
    pub fn block(&self) -> u64 {
        self.block
    }
}

impl<B: HttpBackend, S: Sleeper> Database for ForkDb<B, S> {
    type Error = ForkDbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(info) = self.accounts.get(&address) {
            return Ok(Some(info.clone()));
        }
        let balance = self.reader.balance(address, self.block)?;
        let nonce = self.reader.transaction_count(address, self.block)?;
        let code = self.reader.code(address, self.block)?;
        // An account with no code and default fields is nonexistent for EVM
        // purposes; reporting `None` keeps touched-EOA semantics correct.
        if balance.is_zero() && nonce == 0 && code.is_empty() {
            return Ok(None);
        }
        let bytecode = Bytecode::new_legacy(code.into());
        let info = AccountInfo {
            balance,
            nonce,
            code_hash: bytecode.hash_slow(),
            account_id: None,
            code: Some(bytecode),
        };
        self.accounts.insert(address, info.clone());
        Ok(Some(info))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        // `basic` always attaches code, so revm never needs to resolve a hash
        // it has not seen; reaching here means an inconsistent provider.
        for info in self.accounts.values() {
            if info.code_hash == code_hash {
                return Ok(info.code.clone().unwrap_or_default());
            }
        }
        Err(ForkDbError::UnknownCodeHash(code_hash))
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        if let Some(value) = self.storage.get(&(address, index)) {
            return Ok(*value);
        }
        let value = self.reader.storage_at(address, index, self.block)?;
        self.storage.insert((address, index), value);
        Ok(value)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        if let Some(hash) = self.block_hashes.get(&number) {
            return Ok(*hash);
        }
        let hash = B256::from(self.reader.block_hash(number)?);
        self.block_hashes.insert(number, hash);
        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Shared request recorder handed out by `Canned::new`.
    type SeenLog = std::rc::Rc<RefCell<Vec<(String, Value)>>>;
    use alloy_primitives::Bytes;
    use provider::{HttpBackend, HttpResponse, RpcRequest, Sleeper, TransportError};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::time::Duration;

    /// Serves canned `result` payloads per RPC method, recording requests.
    /// The recorder is shared (`Rc`) so tests can assert on transport counts
    /// after the reader has consumed the backend.
    struct Canned {
        results: RefCell<HashMap<&'static str, VecDeque<Result<Value, String>>>>,
        seen: SeenLog,
    }

    impl Canned {
        fn new(entries: Vec<(&'static str, Result<Value, String>)>) -> (Self, SeenLog) {
            let mut results: HashMap<&'static str, VecDeque<Result<Value, String>>> =
                HashMap::new();
            for (method, result) in entries {
                results.entry(method).or_default().push_back(result);
            }
            let seen = std::rc::Rc::new(RefCell::new(Vec::new()));
            (
                Self {
                    results: RefCell::new(results),
                    seen: std::rc::Rc::clone(&seen),
                },
                seen,
            )
        }
    }

    impl HttpBackend for Canned {
        fn request(&self, request: &RpcRequest) -> Result<HttpResponse, TransportError> {
            self.seen
                .borrow_mut()
                .push((request.method.clone(), request.params.clone()));
            let mut queues = self.results.borrow_mut();
            match queues
                .get_mut(request.method.as_str())
                .and_then(VecDeque::pop_front)
            {
                Some(Ok(value)) => Ok(HttpResponse {
                    result: value,
                    response_bytes: 10,
                }),
                Some(Err(message)) => Err(TransportError::Permanent(message)),
                None => Err(TransportError::Permanent(format!(
                    "no canned response for {}",
                    request.method
                ))),
            }
        }
    }

    struct NoSleeper;

    impl Sleeper for NoSleeper {
        fn sleep(&self, _duration: Duration) {}
    }

    fn word(v: U256) -> Value {
        Value::String(format!("0x{v:064x}"))
    }

    fn db_with(
        entries: Vec<(&'static str, Result<Value, String>)>,
        block: u64,
    ) -> (ForkDb<Canned, NoSleeper>, SeenLog) {
        let (backend, seen) = Canned::new(entries);
        (
            ForkDb::new(
                ChainReader::new(
                    backend,
                    NoSleeper,
                    provider::ProviderBudget::new(u64::MAX, 1 << 24),
                    provider::RetryPolicy {
                        max_retries: 0,
                        initial_delay: Duration::ZERO,
                        max_delay: Duration::ZERO,
                    },
                    4663,
                ),
                block,
            ),
            seen,
        )
    }

    #[test]
    fn basic_returns_none_for_unfunded_unknown_account() {
        let (mut db, _seen) = db_with(
            vec![
                ("eth_getBalance", Ok(word(U256::ZERO))),
                ("eth_getTransactionCount", Ok(Value::String("0x0".into()))),
                ("eth_getCode", Ok(Value::String("0x".into()))),
            ],
            100,
        );
        assert!(
            Database::basic(&mut db, Address::repeat_byte(1))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn basic_attaches_code_and_caches_the_account() {
        let address = Address::repeat_byte(2);
        let (mut db, _seen) = db_with(
            vec![
                ("eth_getBalance", Ok(word(U256::from(7_u64)))),
                ("eth_getTransactionCount", Ok(Value::String("0x3".into()))),
                ("eth_getCode", Ok(Value::String("0x60ff60ff".into()))),
            ],
            100,
        );
        let info = Database::basic(&mut db, address)
            .unwrap()
            .expect("funded account exists");
        assert_eq!(info.balance, U256::from(7));
        assert_eq!(info.nonce, 3);
        assert_eq!(
            info.code.as_ref().expect("code attached").original_bytes(),
            Bytes::from_static(&[0x60, 0xff, 0x60, 0xff])
        );
        // Second read must come from the cache (no further transport).
        let again = Database::basic(&mut db, address).unwrap().expect("cached");
        assert_eq!(again.balance, U256::from(7));
    }

    #[test]
    fn storage_reads_are_cached_per_slot() {
        let address = Address::repeat_byte(3);
        let slot = U256::from(42u64);
        let (mut db, seen) = db_with(
            vec![("eth_getStorageAt", Ok(word(U256::from(0xbeef_u64))))],
            55,
        );
        assert_eq!(
            Database::storage(&mut db, address, slot).unwrap(),
            U256::from(0xbeef)
        );
        assert_eq!(
            Database::storage(&mut db, address, slot).unwrap(),
            U256::from(0xbeef)
        );
        // Exactly one transport read for two lookups.
        assert_eq!(seen.borrow().len(), 1);
    }

    #[test]
    fn block_hash_round_trips_and_errors_on_unknown_block() {
        let hash_bytes = [0xab_u8; 32];
        let (mut db, _seen) = db_with(
            vec![(
                "eth_getBlockByNumber",
                Ok(serde_json::json!({
                    "hash": format!("0x{}", alloy_primitives::hex::encode(hash_bytes))
                })),
            )],
            1,
        );
        assert_eq!(
            Database::block_hash(&mut db, 10).unwrap(),
            B256::new(hash_bytes)
        );
        assert_eq!(
            Database::block_hash(&mut db, 10).unwrap(),
            B256::new(hash_bytes)
        );
        // Unknown block (null result) is an InvalidResponse, not a panic.
        let (mut missing, _seen) = db_with(vec![("eth_getBlockByNumber", Ok(Value::Null))], 1);
        assert!(matches!(
            Database::block_hash(&mut missing, 99),
            Err(ForkDbError::Transport(TransportError::InvalidResponse))
        ));
    }
}
