//! A revm `Database` implementation backed by read-only JSON-RPC reads at
//! one pinned block.
//!
//! This is the fork half of the pre-broadcast simulator: pool and token
//! contracts execute their *real* bytecode against the chain's *real* state
//! at a chosen block, while overrides (executor bytecode, seeded balances)
//! layer on top via `CacheDB<ForkDb>` exactly as fixtures do over
//! `CacheDB<EmptyDB>`. Reads are lazily fetched, cached per run, and never
//! broadcast anything.
use std::cell::RefCell;
use std::collections::HashMap;

use alloy_primitives::{Address, B256, U256};
use provider::{ChainReader, HttpBackend, Sleeper, TransportError};
use revm::database_interface::{DBErrorMarker, Database, DatabaseRef};
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
    accounts: RefCell<HashMap<Address, AccountInfo>>,
    storage: RefCell<HashMap<(Address, U256), U256>>,
    block_hashes: RefCell<HashMap<u64, B256>>,
}

impl<B: HttpBackend, S: Sleeper> ForkDb<B, S> {
    /// Pins the database to `block`; every read targets that state root.
    #[must_use]
    pub fn new(reader: ChainReader<B, S>, block: u64) -> Self {
        Self {
            reader,
            block,
            accounts: RefCell::new(HashMap::new()),
            storage: RefCell::new(HashMap::new()),
            block_hashes: RefCell::new(HashMap::new()),
        }
    }

    /// The pinned block every read targets.
    #[must_use]
    pub fn block(&self) -> u64 {
        self.block
    }

    /// The pinned-block reader, for direct RPC reads alongside EVM execution.
    #[must_use]
    pub fn reader(&self) -> &ChainReader<B, S> {
        &self.reader
    }
}

/// The result of one forked transaction: revm's execution outcome plus the
/// post-state database (mutations committed into the `CacheDB` overlay).
pub struct ForkTx<B: HttpBackend, S: Sleeper> {
    /// revm's committed result (`None`-free: EVM halts are reported inside).
    pub result: Result<revm::context_interface::result::ExecutionResult, String>,
    /// Post-state database; reuse it to chain further transactions.
    pub db: revm::database::CacheDB<ForkDb<B, S>>,
}

/// Executes one transaction against the pinned block's real state. This is
/// the primitive every fork replay builds on: route steps run as successive
/// `fork_transact` calls sharing one `CacheDB`, so pool mutations accumulate
/// exactly as they would in a live bundle.
///
/// # Errors
///
/// Returns [`ForkDbError`] if constructing the database fails; EVM-level
/// reverts surface inside [`ForkTx::result`].
pub fn fork_transact<B: HttpBackend + 'static, S: Sleeper + 'static>(
    reader: ChainReader<B, S>,
    block: u64,
    caller: Address,
    to: Address,
    data: alloy_primitives::Bytes,
) -> Result<ForkTx<B, S>, ForkDbError> {
    let db = revm::database::CacheDB::new(ForkDb::new(reader, block));
    let (result, db) = crate::engine::run_tx(db, caller, to, data);
    Ok(ForkTx { result, db })
}

impl<B: HttpBackend, S: Sleeper> ForkDb<B, S> {
    fn basic_inner(&self, address: Address) -> Result<Option<AccountInfo>, ForkDbError> {
        if let Some(info) = self.accounts.borrow().get(&address) {
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
        self.accounts.borrow_mut().insert(address, info.clone());
        Ok(Some(info))
    }

    fn code_by_hash_inner(&self, code_hash: B256) -> Result<Bytecode, ForkDbError> {
        for info in self.accounts.borrow().values() {
            if info.code_hash == code_hash {
                return Ok(info.code.clone().unwrap_or_default());
            }
        }
        Err(ForkDbError::UnknownCodeHash(code_hash))
    }

    fn storage_inner(&self, address: Address, index: U256) -> Result<U256, ForkDbError> {
        if let Some(value) = self.storage.borrow().get(&(address, index)) {
            return Ok(*value);
        }
        let value = self.reader.storage_at(address, index, self.block)?;
        self.storage.borrow_mut().insert((address, index), value);
        Ok(value)
    }

    fn block_hash_inner(&self, number: u64) -> Result<B256, ForkDbError> {
        if let Some(hash) = self.block_hashes.borrow().get(&number) {
            return Ok(*hash);
        }
        let hash = B256::from(self.reader.block_hash(number)?);
        self.block_hashes.borrow_mut().insert(number, hash);
        Ok(hash)
    }
}

impl<B: HttpBackend, S: Sleeper> DatabaseRef for ForkDb<B, S> {
    type Error = ForkDbError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.basic_inner(address)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.code_by_hash_inner(code_hash)
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.storage_inner(address, index)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.block_hash_inner(number)
    }
}

impl<B: HttpBackend, S: Sleeper> Database for ForkDb<B, S> {
    type Error = ForkDbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.basic_inner(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.code_by_hash_inner(code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.storage_inner(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.block_hash_inner(number)
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

    #[test]
    fn fork_transact_executes_real_code_and_returns_output() {
        // The "contract": MSTORE(0, 0x2a) then RETURN(0, 32) — a deterministic
        // 32-byte answer proving code was fetched from the fork and executed.
        // Only the target carries code; the caller must stay a plain account.
        use std::sync::{Arc, Mutex};
        struct FnBackend {
            contract_hex: String,
            seen: Arc<Mutex<usize>>,
        }
        impl HttpBackend for FnBackend {
            fn request(&self, request: &RpcRequest) -> Result<HttpResponse, TransportError> {
                match request.method.as_str() {
                    "eth_getCode" => {
                        *self.seen.lock().unwrap() += 1;
                        let target = request.params[0].as_str().unwrap_or_default();
                        Ok(HttpResponse {
                            result: Value::String(
                                if target.eq_ignore_ascii_case(&self.contract_hex) {
                                    "0x602a60005260206000f3".into()
                                } else {
                                    "0x".into()
                                },
                            ),
                            response_bytes: 10,
                        })
                    }
                    "eth_getBalance" | "eth_getTransactionCount" => Ok(HttpResponse {
                        // Even-length quantity strings only: the transport
                        // layer hex-decodes balances as bytes.
                        result: Value::String("0x0000000000000000".into()),
                        response_bytes: 10,
                    }),
                    other => Err(TransportError::Permanent(format!("unexpected {other}"))),
                }
            }
        }
        let contract = Address::repeat_byte(0xcc);
        let contract_hex = format!("0x{}", alloy_primitives::hex::encode(contract));
        let seen = Arc::new(Mutex::new(0_usize));
        let reader = ChainReader::new(
            FnBackend {
                contract_hex,
                seen: Arc::clone(&seen),
            },
            NoSleeper,
            provider::ProviderBudget::new(u64::MAX, 1 << 24),
            provider::RetryPolicy {
                max_retries: 0,
                initial_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
            },
            4663,
        );
        let tx = fork_transact(
            reader,
            9,
            Address::repeat_byte(0x11),
            contract,
            Bytes::new(),
        )
        .expect("database constructs");
        let result = tx.result.expect("execution succeeds");
        let output = result.output().expect("contract returned data");
        let mut expected = [0u8; 32];
        expected[31] = 0x2a;
        assert_eq!(output.as_ref(), &expected[..]);
        // Code was served from the fork (revm may re-validate the caller, so
        // only a lower bound holds).
        assert!(*seen.lock().unwrap() >= 1);
    }
}
