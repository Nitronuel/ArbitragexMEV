use std::time::Duration;

use alloy_primitives::{Address, B256, Bytes, U256};
use serde_json::{Value, json};
use thiserror::Error;

use crate::{BudgetExceeded, ProviderBudget};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcRequest {
    pub method: String,
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub result: Value,
    pub response_bytes: usize,
}

/// Builds the JSON-RPC `topics[0]` value: a single topic, or an array when
/// alternates are present.
fn topics_param(topic0: B256, alternates: &[B256]) -> Value {
    if alternates.is_empty() {
        json!(format!("0x{topic0:x}"))
    } else {
        let all: Vec<String> = std::iter::once(format!("0x{topic0:x}"))
            .chain(alternates.iter().map(|t| format!("0x{t:x}")))
            .collect();
        json!(all)
    }
}

/// Providers signal oversized log queries with varying messages; all known
/// shapes name the result count or the log size (audit B12).
fn is_result_cap_error(error: &TransportError) -> bool {
    let message = match error {
        TransportError::Permanent(m) | TransportError::Transient(m) => m.to_ascii_lowercase(),
        _ => return false,
    };
    message.contains("query returned more than")
        || message.contains("log response size exceeded")
        || message.contains("more than 10000")
        || message.contains("response size exceeded")
}

/// Outcome of [`ChainReader::get_logs_with_progress`] (audit B12).
#[derive(Debug, Default)]
pub struct LogsProgress {
    /// All logs fetched from contiguous coverage starting at `from_block`.
    pub logs: Vec<Value>,
    /// Highest block such that every block in `[from_block..=last_covered]`
    /// was fetched. Never advances past an unfetched or failed block.
    pub last_covered_block: u64,
    /// Set only when fetching stopped early.
    pub error: Option<TransportError>,
}

pub struct LogFilter {
    pub from_block: u64,
    pub to_block: u64,
    pub addresses: Vec<Address>,
    pub topic0: B256,
    /// Extra first-position topics accepted in addition to `topic0`
    /// (JSON-RPC `topics[0]` array). Empty = exact match only.
    /// Audit task 1.3: the ring sweep accepts Swap + liquidity-change
    /// events so cache invalidation sees Mint/Burn without a Swap.
    pub topic0_alternates: Vec<B256>,
}

pub trait HttpBackend {
    /// Sends one JSON-RPC request without retry or budget policy.
    ///
    /// # Errors
    ///
    /// Returns a classified transient or permanent transport error.
    fn request(&self, request: &RpcRequest) -> Result<HttpResponse, TransportError>;
}

pub trait Sleeper {
    fn sleep(&self, duration: Duration);
}

/// A `Sleeper` that blocks the calling thread for the requested duration.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_retries: u8,
    pub initial_delay: Duration,
    pub max_delay: Duration,
}

impl RetryPolicy {
    #[must_use]
    pub fn delay(&self, retry: u8) -> Duration {
        let factor = 1_u32.checked_shl(u32::from(retry)).unwrap_or(u32::MAX);
        self.initial_delay
            .saturating_mul(factor)
            .min(self.max_delay)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TransportError {
    #[error("provider budget exceeded: {0}")]
    Budget(#[from] BudgetExceeded),
    #[error("transient transport error: {0}")]
    Transient(String),
    #[error("permanent transport error: {0}")]
    Permanent(String),
    #[error("unexpected chain ID {0}")]
    WrongChain(u64),
    #[error("invalid JSON-RPC response")]
    InvalidResponse,
    #[error("log range requires at least one address")]
    EmptyAddressFilter,
    #[error("invalid block range")]
    InvalidBlockRange,
}

pub struct ChainReader<B, S> {
    backend: B,
    sleeper: S,
    budget: ProviderBudget,
    retry: RetryPolicy,
    expected_chain_id: u64,
}

impl<B: HttpBackend, S: Sleeper> ChainReader<B, S> {
    #[must_use]
    pub fn new(
        backend: B,
        sleeper: S,
        budget: ProviderBudget,
        retry: RetryPolicy,
        expected_chain_id: u64,
    ) -> Self {
        Self {
            backend,
            sleeper,
            budget,
            retry,
            expected_chain_id,
        }
    }

    /// Reads and validates the provider chain ID.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, budget, malformed-response, or wrong-chain
    /// failures.
    pub fn validate_chain_id(&self) -> Result<(), TransportError> {
        let chain_id = self.chain_id()?;
        if chain_id != self.expected_chain_id {
            return Err(TransportError::WrongChain(chain_id));
        }
        Ok(())
    }

    /// Reads the provider chain ID.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, budget, or malformed-response failures.
    pub fn chain_id(&self) -> Result<u64, TransportError> {
        let response = self.execute(&RpcRequest {
            method: "eth_chainId".to_owned(),
            params: json!([]),
        })?;
        quantity(&response.result)
    }

    /// Reads the current (latest) block number.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, budget, or malformed-response failures.
    pub fn current_block(&self) -> Result<u64, TransportError> {
        let response = self.execute(&RpcRequest {
            method: "eth_blockNumber".to_owned(),
            params: json!([]),
        })?;
        quantity(&response.result)
    }

    /// Reads contract bytecode at a block.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, budget, or malformed-response failures.
    pub fn code(&self, address: Address, block: u64) -> Result<Vec<u8>, TransportError> {
        let response = self.execute(&RpcRequest {
            method: "eth_getCode".to_owned(),
            params: json!([address_hex(address), hex_block(block)]),
        })?;
        result_bytes(&response.result)
    }

    /// Executes one `eth_call` against a block and returns the raw return bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, budget, or malformed-response failures.
    pub fn call(&self, to: Address, data: &Bytes, block: u64) -> Result<Bytes, TransportError> {
        let response = self.execute(&RpcRequest {
            method: "eth_call".to_owned(),
            params: json!([{ "to": address_hex(to), "data": bytes_hex(data) }, hex_block(block)]),
        })?;
        result_bytes(&response.result).map(Bytes::from)
    }

    /// Reads one storage slot of an account at a block.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, budget, or malformed-response failures.
    pub fn storage_at(
        &self,
        address: Address,
        index: alloy_primitives::U256,
        block: u64,
    ) -> Result<alloy_primitives::U256, TransportError> {
        let response = self.execute(&RpcRequest {
            method: "eth_getStorageAt".to_owned(),
            params: json!([
                address_hex(address),
                format!("0x{:064x}", index),
                hex_block(block)
            ]),
        })?;
        let raw = result_bytes(&response.result)?;
        if raw.len() > 32 {
            return Err(TransportError::Permanent(
                "storage value exceeds 32 bytes".to_owned(),
            ));
        }
        Ok(alloy_primitives::U256::from_be_slice(&raw))
    }

    /// Reads an account's native balance at a block.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, budget, or malformed-response failures.
    pub fn balance(
        &self,
        address: Address,
        block: u64,
    ) -> Result<alloy_primitives::U256, TransportError> {
        let response = self.execute(&RpcRequest {
            method: "eth_getBalance".to_owned(),
            params: json!([address_hex(address), hex_block(block)]),
        })?;
        // Audit B6: eth_getBalance returns a minimal QUANTITY ("0x0",
        // "0xde0b6b3a7640000") — the old path hex-DECODED it as byte data,
        // so every odd-nibble balance (including zero) failed as
        // InvalidResponse.
        quantity_u256(&response.result)
    }

    /// Reads an account's transaction count (nonce) at a block.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, budget, or malformed-response failures.
    pub fn transaction_count(&self, address: Address, block: u64) -> Result<u64, TransportError> {
        let response = self.execute(&RpcRequest {
            method: "eth_getTransactionCount".to_owned(),
            params: json!([address_hex(address), hex_block(block)]),
        })?;
        quantity(&response.result)
    }

    /// Reads the current network gas price in wei per gas unit
    /// (`eth_gasPrice`).
    ///
    /// The result is parsed as a hex QUANTITY string — not byte data — so a
    /// minimally encoded value like `"0x1"` decodes correctly (the `balance()`
    /// path's defect, audit B6, is deliberately not replicated here).
    ///
    /// # Errors
    ///
    /// Returns an error for transport, budget, or malformed-response
    /// failures.
    /// Reads a V3/V4 pool's `slot0()` — `(sqrtPriceX96, tick, ...)` packed
    /// return — returning the price root and tick (audit task 1.3 refresh).
    ///
    /// Selector `0x3850c7bd`; verified working against live RHC pools.
    ///
    /// # Errors
    ///
    /// Transport, budget, or malformed-response failures.
    pub fn pool_slot0(&self, pool: Address) -> Result<(U256, i32), TransportError> {
        let response = self.execute(&RpcRequest {
            method: "eth_call".to_owned(),
            params: json!([{"to": address_hex(pool), "data": "0x3850c7bd"}, "latest"]),
        })?;
        let raw = result_bytes(&response.result)?;
        if raw.len() < 64 {
            return Err(TransportError::InvalidResponse);
        }
        let sqrt = U256::try_from_be_slice(&raw[..32]).ok_or(TransportError::InvalidResponse)?;
        // int24 occupies the low 3 bytes of the word (right-aligned,
        // big-endian); sign-extend the top bit of byte 31's high nibble.
        let b29 = raw[61];
        let b30 = raw[62];
        let b31 = raw[63];
        if raw[60] != 0 || raw[59] != 0 || raw[58] != 0 {
            return Err(TransportError::InvalidResponse);
        }
        let sign = if b29 & 0x80 != 0 { 0xff_u8 } else { 0x00_u8 };
        let tick = i32::from_be_bytes([sign, b29, b30, b31]);
        Ok((sqrt, tick))
    }

    /// Reads a V3/V4 pool's in-range `liquidity()` (selector `0x1a686502`).
    ///
    /// # Errors
    ///
    /// Transport, budget, or malformed-response failures.
    /// # Errors
    ///
    /// Transport, budget, or malformed-response failures.
    pub fn pool_liquidity(&self, pool: Address) -> Result<U256, TransportError> {
        let response = self.execute(&RpcRequest {
            method: "eth_call".to_owned(),
            params: json!([{"to": address_hex(pool), "data": "0x1a686502"}, "latest"]),
        })?;
        quantity_u256(&response.result)
    }

    /// # Errors
    ///
    /// Transport, budget, or malformed-response failures.
    pub fn gas_price(&self) -> Result<U256, TransportError> {
        let response = self.execute(&RpcRequest {
            method: "eth_gasPrice".to_owned(),
            params: json!([]),
        })?;
        quantity_u256(&response.result)
    }

    /// Reads one historical block hash by number.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, budget, or malformed-response failures,
    /// or [`TransportError::InvalidResponse`] when the provider does not know
    /// the block.
    pub fn block_hash(&self, number: u64) -> Result<[u8; 32], TransportError> {
        let response = self.execute(&RpcRequest {
            method: "eth_getBlockByNumber".to_owned(),
            params: json!([hex_block(number), false]),
        })?;
        if response.result.is_null() {
            return Err(TransportError::InvalidResponse);
        }
        let raw = response
            .result
            .get("hash")
            .and_then(|h| h.as_str())
            .ok_or(TransportError::InvalidResponse)?;
        let bytes = alloy_primitives::hex::decode(raw.trim_start_matches("0x"))
            .map_err(|_| TransportError::InvalidResponse)?;
        bytes
            .try_into()
            .map_err(|_| TransportError::InvalidResponse)
    }

    /// Fetches explicitly filtered logs in provider-safe chunks of at most ten
    /// inclusive blocks.
    ///
    /// # Errors
    ///
    /// Returns an error for empty filters, invalid ranges, transport, budget, or
    /// malformed-response failures.
    pub fn get_logs(&self, filter: &LogFilter) -> Result<Vec<Value>, TransportError> {
        self.get_logs_windowed(filter, 10)
    }

    /// Fetches explicitly filtered logs in windows of at most `window` inclusive
    /// blocks per `eth_getLogs` request, with at least one block per window.
    ///
    /// # Errors
    ///
    /// Returns an error for empty filters, invalid ranges, transport, budget, or
    /// malformed-response failures.
    pub fn get_logs_windowed(
        &self,
        filter: &LogFilter,
        window: u64,
    ) -> Result<Vec<Value>, TransportError> {
        if filter.addresses.is_empty() {
            return Err(TransportError::EmptyAddressFilter);
        }
        if filter.from_block > filter.to_block {
            return Err(TransportError::InvalidBlockRange);
        }
        let window = window.max(1);
        let mut logs = Vec::new();
        let mut start = filter.from_block;
        loop {
            let end = start
                .saturating_add(window.saturating_sub(1))
                .min(filter.to_block);
            let response = self.execute(&RpcRequest {
                method: "eth_getLogs".to_owned(),
                params: json!([{
                    "fromBlock": format!("0x{start:x}"),
                    "toBlock": format!("0x{end:x}"),
                    "address": filter.addresses,
                    "topics": [topics_param(
                        filter.topic0,
                        &filter.topic0_alternates,
                    )],
                }]),
            })?;
            let chunk = response
                .result
                .as_array()
                .ok_or(TransportError::InvalidResponse)?;
            logs.extend(chunk.iter().cloned());
            if end == filter.to_block {
                break;
            }
            start = end + 1;
        }
        Ok(logs)
    }

    /// Fetches logs over `[from_block..=to_block]` with **result-cap
    /// bisection and partial progress** (audit B12/B13).
    ///
    /// Returns everything fetched so far plus the highest contiguously
    /// covered block. `error` is set only when fetching could not continue:
    /// a provider result-cap error is bisected down to single blocks (so a
    /// hot window never wedges the poller), and any other failure stops
    /// iteration with all completed windows retained. Callers advance their
    /// high-water mark to `last_covered_block`, never past it — skipping a
    /// failed range is now structurally impossible.
    #[must_use]
    pub fn get_logs_with_progress(&self, filter: &LogFilter, window: u64) -> LogsProgress {
        let mut progress = LogsProgress::default();
        if filter.addresses.is_empty() || filter.from_block > filter.to_block {
            progress.error = Some(TransportError::InvalidBlockRange);
            return progress;
        }
        let window = window.max(1);
        let mut start = filter.from_block;
        while start <= filter.to_block {
            let end = start
                .saturating_add(window.saturating_sub(1))
                .min(filter.to_block);
            match self.fetch_log_range(filter, start, end) {
                Ok(mut chunk) => {
                    progress.logs.append(&mut chunk);
                    progress.last_covered_block = end;
                    start = end + 1;
                }
                Err(error) => {
                    // Cap-classified failures on a multi-block window are
                    // retried by bisection before giving up.
                    if is_result_cap_error(&error) && end > start {
                        let (mut chunk, covered, retry_error) =
                            self.fetch_range_bisecting(filter, start, end);
                        progress.logs.append(&mut chunk);
                        progress.last_covered_block = covered;
                        if retry_error.is_none() {
                            // Bisection fully covered [start..=end].
                            start = end + 1;
                            continue;
                        }
                        progress.error = retry_error;
                        return progress;
                    }
                    progress.error = Some(error);
                    return progress;
                }
            }
        }
        progress
    }

    fn fetch_log_range(
        &self,
        filter: &LogFilter,
        start: u64,
        end: u64,
    ) -> Result<Vec<Value>, TransportError> {
        let response = self.execute(&RpcRequest {
            method: "eth_getLogs".to_owned(),
            params: json!([{
                "fromBlock": format!("0x{start:x}"),
                "toBlock": format!("0x{end:x}"),
                "address": filter.addresses,
                "topics": [filter.topic0],
            }]),
        })?;
        response
            .result
            .as_array()
            .cloned()
            .ok_or(TransportError::InvalidResponse)
    }

    /// Depth-first left-to-right bisection of one cap-limited range.
    /// Returns `(logs, last_contiguous_covered, terminal_error)` — the
    /// error when a sub-range fails for a non-cap reason or a single block
    /// still exceeds the cap.
    fn fetch_range_bisecting(
        &self,
        filter: &LogFilter,
        start: u64,
        end: u64,
    ) -> (Vec<Value>, u64, Option<TransportError>) {
        let mut logs = Vec::new();
        let mut stack: Vec<(u64, u64)> = vec![(start, end)];
        while let Some((lo, hi)) = stack.pop() {
            match self.fetch_log_range(filter, lo, hi) {
                Ok(mut chunk) => logs.append(&mut chunk),
                Err(error) => {
                    let cap = is_result_cap_error(&error);
                    if !cap || lo == hi {
                        // Non-cap failure mid-bisection, or a single block
                        // still over the cap: stop, keeping contiguous work.
                        return (logs, lo.saturating_sub(1), Some(error));
                    }
                    let mid = lo + (hi - lo) / 2;
                    // Right half first (stack), so left completes first and
                    // `last_covered` stays contiguous with prior progress.
                    stack.push((mid + 1, hi));
                    stack.push((lo, mid));
                }
            }
        }
        // Fully bisected successfully — caller continues from `end`.
        (logs, end, None)
    }

    fn execute(&self, request: &RpcRequest) -> Result<HttpResponse, TransportError> {
        let mut retries = 0;
        loop {
            self.budget.charge_http(&request.method, 0)?;
            match self.backend.request(request) {
                Ok(response) => {
                    self.budget.charge_http_response(response.response_bytes)?;
                    return Ok(response);
                }
                Err(TransportError::Transient(_)) if retries < self.retry.max_retries => {
                    self.sleeper.sleep(self.retry.delay(retries));
                    retries += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

/// Parses a hex QUANTITY string into U256 (audit B6): balances and gas
/// prices arrive minimally encoded, so byte-decoding them fails on odd
/// nibble counts.
fn quantity_u256(result: &Value) -> Result<U256, TransportError> {
    let text = result.as_str().ok_or(TransportError::InvalidResponse)?;
    let digits = text
        .strip_prefix("0x")
        .ok_or(TransportError::InvalidResponse)?;
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(TransportError::InvalidResponse);
    }
    U256::from_str_radix(digits, 16).map_err(|_| TransportError::InvalidResponse)
}

fn quantity(result: &Value) -> Result<u64, TransportError> {
    let encoded = result.as_str().ok_or(TransportError::InvalidResponse)?;
    u64::from_str_radix(encoded.trim_start_matches("0x"), 16)
        .map_err(|_| TransportError::InvalidResponse)
}

fn result_bytes(result: &Value) -> Result<Vec<u8>, TransportError> {
    let encoded = result.as_str().ok_or(TransportError::InvalidResponse)?;
    hex_to_bytes(encoded)
}

fn hex_block(block: u64) -> String {
    format!("0x{block:x}")
}

fn address_hex(address: Address) -> String {
    format!("0x{}", alloy_primitives::hex::encode(address))
}

fn bytes_hex(data: &Bytes) -> String {
    format!("0x{}", alloy_primitives::hex::encode(data))
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, TransportError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    alloy_primitives::hex::decode(hex).map_err(|_| TransportError::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn quantity_parses_hex() {
        assert_eq!(quantity(&json!("0x2105")), Ok(8453));
        assert!(quantity(&json!(null)).is_err());
        assert!(quantity(&json!("zz")).is_err());
    }

    #[test]
    fn quantity_u256_parses_minimal_quantities() {
        // Audit B6: minimal encodings must parse — the byte-decode path
        // rejected every odd-nibble value including zero.
        assert_eq!(quantity_u256(&json!("0x0")), Ok(U256::ZERO));
        assert_eq!(
            quantity_u256(&json!("0xde0b6b3a7640000")),
            Ok(U256::from(1_000_000_000_000_000_000u128))
        );
        assert!(quantity_u256(&json!("0x")).is_err());
        assert!(quantity_u256(&json!(7)).is_err());
    }

    #[test]
    fn result_cap_errors_are_classified() {
        assert!(is_result_cap_error(&TransportError::Permanent(
            "query returned more than 10000 results".to_owned()
        )));
        assert!(is_result_cap_error(&TransportError::Permanent(
            "Log response size exceeded".to_owned()
        )));
        assert!(!is_result_cap_error(&TransportError::Permanent(
            "execution reverted".to_owned()
        )));
        assert!(!is_result_cap_error(&TransportError::InvalidResponse));
    }

    #[test]
    fn hex_transforms_roundtrip() {
        let address = Address::with_last_byte(0xaa);
        assert_eq!(address_hex(address).len(), 42);
        assert_eq!(
            hex_to_bytes(&address_hex(Address::with_last_byte(0xaa))).unwrap(),
            Address::with_last_byte(0xaa).as_slice()
        );
        let bytes = Bytes::from_static(&[0xde_u8, 0xad]);
        assert_eq!(bytes_hex(&bytes), "0xdead");
        assert_eq!(hex_to_bytes("0xdead").unwrap(), vec![0xde, 0xad]);
    }
}
