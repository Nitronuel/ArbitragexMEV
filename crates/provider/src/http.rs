use std::time::Duration;

use alloy_primitives::{Address, B256, Bytes};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogFilter {
    pub from_block: u64,
    pub to_block: u64,
    pub addresses: Vec<Address>,
    pub topic0: B256,
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
    #[error("expected Base chain ID 8453, got {0}")]
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
}

impl<B: HttpBackend, S: Sleeper> ChainReader<B, S> {
    #[must_use]
    pub fn new(backend: B, sleeper: S, budget: ProviderBudget, retry: RetryPolicy) -> Self {
        Self {
            backend,
            sleeper,
            budget,
            retry,
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
        if chain_id != 8453 {
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

    /// Fetches explicitly filtered logs in provider-safe chunks of at most ten
    /// inclusive blocks.
    ///
    /// # Errors
    ///
    /// Returns an error for empty filters, invalid ranges, transport, budget, or
    /// malformed-response failures.
    pub fn get_logs(&self, filter: &LogFilter) -> Result<Vec<Value>, TransportError> {
        if filter.addresses.is_empty() {
            return Err(TransportError::EmptyAddressFilter);
        }
        if filter.from_block > filter.to_block {
            return Err(TransportError::InvalidBlockRange);
        }
        let mut logs = Vec::new();
        let mut start = filter.from_block;
        loop {
            let end = start.saturating_add(9).min(filter.to_block);
            let response = self.execute(&RpcRequest {
                method: "eth_getLogs".to_owned(),
                params: json!([{
                    "fromBlock": format!("0x{start:x}"),
                    "toBlock": format!("0x{end:x}"),
                    "address": filter.addresses,
                    "topics": [filter.topic0],
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
