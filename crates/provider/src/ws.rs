use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use serde_json::{Value, json};
use thiserror::Error;

use crate::{BudgetExceeded, ProviderBudget};

#[must_use]
pub fn sync_topic() -> B256 {
    keccak256("Sync(uint112,uint112)")
}

/// Decodes a `Sync(uint112,uint112)` log `data` payload into `(reserve0,
/// reserve1)`. The ABI packs each `uint112` into its own 32-byte word.
#[must_use]
pub fn decode_sync_reserves(data: &Bytes) -> Option<(U256, U256)> {
    if data.len() < 64 {
        return None;
    }
    Some((
        U256::from_be_slice(&data[..32]),
        U256::from_be_slice(&data[32..64]),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionFilter {
    pub addresses: Vec<Address>,
    pub topic0: B256,
}

impl SubscriptionFilter {
    /// Builds an explicit address- and topic-filtered logs subscription request.
    ///
    /// # Errors
    ///
    /// Returns an error when no pool addresses are supplied.
    pub fn request(&self) -> Result<Value, StreamError> {
        if self.addresses.is_empty() {
            return Err(StreamError::EmptyAddressFilter);
        }
        Ok(json!(["logs", { "address": self.addresses, "topics": [self.topic0] }]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLogEnvelope {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
    pub block_number: u64,
    pub transaction_index: u64,
    pub log_index: u64,
    pub removed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectKind {
    Clean,
    Dirty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamItem {
    Log(RawLogEnvelope),
    Disconnected(DisconnectKind),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StreamError {
    #[error("provider budget exceeded: {0}")]
    Budget(#[from] BudgetExceeded),
    #[error("subscription requires at least one pool address")]
    EmptyAddressFilter,
    #[error("invalid WebSocket log message")]
    InvalidMessage,
    /// Logs arrived but none decoded (audit B11): schema drift used to look
    /// identical to "no activity".
    #[error("log decode failure: {0}")]
    Decode(String),
    #[error("provider transport error: {0}")]
    Transport(String),
}

pub struct LogStream {
    budget: ProviderBudget,
}

impl LogStream {
    #[must_use]
    pub fn new(budget: ProviderBudget) -> Self {
        Self { budget }
    }

    /// Accounts and decodes one raw subscription payload without deduplication
    /// or pool-state mutation.
    ///
    /// # Errors
    ///
    /// Returns an error when the WebSocket budget is exhausted or the payload is
    /// not a complete Ethereum log envelope.
    pub fn message(&self, payload: &str) -> Result<StreamItem, StreamError> {
        self.budget.charge_ws_message(payload.len())?;
        let value: Value =
            serde_json::from_str(payload).map_err(|_| StreamError::InvalidMessage)?;
        let log = value
            .pointer("/params/result")
            .ok_or(StreamError::InvalidMessage)?;
        Ok(StreamItem::Log(RawLogEnvelope {
            address: parse(log, "address")?,
            topics: serde_json::from_value(
                log.get("topics")
                    .cloned()
                    .ok_or(StreamError::InvalidMessage)?,
            )
            .map_err(|_| StreamError::InvalidMessage)?,
            data: parse(log, "data")?,
            block_number: quantity(log, "blockNumber")?,
            transaction_index: quantity(log, "transactionIndex")?,
            log_index: quantity(log, "logIndex")?,
            removed: log.get("removed").and_then(Value::as_bool).unwrap_or(false),
        }))
    }

    #[must_use]
    pub const fn disconnected(clean: bool) -> StreamItem {
        StreamItem::Disconnected(if clean {
            DisconnectKind::Clean
        } else {
            DisconnectKind::Dirty
        })
    }
}

impl RawLogEnvelope {
    /// Decodes one raw `eth_getLogs` result object into an envelope.
    ///
    /// Used by the HTTP-backed poller where the provider refuses the
    /// `address`/`topics` options of an `eth_subscribe` `logs` request.
    ///
    /// # Errors
    ///
    /// Returns [`StreamError::InvalidMessage`] when a required field is absent
    /// or malformed.
    pub fn from_rpc_value(value: &Value) -> Result<Self, StreamError> {
        Ok(Self {
            address: parse(value, "address")?,
            topics: serde_json::from_value(
                value
                    .get("topics")
                    .cloned()
                    .ok_or(StreamError::InvalidMessage)?,
            )
            .map_err(|_| StreamError::InvalidMessage)?,
            data: parse(value, "data")?,
            block_number: quantity(value, "blockNumber")?,
            transaction_index: quantity(value, "transactionIndex")?,
            log_index: quantity(value, "logIndex")?,
            removed: value
                .get("removed")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }
}

fn parse<T: serde::de::DeserializeOwned>(value: &Value, field: &str) -> Result<T, StreamError> {
    serde_json::from_value(
        value
            .get(field)
            .cloned()
            .ok_or(StreamError::InvalidMessage)?,
    )
    .map_err(|_| StreamError::InvalidMessage)
}

fn quantity(value: &Value, field: &str) -> Result<u64, StreamError> {
    let encoded = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(StreamError::InvalidMessage)?;
    u64::from_str_radix(encoded.trim_start_matches("0x"), 16)
        .map_err(|_| StreamError::InvalidMessage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_rpc_value_decodes_raw_getlogs_object() {
        let value = serde_json::json!({
            "address": "0x0000000000000000000000000000000000000010",
            "topics": [format!("{}", sync_topic())],
            "data": "0x000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000003c",
            "blockNumber": "0x2a",
            "transactionIndex": "0x1",
            "logIndex": "0x2",
            "removed": false,
        });
        let envelope = RawLogEnvelope::from_rpc_value(&value).unwrap();
        assert_eq!(envelope.address, Address::with_last_byte(0x10));
        assert_eq!(envelope.block_number, 0x2a);
        assert_eq!(envelope.transaction_index, 1);
        assert_eq!(envelope.log_index, 2);
        assert_eq!(envelope.topics.len(), 1);
        assert_eq!(envelope.data.len(), 64);
        assert!(!envelope.removed);
    }

    #[test]
    fn from_rpc_value_rejects_missing_fields() {
        let value = serde_json::json!({ "address": "0x0000000000000000000000000000000000000010" });
        assert!(RawLogEnvelope::from_rpc_value(&value).is_err());
    }
}
