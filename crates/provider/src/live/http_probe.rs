//! A bounded HTTP log poller standing in for the filtered WebSocket
//! subscription on chains whose provider rejects the `address`/`topics`
//! options of `eth_subscribe` `logs` (Alchemy RHC as of 2026-08-06).
//!
//! The poller drives [`crate::ChainReader::get_logs`] over a cadence and
//! presents each decoded `Sync` envelope through the same [`WsProbe`]
//! interface, so the observation loops are transport-agnostic.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use alloy_primitives::Address;

use crate::live::ws::WsProbe;
use crate::{
    ChainReader, HttpBackend, LogFilter, LogStream, RawLogEnvelope, Sleeper, StreamError,
    StreamItem, TransportError, sync_topic,
};

struct PollState {
    queue: VecDeque<RawLogEnvelope>,
    /// Highest block already fetched through (inclusive).
    high_water: u64,
    /// Cumulative logs that arrived but failed to decode (audit B11).
    decode_failures: u64,
    last_poll: Option<Instant>,
}

/// Fetches `Sync` logs for a fixed address set from the chain tip and yields
/// them one at a time. Each [`WsProbe::next`] call waits up to `window` for a
/// log, matching the quiet-window semantics of the WebSocket client it
/// replaces.
pub struct LiveHttpProbe<R, S> {
    reader: ChainReader<R, S>,
    addresses: Vec<Address>,
    cadence: Duration,
    state: RefCell<PollState>,
}

impl<R: HttpBackend, S: Sleeper> LiveHttpProbe<R, S> {
    /// Creates a poller reading logs strictly newer than `start_block`.
    #[must_use]
    pub fn new(
        reader: ChainReader<R, S>,
        addresses: Vec<Address>,
        start_block: u64,
        cadence: Duration,
    ) -> Self {
        Self {
            reader,
            addresses,
            cadence,
            state: RefCell::new(PollState {
                queue: VecDeque::new(),
                high_water: start_block,
                decode_failures: 0,
                last_poll: None,
            }),
        }
    }

    fn poll_once(&self) -> Result<bool, StreamError> {
        let latest = self.reader.current_block().map_err(to_stream)?;
        let high_water = self.state.borrow().high_water;
        if latest <= high_water {
            return Ok(false);
        }
        let filter = LogFilter {
            from_block: high_water + 1,
            to_block: latest,
            addresses: self.addresses.clone(),
            topic0: sync_topic(),
        };
        let values = self.reader.get_logs(&filter).map_err(to_stream)?;
        // Audit B11: undecodable logs previously vanished silently — 100%
        // decode failure looked identical to "no activity", the worst
        // failure mode to debug. Count both sides and escalate when every
        // log in a non-empty response failed to decode.
        let (envelopes, decode_failures) = decode_all(&values);
        {
            let mut state = self.state.borrow_mut();
            state.decode_failures += decode_failures as u64;
            state.high_water = latest;
        }
        if !values.is_empty() && envelopes.is_empty() {
            return Err(StreamError::Decode(format!(
                "all {} logs in window {}..{latest} failed to decode",
                values.len(),
                high_water + 1
            )));
        }
        if envelopes.is_empty() {
            return Ok(false);
        }
        self.state.borrow_mut().queue.extend(envelopes);
        Ok(true)
    }
}

/// Splits raw log values into decoded envelopes and a failure count
/// (audit B11).
fn decode_all(values: &[serde_json::Value]) -> (Vec<RawLogEnvelope>, usize) {
    let mut envelopes = Vec::with_capacity(values.len());
    let mut failures = 0usize;
    for value in values {
        match RawLogEnvelope::from_rpc_value(value) {
            Ok(envelope) => envelopes.push(envelope),
            Err(_) => failures += 1,
        }
    }
    (envelopes, failures)
}

impl<R: HttpBackend, S: Sleeper> WsProbe for LiveHttpProbe<R, S> {
    fn next(
        &self,
        _stream: &LogStream,
        window: Duration,
    ) -> Result<Option<StreamItem>, StreamError> {
        if let Some(envelope) = self.state.borrow_mut().queue.pop_front() {
            return Ok(Some(StreamItem::Log(envelope)));
        }
        let deadline = Instant::now() + window;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            if let Some(at) = self.state.borrow().last_poll
                && now < at + self.cadence
            {
                let until = at + self.cadence;
                std::thread::sleep(until.duration_since(now).min(deadline.duration_since(now)));
                continue;
            }
            self.state.borrow_mut().last_poll = Some(now);
            if self.poll_once()?
                && let Some(envelope) = self.state.borrow_mut().queue.pop_front()
            {
                return Ok(Some(StreamItem::Log(envelope)));
            }
        }
    }
}

fn to_stream(error: TransportError) -> StreamError {
    match error {
        TransportError::Budget(budget) => StreamError::Budget(budget),
        error => StreamError::Transport(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::{HttpResponse, RpcRequest, TransportError, sync_topic};

    #[derive(Clone, Default)]
    struct FakeBackend {
        calls: Arc<Mutex<Vec<String>>>,
        blocks: Arc<Mutex<Vec<u64>>>,
    }

    impl HttpBackend for FakeBackend {
        fn request(&self, request: &RpcRequest) -> Result<HttpResponse, TransportError> {
            self.calls.lock().unwrap().push(request.method.clone());
            let result = if request.method == "eth_blockNumber" {
                let block = self.blocks.lock().unwrap().pop().unwrap_or(10);
                serde_json::json!(format!("0x{block:x}"))
            } else {
                serde_json::json!([{
                    "address": format!("0x{}", alloy_primitives::hex::encode([0x10; 20])),
                    "topics": [format!("{}", sync_topic())],
                    "data": format!("0x{}", "00".repeat(64)),
                    "blockNumber": "0xb",
                    "transactionIndex": "0x0",
                    "logIndex": "0x0",
                    "removed": false,
                }])
            };
            Ok(HttpResponse {
                result,
                response_bytes: 0,
            })
        }
    }

    fn reader(backend: FakeBackend) -> ChainReader<FakeBackend, crate::ThreadSleeper> {
        ChainReader::new(
            backend,
            crate::ThreadSleeper,
            crate::ProviderBudget::new(10_000_000, 10_000_000),
            crate::RetryPolicy {
                max_retries: 0,
                initial_delay: std::time::Duration::ZERO,
                max_delay: std::time::Duration::ZERO,
            },
            4663,
        )
    }

    #[test]
    fn yields_logs_from_tip_window() {
        let backend = FakeBackend {
            blocks: Arc::new(Mutex::new(vec![11])),
            ..Default::default()
        };
        let probe = LiveHttpProbe::new(
            reader(backend.clone()),
            vec![Address::from_slice(&[0x10; 20])],
            10,
            Duration::from_millis(1),
        );
        let stream = LogStream::new(crate::ProviderBudget::new(10_000_000, 10_000_000));
        let item = probe
            .next(&stream, Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert!(matches!(item, StreamItem::Log(_)));
        assert!(
            backend
                .calls
                .lock()
                .unwrap()
                .contains(&"eth_getLogs".to_owned())
        );
    }

    #[test]
    fn stays_quiet_when_tip_has_not_advanced() {
        let backend = FakeBackend::default();
        let probe = LiveHttpProbe::new(
            reader(backend.clone()),
            vec![Address::from_slice(&[0x10; 20])],
            10,
            Duration::from_millis(1),
        );
        let stream = LogStream::new(crate::ProviderBudget::new(10_000_000, 10_000_000));
        // Tip (10) has not advanced past the start block; no fetch, no logs.
        let item = probe.next(&stream, Duration::from_millis(50)).unwrap();
        assert!(item.is_none());
        assert!(
            !backend
                .calls
                .lock()
                .unwrap()
                .contains(&"eth_getLogs".to_owned())
        );
    }
}
