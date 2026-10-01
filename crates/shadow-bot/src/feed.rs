//! Nitro sequencer-feed trigger lane (shadow side).
//!
//! Stage A1 of the feed-trigger lane: connect to the
//! RHC broadcast feed, log one-line per-message summaries, and optionally
//! capture raw payloads for decoder fixtures. Log-only — nothing here trades,
//! gates, or influences the WS lane. Batch decoding into pool-touch events is
//! stage A2; it consumes the captures recorded here.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use provider::{DisconnectKind, FeedClient, FeedFrame, RedactedUrl};

/// Default RHC Nitro broadcast feed (ordering + calldata, no results).
pub const DEFAULT_FEED_URL: &str = "wss://feed.mainnet.chain.robinhood.com";

/// Resolves `--feed-url` (literal URL or `env:VAR_NAME`), defaulting to
/// [`DEFAULT_FEED_URL`].
///
/// # Errors
///
/// Returns a message when an `env:VAR_NAME` variable is missing.
pub fn resolve_feed_url(arg: Option<&str>) -> Result<String, String> {
    match arg {
        Some(value) => value.strip_prefix("env:").map_or_else(
            || Ok(value.to_owned()),
            |var| std::env::var(var).map_err(|_| format!("missing {var}")),
        ),
        None => Ok(DEFAULT_FEED_URL.to_owned()),
    }
}

/// One-line summary of a raw feed message for `feed: ` log lines.
///
/// Best-effort only: unparseable payloads degrade to a byte count, never an
/// error, so a protocol change shows up as `unparsed` lines instead of a
/// silent lane death.
pub fn summarize_feed_message(text: &str) -> String {
    let bytes = text.len();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return format!("feed: unparsed bytes={bytes}");
    };
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .map_or_else(|| "-".to_owned(), |v| v.to_string());
    let Some(messages) = value.get("messages").and_then(serde_json::Value::as_array) else {
        return format!("feed: bytes={bytes} version={version} msgs=?");
    };
    let mut kinds: BTreeMap<u64, usize> = BTreeMap::new();
    let mut first_seq: Option<u64> = None;
    let mut last_seq: Option<u64> = None;
    for message in messages {
        // Live RHC shape (observed 2026-09-13): each entry carries a top-level
        // `sequenceNumber`; the L1 header nests one level deeper at
        // `message.message.header`.
        if let Some(seq) = message
            .get("sequenceNumber")
            .and_then(serde_json::Value::as_u64)
        {
            first_seq = Some(first_seq.map_or(seq, |first| first.min(seq)));
            last_seq = Some(last_seq.map_or(seq, |last| last.max(seq)));
        }
        if let Some(kind) = message
            .pointer("/message/message/header/kind")
            .and_then(serde_json::Value::as_u64)
        {
            *kinds.entry(kind).or_insert(0) += 1;
        }
    }
    let kinds = kinds
        .iter()
        .map(|(kind, count)| format!("{kind}:{count}"))
        .collect::<Vec<_>>()
        .join(",");
    let seq = match (first_seq, last_seq) {
        (Some(first), Some(last)) => format!("{first}-{last}"),
        _ => "-".to_owned(),
    };
    format!(
        "feed: bytes={bytes} version={version} msgs={} seq={seq} kinds={{{kinds}}}",
        messages.len()
    )
}

/// One envelope message: sequence number plus optional base64 batch payload.
#[derive(Debug, Clone)]
pub struct FeedEnvelope {
    /// Sequence number (= L2 block number on this chain).
    pub seq: Option<u64>,
    /// Sequencer header timestamp (seconds) for backlog filtering.
    pub timestamp: Option<u64>,
    /// Base64 `l2Msg` batch payload, when present.
    pub l2msg: Option<String>,
}

/// Extracts envelope messages from a raw feed payload (never fails — an
/// unparseable frame yields an empty vec and is counted, not fatal).
pub fn extract_messages(text: &str) -> Vec<FeedEnvelope> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(messages) = value.get("messages").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    messages
        .iter()
        .map(|message| FeedEnvelope {
            seq: message
                .get("sequenceNumber")
                .and_then(serde_json::Value::as_u64),
            timestamp: message
                .pointer("/message/message/header/timestamp")
                .and_then(serde_json::Value::as_u64),
            l2msg: message
                .pointer("/message/message/l2Msg")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        })
        .collect()
}

/// Formats one trigger line: `seq<TAB>touch,touch…` where each touch is
/// `a:<40hex>` (address) or `p:<64hex>` (V4 pool id). Empty touch sets log
/// as a bare seq (gap accounting, not agreement input).
pub fn format_trigger(seq: Option<u64>, touches: &[FeedTouch]) -> String {
    let seq = seq.map_or_else(|| "-".to_owned(), |s| s.to_string());
    let mut parts = Vec::with_capacity(touches.len());
    for touch in touches {
        match touch {
            FeedTouch::Address(addr) => {
                parts.push(format!("a:{}", alloy_primitives::hex::encode(addr)));
            }
            FeedTouch::PoolId(id) => {
                parts.push(format!("p:{}", alloy_primitives::hex::encode(id)));
            }
        }
    }
    format!("{seq}\t{}", parts.join(","))
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Bounded log-only feed observation (`feed-watch` command): connects,
/// summarizes every message to stderr, appends raw payloads to `raw_log`
/// when set (fixture capture for stage A2), and decodes pool touches into
/// `touch_log` when set (`seq<TAB>touches` per envelope message — the
/// agreement-harness input, stage A3).
///
/// # Errors
///
/// Returns a message on bad URL, connect failure, or capture-file errors.
/// A mid-run disconnect ends the observation (owner restarts); it is not an
/// error.
pub fn feed_watch_command(
    feed_url: Option<&str>,
    duration_secs: u64,
    raw_log: Option<PathBuf>,
    touch_log: Option<PathBuf>,
    max_backlog_secs: u64,
) -> Result<(), String> {
    let endpoint = resolve_feed_url(feed_url)?;
    let url: RedactedUrl = endpoint
        .parse()
        .map_err(|error: provider::RedactedUrlError| error.to_string())?;
    let mut capture = match raw_log {
        Some(path) => Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|error| format!("open {}: {error}", path.display()))?,
        ),
        None => None,
    };
    let mut triggers = match touch_log {
        Some(path) => Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|error| format!("open {}: {error}", path.display()))?,
        ),
        None => None,
    };
    let client = FeedClient::connect(url).map_err(|error| format!("{error:?}"))?;
    let deadline = Duration::from_secs(duration_secs.max(1));
    let start = Instant::now();
    // Backlog horizon, fixed at connect: envelopes older than this never
    // become triggers (the server replays recent blocks on every connect).
    let horizon = unix_now_secs().saturating_sub(max_backlog_secs);
    let mut messages = 0_u64;
    let mut bytes = 0_u64;
    eprintln!("feed-watch: connected, observing {deadline:?}");
    while start.elapsed() < deadline {
        match client.next(Duration::from_secs(1)) {
            Some(FeedFrame::Text(text)) => {
                messages += 1;
                bytes += text.len() as u64;
                eprintln!("{}", summarize_feed_message(&text));
                if let Some(file) = capture.as_mut() {
                    writeln!(file, "{text}").map_err(|error| format!("write capture: {error}"))?;
                }
                if let Some(file) = triggers.as_mut() {
                    // Backlog replay (the server re-sends recent blocks on
                    // connect) must never become triggers: only envelopes
                    // newer than the backlog horizon emit lines.
                    for envelope in extract_messages(&text) {
                        if envelope.timestamp.unwrap_or(u64::MAX) < horizon {
                            continue;
                        }
                        let mut touches = Vec::new();
                        if let Some(l2msg) = envelope.l2msg
                            && let Ok(txs) = decode_l2msg(&l2msg)
                        {
                            for tx in &txs {
                                touches.extend(touched(tx));
                            }
                        }
                        writeln!(file, "{}", format_trigger(envelope.seq, &touches))
                            .map_err(|error| format!("write triggers: {error}"))?;
                    }
                }
            }
            Some(FeedFrame::Closed(kind)) => {
                let clean = kind == DisconnectKind::Clean;
                eprintln!("feed-watch: disconnected (clean={clean}), ending observation");
                break;
            }
            None => {}
        }
    }
    eprintln!(
        "feed-watch: done messages={messages} bytes={bytes} elapsed={:?}",
        start.elapsed()
    );
    Ok(())
}

/// One sequencer-ordered transaction: eager cheap fields only.
///
/// Mirrors the reference decoder's philosophy (`chainstacklabs /
/// robinhood-chain-sequencer-feed / src / rhfeed / codec.py`): filter on
/// `to_bytes` and `selector` (raw sliced bytes, hash-lookup cost) and never
/// pay for sender recovery on the trigger path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedTx {
    /// Envelope type (0 legacy, 1 2930, 2 1559, 3 blob, 4 7702).
    pub tx_type: u8,
    /// 20-byte recipient, `None` for deployments or unparseable layouts.
    pub to_bytes: Option<[u8; 20]>,
    /// First 4 calldata bytes, `None` for plain transfers / deployments.
    pub selector: Option<[u8; 4]>,
    /// Full calldata (needed for router-leg decoding at promotion).
    pub input: Vec<u8>,
}

/// L2 message kinds carrying user transactions (`arbos/parse_l2.go`).
const L2_BATCH: u8 = 3;
const L2_SIGNED_TX: u8 = 4;

/// Decodes one base64 `l2Msg` payload into sequencer-ordered transactions.
///
/// Unknown inner kinds decode to an empty vec (fail-soft: a protocol addition
/// must never kill the lane; the summary line still counts the message).
///
/// # Errors
///
/// Returns a message when the payload is not valid base64.
pub fn decode_l2msg(b64: &str) -> Result<Vec<FeedTx>, String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|error| format!("bad l2Msg base64: {error}"))?;
    Ok(decode_l2_message(&raw))
}

fn decode_l2_message(payload: &[u8]) -> Vec<FeedTx> {
    let Some((&kind, rest)) = payload.split_first() else {
        return Vec::new();
    };
    match kind {
        L2_SIGNED_TX => decode_transaction(rest).into_iter().collect(),
        L2_BATCH => split_batch(rest).flat_map(decode_l2_message).collect(),
        _ => Vec::new(),
    }
}

/// Splits a batch body into nested L2 messages: repeated `[u64BE
/// length][nested message]`. Stops soft at the first truncation so one
/// malformed tail never discards the decodable prefix.
fn split_batch(payload: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut items = Vec::new();
    let mut offset = 0_usize;
    while offset + 8 <= payload.len() {
        let mut len_bytes = [0_u8; 8];
        len_bytes.copy_from_slice(&payload[offset..offset + 8]);
        let length = usize::try_from(u64::from_be_bytes(len_bytes)).unwrap_or(usize::MAX);
        offset += 8;
        let Some(end) = offset.checked_add(length) else {
            break;
        };
        if length == 0 || end > payload.len() {
            break;
        }
        items.push(&payload[offset..end]);
        offset = end;
    }
    items.into_iter()
}

/// RLP list item payload ranges `(start, end)` for the list at the head of
/// `buf`; `None` on any malformation (never panics on hostile input).
fn scan_rlp_items(buf: &[u8]) -> Option<Vec<(usize, usize)>> {
    let &head = buf.first()?;
    if head < 0xC0 {
        return None;
    }
    let (mut i, end) = if head < 0xF8 {
        (1_usize, 1_usize + usize::from(head - 0xC0))
    } else {
        let n = usize::from(head - 0xF7);
        let len_start = 1_usize.checked_add(n)?;
        let len = usize_from_be(buf.get(1..len_start)?)?;
        (len_start, len_start.checked_add(len)?)
    };
    if end > buf.len() {
        return None;
    }
    let mut out = Vec::new();
    while i < end {
        let c = buf[i];
        let (start, stop) = if c < 0x80 {
            (i, i + 1)
        } else if c < 0xB8 {
            (i + 1, i + 1 + usize::from(c - 0x80))
        } else if c < 0xC0 {
            let n = usize::from(c - 0xB7);
            let start = i.checked_add(1)?.checked_add(n)?;
            (
                start,
                start.checked_add(usize_from_be(buf.get(i + 1..start)?)?)?,
            )
        } else if c < 0xF8 {
            (i + 1, i + 1 + usize::from(c - 0xC0))
        } else {
            let n = usize::from(c - 0xF7);
            let start = i.checked_add(1)?.checked_add(n)?;
            (
                start,
                start.checked_add(usize_from_be(buf.get(i + 1..start)?)?)?,
            )
        };
        if stop > end {
            return None;
        }
        out.push((start, stop));
        i = stop;
    }
    (i == end).then_some(out)
}

fn usize_from_be(bytes: &[u8]) -> Option<usize> {
    if bytes.len() > 8 {
        return None;
    }
    let mut padded = [0_u8; 8];
    padded[8 - bytes.len()..].copy_from_slice(bytes);
    Some(usize::try_from(u64::from_be_bytes(padded)).unwrap_or(usize::MAX))
}

/// Field positions `(nonce, gas, to, value, data)` per envelope type; the
/// signature is always the final three fields.
fn tx_layout(tx_type: u8) -> Option<(usize, usize, usize, usize, usize)> {
    match tx_type {
        0 => Some((0, 2, 3, 4, 5)),     // legacy
        1 => Some((1, 3, 4, 5, 6)),     // 2930
        2..=4 => Some((1, 4, 5, 6, 7)), // 1559, blob, 7702
        _ => None,
    }
}

fn decode_transaction(raw: &[u8]) -> Option<FeedTx> {
    if raw.is_empty() {
        return None;
    }
    let (tx_type, body) = if raw[0] < 0x80 {
        (raw[0], &raw[1..])
    } else {
        (0, raw)
    };
    let layout = tx_layout(tx_type)?;
    let fields = scan_rlp_items(body)?;
    // Payload fields plus v, r, s must all be present.
    if fields.len() < layout.4 + 4 {
        return None;
    }
    let uint = |index: usize| {
        usize_from_be(body.get(fields[index].0..fields[index].1).unwrap_or(&[])).unwrap_or(0)
    };
    let _nonce = uint(layout.0);
    let _gas = uint(layout.1);
    let _value = uint(layout.3);
    let (to_start, to_end) = fields[layout.2];
    let to_bytes: Option<[u8; 20]> = match body.get(to_start..to_end) {
        Some(exact) if exact.len() == 20 => {
            let mut addr = [0_u8; 20];
            addr.copy_from_slice(exact);
            Some(addr)
        }
        _ => None,
    };
    let (data_start, data_end) = fields[layout.4];
    let data = body.get(data_start..data_end).unwrap_or(&[]);
    let selector: Option<[u8; 4]> = data.first_chunk::<4>().copied();
    Some(FeedTx {
        tx_type,
        to_bytes,
        selector,
        input: data.to_vec(),
    })
}

/// RHC router proxy every observed `0x4d819a2a` route goes through
/// (`0x65050a9b7e5075a2ba5ced7b1b64ee66262c40dc`, per live txs — never
/// from memory).
pub const ROUTER_PROXY: [u8; 20] = [
    0x65, 0x05, 0x0a, 0x9b, 0x7e, 0x50, 0x75, 0xa2, 0xba, 0x5c, 0xed, 0x7b, 0x1b, 0x64, 0xee, 0x66,
    0x26, 0x2c, 0x40, 0xdc,
];
/// Router entry selector (`swap((uint8,address,...) ...)`).
pub const ROUTER_ENTRY_SELECTOR: [u8; 4] = [0x4d, 0x81, 0x9a, 0x2a];

/// One pool touched by a feed transaction: V3 legs identify by their contract
/// `address`, V4 legs by `pool_id` (the `PoolManager` emits Swap logs with the
/// `pool_id` as topic1, so ids compare directly against WS-lane observations).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FeedTouch {
    /// V3 pool (or any direct-call) contract address.
    Address([u8; 20]),
    /// V4 pool id (`keccak256(abi.encode(PoolKey))`).
    PoolId([u8; 32]),
}

/// Everything a feed transaction touches: its direct recipient plus, for
/// router-entry calls, every leg pool decoded from calldata.
///
/// Fail-soft throughout: malformed calldata yields the direct recipient only,
/// never an error — a new router format must degrade the trigger, not kill it.
pub fn touched(tx: &FeedTx) -> Vec<FeedTouch> {
    let mut touches: Vec<FeedTouch> = tx
        .to_bytes
        .map_or_else(Vec::new, |addr| vec![FeedTouch::Address(addr)]);
    if tx.to_bytes == Some(ROUTER_PROXY) && tx.selector == Some(ROUTER_ENTRY_SELECTOR) {
        // `input` carries the 4-byte selector; the leg layout starts
        // after it (array offset is the first calldata word).
        if let Some(calldata) = tx.input.get(4..) {
            touches.extend(decode_route_legs(calldata));
        }
    }
    touches
}

fn read_word(input: &[u8], offset: usize) -> Option<[u8; 32]> {
    input.get(offset..offset + 32)?.try_into().ok()
}

fn read_address(input: &[u8], offset: usize) -> Option<[u8; 20]> {
    let word = read_word(input, offset)?;
    if word[..12] != [0_u8; 12] {
        return None;
    }
    let mut addr = [0_u8; 20];
    addr.copy_from_slice(&word[12..32]);
    Some(addr)
}

fn read_u256_low_u64(input: &[u8], offset: usize) -> Option<u64> {
    let word = read_word(input, offset)?;
    if word[..24] != [0_u8; 24] {
        return None;
    }
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&word[24..32]);
    Some(u64::from_be_bytes(bytes))
}

/// V4 pool id = `keccak256(abi.encode(currency0, currency1, fee, tickSpacing,
/// hooks))` with standard 32-byte ABI words.
fn v4_pool_id(
    currency0: [u8; 20],
    currency1: [u8; 20],
    fee: u32,
    tick_spacing: i32,
    hooks: [u8; 20],
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(160);
    for addr in [currency0, currency1] {
        encoded.extend_from_slice(&[0_u8; 12]);
        encoded.extend_from_slice(&addr);
    }
    let mut fee_word = [0_u8; 32];
    fee_word[29..32].copy_from_slice(&fee.to_be_bytes()[1..4]);
    encoded.extend_from_slice(&fee_word);
    let mut tick_word = if tick_spacing < 0 {
        [0xFF_u8; 32]
    } else {
        [0_u8; 32]
    };
    tick_word[28..32].copy_from_slice(&tick_spacing.cast_unsigned().to_be_bytes());
    encoded.extend_from_slice(&tick_word);
    encoded.extend_from_slice(&[0_u8; 12]);
    encoded.extend_from_slice(&hooks);
    alloy_primitives::keccak256(&encoded).0
}

/// Decodes router-entry legs into pool touches.
///
/// Layout (verified against live txs 2026-08-28 AND 2026-09-14: 1-leg
/// `0xf4a3c1…`, 3-leg `0xb98fd3…` — same 10-word head, same
/// array-relative offset base; the Sep-11 "+32B" is a new venue-27 leg
/// type with a 2-word tail, not a base change):
/// `[arrayOffset][recipient][amountIn][minOut][deadline][n]
/// [elemOffsets…][elements…]`, each element a 10-word head (venue,
/// currency0, currency1, pool, fee, tickSpacing, hooks, bytesOffset,
/// poolManager, poolKey) plus dynamic tail. Unknown venue codes (e.g.
/// 27, first seen 2026-09-14) skip that leg but never truncate later
/// legs.
fn decode_route_legs(input: &[u8]) -> Vec<FeedTouch> {
    let mut touches = Vec::new();
    let array_off = read_u256_low_u64(input, 0)
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(usize::MAX);
    if array_off > input.len() {
        return touches;
    }
    let count = read_u256_low_u64(input, array_off)
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(0);
    if count == 0 || count > 16 {
        return touches;
    }
    for index in 0..count {
        // Element offsets are relative to the word AFTER the array
        // length (i.e. array start + 32), verified against live
        // 2026-09-14 calls (`0xf4a3c1…` 1-leg, `0xb98fd3…` 3-leg).
        let Some(off_pos) = array_off.checked_add(32 + index.saturating_mul(32)) else {
            break;
        };
        let rel = read_u256_low_u64(input, off_pos)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(usize::MAX);
        let Some(elem) = array_off.checked_add(32 + rel) else {
            break;
        };
        let Some(venue_word) = read_word(input, elem) else {
            break;
        };
        let venue = venue_word[31];
        let (Some(c0), Some(c1)) = (
            read_address(input, elem + 32),
            read_address(input, elem + 64),
        ) else {
            break;
        };
        if venue == 1 {
            // V3: word 3 is the pool address.
            if let Some(pool) = read_address(input, elem + 96) {
                touches.push(FeedTouch::Address(pool));
            }
        } else if venue == 2 {
            // V4: pool derives from the key components.
            let (Some(fee_word), Some(tick_word), Some(hooks)) = (
                read_word(input, elem + 128),
                read_word(input, elem + 160),
                read_address(input, elem + 192),
            ) else {
                break;
            };
            if fee_word[..29] != [0_u8; 29] {
                break;
            }
            let mut fee_bytes = [0_u8; 4];
            fee_bytes.copy_from_slice(&fee_word[28..32]);
            let fee = u32::from_be_bytes(fee_bytes);
            let mut tick_bytes = [0_u8; 4];
            tick_bytes.copy_from_slice(&tick_word[28..32]);
            let tick_spacing = i32::from_be_bytes(tick_bytes);
            touches.push(FeedTouch::PoolId(v4_pool_id(
                c0,
                c1,
                fee,
                tick_spacing,
                hooks,
            )));
        } else {
            // Unknown venue (e.g. 27, first seen 2026-09-14): no touch
            // for this leg; the loop keeps decoding the rest, so one new
            // venue type never blinds later legs.
        }
    }
    touches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_counts_messages_and_kinds() {
        // Live RHC envelope shape (captured 2026-09-13).
        let line = summarize_feed_message(
            r#"{"version":1,"messages":[
                {"sequenceNumber":100,"message":{"message":{"header":{"kind":3}},"delayedMessagesRead":7}},
                {"sequenceNumber":101,"message":{"message":{"header":{"kind":3}},"delayedMessagesRead":8}},
                {"sequenceNumber":102,"message":{"message":{"header":{"kind":0}},"delayedMessagesRead":9}}]}"#,
        );
        assert!(line.contains("version=1"), "{line}");
        assert!(line.contains("msgs=3"), "{line}");
        assert!(line.contains("seq=100-102"), "{line}");
        assert!(line.contains("0:1"), "{line}");
        assert!(line.contains("3:2"), "{line}");
    }

    #[test]
    fn summary_degrades_on_garbage() {
        assert_eq!(
            summarize_feed_message("not json{{{"),
            "feed: unparsed bytes=11"
        );
        assert!(summarize_feed_message(r#"{"version":2}"#).contains("msgs=?"));
    }

    #[test]
    fn fixture_decodes_to_router_calls() {
        let raw = std::fs::read_to_string("tests/fixtures/feed-msg-1.json").unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let l2msg = value["messages"][0]["message"]["message"]["l2Msg"]
            .as_str()
            .unwrap();
        let txs = decode_l2msg(l2msg).unwrap();
        // Live RHC block (captured 2026-09-13): ten 1559 transactions.
        assert_eq!(txs.len(), 10);
        assert!(txs.iter().all(|tx| tx.tx_type == 2));
        // Two route-executor calls through the RHC router proxy entry.
        let router_calls = txs
            .iter()
            .filter(|tx| {
                tx.to_bytes == Some(hex_to_addr("65050a9b7e5075a2ba5ced7b1b64ee66262c40dc"))
                    && tx.selector == Some([0x4d, 0x81, 0x9a, 0x2a])
            })
            .count();
        assert_eq!(router_calls, 2);
        // One plain transfer (no calldata) also decodes.
        assert_eq!(txs.iter().filter(|tx| tx.selector.is_none()).count(), 1);
        // Both router calls decode to non-empty leg touches (V3 pool
        // addresses and/or V4 pool ids).
        for tx in txs.iter().filter(|tx| {
            tx.to_bytes == Some(hex_to_addr("65050a9b7e5075a2ba5ced7b1b64ee66262c40dc"))
        }) {
            assert!(!touched(tx).is_empty());
        }
        // At least one router call yields decoded leg touches beyond
        // the direct recipient (offset base array+32, both eras).
        assert!(
            txs.iter()
                .filter(|tx| {
                    tx.to_bytes == Some(hex_to_addr("65050a9b7e5075a2ba5ced7b1b64ee66262c40dc"))
                })
                .any(|tx| touched(tx).len() > 1),
            "no router call decoded leg touches"
        );
    }

    fn hex_to_addr(hex: &str) -> [u8; 20] {
        let mut addr = [0_u8; 20];
        addr.copy_from_slice(&alloy_primitives::hex::decode(hex).unwrap());
        addr
    }

    fn word_u64(value: u64) -> [u8; 32] {
        let mut word = [0_u8; 32];
        word[24..32].copy_from_slice(&value.to_be_bytes());
        word
    }

    fn addr_word_bytes(addr: &[u8; 20]) -> [u8; 32] {
        let mut word = [0_u8; 32];
        word[12..32].copy_from_slice(addr);
        word
    }

    /// Unknown venue legs (27, live since the Sep-11 router upgrade) skip
    /// without truncating later legs: leg0 venue-27, leg1 V3 pool must
    /// still surface the V3 pool touch.
    #[test]
    fn unknown_venue_skips_without_truncating() {
        let pool = [0x77_u8; 20];
        let c0 = [0x11_u8; 20];
        let c1 = [0x22_u8; 20];
        // `input` carries the 4-byte entry selector before the layout.
        let mut input = vec![0x4d, 0x81, 0x9a, 0x2a];
        // Top: [arrayOff=160][recipient][amountIn][minOut][deadline][n=2]
        // [off0=64][off1=448] (leg0 carries the 12-word venue-27
        // footprint: 10 head + 2 tail words, so leg1 starts at word 20).
        for word in [
            word_u64(160),
            [0_u8; 32],
            word_u64(1000),
            word_u64(900),
            word_u64(1_789_000_000),
            word_u64(2),
            word_u64(64),
            word_u64(448),
        ] {
            input.extend_from_slice(&word);
        }
        // Leg0: venue 27 + zero padding to the 12-word footprint.
        input.extend_from_slice(&word_u64(27));
        input.extend_from_slice(&addr_word_bytes(&c0));
        input.extend_from_slice(&addr_word_bytes(&c1));
        input.extend_from_slice(&addr_word_bytes(&pool));
        for _ in 0..8 {
            input.extend_from_slice(&[0_u8; 32]);
        }
        // Leg1: V3 leg naming `pool`.
        input.extend_from_slice(&word_u64(1));
        input.extend_from_slice(&addr_word_bytes(&c0));
        input.extend_from_slice(&addr_word_bytes(&c1));
        input.extend_from_slice(&addr_word_bytes(&pool));
        input.extend_from_slice(&word_u64(500));
        input.extend_from_slice(&word_u64(10));
        input.extend_from_slice(&[0_u8; 32]);
        input.extend_from_slice(&word_u64(0x140));
        input.extend_from_slice(&[0_u8; 32]);
        input.extend_from_slice(&[0_u8; 32]);
        input.extend_from_slice(&word_u64(0));
        let tx = FeedTx {
            tx_type: 2,
            to_bytes: Some(ROUTER_PROXY),
            selector: Some(ROUTER_ENTRY_SELECTOR),
            input,
        };
        assert!(touched(&tx).contains(&FeedTouch::Address(pool)));
    }

    #[test]
    fn v4_pool_id_matches_catalog() {
        // Pool 00dd2df2 (native/0x5691, fee 10000, tick 200, hooks 0x2cd9…)
        // from data/pools-rhc-v4.csv + data/v4-overrides.csv.
        let id = v4_pool_id(
            [0_u8; 20],
            hex_to_addr("56910D4409F3a0C78C64DD8D0545FF0705389870"),
            10000,
            200,
            hex_to_addr("2cd91bd228ff4c537031d6b8204782090c84c0cc"),
        );
        assert_eq!(
            alloy_primitives::hex::encode(id),
            "00dd2df2f17d431cf3a0938f06c9cf9abc5e9643b6cc466ca3f71f3af246edf3"
        );
    }

    #[test]
    fn envelope_extraction_and_trigger_format() {
        let envelopes = extract_messages(
            r#"{"version":1,"messages":[
                {"sequenceNumber":42,"message":{"message":{"header":{"kind":3},"l2Msg":"aGk="},"delayedMessagesRead":1}},
                {"sequenceNumber":43,"message":{"message":{"header":{"kind":6}}},"delayedMessagesRead":1}]}"#,
        );
        assert_eq!(envelopes.len(), 2);
        assert_eq!(envelopes[0].seq, Some(42));
        assert_eq!(envelopes[0].l2msg.as_deref(), Some("aGk="));
        assert_eq!(envelopes[1].seq, Some(43));
        assert_eq!(envelopes[1].l2msg, None);
        assert!(extract_messages("garbage").is_empty());

        let touches = vec![
            FeedTouch::Address([0xab_u8; 20]),
            FeedTouch::PoolId([0xcd_u8; 32]),
        ];
        let expected = format!("42\ta:{},p:{}", "ab".repeat(20), "cd".repeat(32));
        assert_eq!(format_trigger(Some(42), &touches), expected);
        assert_eq!(format_trigger(None, &[]), "-\t");
    }

    #[test]
    fn url_resolution_prefers_arg_then_default() {
        assert_eq!(
            resolve_feed_url(Some("wss://example.invalid/feed")),
            Ok("wss://example.invalid/feed".to_owned())
        );
        assert_eq!(resolve_feed_url(None), Ok(DEFAULT_FEED_URL.to_owned()));
        assert!(resolve_feed_url(Some("env:FEED_WATCH_MISSING_VAR")).is_err());
    }
}
