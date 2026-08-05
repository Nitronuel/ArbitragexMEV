//! Bounded live-provider smoke test: verify chain/catalog at one pinned block,
//! then open one filtered `Sync` subscription and consume a small window.

use std::io::Read;
use std::time::Duration;

use alloy_primitives::Address;
use catalog::{CatalogRpc, FactorySpec, parse_manifest, verify_catalog};
use provider::{LogStream, StreamItem, SubscriptionFilter, WsProbe, sync_topic};

use crate::ServiceError;

/// Aggregate outcome of one live smoke-test pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmokeReport {
    pub block: u64,
    pub verified: usize,
    pub quarantined: usize,
    pub sync_received: usize,
    pub subscription_ok: bool,
}

/// Runs a bounded smoke test over a verified manifest at one pinned block.
///
/// Factory specifications are derived from the candidate rows themselves.
/// `build_probe` must connect a WebSocket subscription for the pool addresses
/// derived from the verified catalog. `limit == 0` disables the message cap and
/// relies solely on the timeout.
///
/// # Errors
///
/// Returns an error when the manifest cannot be parsed, catalog verification
/// aborts, or the subscription window fails.
pub fn run_smoke<P: WsProbe>(
    manifest: impl Read,
    block: u64,
    limit: usize,
    timeout: Duration,
    rpc: &impl CatalogRpc,
    stream: &LogStream,
    build_probe: &mut impl FnMut(SubscriptionFilter) -> Result<P, provider::StreamError>,
) -> Result<SmokeReport, ServiceError> {
    let candidates = parse_manifest(manifest)?;
    let factories: Vec<FactorySpec> = candidates
        .iter()
        .map(|candidate| FactorySpec {
            address: candidate.factory,
            fee: candidate.fee,
        })
        .collect();
    let verified = verify_catalog(candidates, &factories, block, rpc)?;
    let verified_count = verified.verified.len();
    let quarantined = verified.quarantined.len();

    let addresses: Vec<Address> = verified
        .verified
        .iter()
        .map(|pool| pool.pool.address)
        .collect();
    if addresses.is_empty() {
        return Ok(SmokeReport {
            block,
            verified: 0,
            quarantined,
            sync_received: 0,
            subscription_ok: false,
        });
    }
    let filter: SubscriptionFilter = SubscriptionFilter {
        addresses,
        topic0: sync_topic(),
    };
    let probe = build_probe(filter)?;

    let mut received = 0;
    while let Some(StreamItem::Log(_)) = probe.next(stream, timeout)? {
        received += 1;
        if limit != 0 && received == limit {
            break;
        }
    }

    Ok(SmokeReport {
        block,
        verified: verified_count,
        quarantined,
        sync_received: received,
        subscription_ok: received > 0,
    })
}
