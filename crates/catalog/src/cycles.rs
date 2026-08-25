use std::{
    collections::{HashMap, HashSet},
    hash::BuildHasher,
};

use alloy_primitives::Address;
use domain::{Cycle, CycleHop, CycleId, PoolId};
use thiserror::Error;

use crate::{
    VerifiedPool,
    graph::{DirectedEdge, adjacency},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CycleLimits {
    pub max_cycles: usize,
    pub max_cycles_per_pool: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledGraph {
    pub cycles: Vec<Cycle>,
    pub by_pool: Vec<Vec<CycleId>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CycleError {
    #[error("duplicate pool ID {0}")]
    DuplicatePoolId(u32),
    #[error("pool IDs must be compact; expected {expected}, found {actual}")]
    NonCompactPoolId { expected: u32, actual: u32 },
    #[error("cycle limit {limit} would be exceeded")]
    CycleLimit { limit: usize },
    #[error("pool {pool_id:?} cycle limit {limit} would be exceeded")]
    PerPoolLimit { pool_id: PoolId, limit: usize },
    #[error("cycle count exceeds the u32 ID space")]
    CycleIdOverflow,
}

/// Cross-anchor-aware dedup key: the cycle's anchor plus its canonical
/// rotation (audit C40).
type DedupKey = (Address, Vec<(Address, Address, Address)>);

/// Compiles deterministic 2-4 hop anchor cycles and their dirty reverse index.
///
/// # Errors
///
/// Returns an error for non-compact pool IDs or before a configured global or
/// per-pool cycle limit would be exceeded.
pub fn compile_cycles<S: BuildHasher>(
    pools: &[VerifiedPool],
    anchors: &HashSet<Address, S>,
    limits: CycleLimits,
) -> Result<CompiledGraph, CycleError> {
    validate_pool_ids(pools)?;
    let adjacency = adjacency(pools);
    let mut sorted_anchors: Vec<_> = anchors.iter().copied().collect();
    sorted_anchors.sort_unstable();

    // Audit C40: dedup is per (anchor, canonical rotation), not per rotation
    // alone — collapsing cross-anchor rotations discarded every anchor except
    // the address-lowest one, and the anchor determines the flash-loan token,
    // so a borrowable rotation could be dropped in favour of an unfundable
    // one.
    let mut discovered: HashSet<DedupKey> = HashSet::new();
    let mut cycles = Vec::new();
    let mut by_pool = vec![Vec::new(); pools.len()];
    for anchor in sorted_anchors {
        let mut path = Vec::with_capacity(4);
        let mut used_pools = HashSet::with_capacity(4);
        let mut used_tokens = HashSet::with_capacity(4);
        used_tokens.insert(anchor);
        walk(
            anchor,
            anchor,
            &adjacency,
            &mut path,
            &mut used_pools,
            &mut used_tokens,
            &mut discovered,
            &mut cycles,
            &mut by_pool,
            limits,
        )?;
    }
    Ok(CompiledGraph { cycles, by_pool })
}

#[allow(clippy::too_many_arguments)]
fn walk(
    anchor: Address,
    current: Address,
    adjacency: &HashMap<Address, Vec<DirectedEdge>>,
    path: &mut Vec<DirectedEdge>,
    used_pools: &mut HashSet<PoolId>,
    used_tokens: &mut HashSet<Address>,
    discovered: &mut HashSet<DedupKey>,
    cycles: &mut Vec<Cycle>,
    by_pool: &mut [Vec<CycleId>],
    limits: CycleLimits,
) -> Result<(), CycleError> {
    let Some(edges) = adjacency.get(&current) else {
        return Ok(());
    };
    for &edge in edges {
        if used_pools.contains(&edge.pool_id) {
            continue;
        }
        if edge.token_out == anchor {
            if path.is_empty() {
                continue;
            }
            path.push(edge);
            let key = (anchor, canonical_key(path));
            if discovered.insert(key) {
                add_cycle(anchor, path, cycles, by_pool, limits)?;
            }
            path.pop();
            continue;
        }
        if path.len() == 3 || !used_tokens.insert(edge.token_out) {
            continue;
        }
        used_pools.insert(edge.pool_id);
        path.push(edge);
        walk(
            anchor,
            edge.token_out,
            adjacency,
            path,
            used_pools,
            used_tokens,
            discovered,
            cycles,
            by_pool,
            limits,
        )?;
        path.pop();
        used_pools.remove(&edge.pool_id);
        used_tokens.remove(&edge.token_out);
    }
    Ok(())
}

fn canonical_key(path: &[DirectedEdge]) -> Vec<(Address, Address, Address)> {
    let directed: Vec<_> = path
        .iter()
        .map(|edge| (edge.pool_address, edge.token_in, edge.token_out))
        .collect();
    (0..directed.len())
        .map(|rotation| {
            directed[rotation..]
                .iter()
                .chain(&directed[..rotation])
                .copied()
                .collect::<Vec<_>>()
        })
        .min()
        .unwrap_or_default()
}

fn add_cycle(
    anchor: Address,
    path: &[DirectedEdge],
    cycles: &mut Vec<Cycle>,
    by_pool: &mut [Vec<CycleId>],
    limits: CycleLimits,
) -> Result<(), CycleError> {
    if cycles.len() == limits.max_cycles {
        return Err(CycleError::CycleLimit {
            limit: limits.max_cycles,
        });
    }
    for edge in path {
        let index = edge.pool_id.0 as usize;
        if by_pool[index].len() == limits.max_cycles_per_pool {
            return Err(CycleError::PerPoolLimit {
                pool_id: edge.pool_id,
                limit: limits.max_cycles_per_pool,
            });
        }
    }

    let id = CycleId(u32::try_from(cycles.len()).map_err(|_| CycleError::CycleIdOverflow)?);
    cycles.push(Cycle {
        id,
        anchor,
        hops: path
            .iter()
            .map(|edge| CycleHop {
                pool_id: edge.pool_id,
                token_in: edge.token_in,
                token_out: edge.token_out,
                fee: edge.fee,
                zero_for_one: edge.zero_for_one,
            })
            .collect(),
    });
    for edge in path {
        by_pool[edge.pool_id.0 as usize].push(id);
    }
    Ok(())
}

fn validate_pool_ids(pools: &[VerifiedPool]) -> Result<(), CycleError> {
    let mut ids: Vec<_> = pools.iter().map(|pool| pool.pool.id.0).collect();
    ids.sort_unstable();
    for (expected, actual) in (0_u32..).zip(ids) {
        if actual < expected {
            return Err(CycleError::DuplicatePoolId(actual));
        }
        if actual != expected {
            return Err(CycleError::NonCompactPoolId { expected, actual });
        }
    }
    Ok(())
}
