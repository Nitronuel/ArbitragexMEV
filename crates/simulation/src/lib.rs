//! In-process Ethereum Virtual Machine simulation of a cross-venue round trip.
//!
//! The closed-form quotes (`v2-math`) estimate the economics of a 2-leg round
//! trip from locally cached reserves, but they cannot see token behavior that
//! only executes on-chain: fee-on-transfer taxes, revert-on-transfer traps, or
//! malicious `transferFrom` drains. This crate replays the actual token
//! movements of a quote through a `revm` interpreter over an in-memory
//! `CacheDB` built purely from local state, so the honeypot filter and the
//! `simulated_profit > gas_cost / expected_win_rate` submission gate run with
//! zero RPC and zero broadcast.
//!
//! ## Offline by construction
//!
//! - No `eth_getCode`, no fork, no provider, no signing, no submission.
//! - Every fixture contract is bytecode this crate assembles; nothing is read
//!   from a chain.
//! - The switch over a quoted round trip is modeled as the six `transferFrom`
//!   movements a real flash-loan route needs (borrow from the lender, `buy`
//!   into the pool, pool payout, `sell` into the second pool, final payout,
//!   repay principal plus fee), each replayed as its own revm transaction so
//!   a revert is attributed to the exact leg that failed. The executor starts
//!   with zero balances, mirroring production where capital is always
//!   borrowed and never held.
#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]

#[cfg(test)]
mod capture_test;
mod db;
#[cfg(test)]
mod dump_probe;
mod engine;
mod executor;
mod fork;
#[allow(clippy::too_many_arguments, clippy::doc_markdown)]
mod payload_builder;
mod tokens;

#[cfg(test)]
mod test_util;

pub use db::{Reserves, build_cache, read_slot};
pub use engine::{
    FLASH_FEE_SCALE, LENDER_ADDRESS, LegResult, Outcome, RoundTripSim, SimError, Step,
    round_trip_steps,
};
pub use executor::{
    V4SwapIntent, encode_v3_callback, encode_v4_unlock, encode_v4_unlock_callback,
    executor_address, max_sqrt_ratio_minus_1, min_sqrt_ratio_plus_1, pool_manager_address,
    v3_callback_runtime, v4_unlock_callback_runtime,
};
pub use fork::{ForkDb, ForkTx, fork_transact};
pub use payload_builder::{
    RHC_POOL_MANAGER, RouteElement, V4_DYNAMIC_FEE_SENTINEL, VENUE_V3, VENUE_V4,
    encode_swap_calldata,
};
pub use tokens::{TokenKind, TokenSpec, token_bytecode};
