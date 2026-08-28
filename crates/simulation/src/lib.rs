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

mod db;
mod engine;
mod executor;
mod fork;
mod tokens;

#[cfg(test)]
mod test_util;

pub use db::{Reserves, build_cache, read_slot};
pub use engine::{
    FLASH_FEE_SCALE, LENDER_ADDRESS, LegResult, Outcome, RoundTripSim, SimError, Step,
    round_trip_steps,
};
pub use executor::{encode_v3_callback, executor_address, v3_callback_runtime};
pub use fork::{ForkDb, ForkTx, fork_transact};
pub use tokens::{TokenKind, TokenSpec, token_bytecode};
