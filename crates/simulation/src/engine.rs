//! Replays a quoted two-hop round trip through revm 42 as four committed
//! `transferFrom` transactions, classifying each leg against its expected
//! credit. This is the honeypot filter: fee-on-transfer and
//! revert-on-transfer tokens fail here instead of on-chain, and a drain is
//! caught by the siphon balance moving.
//!
//! Detection is per-leg: after the transaction the *recipient's* credited
//! delta is compared with the `amount` the closed-form quote assumed, and the
//! fixed siphon address's balance is checked for silent outflow. Pools and
//! tokens are fixtures from [`crate::db::build_cache`]; nothing reads a chain.

use crate::db::{Reserves, balance_slot, build_cache, read_slot};
use crate::tokens::siphon_address;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use revm::bytecode::Bytecode;
use revm::context::journal::Journal;
use revm::context::{BlockEnv, CfgEnv, Context, TxEnv};
use revm::context_interface::result::ExecutionResult;
use revm::database::CacheDB;
use revm::database_interface::EmptyDB;
use revm::handler::{ExecuteCommitEvm, MainBuilder};
use revm::primitives::hardfork::SpecId;
use std::collections::BTreeMap;
/// The concrete revm-42 `Context` shape the fixture replay uses.
type SimContext = Context<BlockEnv, TxEnv, CfgEnv, CacheDB<EmptyDB>, Journal<CacheDB<EmptyDB>>, ()>;

/// Fixed-point scale for [`RoundTripSim::new`]'s `flash_fee_rate`, matching
/// `shadow::FIXED_POINT_SCALE` (1e18 = 100%).
pub const FLASH_FEE_SCALE: u128 = 1_000_000_000_000_000_000;

/// The fixture flash-loan lender. A plain account outside the precompile
/// range; it only needs to hold borrowed balances, which the cache seeds.
pub const LENDER_ADDRESS: Address = Address::new([
    0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0e,
]);

/// One of the six `transferFrom` movements a flash-loan round trip replays:
/// borrow from the lender, route through both pools, then repay principal
/// plus fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// `lender -> executor`: the flash loan delivers `amount` of `token`.
    Borrow { token: Address, amount: U256 },
    /// `executor -> pool0`: the buy leg pays `amount` of `token` into pool0.
    BuyIn { token: Address, amount: U256 },
    /// `pool0 -> executor`: pool0 pays out `amount` of `token`.
    PoolPayout { token: Address, amount: U256 },
    /// `executor -> pool1`: the sell leg pays `amount` of `token` into pool1.
    SellIn { token: Address, amount: U256 },
    /// `pool1 -> executor`: pool1 pays out `amount` of `token`.
    FinalPayout { token: Address, amount: U256 },
    /// `executor -> lender`: repayment of principal plus fee.
    Repay { token: Address, amount: U256 },
}

impl Step {
    fn token(self) -> Address {
        match self {
            Self::Borrow { token, .. }
            | Self::BuyIn { token, .. }
            | Self::PoolPayout { token, .. }
            | Self::SellIn { token, .. }
            | Self::FinalPayout { token, .. }
            | Self::Repay { token, .. } => token,
        }
    }

    fn amount(self) -> U256 {
        match self {
            Self::Borrow { amount, .. }
            | Self::BuyIn { amount, .. }
            | Self::PoolPayout { amount, .. }
            | Self::SellIn { amount, .. }
            | Self::FinalPayout { amount, .. }
            | Self::Repay { amount, .. } => amount,
        }
    }
}

/// The state of a single replayed leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegResult {
    /// The recipient was credited exactly `amount` and no siphon moved.
    Clean,
    /// The recipient was credited less than `amount` (fee-on-transfer).
    Shortfall { expected: U256, actual: U256 },
    /// The recipient was skimmed `siphoned` to the drain address.
    Drained {
        expected: U256,
        actual: U256,
        siphoned: U256,
    },
    /// The transfer reverted or halted; `reason` is its debug rendering.
    Reverted { reason: String },
}

/// Verdict for a full flash-loan round-trip replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Every leg credited its amount and the loan repaid principal plus fee;
    /// `net` is what the executor keeps (`gross_out - repay`).
    NetProfit { gross_out: U256, net: U256 },
    /// The route reverted at `step` (including an unpayable repayment).
    Reverted { step: Step, reason: String },
    /// A fee token shorted the recipient at `step`.
    FeeScreened {
        step: Step,
        expected: U256,
        actual: U256,
    },
    /// A drain token siphoned funds during `step`.
    DrainScreened {
        step: Step,
        expected: U256,
        actual: U256,
        siphoned: U256,
    },
}

/// Error feeding a replay into revm.
#[derive(Debug, thiserror::Error)]
pub enum SimError {
    #[error("revm rejected step {step}: {reason}")]
    Evm { step: usize, reason: String },
}

/// The six steps a flash-loan round trip
/// `borrow lo -> leg0 -> hi -> leg1 -> repay (lo + fee)` replays.
#[must_use]
pub fn round_trip_steps(
    leg0: Reserves,
    leg1: Reserves,
    input: U256,
    mid_out: U256,
    final_out: U256,
    repay_amount: U256,
) -> [Step; 6] {
    [
        Step::Borrow {
            token: leg0.token_in,
            amount: input,
        },
        Step::BuyIn {
            token: leg0.token_in,
            amount: input,
        },
        Step::PoolPayout {
            token: leg0.token_out,
            amount: mid_out,
        },
        Step::SellIn {
            token: leg1.token_in,
            amount: mid_out,
        },
        Step::FinalPayout {
            token: leg1.token_out,
            amount: final_out,
        },
        Step::Repay {
            token: leg0.token_in,
            amount: repay_amount,
        },
    ]
}

/// The revm `transferFrom` calldata for `(from, to, amount)` the fixtures
/// dispatch on.
pub(crate) fn encode_transfer_from(from: Address, to: Address, amount: U256) -> Bytes {
    let mut calldata = Vec::with_capacity(100);
    calldata.extend_from_slice(&0x23b8_72dd_u32.to_be_bytes());
    calldata.extend_from_slice(&from.into_word().0);
    calldata.extend_from_slice(&to.into_word().0);
    calldata.extend_from_slice(&amount.to_be_bytes::<32>());
    Bytes::from(calldata)
}

/// Runs one committed revm transaction; returns the committed database with
/// the execution outcome.
pub(crate) fn run_tx(
    db: CacheDB<EmptyDB>,
    caller: Address,
    to: Address,
    data: Bytes,
) -> (Result<ExecutionResult, String>, CacheDB<EmptyDB>) {
    let tx = TxEnv::builder()
        .caller(caller)
        .kind(TxKind::Call(to))
        .data(data)
        .gas_limit(500_000)
        .build()
        .expect("static transaction fields");
    let mut evm = <SimContext>::new(db, SpecId::PRAGUE)
        .modify_cfg_chained(|cfg| cfg.disable_nonce_check = true)
        .build_mainnet();
    let outcome = evm.transact_commit(tx);
    (
        outcome.map_err(|err| format!("{err}")),
        evm.ctx.journaled_state.database,
    )
}

/// Replays one quoted round trip over a reusable in-memory database.
///
/// Create with [`Self::new`] from the two legs' [`Reserves`], then call
/// [`Self::run`] once; the database settles each leg as it is replayed.
///
/// The replay is funded by a modeled flash loan: the executor starts with
/// **zero** balances, borrows `input` from [`LENDER_ADDRESS`], routes both
/// legs, and must repay `input + fee` at the end. This mirrors production —
/// capital is always borrowed, never held — and catches routes that only look
/// profitable when free capital is assumed.
pub struct RoundTripSim {
    db: CacheDB<EmptyDB>,
    executor: Address,
    leg0: Reserves,
    leg1: Reserves,
    steps: [Step; 6],
    final_out: U256,
    repay: U256,
}

impl RoundTripSim {
    /// Builds the fixture database and the six steps. `seed` carries any
    /// extra `holder -> balance` seeding beyond pool reserves; `code` maps
    /// each address to its assembled bytecode. `flash_fee_rate` is a
    /// fixed-point fraction on [`FLASH_FEE_SCALE`]; the repayment is
    /// `input + input * rate / scale`.
    ///
    /// # Panics
    ///
    /// Panics if the repay amount computation overflows `U256`, which
    /// requires an absurd fee rate far beyond any protocol's.
    #[allow(clippy::too_many_arguments)] // one argument per route quantity
    #[must_use]
    pub fn new(
        leg0: Reserves,
        leg1: Reserves,
        executor: Address,
        seed: &BTreeMap<Address, BTreeMap<Address, U256>>,
        code: impl Fn(Address) -> Bytecode,
        input: U256,
        mid_out: U256,
        final_out: U256,
        flash_fee_rate: U256,
    ) -> Self {
        let repay = input
            .checked_mul(flash_fee_rate)
            .and_then(|fee| fee.checked_div(U256::from(FLASH_FEE_SCALE)))
            .and_then(|fee| fee.checked_add(input))
            .expect("repay amount overflow");
        let tokens = [leg0.token_in, leg0.token_out, leg1.token_in, leg1.token_out];
        let mut db = build_cache(leg0, leg1, &tokens, seed, code, executor);
        // The lender holds enough of the input token to serve the borrow.
        let _ = db.insert_account_storage(leg0.token_in, balance_slot(LENDER_ADDRESS), input);
        Self {
            db,
            executor,
            leg0,
            leg1,
            steps: round_trip_steps(leg0, leg1, input, mid_out, final_out, repay),
            final_out,
            repay,
        }
    }

    /// Replays all six legs and returns the first non-clean verdict.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::Evm`] if revm itself rejects a step (distinct from
    /// an in-EVM revert, which is an `Outcome::Reverted` verdict).
    pub fn run(&mut self) -> Result<Outcome, SimError> {
        let steps = self.steps;
        for (index, step) in steps.into_iter().enumerate() {
            match self.run_leg(index, step)? {
                LegResult::Clean => {}
                LegResult::Shortfall { expected, actual } => {
                    return Ok(Outcome::FeeScreened {
                        step,
                        expected,
                        actual,
                    });
                }
                LegResult::Drained {
                    expected,
                    actual,
                    siphoned,
                } => {
                    return Ok(Outcome::DrainScreened {
                        step,
                        expected,
                        actual,
                        siphoned,
                    });
                }
                LegResult::Reverted { reason } => {
                    return Ok(Outcome::Reverted { step, reason });
                }
            }
        }
        Ok(Outcome::NetProfit {
            gross_out: self.final_out,
            net: self.final_out.saturating_sub(self.repay),
        })
    }

    fn run_leg(&mut self, index: usize, step: Step) -> Result<LegResult, SimError> {
        let (from, to) = self.parties(step);
        let token = step.token();
        let siphon = siphon_address();
        let before_to = read_slot(&self.db, token, balance_slot(to)).unwrap_or_default();
        let before_siphon = read_slot(&self.db, token, balance_slot(siphon)).unwrap_or_default();
        let (outcome, db) = run_tx(
            std::mem::take(&mut self.db),
            self.executor,
            token,
            encode_transfer_from(from, to, step.amount()),
        );
        self.db = db;
        let result = outcome.map_err(|reason| SimError::Evm {
            step: index,
            reason,
        })?;
        if !result.is_success() {
            return Ok(LegResult::Reverted {
                reason: format!("{result:?}"),
            });
        }

        let after_to = read_slot(&self.db, token, balance_slot(to)).unwrap_or_default();
        let after_siphon = read_slot(&self.db, token, balance_slot(siphon)).unwrap_or_default();
        let credited = after_to.wrapping_sub(before_to);
        let siphoned = after_siphon.wrapping_sub(before_siphon);
        if siphoned != U256::ZERO {
            return Ok(LegResult::Drained {
                expected: step.amount(),
                actual: credited,
                siphoned,
            });
        }
        if credited != step.amount() {
            return Ok(LegResult::Shortfall {
                expected: step.amount(),
                actual: credited,
            });
        }
        Ok(LegResult::Clean)
    }

    fn parties(&self, step: Step) -> (Address, Address) {
        match step {
            Step::Borrow { .. } => (LENDER_ADDRESS, self.executor),
            Step::BuyIn { .. } => (self.executor, self.leg0.pool),
            Step::PoolPayout { .. } => (self.leg0.pool, self.executor),
            Step::SellIn { .. } => (self.executor, self.leg1.pool),
            Step::FinalPayout { .. } => (self.leg1.pool, self.executor),
            Step::Repay { .. } => (self.executor, LENDER_ADDRESS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{CACHE_CALLER, fixture_addr as addr};
    use crate::tokens::{TokenKind, TokenSpec, token_bytecode};

    fn route_tokens() -> (Address, Address) {
        (addr(1), addr(2))
    }

    fn route_pools() -> (Address, Address) {
        (addr(3), addr(4))
    }

    fn executor() -> Address {
        CACHE_CALLER
    }

    fn deep_reserves(lo: Address, hi: Address) -> (Reserves, Reserves) {
        let deep = U256::from(1) << 160;
        (
            Reserves {
                pool: route_pools().0,
                token_in: lo,
                token_out: hi,
                reserve_in: deep,
                reserve_out: deep,
            },
            Reserves {
                pool: route_pools().1,
                token_in: hi,
                token_out: lo,
                reserve_in: deep,
                reserve_out: deep,
            },
        )
    }

    /// Bytecode for every address in `entries`; empty for anything else.
    ///
    /// The `entries` array must outlive the returned closure (it is borrowed).
    fn code_for(entries: &[(Address, TokenSpec)]) -> impl Fn(Address) -> Bytecode + '_ {
        move |address| {
            entries
                .iter()
                .find(|(a, _)| *a == address)
                .map(|(_, spec)| token_bytecode(*spec))
                .unwrap_or_else(|| Bytecode::new_legacy(alloy_primitives::Bytes::new()))
        }
    }

    fn amounts() -> (U256, U256, U256) {
        (U256::from(100), U256::from(200), U256::from(300))
    }

    #[test]
    fn standard_route_returns_net_profit() {
        let (lo, hi) = route_tokens();
        let (leg0, leg1) = deep_reserves(lo, hi);
        let (input, mid_out, final_out) = amounts();
        let entries = [(lo, TokenSpec::default()), (hi, TokenSpec::default())];
        let mut sim = RoundTripSim::new(
            leg0,
            leg1,
            executor(),
            &BTreeMap::new(),
            code_for(&entries),
            input,
            mid_out,
            final_out,
            U256::ZERO,
        );
        let outcome = sim.run().expect("revm runs a fixture route");
        assert_eq!(
            outcome,
            Outcome::NetProfit {
                gross_out: final_out,
                net: final_out - input,
            }
        );
    }

    #[test]
    fn flash_fee_reduces_net_and_unpayable_loan_reverts() {
        let (lo, hi) = route_tokens();
        let (leg0, leg1) = deep_reserves(lo, hi);
        let input = U256::from(100);
        let mid_out = U256::from(200);
        // Gross edge is only +5; a 10% flash fee makes repayment (110)
        // impossible from the 105 payout.
        let final_out = U256::from(105);
        let entries = [(lo, TokenSpec::default()), (hi, TokenSpec::default())];
        let mut sim = RoundTripSim::new(
            leg0,
            leg1,
            executor(),
            &BTreeMap::new(),
            code_for(&entries),
            input,
            mid_out,
            final_out,
            U256::from(FLASH_FEE_SCALE) / U256::from(10),
        );
        let outcome = sim.run().expect("revm runs a fixture route");
        assert!(matches!(
            outcome,
            Outcome::Reverted {
                step: Step::Repay { .. },
                ..
            }
        ));
    }

    #[test]
    fn round_trip_steps_follow_the_two_legs() {
        let (lo, hi) = route_tokens();
        let (leg0, leg1) = deep_reserves(lo, hi);
        let (input, mid_out, final_out) = amounts();
        let repay = input + U256::from(5);
        assert_eq!(
            round_trip_steps(leg0, leg1, input, mid_out, final_out, repay),
            [
                Step::Borrow {
                    token: lo,
                    amount: input,
                },
                Step::BuyIn {
                    token: lo,
                    amount: input,
                },
                Step::PoolPayout {
                    token: hi,
                    amount: mid_out,
                },
                Step::SellIn {
                    token: hi,
                    amount: mid_out,
                },
                Step::FinalPayout {
                    token: lo,
                    amount: final_out,
                },
                Step::Repay {
                    token: lo,
                    amount: repay,
                },
            ]
        );
    }

    #[test]
    fn fee_on_transfer_is_screened_on_the_borrow() {
        let (lo, hi) = route_tokens();
        let (leg0, leg1) = deep_reserves(lo, hi);
        let (input, mid_out, final_out) = amounts();
        let entries = [
            (
                lo,
                TokenSpec {
                    kind: TokenKind::FeeOnTransfer,
                    fee_bps: 1000,
                    ..Default::default()
                },
            ),
            (hi, TokenSpec::default()),
        ];
        let mut sim = RoundTripSim::new(
            leg0,
            leg1,
            executor(),
            &BTreeMap::new(),
            code_for(&entries),
            input,
            mid_out,
            final_out,
            U256::ZERO,
        );
        let outcome = sim.run().expect("revm runs a fixture route");
        let credited = input * U256::from(9000) / U256::from(10_000);
        assert_eq!(
            outcome,
            Outcome::FeeScreened {
                step: Step::Borrow {
                    token: lo,
                    amount: input,
                },
                expected: input,
                actual: credited,
            }
        );
    }

    #[test]
    fn drain_token_is_screened_on_the_borrow() {
        let (lo, hi) = route_tokens();
        let (leg0, leg1) = deep_reserves(lo, hi);
        let (input, mid_out, final_out) = amounts();
        let entries = [
            (
                lo,
                TokenSpec {
                    kind: TokenKind::Drain,
                    drain_amount: 25,
                    ..Default::default()
                },
            ),
            (hi, TokenSpec::default()),
        ];
        let mut sim = RoundTripSim::new(
            leg0,
            leg1,
            executor(),
            &BTreeMap::new(),
            code_for(&entries),
            input,
            mid_out,
            final_out,
            U256::ZERO,
        );
        let outcome = sim.run().expect("revm runs a fixture route");
        assert_eq!(
            outcome,
            Outcome::DrainScreened {
                step: Step::Borrow {
                    token: lo,
                    amount: input,
                },
                expected: input,
                actual: input - U256::from(25),
                siphoned: U256::from(25),
            }
        );
    }

    #[test]
    fn revert_token_is_screened_on_the_borrow() {
        let (lo, hi) = route_tokens();
        let (leg0, leg1) = deep_reserves(lo, hi);
        let (input, mid_out, final_out) = amounts();
        let entries = [
            (
                lo,
                TokenSpec {
                    kind: TokenKind::RevertOnTransfer,
                    ..Default::default()
                },
            ),
            (hi, TokenSpec::default()),
        ];
        let mut sim = RoundTripSim::new(
            leg0,
            leg1,
            executor(),
            &BTreeMap::new(),
            code_for(&entries),
            input,
            mid_out,
            final_out,
            U256::ZERO,
        );
        let outcome = sim.run().expect("revm runs a fixture route");
        assert!(matches!(
            outcome,
            Outcome::Reverted {
                step: Step::Borrow { .. },
                ..
            }
        ));
    }
}
