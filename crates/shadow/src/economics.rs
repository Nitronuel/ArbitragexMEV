use alloy_primitives::U256;
use v2_math::OptimalQuote;

/// Fixed-point scale for every USD-denominated economic value.
pub const FIXED_POINT_SCALE: u128 = 1_000_000_000_000_000_000;

/// Shared submission-gate constants (audit S4/A15): one definition instead of
/// per-command scalars that drift.
pub mod gate_defaults {
    use alloy_primitives::U256;

    /// Conservative gas cost of one cross-venue attempt, USD fixed-point
    /// (~$1.00 at current RHC gas ~0.41 gwei for 3-hop).
    pub const STANDARD_GAS_COST_USD: U256 = U256::from_limbs([1_000_000_000_000_000_000, 0, 0, 0]);
    /// Expected win rate for the submission-gate floor (33.34%).
    ///
    /// Operator decision 2026-09-08/09: set just above one-third so the gate
    /// floor (gas_cost / win_rate ≈ 2.9994x gas) sits just UNDER 3x gas —
    /// profit of at least 3x gas gates and executes. A rate of exactly 1/3
    /// is not representable, and 33% flat floors at 3.03x (rejecting exactly
    /// 3x); 33.34% is the smallest two-decimal rate clearing the bar.
    /// Trade-off: if true win rate is lower, EV is negative — acceptable
    /// per operator for live measurement; revisit if loss rate exceeds expectation.
    pub const STANDARD_EXPECTED_WIN_RATE: U256 =
        U256::from_limbs([333_400_000_000_000_000, 0, 0, 0]);

    /// Measurement-mode overrides used by the dormant `run` pipeline
    /// (audit A15): its `interesting=` counts are meant to observe every
    /// profitable cycle, not gate them, so gas is priced at dust and the
    /// win rate is 100%. Named here so the disabled gate is visible as a
    /// decision, not an accident.
    pub const MEASUREMENT_GAS_COST_WEI: U256 = U256::from_limbs([1_000, 0, 0, 0]);
    pub const MEASUREMENT_EXPECTED_WIN_RATE: U256 =
        U256::from_limbs([1_000_000_000_000_000_000, 0, 0, 0]);
}

/// Estimated execution-gas units per route shape, keyed by hop count.
///
/// Phase-2 simulation will replace these with measured values (audit task
/// 2.3); until then they are documented placeholders consistent with the
/// project budget note (~300–500k gas for a 3-hop attempt): a 60k base
/// transaction overhead plus ~120k per swap hop.
pub const BASE_TX_GAS_UNITS: u64 = 60_000;
pub const PER_HOP_GAS_UNITS: u64 = 120_000;

/// Gas units for a 2-hop cross-venue pair attempt.
pub const PAIR_EXECUTION_GAS_UNITS: u64 = BASE_TX_GAS_UNITS + 2 * PER_HOP_GAS_UNITS;
/// Gas units for a 3-hop triangle attempt.
pub const TRIANGLE_EXECUTION_GAS_UNITS: u64 = BASE_TX_GAS_UNITS + 3 * PER_HOP_GAS_UNITS;

/// Per-evaluation market inputs. Validity flags come from a low-frequency gas
/// price read and a liquid reference route whose state must be current.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CostSnapshot {
    /// USD per whole token, scaled by [`FIXED_POINT_SCALE`].
    pub usd_per_token: U256,
    /// False when the cached gas price has exceeded its configured age.
    pub gas_price_age_valid: bool,
    /// False when the reference route state is stale or unavailable.
    pub reference_price_valid: bool,
    /// Live network gas price, wei per gas unit. Zero means "never read" —
    /// which fails the gate closed through `gas_price_age_valid`.
    pub gas_price_wei: U256,
}

impl CostSnapshot {
    #[must_use]
    pub const fn invalid() -> Self {
        Self {
            usd_per_token: U256::ZERO,
            gas_price_age_valid: false,
            reference_price_valid: false,
            gas_price_wei: U256::ZERO,
        }
    }
}

/// Conservative configured cost assumptions.
///
/// All USD values use the fixed-point scale. `flash_fee_rate` and
/// `expected_win_rate` are fixed-point fractions of 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Economics {
    /// Fraction of borrowed capital charged by the selected flash-loan source.
    pub flash_fee_rate: U256,
    /// Conservative gas cost for one attempt, USD fixed-point. Legacy scalar
    /// consumed by [`Economics::classify`]; route-shaped paths should use
    /// [`Economics::classify_route`] with [`PAIR_EXECUTION_GAS_UNITS`] /
    /// [`TRIANGLE_EXECUTION_GAS_UNITS`] so a triangle is not priced as a
    /// pair (audit S4).
    pub gas_cost_usd: U256,
    /// Expected win rate, a fixed-point fraction.
    pub expected_win_rate: U256,
    /// USD value of one whole native token, fixed-point — converts
    /// `gas_price_wei × units` into dollars. Zero fails the gate closed.
    pub native_token_usd: U256,
    /// Data-availability fee per attempt, USD fixed-point. Explicitly zero
    /// until the chain's fee model is verified (audit Part VI); the term is
    /// wired end-to-end so the verified value drops in without restructuring.
    pub da_fee_usd: U256,
}

/// Result of classifying one gross quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// Gross profit in token units from the optimizer.
    pub gross_profit: U256,
    /// Gross profit converted to USD fixed-point.
    pub gross_profit_usd: U256,
    /// Estimated flash-loan fee, USD fixed-point.
    pub flash_cost_usd: U256,
    /// Estimated gas cost, USD fixed-point.
    pub gas_cost_usd: U256,
    /// `gross_profit_usd - flash_cost_usd - gas_cost_usd`, USD fixed-point.
    pub estimated_net_profit_usd: U256,
    /// Submission-gate floor `gas_cost_usd / expected_win_rate`, USD fixed-point.
    pub threshold_usd: U256,
    /// How far below the bar the quote fell, USD fixed-point: zero when
    /// above threshold, otherwise `threshold - net` (or total cost − gross
    /// when unprofitable). Makes near-misses measurable so the floor can be
    /// tuned on data instead of guesses (audit E4).
    pub shortfall_usd: U256,
    pub reason: ClassificationReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassificationReason {
    /// Economic inputs are invalid or stale; no decision is made.
    NotEvaluated { detail: String },
    /// Net profit is not positive after flash and gas costs.
    NotProfitable,
    /// Positive net profit below the submission-gate floor.
    BelowThreshold,
    /// Positive net profit strictly above the submission-gate floor.
    AboveThreshold,
    /// Gate passed, but at the `$1` fixture valuation because the anchor
    /// token has no USD price. Recorded for visibility and never counted as
    /// an honest candidate; the same quote with a priced anchor would have
    /// classified `AboveThreshold`/`BelowThreshold`.
    Provisional { detail: String },
}

impl Economics {
    /// Classifies a gross quote using the submission-gate formula.
    ///
    /// The result is a screening label, never permission to submit. No
    /// classification happens while gas or reference prices are stale.
    #[must_use]
    pub fn classify(&self, quote: &OptimalQuote, snapshot: &CostSnapshot) -> Classification {
        let scale = U256::from(FIXED_POINT_SCALE);

        if !snapshot.gas_price_age_valid {
            return not_evaluated(quote, "gas price is stale");
        }
        if !snapshot.reference_price_valid {
            return not_evaluated(quote, "reference price is stale");
        }
        if snapshot.usd_per_token.is_zero() {
            return not_evaluated(quote, "reference price is zero");
        }
        if self.expected_win_rate.is_zero() {
            return not_evaluated(quote, "expected win rate is zero");
        }

        let Some(gross_profit_usd) = gross_profit_usd_of(quote, snapshot, scale) else {
            return not_evaluated(quote, "gross profit conversion overflow");
        };
        let Some(input_usd) = quote
            .input
            .checked_mul(snapshot.usd_per_token)
            .and_then(|value| value.checked_div(scale))
        else {
            return not_evaluated(quote, "input conversion overflow");
        };
        let Some(flash_cost_usd) = input_usd
            .checked_mul(self.flash_fee_rate)
            .and_then(|value| value.checked_div(scale))
        else {
            return not_evaluated(quote, "flash cost overflow");
        };

        let total_cost = flash_cost_usd
            .checked_add(self.gas_cost_usd)
            .unwrap_or(U256::MAX);
        let net_profit_usd = gross_profit_usd.saturating_sub(total_cost);
        if net_profit_usd.is_zero() {
            return Classification {
                gross_profit: quote.profit,
                gross_profit_usd,
                flash_cost_usd,
                gas_cost_usd: self.gas_cost_usd,
                estimated_net_profit_usd: U256::ZERO,
                threshold_usd: U256::ZERO,
                shortfall_usd: total_cost.saturating_sub(gross_profit_usd),
                reason: ClassificationReason::NotProfitable,
            };
        }

        let Some(threshold_usd) = self
            .gas_cost_usd
            .checked_mul(scale)
            .and_then(|value| value.checked_div(self.expected_win_rate))
        else {
            return not_evaluated(quote, "submission-gate threshold overflow");
        };

        let reason = if net_profit_usd > threshold_usd {
            ClassificationReason::AboveThreshold
        } else {
            ClassificationReason::BelowThreshold
        };
        let shortfall_usd = if matches!(reason, ClassificationReason::AboveThreshold) {
            U256::ZERO
        } else {
            threshold_usd.saturating_sub(net_profit_usd)
        };

        Classification {
            gross_profit: quote.profit,
            gross_profit_usd,
            flash_cost_usd,
            gas_cost_usd: self.gas_cost_usd,
            estimated_net_profit_usd: net_profit_usd,
            threshold_usd,
            shortfall_usd,
            reason,
        }
    }

    /// Route-shaped classification: gas cost derived from the live snapshot
    /// (`units × gas_price_wei × native_token_usd`), plus an explicit
    /// data-availability fee term (audit S4). A triangle is priced with its
    /// own unit count instead of a pair's scalar.
    ///
    /// # Errors
    ///
    /// Never returns `Err`; failures classify as
    /// [`ClassificationReason::NotEvaluated`] with the cause.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn classify_route(
        &self,
        quote: &OptimalQuote,
        snapshot: &CostSnapshot,
        gas_units: u64,
        da_fee_override_usd: Option<U256>,
    ) -> Classification {
        let scale = U256::from(FIXED_POINT_SCALE);

        if !snapshot.gas_price_age_valid {
            return not_evaluated(quote, "gas price is stale");
        }
        if !snapshot.reference_price_valid {
            return not_evaluated(quote, "reference price is stale");
        }
        if snapshot.usd_per_token.is_zero() {
            return not_evaluated(quote, "reference price is zero");
        }
        if self.expected_win_rate.is_zero() {
            return not_evaluated(quote, "expected win rate is zero");
        }
        if self.native_token_usd.is_zero() || snapshot.gas_price_wei.is_zero() {
            return not_evaluated(quote, "native or gas price unset; gas cost unknown");
        }

        // `units × wei` is an ETH-wei cost; one scale division converts it
        // to USD fixed-point via the native price. (A previous draft divided
        // by scale², flooring every real gas price to zero and silently
        // gating at free gas.)
        let Some(gas_cost_usd) = U256::from(gas_units)
            .checked_mul(snapshot.gas_price_wei)
            .and_then(|v| v.checked_mul(self.native_token_usd))
            .and_then(|v| v.checked_div(scale))
        else {
            return not_evaluated(quote, "gas cost conversion overflow");
        };
        let da_fee_usd = da_fee_override_usd.unwrap_or(self.da_fee_usd);
        let Some(total_cost) = flash_cost_usd_checked(quote, self, snapshot, scale) else {
            return not_evaluated(quote, "flash cost overflow");
        };
        let Some(total_cost) = total_cost
            .checked_add(gas_cost_usd)
            .and_then(|v| v.checked_add(da_fee_usd))
        else {
            return not_evaluated(quote, "cost sum overflow");
        };

        let Some(gross_profit_usd) = gross_profit_usd_of(quote, snapshot, scale) else {
            return not_evaluated(quote, "gross profit conversion overflow");
        };
        let net_profit_usd = gross_profit_usd.saturating_sub(total_cost);
        let Some(threshold_usd) = gas_cost_usd
            .checked_add(da_fee_usd)
            .and_then(|gate_base| gate_base.checked_mul(scale))
            .and_then(|value| value.checked_div(self.expected_win_rate))
        else {
            return not_evaluated(quote, "submission-gate threshold overflow");
        };

        if net_profit_usd.is_zero() {
            return Classification {
                gross_profit: quote.profit,
                gross_profit_usd,
                flash_cost_usd: flash_cost_of(quote, self, snapshot, scale),
                gas_cost_usd,
                estimated_net_profit_usd: U256::ZERO,
                threshold_usd,
                shortfall_usd: total_cost.saturating_sub(gross_profit_usd),
                reason: ClassificationReason::NotProfitable,
            };
        }

        let reason = if net_profit_usd > threshold_usd {
            ClassificationReason::AboveThreshold
        } else {
            ClassificationReason::BelowThreshold
        };
        let shortfall_usd = if matches!(reason, ClassificationReason::AboveThreshold) {
            U256::ZERO
        } else {
            threshold_usd.saturating_sub(net_profit_usd)
        };

        Classification {
            gross_profit: quote.profit,
            gross_profit_usd,
            flash_cost_usd: flash_cost_of(quote, self, snapshot, scale),
            gas_cost_usd,
            estimated_net_profit_usd: net_profit_usd,
            threshold_usd,
            shortfall_usd,
            reason,
        }
    }
}

fn gross_profit_usd_of(quote: &OptimalQuote, snapshot: &CostSnapshot, scale: U256) -> Option<U256> {
    quote
        .profit
        .checked_mul(snapshot.usd_per_token)
        .and_then(|value| value.checked_div(scale))
}

/// Flash-loan fee for the quote's input, USD fixed-point.
fn flash_cost_of(
    quote: &OptimalQuote,
    economics: &Economics,
    snapshot: &CostSnapshot,
    scale: U256,
) -> U256 {
    let input_usd = quote
        .input
        .checked_mul(snapshot.usd_per_token)
        .and_then(|value| value.checked_div(scale));
    input_usd
        .and_then(|v| v.checked_mul(economics.flash_fee_rate))
        .and_then(|v| v.checked_div(scale))
        .unwrap_or(U256::MAX)
}

/// Checked variant used for control flow inside [`Economics::classify_route`].
fn flash_cost_usd_checked(
    quote: &OptimalQuote,
    economics: &Economics,
    snapshot: &CostSnapshot,
    scale: U256,
) -> Option<U256> {
    let value = flash_cost_of(quote, economics, snapshot, scale);
    if value == U256::MAX {
        None
    } else {
        Some(value)
    }
}

fn not_evaluated(quote: &OptimalQuote, detail: &str) -> Classification {
    Classification {
        gross_profit: quote.profit,
        gross_profit_usd: U256::ZERO,
        flash_cost_usd: U256::ZERO,
        gas_cost_usd: U256::ZERO,
        estimated_net_profit_usd: U256::ZERO,
        threshold_usd: U256::ZERO,
        shortfall_usd: U256::ZERO,
        reason: ClassificationReason::NotEvaluated {
            detail: detail.to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate_fixture() -> (Economics, CostSnapshot) {
        let scale = U256::from(FIXED_POINT_SCALE);
        let economics = Economics {
            flash_fee_rate: U256::ZERO,
            gas_cost_usd: scale, // $1 gas
            expected_win_rate: gate_defaults::STANDARD_EXPECTED_WIN_RATE,
            native_token_usd: scale,
            da_fee_usd: U256::ZERO,
        };
        let snapshot = CostSnapshot {
            usd_per_token: scale, // $1/token: token profit == USD profit
            gas_price_age_valid: true,
            reference_price_valid: true,
            gas_price_wei: U256::from(1u64),
        };
        (economics, snapshot)
    }

    #[test]
    fn standard_floor_sits_just_under_3x_gas() {
        let scale = U256::from(FIXED_POINT_SCALE);
        let gas = scale; // $1
        let threshold = gas
            .checked_mul(scale)
            .and_then(|value| value.checked_div(gate_defaults::STANDARD_EXPECTED_WIN_RATE))
            .expect("floor computes");
        let three_x = gas.checked_mul(U256::from(3u64)).expect("3x computes");
        assert!(
            threshold < three_x,
            "floor {threshold} must sit under 3x gas {three_x}"
        );
        // ...but not far under: the rate stays within (33.3%, 33.5%].
        assert!(gate_defaults::STANDARD_EXPECTED_WIN_RATE > U256::from(333_000_000_000_000_000u64));
        assert!(gate_defaults::STANDARD_EXPECTED_WIN_RATE <= U256::from(335_000_000_000_000_000u64));
    }

    #[test]
    fn three_x_gas_net_profit_gates_above_threshold() {
        let (economics, snapshot) = gate_fixture();
        let scale = U256::from(FIXED_POINT_SCALE);
        // Net $3 on $1 gas (flash fee zero, gross $4).
        let quote = OptimalQuote {
            input: U256::ZERO,
            output: U256::ZERO,
            profit: scale.checked_mul(U256::from(4u64)).expect("gross"),
        };
        let classification = economics.classify(&quote, &snapshot);
        assert_eq!(classification.reason, ClassificationReason::AboveThreshold);
        assert_eq!(classification.shortfall_usd, U256::ZERO);
    }

    #[test]
    fn sub_3x_gas_net_profit_stays_below_threshold() {
        let (economics, snapshot) = gate_fixture();
        let scale = U256::from(FIXED_POINT_SCALE);
        // Net $2.99 on $1 gas stays below the ~$2.9994 floor.
        let quote = OptimalQuote {
            input: U256::ZERO,
            output: U256::ZERO,
            profit: scale
                .checked_mul(U256::from(399u64))
                .and_then(|value| value.checked_div(U256::from(100u64)))
                .expect("gross"),
        };
        let classification = economics.classify(&quote, &snapshot);
        assert_eq!(classification.reason, ClassificationReason::BelowThreshold);
    }
}
