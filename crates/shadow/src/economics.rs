use alloy_primitives::U256;
use v2_math::OptimalQuote;

/// Fixed-point scale for every USD-denominated economic value.
pub const FIXED_POINT_SCALE: u128 = 1_000_000_000_000_000_000;

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
}

impl CostSnapshot {
    #[must_use]
    pub const fn invalid() -> Self {
        Self {
            usd_per_token: U256::ZERO,
            gas_price_age_valid: false,
            reference_price_valid: false,
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
    /// Conservative gas cost for one attempt, USD fixed-point.
    pub gas_cost_usd: U256,
    /// Expected win rate, a fixed-point fraction.
    pub expected_win_rate: U256,
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

        let Some(gross_profit_usd) = quote
            .profit
            .checked_mul(snapshot.usd_per_token)
            .and_then(|value| value.checked_div(scale))
        else {
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

        Classification {
            gross_profit: quote.profit,
            gross_profit_usd,
            flash_cost_usd,
            gas_cost_usd: self.gas_cost_usd,
            estimated_net_profit_usd: net_profit_usd,
            threshold_usd,
            reason,
        }
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
        reason: ClassificationReason::NotEvaluated {
            detail: detail.to_owned(),
        },
    }
}
