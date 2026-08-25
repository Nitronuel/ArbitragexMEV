use alloy_primitives::U256;
use domain::{Cycle, PoolState};
use ruint::{Uint, UintTryFrom};

use crate::{MathError, quote::validate_fee, quote_cycle};

type Wide = Uint<4096, 64>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptimalQuote {
    pub input: U256,
    pub output: U256,
    pub profit: U256,
}

/// Finds the best profitable integer input for the cycle.
///
/// The composed no-floor curve bounds exact output from above. Intervals whose
/// bound cannot improve the best exact replay are pruned.
///
/// # Errors
///
/// Returns an error for invalid cycle data, missing states, invalid fees, or
/// arithmetic overflow.
pub fn optimal_input(
    cycle: &Cycle,
    states: &[PoolState],
) -> Result<Option<OptimalQuote>, MathError> {
    if !(2..=4).contains(&cycle.hops.len()) {
        return Err(MathError::InvalidCycleLength);
    }
    validate_route(cycle)?;

    let (a, b, c) = coefficients(cycle, states)?;
    if a <= b {
        return Ok(None);
    }

    let mut best = None;
    let center = continuous_center(a, b, c)?;
    evaluate(center.max(Wide::from(1)), cycle, states, &mut best)?;
    evaluate(
        center
            .checked_add(Wide::from(1))
            .ok_or(MathError::Overflow)?,
        cycle,
        states,
        &mut best,
    )?;

    let last_hop = cycle.hops.last().ok_or(MathError::InvalidCycleLength)?;
    let last_index = usize::try_from(last_hop.pool_id.0).map_err(|_| MathError::Overflow)?;
    let last_state = states
        .get(last_index)
        .ok_or(MathError::MissingPoolState(last_hop.pool_id.0))?;
    let final_reserve_out = if last_hop.zero_for_one {
        last_state.reserve1
    } else {
        last_state.reserve0
    };
    let end = widen(final_reserve_out)
        .checked_sub(Wide::from(1))
        .ok_or(MathError::ZeroReserve)?;
    if end >= Wide::from(1) {
        search_interval(Wide::from(1), end, (a, b, c), cycle, states, &mut best)?;
    }
    Ok(best)
}

#[allow(clippy::large_types_passed_by_value)]
fn search_interval(
    start: Wide,
    end: Wide,
    coefficients: (Wide, Wide, Wide),
    cycle: &Cycle,
    states: &[PoolState],
    best: &mut Option<OptimalQuote>,
) -> Result<(), MathError> {
    let (a, b, c) = coefficients;
    let center = continuous_center(a, b, c)?;
    let mut stack = vec![(start, end)];
    let mut budget = MAX_INTERVAL_VISITS;
    while let Some((start, end)) = stack.pop() {
        if budget == 0 {
            return Ok(());
        }
        budget -= 1;

        let best_profit = best.map_or(Wide::ZERO, |quote| widen(quote.profit));
        if ideal_profit_bound(start, end, coefficients, center)? <= best_profit {
            continue;
        }
        if start == end {
            evaluate(start, cycle, states, best)?;
            continue;
        }

        let middle = start
            .checked_add(end.checked_sub(start).ok_or(MathError::Overflow)? / Wide::from(2))
            .ok_or(MathError::Overflow)?;
        let left = (start, middle);
        let right = (
            middle
                .checked_add(Wide::from(1))
                .ok_or(MathError::Overflow)?,
            end,
        );
        if center <= middle {
            stack.push(right);
            stack.push(left);
        } else {
            stack.push(left);
            stack.push(right);
        }
    }
    Ok(())
}

/// Visit budget for the interval search. Bounds worst-case quote latency
/// (~0.15ms per visit) so a pathological reserve configuration cannot stall
/// the polling loop. On budget exhaustion the best input found so far is
/// returned; on extreme asymmetric reserves that may sit integer-floor dust
/// below the true optimum, which is acceptable for gate classification.
const MAX_INTERVAL_VISITS: usize = 1_500;

#[allow(clippy::large_types_passed_by_value)]
fn ideal_profit_bound(
    start: Wide,
    end: Wide,
    coefficients: (Wide, Wide, Wide),
    center: Wide,
) -> Result<Wide, MathError> {
    let (a, b, c) = coefficients;
    let next = center
        .checked_add(Wide::from(1))
        .ok_or(MathError::Overflow)?;
    [start, end, center.clamp(start, end), next.clamp(start, end)]
        .into_iter()
        .try_fold(Wide::ZERO, |bound, input| {
            let denominator = b
                .checked_add(c.checked_mul(input).ok_or(MathError::Overflow)?)
                .ok_or(MathError::Overflow)?;
            let output = a.checked_mul(input).ok_or(MathError::Overflow)? / denominator;
            Ok(bound.max(output.saturating_sub(input)))
        })
}

#[allow(clippy::large_types_passed_by_value)]
fn continuous_center(a: Wide, b: Wide, c: Wide) -> Result<Wide, MathError> {
    let root = a.checked_mul(b).ok_or(MathError::Overflow)?.root(2);
    Ok(root.saturating_sub(b) / c)
}

#[allow(clippy::large_types_passed_by_value)]
fn evaluate(
    candidate: Wide,
    cycle: &Cycle,
    states: &[PoolState],
    best: &mut Option<OptimalQuote>,
) -> Result<(), MathError> {
    let Ok(input) = U256::uint_try_from(candidate) else {
        return Ok(());
    };
    let output = quote_cycle(input, cycle, states)?;
    if output <= input {
        return Ok(());
    }

    let quote = OptimalQuote {
        input,
        output,
        profit: output - input,
    };
    if best.is_none_or(|current| {
        quote.profit > current.profit
            || (quote.profit == current.profit && quote.input < current.input)
    }) {
        *best = Some(quote);
    }
    Ok(())
}

fn coefficients(cycle: &Cycle, states: &[PoolState]) -> Result<(Wide, Wide, Wide), MathError> {
    let mut coefficients = None;
    for hop in &cycle.hops {
        validate_fee(hop.fee)?;
        let index = usize::try_from(hop.pool_id.0).map_err(|_| MathError::Overflow)?;
        let state = states
            .get(index)
            .ok_or(MathError::MissingPoolState(hop.pool_id.0))?;
        let (reserve_in, reserve_out) = if hop.zero_for_one {
            (state.reserve0, state.reserve1)
        } else {
            (state.reserve1, state.reserve0)
        };
        if reserve_in.is_zero() || reserve_out.is_zero() {
            return Err(MathError::ZeroReserve);
        }

        let numerator = Wide::from(hop.fee.numerator);
        let denominator = Wide::from(hop.fee.denominator);
        let hop_a = numerator
            .checked_mul(widen(reserve_out))
            .ok_or(MathError::Overflow)?;
        let hop_b = denominator
            .checked_mul(widen(reserve_in))
            .ok_or(MathError::Overflow)?;
        let hop_c = numerator;

        coefficients = Some(match coefficients {
            None => (hop_a, hop_b, hop_c),
            Some((a, b, c)) => {
                let next_a = hop_a.checked_mul(a).ok_or(MathError::Overflow)?;
                let next_b = hop_b.checked_mul(b).ok_or(MathError::Overflow)?;
                let next_c = hop_b
                    .checked_mul(c)
                    .and_then(|value| {
                        hop_c
                            .checked_mul(a)
                            .and_then(|term| value.checked_add(term))
                    })
                    .ok_or(MathError::Overflow)?;
                (next_a, next_b, next_c)
            }
        });
    }
    coefficients.ok_or(MathError::InvalidCycleLength)
}

fn widen(value: U256) -> Wide {
    Wide::from_limbs_slice(value.as_limbs())
}

/// Rejects a cycle whose hops do not form a closed route: each hop must take
/// its `token_in` from the previous hop's `token_out`, the first hop must
/// start at the cycle's anchor, and the last hop must return to it.
///
/// Without this guard a structurally impossible cycle — legs drawn from two
/// different token pairs, for instance — prices silently and reports P&L for
/// a route that cannot exist (audit finding S7).
///
/// # Errors
///
/// Returns [`MathError::DiscontinuousRoute`] naming the first broken seam.
pub fn validate_route(cycle: &Cycle) -> Result<(), MathError> {
    let Some(first) = cycle.hops.first() else {
        return Err(MathError::InvalidCycleLength);
    };
    if first.token_in != cycle.anchor {
        return Err(MathError::DiscontinuousRoute(
            0,
            format!("anchor {}", cycle.anchor),
            format!("{}", first.token_in),
        ));
    }
    for (index, pair) in cycle.hops.windows(2).enumerate() {
        if pair[0].token_out != pair[1].token_in {
            return Err(MathError::DiscontinuousRoute(
                index + 1,
                format!("{}", pair[0].token_out),
                format!("{}", pair[1].token_in),
            ));
        }
    }
    if let Some(last) = cycle.hops.last()
        && last.token_out != cycle.anchor
    {
        let index = cycle.hops.len().saturating_sub(1);
        return Err(MathError::DiscontinuousRoute(
            index,
            format!("{}", last.token_out),
            format!("anchor {}", cycle.anchor),
        ));
    }
    Ok(())
}
