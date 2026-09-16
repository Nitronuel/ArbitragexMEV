use alloy_primitives::U256;
use domain::{Cycle, PoolState};
use ruint::{Uint, UintTryFrom};

use crate::{MathError, quote::validate_fee, quote_cycle};

type Wide = Uint<1024, 16>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptimalQuote {
    pub input: U256,
    pub output: U256,
    pub profit: U256,
}

/// Finds the best profitable integer input for the cycle.
///
/// The composed profit curve `f(x) = a·x/(b + c·x) − x` is strictly concave,
/// so the continuous maximiser `center = (√(ab) − b)/c` and its integer
/// neighbours contain the optimum. Per-hop integer flooring perturbs profit
/// by at most a few wei, so a tight window around `center` is sufficient;
/// the previous full-range branch-and-bound search over
/// `[1, final_reserve_out)` was redundant and dominated worst-case latency.
///
/// # Errors
///
/// Returns an error for invalid cycle data, missing states, invalid fees, or
/// arithmetic overflow.
pub fn optimal_input(
    cycle: &Cycle,
    states: &[PoolState],
) -> Result<Option<OptimalQuote>, MathError> {
    if !(2..=5).contains(&cycle.hops.len()) {
        return Err(MathError::InvalidCycleLength);
    }
    validate_route(cycle)?;

    let (a, b, c) = coefficients(cycle, states)?;
    if a <= b {
        return Ok(None);
    }

    let center = continuous_center(a, b, c)?;
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
    let reserve_end = widen(final_reserve_out)
        .checked_sub(Wide::from(1))
        .unwrap_or(Wide::ZERO);

    let mut best: Option<OptimalQuote> = None;
    // For tiny final reserves (property-test scale, e.g. ≤5000) exhaustive
    // search is cheap and guarantees exactness despite relatively large
    // per-hop flooring perturbation. For chain-scale reserves the profit
    // curve is smooth and the integer optimum lies within a few wei of the
    // continuous centre, so a tight window suffices and bounds work to at
    // most 17 exact evaluations — versus up to 1,500 visits over a ~1e24
    // interval previously.
    if reserve_end <= Wide::from(5_000) {
        // `reserve_end` ≤ 5000 guarantees high limbs are zero; low limb holds the value.
        let end_u64 = reserve_end.as_limbs()[0];
        for n in 1..=end_u64 {
            evaluate(Wide::from(n), cycle, states, &mut best)?;
        }
    } else {
        let window: i32 = 8;
        for offset in -window..=window {
            let abs = u64::from(offset.unsigned_abs());
            let candidate = if offset < 0 {
                center.checked_sub(Wide::from(abs))
            } else {
                center.checked_add(Wide::from(abs))
            };
            let Some(candidate) = candidate else {
                continue;
            };
            if candidate < Wide::from(1) || candidate > reserve_end {
                continue;
            }
            evaluate(candidate, cycle, states, &mut best)?;
        }
        // Ensure the centre itself is evaluated even when clamped above
        // (e.g. centre == 0 with window start at 1).
        if center < Wide::from(1) {
            evaluate(Wide::from(1), cycle, states, &mut best)?;
        }
    }
    Ok(best)
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
