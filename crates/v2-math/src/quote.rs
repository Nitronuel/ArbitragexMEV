use alloy_primitives::U256;
use domain::{Cycle, Fee, PoolState};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MathError {
    #[error("fee must satisfy 0 < numerator <= denominator")]
    InvalidFee,
    #[error("pool reserves must be non-zero")]
    ZeroReserve,
    #[error("arithmetic overflow")]
    Overflow,
    #[error("cycle must contain between two and four hops")]
    InvalidCycleLength,
    #[error("pool state {0} is missing")]
    MissingPoolState(u32),
}

/// Quotes one constant-product hop with exact floor division.
///
/// # Errors
///
/// Returns an error for an invalid fee, zero reserve, or any intermediate
/// arithmetic overflow.
pub fn quote_hop(
    input: U256,
    reserve_in: U256,
    reserve_out: U256,
    fee: Fee,
) -> Result<U256, MathError> {
    validate_fee(fee)?;
    if reserve_in.is_zero() || reserve_out.is_zero() {
        return Err(MathError::ZeroReserve);
    }
    if input.is_zero() {
        return Ok(U256::ZERO);
    }

    let numerator = U256::from(fee.numerator);
    let denominator = U256::from(fee.denominator);
    let input_with_fee = input.checked_mul(numerator).ok_or(MathError::Overflow)?;
    let output_numerator = input_with_fee
        .checked_mul(reserve_out)
        .ok_or(MathError::Overflow)?;
    let output_denominator = reserve_in
        .checked_mul(denominator)
        .and_then(|value| value.checked_add(input_with_fee))
        .ok_or(MathError::Overflow)?;
    Ok(output_numerator / output_denominator)
}

/// Replays a cycle against locally supplied pool states.
///
/// # Errors
///
/// Returns an error when the cycle shape or state index is invalid, or a hop
/// quote fails.
pub fn quote_cycle(input: U256, cycle: &Cycle, states: &[PoolState]) -> Result<U256, MathError> {
    if !(2..=4).contains(&cycle.hops.len()) {
        return Err(MathError::InvalidCycleLength);
    }

    cycle.hops.iter().try_fold(input, |amount, hop| {
        let index = usize::try_from(hop.pool_id.0).map_err(|_| MathError::Overflow)?;
        let state = states
            .get(index)
            .ok_or(MathError::MissingPoolState(hop.pool_id.0))?;
        let (reserve_in, reserve_out) = if hop.zero_for_one {
            (state.reserve0, state.reserve1)
        } else {
            (state.reserve1, state.reserve0)
        };
        quote_hop(amount, reserve_in, reserve_out, hop.fee)
    })
}

pub(crate) fn validate_fee(fee: Fee) -> Result<(), MathError> {
    if fee.numerator == 0 || fee.denominator == 0 || fee.numerator > fee.denominator {
        return Err(MathError::InvalidFee);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, U256};
    use domain::{Cycle, CycleHop, CycleId, Fee, PoolId, PoolState, StateVersion};

    use super::{MathError, quote_cycle, quote_hop};

    #[test]
    fn quotes_no_fee_with_floor_division() {
        let output = quote_hop(
            U256::from(100),
            U256::from(1_000),
            U256::from(1_000),
            Fee {
                numerator: 1,
                denominator: 1,
            },
        )
        .unwrap();
        assert_eq!(output, U256::from(90));
    }

    #[test]
    fn quotes_canonical_thirty_basis_point_fee() {
        let output = quote_hop(
            U256::from(100),
            U256::from(1_000),
            U256::from(1_000),
            Fee {
                numerator: 997,
                denominator: 1_000,
            },
        )
        .unwrap();
        assert_eq!(output, U256::from(90));
    }

    #[test]
    fn zero_input_returns_zero() {
        let output = quote_hop(
            U256::ZERO,
            U256::from(1_000),
            U256::from(1_000),
            Fee {
                numerator: 997,
                denominator: 1_000,
            },
        )
        .unwrap();
        assert_eq!(output, U256::ZERO);
    }

    #[test]
    fn rejects_zero_reserves_and_overflow() {
        let fee = Fee {
            numerator: 997,
            denominator: 1_000,
        };
        assert!(quote_hop(U256::from(1), U256::ZERO, U256::from(1), fee).is_err());
        assert!(quote_hop(U256::from(1), U256::from(1), U256::ZERO, fee).is_err());
        assert!(quote_hop(U256::MAX, U256::from(1), U256::from(1), fee).is_err());
    }

    #[test]
    fn rejects_invalid_fees() {
        let reserve = U256::from(1_000);
        for fee in [
            Fee {
                numerator: 0,
                denominator: 1_000,
            },
            Fee {
                numerator: 1,
                denominator: 0,
            },
            Fee {
                numerator: 1_001,
                denominator: 1_000,
            },
        ] {
            assert_eq!(
                quote_hop(U256::from(1), reserve, reserve, fee),
                Err(MathError::InvalidFee)
            );
        }
    }

    #[test]
    fn cycle_uses_pool_index_and_reverse_direction() {
        let anchor = Address::repeat_byte(1);
        let token = Address::repeat_byte(2);
        let fee = Fee {
            numerator: 1,
            denominator: 1,
        };
        let cycle = Cycle {
            id: CycleId(0),
            anchor,
            hops: vec![
                CycleHop {
                    pool_id: PoolId(1),
                    token_in: anchor,
                    token_out: token,
                    fee,
                    zero_for_one: false,
                },
                CycleHop {
                    pool_id: PoolId(0),
                    token_in: token,
                    token_out: anchor,
                    fee,
                    zero_for_one: true,
                },
            ],
        };
        let states = [
            PoolState {
                reserve0: U256::from(1_000),
                reserve1: U256::from(1_000),
                block_number: 1,
                transaction_index: 0,
                log_index: 0,
                version: StateVersion(1),
            },
            PoolState {
                reserve0: U256::from(2_000),
                reserve1: U256::from(1_000),
                block_number: 1,
                transaction_index: 0,
                log_index: 0,
                version: StateVersion(1),
            },
        ];

        assert_eq!(
            quote_cycle(U256::from(100), &cycle, &states).unwrap(),
            U256::from(153)
        );
    }
}
