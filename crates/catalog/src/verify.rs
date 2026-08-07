use alloy_primitives::{Address, U256};
use domain::{Fee, Pool, PoolId, PoolState, StateVersion};
use thiserror::Error;

use crate::CandidatePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactorySpec {
    pub address: Address,
    pub fee: Fee,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPool {
    pub pool: Pool,
    pub token0_decimals: u8,
    pub token1_decimals: u8,
    pub initial_state: PoolState,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedPool {
    pub candidate: CandidatePool,
    pub reason: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CatalogResult {
    pub verified: Vec<VerifiedPool>,
    pub quarantined: Vec<QuarantinedPool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RpcError {
    #[error("pinned block is unavailable")]
    PinnedBlockUnavailable,
    #[error("RPC call failed: {0}")]
    Call(String),
}

/// Read-only calls required to verify a catalog at one pinned block.
///
/// Implementations must return [`RpcError::PinnedBlockUnavailable`] whenever
/// the requested block cannot be served. Other call failures are pool-local.
#[allow(clippy::missing_errors_doc)]
pub trait CatalogRpc {
    fn chain_id(&self, block: u64) -> Result<u64, RpcError>;
    fn get_code(&self, address: Address, block: u64) -> Result<Vec<u8>, RpcError>;
    fn factory(&self, pair: Address, block: u64) -> Result<Address, RpcError>;
    fn token0(&self, pair: Address, block: u64) -> Result<Address, RpcError>;
    fn token1(&self, pair: Address, block: u64) -> Result<Address, RpcError>;
    fn get_pair(
        &self,
        factory: Address,
        token0: Address,
        token1: Address,
        block: u64,
    ) -> Result<Address, RpcError>;
    fn decimals(&self, token: Address, block: u64) -> Result<u8, RpcError>;
    fn get_reserves(&self, pair: Address, block: u64) -> Result<(U256, U256), RpcError>;
}

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("unexpected chain ID {0} for this catalog")]
    WrongChain(u64),
    #[error("pinned block {0} is unavailable")]
    PinnedBlockUnavailable(u64),
    #[error("catalog exceeds the 2,000-pool cap")]
    PoolCapExceeded,
}

/// Verifies candidate contracts and metadata at one pinned block.
///
/// The expected chain is derived from the candidates' own `chain_id`; the live
/// RPC must report the same chain or the bootstrap aborts. Candidate-local
/// failures are quarantined.
///
/// # Errors
///
/// Returns a fatal error when the RPC reports a chain other than the catalog's
/// chain or cannot serve the pinned block.
pub fn verify_catalog<R: CatalogRpc>(
    candidates: Vec<CandidatePool>,
    factories: &[FactorySpec],
    block: u64,
    rpc: &R,
) -> Result<CatalogResult, CatalogError> {
    if candidates.len() > 2_000 {
        return Err(CatalogError::PoolCapExceeded);
    }
    let Some(expected) = candidates.first().map(|candidate| candidate.chain_id) else {
        return Ok(CatalogResult::default());
    };
    let actual = fatal(rpc.chain_id(block), block)?;
    if actual != expected {
        return Err(CatalogError::WrongChain(actual));
    }

    let mut result = CatalogResult::default();
    for candidate in candidates {
        if candidate.chain_id != expected {
            result.quarantined.push(QuarantinedPool {
                candidate,
                reason: "candidate chain ID mismatch".to_owned(),
            });
            continue;
        }
        match verify_candidate(&candidate, factories, block, rpc) {
            Ok(mut verified) => {
                let id = u32::try_from(result.verified.len())
                    .map_err(|_| CatalogError::PoolCapExceeded)?;
                verified.pool.id = PoolId(id);
                result.verified.push(verified);
            }
            Err(VerifyFailure::Fatal) => {
                return Err(CatalogError::PinnedBlockUnavailable(block));
            }
            Err(VerifyFailure::Quarantine(reason)) => result
                .quarantined
                .push(QuarantinedPool { candidate, reason }),
        }
    }
    Ok(result)
}

enum VerifyFailure {
    Fatal,
    Quarantine(String),
}

fn verify_candidate<R: CatalogRpc>(
    candidate: &CandidatePool,
    factories: &[FactorySpec],
    block: u64,
    rpc: &R,
) -> Result<VerifiedPool, VerifyFailure> {
    let spec = factories
        .iter()
        .find(|factory| factory.address == candidate.factory)
        .ok_or_else(|| VerifyFailure::Quarantine("unknown factory".to_owned()))?;
    if spec.fee != candidate.fee {
        return Err(VerifyFailure::Quarantine(
            "unsupported factory fee".to_owned(),
        ));
    }

    let code = local(rpc.get_code(candidate.address, block))?;
    if code.is_empty() {
        return Err(VerifyFailure::Quarantine("empty pair bytecode".to_owned()));
    }
    if local(rpc.factory(candidate.address, block))? != candidate.factory {
        return Err(VerifyFailure::Quarantine(
            "pair factory mismatch".to_owned(),
        ));
    }
    if local(rpc.token0(candidate.address, block))? != candidate.token0
        || local(rpc.token1(candidate.address, block))? != candidate.token1
    {
        return Err(VerifyFailure::Quarantine("pair token mismatch".to_owned()));
    }
    if local(rpc.get_pair(candidate.factory, candidate.token0, candidate.token1, block))?
        != candidate.address
    {
        return Err(VerifyFailure::Quarantine(
            "factory get_pair mismatch".to_owned(),
        ));
    }

    let token0_decimals = local(rpc.decimals(candidate.token0, block))?;
    let token1_decimals = local(rpc.decimals(candidate.token1, block))?;
    if token0_decimals > 36 || token1_decimals > 36 {
        return Err(VerifyFailure::Quarantine(
            "unsupported token decimals".to_owned(),
        ));
    }
    let (reserve0, reserve1) = local(rpc.get_reserves(candidate.address, block))?;
    if reserve0.is_zero() || reserve1.is_zero() {
        return Err(VerifyFailure::Quarantine("zero reserves".to_owned()));
    }

    Ok(VerifiedPool {
        pool: Pool {
            id: PoolId(0),
            address: candidate.address,
            token0: candidate.token0,
            token1: candidate.token1,
            fee: candidate.fee,
            profile: candidate.profile,
        },
        token0_decimals,
        token1_decimals,
        initial_state: PoolState {
            reserve0,
            reserve1,
            block_number: block,
            transaction_index: 0,
            log_index: 0,
            version: StateVersion(0),
        },
        source: candidate.source.clone(),
    })
}

fn fatal<T>(result: Result<T, RpcError>, block: u64) -> Result<T, CatalogError> {
    result.map_err(|_| CatalogError::PinnedBlockUnavailable(block))
}

fn local<T>(result: Result<T, RpcError>) -> Result<T, VerifyFailure> {
    result.map_err(|error| match error {
        RpcError::PinnedBlockUnavailable => VerifyFailure::Fatal,
        RpcError::Call(message) => VerifyFailure::Quarantine(message),
    })
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, U256};
    use domain::{Fee, Profile};

    use super::{CatalogError, CatalogRpc, FactorySpec, RpcError, verify_catalog};
    use crate::CandidatePool;

    const BLOCK: u64 = 20_000_000;
    const FEE: Fee = Fee {
        numerator: 997,
        denominator: 1_000,
    };

    #[derive(Clone)]
    struct FakeRpc {
        chain_id: Result<u64, RpcError>,
        code: Result<Vec<u8>, RpcError>,
        factory: Result<Address, RpcError>,
        token0: Result<Address, RpcError>,
        token1: Result<Address, RpcError>,
        pair: Result<Address, RpcError>,
        decimals: Result<u8, RpcError>,
        reserves: Result<(U256, U256), RpcError>,
    }

    impl CatalogRpc for FakeRpc {
        fn chain_id(&self, _block: u64) -> Result<u64, RpcError> {
            self.chain_id.clone()
        }
        fn get_code(&self, _address: Address, _block: u64) -> Result<Vec<u8>, RpcError> {
            self.code.clone()
        }
        fn factory(&self, _pair: Address, _block: u64) -> Result<Address, RpcError> {
            self.factory.clone()
        }
        fn token0(&self, _pair: Address, _block: u64) -> Result<Address, RpcError> {
            self.token0.clone()
        }
        fn token1(&self, _pair: Address, _block: u64) -> Result<Address, RpcError> {
            self.token1.clone()
        }
        fn get_pair(
            &self,
            _factory: Address,
            _token0: Address,
            _token1: Address,
            _block: u64,
        ) -> Result<Address, RpcError> {
            self.pair.clone()
        }
        fn decimals(&self, _token: Address, _block: u64) -> Result<u8, RpcError> {
            self.decimals.clone()
        }
        fn get_reserves(&self, _pair: Address, _block: u64) -> Result<(U256, U256), RpcError> {
            self.reserves.clone()
        }
    }

    fn candidate() -> CandidatePool {
        CandidatePool {
            chain_id: 8453,
            address: Address::repeat_byte(16),
            factory: Address::repeat_byte(32),
            token0: Address::repeat_byte(1),
            token1: Address::repeat_byte(2),
            fee: FEE,
            profile: Profile::ConstantProduct,
            source: "protocol deployment".to_owned(),
        }
    }

    fn rpc(candidate: &CandidatePool) -> FakeRpc {
        FakeRpc {
            chain_id: Ok(8453),
            code: Ok(vec![1]),
            factory: Ok(candidate.factory),
            token0: Ok(candidate.token0),
            token1: Ok(candidate.token1),
            pair: Ok(candidate.address),
            decimals: Ok(18),
            reserves: Ok((U256::from(1_000), U256::from(2_000))),
        }
    }

    fn factories(candidate: &CandidatePool) -> [FactorySpec; 1] {
        [FactorySpec {
            address: candidate.factory,
            fee: FEE,
        }]
    }

    #[test]
    fn verifies_matching_pool_at_pinned_block() {
        let candidate = candidate();
        let result = verify_catalog(
            vec![candidate.clone()],
            &factories(&candidate),
            BLOCK,
            &rpc(&candidate),
        )
        .unwrap();
        assert_eq!(result.verified.len(), 1);
        assert!(result.quarantined.is_empty());
        assert_eq!(result.verified[0].initial_state.block_number, BLOCK);
    }

    #[test]
    fn quarantines_unknown_factory_and_unsupported_fee() {
        let candidate = candidate();
        let result = verify_catalog(vec![candidate.clone()], &[], BLOCK, &rpc(&candidate)).unwrap();
        assert_eq!(result.quarantined.len(), 1);

        let wrong_fee = [FactorySpec {
            address: candidate.factory,
            fee: Fee {
                numerator: 998,
                denominator: 1_000,
            },
        }];
        let result =
            verify_catalog(vec![candidate.clone()], &wrong_fee, BLOCK, &rpc(&candidate)).unwrap();
        assert_eq!(result.quarantined.len(), 1);
    }

    #[test]
    fn quarantines_empty_code_spoofed_pair_and_factory_mismatch() {
        let candidate = candidate();
        let factory_specs = factories(&candidate);

        let mut fake = rpc(&candidate);
        fake.code = Ok(Vec::new());
        assert_eq!(
            verify_catalog(vec![candidate.clone()], &factory_specs, BLOCK, &fake)
                .unwrap()
                .quarantined
                .len(),
            1
        );

        let mut fake = rpc(&candidate);
        fake.factory = Ok(Address::repeat_byte(99));
        assert_eq!(
            verify_catalog(vec![candidate.clone()], &factory_specs, BLOCK, &fake)
                .unwrap()
                .quarantined
                .len(),
            1
        );

        let mut fake = rpc(&candidate);
        fake.token0 = Ok(Address::repeat_byte(99));
        assert_eq!(
            verify_catalog(vec![candidate.clone()], &factory_specs, BLOCK, &fake)
                .unwrap()
                .quarantined
                .len(),
            1
        );

        let mut fake = rpc(&candidate);
        fake.pair = Ok(Address::repeat_byte(99));
        assert_eq!(
            verify_catalog(vec![candidate.clone()], &factory_specs, BLOCK, &fake)
                .unwrap()
                .quarantined
                .len(),
            1
        );
    }

    #[test]
    fn quarantines_zero_reserves_unsupported_decimals_and_local_call_failure() {
        let candidate = candidate();
        let factory_specs = factories(&candidate);

        let mut fake = rpc(&candidate);
        fake.reserves = Ok((U256::ZERO, U256::from(1)));
        assert_eq!(
            verify_catalog(vec![candidate.clone()], &factory_specs, BLOCK, &fake)
                .unwrap()
                .quarantined
                .len(),
            1
        );

        let mut fake = rpc(&candidate);
        fake.decimals = Ok(37);
        assert_eq!(
            verify_catalog(vec![candidate.clone()], &factory_specs, BLOCK, &fake)
                .unwrap()
                .quarantined
                .len(),
            1
        );

        let mut fake = rpc(&candidate);
        fake.code = Err(RpcError::Call("revert".to_owned()));
        assert_eq!(
            verify_catalog(vec![candidate.clone()], &factory_specs, BLOCK, &fake)
                .unwrap()
                .quarantined
                .len(),
            1
        );
    }

    #[test]
    fn wrong_chain_and_unavailable_pinned_block_are_fatal() {
        let candidate = candidate();
        let factory_specs = factories(&candidate);
        let mut fake = rpc(&candidate);
        fake.chain_id = Ok(1);
        assert!(matches!(
            verify_catalog(vec![candidate.clone()], &factory_specs, BLOCK, &fake),
            Err(CatalogError::WrongChain(1))
        ));

        let mut fake = rpc(&candidate);
        fake.reserves = Err(RpcError::PinnedBlockUnavailable);
        assert!(matches!(
            verify_catalog(vec![candidate], &factory_specs, BLOCK, &fake),
            Err(CatalogError::PinnedBlockUnavailable(BLOCK))
        ));
    }

    #[test]
    fn assigns_compact_ids_and_quarantines_candidate_chain_mismatch() {
        let candidate = candidate();
        let verified = verify_catalog(
            vec![candidate.clone()],
            &factories(&candidate),
            BLOCK,
            &rpc(&candidate),
        )
        .unwrap();
        assert_eq!(verified.verified[0].pool.id.0, 0);

        let wrong_chain = CandidatePool {
            chain_id: 1,
            ..candidate.clone()
        };
        let result = verify_catalog(
            vec![candidate.clone(), wrong_chain],
            &factories(&candidate),
            BLOCK,
            &rpc(&candidate),
        )
        .unwrap();
        assert_eq!(result.verified.len(), 1);
        assert_eq!(result.quarantined.len(), 1);
    }
}
