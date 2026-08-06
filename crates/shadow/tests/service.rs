use std::{collections::HashSet, fmt::Write as _, fs, path::PathBuf};

use alloy_primitives::{Address, U256};
use catalog::{CatalogRpc, CycleLimits, FactorySpec, RpcError};
use domain::Fee;
use shadow::{
    CostSnapshot, Economics, FIXED_POINT_SCALE, ServiceError, ServiceSnapshot, replay_observation,
};
use storage::Storage;
use tempfile::TempDir;

const LIMITS: CycleLimits = CycleLimits {
    max_cycles: 1_000,
    max_cycles_per_pool: 1_000,
};

fn economics() -> Economics {
    let scale = U256::from(FIXED_POINT_SCALE);
    Economics {
        flash_fee_rate: U256::ZERO,
        gas_cost_usd: U256::from(1_000),
        expected_win_rate: scale,
    }
}

fn reference() -> CostSnapshot {
    CostSnapshot {
        usd_per_token: U256::from(FIXED_POINT_SCALE),
        gas_price_age_valid: true,
        reference_price_valid: true,
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/service/snapshot.json")
}

fn load_snapshot() -> ServiceSnapshot {
    serde_json::from_slice(&fs::read(fixture_path()).unwrap()).unwrap()
}

fn setup() -> (TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("shadow.sqlite");
    (directory, path)
}

#[test]
fn observe_snapshot_records_and_replays_matching_observations() {
    let snapshot = load_snapshot();
    let (_directory, db) = setup();

    let report = shadow::observe_snapshot(
        snapshot,
        20_669_u64 * 86_400_000,
        economics(),
        reference(),
        &db,
        1_000,
        LIMITS,
        24_000_000,
        5_000_000_000,
    )
    .unwrap();

    assert_eq!(report.pool_count, 2);
    assert_eq!(report.quarantined, 0);
    assert!(report.cycle_count >= 1);
    assert!(report.evaluated >= 1);
    assert!(report.recorded >= 1);

    let storage = Storage::open(&db).unwrap();
    let observations = storage.load_observations().unwrap();
    assert!(!observations.is_empty());
    for (id, _) in observations {
        let result = replay_observation(&storage, id).unwrap();
        assert!(result.matched, "observation {id} did not reproduce exactly");
    }
}

#[test]
fn observe_catalog_wires_verification_graph_and_evaluation() {
    let pools = two_factory_pools();
    let factories: Vec<FactorySpec> = pools
        .iter()
        .map(|pool| FactorySpec {
            address: pool.factory,
            fee: Fee {
                numerator: 997,
                denominator: 1_000,
            },
        })
        .collect();
    let anchors: HashSet<Address> = [Address::repeat_byte(1)].into_iter().collect();

    let (_directory, db) = setup();
    let report = shadow::observe_catalog(
        two_factory_manifest(4663).as_bytes(),
        &factories,
        &anchors,
        2_000_000,
        &TwoFactoryRpc {
            chain_id: Ok(4663),
            pools: pools.clone(),
        },
        two_factory_events(),
        20_669_u64 * 86_400_000,
        economics(),
        reference(),
        &db,
        1_000,
        LIMITS,
        24_000_000,
        5_000_000_000,
    )
    .unwrap();

    assert_eq!(report.pool_count, 2);
    assert_eq!(report.quarantined, 0);
    assert!(report.cycle_count >= 1);
    assert!(report.recorded >= 1);
}

#[test]
fn observe_catalog_fails_closed_on_wrong_chain_and_invalid_manifest() {
    let pools = two_factory_pools();
    let factories: Vec<FactorySpec> = pools
        .iter()
        .map(|pool| FactorySpec {
            address: pool.factory,
            fee: Fee {
                numerator: 997,
                denominator: 1_000,
            },
        })
        .collect();
    let anchors: HashSet<Address> = [Address::repeat_byte(1)].into_iter().collect();
    let (_directory, db) = setup();

    let invalid_chain = shadow::observe_catalog(
        two_factory_manifest(1).as_bytes(),
        &factories,
        &anchors,
        2_000_000,
        &TwoFactoryRpc {
            chain_id: Ok(4663),
            pools: pools.clone(),
        },
        vec![],
        1,
        economics(),
        reference(),
        &db,
        1_000,
        LIMITS,
        24_000_000,
        5_000_000_000,
    )
    .unwrap_err();
    assert!(matches!(invalid_chain, ServiceError::Manifest(_)));

    let wrong_chain_rpc = shadow::observe_catalog(
        two_factory_manifest(4663).as_bytes(),
        &factories,
        &anchors,
        2_000_000,
        &TwoFactoryRpc {
            chain_id: Ok(1),
            pools,
        },
        vec![],
        1,
        economics(),
        reference(),
        &db,
        1_000,
        LIMITS,
        24_000_000,
        5_000_000_000,
    )
    .unwrap_err();
    assert!(matches!(
        wrong_chain_rpc,
        ServiceError::Catalog(catalog::CatalogError::WrongChain(1))
    ));
}

#[derive(Debug, Clone)]
struct TestPool {
    factory: Address,
    address: Address,
    token0: Address,
    token1: Address,
    reserve0: U256,
    reserve1: U256,
}

fn two_factory_pools() -> Vec<TestPool> {
    let scale = U256::from(FIXED_POINT_SCALE);
    vec![
        TestPool {
            factory: Address::repeat_byte(32),
            address: Address::repeat_byte(16),
            token0: Address::repeat_byte(1),
            token1: Address::repeat_byte(2),
            reserve0: scale,
            reserve1: scale,
        },
        TestPool {
            factory: Address::repeat_byte(33),
            address: Address::repeat_byte(17),
            token0: Address::repeat_byte(1),
            token1: Address::repeat_byte(2),
            reserve0: scale * U256::from(3),
            reserve1: scale * U256::from(3) / U256::from(10),
        },
    ]
}

fn two_factory_manifest(chain_id: u64) -> String {
    let pools = two_factory_pools();
    let mut output = String::from(
        "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,source\n",
    );
    for pool in pools {
        writeln!(
            output,
            "{chain_id},{},{},{},{},997,1000,offline fixture",
            pool.address, pool.factory, pool.token0, pool.token1,
        )
        .expect("writing to a String cannot fail");
    }
    output
}

fn two_factory_events() -> Vec<state::SyncLog> {
    vec![state::SyncLog {
        pool_id: domain::PoolId(0),
        reserve0: U256::from(FIXED_POINT_SCALE) + U256::from(1),
        reserve1: U256::from(FIXED_POINT_SCALE) - U256::from(1),
        block_hash: alloy_primitives::B256::from(U256::from(2)),
        position: state::CanonicalPosition {
            block_number: 2_000_001,
            transaction_index: 0,
            log_index: 0,
        },
        removed: false,
    }]
}

struct TwoFactoryRpc {
    chain_id: Result<u64, RpcError>,
    pools: Vec<TestPool>,
}

impl CatalogRpc for TwoFactoryRpc {
    fn chain_id(&self, _block: u64) -> Result<u64, RpcError> {
        self.chain_id.clone()
    }
    fn get_code(&self, _address: Address, _block: u64) -> Result<Vec<u8>, RpcError> {
        Ok(vec![1])
    }
    fn factory(&self, pair: Address, _block: u64) -> Result<Address, RpcError> {
        self.pools
            .iter()
            .find(|pool| pool.address == pair)
            .map(|pool| pool.factory)
            .ok_or_else(|| RpcError::Call("unknown pair".to_owned()))
    }
    fn token0(&self, pair: Address, _block: u64) -> Result<Address, RpcError> {
        self.pools
            .iter()
            .find(|pool| pool.address == pair)
            .map(|pool| pool.token0)
            .ok_or_else(|| RpcError::Call("unknown pair".to_owned()))
    }
    fn token1(&self, pair: Address, _block: u64) -> Result<Address, RpcError> {
        self.pools
            .iter()
            .find(|pool| pool.address == pair)
            .map(|pool| pool.token1)
            .ok_or_else(|| RpcError::Call("unknown pair".to_owned()))
    }
    fn get_pair(
        &self,
        factory: Address,
        token0: Address,
        token1: Address,
        _block: u64,
    ) -> Result<Address, RpcError> {
        self.pools
            .iter()
            .find(|pool| pool.factory == factory && pool.token0 == token0 && pool.token1 == token1)
            .map(|pool| pool.address)
            .ok_or_else(|| RpcError::Call("no pair".to_owned()))
    }
    fn decimals(&self, _token: Address, _block: u64) -> Result<u8, RpcError> {
        Ok(18)
    }
    fn get_reserves(&self, pair: Address, _block: u64) -> Result<(U256, U256), RpcError> {
        self.pools
            .iter()
            .find(|pool| pool.address == pair)
            .map(|pool| (pool.reserve0, pool.reserve1))
            .ok_or_else(|| RpcError::Call("unknown pair".to_owned()))
    }
}
