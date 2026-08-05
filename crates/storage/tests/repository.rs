use std::fs;

use alloy_primitives::{B256, U256};
use domain::{CycleId, Fee, PoolId, StateVersion};
use provider::UsageSnapshot;
use rusqlite::Connection;
use state::CanonicalPosition;
use storage::{
    CheckpointRecord, HealthInterval, ObservationRecord, RouteStateRecord, Storage, StorageError,
};
use tempfile::TempDir;

fn database() -> (TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("shadow.sqlite");
    (directory, path)
}

fn checkpoint(block: u64) -> CheckpointRecord {
    CheckpointRecord {
        pool_id: PoolId(0),
        position: CanonicalPosition {
            block_number: block,
            transaction_index: 1,
            log_index: 2,
        },
        block_hash: B256::from(U256::from(block)),
        reserve0: U256::from(block * 10),
        reserve1: U256::from(block * 20),
        version: StateVersion(block),
    }
}

fn observation(timestamp: u64) -> ObservationRecord {
    ObservationRecord {
        cycle_id: CycleId(7),
        observed_at_unix_milliseconds: timestamp,
        input: U256::from(100),
        output: U256::from(130),
        estimated_profit: U256::from(30),
        route_states: vec![RouteStateRecord {
            pool_id: PoolId(0),
            state_version: StateVersion(11),
            reserve0: U256::from(1_000),
            reserve1: U256::from(2_000),
            fee: Fee {
                numerator: 997,
                denominator: 1_000,
            },
            zero_for_one: true,
        }],
    }
}

#[test]
fn enables_wal_foreign_keys_and_schema_version() {
    let (_directory, path) = database();
    drop(Storage::open(&path).unwrap());
    let _reopened = Storage::open(&path).unwrap();
    let connection = Connection::open(path).unwrap();
    let journal: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let foreign_keys: i64 = connection
        .query_row(
            "SELECT count(*) FROM pragma_foreign_key_list('observation_route_states')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(journal, "wal");
    assert!(foreign_keys >= 1);
    assert_eq!(version, 1);
}

#[test]
fn checkpoint_batch_is_atomic_and_event_keys_are_idempotent() {
    let (_directory, path) = database();
    let mut storage = Storage::open(&path).unwrap();
    let first = checkpoint(10);
    storage.commit_checkpoint(&[first.clone(), first]).unwrap();
    let connection = Connection::open(path).unwrap();
    let count: i64 = connection
        .query_row("SELECT count(*) FROM checkpoints", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);

    let mut invalid = checkpoint(11);
    invalid.reserve0 = U256::MAX;
    invalid.version = StateVersion(u64::MAX);
    assert!(
        storage
            .commit_checkpoint(&[checkpoint(12), invalid])
            .is_err()
    );
    let count: i64 = connection
        .query_row("SELECT count(*) FROM checkpoints", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn observation_atomically_stores_fixed_width_reproduction_fields() {
    let (_directory, path) = database();
    let mut storage = Storage::open(&path).unwrap();
    let id = storage.record_observation(&observation(1_000)).unwrap();
    let connection = Connection::open(path).unwrap();
    let row = connection.query_row(
        "SELECT length(input), length(output), length(estimated_profit) FROM observations WHERE id = ?1",
        [id],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
    ).unwrap();
    assert_eq!(row, (32, 32, 32));
    let route = connection.query_row(
        "SELECT state_version, length(reserve0), length(reserve1), fee_numerator, fee_denominator, zero_for_one FROM observation_route_states WHERE observation_id = ?1",
        [id],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, i64>(4)?, row.get::<_, i64>(5)?)),
    ).unwrap();
    assert_eq!(route, (11, 32, 32, 997, 1_000, 1));
}

#[test]
fn load_observation_round_trips_reproduction_fields() {
    let (_directory, path) = database();
    let mut storage = Storage::open(&path).unwrap();
    let id = storage.record_observation(&observation(1_000)).unwrap();
    let loaded = storage.load_observation(id).unwrap();
    assert_eq!(loaded.cycle_id, CycleId(7));
    assert_eq!(loaded.input, U256::from(100));
    assert_eq!(loaded.output, U256::from(130));
    assert_eq!(loaded.estimated_profit, U256::from(30));
    assert_eq!(loaded.route_states.len(), 1);
    assert_eq!(loaded.route_states[0].pool_id, PoolId(0));
    assert_eq!(loaded.route_states[0].state_version, StateVersion(11));
    assert_eq!(loaded.route_states[0].reserve0, U256::from(1_000));
    assert_eq!(loaded.route_states[0].reserve1, U256::from(2_000));
    assert_eq!(loaded.route_states[0].fee.numerator, 997);
    assert_eq!(loaded.route_states[0].fee.denominator, 1_000);
    assert!(loaded.route_states[0].zero_for_one);

    let (listed_id, listed) = storage.load_observations().unwrap().remove(0);
    assert_eq!(listed_id, id);
    assert_eq!(listed, loaded);
}

#[test]
fn observation_route_failure_rolls_back_parent_row() {
    let (_directory, path) = database();
    let mut storage = Storage::open(&path).unwrap();
    let mut invalid = observation(1_000);
    invalid.route_states[0].fee.denominator = 0;
    assert!(storage.record_observation(&invalid).is_err());
    let connection = Connection::open(path).unwrap();
    let count: i64 = connection
        .query_row("SELECT count(*) FROM observations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn reorg_invalidation_marks_every_observation_using_affected_versions() {
    let (_directory, path) = database();
    let mut storage = Storage::open(&path).unwrap();
    let id = storage.record_observation(&observation(1_000)).unwrap();
    assert_eq!(
        storage
            .invalidate_observations(PoolId(0), StateVersion(11))
            .unwrap(),
        1
    );
    let connection = Connection::open(path).unwrap();
    let valid: i64 = connection
        .query_row(
            "SELECT valid FROM observations WHERE id = ?1",
            [id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(valid, 0);
}

#[test]
fn persists_health_usage_and_bounded_retention() {
    let (_directory, path) = database();
    let mut storage = Storage::open(&path).unwrap();
    storage
        .record_health_interval(&HealthInterval {
            started_at_unix_milliseconds: 10,
            ended_at_unix_milliseconds: 20,
            state: "STALE".to_owned(),
            reason: "disconnect".to_owned(),
        })
        .unwrap();
    storage
        .record_usage(
            1,
            UsageSnapshot {
                request_cu: 26,
                http_response_bytes: 100,
                websocket_delivered_bytes: 200,
                websocket_accounted_bytes: 240,
            },
        )
        .unwrap();
    assert_eq!(storage.usage_summary().unwrap().request_cu, 26);
    storage.record_observation(&observation(100)).unwrap();
    storage.record_observation(&observation(200)).unwrap();
    storage.prune_before(150).unwrap();
    let connection = Connection::open(path).unwrap();
    let count: i64 = connection
        .query_row("SELECT count(*) FROM observations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn refuses_work_when_database_is_at_size_limit() {
    let (_directory, path) = database();
    let mut storage = Storage::open_with_limit(&path, 1).unwrap();
    assert!(matches!(
        storage.record_observation(&observation(1)),
        Err(StorageError::SizeLimit { .. })
    ));
}

#[test]
fn schema_and_database_never_store_rpc_urls() {
    let (_directory, path) = database();
    let _storage = Storage::open(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    let schema: String = connection
        .query_row(
            "SELECT group_concat(sql, ' ') FROM sqlite_schema WHERE sql IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let lowered = schema.to_lowercase();
    assert!(!lowered.contains("rpc_url"));
    assert!(!lowered.contains("http_url"));
    assert!(!lowered.contains("ws_url"));
    let bytes = fs::read(path).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("secret-api-key"));
}
