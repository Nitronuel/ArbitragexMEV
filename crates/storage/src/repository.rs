use std::{
    fs,
    path::{Path, PathBuf},
};

use alloy_primitives::{B256, U256};
use domain::{CycleId, Fee, PoolId, StateVersion};
use provider::UsageSnapshot;
use rusqlite::{Connection, params};
use state::CanonicalPosition;
use thiserror::Error;

use crate::schema::MIGRATION;

const DEFAULT_MAX_BYTES: u64 = 10_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRecord {
    pub pool_id: PoolId,
    pub position: CanonicalPosition,
    pub block_hash: B256,
    pub reserve0: U256,
    pub reserve1: U256,
    pub version: StateVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteStateRecord {
    pub pool_id: PoolId,
    pub state_version: StateVersion,
    pub reserve0: U256,
    pub reserve1: U256,
    pub fee: Fee,
    /// Swap direction used to reproduce the exact recorded quote.
    pub zero_for_one: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationRecord {
    pub cycle_id: CycleId,
    pub observed_at_unix_milliseconds: u64,
    pub input: U256,
    pub output: U256,
    pub estimated_profit: U256,
    pub route_states: Vec<RouteStateRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthInterval {
    pub started_at_unix_milliseconds: u64,
    pub ended_at_unix_milliseconds: u64,
    pub state: String,
    pub reason: String,
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database metadata failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("database size {actual} bytes meets or exceeds limit {limit}")]
    SizeLimit { actual: u64, limit: u64 },
    #[error("{field} value does not fit SQLite INTEGER")]
    IntegerRange { field: &'static str },
    #[error("observation route cannot be empty")]
    EmptyRoute,
    #[error("unsupported database schema version {0}")]
    UnsupportedSchemaVersion(i64),
}

pub struct Storage {
    connection: Connection,
    path: PathBuf,
    max_bytes: u64,
}

impl Storage {
    /// Opens or creates a bounded shadow-mode database.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot open, configure, or migrate the file.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        Self::open_with_limit(path, DEFAULT_MAX_BYTES)
    }

    /// Opens a database with an explicit byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot open, configure, or migrate the file.
    pub fn open_with_limit(path: &Path, max_bytes: u64) -> Result<Self, StorageError> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", true)?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        match version {
            0 => connection.execute_batch(MIGRATION)?,
            1 => {}
            other => return Err(StorageError::UnsupportedSchemaVersion(other)),
        }
        Ok(Self {
            connection,
            path: path.to_owned(),
            max_bytes,
        })
    }

    /// Atomically inserts idempotent canonical checkpoint event keys.
    ///
    /// # Errors
    ///
    /// Returns an error on size refusal, integer conversion, or `SQLite` failure.
    pub fn commit_checkpoint(&mut self, records: &[CheckpointRecord]) -> Result<(), StorageError> {
        self.ensure_capacity()?;
        let transaction = self.connection.transaction()?;
        {
            let mut statement = transaction.prepare(
                "INSERT OR IGNORE INTO checkpoints
                 (pool_id, block_number, transaction_index, log_index, block_hash,
                  reserve0, reserve1, state_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for record in records {
                statement.execute(params![
                    i64::from(record.pool_id.0),
                    integer(record.position.block_number, "block_number")?,
                    integer(record.position.transaction_index, "transaction_index")?,
                    integer(record.position.log_index, "log_index")?,
                    record.block_hash.as_slice(),
                    uint_blob(record.reserve0),
                    uint_blob(record.reserve1),
                    integer(record.version.0, "state_version")?,
                ])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Atomically stores an observation and every route-state reproduction row.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty route, size refusal, integer conversion, or
    /// `SQLite` failure. No partial observation remains after an error.
    pub fn record_observation(&mut self, record: &ObservationRecord) -> Result<i64, StorageError> {
        if record.route_states.is_empty() {
            return Err(StorageError::EmptyRoute);
        }
        self.ensure_capacity()?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO observations
             (cycle_id, observed_at_ms, input, output, estimated_profit)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                i64::from(record.cycle_id.0),
                integer(record.observed_at_unix_milliseconds, "observed_at_ms")?,
                uint_blob(record.input),
                uint_blob(record.output),
                uint_blob(record.estimated_profit),
            ],
        )?;
        let observation_id = transaction.last_insert_rowid();
        {
            let mut statement = transaction.prepare(
                "INSERT INTO observation_route_states
                 (observation_id, route_index, pool_id, state_version, reserve0,
                  reserve1, fee_numerator, fee_denominator, zero_for_one)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for (route_index, route) in record.route_states.iter().enumerate() {
                statement.execute(params![
                    observation_id,
                    integer_usize(route_index, "route_index")?,
                    i64::from(route.pool_id.0),
                    integer(route.state_version.0, "state_version")?,
                    uint_blob(route.reserve0),
                    uint_blob(route.reserve1),
                    i64::from(route.fee.numerator),
                    i64::from(route.fee.denominator),
                    bool_as_integer(route.zero_for_one),
                ])?;
            }
        }
        transaction.commit()?;
        Ok(observation_id)
    }

    /// Invalidates observations that used an affected pool version or newer.
    ///
    /// # Errors
    ///
    /// Returns an error on size refusal, version conversion, or `SQLite` failure.
    pub fn invalidate_observations(
        &mut self,
        pool_id: PoolId,
        from_version: StateVersion,
    ) -> Result<usize, StorageError> {
        self.ensure_capacity()?;
        Ok(self.connection.execute(
            "UPDATE observations SET valid = 0
             WHERE valid = 1 AND EXISTS (
                 SELECT 1 FROM observation_route_states route
                 WHERE route.observation_id = observations.id
                   AND route.pool_id = ?1 AND route.state_version >= ?2
             )",
            params![
                i64::from(pool_id.0),
                integer(from_version.0, "state_version")?
            ],
        )?)
    }

    /// Persists one bounded health interval.
    ///
    /// # Errors
    ///
    /// Returns an error on size refusal, integer conversion, or `SQLite` failure.
    pub fn record_health_interval(
        &mut self,
        interval: &HealthInterval,
    ) -> Result<(), StorageError> {
        self.ensure_capacity()?;
        self.connection.execute(
            "INSERT INTO health_intervals (started_at_ms, ended_at_ms, state, reason)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                integer(interval.started_at_unix_milliseconds, "started_at_ms")?,
                integer(interval.ended_at_unix_milliseconds, "ended_at_ms")?,
                interval.state,
                interval.reason,
            ],
        )?;
        Ok(())
    }

    /// Upserts one hourly provider-usage snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error on size refusal, integer conversion, or `SQLite` failure.
    pub fn record_usage(
        &mut self,
        hour_unix: u64,
        usage: UsageSnapshot,
    ) -> Result<(), StorageError> {
        self.ensure_capacity()?;
        self.connection.execute(
            "INSERT INTO provider_usage
             (hour_unix, request_cu, http_response_bytes, websocket_delivered_bytes,
              websocket_accounted_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(hour_unix) DO UPDATE SET
               request_cu = excluded.request_cu,
               http_response_bytes = excluded.http_response_bytes,
               websocket_delivered_bytes = excluded.websocket_delivered_bytes,
               websocket_accounted_bytes = excluded.websocket_accounted_bytes",
            params![
                integer(hour_unix, "hour_unix")?,
                integer(usage.request_cu, "request_cu")?,
                integer(usage.http_response_bytes, "http_response_bytes")?,
                integer(usage.websocket_delivered_bytes, "websocket_delivered_bytes")?,
                integer(usage.websocket_accounted_bytes, "websocket_accounted_bytes")?,
            ],
        )?;
        Ok(())
    }

    /// Sums independently metered provider usage rows.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot read the summary or a stored total is
    /// outside the unsigned domain.
    pub fn usage_summary(&self) -> Result<UsageSnapshot, StorageError> {
        let totals = self.connection.query_row(
            "SELECT coalesce(sum(request_cu), 0),
                    coalesce(sum(http_response_bytes), 0),
                    coalesce(sum(websocket_delivered_bytes), 0),
                    coalesce(sum(websocket_accounted_bytes), 0)
             FROM provider_usage",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;
        Ok(UsageSnapshot {
            request_cu: unsigned(totals.0, "request_cu")?,
            http_response_bytes: unsigned(totals.1, "http_response_bytes")?,
            websocket_delivered_bytes: unsigned(totals.2, "websocket_delivered_bytes")?,
            websocket_accounted_bytes: unsigned(totals.3, "websocket_accounted_bytes")?,
        })
    }

    /// Deletes bounded historical rows before one timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error on timestamp conversion or `SQLite` transaction failure.
    pub fn prune_before(&mut self, unix_milliseconds: u64) -> Result<(), StorageError> {
        let cutoff = integer(unix_milliseconds, "retention cutoff")?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "DELETE FROM observations WHERE observed_at_ms < ?1",
            [cutoff],
        )?;
        transaction.execute(
            "DELETE FROM health_intervals WHERE ended_at_ms < ?1",
            [cutoff],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Loads one observation and its ordered route-state reproduction rows.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot read the row or a stored value is
    /// outside its expected domain.
    pub fn load_observation(&self, id: i64) -> Result<ObservationRecord, StorageError> {
        let (cycle_id, observed_at_unix_milliseconds, input, output, estimated_profit) =
            self.connection.query_row(
                "SELECT cycle_id, observed_at_ms, input, output, estimated_profit
                 FROM observations WHERE id = ?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )?;
        Ok(ObservationRecord {
            cycle_id: CycleId(u32_value(cycle_id, "cycle_id")?),
            observed_at_unix_milliseconds: unsigned(
                observed_at_unix_milliseconds,
                "observed_at_ms",
            )?,
            input: uint_blob_from(&input)?,
            output: uint_blob_from(&output)?,
            estimated_profit: uint_blob_from(&estimated_profit)?,
            route_states: self.load_route_states(id)?,
        })
    }

    /// Loads every valid observation in recording order with its database id.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot read a row or a stored value is
    /// outside its expected domain.
    pub fn load_observations(&self) -> Result<Vec<(i64, ObservationRecord)>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT id, cycle_id, observed_at_ms, input, output, estimated_profit
             FROM observations WHERE valid = 1 ORDER BY observed_at_ms, id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })?;
        let mut records = Vec::new();
        for row in rows {
            let (id, cycle_id, observed_at_unix_milliseconds, input, output, estimated_profit) =
                row?;
            records.push((
                id,
                ObservationRecord {
                    cycle_id: CycleId(u32_value(cycle_id, "cycle_id")?),
                    observed_at_unix_milliseconds: unsigned(
                        observed_at_unix_milliseconds,
                        "observed_at_ms",
                    )?,
                    input: uint_blob_from(&input)?,
                    output: uint_blob_from(&output)?,
                    estimated_profit: uint_blob_from(&estimated_profit)?,
                    route_states: self.load_route_states(id)?,
                },
            ));
        }
        Ok(records)
    }

    /// Loads persisted bounded health intervals in recording order.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot read a row or a stored timestamp is
    /// outside its expected domain.
    pub fn load_health_intervals(&self) -> Result<Vec<HealthInterval>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT started_at_ms, ended_at_ms, state, reason
             FROM health_intervals ORDER BY started_at_ms",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut intervals = Vec::new();
        for row in rows {
            let (started, ended, state, reason) = row?;
            intervals.push(HealthInterval {
                started_at_unix_milliseconds: unsigned(started, "started_at_ms")?,
                ended_at_unix_milliseconds: unsigned(ended, "ended_at_ms")?,
                state,
                reason,
            });
        }
        Ok(intervals)
    }

    fn load_route_states(
        &self,
        observation_id: i64,
    ) -> Result<Vec<RouteStateRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT pool_id, state_version, reserve0, reserve1, fee_numerator,
                    fee_denominator, zero_for_one
             FROM observation_route_states WHERE observation_id = ?1
             ORDER BY route_index",
        )?;
        let rows = statement.query_map([observation_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        let mut states = Vec::new();
        for row in rows {
            let (
                pool_id,
                state_version,
                reserve0,
                reserve1,
                fee_numerator,
                fee_denominator,
                zero_for_one,
            ) = row?;
            states.push(RouteStateRecord {
                pool_id: PoolId(u32_value(pool_id, "pool_id")?),
                state_version: StateVersion(unsigned(state_version, "state_version")?),
                reserve0: uint_blob_from(&reserve0)?,
                reserve1: uint_blob_from(&reserve1)?,
                fee: Fee {
                    numerator: u32_value(fee_numerator, "fee_numerator")?,
                    denominator: u32_value(fee_denominator, "fee_denominator")?,
                },
                zero_for_one: integer_as_bool(zero_for_one, "zero_for_one")?,
            });
        }
        Ok(states)
    }

    fn ensure_capacity(&self) -> Result<(), StorageError> {
        let actual = file_size(&self.path)?
            .saturating_add(file_size(&PathBuf::from(format!(
                "{}-wal",
                self.path.display()
            )))?)
            .saturating_add(file_size(&PathBuf::from(format!(
                "{}-shm",
                self.path.display()
            )))?);
        if actual >= self.max_bytes {
            return Err(StorageError::SizeLimit {
                actual,
                limit: self.max_bytes,
            });
        }
        Ok(())
    }
}

fn uint_blob(value: U256) -> [u8; 32] {
    value.to_be_bytes()
}

fn uint_blob_from(bytes: &[u8]) -> Result<U256, StorageError> {
    if bytes.len() != 32 {
        return Err(StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stored U256 must be 32 bytes",
        )));
    }
    Ok(U256::from_be_slice(bytes))
}

fn bool_as_integer(value: bool) -> i64 {
    i64::from(value)
}

fn integer_as_bool(value: i64, field: &'static str) -> Result<bool, StorageError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StorageError::IntegerRange { field }),
    }
}

fn integer(value: u64, field: &'static str) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::IntegerRange { field })
}

fn integer_usize(value: usize, field: &'static str) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::IntegerRange { field })
}

fn unsigned(value: i64, field: &'static str) -> Result<u64, StorageError> {
    u64::try_from(value).map_err(|_| StorageError::IntegerRange { field })
}

fn u32_value(value: i64, field: &'static str) -> Result<u32, StorageError> {
    u32::try_from(value).map_err(|_| StorageError::IntegerRange { field })
}

fn file_size(path: &Path) -> Result<u64, StorageError> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .or_else(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Ok(0)
            } else {
                Err(error)
            }
        })
        .map_err(StorageError::Io)
}
