CREATE TABLE checkpoints (
    pool_id INTEGER NOT NULL,
    block_number INTEGER NOT NULL,
    transaction_index INTEGER NOT NULL,
    log_index INTEGER NOT NULL,
    block_hash BLOB NOT NULL CHECK(length(block_hash) = 32),
    reserve0 BLOB NOT NULL CHECK(length(reserve0) = 32),
    reserve1 BLOB NOT NULL CHECK(length(reserve1) = 32),
    state_version INTEGER NOT NULL,
    PRIMARY KEY (pool_id, block_number, transaction_index, log_index)
) STRICT;

CREATE TABLE observations (
    id INTEGER PRIMARY KEY,
    cycle_id INTEGER NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    input BLOB NOT NULL CHECK(length(input) = 32),
    output BLOB NOT NULL CHECK(length(output) = 32),
    estimated_profit BLOB NOT NULL CHECK(length(estimated_profit) = 32),
    valid INTEGER NOT NULL DEFAULT 1 CHECK(valid IN (0, 1))
) STRICT;

CREATE TABLE observation_route_states (
    observation_id INTEGER NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
    route_index INTEGER NOT NULL,
    pool_id INTEGER NOT NULL,
    state_version INTEGER NOT NULL,
    reserve0 BLOB NOT NULL CHECK(length(reserve0) = 32),
    reserve1 BLOB NOT NULL CHECK(length(reserve1) = 32),
    fee_numerator INTEGER NOT NULL CHECK(fee_numerator > 0),
    fee_denominator INTEGER NOT NULL CHECK(fee_denominator >= fee_numerator),
    zero_for_one INTEGER NOT NULL CHECK(zero_for_one IN (0, 1)),
    PRIMARY KEY (observation_id, route_index)
) STRICT;

CREATE INDEX observation_route_pool_version
ON observation_route_states(pool_id, state_version);

CREATE TABLE health_intervals (
    id INTEGER PRIMARY KEY,
    started_at_ms INTEGER NOT NULL,
    ended_at_ms INTEGER NOT NULL,
    state TEXT NOT NULL,
    reason TEXT NOT NULL
) STRICT;

CREATE TABLE provider_usage (
    hour_unix INTEGER PRIMARY KEY,
    request_cu INTEGER NOT NULL,
    http_response_bytes INTEGER NOT NULL,
    websocket_delivered_bytes INTEGER NOT NULL,
    websocket_accounted_bytes INTEGER NOT NULL
) STRICT;

PRAGMA user_version = 1;
