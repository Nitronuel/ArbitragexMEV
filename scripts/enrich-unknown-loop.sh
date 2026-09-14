#!/usr/bin/env bash
# Supervisor loop for daily unknown-pool enrichment. Runs one pass at
# startup, then every 24h. Single-flight via flock; appends to
# logs/live/enrich-unknown.log. Restart: kill + relaunch like the other
# live loops (run-pairs, pool-indexer).
set -u
cd "$(dirname "$0")/.." || exit 1
LOCK="/tmp/enrich-unknown.lock"
while true; do
  flock -n "$LOCK" bash scripts/enrich-unknown-daily.sh || \
    echo "$(date -u +%FT%TZ) enrich-unknown: previous pass still running, skipping" >> logs/live/enrich-unknown.log
  sleep 86400
done
