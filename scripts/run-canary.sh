#!/usr/bin/env bash
# Resource-capped shadow-mode observation invocation.
#
# Usage:
#   ./scripts/run-canary.sh <config.toml> <snapshot.json> <db.sqlite>
#
# Applies a memory and file-size ceiling via systemd-run or shell ulimit where
# available, then runs the offline observation pipeline once. This is the
# resource harness that a live 24-hour canary (Task 11) will reuse; live
# provider access is a separately gated stage and is NOT authorized by the
# Tasks 1-10 shadow implementation, so this script never attempts a live run.
set -euo pipefail

if [[ $# -lt 3 ]]; then
  printf 'usage: %s <config.toml> <snapshot.json> <db.sqlite3>\n' "$0" >&2
  exit 2
fi

config=$1
snapshot=$2
db=$3

root=$(git rev-parse --show-toplevel)
cd "$root"

mem_limit_mb=${RUNTIME_MEMORY_LIMIT_MB:-2457}
file_limit_mb=${RUNTIME_FILE_LIMIT_MB:-20480}

run_command() {
  cargo run -q -p shadow-bot -- run \
    --config "$config" \
    --snapshot "$snapshot" \
    --db "$db"
}

case "$(uname -s)" in
  Linux)
    if command -v systemd-run >/dev/null 2>&1; then
      exec systemd-run --scope --unit=shadow-canary \
        -p MemoryMax="$((mem_limit_mb * 1024 * 1024))" \
        -p TasksMax=256 \
        /bin/bash -c "$(declare -f run_command); run_command"
    fi
    # Fall back to shell ulimits.
    run_command_kb=$((mem_limit_mb * 1024))
    ulimit -v "$run_command_kb" 2>/dev/null || true
    ulimit -f "$file_limit_mb" 2>/dev/null || true
    exec bash -c "$(declare -f run_command); run_command"
    ;;
  *) exec bash -c "$(declare -f run_command); run_command" ;;
esac