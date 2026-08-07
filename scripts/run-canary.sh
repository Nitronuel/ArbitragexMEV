#!/usr/bin/env bash
# Resource-capped shadow-mode observation invocation.
#
# Usage:
#   ./scripts/run-canary.sh <config.toml> <snapshot.json> <db.sqlite3>   # offline pass
#   ./scripts/run-canary.sh --live <config.toml> <manifest.csv> <db.sqlite3> [--poll-ms N --drain-ms N]
#
# Applies a memory and file-size ceiling via systemd-run or shell ulimit where
# available, then runs the observation pipeline. The default is a single offline
# snapshot pass. `--live` switches to the live manifest-observation mode: it
# sources the runtime RPC endpoints from a file OUTSIDE the repo, then runs
# `shadow-bot run --manifest`, which keeps reserves current from the HTTP
# `eth_getLogs` poller (RHC rejects filtered WS `logs` subscriptions) and exits
# gracefully on SIGTERM (the 24-hour canary harness). `--poll-ms` is the poll
# cadence: it is the canary's CU/request budget control, default 2000 (≈3M local
# request-CU/day vs. the 24M ceiling); lower = more responsive, higher budget burn.
set -euo pipefail

if [[ $# -lt 1 ]]; then
  printf 'usage: %s [--live] <config.toml> <snapshot.json|manifest.csv> <db.sqlite3> [--poll-ms S] [--drain-ms N]\n' "$0" >&2
  exit 2
fi

live=0
poll_ms=2000
drain_ms=250
args=( "$@" )
if [[ ${args[0]} == --live ]]; then
  live=1
  shift
fi

# Accept optional poll/drain overrides after the three positional arguments.
config=$1
input=$2
db=$3
shift 3
while [[ $# -gt 0 ]]; do
  case "$1" in
    --poll-ms) poll_ms=$2; shift 2 ;;
    --drain-ms) drain_ms=$2; shift 2 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done

root=$(git rev-parse --show-toplevel)
cd "$root"

mem_limit_mb=${RUNTIME_MEMORY_LIMIT_MB:-2457}
file_limit_mb=${RUNTIME_FILE_LIMIT_MB:-20480}

run_command() {
  if [[ $live -eq 1 ]]; then
    cargo run -q -p shadow-bot -- run \
      --config "$config" \
      --manifest "$input" \
      --db "$db" \
      --poll-ms "$poll_ms" \
      --drain-ms "$drain_ms"
  else
    cargo run -q -p shadow-bot -- run \
      --config "$config" \
      --snapshot "$input" \
      --db "$db"
  fi
}

# Live mode requires the RPC endpoints, which live outside the repo.
if [[ $live -eq 1 ]]; then
  env_file=${SHADOW_RUNTIME_ENV:-$HOME/.config/base-shadow/runtime.env}
  if [[ -f "$env_file" ]]; then
    # shellcheck disable=SC1090
    set -a; source "$env_file"; set +a
  else
    printf 'error: live canary requires runtime env file: %s\n' "$env_file" >&2
    exit 1
  fi
fi

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