#!/usr/bin/env bash
# Launches shadow-bot with the runtime RPC endpoints sourced from a file that
# lives OUTSIDE the repo (never tracked, never scanned by check-secrets).
#
# Usage:
#   ./scripts/run-shadow.sh <shadow-bot args...>      e.g. validate-config --config config/shadow.toml
#
# The runtime env file defaults to $HOME/.config/base-shadow/runtime.env and can
# be overridden with SHADOW_RUNTIME_ENV. It must export:
#   BASE_HTTP_RPC_URL='https://...'   (Alchemy HTTPS endpoint)
#   BASE_WS_RPC_URL='wss://...'       (Alchemy WebSocket endpoint)
# Offline commands still work when the file is absent; live commands warn loudly.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

env_file=${SHADOW_RUNTIME_ENV:-$HOME/.config/base-shadow/runtime.env}
if [[ -f "$env_file" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$env_file"
  set +a
else
  printf 'warning: runtime env file not found: %s\n' "$env_file" >&2
  printf '  offline commands (validate-config, verify-catalog) still work.\n' >&2
  printf '  live commands need BASE_HTTP_RPC_URL / BASE_WS_RPC_URL exports.\n' >&2
  printf '  see docs/runbooks/shadow-mode.md, section 2.\n' >&2
fi

exec cargo run -q -p shadow-bot -- "$@"
