#!/usr/bin/env bash
# Watches a run-pairs canary log for gate-passing events and records the
# chain tip at first sight. RHC serves ~60-120 minutes of historical state,
# so a fork replay must be pinned to a block within that horizon — this
# watcher freezes the block number the moment an episode appears.
#
# Usage: ./scripts/watch-gates.sh <canary-log> [captures-dir]
set -euo pipefail

log=${1:?usage: watch-gates.sh <canary-log> [captures-dir]}
dir=${2:-logs/captures}
mkdir -p "$dir"

rpc_url=${ROBINHOOD_HTTP_RPC_URL:?set ROBINHOOD_HTTP_RPC_URL}

tip() {
  local r
  r=$(curl -s -X POST -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
    "$rpc_url" | sed 's/.*"result":"\([0-9a-fx]*\)".*/\1/')
  printf '%d' "$r"
}

echo "watch-gates: tailing $log"
tail -n 0 -F "$log" | while read -r line; do
  case "$line" in
    *gated=*) : ;;          # a poll line — fall through to extraction
    *) continue ;;          # anything else
  esac
  gated=$(printf '%s' "$line" | grep -oE 'gated=[0-9]+' | head -1 | cut -d= -f2)
  [ "${gated:-0}" -gt 0 ] || continue
  blk=$(printf '%s' "$line" | grep -oE 'poll [0-9]+' | grep -oE '[0-9]+' | tail -1)
  tip_now=$(tip)
  file="$dir/gate-$(date -u +%Y%m%dT%H%M%S)-blk${tip_now}.json"
  # One capture per episode burst: skip if we recorded within the last
  # 200 blocks (~20s) — consecutive polls re-report the same dislocation.
  latest=$(ls -t "$dir" 2>/dev/null | head -1 || true)
  if [[ -n $latest ]] && grep -q '"tip_block"' "$dir/$latest" 2>/dev/null; then
    prev=$(grep -oE '"tip_block": *[0-9]+' "$dir/$latest" | grep -oE '[0-9]+')
    if (( tip_now - prev < 200 )); then
      echo "watch-gates: same episode as $latest, skipping"
      continue
    fi
  fi
  printf '{"detected_at_utc":"%s","poll_from_block":%s,"tip_block":%s,"gated":%s,"log_line":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${blk:-0}" "$tip_now" "$gated" \
    "$(printf '%s' "$line" | tr '"' "'")" >"$file"
  echo "watch-gates: CAPTURED $file (episode at tip $tip_now)"
done
