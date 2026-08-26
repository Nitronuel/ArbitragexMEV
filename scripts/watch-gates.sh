#!/usr/bin/env bash
# Watches a run-pairs canary log for gate-passing events and records the
# chain tip at first sight. RHC serves ~60-120 minutes of historical state,
# so a fork replay must be pinned to a block within that horizon — this
# watcher freezes the block number the moment an episode appears.
#
# Usage: ./scripts/watch-gates.sh <canary-log> [captures-dir]
#
# Audit P3 hardening: an RPC hiccup or malformed response must skip the
# capture and continue, never kill the watcher (a dead watcher silently
# abandons evidence during exactly the volatile conditions that produce
# gates).
set -uo pipefail

log=${1:?usage: watch-gates.sh <canary-log> [captures-dir]}
dir=${2:-logs/captures}
mkdir -p "$dir"

rpc_url=${ROBINHOOD_HTTP_RPC_URL:?set ROBINHOOD_HTTP_RPC_URL}

# Prints the decimal chain tip, or nothing on any failure.
tip() {
  local resp hex
  resp=$(curl -s --max-time 5 -X POST -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
    "$rpc_url") || return 1
  hex=$(printf '%s' "$resp" | sed -n 's/.*"result":"\([0-9a-fA-Fx]*\)".*/\1/p')
  [[ $hex =~ ^0x[0-9a-fA-F]+$ ]] || return 1
  printf '%d' "$hex"
}

echo "watch-gates: tailing $log"
# Gate-passing rows carry their pair identity on separate "GATED pair" lines
# emitted just before each poll summary; buffer the most recent one so the
# capture records which opportunity gated. Triangle gates have no single
# pair — verify-capture needs --token-lo/--token-hi for those.
last_pair_lo=
last_pair_hi=
tail -n 0 -F "$log" | while read -r line; do
  case "$line" in
    *"GATED pair "*)
      last_pair_lo=$(printf '%s' "$line" | grep -oE 'token_lo=[0-9a-fA-Fx]+' | head -1 | cut -d= -f2)
      last_pair_hi=$(printf '%s' "$line" | grep -oE 'token_hi=[0-9a-fA-Fx]+' | head -1 | cut -d= -f2)
      continue ;;
    *" gated="*) : ;;       # a poll line — fall through to extraction
    *) continue ;;          # anything else
  esac

  gated=$(printf '%s' "$line" | grep -oE 'gated=[0-9]+' | head -1 | cut -d= -f2)
  [ "${gated:-0}" -gt 0 ] || continue

  # The sweep's confirmed coverage top (audit task 0.2 renamed the field).
  blk=$(printf '%s' "$line" | grep -oE 'swept_to=[0-9]+' | head -1 | cut -d= -f2)
  [ -n "$blk" ] || blk=0

  if ! tip_now=$(tip); then
    echo "watch-gates: $(date -u +%H:%M:%S) tip read failed; skipping capture" >&2
    continue
  fi

  file="$dir/gate-$(date -u +%Y%m%dT%H%M%S)-blk${tip_now}.json"
  # One capture per episode burst: skip if we recorded within the last
  # 200 blocks (~20s) — consecutive polls re-report the same dislocation.
  latest=$(ls -t "$dir"/gate-*.json 2>/dev/null | head -1 || true)
  if [[ -n $latest ]]; then
    prev=$(grep -oE '"tip_block": *[0-9]+' "$latest" 2>/dev/null | grep -oE '[0-9]+' | head -1)
    if [[ -n $prev ]] && (( tip_now > prev )) && (( tip_now - prev < 200 )); then
      echo "watch-gates: same episode as $latest, skipping"
      continue
    fi
  fi

  printf '{"detected_at_utc":"%s","poll_from_block":%s,"tip_block":%s,"gated":%s,"token_lo":"%s","token_hi":"%s","log_line":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$blk" "$tip_now" "$gated" \
    "${last_pair_lo:-}" "${last_pair_hi:-}" \
    "$(printf '%s' "$line" | tr '"' "'" | tr -d '\n')" >"$file" \
    && echo "watch-gates: CAPTURED $file (episode at tip $tip_now)"
done
