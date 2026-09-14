#!/usr/bin/env bash
# One-time enrichment for hot-but-unknown V3 pools: token0/token1/fee reads.
# Read-only. Appends catalog-schema rows to stdout (caller redirects/appends).
# Usage: scripts/enrich-v3-hot.sh data/hot-unknown.csv [max_pools]
# Fail-soft (2026-09-14): a dead/reverting/hanging pool is skipped (bounded
# per-call timeout), never stalls or aborts the remaining batch. No `set -e`:
# every capture is explicitly guarded. Input is fed via process substitution
# so the counters survive the loop (the `tail |` pipeline used to zero them).
set -uo pipefail
RPC_URL="https://rpc.mainnet.chain.robinhood.com"
FACTORY="0x1f7d7550B1b028f7571E69A784071F0205FD2EfA"
UNKNOWN="${1:?hot-unknown.csv}"
MAXP="${2:-234}"
CALL_TIMEOUT=20  # seconds per eth_call; a dead address must not stall the pass

get() { timeout "$CALL_TIMEOUT" cast call "$1" "$2" --rpc-url "$RPC_URL" 2>/dev/null; }
ck()  { cast --to-checksum-address "$1" 2>/dev/null; }

n=0
skipped=0
while IFS=, read -r venue id swaps; do
  [[ "$venue" == "v3" ]] || continue
  [[ $n -lt $MAXP ]] || break
  n=$((n + 1))
  skip() { echo "enrich-v3-hot: skip $id ($1)" >&2; skipped=$((skipped + 1)); }
  # NOTE: cast annotates uint output ("10000 [1e4]") — keep the bare number.
  # cast returns lowercase addresses; manifest requires EIP-55 checksum
  # (strict parse_manifest rejects miscased rows — 234-row incident 2026-09-07).
  t0r="$(get "$id" "token0()(address)")" || { skip "token0"; continue; }
  t1r="$(get "$id" "token1()(address)")" || { skip "token1"; continue; }
  fer="$(get "$id" "fee()(uint24)")"     || { skip "fee"; continue; }
  fe="${fer%% *}"
  id_ck="$(ck "$id")" || { skip "checksum"; continue; }
  t0="$(ck "$t0r")"   || { skip "checksum t0"; continue; }
  t1="$(ck "$t1r")"   || { skip "checksum t1"; continue; }
  if [[ -z "$fe" || -z "$t0" || -z "$t1" || -z "$id_ck" ]]; then
    skip "empty field"
    continue
  fi
  echo "4663,$id_ck,$FACTORY,$t0,$t1,$fe,1000000,v3,,hot-enriched"
  sleep 0.2
done < <(tail -n +2 "$UNKNOWN")
echo "enriched $n v3 pools (skipped $skipped)" >&2
