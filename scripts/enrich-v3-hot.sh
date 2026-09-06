#!/usr/bin/env bash
# One-time enrichment for hot-but-unknown V3 pools: token0/token1/fee reads.
# Read-only. Appends catalog-schema rows to stdout (caller redirects/appends).
# Usage: scripts/enrich-v3-hot.sh data/hot-unknown.csv [max_pools]
set -euo pipefail
RPC_URL="https://rpc.mainnet.chain.robinhood.com"
FACTORY="0x1f7d7550B1b028f7571E69A784071F0205FD2EfA"
UNKNOWN="${1:?hot-unknown.csv}"
MAXP="${2:-234}"
n=0
tail -n +2 "$UNKNOWN" | while IFS=, read -r venue id swaps; do
  [[ "$venue" == "v3" ]] || continue
  [[ $n -lt $MAXP ]] || break
  n=$((n + 1))
  # NOTE: cast annotates uint output ("10000 [1e4]") — keep the bare number.
  t0="$(cast call "$id" "token0()(address)" --rpc-url "$RPC_URL")"
  t1="$(cast call "$id" "token1()(address)" --rpc-url "$RPC_URL")"
  fee="$(cast call "$id" "fee()(uint24)" --rpc-url "$RPC_URL" | cut -d' ' -f1)"
  echo "4663,$id,$FACTORY,$t0,$t1,$fee,1000000,v3,,hot-enriched"
  sleep 0.2
done
echo "enriched $n v3 pools" >&2
