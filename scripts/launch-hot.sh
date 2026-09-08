#!/usr/bin/env bash
# Hot-manifest detection loop: 1,034 live-trading pools (see hot-pools.py).
# Single loop on purpose — two sweeps doubled gateway load into throttle
# spiral (2026-09-06: polls degraded 6s -> 45min). Dry-run execution is
# handled by the `trade` window on logs/live/trades-hot.csv.
set -euo pipefail
cd "$(dirname "$0")/.."
touch logs/live/trades-hot.csv
# Provider cutover 2026-09-06 (bake-off: Chainstack 17/17, public 5x429):
# Chainstack HTTP is primary via env (value never echoed — label only);
# public gateway is the fallback when the env var is unset.
RPC_URL="${CHAINSTACK_RHC_HTTP_URL:-https://rpc.mainnet.chain.robinhood.com}"
if [[ -n "${CHAINSTACK_RHC_HTTP_URL:-}" ]]; then BACKEND="chainstack"; else BACKEND="public"; fi
echo "$(date -u +%FT%TZ) launch-hot: backend=$BACKEND manifest=hot window=10 poll-ms=3000" >> logs/live/run-pairs-hot.log
exec ./target/release/shadow-bot run-pairs \
  --a data/pools-all.csv --b data/pools-all.csv \
  --manifest data/manifest-hot.csv --prices data/prices-live.csv \
  --rpc "$RPC_URL" \
  --events ws \
  --native-usd 2490000000000000000000 \
  --window 10 --poll-ms 3000 --delay-ms 500 --max-skew 10 --global \
  --flash-provider auto --flash-support data/flash-support.csv \
  --csv logs/live/trades-hot.csv >> logs/live/run-pairs-hot.log 2>&1
