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
# Startup invariant (Phase 1, 2026-09-15): refuse to launch blind when the
# V4 tick/hooks table no longer covers the live manifest (split-brain
# incident: overrides-inc held 9.5k pools never folded into the loaded
# file, and 12% of gated rows refused at trade time). Refuse <90%, loud
# warn <95%. Counts only — no endpoint values ever leave this shell.
COVERAGE=$(python3 -c "
import csv
def norm(s): return (s or '').strip().lower().removeprefix('0x')
man={norm(r['pool_id']) for r in csv.DictReader(open('data/manifest-hot.csv')) if (r.get('profile') or '')=='v4' and r.get('pool_id')}
ov={norm(r['pool_id']) for r in csv.DictReader(open('data/v4-overrides.csv')) if r.get('pool_id')}
print('%.2f' % (100*len(man&ov)/len(man)) if man else '0.00')" 2>/dev/null || echo "0.00")
echo "$(date -u +%FT%TZ) launch-hot: overrides coverage=${COVERAGE}% (manifest-hot v4)" >> logs/live/run-pairs-hot.log
if python3 -c "import sys; sys.exit(0 if float('$COVERAGE') >= 90.0 else 1)"; then
  if python3 -c "import sys; sys.exit(0 if float('$COVERAGE') < 95.0 else 1)"; then
    echo "$(date -u +%FT%TZ) launch-hot: WARNING overrides coverage ${COVERAGE}% < 95% — run the pool-indexer fold" >> logs/live/run-pairs-hot.log
  fi
else
  echo "$(date -u +%FT%TZ) launch-hot: REFUSING launch — overrides coverage ${COVERAGE}% < 90%" >> logs/live/run-pairs-hot.log
  echo "launch-hot: refusing — v4-overrides coverage ${COVERAGE}% < 90% (see logs/live/run-pairs-hot.log)" >&2
  exit 1
fi
exec ./target/release/shadow-bot run-pairs \
  --a data/pools-all.csv --b data/pools-all.csv \
  --manifest data/manifest-hot.csv --prices data/prices-live.csv \
  --rpc "$RPC_URL" \
  --events ws \
  --native-usd 2490000000000000000000 \
  --window 10 --poll-ms 3000 --delay-ms 500 --max-skew 10 --global \
  --flash-provider auto --flash-support data/flash-support.csv \
  --overrides data/v4-overrides.csv --hook-allowlist data/hook-allowlist.csv \
  --v3-algebra data/v3-algebra.csv \
  --max-hops 5 \
  --csv logs/live/trades-hot.csv \
  --log-quote-detail logs/quoter-baseline.csv >> logs/live/run-pairs-hot.log 2>&1
