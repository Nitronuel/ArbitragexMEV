#!/usr/bin/env bash
# Launch the live detect → execute loop as one supervised unit.
#
#   Terminal A process: run-pairs  (detection; read-only, writes gated CSV)
#   Terminal B process: trade      (execution; acts only on NEW gated rows)
#
# Both processes restart on crash until the script is Ctrl-C'd. Logs land in
# logs/live/. Nothing broadcasts without --broadcast; trade refuses rows whose
# V4 legs lack tick/hooks overrides.
#
# Usage:
#   scripts/launch-live.sh [--broadcast] [native_usd]
#
# Safety rails honored (SECURITY.md): every submission still passes the
# simulated_profit > gas_cost / expected_win_rate floor via the quote gate and
# the on-chain minProfit; underfunded attempts are refused pre-broadcast.
set -euo pipefail
cd "$(dirname "$0")/.."

BROADCAST="${1:-}"
if [[ "$BROADCAST" == "--broadcast" ]]; then
  BROADCAST_FLAG="--broadcast"
  shift
elif [[ -z "$BROADCAST" ]]; then
  BROADCAST_FLAG=""
else
  BROADCAST_FLAG=""
fi
NATIVE_USD="${1:-2488}"
# run-pairs --native-usd is 1e18 fixed-point USD (main.rs docs), while
# NATIVE_USD stays human-readable whole dollars here.
NATIVE_USD_FP="${NATIVE_USD}000000000000000000"

OWNER="0x3219E15A8d1e82368340dfB6697fE6a6B41d686D"
EXECUTOR="0x727f41B647e9F0958dd539b0dFff4fc46A90A950" # ExecutorUUPS proxy 2026-09-06 (was 0xaAeB... V3 bare)
TRADE_ATTEMPTS="${TRADE_ATTEMPTS:-2}"
GAS_CAP_GWEI="${GAS_CAP_GWEI:-1.0}"
# Capital source: morpho (Morpho Blue flash, no float, any gas-covered wallet
# can trade) or float (legacy owner-seeded executor balance).
CAPITAL_SOURCE="${CAPITAL_SOURCE:-morpho}"
RPC="https://rpc.mainnet.chain.robinhood.com"
CSV="logs/live/trades.csv"
RUNPAIRS_LOG="logs/live/run-pairs.log"
TRADE_LOG="logs/live/trade.log"
OVERRIDES="${V4_OVERRIDES:-data/v4-overrides.csv}"

if [[ -z "${ARBITRAGE_WALLET_PRIVATE_KEY:-}" && -f "$HOME/.bashrc" ]]; then
  # shellcheck disable=SC1090
  source <(grep -E '^[[:space:]]*(export[[:space:]]+)?ARBITRAGE_WALLET_PRIVATE_KEY=' "$HOME/.bashrc" || true)
fi
if [[ -z "${ARBITRAGE_WALLET_PRIVATE_KEY:-}" ]]; then
  echo "FATAL: ARBITRAGE_WALLET_PRIVATE_KEY not set" >&2
  exit 1
fi

mkdir -p logs/live
touch "$CSV"
if ! head -n 1 "$CSV" | grep -q "^kind,"; then
  echo "kind,token_lo,token_hi,to_block,input,output,profit,log2_skew,gross_profit_usd,net_profit_usd,shortfall_usd,threshold_usd,floor_ratio,optimal_unclamped,input_capacity,reason_code,reason_detail,anchor_priced,legs" > "$CSV"
fi

echo "launch-live: broadcast=${BROADCAST_FLAG:-DRY-RUN} native_usd=$NATIVE_USD executor=$EXECUTOR"

RUNPAIRS_BIN="${SHADOW_BIN:-./target/release/shadow-bot}"
run_pairs_loop() {
  while true; do
    "$RUNPAIRS_BIN" run-pairs \
      --a data/pools-all.csv --b data/pools-all.csv \
      --manifest data/pools-all.csv --prices data/prices-live.csv \
      --rpc "$RPC" --native-usd "$NATIVE_USD_FP" \
      --window 10 --poll-ms 3000 --delay-ms 200 --max-swaps 0 --max-skew 10 --global \
      --flash-provider auto --flash-support data/flash-support.csv \
      --csv "$CSV" >> "$RUNPAIRS_LOG" 2>&1
    echo "$(date -u +%FT%TZ) run-pairs exited; restarting in 5s" >> "$RUNPAIRS_LOG"
    sleep 5
  done
}

trade_loop() {
  while true; do
    "$RUNPAIRS_BIN" trade \
      --executor "$EXECUTOR" --csv "$CSV" --overrides "$OVERRIDES" \
      --flash --capital-source "$CAPITAL_SOURCE" --max-attempts "$TRADE_ATTEMPTS" --gas-cap-gwei "$GAS_CAP_GWEI" \
      $BROADCAST_FLAG >> "$TRADE_LOG" 2>&1
    echo "$(date -u +%FT%TZ) trade exited; restarting in 5s" >> "$TRADE_LOG"
    sleep 5
  done
}

run_pairs_loop &
P1=$!
trade_loop &
P2=$!
trap 'kill $P1 $P2 2>/dev/null; echo "launch-live: stopped"; exit 0' INT TERM
echo "launch-live: running (run-pairs pid $P1 → $RUNPAIRS_LOG, trade pid $P2 → $TRADE_LOG)"
echo "launch-live: Ctrl-C to stop both; tail -f $TRADE_LOG for EXECUTED lines"
wait
