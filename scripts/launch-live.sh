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

OWNER="0x3219E15A8d1e82368340dfB6697fE6a6B41d686D"
EXECUTOR="0xE1dB326DC4B0853914EA455E7ED49d970d59180d"
TRADE_ATTEMPTS="${TRADE_ATTEMPTS:-2}"
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
if ! head -c 1 "$CSV" | grep -q "kind"; then
  echo "kind,token_lo,token_hi,to_block,input,output,profit,log2_skew,gross_profit_usd,net_profit_usd,shortfall_usd,threshold_usd,floor_ratio,optimal_unclamped,input_capacity,reason_code,reason_detail,anchor_priced,legs" > "$CSV"
fi

echo "launch-live: broadcast=${BROADCAST_FLAG:-DRY-RUN} native_usd=$NATIVE_USD executor=$EXECUTOR"

run_pairs_loop() {
  while true; do
    ./target/debug/shadow-bot run-pairs \
      --a data/pools-rhc-v3.csv --b data/pools-rhc-v4.csv \
      --manifest data/manifest-activity.csv --prices data/prices-seed.csv \
      --rpc "$RPC" --native-usd "$NATIVE_USD" \
      --window 4000 --poll-ms 2000 --delay-ms 1500 --max-swaps 0 \
      --csv "$CSV" >> "$RUNPAIRS_LOG" 2>&1
    echo "$(date -u +%FT%TZ) run-pairs exited; restarting in 5s" >> "$RUNPAIRS_LOG"
    sleep 5
  done
}

trade_loop() {
  while true; do
    ./target/debug/shadow-bot trade \
      --executor "$EXECUTOR" --csv "$CSV" --overrides "$OVERRIDES" \
      --flash --max-attempts "$TRADE_ATTEMPTS" \
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
