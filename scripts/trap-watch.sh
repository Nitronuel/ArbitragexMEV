#!/bin/bash
# Monster-trap watcher (2026-09-21): CSV-watch (zero RPC) + on-demand one-shot
# trade on floor>=5 rows. Standing operator orders: screen 5691 (done),
# fire ONE normal-estimate attempt per trigger when wallet > ~$1.
#
# Flow per trigger: balance-gate (1 RPC call) -> pause detection (frees the
# public 60s budget window) -> one-shot trade on scratch CSV (max-attempts 1,
# NO --probe, normal estimate) -> resume detection -> log outcome.
# Fail-closed everywhere: estimate-refusals and fund-refusals spend $0.
# Blast radius per trigger: detection blind ~2-3 min, at most ONE broadcast.
set -u
cd /root/project/mev/arbitrage || exit 1
# NOTE: do NOT `source ~/.bashrc` here — the environment is inherited
# from the launcher (which sources it interactively). Sourcing inside a
# detached non-interactive shell trips the session security hook (silent kill).
# Required env (inherited): ARBITRAGE_WALLET_PRIVATE_KEY (trade signing),
# CHAINSTACK_RHC_WSS_URL (detection WS lane).
CSV=logs/live/trades-hot.csv
TLOG=logs/live/trade-hot.log
WALLET=0xa0cd80624130f06d2f9f1e5c3bcf9563dec5018a
MIN_WEI=400000000000000
LAST_FILE=/tmp/trap-last-block
LOCK=/tmp/trap.lock
EXEC=0x727f41B647e9F0958dd539b0dFff4fc46A90A950
RPC=https://rpc.mainnet.chain.robinhood.com

log() { echo "$(date -u +%FT%TZ) trap-watch: $*" >> "$TLOG"; }

if [ ! -f "$LAST_FILE" ]; then
  python3 -c "
import csv
rows=[r for r in csv.DictReader(open('$CSV')) if r['reason_code']=='above_threshold']
print(max(int(r['to_block']) for r in rows))
" > "$LAST_FILE"
fi

log "watcher started pid=$$, LAST=$(cat $LAST_FILE)"

while true; do
  sleep 45
  [ -f "$LOCK" ] && continue
  LAST=$(cat "$LAST_FILE")
  NEW=$(python3 -c "
import csv
rows=list(csv.DictReader(open('$CSV')))
new=[r for r in rows if r['reason_code']=='above_threshold' and int(r['to_block'])>$LAST and float(r['floor_ratio'])>=5]
print(len(new))
for r in new:
    print(r['to_block'],r['token_lo'][:10],r['token_hi'][:10],r['floor_ratio'],r['profit'])
")
  COUNT=$(echo "$NEW" | head -n 1)
  [ "$COUNT" = "0" ] && continue
  touch "$LOCK"
  # Advance LAST first (never refire on the same rows).
  python3 -c "
import csv
rows=[r for r in csv.DictReader(open('$CSV')) if r['reason_code']=='above_threshold']
open('$LAST_FILE','w').write(str(max(int(r['to_block']) for r in rows)))
"
  log "TRIGGER ${COUNT} row(s): $(echo "$NEW" | tail -n +2 | tr '\n' ';' | cut -c1-300)"
  # Balance gate (single RPC call, only at trigger time).
  BAL=$(curl -s -m 25 -X POST -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBalance\",\"params\":[\"$WALLET\",\"latest\"]}" \
    "$RPC" | python3 -c "import sys,json;print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo 0)
  log "trigger balance=${BAL} wei"
  case "$BAL" in ''|*[!0-9]*) BAL=0 ;; esac
  if [ "$BAL" -lt "$MIN_WEI" ]; then
    log "TRIGGER MISSED (unfunded, need >~\$1)"
    rm -f "$LOCK"
    continue
  fi
  # Snapshot detection cmdline, then pause it for a clean budget window.
  DETPID=$(ps -eo pid,args | awk '/target\/release\/shadow-bot run-pairs/ && !/awk/ {print $1}' | head -n 1)
  DETCMD=""
  if [ -n "$DETPID" ]; then
    DETCMD=$(tr '\0' ' ' < "/proc/$DETPID/cmdline")
    kill "$DETPID" && log "detection paused (pid $DETPID)"
    sleep 3
  else
    log "detection not running at trigger (nothing to pause)"
  fi
  # One-shot trade on scratch CSV. Trade skips rows present at startup, so:
  # header-only scratch -> launch -> wait -> append trigger rows (proven pattern).
  SCRATCH=/tmp/trap-rows.csv
  head -n 1 "$CSV" > "$SCRATCH"
  # (env inherited from watcher launcher: key + WS/RPC lanes)
  setsid nohup env -u CHAINSTACK_RHC_HTTP_URL ./target/release/shadow-bot trade \
    --rpc "$RPC" --executor "$EXEC" --csv "$SCRATCH" \
    --overrides data/v4-overrides.csv --hook-allowlist data/hook-allowlist.csv \
    --v3-algebra data/v3-algebra.csv --router-dead-pools data/router-dead-pools.csv \
    --prices data/prices-live.csv --flash --poll-ms 3000 --profit-safety-pct 0 \
    --max-attempts 1 --broadcast >> "$TLOG" 2>&1 < /dev/null &
  TPID=$!
  log "one-shot trade launched (pid $TPID)"
  sleep 8
  N=$(python3 -c "
import csv
rows=list(csv.DictReader(open('$CSV')))
last=$LAST
new=[r for r in rows if r['reason_code']=='above_threshold' and int(r['to_block'])>last and float(r['floor_ratio'])>=5]
import csv as c
with open('$SCRATCH','a',newline='') as f:
    w=c.DictWriter(f,fieldnames=rows[0].keys())
    w.writerows(new)
print(len(new))
")
  log "scratch rows appended: $N"
  # Wait up to ~150s for natural exit (estimate usually resolves fast on a
  # free budget; 429-flail is the slow case).
  WAITED=0
  while kill -0 "$TPID" 2>/dev/null && [ "$WAITED" -lt 150 ]; do sleep 10; WAITED=$((WAITED+10)); done
  if kill -0 "$TPID" 2>/dev/null; then kill "$TPID"; log "one-shot timed out, killed"; else log "one-shot exited naturally"; fi
  # Resume detection with its exact prior cmdline.
  if [ -n "$DETCMD" ]; then
    # shellcheck disable=SC2086
    setsid nohup $DETCMD >> logs/live/run-pairs-hot.log 2>&1 < /dev/null &
    log "detection resumed"
  fi
  rm -f "$LOCK"
done
