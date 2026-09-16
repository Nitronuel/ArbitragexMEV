#!/usr/bin/env bash
# Watchdog: run-pairs wedges (no new poll lines) instead of exiting when the
# gateway throttles hard, so the supervisor never restarts it. Kills + relaunches
# via scripts/launch-hot.sh if the hot log goes quiet.
#
# Usage: scripts/watch-loop.sh [max_quiet_secs] [max_median_gap_secs]
#   (defaults 300 / 90). Restarts when the log goes quiet OR the median of
#   the last 10 poll gaps exceeds the cadence bound (throttle spiral guard).
set -euo pipefail
cd "$(dirname "$0")/.."
MAXQ="${1:-300}"
MAXGAP="${2:-90}"
LOG="logs/live/run-pairs-hot.log"
restart() {
  echo "$(date -u +%FT%TZ) watch-loop: $1, restarting hot loop" >> logs/live/watch-loop.log
  # WSS event lane always needs the operator exports (PS1 guard for
  # non-interactive panes; values never leave this shell).
  PS1=x source ~/.bashrc 2>/dev/null || true
  # HTTP backend is operator-selectable via DETECTION_HTTP_BACKEND
  # (default `public` since 2026-09-16): detection HTTP on the public
  # gateway keeps the Chainstack account-level RPS budget for `trade`,
  # which -32005-walls otherwise (incident 2026-09-16). Set
  # DETECTION_HTTP_BACKEND=chainstack to restore the 2026-09-07 posture.
  local backend="${DETECTION_HTTP_BACKEND:-public}"
  if [[ "$backend" == "chainstack" && -z "${CHAINSTACK_RHC_HTTP_URL:-}" ]]; then
    echo "$(date -u +%FT%TZ) watch-loop: DETECTION_HTTP_BACKEND=chainstack but CHAINSTACK_RHC_HTTP_URL unavailable; staying public" >> logs/live/watch-loop.log
    backend="public"
  fi
  if [[ "$backend" == "public" ]]; then
    unset CHAINSTACK_RHC_HTTP_URL
  fi
  pkill -f "manifest-hot" 2>/dev/null || true
  sleep 3
  pkill -9 -f "manifest-hot" 2>/dev/null || true
  sleep 2
  tmux new-window -t live -n hot -d "./scripts/launch-hot.sh" 2>/dev/null || ./scripts/launch-hot.sh &
}
while true; do
  sleep 60
  if [[ ! -f "$LOG" ]]; then continue; fi
  age=$(( $(date +%s) - $(stat -c %Y "$LOG") ))
  if (( age > MAXQ )); then
    restart "log quiet ${age}s > ${MAXQ}s"
    continue
  fi
  gap=$(tr -d '\000' < "$LOG" | grep -oE "poll tip=[0-9]+" | tail -11 | grep -oE "[0-9]+" | python3 -c "
import sys, statistics
tips = [int(x) for x in sys.stdin.read().split()]
gaps = sorted((b - a) / 10.0 for a, b in zip(tips, tips[1:]) if 0 < b - a)
print(round(statistics.median(gaps)) if gaps else 0)")
  if (( gap > MAXGAP )); then
    restart "median poll gap ${gap}s > ${MAXGAP}s"
  fi
done
