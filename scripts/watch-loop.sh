#!/usr/bin/env bash
# Watchdog: run-pairs wedges (no new poll lines) instead of exiting when the
# gateway throttles hard, so the supervisor never restarts it. Kills + relaunches
# via scripts/launch-hot.sh if the hot log goes quiet.
#
# Usage: scripts/watch-loop.sh [max_quiet_secs] (default 300)
set -euo pipefail
cd "$(dirname "$0")/.."
MAXQ="${1:-300}"
LOG="logs/live/run-pairs-hot.log"
while true; do
  sleep 60
  if [[ ! -f "$LOG" ]]; then continue; fi
  age=$(( $(date +%s) - $(stat -c %Y "$LOG") ))
  if (( age > MAXQ )); then
    echo "$(date -u +%FT%TZ) watch-loop: log quiet ${age}s > ${MAXQ}s, restarting hot loop" >> logs/live/watch-loop.log
    pkill -f "manifest-hot" 2>/dev/null || true
    sleep 3
    pkill -9 -f "manifest-hot" 2>/dev/null || true
    sleep 2
    tmux new-window -t live -n hot -d "./scripts/launch-hot.sh" 2>/dev/null || ./scripts/launch-hot.sh &
  fi
done
