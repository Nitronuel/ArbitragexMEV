#!/usr/bin/env bash
# Daily enrichment pass over hot-but-unknown pools (one shot; also run by hand).
# Reads the newest hot-unknown inventory, enriches missing V3 pools
# (read-only eth_calls on the public gateway), validates, and merges into
# data/pools-rhc-v3.csv + data/pools-all.csv with dedup guards.
# V4 rows are counted and skipped (Initialize lookup is archive-gated until
# the premium reset); V2 rows are counted for the C2 project.
# Exit 0 always unless the environment itself is broken (never page).
set -u
cd "$(dirname "$0")/.." || exit 1
LOG="logs/live/enrich-unknown.log"
ts() { date -u +%FT%TZ; }

latest="$(ls -t data/hot-unknown-auto-*.csv 2>/dev/null | head -1)"
if [[ -z "${latest:-}" ]]; then
  latest="data/hot-unknown.csv"
fi
[[ -f "$latest" ]] || { echo "$(ts) enrich-unknown: no inventory file, nothing to do" >> "$LOG"; exit 0; }

python3 - "$latest" << 'EOF' >> "$LOG" 2>&1
import csv, subprocess, sys, tempfile, os

inv = sys.argv[1]
want_v3, skip = [], {"v4": 0, "v2": 0}
for r in csv.DictReader(open(inv)):
    if r.get("venue") == "v3":
        want_v3.append(r["id"])
    elif r.get("venue") in skip:
        skip[r["venue"]] += 1

def keys(path):
    s = set()
    try:
        for r in csv.DictReader(open(path)):
            v = (r.get("pool_address") or "").strip().lower()
            if v:
                s.add(v)
    except FileNotFoundError:
        pass
    return s

known = (
    keys("data/pools-rhc-v3.csv")
    | keys("data/pools-v3-inc.csv")
    | keys("data/pools-all.csv")
)
missing = [a for a in want_v3 if a.lower() not in known]
# de-dupe repeat inventory rows, preserve order
missing = list(dict.fromkeys(a.lower() for a in missing))
print(f"enrich-unknown: inventory={inv} v3_want={len(want_v3)} "
      f"v3_missing={len(missing)} skip_v4={skip['v4']} skip_v2={skip['v2']}", flush=True)
if not missing:
    sys.exit(0)

with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as tf:
    w = csv.writer(tf)
    w.writerow(["venue", "id", "swaps"])
    for a in missing:
        w.writerow(["v3", a, 0])
    tmp_in = tf.name
tmp_out = tmp_in + ".out"
# stdout must be redirected via the stdout= kwarg: capture_output is a
# boolean flag (truthy -> PIPE), so passing a file object there silently
# discarded the enrichment output (bug: merged +0 since 2026-09-12).
with open(tmp_out, "w") as out:
    rc = subprocess.run(
        ["bash", "scripts/enrich-v3-hot.sh", tmp_in, str(len(missing))],
        stdout=out, text=True,
    ).returncode
os.unlink(tmp_in)
if rc != 0:
    print(f"enrich-unknown: enrich-v3-hot.sh rc={rc}, keeping {tmp_out} for inspection")
    sys.exit(0)

import re
CK = re.compile(r"^0x[0-9a-fA-F]{40}$")
fresh = []
for r in csv.reader(open(tmp_out)):
    if not r or r[0] != "4663" or len(r) != 10:
        continue
    if not all(CK.match(x) for x in (r[1], r[3], r[4])):
        continue
    if not r[5].isdigit():
        continue
    if r[1].lower() in known:
        continue
    fresh.append(r)
    known.add(r[1].lower())
os.unlink(tmp_out)
if fresh:
    with open("data/pools-rhc-v3.csv", "a") as f:
        for r in fresh:
            f.write(",".join(r) + "\n")
    with open("data/pools-all.csv", "a") as f:
        for r in fresh:
            f.write(",".join(r) + ",\n")
print(f"enrich-unknown: merged +{len(fresh)} v3 pools", flush=True)
EOF
echo "$(ts) enrich-unknown: pass done (rc=$?)" >> "$LOG"
