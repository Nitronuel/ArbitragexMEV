#!/usr/bin/env python3
"""Post-window analyzer for run-pairs canary windows.

Reads one or more canary (log, csv) window pairs and prints, per window:
poll/eval throughput, the reason-class x kind distribution of CSV rows, every
AboveThreshold row with its anchor_priced flag, frozen-value clusters
(consecutive identical net_profit_usd per pair/triangle — the stale-leg
artifact signature), and the near-miss band split by priced/unpriced anchors.

Usage:
    analyze-canary.py --label canary8d --log LOG --csv CSV \
        [--max-polls N] [--label ... --log ... --csv ...]...

`--max-polls N` slices all metrics to the first N `gated=` polls of that
window so unequal-length windows compare at equal elapsed work.

Stdlib only; read-only. The last CSV line is ignored if it is incomplete
(the live BufWriter tail).
"""

import argparse
import csv
import re
import sys
from collections import Counter

GATED_RE = re.compile(r"gated=(\d+)")
REASONS = ("NotEvaluated", "NotProfitable", "BelowThreshold", "AboveThreshold")
NEAR_MISS_BAND = (0.5, 1.0)
CSV_COLUMNS = [
    "kind",
    "token_lo",
    "token_hi",
    "to_block",
    "input",
    "output",
    "profit",
    "log2_skew",
    "gross_profit_usd",
    "net_profit_usd",
    "threshold_usd",
    "floor_ratio",
    "reason",
    "anchor_priced",
]
# Headers accepted, oldest format first. `kind` was added in canary7,
# `floor_ratio`/`anchor_priced` in the canary8e tooling.
KNOWN_PREFIXES = (
    ["token_lo", "token_hi", "to_block", "input", "output", "profit",
     "log2_skew", "gross_profit_usd", "net_profit_usd", "threshold_usd",
     "reason"],
    CSV_COLUMNS[:-2],
    CSV_COLUMNS[:-1],
    CSV_COLUMNS,
)


def count_log_polls(path, max_polls):
    """Returns (polls_read, gated_poll_sum) over the first max_polls lines."""
    polls = 0
    gated_sum = 0
    with open(path) as f:
        for line in f:
            m = GATED_RE.search(line)
            if not m:
                continue
            if max_polls and polls >= max_polls:
                break
            polls += 1
            gated_sum += int(m.group(1))
    return polls, gated_sum


def read_csv_rows(path, max_rows):
    """Yields dict rows; skips a torn trailing line from a live buffer."""
    rows = []
    with open(path) as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return rows
        if header not in KNOWN_PREFIXES:
            raise SystemExit(
                f"{path}: unexpected CSV header {header}; not a run-pairs gated CSV"
            )
        pad = len(header) < len(CSV_COLUMNS)
        prev_tail = None
        for fields in reader:
            if not fields:
                continue
            if prev_tail is not None:
                rows.append(prev_tail)
            prev_tail = fields  # hold back one row: last may be torn
            if max_rows and len(rows) >= max_rows:
                break
        if prev_tail is not None and len(prev_tail) >= len(header):
            # Complete final row; a torn live-buffer tail is shorter.
            rows.append(prev_tail)
    out = []
    for fields in rows:
        n = len(fields)
        if n == len(CSV_COLUMNS) - 3:  # pre-canary7: no kind/floor_ratio/priced
            fields = ["pair"] + fields[:11] + ["?", "?"]
        elif n == len(CSV_COLUMNS) - 2:  # canary7: no floor_ratio/priced
            fields = fields + ["?", "?"]
        elif n == len(CSV_COLUMNS) - 1:  # pre-canary8e: no priced flag
            fields = fields + ["?"]
        out.append(dict(zip(CSV_COLUMNS, fields)))
    return out


def reason_of(row):
    raw = (row.get("reason") or "").strip()
    for candidate in REASONS:
        if candidate in raw:
            return candidate
    return "Unknown"


def frozen_clusters(rows):
    """Longest runs of consecutive identical net_profit_usd per series.

    A stale leg produces bit-identical profit across consecutive polls; any
    span > 1 is an artifact signature worth reporting.
    """
    spans = Counter()
    longest = {}
    series = {}
    for r in rows:
        key = (r["kind"], r["token_lo"], r["token_hi"])
        val = r["net_profit_usd"]
        seq = series.setdefault(key, [])
        if seq and seq[-1][0] == val:
            seq[-1] = (val, seq[-1][1] + 1)
        else:
            seq.append((val, 1))
    for key, runs in series.items():
        for _, n in runs:
            if n > 1:
                spans[key[0]] += n - 1
                longest[key[0]] = max(longest.get(key[0], 0), n)
    return spans, longest


def analyze(label, log_path, csv_path, max_polls):
    polls, gated_polls = count_log_polls(log_path, max_polls)
    # A poll can evaluate far more rows than one; only slice when requested.
    max_rows = None if max_polls == 0 else max_polls * 12 + 16
    rows = read_csv_rows(csv_path, max_rows)

    classes = Counter((r["kind"], reason_of(r)) for r in rows)
    above = [r for r in rows if reason_of(r) == "AboveThreshold"]
    priced_counts = Counter((r["anchor_priced"] or "?").strip().lower() for r in above)
    for r in rows:
        flag = (r.get("anchor_priced") or "").strip()
        if not flag or flag == "?":
            r["anchor_priced"] = "?"
        else:
            r["anchor_priced"] = flag.lower()

    near_misses = Counter()
    for r in rows:
        if reason_of(r) not in ("BelowThreshold",):
            continue
        try:
            ratio = float(r["floor_ratio"] or "nan")
        except ValueError:
            continue
        if NEAR_MISS_BAND[0] <= ratio < NEAR_MISS_BAND[1]:
            near_misses[(r["kind"], r["anchor_priced"])] += 1

    spans, longest = frozen_clusters(rows)

    print(f"=== {label} ===")
    print(f"polls: {polls}  gated-poll-events: {gated_polls}  csv-rows: {len(rows)}")
    print("reason distribution:")
    for kind in ("pair", "triangle"):
        parts = ", ".join(f"{cls}={classes[(kind, cls)]}" for cls in REASONS)
        print(f"  {kind}: {parts}")
    print(
        "AboveThreshold rows: {} (priced: true={}, false={}, ?={})".format(
            len(above),
            priced_counts["true"],
            priced_counts["false"],
            priced_counts["?"],
        )
    )
    for r in above[:10]:
        print(
            f"  {r['kind']} {r['token_lo'][:12]}<->{r['token_hi'][:10]}"
            f" blk={r['to_block']} fr={r['floor_ratio']} priced={r['anchor_priced']}"
        )
    if len(above) > 10:
        print(f"  ... and {len(above) - 10} more")
    print(f"near-miss (floor_ratio {NEAR_MISS_BAND}): {dict(near_misses) or 'none'}")
    print(f"frozen extra-repeats by kind: {dict(spans) or 'none'}")
    print(f"longest identical-profit run by kind: {longest or 'n/a'}")
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--label", action="append", default=[])
    ap.add_argument("--log", action="append", default=[])
    ap.add_argument("--csv", action="append", default=[])
    ap.add_argument("--max-polls", type=int, default=0)
    args = ap.parse_args()
    if not (args.label and args.log and args.csv):
        ap.error("--label/--log/--csv are required together (repeatable)")
    if not (len(args.label) == len(args.log) == len(args.csv)):
        ap.error("labels, logs, and csvs must be provided in equal counts")
    for label, log_path, csv_path in zip(args.label, args.log, args.csv):
        analyze(label, log_path, csv_path, args.max_polls)


if __name__ == "__main__":
    sys.exit(main())
