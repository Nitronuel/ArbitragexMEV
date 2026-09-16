#!/usr/bin/env python3
"""Feed-vs-WS trigger agreement (stage A3 of 2026-09-13-feed-trigger-lane.md).

Compares Nitro feed pool touches (`seq<TAB>touches` from
`shadow-bot feed-watch --touch-log`) against evaluated rows in a run-pairs
GATED CSV: for each row, were any of its leg pools seen in feed touches
within [to_block - window, to_block]?

Read-only. Exit 0 prints the report; exit 1 when above-threshold recall is
below the promotion bar (and at least one above-threshold row was in scope).
"""
import argparse
import csv
import sys


def parse_touches(path):
    """seq -> set of 'a:<addr>' / 'p:<poolid>' touch keys."""
    by_seq = {}
    gaps = 0
    prev = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or "\t" not in line:
                continue
            seq_raw, _, touch_raw = line.partition("\t")
            try:
                seq = int(seq_raw)
            except ValueError:
                continue
            if prev is not None and seq > prev + 1:
                gaps += seq - prev - 1
            prev = seq if prev is None or seq > prev else prev
            touches = {t.strip().lower() for t in touch_raw.split(",") if t.strip()}
            by_seq.setdefault(seq, set()).update(touches)
    return by_seq, gaps


def leg_keys(legs_field):
    """Pool keys for one CSV legs cell: 'a:<addr>' for V3, 'p:<poolid>' for V4.

    Leg shapes: `v3:<pool_addr>:…` vs `v4:<pool_manager>:<pool_id>:…`.
    """
    keys = set()
    for leg in legs_field.split("|"):
        parts = leg.split(":")
        if len(parts) < 3:
            continue
        profile = parts[0]
        if profile == "v3":
            addr = parts[1].lower().removeprefix("0x")
            if len(addr) == 40:
                keys.add("a:" + addr)
        elif profile == "v4" and len(parts) >= 3:
            pool_id = parts[2].lower().removeprefix("0x")
            if len(pool_id) == 64:
                keys.add("p:" + pool_id)
    return keys


def load_rows(path):
    rows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            try:
                to_block = int(row["to_block"])
            except (KeyError, ValueError, TypeError):
                continue
            rows.append(
                {
                    "to_block": to_block,
                    "reason": (row.get("reason_code") or "").strip(),
                    "keys": leg_keys(row.get("legs", "")),
                }
            )
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--touches", required=True)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--window", type=int, default=50,
                    help="lookback blocks for a trigger to count")
    ap.add_argument("--recall-bar", type=float, default=0.99)
    args = ap.parse_args()

    by_seq, gaps = parse_touches(args.touches)
    rows = load_rows(args.csv)
    if not by_seq or not rows:
        print(f"feed-agreement: touches={len(by_seq)} rows={len(rows)} gaps={gaps} (insufficient data)")
        return 0

    lo, hi = min(by_seq), max(by_seq)
    in_scope = [r for r in rows if lo <= r["to_block"] <= hi and r["keys"]]
    above = [r for r in in_scope if r["reason"] == "above_threshold"]

    def recall(subset):
        if not subset:
            return None
        hit = 0
        for row in subset:
            start = row["to_block"] - args.window
            seen = set()
            for seq in range(start, row["to_block"] + 1):
                seen |= by_seq.get(seq, set())
            if row["keys"] & seen:
                hit += 1
        return hit / len(subset)

    all_recall = recall(in_scope)
    above_recall = recall(above)
    fmt = lambda v: "n/a" if v is None else f"{v:.3f}"
    print(f"feed-agreement: seqs={lo}-{hi} gaps={gaps} rows_in_scope={len(in_scope)} "
          f"above_threshold={len(above)}")
    print(f"feed-agreement: recall_all={fmt(all_recall)} recall_above={fmt(above_recall)} "
          f"window={args.window} bar={args.recall_bar}")
    if above and above_recall is not None and above_recall < args.recall_bar:
        print("feed-agreement: BELOW BAR")
        return 1
    print("feed-agreement: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
