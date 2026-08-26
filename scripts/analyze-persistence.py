#!/usr/bin/env python3
"""Dislocation persistence-time analyzer (audit task 0.9 / Part VI.1).

Consumes one or more run-pairs canary CSVs (the honest-gate schema with
`reason_code` columns) and measures how long each gated dislocation
PERSISTS — the decisive viability metric on an FCFS chain: our reaction
latency (~seconds) must beat an episode's lifetime for any submission to
win.

Method:
  - Only `above_threshold` rows gate; `pair` rows carry a real pair.
  - Consecutive sightings of the same pair within EPISODE_GAP blocks are
    ONE episode (matches scripts/watch-gates.sh's dedupe horizon).
  - Persistence = last_seen_block - first_seen_block per episode, in
    blocks and seconds at SECONDS_PER_BLOCK.

Usage:
  ./scripts/analyze-persistence.py logs/canary/canary-honest-*.csv
"""

from __future__ import annotations

import csv
import glob
import sys
from collections import defaultdict

EPISODE_GAP_BLOCKS = 200  # matches watch-gates.sh episode dedupe
SECONDS_PER_BLOCK = 0.1   # RHC measured cadence


def load_gated(paths: list[str]):
    """Yields (pair_key, block) for every above_threshold pair row."""
    for pattern in paths:
        for path in sorted(glob.glob(pattern)):
            with open(path, newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    if row.get("reason_code") != "above_threshold":
                        continue
                    if row.get("kind") != "pair":
                        continue  # triangles have no single pair
                    key = (row["token_lo"], row["token_hi"])
                    yield key, int(row["to_block"])


def episodes(sightings: list[int]) -> list[tuple[int, int]]:
    """Collapses sorted block sightings into (first, last) episodes."""
    episodes = []
    first = prev = sightings[0]
    for block in sightings[1:]:
        if block - prev > EPISODE_GAP_BLOCKS:
            episodes.append((first, prev))
            first = block
        prev = block
    episodes.append((first, prev))
    return episodes


def pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round(p * (len(ordered) - 1))))
    return ordered[idx]


def main() -> int:
    paths = sys.argv[1:]
    if not paths:
        print(__doc__)
        return 2

    by_pair: dict[tuple[str, str], list[int]] = defaultdict(list)
    total_rows = 0
    for key, block in load_gated(paths):
        by_pair[key].append(block)
        total_rows += 1

    if total_rows == 0:
        print("no above_threshold pair rows found — nothing to analyze")
        return 0

    all_persistence: list[float] = []
    print(f"{'pair':44s} {'rows':>5s} {'eps':>4s} {'median_s':>9s} {'p90_s':>8s} {'max_s':>8s}")
    for (lo, hi), blocks in sorted(by_pair.items(), key=lambda kv: -len(kv[1])):
        blocks.sort()
        eps = episodes(blocks)
        spans = [
            (last - first) * SECONDS_PER_BLOCK + SECONDS_PER_BLOCK
            for first, last in eps
        ]
        all_persistence.extend(spans)
        short_lo = f"{lo[:10]}…{lo[-6:]}"
        short_hi = f"{hi[:10]}…{hi[-6:]}"
        print(
            f"{short_lo}/{short_hi:22s} {len(blocks):>5d} {len(eps):>4d} "
            f"{pct(spans, 0.5):>9.1f} {pct(spans, 0.9):>8.1f} {max(spans):>8.1f}"
        )

    print()
    print(f"gate rows: {total_rows}   distinct pairs: {len(by_pair)}   "
          f"episodes: {len(all_persistence)}")
    if all_persistence:
        beatable = sum(1 for s in all_persistence if s >= 2.0)
        print(f"persistence seconds: median={pct(all_persistence, 0.5):.1f} "
              f"p90={pct(all_persistence, 0.9):.1f} max={max(all_persistence):.1f}")
        print(f"episodes persisting >=2s (beat a ~2s reaction loop): "
              f"{beatable}/{len(all_persistence)} "
              f"({100 * beatable / len(all_persistence):.0f}%)")
        print("reading: on FCFS, only episodes outliving our detection+submission"
              " latency are winnable; sub-2s episodes are visible-but-unwinnable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
