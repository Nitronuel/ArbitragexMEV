#!/usr/bin/env python3
"""Re-probe every v3-catalog manifest pool to classify Algebra vs true-V3.

Algebra-logic pools (Ramses family on RHC) answer `globalState()` and revert
`slot0()`; true Uniswap V3 pools answer `slot0()`. Detection quotes V3 math on
`slot0` word positions, so Algebra pools produce ghost gates and the executor's
V3 settlement cannot run them — they must be excluded via `data/v3-algebra.csv`
(trade refuses pre-estimate; run-pairs drops at load).

Writes `data/v3-algebra.csv` (one lowercase pool address per line, comment
header). Retry with exponential backoff on 429 (-32005-style throttles) and
surface per-pool probes that fail on other errors as UNKNOWN (kept if already
listed, so we never silently un-exclude an unverified pool).

Usage: python3 scripts/algebra-rescan.py [--rpc URL] [--out data/v3-algebra.csv]
RPC defaults to $CHAINSTACK_RHC_HTTP_URL, else the public RHC gateway.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import urllib.request

PUBLIC_RPC = "https://rpc.mainnet.chain.robinhood.com"

GLOBAL_STATE_SELECTOR = "0xe76c01e4"  # globalState()
SLOT0_SELECTOR = "0x3850c7bd"  # slot0()


def eth_call(rpc: str, to: str, data: str, retries: int = 4) -> str | None:
    """Returns hex result, '' for revert, None for transient failure."""
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"],
    }).encode()
    delay = 0.5
    for _ in range(retries):
        req = urllib.request.Request(
            rpc, data=payload, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = json.loads(resp.read())
        except Exception:
            time.sleep(delay)
            delay *= 2
            continue
        if "error" in body:
            code = body["error"].get("code")
            if code in (-32005, -32002, 429):
                time.sleep(delay)
                delay *= 2
                continue
            return ""  # execution revert = definitive answer
        return body.get("result", "")
    return None  # still throttled after retries


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default=os.environ.get("CHAINSTACK_RHC_HTTP_URL", PUBLIC_RPC))
    ap.add_argument("--manifest", default="data/manifest-hot.csv")
    ap.add_argument("--out", default="data/v3-algebra.csv")
    args = ap.parse_args()

    with open(args.manifest, newline="") as f:
        pools = [
            r["pool_address"].lower()
            for r in csv.DictReader(f)
            if (r.get("profile") or "") == "v3" and r.get("pool_address")
        ]
    # dedupe, keep order
    seen: set[str] = set()
    pools = [p for p in pools if not (p in seen or seen.add(p))]
    print(f"probing {len(pools)} manifest v3 pools via {args.rpc.split('//')[1].split('/')[0]}")

    algebra: list[str] = []
    unknown: list[str] = []
    for i, pool in enumerate(pools):
        gs = eth_call(args.rpc, pool, GLOBAL_STATE_SELECTOR)
        if gs is None:
            unknown.append(pool)
            print(f"[{i+1}/{len(pools)}] {pool} UNKNOWN (throttled)", flush=True)
            continue
        if gs:
            # answers globalState -> Algebra-family (verify slot0 reverts)
            s0 = eth_call(args.rpc, pool, SLOT0_SELECTOR)
            if s0 == "" or s0:
                algebra.append(pool)  # revert or different answer => Algebra
            print(f"[{i+1}/{len(pools)}] {pool} ALGEBRA", flush=True)
            continue
        # globalState reverted; slot0 must answer for true-V3
        s0 = eth_call(args.rpc, pool, SLOT0_SELECTOR)
        if s0 is None:
            unknown.append(pool)
            print(f"[{i+1}/{len(pools)}] {pool} UNKNOWN (throttled)", flush=True)
        elif s0:
            print(f"[{i+1}/{len(pools)}] {pool} v3", flush=True)
        else:
            algebra.append(pool)  # neither answers: dead pool, keep excluded
            print(f"[{i+1}/{len(pools)}] {pool} DEAD (both revert)", flush=True)
        if (i + 1) % 25 == 0:
            time.sleep(0.2)  # pacing for the free tier

    prior = {
        ln.strip().lower()
        for ln in open(args.out)
        if ln.strip().startswith("0x")
    }
    # Never silently un-exclude a pool we could not re-verify.
    final = sorted(set(algebra) | {p for p in prior if p in unknown or p not in pools})
    with open(args.out, "w") as f:
        f.write(
            "# Algebra-logic pools hiding in the v3 catalog (slot0() reverts;\n"
            "# algebraSwapCallback instead of UniswapV3 callback + dynamic fees).\n"
            "# Quoted with V3 math they produce ghost gates; our V3-direct\n"
            "# settlement cannot execute them. Refused pre-estimate (trade)\n"
            "# and skipped at load (detection). Regenerate:\n"
            "#   python3 scripts/algebra-rescan.py\n"
        )
        for p in final:
            f.write(p + "\n")
    print(f"wrote {args.out}: {len(final)} entries "
          f"({len(algebra)} fresh algebra, {len(final)-len(algebra)} retained/unknown)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
