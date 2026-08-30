#!/usr/bin/env python3
"""Discover tickSpacing/hooks for specific V4 poolIds from RHC Initialize events.

The enumeration CSV omits tickSpacing/hooks (audit B58); the `trade` command
refuses V4 legs without them. This tool sweeps the PoolManager's Initialize
logs in windows via curl (the gateway rate-limits; urllib gets 403-blocked),
writing an overrides CSV: pool_id,tick_spacing,hooks

Usage:
  python3 scripts/enrich_v4.py <pool_ids.txt> <overrides.csv> [start_block] [end_block]

  pool_ids.txt : one 32-byte poolId hex per line
  overrides.csv: appended to (created with a header if missing); resumable —
                 already-known ids are skipped on re-run.

Sweeps backward from `end_block` (default: current tip) in 150k windows with
pacing, down to `start_block` (default: end - 6,000,000). Re-run with a lower
start_block to continue deeper.
"""
import json
import os
import subprocess
import sys
import time

RPC = "https://rpc.mainnet.chain.robinhood.com"
PM = "0x8366a39cc670b4001a1121b8f6a443a643e40951"
INIT_TOPIC = "0xdd466e674ea557f56295e2d0218a125ea4b4f0f6f3307b95f85e6110838d6438"
WINDOW = 150_000
PACING_SECS = 6


def tip_block() -> int:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []})
    out = subprocess.run(
        ["curl", "-s", "-m", "20", "-X", "POST", RPC, "-H", "Content-Type: application/json", "-d", body],
        capture_output=True, text=True,
    ).stdout
    return int(json.loads(out)["result"], 16)


def get_logs(from_b: int, to_b: int):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getLogs", "params": [{
        "fromBlock": hex(from_b), "toBlock": hex(to_b), "address": PM, "topics": [INIT_TOPIC]}]})
    for attempt in range(4):
        out = subprocess.run(
            ["curl", "-s", "-m", "40", "-X", "POST", RPC, "-H", "Content-Type: application/json", "-d", body],
            capture_output=True, text=True,
        ).stdout
        try:
            res = json.loads(out)
        except json.JSONDecodeError:
            res = {"error": out[:80]}
        if "result" in res:
            return res["result"]
        print(f"  retry {attempt}: {str(res.get('error'))[:80]}", flush=True)
        time.sleep(10)
    return []


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    ids_file, out_csv = sys.argv[1], sys.argv[2]
    with open(ids_file) as f:
        targets = {ln.strip().lower() for ln in f if ln.strip()}
    header_needed = not os.path.exists(out_csv) or os.path.getsize(out_csv) == 0
    known = set()
    if not header_needed:
        with open(out_csv) as f:
            for ln in f:
                if ln.strip() and not ln.startswith("pool_id"):
                    known.add(ln.split(",")[0].strip().lower())
    pending = targets - known
    print(f"targets: {len(targets)}, already known: {len(targets & known)}, pending: {len(pending)}")
    if not pending:
        return 0

    end = int(sys.argv[4], 0) if len(sys.argv) > 4 else tip_block()
    start = int(sys.argv[3], 0) if len(sys.argv) > 3 else end - 6_000_000

    with open(out_csv, "a") as out:
        if header_needed:
            out.write("pool_id,tick_spacing,hooks\n")
        top = end
        while top > start and pending:
            frm = max(start, top - WINDOW)
            logs = get_logs(frm, top)
            n = 0
            for lg in logs:
                pid = "0x" + lg["topics"][1][2:].lower()
                if pid in pending:
                    data = lg["data"][2:]
                    tick = int(data[64:128], 16)
                    if tick >= 1 << 255:
                        tick -= 1 << 256
                    hooks = "0x" + data[128:192][-40:].lstrip("0")
                    out.write(f"{pid},{tick},{hooks}\n")
                    pending.discard(pid)
                    n += 1
            out.flush()
            print(f"window {frm}-{top}: {len(logs)} inits, {n} new ({len(pending)} pending)", flush=True)
            top = frm
            time.sleep(PACING_SECS)
    print("=== DONE ===" if not pending else f"=== {len(pending)} still missing — re-run with a lower start_block ===")
    for pid in sorted(pending):
        print(pid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
