#!/usr/bin/env python3
"""Hot-pool manifest: derive the watch universe from LIVE swap flow.

Problem: the static catalog (934k pools) covers only ~30% of actively
trading V4 pools; 70% of live flow is invisible to the dirty-set evaluator.

This tool ranks pools by trailing swap count and emits a manifest containing
only catalog rows for hot pools (same CSV schema the poller expects), plus a
report of hot-but-unknown pools needing one-time metadata enrichment.

Read-only (eth_getLogs only). No key, no broadcast.

Usage:
  python3 scripts/hot-pools.py [--window-blocks N] [--top-v4 N] [--top-v3 N]
      [--out data/manifest-hot.csv] [--unknown data/hot-unknown.csv]

Defaults: window 6000 blocks (~10 min), top 1000 per venue.
"""
import argparse
import csv
import json
import subprocess
import sys
import time

RPC = "https://rpc.mainnet.chain.robinhood.com"
PM = "0x8366a39CC670B4001A1121B8F6A443A643e40951"

# keccak256("Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)")
V4_SWAP0 = "0x40e9cecb9f5f1f1c5b9c97dec2917b7ee92e57ba5563708daca94dd84ad7112f"
# keccak256("Swap(address,address,int256,int256,uint160,uint128,int24)")
V3_SWAP0 = "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67"

HEADER = ("chain_id,pool_address,factory_address,token0,token1,"
          "fee_numerator,fee_denominator,profile,pool_id,source")


def rpc(method, params, retries=8):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    # NOTE: the public gateway 403-blocks urllib; curl works.
    last = None
    for attempt in range(retries):
        out = subprocess.run(
            ["curl", "-s", "--max-time", "60", "-X", "POST", RPC,
             "-H", "Content-Type: application/json", "-d", body],
            capture_output=True, text=True).stdout
        try:
            last = json.loads(out)
        except json.JSONDecodeError:
            time.sleep(2 * (attempt + 1))
            continue
        if "error" in last:
            # 429 / rate limits: back off and retry
            time.sleep(2 * (attempt + 1))
            continue
        return last["result"]
    raise RuntimeError(f"rpc {method} failed after {retries} retries: {last}")


def get_logs(topics, frm, address=None):
    p = {"fromBlock": hex(frm), "toBlock": "latest", "topics": topics}
    if address:
        p["address"] = address
    # chunk into small windows (gateway caps results at 10k logs/query)
    tip = int(rpc("eth_blockNumber", []), 16)
    logs = []
    start = frm
    while start <= tip:
        end = min(start + 499, tip)
        p["fromBlock"] = hex(start)
        p["toBlock"] = hex(end)
        logs.extend(rpc("eth_getLogs", [p]))
        time.sleep(0.5)
        start = end + 1
    return logs


def rank(logs, topic_idx):
    from collections import Counter
    c = Counter()
    for log in logs:
        t = log.get("topics", [])
        if len(t) > topic_idx:
            c[t[topic_idx].lower()] += 1
    return c


def load_catalog(path, key):
    rows = {}
    with open(path) as f:
        for r in csv.DictReader(f):
            rows[r[key].lower()] = r
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-blocks", type=int, default=6000)
    ap.add_argument("--top-v4", type=int, default=1000)
    ap.add_argument("--top-v3", type=int, default=1000)
    ap.add_argument("--out", default="data/manifest-hot.csv")
    ap.add_argument("--unknown", default="data/hot-unknown.csv")
    ap.add_argument("--overrides", default="data/v4-overrides.csv",
                    help="tickSpacing/hooks per pool_id for the hooks gate")
    ap.add_argument("--hook-allowlist", default="data/hook-allowlist.csv",
                    help="pool_ids (one per line, 0x optional) exempt from the hooks gate")
    a = ap.parse_args()

    tip = int(rpc("eth_blockNumber", []), 16)
    frm = tip - a.window_blocks
    print(f"tip={tip} window=[{frm},{tip}]", flush=True)

    v4 = rank(get_logs([V4_SWAP0], frm, PM), 1)
    # V3 ranking key is the log address (pool), not a topic:
    from collections import Counter
    v3c = Counter()
    for log in get_logs([V3_SWAP0], frm):
        v3c[log["address"].lower()] += 1
    print(f"active v4 pools: {len(v4)}", flush=True)

    cat4 = load_catalog("data/pools-rhc-v4.csv", "pool_id")
    cat3 = load_catalog("data/pools-rhc-v3.csv", "pool_address")
    print(f"catalog: v4={len(cat4)} v3={len(cat3)}", flush=True)

    hot4 = v4.most_common(a.top_v4)
    hot3 = v3c.most_common(a.top_v3)
    known, unknown = [], []
    for pid, n in hot4:
        if pid in cat4:
            r = dict(cat4[pid]); r["source"] = "hot"; known.append(r)
        else:
            unknown.append({"venue": "v4", "id": pid, "swaps": n})
    for addr, n in hot3:
        if addr in cat3:
            r = dict(cat3[addr]); r["source"] = "hot"; known.append(r)
        else:
            unknown.append({"venue": "v3", "id": addr, "swaps": n})
    print(f"hot known: {len(known)}  hot unknown (need enrich): {len(unknown)}",
          flush=True)
    # Phase-3 hooks gate: V4 rows with nonzero-hook overrides are refused
    # unless explicitly allow-listed (hook pricing needs hook logic;
    # vanilla math on hook pools produces ghosts).
    allowed = set()
    try:
        with open(a.hook_allowlist, newline="") as f:
            for line in f:
                line = line.strip().lower()
                if not line or line.startswith("pool_id") or line.startswith("#"):
                    continue
                allowed.add(line.removeprefix("0x"))
    except FileNotFoundError:
        pass
    overrides = {}
    try:
        with open(a.overrides, newline="") as f:
            for row in csv.DictReader(f):
                pid = (row.get("pool_id") or "").strip().lower().removeprefix("0x")
                hooks = (row.get("hooks") or "").strip().lower()
                if pid:
                    overrides[pid] = hooks
    except FileNotFoundError:
        print("hooks gate: no overrides file, gate skipped", flush=True)
    kept, hook_skipped = [], 0
    for r in known:
        if (r.get("profile") or "").strip() == "v4":
            pid = (r.get("pool_id") or "").strip().lower().removeprefix("0x")
            hooks = overrides.get(pid, "")
            nonzero = hooks not in ("", "0x" + "0" * 40, "0" * 40)
            if nonzero and pid not in allowed:
                hook_skipped += 1
                continue
        kept.append(r)
    known = kept
    print(f"hooks gate: kept={len(known)} skipped_nonzero_hook={hook_skipped} "
          f"allowlisted={len(allowed)}", flush=True)
    unk_swaps = sum(u["swaps"] for u in unknown)
    tot_swaps = sum(v4.values()) + sum(v3c.values())
    print(f"unknown share of flow: {unk_swaps}/{tot_swaps} "
          f"({100.0 * unk_swaps / max(tot_swaps, 1):.1f}%)", flush=True)

    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=HEADER.split(","))
        w.writeheader()
        for r in known:
            w.writerow({k: r.get(k, "") for k in HEADER.split(",")})
    with open(a.unknown, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["venue", "id", "swaps"])
        w.writeheader()
        for u in sorted(unknown, key=lambda x: -x["swaps"]):
            w.writerow(u)
    print(f"wrote {a.out} ({len(known)} rows) + {a.unknown} ({len(unknown)})")


if __name__ == "__main__":
    sys.exit(main())
