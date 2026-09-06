#!/usr/bin/env python3
"""Enrich hot-but-unknown V4 pools by decoding live router calldata.

For pools traded through the RHC router (0x6505…), the swap calldata carries
the full pool key: (c0, c1, fee, tickSpacing, hooks, poolKey). One decoded tx
per pool yields a catalog-ready row — no Initialize history needed.

Read-only. Usage:
  python3 scripts/enrich-v4-hot.py data/hot-unknown.csv [top_n] [out_rows.csv]
Defaults: top 200, appends catalog rows to data/manifest-hot.csv.
"""
import csv
import json
import subprocess
import sys
import time

RPC = "https://rpc.mainnet.chain.robinhood.com"
PM = "0x8366a39CC670B4001A1121B8F6A443A643e40951"
ROUTER = "0x65050a9b7e5075a2ba5ced7b1b64ee66262c40dc"
SWAP0 = "0x40e9cecb9f5f1f1c5b9c97dec2917b7ee92e57ba5563708daca94dd84ad7112f"
ROUTER_SEL = "4d819a2a"

HEADER = ["chain_id", "pool_address", "factory_address", "token0", "token1",
          "fee_numerator", "fee_denominator", "profile", "pool_id", "source"]


def rpc(method, params, retries=6):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    for i in range(retries):
        o = subprocess.run(
            ["curl", "-s", "--max-time", "30", "-X", "POST", RPC,
             "-H", "Content-Type: application/json", "-d", body],
            capture_output=True, text=True).stdout
        try:
            d = json.loads(o)
        except json.JSONDecodeError:
            time.sleep(2 * (i + 1))
            continue
        if "error" in d:
            time.sleep(2 * (i + 1))
            continue
        return d["result"]
    raise RuntimeError(f"rpc {method} failed")


def addr(word):
    return "0x" + word[24:]


def decode_router_element(data, poolid):
    """Find poolKey bytes, back up 9 slots, read the RouterEl fields."""
    blob = data[8:]  # strip 0x + selector (caller checks selector)
    raw = bytes.fromhex(blob)
    k = bytes.fromhex(poolid[2:])
    # poolKey slot index within element is 9; element = 10 slots
    idx = raw.find(k)
    while idx >= 0:
        if (idx - 4) % 32 == 0:  # 4 = selector bytes before blob
            el = idx - 9 * 32
            if el >= 0:
                w = [raw[el + 32 * i:el + 32 * (i + 1)] for i in range(10)]
                venue = int.from_bytes(w[0], "big")
                c0, c1 = addr(w[1].hex()), addr(w[2].hex())
                fee = int.from_bytes(w[4], "big")
                spacing = int.from_bytes(w[5], "big", signed=True)
                hooks = addr(w[6].hex())
                pm = addr(w[8].hex())
                if (venue in (0, 1, 2) and pm.lower() == PM.lower()
                        and w[1][:12] == bytes(12) and w[2][:12] == bytes(12)):
                    return {"c0": c0, "c1": c1, "fee": fee,
                            "spacing": spacing, "hooks": hooks}
        idx = raw.find(k, idx + 1)
    return None


def main():
    unk_path, topn, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    cands = [r for r in csv.DictReader(open(unk_path))
             if r["venue"] == "v4"][:topn]
    tip = int(rpc("eth_blockNumber", []), 16)
    print(f"enriching top-{len(cands)} unknown v4 (tip {tip})", flush=True)
    rows, failed = [], []
    for cand in cands:
        pid = cand["id"]
        try:
            logs = rpc("eth_getLogs", [{
                "fromBlock": hex(tip - 6000), "toBlock": "latest",
                "address": PM, "topics": [SWAP0, "0x" + pid]}])
        except RuntimeError:
            failed.append(pid)
            continue
        got = None
        for log in logs[:8]:
            tx = rpc("eth_getTransactionByHash", [log["transactionHash"]])
            inp = tx.get("input", "")
            if ((tx.get("to") or "").lower() == ROUTER
                    and inp[2:10].lower() == ROUTER_SEL):
                got = decode_router_element(inp, pid)
                if got:
                    break
            time.sleep(0.3)
        if got:
            t0, t1 = sorted([got["c0"], got["c1"]],
                            key=lambda a: int(a, 16))
            rows.append({
                "chain_id": "4663", "pool_address": PM,
                "factory_address": PM, "token0": t0, "token1": t1,
                "fee_numerator": str(got["fee"]),
                "fee_denominator": "1000000", "profile": "v4",
                "pool_id": "0x" + pid, "source": "hot-txdecode"})
            print(f"  {pid[:14]}.. fee={got['fee']} spacing={got['spacing']} "
                  f"hooks={got['hooks'][:14]}..", flush=True)
        else:
            failed.append(pid)
            print(f"  {pid[:14]}.. no router tx decoded", flush=True)
    with open(out, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=HEADER)
        for r in rows:
            w.writerow(r)
    print(f"decoded {len(rows)}/{len(cands)} -> {out}; failed={len(failed)}")


if __name__ == "__main__":
    main()
