#!/usr/bin/env python3
"""Backfill V4 tickSpacing/hooks overrides from Blockscout Initialize events.

Usage: scripts/backfill-overrides.py pool_ids.txt [--out data/v4-overrides.csv]
       scripts/backfill-overrides.py pool_ids.txt --catalog-out new-v4.csv

Reads pool_ids (one 0x-prefixed poolId per line), fetches each pool's
Initialize log from the Blockscout PRO API (full history — the path that
is archive-walled on free RPCs), decodes fee/tickSpacing/hooks, and
appends missing rows (dedup by pool_id). Read-only against the chain;
only appends to local files (union semantics).

--catalog-out PATH: additionally write catalog-schema rows
(chain_id,pool_address,factory_address,token0,token1,fee_numerator,
fee_denominator,profile,pool_id,source). Currencies come from Initialize
topics 1-2, so unknown V4 pools are fully enriched by the same fetch.

Needs BLOCKSCOUT_API_KEY in env (see $HOME/.bashrc; never in the repo).
Paced at 2 req/s to respect free-tier limits.
"""
import csv
import json
import os
import re
import subprocess
import sys
import time

PM = "0x8366a39CC670B4001A1121B8F6A443A643e40951"
INIT_TOPIC = "0xdd466e674ea557f56295e2d0218a125ea4b4f0f6f3307b95f85e6110838d6438"
API = "https://api.blockscout.com/4663/api"
PID_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")


def checksum(addr):
    """EIP-55 checksum via cast (manifest parser rejects miscased rows)."""
    out = subprocess.run(["cast", "--to-checksum-address", addr],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"checksum failed for {addr}")
    return out.stdout.strip()


def api_key():
    key = os.environ.get("BLOCKSCOUT_API_KEY", "")
    if not key:
        # Non-interactive shells skip .bashrc guards; read the export directly.
        try:
            with open(os.path.expanduser("~/.bashrc")) as f:
                for line in f:
                    m = re.search(r"BLOCKSCOUT_API_KEY=['\"]?([^'\"\s]+)['\"]?", line)
                    if m:
                        key = m.group(1)
                        break
        except FileNotFoundError:
            pass
    if not key:
        sys.exit("FATAL: BLOCKSCOUT_API_KEY not set")
    return key


def get_initialize(key, pid):
    url = (
        f"{API}?module=logs&action=getLogs&fromBlock=0&toBlock=latest"
        f"&address={PM}&topic0={INIT_TOPIC}&topic0_1_opr=and&topic1={pid}"
        f"&apikey={key}"
    )
    out = subprocess.run(
        ["curl", "-s", "--max-time", "60", url],
        capture_output=True, text=True,
    ).stdout
    try:
        res = json.loads(out).get("result") or []
    except ValueError:
        return None
    return res[0] if res else None


def decode_init(log):
    data = (log.get("data") or "")[2:]
    words = [data[i:i + 64] for i in range(0, len(data), 64)]
    if len(words) < 5:
        return None
    fee = int(words[0], 16)
    spacing = int(words[1], 16)
    if spacing >= 1 << 23:  # int24 two's complement
        spacing -= 1 << 24
    hooks = "0x" + words[2][-40:]
    topics = log.get("topics") or []
    c0 = "0x" + topics[1][-40:] if len(topics) > 1 else ""
    c1 = "0x" + topics[2][-40:] if len(topics) > 2 else ""
    return fee, spacing, hooks, c0, c1


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit("usage: backfill-overrides.py pool_ids.txt [--out PATH] [--catalog-out PATH]")
    ids_path = args[0]
    out_path = "data/v4-overrides.csv"
    cat_path = None
    i = 1
    while i < len(args):
        if args[i] == "--out" and i + 1 < len(args):
            out_path = args[i + 1]
            i += 2
        elif args[i] == "--catalog-out" and i + 1 < len(args):
            cat_path = args[i + 1]
            i += 2
        else:
            sys.exit(f"unknown arg {args[i]}")
    key = api_key()
    have = set()
    try:
        for r in csv.DictReader(open(out_path)):
            pid = (r.get("pool_id") or "").strip().lower()
            if pid:
                have.add(pid)
    except FileNotFoundError:
        pass
    want = []
    for line in open(ids_path):
        pid = line.strip()
        if PID_RE.match(pid) and pid.lower() not in have:
            want.append(pid)
            have.add(pid.lower())
    print(f"backfill: {len(want)} pools to fetch -> {out_path}", flush=True)
    cat_f = open(cat_path, "a", newline="") if cat_path else None
    cat_w = csv.writer(cat_f) if cat_f else None
    if cat_f and os.path.getsize(cat_path) == 0:
        cat_w.writerow(["chain_id", "pool_address", "factory_address", "token0",
                        "token1", "fee_numerator", "fee_denominator", "profile",
                        "pool_id", "source"])
    done = 0
    with open(out_path, "a", newline="") as f:
        w = csv.writer(f)
        for i, pid in enumerate(want):
            log = get_initialize(key, pid)
            if log is None:
                print(f"backfill: NO Initialize for {pid}", flush=True)
            else:
                dec = decode_init(log)
                if dec is None:
                    print(f"backfill: UNDECODABLE Initialize for {pid}", flush=True)
                else:
                    fee, spacing, hooks, c0, c1 = dec
                    w.writerow([pid, spacing, hooks])
                    f.flush()
                    done += 1
                    if cat_w and c0 and c1:
                        t0, t1 = checksum(c0), checksum(c1)
                        lo, hi = (t0, t1) if t0.lower() < t1.lower() else (t1, t0)
                        cat_w.writerow(
                            ["4663", PM, PM, lo, hi, fee, 1000000,
                             "v4", pid, "backfill-init"])
                        cat_f.flush()
            if (i + 1) % 50 == 0:
                print(f"backfill: {i + 1}/{len(want)} done={done}", flush=True)
            time.sleep(0.5)
    if cat_f:
        cat_f.close()
    print(f"backfill: DONE fetched={done}/{len(want)}", flush=True)


if __name__ == "__main__":
    main()
