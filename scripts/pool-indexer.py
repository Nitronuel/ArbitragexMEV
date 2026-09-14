#!/usr/bin/env python3
"""Rolling pool indexer: frontier pool discovery while detection runs.

Polls pool-creation events (V4 Initialize, V3/V2/Up PoolCreated/PairCreated)
on the PUBLIC gateway and appends new pools to per-venue `-inc` catalogs.
Self-maintaining (2026-09-11): --merge-every ticks folds unmerged `-inc`
tails into the base catalogs, the union, and v4 overrides (append-only,
union semantics — live files are never rewritten or shrunk), and
--hot-refresh-every ticks union-promotes a fresh hot-flow candidate
(add-only) into the live manifest, so discoveries reach detection
with no manual merge. Never reads provider env vars, so detection
(Chainstack) and execution are unaffected.

Creation events carry the full pool key — no archive history needed.

Usage:
  python3 scripts/pool-indexer.py [--ticks N] [--window W] [--cadence S]
      [--checkpoint PATH]
  --ticks 0 = run forever (default). --ticks N = exit after N ticks (dry-run).

State: data/index-checkpoint.json {venue: last_swept_block}, atomic write.
Outputs: data/pools-{v2,v3,v4,up}-inc.csv (catalog schema, source=indexer-rolling).
Logs: one line per tick on stdout (caller redirects to logs/live/pool-indexer.log).
"""
import argparse
import csv
import json
import os
import subprocess
import sys
import time

# PUBLIC gateway only — hardcoded so this can never consume Chainstack RU
# or provider keys. Same pattern as hot-pools.py / enrich-v4-hot.py.
RPC = "https://rpc.mainnet.chain.robinhood.com"

PM = "0x8366a39CC670B4001A1121B8F6A443A643e40951"
V3_FACTORY = "0x1f7d7550B1b028f7571E69A784071F0205FD2EfA"
V2_FACTORY = "0x8bcEaA40B9AcdfAedF85AdF4FF01F5Ad6517937f"
UP_FACTORY = "0x1ac9dB4a2608ba45D6127B1737949b51Bb54B7F3"

# topic0 pinned in crates/provider/src/events.rs (keccak-verified tests).
T_V4_INIT = "0xdd466e674ea557f56295e2d0218a125ea4b4f0f6f3307b95f85e6110838d6438"
T_V3_CREATED = "0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118"
T_V2_CREATED = "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9"
T_UP_CREATED = "0xab0d57f0df537bb25e80245ef7748fa62353808c54d6e528a9dd20887aed9ac2"

HEADER = ["chain_id", "pool_address", "factory_address", "token0", "token1",
          "fee_numerator", "fee_denominator", "profile", "pool_id", "source"]

VENUES = [
    # (name, address, topic0, profile, out_file)
    ("v4", PM, T_V4_INIT, "v4", "data/pools-v4-inc.csv"),
    ("v3", V3_FACTORY, T_V3_CREATED, "v3", "data/pools-v3-inc.csv"),
    ("v2", V2_FACTORY, T_V2_CREATED, "v2", "data/pools-v2-inc.csv"),
    ("up", UP_FACTORY, T_UP_CREATED, "up", "data/pools-up-inc.csv"),
]


def log(msg):
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} pool-indexer: {msg}",
          flush=True)


def rpc(method, params, retries=8):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    last = None
    for attempt in range(retries):
        try:
            out = subprocess.run(
                ["curl", "-s", "--max-time", "60", "-X", "POST", RPC,
                 "-H", "Content-Type: application/json", "-d", body],
                capture_output=True, text=True).stdout
            last = json.loads(out)
        except (json.JSONDecodeError, subprocess.SubprocessError):
            time.sleep(2 * (attempt + 1))
            continue
        if "error" in last:
            time.sleep(2 * (attempt + 1))
            continue
        return last["result"]
    raise RuntimeError(f"rpc {method} failed after {retries} retries: {last}")


def checksum(addr):
    """EIP-55 checksum (manifest parser rejects miscased rows)."""
    out = subprocess.run(["cast", "--to-checksum-address", addr],
                         capture_output=True, text=True).stdout.strip()
    if not out:
        raise RuntimeError(f"checksum failed for {addr}")
    return out


def word_addr(word):
    return "0x" + word[-40:]


def decode_v4(log):
    t = log["topics"]
    d = bytes.fromhex(log["data"][2:])
    w = [d[i * 32:(i + 1) * 32] for i in range(5)]
    return {
        "pool": PM,
        "t0": word_addr(t[2][2:]),
        "t1": word_addr(t[3][2:]),
        "fee": str(int.from_bytes(w[0], "big")),
        "tick_spacing": str(int.from_bytes(w[1], "big", signed=True)),
        "hooks": word_addr(w[2].hex()),
        "pool_id": t[1],
    }


def decode_v3(log):
    t = log["topics"]
    d = bytes.fromhex(log["data"][2:])
    return {
        "pool": word_addr(d[1 * 32:2 * 32].hex()),
        "t0": word_addr(t[1][2:]),
        "t1": word_addr(t[2][2:]),
        "fee": str(int.from_bytes(bytes.fromhex(t[3][2:]), "big")),
    }


def decode_v2(log):
    t = log["topics"]
    d = bytes.fromhex(log["data"][2:])
    return {
        "pool": word_addr(d[0:32].hex()),
        "t0": word_addr(t[1][2:]),
        "t1": word_addr(t[2][2:]),
        "fee": "3000",
    }


def decode_up(log):
    t = log["topics"]
    d = bytes.fromhex(log["data"][2:])
    return {
        "pool": word_addr(d[0:32].hex()),
        "t0": word_addr(t[1][2:]),
        "t1": word_addr(t[2][2:]),
        "fee": str(int.from_bytes(bytes.fromhex(t[3][2:]), "big")),
    }


DECODERS = {"v4": decode_v4, "v3": decode_v3, "v2": decode_v2, "up": decode_up}
FACTORY_OF = {"v4": PM, "v3": V3_FACTORY, "v2": V2_FACTORY, "up": UP_FACTORY}


def load_known():
    """Pool keys already cataloged (pool_id for v4, pool address otherwise).

    Includes the rolling `-inc` files themselves so a restart never
    re-appends pools a previous run already wrote (dupes observed 2026-09-10
    before this guard: 5/72 re-added across restarts).
    """
    known = set()

    def ingest(path):
        try:
            f = open(path)
        except FileNotFoundError:
            return
        with f:
            for r in csv.DictReader(f):
                if not r.get("pool_id") and not r.get("pool_address"):
                    continue
                if r.get("profile") == "v4" and r.get("pool_id"):
                    known.add(("v4", r["pool_id"].lower()))
                elif r.get("pool_address"):
                    known.add((r.get("profile", ""), r["pool_address"].lower()))

    ingest("data/pools-all.csv")
    for v in ("v2", "v3", "v4", "up"):
        ingest(f"data/pools-{v}-inc.csv")
    return known


def load_checkpoint(path, tip):
    try:
        with open(path) as f:
            ck = json.load(f)
        return {v[0]: int(ck.get(v[0], tip)) for v in VENUES}
    except (FileNotFoundError, ValueError, KeyError):
        return {v[0]: tip for v in VENUES}


def save_checkpoint(path, ck):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(ck, f)
    os.replace(tmp, path)


def ensure_header(path, header=HEADER):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        with open(path, "w", newline="") as f:
            csv.writer(f).writerow(header)


# Merge/promote map: rolling -inc file -> base catalog it feeds.
# hot-pools.py reads ONLY the base catalogs, so without this merge the
# indexer could never contribute to the hot manifest (gap found 2026-09-11).
MERGE_MAP = [
    ("data/pools-v4-inc.csv", "data/pools-rhc-v4.csv"),
    ("data/pools-v3-inc.csv", "data/pools-rhc-v3.csv"),
    ("data/pools-v2-inc.csv", "data/pools-rhc-v2.csv"),
    ("data/pools-up-inc.csv", "data/pools-rhc-up.csv"),
]
POOLS_ALL = "data/pools-all.csv"
OVERRIDES = "data/v4-overrides.csv"
OVERRIDES_INC = "data/v4-overrides-inc.csv"


def merge_key(row):
    prof = (row.get("profile") or "").strip()
    if prof == "v4" and row.get("pool_id"):
        return ("v4", row["pool_id"].strip().lower())
    if row.get("pool_address"):
        return (prof, row["pool_address"].strip().lower())
    return None


def read_data_rows(path):
    try:
        with open(path, newline="") as f:
            return list(csv.DictReader(f))
    except FileNotFoundError:
        return []


def merge_inc_files(known, offsets):
    """Fold unmerged -inc tails into base catalogs + pools-all.csv.

    Append-only (crash-safe order: pools-all first, then base), union
    semantics — never rewrites or shrinks a live file. Rows whose key is
    already in `known` (pools-all ∪ inc) are skipped, so earlier manual
    merges never produce dupes. Returns (appended_by_file, new_offsets).
    """
    appended, new_offsets = {}, dict(offsets)
    for inc, base in MERGE_MAP:
        rows = read_data_rows(inc)
        start = min(new_offsets.get(inc, 0), len(rows))
        fresh = []
        for r in rows[start:]:
            k = merge_key(r)
            if k is None or k in known:
                continue
            fresh.append(r)
            known.add(k)
        if fresh:
            all_rows = [[r.get(c, "") for c in HEADER] + [""] for r in fresh]
            with open(POOLS_ALL, "a", newline="") as f:
                csv.writer(f).writerows(all_rows)
            base_rows = [[r.get(c, "") for c in HEADER] for r in fresh]
            with open(base, "a", newline="") as f:
                csv.writer(f).writerows(base_rows)
        appended[inc] = len(fresh)
        new_offsets[inc] = len(rows)
    return appended, new_offsets


def load_override_keys():
    keys = set()
    for r in read_data_rows(OVERRIDES):
        pid = (r.get("pool_id") or "").strip().lower()
        if pid:
            keys.add(pid)
    return keys


def merge_overrides_inc(ov_known, offset):
    """Fold unmerged v4-overrides-inc tail into v4-overrides.csv (append-only)."""
    rows = read_data_rows(OVERRIDES_INC)
    start = min(offset, len(rows))
    fresh = []
    for r in rows[start:]:
        pid = (r.get("pool_id") or "").strip().lower()
        if not pid or pid in ov_known:
            continue
        fresh.append(r)
        ov_known.add(pid)
    if fresh:
        with open(OVERRIDES, "a", newline="") as f:
            csv.writer(f).writerows(
                [[r.get("pool_id", ""), r.get("tick_spacing", ""),
                  r.get("hooks", "")] for r in fresh])
    return len(fresh), len(rows)


def promote_hot(candidate, live):
    """Union-promote hot-candidate rows into the live manifest (add-only).

    Never shrinks or rewrites the live file: candidate rows whose key
    (pool_id for v4, pool address otherwise) already exists are skipped.
    Refuses to create the live file if missing. Returns
    (promoted, candidate_rows, live_total).
    """
    if not os.path.exists(live):
        raise RuntimeError(f"live manifest missing, refusing to create: {live}")
    keys = set()
    for r in read_data_rows(live):
        k = merge_key(r)
        if k:
            keys.add(k)
    cand = read_data_rows(candidate)
    fresh = [r for r in cand if merge_key(r) and merge_key(r) not in keys]
    if fresh:
        with open(live, "a", newline="") as f:
            csv.writer(f).writerows(
                [[r.get(c, "") for c in HEADER] for r in fresh])
    return len(fresh), len(cand), sum(1 for _ in read_data_rows(live))


def run_hot_refresh(live):
    """Build a hot-flow candidate and union-promote it into the live manifest.

    Fail-closed: a nonzero hot-pools exit leaves every live file untouched.
    """
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    cand = f"data/manifest-hot-auto-{ts}.csv"
    unk = f"data/hot-unknown-auto-{ts}.csv"
    try:
        p = subprocess.run(
            [sys.executable, "scripts/hot-pools.py",
             "--out", cand, "--unknown", unk],
            capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        log("hot-refresh FAILED: hot-pools.py timed out after 3600s, live untouched")
        return
    if p.returncode != 0:
        tail = (p.stdout + p.stderr).strip().splitlines()[-3:]
        log(f"hot-refresh FAILED rc={p.returncode} ({' | '.join(tail)}), live untouched")
        return
    try:
        promoted, n_cand, total = promote_hot(cand, live)
        log(f"hot-refresh ok candidate={n_cand} promoted={promoted} live={total} ({cand})")
    except (OSError, RuntimeError) as e:
        log(f"hot-refresh promote refused: {e}")


def sweep_venue(name, address, topic, start, end):
    return rpc("eth_getLogs", [{
        "fromBlock": hex(start), "toBlock": hex(end),
        "address": address, "topics": [topic]}])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ticks", type=int, default=0)
    ap.add_argument("--window", type=int, default=1000)
    ap.add_argument("--cadence", type=int, default=60)
    ap.add_argument("--checkpoint", default="data/index-checkpoint.json")
    ap.add_argument("--merge-every", type=int, default=30,
                    help="fold -inc tails into base catalogs every N ticks (0=off)")
    ap.add_argument("--hot-refresh-every", type=int, default=0,
                    help="union-promote a fresh hot candidate every N ticks (0=off; "
                         "default off: manifest swaps stay operator-gated per "
                         "2026-09-10 ruling — enable explicitly to override)")
    ap.add_argument("--live-manifest", default="data/manifest-hot.csv")
    args = ap.parse_args()

    log(f"start endpoint=public-rhc window={args.window} cadence={args.cadence}s ticks={'inf' if args.ticks == 0 else args.ticks}")
    known = load_known()
    log(f"catalog keys loaded: {len(known)}")
    for _, _, _, _, out in VENUES:
        ensure_header(out)
    ensure_header("data/v4-overrides-inc.csv", ["pool_id", "tick_spacing", "hooks"])

    tip = int(rpc("eth_blockNumber", []), 16)
    ck = load_checkpoint(args.checkpoint, tip)
    # First run with no checkpoint starts at tip (frontier only, no backfill).
    try:
        with open(args.checkpoint) as f:
            raw_ck = json.load(f)
    except (FileNotFoundError, ValueError):
        raw_ck = {}
    merged = raw_ck.get("merged", {}) if isinstance(raw_ck.get("merged", {}), dict) else {}
    try:
        merged_ov = int(raw_ck.get("merged_ov", 0))
    except (TypeError, ValueError):
        merged_ov = 0
    ck["merged"] = merged
    ck["merged_ov"] = merged_ov
    save_checkpoint(args.checkpoint, ck)

    done = 0
    while True:
        tip = int(rpc("eth_blockNumber", []), 16)
        summary = []
        for name, address, topic, profile, out in VENUES:
            start = max(ck[name] - 200, 0)  # overlap: reorg-safe, deduped
            end = min(start + args.window, tip)
            if end <= ck[name]:
                summary.append(f"{name}:0")
                continue
            try:
                logs = sweep_venue(name, address, topic, start, end)
            except RuntimeError as e:
                log(f"{name} [{start},{end}] rpc failed, checkpoint frozen: {e}")
                summary.append(f"{name}:ERR")
                continue
            added = 0
            rows = []
            ov_rows = []
            for lg in logs:
                try:
                    d = DECODERS[name](lg)
                except (IndexError, ValueError):
                    continue
                key = ("v4", d.get("pool_id", "").lower()) if name == "v4" \
                    else (profile, d["pool"].lower())
                if key[1] in ("", "0x" + "0" * 40) or key in known:
                    continue
                try:
                    t0 = checksum(d["t0"])
                    t1 = checksum(d["t1"])
                    pool = checksum(d["pool"])
                    fac = checksum(address)
                except RuntimeError:
                    continue
                pid = d.get("pool_id", "")
                rows.append(["4663", pool, fac, t0, t1, d["fee"],
                             "1000000", profile, pid, "indexer-rolling"])
                if name == "v4":
                    ov_rows.append([pid.lower(), d["tick_spacing"],
                                    checksum(d["hooks"])])
                known.add(key)
                added += 1
            if rows:
                with open(out, "a", newline="") as f:
                    csv.writer(f).writerows(rows)
            if ov_rows:
                with open("data/v4-overrides-inc.csv", "a", newline="") as f:
                    csv.writer(f).writerows(ov_rows)
            ck[name] = end
            summary.append(f"{name}:{added}")
        if args.merge_every and (done == 0 or (done + 1) % args.merge_every == 0):
            try:
                app, merged = merge_inc_files(known, merged)
                ov_n, merged_ov = merge_overrides_inc(load_override_keys(), merged_ov)
                ck["merged"] = merged
                ck["merged_ov"] = merged_ov
                total = sum(app.values())
                if total or ov_n:
                    detail = " ".join(f"{k.split('-')[1]}:+{v}" for k, v in app.items() if v)
                    log(f"merge: +{total} pools {detail} +{ov_n} overrides")
            except OSError as e:
                log(f"merge FAILED, offsets frozen: {e}")
        if args.hot_refresh_every and (done + 1) % args.hot_refresh_every == 0:
            run_hot_refresh(args.live_manifest)
        save_checkpoint(args.checkpoint, ck)
        log(f"tip={tip} swept={' '.join(summary)}")
        done += 1
        if args.ticks and done >= args.ticks:
            log(f"tick limit {args.ticks} reached, exiting")
            return
        time.sleep(args.cadence)


if __name__ == "__main__":
    main()
