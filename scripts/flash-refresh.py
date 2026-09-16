#!/usr/bin/env python3
"""Flash-support refresher: rebuild data/flash-support.csv from LIVE Morpho Blue inventory.

Morpho Blue's `flashLoan` (upstream Morpho.sol:422) is a plain safeTransfer
from the Blue contract's own balance — no market, no pool. A token is
flashable **iff** `balanceOf(MORPHO) > 0` right now. A static support list
rots as suppliers withdraw (2026-09-09 audit: 10 of 26 listed rows held zero),
which silently reverts every gated attempt at estimate (fail-closed, 0 gas).

This tool probes the candidate token set with one `eth_call balanceOf` per
token against the public gateway (0 CU, read-only) and writes rows only for
tokens Blue currently holds, plus a report of zero-balance candidates.

Candidate set (union):
  --tokens FILE     one 0x-address per line (e.g. anchors seen in quotes)
  --manifest CSV    pools-all/manifest CSV; token0/token1 columns join in
  --prices CSV      derive-prices output (token column)
  --existing CSV    prior flash-support.csv rows are re-checked, not trusted

Defaults write data/flash-support.csv (atomically) and print a summary.
Provider rows keep the `morpho` label (the only flash source live on RHC).

Usage:
  python3 scripts/flash-refresh.py                       # default candidates
  python3 scripts/flash-refresh.py --out /tmp/support.csv --dry-run
"""
import argparse
import csv
import json
import os
import subprocess
import sys
import time

RPC = os.environ.get(
    "FLASH_REFRESH_RPC_URL", "https://rpc.mainnet.chain.robinhood.com"
)
# Default stays the public gateway (never burns Chainstack RU by accident —
# same discipline as pool-indexer.py); export FLASH_REFRESH_RPC_URL only for
# explicit one-shot refreshes during public-gateway 429 storms.
MORPHO = "0x9D53d5E3bd5E8d4Cbfa6DB1ca238AEA02E651010"
BALANCEOF = "0x70a08231"  # keccak("balanceOf(address)")[0:4]
DECIMALS = "0x313ce567"  # keccak("decimals()")[0:4]
NATIVE_SENTINEL = "0x0000000000000000000000000000000000000000"
WRAPPED_NATIVE = "0x0bd7d308f8e1639fab988df18a8011f41eacad73"
USDG = "0x5fc5360d0400a0fd4f2af552add042d716f1d168"
HEADER = ["token", "provider"]


def rpc(method, params, retries=6):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    last = None
    for attempt in range(retries):
        out = subprocess.run(
            ["curl", "-s", "--max-time", "30", "-X", "POST", RPC,
             "-H", "Content-Type: application/json", "-d", body],
            capture_output=True, text=True).stdout
        try:
            last = json.loads(out)
        except json.JSONDecodeError:
            time.sleep(1 + attempt)
            continue
        if "error" in last:
            # A deterministic call error (e.g. code 3 revert on a non-ERC20
            # contract) is an ANSWER, not a transport failure: return it once
            # and let the caller classify. Only retry transport-level junk.
            code = last["error"].get("code")
            if code == 3:
                return last
            time.sleep(1 + attempt)
            continue
        return last.get("result")
    raise RuntimeError(f"rpc {method} failed after {retries} retries: {last}")


def eth_call_int(to, data):
    r = rpc("eth_call", [{"to": to, "data": data}, "latest"])
    if isinstance(r, dict):
        return None
    return int(r, 16) if r and r != "0x" else None


def norm(addr):
    # ABI-pad to a full 32-byte word (64 hex chars). A bare 40-char address
    # makes short calldata and every probe reverts (found 2026-09-15: all
    # 38 probes failed deterministically on two endpoints).
    return addr.strip().lower().removeprefix("0x").rjust(64, "0")


def balance_of(token):
    r = rpc("eth_call", [{"to": token, "data": BALANCEOF + norm(MORPHO)}, "latest"])
    if isinstance(r, dict) and "error" in r:
        return None  # deterministic revert: not a probeable ERC20
    return int(r, 16) if r and r != "0x" else None


def load_tokens(args):
    tokens = set()

    if args.existing and os.path.exists(args.existing):
        try:
            with open(args.existing, newline="") as f:
                for row in csv.DictReader(f):
                    t = (row.get("token") or "").strip().lower()
                    if t.startswith("0x") and len(t) == 42:
                        tokens.add(t)
        except OSError as e:
            print(f"existing read failed ({e}); continuing", file=sys.stderr)
    for path, cols in ((args.prices, ("token",)), (args.manifest, ("token0", "token1"))):
        if not path or not os.path.exists(path):
            continue
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                for col in cols:
                    t = (row.get(col) or "").strip().lower()
                    if t.startswith("0x") and len(t) == 42 and t != NATIVE_SENTINEL:
                        tokens.add(t)
    if args.tokens:
        with open(args.tokens) as f:
            for line in f:
                t = line.strip().lower()
                if t.startswith("0x") and len(t) == 42 and t != NATIVE_SENTINEL:
                    tokens.add(t)
    # Anchors quoted against wrapped native always matter; USDG is the gate floor unit.
    tokens.add(WRAPPED_NATIVE)
    tokens.add(USDG)
    return sorted(tokens)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/flash-support.csv")
    ap.add_argument("--prices", default="data/prices-live.csv")
    ap.add_argument("--manifest", default="data/manifest-hot.csv")
    ap.add_argument("--tokens", default=None, help="extra candidates, one per line")
    ap.add_argument("--existing", default=None,
                    help="prior support CSV to re-check (default: --out)")
    ap.add_argument("--min-raw-balance", type=int, default=1,
                    help="minimum balanceOf(MORPHO) raw units to list")
    ap.add_argument("--dry-run", action="store_true",
                    help="report only; do not write the output CSV")
    a = ap.parse_args()

    existing = a.existing or a.out
    tokens = load_tokens(a)
    print(f"probing {len(tokens)} candidate token(s) for Morpho Blue inventory", flush=True)

    keep, zero, failed = [], [], []
    for i, token in enumerate(tokens):
        try:
            bal = balance_of(token)
        except RuntimeError as e:
            print(f"  FAIL {token}: {e}", file=sys.stderr)
            failed.append(token)
            continue
        if bal is None:
            # Deterministic revert (non-ERC20, fee-on-transfer trap, etc.) —
            # the executor's balanceOf would revert too, so exclusion is
            # fail-closed and correct.
            failed.append(token)
            continue
        if bal >= a.min_raw_balance:
            keep.append((token, bal))
        else:
            zero.append(token)
        if (i + 1) % 25 == 0:
            print(f"  ...{i + 1}/{len(tokens)} probed", flush=True)
        time.sleep(0.15)

    print(f"\nflashable now: {len(keep)}  zero-balance: {len(zero)}  failed: {len(failed)}")
    for token, bal in sorted(keep, key=lambda kv: -kv[1]):
        print(f"  HOLD  {token}  raw={bal:,}")
    for token in zero:
        print(f"  zero  {token}")
    if failed:
        print("  failed probes are EXCLUDED (fail-closed):", ", ".join(failed[:5]),
              f"(+{len(failed) - 5} more)" if len(failed) > 5 else "")

    if a.dry_run:
        print("dry-run: no file written")
        return 0

    tmp = f"{a.out}.tmp"
    with open(tmp, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        for token, _bal in sorted(keep):
            w.writerow([token, "morpho"])
    os.replace(tmp, a.out)
    print(f"wrote {a.out} ({len(keep)} rows)")
    if failed:
        print(f"NOTE {len(failed)} probe(s) failed and were excluded; re-run to retry")
    return 0


if __name__ == "__main__":
    sys.exit(main())
