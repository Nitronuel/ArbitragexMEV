#!/usr/bin/env bash
# Read-only: probe RHC PoolManager pool state via extsload across candidate
# mapping slots 0..15. An initialized pool shows sqrtPriceX96 in (2^32, 2^192)
# with a small tick at the base slot. No key, no broadcast.
# Usage: scripts/pool-state.sh <poolId>
set -euo pipefail
RPC_URL="https://rpc.mainnet.chain.robinhood.com"
PM="0x8366a39CC670B4001A1121B8F6A443A643e40951"
POOLID="${1:?poolId hex}"
PID="${POOLID#0x}"
EXTSEL=$(cast keccak "extsload(bytes32)" | cut -c1-10)
python3 - "$PID" "$EXTSEL" "$PM" "$RPC_URL" <<'EOF'
import json, subprocess, sys
pid, extsel, pm, rpc = sys.argv[1:5]
def keccak_preimage(hexdata):
    out = subprocess.run(["cast", "keccak", "0x" + hexdata],
                         capture_output=True, text=True).stdout.strip()
    return out
def extsload(slot_hex):
    cd = extsel + slot_hex[2:].rjust(64, "0")
    out = subprocess.run(
        ["cast", "call", pm, cd, "--rpc-url", rpc],
        capture_output=True, text=True).stdout.strip()
    return out
for s in range(16):
    base = keccak_preimage(pid + format(s, "064x"))
    v = extsload(base)
    try:
        n = int(v, 16)
    except ValueError:
        print(f"mapslot {s}: rpc-error {v[:80]}"); continue
    sqrt = n & (2**160 - 1)
    tick = (n >> 160) & 0xFFFFFF
    if tick >= 2**23:
        tick -= 2**24
    sane = (2**32 < sqrt < 2**192) and abs(tick) < 887272
    # liquidity lives at base+3 in standard v4 layout
    liq = None
    if sane:
        lv = extsload(hex(int(base, 16) + 3))
        try:
            liq = int(lv, 16) & (2**128 - 1)
        except ValueError:
            liq = -1
    print(f"mapslot {s}: sqrtPriceX96={sqrt} tick={tick} "
          f"liquidity={liq} {'<== INITIALIZED' if sane and liq else ''}")
EOF
