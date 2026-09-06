#!/usr/bin/env bash
# Read-only token metadata (decimals/totalSupply) on RHC. No key, no broadcast.
set -euo pipefail
RPC_URL="https://rpc.mainnet.chain.robinhood.com"
for tok in "$@"; do
  echo "token $tok"
  echo -n "  decimals: "; cast call "$tok" "decimals()(uint8)" --rpc-url "$RPC_URL"
  echo -n "  symbol: "; cast call "$tok" "symbol()(string)" --rpc-url "$RPC_URL" 2>/dev/null || echo "(no symbol)"
done
