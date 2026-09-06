#!/usr/bin/env bash
# Post-deploy verification for the UUPS proxy (read-only).
# Usage: scripts/verify-uups.sh <PROXY> <IMPL>
set -euo pipefail
PROXY="${1:?proxy address}"; IMPL="${2:?impl address}"
RPC_URL="https://rpc.mainnet.chain.robinhood.com"
echo "chain: $(cast chain-id --rpc-url "$RPC_URL") (expect 4663)"
echo "impl code bytes: $(cast code "$IMPL" --rpc-url "$RPC_URL" | wc -c)"
echo "proxy code bytes: $(cast code "$PROXY" --rpc-url "$RPC_URL" | wc -c)"
echo "proxiableUUID (on IMPL, direct call):"
cast call "$IMPL" "proxiableUUID()(bytes32)" --rpc-url "$RPC_URL"
echo "ERC1967 implementation slot (on PROXY, expect impl address):"
cast storage "$PROXY" 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url "$RPC_URL"
echo "owner (via PROXY):"
cast call "$PROXY" "owner()(address)" --rpc-url "$RPC_URL"
echo "MORPHO (via PROXY):"
cast call "$PROXY" "MORPHO()(address)" --rpc-url "$RPC_URL"
