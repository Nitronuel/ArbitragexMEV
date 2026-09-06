#!/usr/bin/env bash
# Day-0 UUPS deploy for the RHC arbitrage executor (instructions saved, run later).
#
# Deploys the implementation, then an ERC1967Proxy pointing at it. The PROXY
# address is permanent; all future layers go through scripts/upgrade-uups.sh.
# See docs/runbooks/uups-deploy.md (nothing is deployed by saving this file).
#
# Usage: scripts/deploy-uups.sh [IMPL_CONTRACT] [OWNER_ADDRESS]
#   IMPL_CONTRACT default: ExecutorUUPS (must exist under contracts/)
#   OWNER_ADDRESS default: deployer address derived from the private key
#
# Key handling: ARBITRAGE_WALLET_PRIVATE_KEY from env (or the anchored line in
# ~/.bashrc). Never printed, logged, echoed, or written to any file here.
set -euo pipefail

RPC_URL="https://rpc.mainnet.chain.robinhood.com"
EXPECTED_CHAIN_ID="4663"

if [[ -z "${ARBITRAGE_WALLET_PRIVATE_KEY:-}" && -f "$HOME/.bashrc" ]]; then
  # shellcheck disable=SC1090
  source <(grep -E '^[[:space:]]*(export[[:space:]]+)?ARBITRAGE_WALLET_PRIVATE_KEY=' "$HOME/.bashrc" || true)
fi

if [[ -z "${ARBITRAGE_WALLET_PRIVATE_KEY:-}" ]]; then
  echo "FATAL: ARBITRAGE_WALLET_PRIVATE_KEY is not set (add it to ~/.bashrc as 'export ARBITRAGE_WALLET_PRIVATE_KEY=0x...')" >&2
  exit 1
fi

CHAIN_ID="$(cast chain-id --rpc-url "$RPC_URL")"
if [[ "$CHAIN_ID" != "$EXPECTED_CHAIN_ID" ]]; then
  echo "FATAL: unexpected chain id $CHAIN_ID (expected $EXPECTED_CHAIN_ID)" >&2
  exit 1
fi
echo "chain id: $CHAIN_ID ok"

DEPLOYER="$(cast wallet address --private-key "$ARBITRAGE_WALLET_PRIVATE_KEY")"
echo "deployer: $DEPLOYER"

BAL_WEI="$(cast balance "$DEPLOYER" --rpc-url "$RPC_URL")"
BAL_ETH="$(cast from-wei "$BAL_WEI")"
echo "deployer balance: $BAL_WEI wei ($BAL_ETH ETH)"
if [[ "$BAL_WEI" == "0" ]]; then
  echo "FATAL: deployer has zero balance — fund $DEPLOYER on RHC first" >&2
  exit 1
fi

cd "$(dirname "$0")/.."

IMPL="${1:-ExecutorUUPS}"
OWNER="${2:-$DEPLOYER}"
IMPL_PATH="contracts/$IMPL.sol"
if [[ ! -f "$IMPL_PATH" ]]; then
  echo "FATAL: $IMPL_PATH not found — write it first (see docs/runbooks/uups-deploy.md §3)" >&2
  exit 1
fi

GAS_FLAGS=()
if [[ -n "${GAS_PRICE_GWEI:-}" ]]; then
  GAS_PRICE_WEI="$(python3 -c "print(int(float('$GAS_PRICE_GWEI') * 1_000_000_000))")"
  echo "pinning gas price: $GAS_PRICE_GWEI gwei ($GAS_PRICE_WEI wei, legacy)"
  GAS_FLAGS=(--gas-price "$GAS_PRICE_WEI")
fi

echo "building..."
forge build 2>&1 | tail -5

echo "deploying implementation ($IMPL)..."
IMPL_OUT="$(forge create \
  --rpc-url "$RPC_URL" \
  --private-key "$ARBITRAGE_WALLET_PRIVATE_KEY" \
  --broadcast \
  "${GAS_FLAGS[@]}" \
  --json \
  "$IMPL_PATH:$IMPL")"
IMPL_ADDR="$(python3 -c "import sys,json;print(json.load(sys.stdin)['deployedTo'])" <<<"$IMPL_OUT")"
echo "implementation: $IMPL_ADDR"

INIT_DATA="$(cast calldata "initialize(address)" "$OWNER")"
echo "deploying ERC1967Proxy..."
PROXY_OUT="$(forge create \
  --rpc-url "$RPC_URL" \
  --private-key "$ARBITRAGE_WALLET_PRIVATE_KEY" \
  --broadcast \
  "${GAS_FLAGS[@]}" \
  --json \
  "node_modules/@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy" \
  --constructor-args "$IMPL_ADDR" "$INIT_DATA")"
PROXY_ADDR="$(python3 -c "import sys,json;print(json.load(sys.stdin)['deployedTo'])" <<<"$PROXY_OUT")"
echo "proxy (PERMANENT): $PROXY_ADDR"

echo "verifying through proxy..."
cast call "$PROXY_ADDR" "owner()(address)" --rpc-url "$RPC_URL"
# NOTE: proxiableUUID() carries OZ v5's notDelegated guard — it MUST be called
# on the implementation directly (calling it through the proxy reverts by
# design, ERC-1822). The proxy side is checked via its ERC1967 slot instead.
cast call "$IMPL_ADDR" "proxiableUUID()(bytes32)" --rpc-url "$RPC_URL"
cast storage "$PROXY_ADDR" \
  0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc \
  --rpc-url "$RPC_URL" # expect the implementation address

BLOCK="$(cast block-number --rpc-url "$RPC_URL")"
mkdir -p deployments
IMPL_NAME="$IMPL" python3 - "$PROXY_ADDR" "$IMPL_ADDR" "$OWNER" "$BLOCK" <<'EOF'
import json, os, sys
proxy, impl, owner, block = sys.argv[1:5]
path = "deployments/rhc-4663.json"
hist = []
if os.path.exists(path):
    with open(path) as f:
        hist = json.load(f)
hist.append({"proxy": proxy, "implementation": impl,
             "contract": os.environ["IMPL_NAME"], "owner": owner,
             "block": int(block)})
with open(path, "w") as f:
    json.dump(hist, f, indent=2)
    f.write("\n")
EOF

echo "done. proxy=$PROXY_ADDR impl=$IMPL_ADDR (recorded in deployments/rhc-4663.json)"
echo "next: fund float + approve routers FROM THE PROXY, point bot config at the proxy."
