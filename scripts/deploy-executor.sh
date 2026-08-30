#!/usr/bin/env bash
# Deploy the RHC arbitrage executor — funded-caller mode (vault = address(0)).
#
# Key handling: ARBITRAGE_WALLET_PRIVATE_KEY is read from the environment; if
# unset, only the anchored assignment line is sourced from ~/.bashrc. The key
# is never printed, logged, echoed, or written to any file by this script.
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

CONTRACT="${1:-ExecutorV2}"
CONSTRUCTOR_ARGS="${2:-}"

echo "broadcasting forge create ($CONTRACT)..."

# Optional gas-price pin (legacy type-0 tx): GAS_PRICE_GWEI=0.18 scripts/deploy-executor.sh X
# Use when forge's 1559 estimate exceeds the wallet balance (RHC base fee spike).
GAS_FLAGS=()
if [[ -n "${GAS_PRICE_GWEI:-}" ]]; then
  GAS_PRICE_WEI="$(python3 -c "print(int(float('$GAS_PRICE_GWEI') * 1_000_000_000))")"
  echo "pinning gas price: $GAS_PRICE_GWEI gwei ($GAS_PRICE_WEI wei, legacy)"
  GAS_FLAGS=(--gas-price "$GAS_PRICE_WEI")
fi

if [[ -n "$CONSTRUCTOR_ARGS" ]]; then
  forge create \
    --rpc-url "$RPC_URL" \
    --private-key "$ARBITRAGE_WALLET_PRIVATE_KEY" \
    --broadcast \
    "${GAS_FLAGS[@]}" \
    --json \
    "contracts/$CONTRACT.sol:$CONTRACT" \
    --constructor-args $CONSTRUCTOR_ARGS
else
  forge create \
    --rpc-url "$RPC_URL" \
    --private-key "$ARBITRAGE_WALLET_PRIVATE_KEY" \
    --broadcast \
    "${GAS_FLAGS[@]}" \
    --json \
    "contracts/$CONTRACT.sol:$CONTRACT"
fi
