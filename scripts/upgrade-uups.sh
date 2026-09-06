#!/usr/bin/env bash
# Upgrade the UUPS proxy to a new implementation (adding a layer).
# Same proxy address forever; funds and approvals stay put.
# See docs/runbooks/uups-deploy.md §5 (nothing is deployed by saving this file).
#
# Usage: scripts/upgrade-uups.sh <PROXY_ADDRESS> <NEW_IMPL_CONTRACT>
#   e.g. scripts/upgrade-uups.sh 0xYourProxy... ExecutorV4Morpho
#
# Key handling: ARBITRAGE_WALLET_PRIVATE_KEY from env (or the anchored line in
# ~/.bashrc). Never printed, logged, echoed, or written to any file here.
set -euo pipefail

RPC_URL="https://rpc.mainnet.chain.robinhood.com"
EXPECTED_CHAIN_ID="4663"

if [[ $# -ne 2 ]]; then
  echo "usage: scripts/upgrade-uups.sh <PROXY_ADDRESS> <NEW_IMPL_CONTRACT>" >&2
  exit 1
fi
PROXY="$1"
NEW_IMPL="$2"
NEW_IMPL_PATH="contracts/$NEW_IMPL.sol"

if [[ -z "${ARBITRAGE_WALLET_PRIVATE_KEY:-}" && -f "$HOME/.bashrc" ]]; then
  # shellcheck disable=SC1090
  source <(grep -E '^[[:space:]]*(export[[:space:]]+)?ARBITRAGE_WALLET_PRIVATE_KEY=' "$HOME/.bashrc" || true)
fi

if [[ -z "${ARBITRAGE_WALLET_PRIVATE_KEY:-}" ]]; then
  echo "FATAL: ARBITRAGE_WALLET_PRIVATE_KEY is not set (add it to ~/.bashrc as 'export ARBITRAGE_WALLET_PRIVATE_KEY=0x...')" >&2
  exit 1
fi

if [[ ! -f "$NEW_IMPL_PATH" ]]; then
  echo "FATAL: $NEW_IMPL_PATH not found — write it first (storage prefix must match the current impl)" >&2
  exit 1
fi

CHAIN_ID="$(cast chain-id --rpc-url "$RPC_URL")"
if [[ "$CHAIN_ID" != "$EXPECTED_CHAIN_ID" ]]; then
  echo "FATAL: unexpected chain id $CHAIN_ID (expected $EXPECTED_CHAIN_ID)" >&2
  exit 1
fi
echo "chain id: $CHAIN_ID ok"

cd "$(dirname "$0")/.."

DEPLOYER="$(cast wallet address --private-key "$ARBITRAGE_WALLET_PRIVATE_KEY")"
OWNER="$(cast call "$PROXY" "owner()(address)" --rpc-url "$RPC_URL")"
echo "proxy:   $PROXY"
echo "owner:   $OWNER"
echo "deployer: $DEPLOYER"
if [[ "$OWNER" != "$DEPLOYER" ]]; then
  echo "FATAL: deployer is not the proxy owner — refusing to upgrade" >&2
  exit 1
fi

if [[ -z "$(cast code "$PROXY" --rpc-url "$RPC_URL" | sed 's/^0x//')" ]]; then
  echo "FATAL: no code at $PROXY on chain $CHAIN_ID" >&2
  exit 1
fi

GAS_FLAGS=()
if [[ -n "${GAS_PRICE_GWEI:-}" ]]; then
  GAS_PRICE_WEI="$(python3 -c "print(int(float('$GAS_PRICE_GWEI') * 1_000_000_000))")"
  echo "pinning gas price: $GAS_PRICE_GWEI gwei ($GAS_PRICE_WEI wei, legacy)"
  GAS_FLAGS=(--gas-price "$GAS_PRICE_WEI")
fi

echo "building + testing..."
forge build 2>&1 | tail -5
forge test --summary

echo "review storage layout diff BEFORE broadcasting (append-only, no reorder/delete):"
echo "  forge inspect <OldImpl> storage-layout | sha256sum"
echo "  forge inspect $NEW_IMPL storage-layout | sha256sum"
echo "  (compare manually; abort here with Ctrl-C if anything but appends)"

echo "deploying new implementation ($NEW_IMPL)..."
NEW_OUT="$(forge create \
  --rpc-url "$RPC_URL" \
  --private-key "$ARBITRAGE_WALLET_PRIVATE_KEY" \
  --broadcast \
  "${GAS_FLAGS[@]}" \
  --json \
  "$NEW_IMPL_PATH:$NEW_IMPL")"
NEW_ADDR="$(python3 -c "import sys,json;print(json.load(sys.stdin)['deployedTo'])" <<<"$NEW_OUT")"
echo "new implementation: $NEW_ADDR"

echo "checking proxiableUUID match..."
PROXY_UUID="$(cast call "$PROXY" "proxiableUUID()(bytes32)" --rpc-url "$RPC_URL")"
IMPL_UUID="$(cast call "$NEW_ADDR" "proxiableUUID()(bytes32)" --rpc-url "$RPC_URL")"
echo "proxy uuid: $PROXY_UUID"
echo "impl  uuid: $IMPL_UUID"
if [[ "$PROXY_UUID" != "$IMPL_UUID" ]]; then
  echo "FATAL: UUID mismatch — new impl is not compatible with this proxy" >&2
  exit 1
fi

echo "upgrading proxy to $NEW_ADDR..."
cast send "$PROXY" "upgradeToAndCall(address,bytes)" "$NEW_ADDR" 0x \
  --rpc-url "$RPC_URL" --private-key "$ARBITRAGE_WALLET_PRIVATE_KEY" "${GAS_FLAGS[@]}"

echo "verifying..."
cast call "$PROXY" "owner()(address)" --rpc-url "$RPC_URL"

BLOCK="$(cast block-number --rpc-url "$RPC_URL")"
mkdir -p deployments
IMPL_NAME="$NEW_IMPL" python3 - "$PROXY" "$NEW_ADDR" "$OWNER" "$BLOCK" <<'EOF'
import json, os, sys
proxy, impl, owner, block = sys.argv[1:5]
path = "deployments/rhc-4663.json"
hist = []
if os.path.exists(path):
    with open(path) as f:
        hist = json.load(f)
hist.append({"proxy": proxy, "implementation": impl,
             "contract": os.environ["IMPL_NAME"], "owner": owner,
             "block": int(block), "upgrade": True})
with open(path, "w") as f:
    json.dump(hist, f, indent=2)
    f.write("\n")
EOF

echo "done. proxy=$PROXY now points at $NEW_ADDR (recorded in deployments/rhc-4663.json)"
echo "next: fork-replay one V3 + one V4 leg through the PROXY, then record in STATUS.md/RESUME.md."
