#!/usr/bin/env bash
# Wallet management for the RHC arbitrage bot.
#
# Flow model (ExecutorV2, funded-caller):
#   OWNER WALLET (0x3219E15A...)  — holds the key + all gas + input capital.
#     It is the only account that can call execute() (owner is immutable), so
#     it IS the trading account. Native-input routes send msg.value per
#     attempt — no idle capital sits in the executor.
#   EXECUTOR (0x5d1Aa3f6...)     — routes trades, accumulates profit (native
#     or ERC20 depending on the route's final asset).
#
# Money flow:
#   owner --per-attempt msg.value--> router/PM --> profit lands in executor
#   executor --rescue()--> owner          (sweep profits back)
#   owner --sweep <addr>--> cold storage  (manual, explicit)
#
# Key handling: ARBITRAGE_WALLET_PRIVATE_KEY from the environment only; if
# unset, only the anchored assignment line is sourced from ~/.bashrc. The key
# is never printed, logged, or written to any file.
set -euo pipefail

RPC_URL="https://rpc.mainnet.chain.robinhood.com"
OWNER="0x3219E15A8d1e82368340dfB6697fE6a6B41d686D"
EXECUTOR="0x5d1Aa3f67AC0Ee82FB46497deE85105C070AE93B"
NATIVE="0x0000000000000000000000000000000000000000"
# Gas reserve (wei) the wallet will never spend below when sweeping:
# ~3 rescue/fund ops at ~0.14 gwei * 100k gas each, rounded up.
GAS_RESERVE_WEI_DEFAULT=30000000000

if [[ -z "${ARBITRAGE_WALLET_PRIVATE_KEY:-}" && -f "$HOME/.bashrc" ]]; then
  # shellcheck disable=SC1090
  source <(grep -E '^[[:space:]]*(export[[:space:]]+)?ARBITRAGE_WALLET_PRIVATE_KEY=' "$HOME/.bashrc" || true)
fi

wei_to_eth() {
  cast from-wei "$1" 2>/dev/null || echo "0"
}

cmd="${1:-balance}"
case "$cmd" in
  balance)
    CHAIN="$(cast chain-id --rpc-url "$RPC_URL")"
    GP="$(cast gas-price --rpc-url "$RPC_URL")"
    OW="$(cast balance "$OWNER" --rpc-url "$RPC_URL")"
    EX="$(cast balance "$EXECUTOR" --rpc-url "$RPC_URL")"
    if [[ "$CHAIN" != "4663" ]]; then
      echo "FATAL: chain id $CHAIN != 4663" >&2
      exit 1
    fi
    echo "chain:        4663 ok"
    echo "gas price:    $GP wei ($(( GP / 1000000000 )).$(( (GP / 1000000) % 1000 )) gwei)"
    echo "owner wallet: $OW wei (~$(wei_to_eth "$OW") ETH)"
    echo "executor:     $EX wei (~$(wei_to_eth "$EX") ETH)"
    echo "combined:     $(( OW + EX )) wei (~$(wei_to_eth $(( OW + EX ))) ETH)"
    # attempts at 400k and 500k gas
    if [[ "$GP" -gt 0 ]]; then
      echo "attempts@400k gas: $(( OW / (400000 * GP) ))   @500k: $(( OW / (500000 * GP) ))"
    fi
    ;;

  fund-executor)
    # Move native working capital owner -> executor (only needed for
    # ERC20-input routes or if you want a buffer in the executor).
    AMOUNT_WEI="$(cast to-wei "$2" 2>/dev/null || echo "$2")"
    [[ -n "${ARBITRAGE_WALLET_PRIVATE_KEY:-}" ]] || { echo "FATAL: key not set" >&2; exit 1; }
    echo "sending $AMOUNT_WEI wei owner -> executor..."
    cast send "$EXECUTOR" --value "$AMOUNT_WEI" \
      --rpc-url "$RPC_URL" --private-key "$ARBITRAGE_WALLET_PRIVATE_KEY" \
      --json | python3 -c 'import json,sys; d=json.load(sys.stdin); print("tx:", d.get("transactionHash"), "status:", d.get("status"))'
    ;;

  rescue)
    # Sweep profit from the executor back to the owner. Usage:
    #   wallet.sh rescue <token|native> [amount_wei]  (default: full balance)
    TOKEN="${2:-$NATIVE}"
    if [[ "$TOKEN" == "$NATIVE" ]]; then
      BAL="$(cast balance "$EXECUTOR" --rpc-url "$RPC_URL")"
    else
      DATA="0x70a08231000000000000000000000000${EXECUTOR:2}"
      BAL="$(cast call "$TOKEN" "$DATA" --rpc-url "$RPC_URL" | python3 -c 'import sys; print(int(sys.stdin.read().strip(), 16))')"
    fi
    AMOUNT="${3:-$BAL}"
    [[ "$AMOUNT" -gt 0 ]] || { echo "executor balance is 0 — nothing to rescue"; exit 0; }
    [[ -n "${ARBITRAGE_WALLET_PRIVATE_KEY:-}" ]] || { echo "FATAL: key not set" >&2; exit 1; }
    echo "rescuing $AMOUNT wei of $TOKEN executor -> owner..."
    cast send "$EXECUTOR" "rescue(address,address,uint256)" "$TOKEN" "$OWNER" "$AMOUNT" \
      --rpc-url "$RPC_URL" --private-key "$ARBITRAGE_WALLET_PRIVATE_KEY" \
      --json | python3 -c 'import json,sys; d=json.load(sys.stdin); print("tx:", d.get("transactionHash"), "status:", d.get("status"))'
    ;;

  sweep)
    # Owner -> external address (cold storage). Explicit two-arg confirmation.
    # Usage: wallet.sh sweep <to_address> <amount_eth> <OWNER_ADDRESS_ECHOBACK>
    TO="$2"; AMOUNT="$(cast to-wei "$3" 2>/dev/null || echo "$3")"; CONFIRM="${4:-}"
    [[ "$CONFIRM" == "$OWNER" ]] || {
      echo "refusing: sweep requires echoing the owner address as the 4th arg (safety)" >&2
      echo "usage: wallet.sh sweep <to> <amount_eth> $OWNER" >&2
      exit 1
    }
    BAL="$(cast balance "$OWNER" --rpc-url "$RPC_URL")"
    RESERVE="${GAS_RESERVE_WEI:-$GAS_RESERVE_WEI_DEFAULT}"
    (( AMOUNT + RESERVE <= BAL )) || {
      echo "refusing: $AMOUNT wei + gas reserve $RESERVE exceeds balance $BAL" >&2
      exit 1
    }
    [[ -n "${ARBITRAGE_WALLET_PRIVATE_KEY:-}" ]] || { echo "FATAL: key not set" >&2; exit 1; }
    echo "sweeping $AMOUNT wei owner -> $TO (reserve $RESERVE kept)..."
    cast send "$TO" --value "$AMOUNT" \
      --rpc-url "$RPC_URL" --private-key "$ARBITRAGE_WALLET_PRIVATE_KEY" \
      --json | python3 -c 'import json,sys; d=json.load(sys.stdin); print("tx:", d.get("transactionHash"), "status:", d.get("status"))'
    ;;

  *)
    echo "usage: wallet.sh {balance|fund-executor <amount_eth>|rescue [token] [amount_wei]|sweep <to> <amount_eth> <owner>}" >&2
    exit 1
    ;;
esac
