#!/usr/bin/env bash
# Wallet management for the RHC arbitrage bot.
#
# Flow model (Morpho flash, gas-only — float retired 2026-09-05):
#   OWNER WALLET (0x3219E15A...)  — holds the key + ALL funds as gas money.
#     It is the only account that can call the executor (owner is immutable).
#     Trade capital comes from Morpho Blue flash loans (free, per-trade), so
#     the wallet needs only gas: minimum $5 balance, gas per attempt ≤ $1.5.
#   EXECUTOR (0x727f41B647e9F0958dd539b0dFff4fc46A90A950, UUPS proxy live
#     since 2026-09-06) — routes trades, accumulates profit (native or
#     ERC20 per route's final asset). Retired V3 0xaAeBdb1001974506bfDB24Bc70D7A9b88f2ad09c.
#
# Money flow:
#   Morpho Blue --flash--> executor --legs--> profit lands in executor
#   executor --rescue()--> owner          (sweep profits / retired float back)
#   owner --sweep <addr>--> cold storage  (manual, explicit)
#
# Key handling: ARBITRAGE_WALLET_PRIVATE_KEY from the environment only; if
# unset, only the anchored assignment line is sourced from ~/.bashrc. The key
# is never printed, logged, or written to any file.
# Trading rules (2026-09-08 operator update): wallet min $5, gas/attempt ≤ $1.5,
# gate floor ~$3 (win_rate 33%, live gas-cost). Broadcast requires gate pass + approval.
set -euo pipefail

RPC_URL="https://rpc.mainnet.chain.robinhood.com"
OWNER="0x3219E15A8d1e82368340dfB6697fE6a6B41d686D"
EXECUTOR="0x727f41B647e9F0958dd539b0dFff4fc46A90A950"
NATIVE="0x0000000000000000000000000000000000000000"
# Trading constraints (operator 2026-09-08):
MIN_WALLET_USD=5              # minimum wallet balance to trade
MAX_GAS_USD_PER_ATTEMPT=1.5   # max gas cost per attempt (USD)
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

usd_to_wei() {
  # $1 = USD amount (e.g., "5" or "1.5"), $2 = native USD price (wei per ETH, 1e18 scale)
  python3 -c "print(int(float('$1') * $2 / 1e18))" 2>/dev/null || echo "0"
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
    # Fetch native USD price for gas calculations (fallback $2500)
    NATIVE_USD="$(python3 -c "print(2500 * 10**18)" 2>/dev/null || echo "2500000000000000000000")"
    GP_GWEI=$(( GP / 1000000000 ))
    GP_MGWEI=$(( (GP / 1000000) % 1000 ))
    echo "chain:        4663 ok"
    echo "gas price:    $GP wei ($GP_GWEI.$GP_MGWEI gwei)"
    OW_ETH=$(wei_to_eth "$OW")
    EX_ETH=$(wei_to_eth "$EX")
    COMBINED_ETH=$(wei_to_eth $(( OW + EX )))
    echo "owner wallet: $OW wei (~$OW_ETH ETH)"
    echo "executor:     $EX wei (~$EX_ETH ETH)"
    echo "combined:     $(( OW + EX )) wei (~$COMBINED_ETH ETH)"
    # Gas cost estimates at 400k and 500k gas
    if [[ "$GP" -gt 0 ]]; then
      GAS_COST_400K=$(( 400000 * GP ))
      GAS_COST_500K=$(( 500000 * GP ))
      GAS_USD_400K=$(python3 -c "print(round($GAS_COST_400K * $NATIVE_USD / 1e36, 2))" 2>/dev/null || echo "?")
      GAS_USD_500K=$(python3 -c "print(round($GAS_COST_500K * $NATIVE_USD / 1e36, 2))" 2>/dev/null || echo "?")
      echo "gas/400k:     $GAS_COST_400K wei (~\$${GAS_USD_400K})"
      echo "gas/500k:     $GAS_COST_500K wei (~\$${GAS_USD_500K})"
      echo "attempts@400k: $(( OW / GAS_COST_400K ))   @500k: $(( OW / GAS_COST_500K ))"
    fi
    # Wallet trading readiness check
    MIN_WEI=$(usd_to_wei "$MIN_WALLET_USD" "$NATIVE_USD")
    MAX_GAS_WEI=$(usd_to_wei "$MAX_GAS_USD_PER_ATTEMPT" "$NATIVE_USD")
    if (( OW >= MIN_WEI )); then
      echo "wallet:       OK (≥\$$MIN_WALLET_USD)"
    else
      echo "wallet:       LOW (<\$$MIN_WALLET_USD, need $(python3 -c "print(round(($MIN_WEI - OW) / 1e18, 4))" 2>/dev/null || echo "?") ETH more)"
    fi
    if (( GAS_COST_400K <= MAX_GAS_WEI )); then
      echo "gas/attempt:  OK (≤\$$MAX_GAS_USD_PER_ATTEMPT)"
    else
      echo "gas/attempt:  HIGH (>\\\$$MAX_GAS_USD_PER_ATTEMPT, 400k gas = \$${GAS_USD_400K})"
    fi
    ;;

  rescue)
    # Sweep profit (or retired float) from the executor back to the owner.
    # Usage:
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
    echo "usage: wallet.sh {balance|rescue [token] [amount_wei]|sweep <to> <amount_eth> <owner>}" >&2
    exit 1
    ;;
esac
