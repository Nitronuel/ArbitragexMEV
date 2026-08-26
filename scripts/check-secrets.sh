#!/usr/bin/env bash
# Scans for credential-like content (audit P2).
#
# Design note: a raw private key and a keccak hash are indistinguishable by
# shape — both are 0x + 64 hex. Catalogs legitimately contain tens of
# thousands of such hashes, so a blocking bare-hex rule would be disabled
# within a week. Instead:
#   BLOCKING: credential-shaped assignments (PRIVATE_KEY=, MNEMONIC=,
#     API_KEY=, *_SECRET/*_TOKEN), API-key URL paths (Alchemy/QuickNode/
#     Infura/dRPC), JWTs, sk- keys.
#   WARNING (non-blocking): bare 0x+64-hex literals outside data/ — an
#     operator eyeballs whether any is a key. SECURITY.md's rule remains the
#     primary control: keys come from env at runtime, never from files.
# Scans STAGED changes too; full-history scanning needs gitleaks/trufflehog
# (documented gap).
set -uo pipefail

status=0

fail() {
  printf 'Credential-like content found (%s):\n' "$1" >&2
  shift
  printf '%s\n' "$*" >&2
  status=1
}

if [[ -z "$(git ls-files)" ]]; then
  printf 'No tracked files to scan.\n'
  exit 0
fi

BLOCK_PATTERNS=(
  'sk-[A-Za-z0-9]{20,}'
  '(PRIVATE_KEY|MNEMONIC|API_KEY)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9_./+=-]{12,}'
  '(alchemy|quiknode|infura|drpc)\.[a-z]+/[A-Za-z0-9_-]{16,}|quiknode\.pro/[0-9a-fA-F]{16,}'
  'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}'
  '(API_KEY|SECRET|TOKEN|PASSWORD)[A-Z_]*[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9_./+=-]{20,}'
)

for pattern in "${BLOCK_PATTERNS[@]}"; do
  hits=$(git grep -nIE "$pattern" -- . 2>/dev/null | head -5)
  if [[ -n $hits ]]; then
    fail "tracked" "$hits"
  fi
  staged=$(git diff --cached -U0 -- . 2>/dev/null | grep "^+" | grep -E "$pattern" | head -5)
  if [[ -n $staged ]]; then
    fail "staged" "$staged"
  fi
done

# Warning-only: bare 0x+64-hex outside data/ (catalogs are full of hashes).
warn_hits=$(git grep -nI '0x[0-9a-fA-F]\{64\}' -- ':(exclude)data' 2>/dev/null \
  | grep -vE '/tests?/|_test\.rs|mod tests|#\[' | head -8)
if [[ -n $warn_hits ]]; then
  printf 'NOTE (warning-only): bare 0x+64-hex literals outside data/ — verify none is a key:\n' >&2
  printf '%s\n' "$warn_hits" >&2
fi

if [[ $status -eq 0 ]]; then
  printf 'No credential-like content found.\n'
fi
exit $status
