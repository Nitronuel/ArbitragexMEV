#!/usr/bin/env bash
set -euo pipefail

if [[ -z "$(git ls-files)" ]]; then
  printf 'No tracked files to scan.\n'
  exit 0
fi

if git grep -nE \
  'sk-[A-Za-z0-9]{20,}|(PRIVATE_KEY|MNEMONIC|API_KEY)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9_./+=-]{12,}'; then
  printf 'Credential-like content found in tracked files.\n' >&2
  exit 1
fi

printf 'No credential-like content found in tracked files.\n'
