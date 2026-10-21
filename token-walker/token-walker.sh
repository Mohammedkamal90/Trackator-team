#!/usr/bin/env bash
# Run token-walker from ANY directory:   /path/to/token-walker/token-walker.sh <project|file.sol> [options]
# Builds on first use (needs node >= 18 and npm).
set -euo pipefail
SELF="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"   # resolves symlinks (works when linked into PATH)
if [ ! -f "$SELF/dist/index.js" ]; then
  echo "token-walker: first run, building..." >&2
  (cd "$SELF" && npm install --include=dev --no-audit --no-fund >&2 && npx tsc >&2)
fi
exec node "$SELF/dist/index.js" "$@"
