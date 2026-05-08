#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cat >&2 <<'EOF'
tools/run-stone.sh is currently an alias for the local Scarb/Stwo proof flow.
Integrity/Stone proof serialization is still a separate integration step.
EOF

exec "$ROOT_DIR/tools/run-cairo-proof.sh" "$@"
