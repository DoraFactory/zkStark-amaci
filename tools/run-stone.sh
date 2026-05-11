#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  tools/run-stone.sh --check
  tools/run-stone.sh --help

This repository currently has a complete local Scarb/Stwo proof path, but it
does not yet contain an automated Cairo 1 -> Stone AIR input -> cpu_air_prover
pipeline.

Use these commands for the current local proof path:
  npm run prove:tally
  npm run prove:all-split-small

For the Integrity path, produce a real Stone proof first, then serialize it:
  npm run serialize:integrity-calldata -- \
    --stone-proof /absolute/path/to/stone-proof.json \
    --integrity-repo /absolute/path/to/integrity \
    --out /absolute/path/to/integrity-calldata.json \
    --text

Do not pass the Scarb/Stwo proof.json produced by scarb prove as a Stone proof.
EOF
}

tool_status() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    printf 'ok       %s (%s)\n' "$name" "$(command -v "$name")"
    return 0
  fi

  printf 'missing  %s\n' "$name"
  return 1
}

check_toolchain() {
  local missing=0

  echo "Local proof tools:"
  tool_status node || missing=1
  tool_status scarb || missing=1
  echo

  echo "Stone proof tools:"
  tool_status cairo1-run || missing=1
  tool_status cpu_air_prover || missing=1
  tool_status cpu_air_verifier || missing=1
  echo

  echo "Integrity serialization tools:"
  tool_status proof_serializer || true
  tool_status cargo || true
  echo

  cat <<'EOF'
Status:
  - node/scarb are enough for this repo's current local Scarb/Stwo proof flow.
  - cairo1-run + cpu_air_prover + cpu_air_verifier are required before this
    repo can generate a real Stone proof artifact.
  - proof_serializer can be supplied either as a PATH binary, via
    --proof-serializer to npm run serialize:integrity-calldata, or by passing
    --integrity-repo so the tool can run cargo inside the Integrity repo.
EOF

  if [[ "$missing" -ne 0 ]]; then
    return 1
  fi
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" == "--check" ]]; then
  check_toolchain
  exit $?
fi

usage >&2
cat >&2 <<'EOF'

Refusing to run: tools/run-stone.sh is intentionally not an alias for
scarb prove. Passing through to Scarb/Stwo would create a local proof, not a
Stone/Integrity proof.
EOF

exit 2
