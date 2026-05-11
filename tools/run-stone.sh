#!/usr/bin/env bash
set -euo pipefail

STONE_PROVER_DIR="${STONE_PROVER_DIR:-$HOME/stone-prover}"
INTEGRITY_DIR="${INTEGRITY_DIR:-$HOME/integrity}"

usage() {
  cat <<'EOF'
Usage:
  tools/run-stone.sh --check
  tools/run-stone.sh --help

This repository has a complete local Scarb/Stwo proof path and a tally-focused
Cairo 1 -> Stone AIR input -> cpu_air_prover pipeline.

Use these commands for the current local proof path:
  npm run prove:tally
  npm run prove:all-split-small

For the current tally Stone proof path:
  npm run stone:air:tally -- --out-dir /absolute/path/to/stone-tally --layout recursive
  npm run stone:prove:tally -- \
    --air-run /absolute/path/to/stone-tally/stone-air-run.json \
    --out-dir /absolute/path/to/stone-tally-proof

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

find_stone_config_file() {
  local file_name="$1"
  local candidates=(
    "$STONE_PROVER_DIR/$file_name"
    "$STONE_PROVER_DIR/e2e_test/Cairo/$file_name"
    "$STONE_PROVER_DIR/e2e_test/CairoZero/$file_name"
    "$INTEGRITY_DIR/examples/proofs/$file_name"
  )

  local candidate
  for candidate in "${candidates[@]}"; do
    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

config_status() {
  local file_name="$1"
  local path
  if path="$(find_stone_config_file "$file_name")"; then
    printf 'ok       %s (%s)\n' "$file_name" "$path"
    return 0
  fi

  printf 'missing  %s\n' "$file_name"
  return 1
}

check_toolchain() {
  local missing=0
  local serializer_ready=0

  echo "Local proof tools:"
  tool_status node || missing=1
  tool_status scarb || missing=1
  echo

  echo "Stone proof tools:"
  tool_status cairo1-run || missing=1
  tool_status cpu_air_prover || missing=1
  tool_status cpu_air_verifier || missing=1
  echo

  echo "Stone prover config files:"
  config_status cpu_air_prover_config.json || missing=1
  config_status cpu_air_params.json || missing=1
  echo

  echo "Integrity serialization tools:"
  if tool_status proof_serializer; then
    serializer_ready=1
  fi
  if tool_status cargo; then
    serializer_ready=1
  fi
  echo

  cat <<'EOF'
Status:
  - node/scarb are enough for this repo's current local Scarb/Stwo proof flow.
  - cairo1-run + cpu_air_prover + cpu_air_verifier are required before this
    repo can generate a real Stone proof artifact.
  - cpu_air_prover_config.json + cpu_air_params.json are also required; they
    are usually present under stone-prover/e2e_test/Cairo.
  - proof_serializer can be supplied either as a PATH binary or via
    --proof-serializer to npm run serialize:integrity-calldata.
  - cargo is enough only when --integrity-repo points to a local Integrity
    checkout, because the serializer command can then run through cargo.
EOF

  if [[ "$serializer_ready" -ne 1 ]]; then
    missing=1
  fi

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
