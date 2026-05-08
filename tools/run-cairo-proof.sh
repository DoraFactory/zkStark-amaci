#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  tools/run-cairo-proof.sh <tally-input.json> [out-dir]

Runs the current local Cairo proof flow:
  1. Generate scarb execute arguments from an existing TallyVotes JSON input.
  2. Run scarb prove --execute for zkstark_amaci_tally.
  3. Verify the generated proof with scarb verify.

This uses the Scarb/Stwo proof flow available on this machine. Integrity/Stone
proof serialization is a separate integration step.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "node is required to prepare Cairo arguments" >&2
  exit 1
fi

if ! command -v scarb >/dev/null 2>&1; then
  echo "scarb is required to execute, prove, and verify the Cairo target" >&2
  exit 1
fi

INPUT_PATH="$1"
OUT_DIR="${2:-$ROOT_DIR/target/cairo-proof}"

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

PREPARED_JSON="$OUT_DIR/tally-prepared.json"
CAIRO_INPUT_JSON="$OUT_DIR/tally-cairo-input.json"
CAIRO_ARGS_JSON="$OUT_DIR/tally-cairo-args.json"
RUN_METADATA_JSON="$OUT_DIR/proof-run.json"

node "$ROOT_DIR/tools/prepare-tally-input.mjs" \
  "$INPUT_PATH" \
  --out "$PREPARED_JSON" \
  --cairo-input-out "$CAIRO_INPUT_JSON" \
  --cairo-args-out "$CAIRO_ARGS_JSON"

(
  cd "$ROOT_DIR/cairo"
  scarb prove --execute --arguments-file "$CAIRO_ARGS_JSON" --print-program-output

  EXECUTION_ID="$(
    find target/execute/zkstark_amaci_tally -maxdepth 1 -type d -name 'execution*' \
      | sed 's|.*/execution||' \
      | sort -n \
      | tail -1
  )"

  if [[ -z "$EXECUTION_ID" ]]; then
    echo "could not find generated execution id" >&2
    exit 1
  fi

  scarb verify --execution-id "$EXECUTION_ID"

  PROOF_JSON="$ROOT_DIR/cairo/target/execute/zkstark_amaci_tally/execution$EXECUTION_ID/proof/proof.json"
  printf '{\n' > "$RUN_METADATA_JSON"
  printf '  "executionId": "%s",\n' "$EXECUTION_ID" >> "$RUN_METADATA_JSON"
  printf '  "proofJson": "%s",\n' "$PROOF_JSON" >> "$RUN_METADATA_JSON"
  printf '  "preparedJson": "%s",\n' "$PREPARED_JSON" >> "$RUN_METADATA_JSON"
  printf '  "cairoInputJson": "%s",\n' "$CAIRO_INPUT_JSON" >> "$RUN_METADATA_JSON"
  printf '  "cairoArgsJson": "%s"\n' "$CAIRO_ARGS_JSON" >> "$RUN_METADATA_JSON"
  printf '}\n' >> "$RUN_METADATA_JSON"
  echo "Proof metadata written to: $RUN_METADATA_JSON"
)
