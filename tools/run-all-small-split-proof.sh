#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  tools/run-all-small-split-proof.sh --tally-input <tally-input.json> [--out-dir <dir>]

Runs the proof-feasibility path with split message circuits:
  1. tally
  2. add-new-key
  3. process-messages split boundary + 5 steps
  4. process-deactivate split boundary + 5 steps
EOF
}

TALLY_INPUT=""
OUT_DIR="$ROOT_DIR/target/cairo-proof/all-split"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tally-input)
      TALLY_INPUT="${2:-}"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$TALLY_INPUT" ]]; then
  echo "--tally-input is required" >&2
  usage >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
TALLY_INPUT="$(cd "$(dirname "$TALLY_INPUT")" && pwd)/$(basename "$TALLY_INPUT")"

"$ROOT_DIR/tools/run-cairo-proof.sh" \
  --circuit tally \
  --input "$TALLY_INPUT" \
  --out-dir "$OUT_DIR/tally"

"$ROOT_DIR/tools/run-cairo-proof.sh" \
  --circuit add-new-key \
  --out-dir "$OUT_DIR/add-new-key"

"$ROOT_DIR/tools/run-process-messages-split-proof.sh" \
  --out-dir "$OUT_DIR/process-messages-split"

"$ROOT_DIR/tools/run-process-deactivate-split-proof.sh" \
  --out-dir "$OUT_DIR/process-deactivate-split"

printf '{\n' > "$OUT_DIR/all-split-proofs.json"
printf '  "tally": "%s",\n' "$OUT_DIR/tally/proof-run.json" >> "$OUT_DIR/all-split-proofs.json"
printf '  "addNewKey": "%s",\n' "$OUT_DIR/add-new-key/proof-run.json" >> "$OUT_DIR/all-split-proofs.json"
printf '  "processMessagesSplit": "%s",\n' "$OUT_DIR/process-messages-split/split-process-messages-proofs.json" >> "$OUT_DIR/all-split-proofs.json"
printf '  "processDeactivateSplit": "%s"\n' "$OUT_DIR/process-deactivate-split/split-process-deactivate-proofs.json" >> "$OUT_DIR/all-split-proofs.json"
printf '}\n' >> "$OUT_DIR/all-split-proofs.json"

echo "All split proof metadata written to: $OUT_DIR/all-split-proofs.json"
