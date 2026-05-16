#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  tools/run-all-small-native-stone-split-proof.sh --tally-input <tally-input.json> [--out-dir <dir>]

Runs the full small native AMACI split set through Stone:
  1. tally-native
  2. add-new-key-native
  3. process-messages native split
  4. process-deactivate native split
EOF
}

TALLY_INPUT=""
OUT_DIR="$ROOT_DIR/target/stone-proof/all-native-stone-split"

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

"$ROOT_DIR/tools/run-stone-native-circuit-proof.sh" \
  --circuit tally-native \
  --input "$TALLY_INPUT" \
  --out-dir "$OUT_DIR/tally-native"

"$ROOT_DIR/tools/run-stone-native-circuit-proof.sh" \
  --circuit add-new-key-native \
  --out-dir "$OUT_DIR/add-new-key-native"

"$ROOT_DIR/tools/run-process-messages-native-stone-split-proof.sh" \
  --out-dir "$OUT_DIR/process-messages-native-stone-split"

"$ROOT_DIR/tools/run-process-deactivate-native-stone-split-proof.sh" \
  --out-dir "$OUT_DIR/process-deactivate-native-stone-split"

printf '{\n' > "$OUT_DIR/all-native-stone-split-proofs.json"
printf '  "tally": "%s",\n' "$OUT_DIR/tally-native/stone-proof/proof-run.json" >> "$OUT_DIR/all-native-stone-split-proofs.json"
printf '  "addNewKey": "%s",\n' "$OUT_DIR/add-new-key-native/stone-proof/proof-run.json" >> "$OUT_DIR/all-native-stone-split-proofs.json"
printf '  "processMessagesSplit": "%s",\n' "$OUT_DIR/process-messages-native-stone-split/split-process-messages-native-stone-proofs.json" >> "$OUT_DIR/all-native-stone-split-proofs.json"
printf '  "processDeactivateSplit": "%s"\n' "$OUT_DIR/process-deactivate-native-stone-split/split-process-deactivate-native-stone-proofs.json" >> "$OUT_DIR/all-native-stone-split-proofs.json"
printf '}\n' >> "$OUT_DIR/all-native-stone-split-proofs.json"

echo "All native Stone split proof metadata written to: $OUT_DIR/all-native-stone-split-proofs.json"
