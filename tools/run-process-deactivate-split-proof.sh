#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  tools/run-process-deactivate-split-proof.sh [--input <input.json>] [--out-dir <dir>]

This proves the small ProcessDeactivateMessages relation as linked pieces:
  1. one process-deactivate-boundary proof
  2. five process-deactivate-step proofs, one for each message slot

If --input is omitted, the current small synthetic ProcessDeactivateMessages
fixture is generated under the output directory.
EOF
}

INPUT_PATH=""
OUT_DIR="$ROOT_DIR/target/cairo-proof/process-deactivate-split"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input)
      INPUT_PATH="${2:-}"
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

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

if [[ -z "$INPUT_PATH" ]]; then
  INPUT_PATH="$OUT_DIR/process-deactivate-small-input.json"
  node "$ROOT_DIR/tools/write-small-fixture.mjs" --circuit process-deactivate --out "$INPUT_PATH"
fi
INPUT_PATH="$(cd "$(dirname "$INPUT_PATH")" && pwd)/$(basename "$INPUT_PATH")"

"$ROOT_DIR/tools/run-cairo-proof.sh" \
  --circuit process-deactivate-boundary \
  --input "$INPUT_PATH" \
  --out-dir "$OUT_DIR/boundary"

for message_index in 0 1 2 3 4; do
  "$ROOT_DIR/tools/run-cairo-proof.sh" \
    --circuit process-deactivate-step \
    --input "$INPUT_PATH" \
    --message-index "$message_index" \
    --out-dir "$OUT_DIR/step-$message_index"
done

printf '{\n' > "$OUT_DIR/split-process-deactivate-proofs.json"
printf '  "boundary": "%s",\n' "$OUT_DIR/boundary/proof-run.json" >> "$OUT_DIR/split-process-deactivate-proofs.json"
printf '  "steps": [\n' >> "$OUT_DIR/split-process-deactivate-proofs.json"
for message_index in 0 1 2 3 4; do
  suffix=","
  if [[ "$message_index" == "4" ]]; then
    suffix=""
  fi
  printf '    "%s"%s\n' "$OUT_DIR/step-$message_index/proof-run.json" "$suffix" >> "$OUT_DIR/split-process-deactivate-proofs.json"
done
printf '  ]\n' >> "$OUT_DIR/split-process-deactivate-proofs.json"
printf '}\n' >> "$OUT_DIR/split-process-deactivate-proofs.json"

echo "Split ProcessDeactivate proof metadata written to: $OUT_DIR/split-process-deactivate-proofs.json"
