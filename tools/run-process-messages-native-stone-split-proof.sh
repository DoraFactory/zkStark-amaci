#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  tools/run-process-messages-native-stone-split-proof.sh [--input <input.json>] [--out-dir <dir>]

Runs the small ProcessMessages native split relation through Stone:
  1. one process-messages-boundary-native proof
  2. one process-message-coord-key-native proof
  3. five process-message-ecdh-native proofs
  4. five process-message-decrypt-native proofs
  5. five process-message-signature-native proofs
  6. five process-message-step-core-native proofs

If --input is omitted, the current small synthetic ProcessMessages fixture is
generated under the output directory.
EOF
}

INPUT_PATH=""
OUT_DIR="$ROOT_DIR/target/stone-proof/process-messages-native-stone-split"

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
  INPUT_PATH="$OUT_DIR/process-messages-small-input.json"
  node "$ROOT_DIR/tools/write-small-fixture.mjs" --circuit process-messages --out "$INPUT_PATH"
fi
INPUT_PATH="$(cd "$(dirname "$INPUT_PATH")" && pwd)/$(basename "$INPUT_PATH")"

run_stone_one() {
  local circuit="$1"
  local out_dir="$2"
  local message_index="${3:-}"
  local args=(
    --circuit "$circuit"
    --input "$INPUT_PATH"
    --out-dir "$out_dir"
  )
  if [[ -n "$message_index" ]]; then
    args+=(--message-index "$message_index")
  fi
  "$ROOT_DIR/tools/run-stone-native-circuit-proof.sh" "${args[@]}"
}

run_stone_one process-messages-boundary-native "$OUT_DIR/boundary"
run_stone_one process-message-coord-key-native "$OUT_DIR/coord-key"

for message_index in 0 1 2 3 4; do
  run_stone_one process-message-ecdh-native "$OUT_DIR/ecdh-$message_index" "$message_index"
  run_stone_one process-message-decrypt-native "$OUT_DIR/decrypt-$message_index" "$message_index"
  run_stone_one process-message-signature-native "$OUT_DIR/signature-$message_index" "$message_index"
  run_stone_one process-message-step-core-native "$OUT_DIR/core-$message_index" "$message_index"
done

MANIFEST="$OUT_DIR/split-process-messages-native-stone-proofs.json"
printf '{\n' > "$MANIFEST"
printf '  "boundary": "%s",\n' "$OUT_DIR/boundary/stone-proof/proof-run.json" >> "$MANIFEST"
printf '  "coordKey": "%s",\n' "$OUT_DIR/coord-key/stone-proof/proof-run.json" >> "$MANIFEST"
printf '  "ecdh": [\n' >> "$MANIFEST"
for message_index in 0 1 2 3 4; do
  suffix=","
  if [[ "$message_index" == "4" ]]; then
    suffix=""
  fi
  printf '    "%s"%s\n' "$OUT_DIR/ecdh-$message_index/stone-proof/proof-run.json" "$suffix" >> "$MANIFEST"
done
printf '  ],\n' >> "$MANIFEST"
printf '  "decrypt": [\n' >> "$MANIFEST"
for message_index in 0 1 2 3 4; do
  suffix=","
  if [[ "$message_index" == "4" ]]; then
    suffix=""
  fi
  printf '    "%s"%s\n' "$OUT_DIR/decrypt-$message_index/stone-proof/proof-run.json" "$suffix" >> "$MANIFEST"
done
printf '  ],\n' >> "$MANIFEST"
printf '  "signatures": [\n' >> "$MANIFEST"
for message_index in 0 1 2 3 4; do
  suffix=","
  if [[ "$message_index" == "4" ]]; then
    suffix=""
  fi
  printf '    "%s"%s\n' "$OUT_DIR/signature-$message_index/stone-proof/proof-run.json" "$suffix" >> "$MANIFEST"
done
printf '  ],\n' >> "$MANIFEST"
printf '  "cores": [\n' >> "$MANIFEST"
for message_index in 0 1 2 3 4; do
  suffix=","
  if [[ "$message_index" == "4" ]]; then
    suffix=""
  fi
  printf '    "%s"%s\n' "$OUT_DIR/core-$message_index/stone-proof/proof-run.json" "$suffix" >> "$MANIFEST"
done
printf '  ]\n' >> "$MANIFEST"
printf '}\n' >> "$MANIFEST"

node "$ROOT_DIR/tools/check-native-split-links.mjs" \
  "$MANIFEST" \
  --out "$OUT_DIR/native-stone-split-link-report.json" \
  --text

echo "Native Stone split ProcessMessages proof metadata written to: $MANIFEST"
