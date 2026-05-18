#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  tools/run-process-messages-native-split-proof.sh [--input <input.json>] [--out-dir <dir>]

This proves the small ProcessMessages relation as Starknet-native linked pieces:
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
OUT_DIR="$ROOT_DIR/target/cairo-proof/process-messages-native-split"

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

"$ROOT_DIR/tools/run-cairo-proof.sh" \
  --circuit process-messages-boundary-native \
  --input "$INPUT_PATH" \
  --out-dir "$OUT_DIR/boundary"

"$ROOT_DIR/tools/run-cairo-proof.sh" \
  --circuit process-message-coord-key-native \
  --input "$INPUT_PATH" \
  --out-dir "$OUT_DIR/coord-key"

for message_index in 0 1 2 3 4; do
  "$ROOT_DIR/tools/run-cairo-proof.sh" \
    --circuit process-message-ecdh-native \
    --input "$INPUT_PATH" \
    --message-index "$message_index" \
    --out-dir "$OUT_DIR/ecdh-$message_index"

  "$ROOT_DIR/tools/run-cairo-proof.sh" \
    --circuit process-message-decrypt-native \
    --input "$INPUT_PATH" \
    --message-index "$message_index" \
    --out-dir "$OUT_DIR/decrypt-$message_index"

  "$ROOT_DIR/tools/run-cairo-proof.sh" \
    --circuit process-message-signature-native \
    --input "$INPUT_PATH" \
    --message-index "$message_index" \
    --out-dir "$OUT_DIR/signature-$message_index"

  "$ROOT_DIR/tools/run-cairo-proof.sh" \
    --circuit process-message-step-core-native \
    --input "$INPUT_PATH" \
    --message-index "$message_index" \
    --out-dir "$OUT_DIR/core-$message_index"
done

printf '{\n' > "$OUT_DIR/split-process-messages-native-proofs.json"
printf '  "boundary": "%s",\n' "$OUT_DIR/boundary/proof-run.json" >> "$OUT_DIR/split-process-messages-native-proofs.json"
printf '  "coordKey": "%s",\n' "$OUT_DIR/coord-key/proof-run.json" >> "$OUT_DIR/split-process-messages-native-proofs.json"
printf '  "ecdh": [\n' >> "$OUT_DIR/split-process-messages-native-proofs.json"
for message_index in 0 1 2 3 4; do
  suffix=","
  if [[ "$message_index" == "4" ]]; then
    suffix=""
  fi
  printf '    "%s"%s\n' "$OUT_DIR/ecdh-$message_index/proof-run.json" "$suffix" >> "$OUT_DIR/split-process-messages-native-proofs.json"
done
printf '  ],\n' >> "$OUT_DIR/split-process-messages-native-proofs.json"
printf '  "decrypt": [\n' >> "$OUT_DIR/split-process-messages-native-proofs.json"
for message_index in 0 1 2 3 4; do
  suffix=","
  if [[ "$message_index" == "4" ]]; then
    suffix=""
  fi
  printf '    "%s"%s\n' "$OUT_DIR/decrypt-$message_index/proof-run.json" "$suffix" >> "$OUT_DIR/split-process-messages-native-proofs.json"
done
printf '  ],\n' >> "$OUT_DIR/split-process-messages-native-proofs.json"
printf '  "signatures": [\n' >> "$OUT_DIR/split-process-messages-native-proofs.json"
for message_index in 0 1 2 3 4; do
  suffix=","
  if [[ "$message_index" == "4" ]]; then
    suffix=""
  fi
  printf '    "%s"%s\n' "$OUT_DIR/signature-$message_index/proof-run.json" "$suffix" >> "$OUT_DIR/split-process-messages-native-proofs.json"
done
printf '  ],\n' >> "$OUT_DIR/split-process-messages-native-proofs.json"
printf '  "cores": [\n' >> "$OUT_DIR/split-process-messages-native-proofs.json"
for message_index in 0 1 2 3 4; do
  suffix=","
  if [[ "$message_index" == "4" ]]; then
    suffix=""
  fi
  printf '    "%s"%s\n' "$OUT_DIR/core-$message_index/proof-run.json" "$suffix" >> "$OUT_DIR/split-process-messages-native-proofs.json"
done
printf '  ]\n' >> "$OUT_DIR/split-process-messages-native-proofs.json"
printf '}\n' >> "$OUT_DIR/split-process-messages-native-proofs.json"

node "$ROOT_DIR/tools/check-native-split-links.mjs" \
  "$OUT_DIR/split-process-messages-native-proofs.json" \
  --out "$OUT_DIR/native-split-link-report.json" \
  --text

echo "Native split ProcessMessages proof metadata written to: $OUT_DIR/split-process-messages-native-proofs.json"
