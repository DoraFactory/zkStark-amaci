#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  tools/run-process-deactivate-split-proof.sh [--input <input.json>] [--out-dir <dir>]

This proves the small ProcessDeactivateMessages relation as linked pieces:
  1. one process-deactivate-boundary proof
  2. one process-deactivate-coord-key proof
  3. five process-deactivate-ecdh-command proofs
  4. five process-deactivate-signature proofs
  5. five process-deactivate-decrypt-current proofs
  6. five process-deactivate-decrypt-new proofs
  7. five process-deactivate-ecdh-leaf proofs
  8. five process-deactivate-step-core proofs

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

"$ROOT_DIR/tools/run-cairo-proof.sh" \
  --circuit process-deactivate-coord-key \
  --input "$INPUT_PATH" \
  --out-dir "$OUT_DIR/coord-key"

for message_index in 0 1 2 3 4; do
  "$ROOT_DIR/tools/run-cairo-proof.sh" \
    --circuit process-deactivate-ecdh-command \
    --input "$INPUT_PATH" \
    --message-index "$message_index" \
    --out-dir "$OUT_DIR/command-ecdh-$message_index"

  "$ROOT_DIR/tools/run-cairo-proof.sh" \
    --circuit process-deactivate-signature \
    --input "$INPUT_PATH" \
    --message-index "$message_index" \
    --out-dir "$OUT_DIR/signature-$message_index"

  "$ROOT_DIR/tools/run-cairo-proof.sh" \
    --circuit process-deactivate-decrypt-current \
    --input "$INPUT_PATH" \
    --message-index "$message_index" \
    --out-dir "$OUT_DIR/current-decrypt-$message_index"

  "$ROOT_DIR/tools/run-cairo-proof.sh" \
    --circuit process-deactivate-decrypt-new \
    --input "$INPUT_PATH" \
    --message-index "$message_index" \
    --out-dir "$OUT_DIR/new-decrypt-$message_index"

  "$ROOT_DIR/tools/run-cairo-proof.sh" \
    --circuit process-deactivate-ecdh-leaf \
    --input "$INPUT_PATH" \
    --message-index "$message_index" \
    --out-dir "$OUT_DIR/leaf-ecdh-$message_index"

  "$ROOT_DIR/tools/run-cairo-proof.sh" \
    --circuit process-deactivate-step-core \
    --input "$INPUT_PATH" \
    --message-index "$message_index" \
    --out-dir "$OUT_DIR/core-$message_index"
done

printf '{\n' > "$OUT_DIR/split-process-deactivate-proofs.json"
printf '  "boundary": "%s",\n' "$OUT_DIR/boundary/proof-run.json" >> "$OUT_DIR/split-process-deactivate-proofs.json"
printf '  "coordKey": "%s",\n' "$OUT_DIR/coord-key/proof-run.json" >> "$OUT_DIR/split-process-deactivate-proofs.json"
printf '  "commandEcdh": [\n' >> "$OUT_DIR/split-process-deactivate-proofs.json"
for message_index in 0 1 2 3 4; do
  suffix=","
  if [[ "$message_index" == "4" ]]; then
    suffix=""
  fi
  printf '    "%s"%s\n' "$OUT_DIR/command-ecdh-$message_index/proof-run.json" "$suffix" >> "$OUT_DIR/split-process-deactivate-proofs.json"
done
printf '  ],\n' >> "$OUT_DIR/split-process-deactivate-proofs.json"
printf '  "signatures": [\n' >> "$OUT_DIR/split-process-deactivate-proofs.json"
for message_index in 0 1 2 3 4; do
  suffix=","
  if [[ "$message_index" == "4" ]]; then
    suffix=""
  fi
  printf '    "%s"%s\n' "$OUT_DIR/signature-$message_index/proof-run.json" "$suffix" >> "$OUT_DIR/split-process-deactivate-proofs.json"
done
printf '  ],\n' >> "$OUT_DIR/split-process-deactivate-proofs.json"
printf '  "currentDecrypt": [\n' >> "$OUT_DIR/split-process-deactivate-proofs.json"
for message_index in 0 1 2 3 4; do
  suffix=","
  if [[ "$message_index" == "4" ]]; then
    suffix=""
  fi
  printf '    "%s"%s\n' "$OUT_DIR/current-decrypt-$message_index/proof-run.json" "$suffix" >> "$OUT_DIR/split-process-deactivate-proofs.json"
done
printf '  ],\n' >> "$OUT_DIR/split-process-deactivate-proofs.json"
printf '  "newDecrypt": [\n' >> "$OUT_DIR/split-process-deactivate-proofs.json"
for message_index in 0 1 2 3 4; do
  suffix=","
  if [[ "$message_index" == "4" ]]; then
    suffix=""
  fi
  printf '    "%s"%s\n' "$OUT_DIR/new-decrypt-$message_index/proof-run.json" "$suffix" >> "$OUT_DIR/split-process-deactivate-proofs.json"
done
printf '  ],\n' >> "$OUT_DIR/split-process-deactivate-proofs.json"
printf '  "leafEcdh": [\n' >> "$OUT_DIR/split-process-deactivate-proofs.json"
for message_index in 0 1 2 3 4; do
  suffix=","
  if [[ "$message_index" == "4" ]]; then
    suffix=""
  fi
  printf '    "%s"%s\n' "$OUT_DIR/leaf-ecdh-$message_index/proof-run.json" "$suffix" >> "$OUT_DIR/split-process-deactivate-proofs.json"
done
printf '  ],\n' >> "$OUT_DIR/split-process-deactivate-proofs.json"
printf '  "cores": [\n' >> "$OUT_DIR/split-process-deactivate-proofs.json"
for message_index in 0 1 2 3 4; do
  suffix=","
  if [[ "$message_index" == "4" ]]; then
    suffix=""
  fi
  printf '    "%s"%s\n' "$OUT_DIR/core-$message_index/proof-run.json" "$suffix" >> "$OUT_DIR/split-process-deactivate-proofs.json"
done
printf '  ]\n' >> "$OUT_DIR/split-process-deactivate-proofs.json"
printf '}\n' >> "$OUT_DIR/split-process-deactivate-proofs.json"

echo "Split ProcessDeactivate proof metadata written to: $OUT_DIR/split-process-deactivate-proofs.json"
