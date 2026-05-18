#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  tools/run-stone-native-circuit-proof.sh --circuit <native-circuit> [--input <input.json>] [--out-dir <dir>] [--message-index <n>]

Runs one native AMACI circuit through the Stone path:
  1. tools/run-stone-air.sh
  2. tools/run-stone-proof.sh

The output directory contains:
  stone-air/stone-air-run.json
  stone-proof/stone-proof.json
  stone-proof/proof-run.json
EOF
}

CIRCUIT=""
INPUT_PATH=""
OUT_DIR=""
MESSAGE_INDEX=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --circuit)
      CIRCUIT="${2:-}"
      shift 2
      ;;
    --input)
      INPUT_PATH="${2:-}"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    --message-index)
      MESSAGE_INDEX="${2:-}"
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

if [[ -z "$CIRCUIT" ]]; then
  echo "--circuit is required" >&2
  usage >&2
  exit 1
fi

OUT_DIR="${OUT_DIR:-$ROOT_DIR/target/stone-proof/$CIRCUIT}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

AIR_ARGS=(
  --circuit "$CIRCUIT"
  --out-dir "$OUT_DIR/stone-air"
)
if [[ -n "$INPUT_PATH" ]]; then
  AIR_ARGS+=(--input "$INPUT_PATH")
fi
if [[ -n "$MESSAGE_INDEX" ]]; then
  AIR_ARGS+=(--message-index "$MESSAGE_INDEX")
fi

"$ROOT_DIR/tools/run-stone-air.sh" "${AIR_ARGS[@]}"

"$ROOT_DIR/tools/run-stone-proof.sh" \
  --air-run "$OUT_DIR/stone-air/stone-air-run.json" \
  --out-dir "$OUT_DIR/stone-proof"

printf '{\n' > "$OUT_DIR/stone-circuit-run.json"
printf '  "circuit": "%s",\n' "$CIRCUIT" >> "$OUT_DIR/stone-circuit-run.json"
if [[ -n "$MESSAGE_INDEX" ]]; then
  printf '  "messageIndex": %s,\n' "$MESSAGE_INDEX" >> "$OUT_DIR/stone-circuit-run.json"
fi
printf '  "stoneAirRunJson": "%s",\n' "$OUT_DIR/stone-air/stone-air-run.json" >> "$OUT_DIR/stone-circuit-run.json"
printf '  "proofRunJson": "%s"\n' "$OUT_DIR/stone-proof/proof-run.json" >> "$OUT_DIR/stone-circuit-run.json"
printf '}\n' >> "$OUT_DIR/stone-circuit-run.json"

echo "Stone circuit metadata written to: $OUT_DIR/stone-circuit-run.json"
