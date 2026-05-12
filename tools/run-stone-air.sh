#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  tools/run-stone-air.sh --circuit tally [--input <tally-input.json>] [--out-dir <dir>] [--layout <layout>]

Generates Stone AIR input files for a Cairo proof-mode executable. This does
not run cpu_air_prover yet.

Current support:
  --circuit tally

Outputs:
  prepared.json
  cairo-input.json
  scarb-cairo-args.json
  cairo1-run-args.txt
  trace.bin
  memory.bin
  air-public-input.json
  air-private-input.json
  stone-air-run.json
EOF
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required" >&2
    exit 1
  fi
}

CIRCUIT=""
INPUT_PATH=""
OUT_DIR=""
LAYOUT="all_cairo"

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
    --layout)
      LAYOUT="${2:-}"
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

if [[ "$CIRCUIT" != "tally" ]]; then
  echo "--circuit tally is currently required" >&2
  usage >&2
  exit 1
fi

INPUT_PATH="${INPUT_PATH:-$ROOT_DIR/fixtures/tally-small/000000.json}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/target/stone-air/tally}"

require_tool node
require_tool scarb
require_tool cairo1-run

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
INPUT_PATH="$(cd "$(dirname "$INPUT_PATH")" && pwd)/$(basename "$INPUT_PATH")"

PREPARED_JSON="$OUT_DIR/prepared.json"
CAIRO_INPUT_JSON="$OUT_DIR/cairo-input.json"
SCARB_ARGS_JSON="$OUT_DIR/scarb-cairo-args.json"
CAIRO1_ARGS_TXT="$OUT_DIR/cairo1-run-args.txt"
TRACE_FILE="$OUT_DIR/trace.bin"
MEMORY_FILE="$OUT_DIR/memory.bin"
AIR_PUBLIC_INPUT="$OUT_DIR/air-public-input.json"
AIR_PRIVATE_INPUT="$OUT_DIR/air-private-input.json"
RUN_JSON="$OUT_DIR/stone-air-run.json"
RUN_LOG="$OUT_DIR/cairo1-run.log"
EXECUTABLE_JSON="$ROOT_DIR/cairo/target/dev/tally_votes_stone.executable.json"

echo "==> Preparing tally input"
node "$ROOT_DIR/tools/prepare-tally-input.mjs" \
  "$INPUT_PATH" \
  --out "$PREPARED_JSON" \
  --cairo-input-out "$CAIRO_INPUT_JSON" \
  --cairo-args-out "$SCARB_ARGS_JSON"

echo "==> Converting args for cairo1-run proof mode"
node "$ROOT_DIR/tools/convert-cairo1-run-args.mjs" \
  "$SCARB_ARGS_JSON" \
  --out "$CAIRO1_ARGS_TXT" \
  --text

echo "==> Building Cairo executable"
(
  cd "$ROOT_DIR/cairo"
  scarb build
)

if [[ ! -f "$EXECUTABLE_JSON" ]]; then
  echo "missing executable: $EXECUTABLE_JSON" >&2
  exit 1
fi

echo "==> Running cairo1-run proof mode for tally"
cairo1-run \
  "$EXECUTABLE_JSON" \
  --layout "$LAYOUT" \
  --proof_mode \
  --trace_file "$TRACE_FILE" \
  --memory_file "$MEMORY_FILE" \
  --air_public_input "$AIR_PUBLIC_INPUT" \
  --air_private_input "$AIR_PRIVATE_INPUT" \
  --args_file "$CAIRO1_ARGS_TXT" \
  --print_output \
  2>&1 | tee "$RUN_LOG"

printf '{\n' > "$RUN_JSON"
printf '  "circuit": "tally",\n' >> "$RUN_JSON"
printf '  "executable": "%s",\n' "$EXECUTABLE_JSON" >> "$RUN_JSON"
printf '  "layout": "%s",\n' "$LAYOUT" >> "$RUN_JSON"
printf '  "inputPath": "%s",\n' "$INPUT_PATH" >> "$RUN_JSON"
printf '  "preparedJson": "%s",\n' "$PREPARED_JSON" >> "$RUN_JSON"
printf '  "cairoInputJson": "%s",\n' "$CAIRO_INPUT_JSON" >> "$RUN_JSON"
printf '  "scarbArgsJson": "%s",\n' "$SCARB_ARGS_JSON" >> "$RUN_JSON"
printf '  "cairo1ArgsTxt": "%s",\n' "$CAIRO1_ARGS_TXT" >> "$RUN_JSON"
printf '  "traceFile": "%s",\n' "$TRACE_FILE" >> "$RUN_JSON"
printf '  "memoryFile": "%s",\n' "$MEMORY_FILE" >> "$RUN_JSON"
printf '  "airPublicInput": "%s",\n' "$AIR_PUBLIC_INPUT" >> "$RUN_JSON"
printf '  "airPrivateInput": "%s",\n' "$AIR_PRIVATE_INPUT" >> "$RUN_JSON"
printf '  "runLog": "%s"\n' "$RUN_LOG" >> "$RUN_JSON"
printf '}\n' >> "$RUN_JSON"

echo "Stone AIR metadata written to: $RUN_JSON"
