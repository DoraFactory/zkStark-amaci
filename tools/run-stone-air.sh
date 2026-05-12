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

Default layout:
  dex

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

detect_cairo_corelib_dir() {
  local candidates=()

  if [[ -n "${CAIRO_CORELIB_DIR:-}" ]]; then
    candidates+=("$CAIRO_CORELIB_DIR")
  fi

  if [[ -n "${CAIRO_VM_DIR:-}" ]]; then
    candidates+=(
      "$CAIRO_VM_DIR/cairo1-run/corelib"
      "$CAIRO_VM_DIR/corelib"
    )
  fi

  if [[ -n "${HOME:-}" ]]; then
    candidates+=(
      "$HOME/cairo-vm/cairo1-run/corelib"
      "$HOME/cairo-vm/corelib"
    )
  fi

  candidates+=(
    "$ROOT_DIR/corelib"
    "$ROOT_DIR/../corelib"
  )

  local candidate nested
  for candidate in "${candidates[@]}"; do
    if [[ -d "$candidate/src" ]]; then
      (cd "$candidate" && pwd)
      return 0
    fi

    nested="$candidate/corelib"
    if [[ -d "$nested/src" ]]; then
      (cd "$nested" && pwd)
      return 0
    fi
  done

  return 1
}

CIRCUIT=""
INPUT_PATH=""
OUT_DIR=""
LAYOUT="dex"

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

if ! grep -q 'name = "tally_votes_stone"' "$ROOT_DIR/cairo/Scarb.toml" \
  || ! grep -q 'stone_tally_votes' "$ROOT_DIR/cairo/src/lib.cairo" \
  || [[ ! -f "$ROOT_DIR/cairo/src/stone_tally_votes.cairo" ]]; then
  cat >&2 <<EOF
Stone tally executable source is incomplete.

Expected:
  - cairo/Scarb.toml contains target executable tally_votes_stone
  - cairo/src/lib.cairo declares mod stone_tally_votes
  - cairo/src/stone_tally_votes.cairo exists

Your checkout likely has tools/run-stone-air.sh but not the matching Cairo
proof-mode wrapper files. Pull or apply the full Stone AIR entrypoint changes.
EOF
  exit 1
fi

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
PACKAGE_SIERRA_JSON="$ROOT_DIR/cairo/target/dev/zkstark_amaci_tally.sierra.json"
RUNNER_SIERRA_JSON="$OUT_DIR/tally_votes_stone.cairo1-run.sierra.json"
CORELIB_DIR="$(detect_cairo_corelib_dir || true)"

if [[ -z "$CORELIB_DIR" ]]; then
  cat >&2 <<'EOF'
cairo1-run could not find a Cairo development corelib.

Set CAIRO_CORELIB_DIR to the corelib directory built with cairo-vm, for example:
  CAIRO_CORELIB_DIR=~/cairo-vm/cairo1-run/corelib npm run stone:air:tally -- --out-dir ~/zkstark-amaci-proofs/stone-tally

If that directory does not exist, run the cairo-vm dependency setup first:
  cd ~/cairo-vm/cairo1-run && make deps
EOF
  exit 1
fi

CORELIB_PARENT="$(cd "$CORELIB_DIR/.." && pwd)"

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

if [[ ! -f "$PACKAGE_SIERRA_JSON" ]]; then
  echo "missing package Sierra artifact: $PACKAGE_SIERRA_JSON" >&2
  exit 1
fi

echo "==> Exporting cairo1-run Sierra artifact"
node "$ROOT_DIR/tools/export-cairo1-run-sierra.mjs" \
  "$PACKAGE_SIERRA_JSON" \
  --function "zkstark_amaci_tally::stone_tally_votes::tally_votes_stone_main" \
  --main-name "zkstark_amaci_tally::stone_tally_votes::main" \
  --out "$RUNNER_SIERRA_JSON"

echo "==> Running cairo1-run proof mode for tally"
echo "cairo1-run corelib: $CORELIB_DIR"
(
  cd "$CORELIB_PARENT"
  cairo1-run \
    "$RUNNER_SIERRA_JSON" \
    --layout "$LAYOUT" \
    --proof_mode \
    --trace_file "$TRACE_FILE" \
    --memory_file "$MEMORY_FILE" \
    --air_public_input "$AIR_PUBLIC_INPUT" \
    --air_private_input "$AIR_PRIVATE_INPUT" \
    --args_file "$CAIRO1_ARGS_TXT" \
    --print_output
) 2>&1 | tee "$RUN_LOG"

printf '{\n' > "$RUN_JSON"
printf '  "circuit": "tally",\n' >> "$RUN_JSON"
printf '  "executable": "%s",\n' "$EXECUTABLE_JSON" >> "$RUN_JSON"
printf '  "packageSierraJson": "%s",\n' "$PACKAGE_SIERRA_JSON" >> "$RUN_JSON"
printf '  "runnerSierraJson": "%s",\n' "$RUNNER_SIERRA_JSON" >> "$RUN_JSON"
printf '  "layout": "%s",\n' "$LAYOUT" >> "$RUN_JSON"
printf '  "inputPath": "%s",\n' "$INPUT_PATH" >> "$RUN_JSON"
printf '  "preparedJson": "%s",\n' "$PREPARED_JSON" >> "$RUN_JSON"
printf '  "cairoInputJson": "%s",\n' "$CAIRO_INPUT_JSON" >> "$RUN_JSON"
printf '  "scarbArgsJson": "%s",\n' "$SCARB_ARGS_JSON" >> "$RUN_JSON"
printf '  "cairo1ArgsTxt": "%s",\n' "$CAIRO1_ARGS_TXT" >> "$RUN_JSON"
printf '  "corelibDir": "%s",\n' "$CORELIB_DIR" >> "$RUN_JSON"
printf '  "cairo1RunCwd": "%s",\n' "$CORELIB_PARENT" >> "$RUN_JSON"
printf '  "traceFile": "%s",\n' "$TRACE_FILE" >> "$RUN_JSON"
printf '  "memoryFile": "%s",\n' "$MEMORY_FILE" >> "$RUN_JSON"
printf '  "airPublicInput": "%s",\n' "$AIR_PUBLIC_INPUT" >> "$RUN_JSON"
printf '  "airPrivateInput": "%s",\n' "$AIR_PRIVATE_INPUT" >> "$RUN_JSON"
printf '  "runLog": "%s"\n' "$RUN_LOG" >> "$RUN_JSON"
printf '}\n' >> "$RUN_JSON"

echo "Stone AIR metadata written to: $RUN_JSON"
