#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  tools/run-cairo-proof.sh <tally-input.json> [out-dir]
  tools/run-cairo-proof.sh --circuit <name> [--input <input.json>] [--out-dir <dir>] [--message-index <n>]
  tools/run-cairo-proof.sh --all --tally-input <tally-input.json> [--out-dir <dir>]

Circuits:
  tally
  tally-native
  add-new-key
  process-messages
  process-messages-boundary
  process-messages-boundary-native
  process-message-step
  process-message-coord-key
  process-message-coord-key-native
  process-message-ecdh
  process-message-ecdh-native
  process-message-signature
  process-message-signature-native
  process-message-step-core
  process-deactivate-boundary
  process-deactivate-boundary-native
  process-deactivate-step
  process-deactivate-coord-key
  process-deactivate-coord-key-native
  process-deactivate-ecdh-command
  process-deactivate-ecdh-leaf
  process-deactivate-ecdh-command-native
  process-deactivate-ecdh-leaf-native
  process-deactivate-signature
  process-deactivate-signature-native
  process-deactivate-decrypt-current
  process-deactivate-decrypt-new
  process-deactivate-decrypt-current-native
  process-deactivate-decrypt-new-native
  process-deactivate-step-core
  process-deactivate

Notes:
  - The legacy positional form runs only the tally proof.
  - tally and tally-native require an input JSON.
  - add-new-key, process-messages, process-messages-boundary,
    process-messages-boundary-native,
    process-message-step, process-message-*, and process-deactivate generate the current small
    synthetic fixture when --input is omitted.
  - process-message-step, process-message-ecdh, process-message-signature,
    process-message-step-core, process-deactivate-step,
    process-deactivate-ecdh-*, process-deactivate-signature*,
    process-deactivate-decrypt-*, and process-deactivate-step-core require --message-index
    0..4 and prove one linked message step.
  - --all runs tally plus the three small synthetic circuit proofs.

Flow per circuit:
  1. Prepare canonical Cairo arguments.
  2. Run scarb prove --execute for the selected executable.
  3. Run scarb verify for the generated execution id.
  4. Write proof metadata under the output directory.

This uses the local Scarb/Stwo proof flow. Integrity/Stone proof serialization
and Starknet FactRegistry submission are separate integration steps.
EOF
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required" >&2
    exit 1
  fi
}

prepare_circuit_name() {
  case "$1" in
    tally) echo "tally" ;;
    tally-native) echo "tally-native" ;;
    add-new-key) echo "add-new-key" ;;
    process-messages) echo "process-messages-stateful-ecdh-signature" ;;
    process-messages-boundary) echo "process-messages-boundary" ;;
    process-messages-boundary-native) echo "process-messages-boundary-native" ;;
    process-message-step) echo "process-message-step-ecdh-signature" ;;
    process-message-coord-key) echo "process-message-coord-key" ;;
    process-message-coord-key-native) echo "process-message-coord-key-native" ;;
    process-message-ecdh) echo "process-message-ecdh" ;;
    process-message-ecdh-native) echo "process-message-ecdh-native" ;;
    process-message-signature) echo "process-message-signature" ;;
    process-message-signature-native) echo "process-message-signature-native" ;;
    process-message-step-core) echo "process-message-step-core" ;;
    process-deactivate-boundary) echo "process-deactivate-boundary" ;;
    process-deactivate-boundary-native) echo "process-deactivate-boundary-native" ;;
    process-deactivate-step) echo "process-deactivate-step" ;;
    process-deactivate-coord-key) echo "process-deactivate-coord-key" ;;
    process-deactivate-coord-key-native) echo "process-deactivate-coord-key-native" ;;
    process-deactivate-ecdh-command) echo "process-deactivate-ecdh-command" ;;
    process-deactivate-ecdh-leaf) echo "process-deactivate-ecdh-leaf" ;;
    process-deactivate-ecdh-command-native) echo "process-deactivate-ecdh-command-native" ;;
    process-deactivate-ecdh-leaf-native) echo "process-deactivate-ecdh-leaf-native" ;;
    process-deactivate-signature) echo "process-deactivate-signature" ;;
    process-deactivate-signature-native) echo "process-deactivate-signature-native" ;;
    process-deactivate-decrypt-current) echo "process-deactivate-decrypt-current" ;;
    process-deactivate-decrypt-new) echo "process-deactivate-decrypt-new" ;;
    process-deactivate-decrypt-current-native) echo "process-deactivate-decrypt-current-native" ;;
    process-deactivate-decrypt-new-native) echo "process-deactivate-decrypt-new-native" ;;
    process-deactivate-step-core) echo "process-deactivate-step-core" ;;
    process-deactivate) echo "process-deactivate-stateful" ;;
    *) echo "unsupported circuit: $1" >&2; exit 1 ;;
  esac
}

executable_name() {
  case "$1" in
    tally) echo "tally_votes" ;;
    tally-native) echo "tally_votes_native" ;;
    add-new-key) echo "add_new_key" ;;
    process-messages) echo "process_messages_stateful_with_ecdh_signature" ;;
    process-messages-boundary) echo "process_messages_boundary" ;;
    process-messages-boundary-native) echo "process_messages_native_boundary" ;;
    process-message-step) echo "process_message_step_with_ecdh_signature" ;;
    process-message-coord-key) echo "process_message_coord_key" ;;
    process-message-coord-key-native) echo "process_message_coord_key_native" ;;
    process-message-ecdh) echo "process_message_ecdh" ;;
    process-message-ecdh-native) echo "process_message_ecdh_native" ;;
    process-message-signature) echo "process_message_signature" ;;
    process-message-signature-native) echo "process_message_signature_native" ;;
    process-message-step-core) echo "process_message_step_core" ;;
    process-deactivate-boundary) echo "process_deactivate_messages_boundary" ;;
    process-deactivate-boundary-native) echo "process_deactivate_native_boundary" ;;
    process-deactivate-step) echo "process_deactivate_message_step" ;;
    process-deactivate-coord-key) echo "process_deactivate_coord_key" ;;
    process-deactivate-coord-key-native) echo "process_deactivate_coord_key_native" ;;
    process-deactivate-ecdh-command) echo "process_deactivate_ecdh" ;;
    process-deactivate-ecdh-leaf) echo "process_deactivate_ecdh" ;;
    process-deactivate-ecdh-command-native) echo "process_deactivate_ecdh_native" ;;
    process-deactivate-ecdh-leaf-native) echo "process_deactivate_ecdh_native" ;;
    process-deactivate-signature) echo "process_deactivate_signature" ;;
    process-deactivate-signature-native) echo "process_deactivate_signature_native" ;;
    process-deactivate-decrypt-current) echo "process_deactivate_decrypt" ;;
    process-deactivate-decrypt-new) echo "process_deactivate_decrypt" ;;
    process-deactivate-decrypt-current-native) echo "process_deactivate_decrypt_native" ;;
    process-deactivate-decrypt-new-native) echo "process_deactivate_decrypt_native" ;;
    process-deactivate-step-core) echo "process_deactivate_step_core" ;;
    process-deactivate) echo "process_deactivate_messages_stateful" ;;
    *) echo "unsupported circuit: $1" >&2; exit 1 ;;
  esac
}

can_generate_fixture() {
  case "$1" in
    add-new-key|process-messages|process-messages-boundary|process-messages-boundary-native|process-message-step|process-message-coord-key|process-message-coord-key-native|process-message-ecdh|process-message-ecdh-native|process-message-signature|process-message-signature-native|process-message-step-core|process-deactivate-boundary|process-deactivate-boundary-native|process-deactivate-step|process-deactivate-coord-key|process-deactivate-coord-key-native|process-deactivate-ecdh-command|process-deactivate-ecdh-leaf|process-deactivate-ecdh-command-native|process-deactivate-ecdh-leaf-native|process-deactivate-signature|process-deactivate-signature-native|process-deactivate-decrypt-current|process-deactivate-decrypt-new|process-deactivate-decrypt-current-native|process-deactivate-decrypt-new-native|process-deactivate-step-core|process-deactivate) return 0 ;;
    *) return 1 ;;
  esac
}

latest_execution_id() {
  find target/execute/zkstark_amaci_tally -maxdepth 1 -type d -name 'execution*' \
    | sed 's|.*/execution||' \
    | sort -n \
    | tail -1
}

write_metadata() {
  local metadata_json="$1"
  local circuit="$2"
  local prepare_circuit="$3"
  local executable="$4"
  local generated_input="$5"
  local input_path="$6"
  local execution_id="$7"
  local proof_json="$8"
  local prepared_json="$9"
  local cairo_input_json="${10}"
  local cairo_args_json="${11}"
  local prove_log="${12}"
  local verify_log="${13}"
  local message_index="${14}"

  printf '{\n' > "$metadata_json"
  printf '  "circuit": "%s",\n' "$circuit" >> "$metadata_json"
  printf '  "prepareCircuit": "%s",\n' "$prepare_circuit" >> "$metadata_json"
  printf '  "executable": "%s",\n' "$executable" >> "$metadata_json"
  printf '  "generatedInput": %s,\n' "$generated_input" >> "$metadata_json"
  if [[ -n "$message_index" ]]; then
    printf '  "messageIndex": %s,\n' "$message_index" >> "$metadata_json"
  fi
  printf '  "inputPath": "%s",\n' "$input_path" >> "$metadata_json"
  printf '  "executionId": "%s",\n' "$execution_id" >> "$metadata_json"
  printf '  "proofProducer": "scarb-stwo-local",\n' >> "$metadata_json"
  printf '  "integritySubmissionReady": false,\n' >> "$metadata_json"
  printf '  "proofJson": "%s",\n' "$proof_json" >> "$metadata_json"
  printf '  "preparedJson": "%s",\n' "$prepared_json" >> "$metadata_json"
  printf '  "cairoInputJson": "%s",\n' "$cairo_input_json" >> "$metadata_json"
  printf '  "cairoArgsJson": "%s",\n' "$cairo_args_json" >> "$metadata_json"
  printf '  "proveLog": "%s",\n' "$prove_log" >> "$metadata_json"
  printf '  "verifyLog": "%s"\n' "$verify_log" >> "$metadata_json"
  printf '}\n' >> "$metadata_json"
}

run_one() {
  local circuit="$1"
  local input_path="$2"
  local out_dir="$3"
  local message_index="${4:-}"

  local prepare_circuit
  local executable
  prepare_circuit="$(prepare_circuit_name "$circuit")"
  executable="$(executable_name "$circuit")"

  mkdir -p "$out_dir"
  out_dir="$(cd "$out_dir" && pwd)"

  local generated_input=false
  if [[ -z "$input_path" ]]; then
    if can_generate_fixture "$circuit"; then
      input_path="$out_dir/$circuit-small-input.json"
      local fixture_circuit="$circuit"
      if [[ "$circuit" == "process-messages-boundary" || "$circuit" == "process-messages-boundary-native" || "$circuit" == "process-message-step" || "$circuit" == process-message-* ]]; then
        fixture_circuit="process-messages"
      elif [[ "$circuit" == "process-deactivate-boundary" || "$circuit" == "process-deactivate-boundary-native" || "$circuit" == "process-deactivate-step" || "$circuit" == process-deactivate-* ]]; then
        fixture_circuit="process-deactivate"
      fi
      node "$ROOT_DIR/tools/write-small-fixture.mjs" --circuit "$fixture_circuit" --out "$input_path"
      generated_input=true
    else
      echo "$circuit requires --input" >&2
      exit 1
    fi
  fi

  input_path="$(cd "$(dirname "$input_path")" && pwd)/$(basename "$input_path")"

  local prepared_json="$out_dir/$circuit-prepared.json"
  local cairo_input_json="$out_dir/$circuit-cairo-input.json"
  local cairo_args_json="$out_dir/$circuit-cairo-args.json"
  local prove_log="$out_dir/$circuit-prove.log"
  local verify_log="$out_dir/$circuit-verify.log"
  local metadata_json="$out_dir/proof-run.json"

  if [[ "$circuit" == "process-message-step" || "$circuit" == "process-message-ecdh" || "$circuit" == "process-message-ecdh-native" || "$circuit" == "process-message-signature" || "$circuit" == "process-message-signature-native" || "$circuit" == "process-message-step-core" || "$circuit" == "process-deactivate-step" || "$circuit" == "process-deactivate-ecdh-command" || "$circuit" == "process-deactivate-ecdh-leaf" || "$circuit" == "process-deactivate-ecdh-command-native" || "$circuit" == "process-deactivate-ecdh-leaf-native" || "$circuit" == "process-deactivate-signature" || "$circuit" == "process-deactivate-signature-native" || "$circuit" == "process-deactivate-decrypt-current" || "$circuit" == "process-deactivate-decrypt-new" || "$circuit" == "process-deactivate-decrypt-current-native" || "$circuit" == "process-deactivate-decrypt-new-native" || "$circuit" == "process-deactivate-step-core" ]]; then
    if [[ -z "$message_index" ]]; then
      echo "$circuit requires --message-index" >&2
      exit 1
    fi
    if ! [[ "$message_index" =~ ^[0-4]$ ]]; then
      echo "--message-index must be an integer in [0, 4]" >&2
      exit 1
    fi
  fi

  echo "==> Preparing $circuit"
  local prepare_args=(
    "$ROOT_DIR/tools/prepare-amaci-circuit-input.mjs"
    --circuit "$prepare_circuit"
    "$input_path"
    --out "$prepared_json"
    --cairo-input-out "$cairo_input_json"
    --cairo-args-out "$cairo_args_json"
  )
  if [[ -n "$message_index" ]]; then
    prepare_args+=(--message-index "$message_index")
  fi
  node "${prepare_args[@]}"

  echo "==> Proving $circuit with executable $executable"
  (
    cd "$ROOT_DIR/cairo"
    scarb prove \
      --execute \
      --executable-name "$executable" \
      --arguments-file "$cairo_args_json" \
      --print-program-output \
      2>&1 | tee "$prove_log"

    local execution_id
    execution_id="$(latest_execution_id)"
    if [[ -z "$execution_id" ]]; then
      echo "could not find generated execution id for $circuit" >&2
      exit 1
    fi

    echo "==> Verifying $circuit execution $execution_id"
    scarb verify --execution-id "$execution_id" 2>&1 | tee "$verify_log"

    local proof_json="$ROOT_DIR/cairo/target/execute/zkstark_amaci_tally/execution$execution_id/proof/proof.json"
    write_metadata \
      "$metadata_json" \
      "$circuit" \
      "$prepare_circuit" \
      "$executable" \
      "$generated_input" \
      "$input_path" \
      "$execution_id" \
      "$proof_json" \
      "$prepared_json" \
      "$cairo_input_json" \
      "$cairo_args_json" \
      "$prove_log" \
      "$verify_log" \
      "$message_index"
  )

  echo "Proof metadata written to: $metadata_json"
}

require_tool node
require_tool scarb

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ $# -ge 1 && "${1:0:1}" != "-" ]]; then
  if [[ $# -lt 1 || $# -gt 2 ]]; then
    usage >&2
    exit 1
  fi
  run_one "tally" "$1" "${2:-$ROOT_DIR/target/cairo-proof/tally}"
  exit 0
fi

MODE="single"
CIRCUIT=""
INPUT_PATH=""
TALLY_INPUT=""
OUT_DIR=""
MESSAGE_INDEX=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)
      MODE="all"
      shift
      ;;
    --circuit)
      CIRCUIT="${2:-}"
      shift 2
      ;;
    --input)
      INPUT_PATH="${2:-}"
      shift 2
      ;;
    --tally-input)
      TALLY_INPUT="${2:-}"
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
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$MODE" == "all" ]]; then
  if [[ -z "$TALLY_INPUT" ]]; then
    echo "--all requires --tally-input" >&2
    usage >&2
    exit 1
  fi
  OUT_DIR="${OUT_DIR:-$ROOT_DIR/target/cairo-proof/all}"
  mkdir -p "$OUT_DIR"
  OUT_DIR="$(cd "$OUT_DIR" && pwd)"

  run_one "tally" "$TALLY_INPUT" "$OUT_DIR/tally"
  run_one "add-new-key" "" "$OUT_DIR/add-new-key"
  run_one "process-messages" "" "$OUT_DIR/process-messages"
  run_one "process-deactivate" "" "$OUT_DIR/process-deactivate"

  printf '{\n' > "$OUT_DIR/all-proofs.json"
  printf '  "tally": "%s",\n' "$OUT_DIR/tally/proof-run.json" >> "$OUT_DIR/all-proofs.json"
  printf '  "addNewKey": "%s",\n' "$OUT_DIR/add-new-key/proof-run.json" >> "$OUT_DIR/all-proofs.json"
  printf '  "processMessages": "%s",\n' "$OUT_DIR/process-messages/proof-run.json" >> "$OUT_DIR/all-proofs.json"
  printf '  "processDeactivate": "%s"\n' "$OUT_DIR/process-deactivate/proof-run.json" >> "$OUT_DIR/all-proofs.json"
  printf '}\n' >> "$OUT_DIR/all-proofs.json"
  echo "All proof metadata written to: $OUT_DIR/all-proofs.json"
  exit 0
fi

if [[ -z "$CIRCUIT" ]]; then
  echo "--circuit is required unless using --all or legacy tally form" >&2
  usage >&2
  exit 1
fi

run_one "$CIRCUIT" "$INPUT_PATH" "${OUT_DIR:-$ROOT_DIR/target/cairo-proof/$CIRCUIT}" "$MESSAGE_INDEX"
