#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  tools/run-cairo-proof.sh --circuit <native-name> [--input <input.json>] [--out-dir <dir>] [--message-index <n>]

Native circuits:
  tally-native
  add-new-key-native
  process-messages-boundary-native
  process-messages-stage-native
  process-message-coord-key-native
  process-message-ecdh-native
  process-message-decrypt-native
  process-message-signature-native
  process-message-step-core-native
  process-deactivate-boundary-native
  process-deactivate-coord-key-native
  process-deactivate-ecdh-command-native
  process-deactivate-ecdh-leaf-native
  process-deactivate-signature-native
  process-deactivate-decrypt-current-native
  process-deactivate-decrypt-new-native
  process-deactivate-step-core-native

Notes:
  - Only Starknet-native AMACI circuits are supported.
  - tally-native requires an input JSON.
  - The other native circuits can generate the current small synthetic fixture
    when --input is omitted.
  - ProcessMessages per-message circuits require --message-index 0..2.
  - ProcessDeactivate per-message circuits require --message-index 0..2.

Flow per circuit:
  1. Prepare canonical Cairo arguments.
  2. Run scarb prove --execute for the selected executable.
  3. Run scarb verify for the generated execution id.
  4. Write proof metadata under the output directory.
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
    tally-native) echo "tally-native" ;;
    add-new-key-native) echo "add-new-key-native" ;;
    process-messages-boundary-native) echo "process-messages-boundary-native" ;;
    process-messages-stage-native) echo "process-messages-stage-native" ;;
    process-message-coord-key-native) echo "process-message-coord-key-native" ;;
    process-message-ecdh-native) echo "process-message-ecdh-native" ;;
    process-message-decrypt-native) echo "process-message-decrypt-native" ;;
    process-message-signature-native) echo "process-message-signature-native" ;;
    process-message-step-core-native) echo "process-message-step-core-native" ;;
    process-deactivate-boundary-native) echo "process-deactivate-boundary-native" ;;
    process-deactivate-coord-key-native) echo "process-deactivate-coord-key-native" ;;
    process-deactivate-ecdh-command-native) echo "process-deactivate-ecdh-command-native" ;;
    process-deactivate-ecdh-leaf-native) echo "process-deactivate-ecdh-leaf-native" ;;
    process-deactivate-signature-native) echo "process-deactivate-signature-native" ;;
    process-deactivate-decrypt-current-native) echo "process-deactivate-decrypt-current-native" ;;
    process-deactivate-decrypt-new-native) echo "process-deactivate-decrypt-new-native" ;;
    process-deactivate-step-core-native) echo "process-deactivate-step-core-native" ;;
    *) echo "unsupported native circuit: $1" >&2; exit 1 ;;
  esac
}

executable_name() {
  case "$1" in
    tally-native) echo "tally_votes_native" ;;
    add-new-key-native) echo "add_new_key_native" ;;
    process-messages-boundary-native) echo "process_messages_native_boundary" ;;
    process-messages-stage-native) echo "process_messages_stage_native" ;;
    process-message-coord-key-native) echo "process_message_coord_key_native" ;;
    process-message-ecdh-native) echo "process_message_ecdh_native" ;;
    process-message-decrypt-native) echo "process_message_decrypt_native" ;;
    process-message-signature-native) echo "process_message_signature_native" ;;
    process-message-step-core-native) echo "process_message_step_core_native" ;;
    process-deactivate-boundary-native) echo "process_deactivate_native_boundary" ;;
    process-deactivate-coord-key-native) echo "process_deactivate_coord_key_native" ;;
    process-deactivate-ecdh-command-native|process-deactivate-ecdh-leaf-native) echo "process_deactivate_ecdh_native" ;;
    process-deactivate-signature-native) echo "process_deactivate_signature_native" ;;
    process-deactivate-decrypt-current-native|process-deactivate-decrypt-new-native) echo "process_deactivate_decrypt_native" ;;
    process-deactivate-step-core-native) echo "process_deactivate_step_core_native" ;;
    *) echo "unsupported native circuit: $1" >&2; exit 1 ;;
  esac
}

can_generate_fixture() {
  case "$1" in
    add-new-key-native|process-messages-boundary-native|process-messages-stage-native|process-message-coord-key-native|process-message-ecdh-native|process-message-decrypt-native|process-message-signature-native|process-message-step-core-native|process-deactivate-boundary-native|process-deactivate-coord-key-native|process-deactivate-ecdh-command-native|process-deactivate-ecdh-leaf-native|process-deactivate-signature-native|process-deactivate-decrypt-current-native|process-deactivate-decrypt-new-native|process-deactivate-step-core-native) return 0 ;;
    *) return 1 ;;
  esac
}

requires_message_index() {
  case "$1" in
    process-message-ecdh-native|process-message-decrypt-native|process-message-signature-native|process-message-step-core-native|process-deactivate-ecdh-command-native|process-deactivate-ecdh-leaf-native|process-deactivate-signature-native|process-deactivate-decrypt-current-native|process-deactivate-decrypt-new-native|process-deactivate-step-core-native) return 0 ;;
    *) return 1 ;;
  esac
}

fixture_circuit_name() {
  case "$1" in
    add-new-key-native) echo "add-new-key" ;;
    process-messages-boundary-native|process-messages-stage-native|process-message-*) echo "process-messages" ;;
    process-deactivate-boundary-native|process-deactivate-*) echo "process-deactivate" ;;
    *) echo "" ;;
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
      local fixture_circuit
      fixture_circuit="$(fixture_circuit_name "$circuit")"
      input_path="$out_dir/$circuit-small-input.json"
      node "$ROOT_DIR/tools/write-small-fixture.mjs" --circuit "$fixture_circuit" --out "$input_path"
      generated_input=true
    else
      echo "$circuit requires --input" >&2
      exit 1
    fi
  fi

  input_path="$(cd "$(dirname "$input_path")" && pwd)/$(basename "$input_path")"

  if requires_message_index "$circuit"; then
    if [[ -z "$message_index" ]]; then
      echo "$circuit requires --message-index" >&2
      exit 1
    fi
    local max_message_index=2
    if ! [[ "$message_index" =~ ^[0-9]+$ ]] || (( message_index > max_message_index )); then
      echo "--message-index must be an integer in [0, $max_message_index]" >&2
      exit 1
    fi
  fi

  local prepared_json="$out_dir/$circuit-prepared.json"
  local cairo_input_json="$out_dir/$circuit-cairo-input.json"
  local cairo_args_json="$out_dir/$circuit-cairo-args.json"
  local prove_log="$out_dir/$circuit-prove.log"
  local verify_log="$out_dir/$circuit-verify.log"
  local metadata_json="$out_dir/proof-run.json"

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

run_one "$CIRCUIT" "$INPUT_PATH" "${OUT_DIR:-$ROOT_DIR/target/cairo-proof/$CIRCUIT}" "$MESSAGE_INDEX"
