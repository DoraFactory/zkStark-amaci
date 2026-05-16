#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  tools/run-stone-air.sh --circuit <native-circuit> [--input <input.json>] [--out-dir <dir>] [--message-index <n>] [--layout <layout>]
  tools/run-stone-air.sh --circuit tally [--input <tally-input.json>] [--out-dir <dir>] [--layout <layout>]

Generates Stone AIR input files for a Cairo proof-mode executable. This does
not run cpu_air_prover yet.

Supported native circuits:
  tally-native
  add-new-key-native
  process-messages-boundary-native
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

Legacy compatibility:
  tally

Default layout:
  native circuits: recursive_with_poseidon
  tally: recursive

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
LAYOUT=""
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
    --layout)
      LAYOUT="${2:-}"
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

is_supported_circuit() {
  case "$1" in
    tally|tally-native|add-new-key-native|process-messages-boundary-native|process-message-coord-key-native|process-message-ecdh-native|process-message-decrypt-native|process-message-signature-native|process-message-step-core-native|process-deactivate-boundary-native|process-deactivate-coord-key-native|process-deactivate-ecdh-command-native|process-deactivate-ecdh-leaf-native|process-deactivate-signature-native|process-deactivate-decrypt-current-native|process-deactivate-decrypt-new-native|process-deactivate-step-core-native) return 0 ;;
    *) return 1 ;;
  esac
}

is_message_index_circuit() {
  case "$1" in
    process-message-ecdh-native|process-message-decrypt-native|process-message-signature-native|process-message-step-core-native|process-deactivate-ecdh-command-native|process-deactivate-ecdh-leaf-native|process-deactivate-signature-native|process-deactivate-decrypt-current-native|process-deactivate-decrypt-new-native|process-deactivate-step-core-native) return 0 ;;
    *) return 1 ;;
  esac
}

prepare_circuit_name() {
  case "$1" in
    tally) echo "tally" ;;
    tally-native) echo "tally-native" ;;
    add-new-key-native) echo "add-new-key-native" ;;
    process-messages-boundary-native) echo "process-messages-boundary-native" ;;
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
    *) echo "unsupported circuit: $1" >&2; exit 1 ;;
  esac
}

source_executable_name() {
  case "$1" in
    tally) echo "tally_votes" ;;
    tally-native) echo "tally_votes_native" ;;
    add-new-key-native) echo "add_new_key_native" ;;
    process-messages-boundary-native) echo "process_messages_native_boundary" ;;
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
    *) echo "unsupported circuit: $1" >&2; exit 1 ;;
  esac
}

fixture_circuit_name() {
  case "$1" in
    add-new-key-native) echo "add-new-key" ;;
    process-messages-boundary-native|process-message-*) echo "process-messages" ;;
    process-deactivate-boundary-native|process-deactivate-*) echo "process-deactivate" ;;
    *) echo "" ;;
  esac
}

wrapper_imports() {
  case "$1" in
    tally)
      cat <<'EOF'
use crate::public_output::{TallyPublicFields, TallyPublicOutput};
use crate::tally_votes::{TallyWitness, main as target_main};
EOF
      ;;
    tally-native)
      cat <<'EOF'
use crate::native_tally_votes::{
    TallyNativePublicFields as FieldsType, TallyNativeWitness as WitnessType,
    TallyNativePublicOutput as OutputType, main as target_main,
};
EOF
      ;;
    add-new-key-native)
      cat <<'EOF'
use crate::add_new_key::{
    NativeAddNewKeyPublicFields as FieldsType, NativeAddNewKeyWitness as WitnessType,
    NativeAddNewKeyPublicOutput as OutputType, add_new_key_native_main as target_main,
};
EOF
      ;;
    process-messages-boundary-native)
      cat <<'EOF'
use crate::native_process_messages::{
    ProcessMessagesNativePublicFields as FieldsType,
    ProcessMessagesNativeBoundaryWitness as WitnessType,
    ProcessMessagesNativePublicOutput as OutputType,
    process_messages_native_boundary_main as target_main,
};
EOF
      ;;
    process-message-coord-key-native)
      cat <<'EOF'
use crate::process_messages::{
    NativeProcessMessageCoordKeyPublicFields as FieldsType,
    NativeProcessMessageCoordKeyWitness as WitnessType,
    NativeProcessMessageCoordKeyPublicOutput as OutputType,
    process_message_coord_key_native_main as target_main,
};
EOF
      ;;
    process-message-ecdh-native)
      cat <<'EOF'
use crate::process_messages::{
    NativeProcessMessageEcdhPublicFields as FieldsType,
    NativeProcessMessageEcdhWitness as WitnessType,
    NativeProcessMessageEcdhPublicOutput as OutputType,
    process_message_ecdh_native_main as target_main,
};
EOF
      ;;
    process-message-decrypt-native)
      cat <<'EOF'
use crate::process_messages::{
    NativeProcessMessageDecryptPublicFields as FieldsType,
    NativeProcessMessageDecryptWitness as WitnessType,
    NativeProcessMessageDecryptPublicOutput as OutputType,
    process_message_decrypt_native_main as target_main,
};
EOF
      ;;
    process-message-signature-native)
      cat <<'EOF'
use crate::process_messages::{
    NativeProcessMessageSignaturePublicFields as FieldsType,
    NativeProcessMessageSignatureWitness as WitnessType,
    NativeProcessMessageSignaturePublicOutput as OutputType,
    process_message_signature_native_main as target_main,
};
EOF
      ;;
    process-message-step-core-native)
      cat <<'EOF'
use crate::process_messages::{
    NativeProcessMessageStepCorePublicFields as FieldsType,
    NativeProcessMessageStepCoreWitness as WitnessType,
    NativeProcessMessageStepCorePublicOutput as OutputType,
    process_message_step_core_native_main as target_main,
};
EOF
      ;;
    process-deactivate-boundary-native)
      cat <<'EOF'
use crate::native_process_deactivate::{
    ProcessDeactivateNativePublicFields as FieldsType,
    ProcessDeactivateNativeBoundaryWitness as WitnessType,
    ProcessDeactivateNativePublicOutput as OutputType,
    process_deactivate_native_boundary_main as target_main,
};
EOF
      ;;
    process-deactivate-coord-key-native)
      cat <<'EOF'
use crate::process_deactivate::{
    NativeProcessDeactivateCoordKeyPublicFields as FieldsType,
    NativeProcessDeactivateCoordKeyWitness as WitnessType,
    NativeProcessDeactivateCoordKeyPublicOutput as OutputType,
    process_deactivate_coord_key_native_main as target_main,
};
EOF
      ;;
    process-deactivate-ecdh-command-native|process-deactivate-ecdh-leaf-native)
      cat <<'EOF'
use crate::process_deactivate::{
    NativeProcessDeactivateEcdhPublicFields as FieldsType,
    NativeProcessDeactivateEcdhWitness as WitnessType,
    NativeProcessDeactivateEcdhPublicOutput as OutputType,
    process_deactivate_ecdh_native_main as target_main,
};
EOF
      ;;
    process-deactivate-signature-native)
      cat <<'EOF'
use crate::process_deactivate::{
    NativeProcessDeactivateSignaturePublicFields as FieldsType,
    NativeProcessDeactivateSignatureWitness as WitnessType,
    NativeProcessDeactivateSignaturePublicOutput as OutputType,
    process_deactivate_signature_native_main as target_main,
};
EOF
      ;;
    process-deactivate-decrypt-current-native|process-deactivate-decrypt-new-native)
      cat <<'EOF'
use crate::process_deactivate::{
    NativeProcessDeactivateDecryptPublicFields as FieldsType,
    NativeProcessDeactivateDecryptWitness as WitnessType,
    NativeProcessDeactivateDecryptPublicOutput as OutputType,
    process_deactivate_decrypt_native_main as target_main,
};
EOF
      ;;
    process-deactivate-step-core-native)
      cat <<'EOF'
use crate::process_deactivate::{
    NativeProcessDeactivateStepCorePublicFields as FieldsType,
    NativeProcessDeactivateStepCoreWitness as WitnessType,
    NativeProcessDeactivateStepCorePublicOutput as OutputType,
    process_deactivate_step_core_native_main as target_main,
};
EOF
      ;;
    *) echo "unsupported circuit: $1" >&2; exit 1 ;;
  esac
}

write_stone_wrapper() {
  local circuit="$1"
  local wrapper_file="$2"

  if [[ "$circuit" == "tally" ]]; then
    {
      wrapper_imports "$circuit"
      cat <<'EOF'

#[executable]
pub fn stone_main(input: Array<felt252>) -> Array<felt252> {
    let mut serialized = input.span();
    let fields: TallyPublicFields = Serde::<TallyPublicFields>::deserialize(ref serialized)
        .expect('STONE_FIELDS');
    let witness: TallyWitness = Serde::<TallyWitness>::deserialize(ref serialized)
        .expect('STONE_WITNESS');
    assert(serialized.len() == 0, 'STONE_ARGS');

    let output: TallyPublicOutput = target_main(fields, witness);
    let mut serialized_output = array![];
    output.serialize(ref serialized_output);
    serialized_output
}
EOF
    } > "$wrapper_file"
  else
    {
      wrapper_imports "$circuit"
      cat <<'EOF'

#[executable]
pub fn stone_main(input: Array<felt252>) -> Array<felt252> {
    let mut serialized = input.span();
    let fields: FieldsType = Serde::<FieldsType>::deserialize(ref serialized)
        .expect('STONE_FIELDS');
    let witness: WitnessType = Serde::<WitnessType>::deserialize(ref serialized)
        .expect('STONE_WITNESS');
    assert(serialized.len() == 0, 'STONE_ARGS');

    let output: OutputType = target_main(fields, witness);
    let mut serialized_output = array![];
    output.serialize(ref serialized_output);
    serialized_output
}
EOF
    } > "$wrapper_file"
  fi
}

if ! is_supported_circuit "$CIRCUIT"; then
  echo "--circuit must be one of the supported native circuits or tally" >&2
  usage >&2
  exit 1
fi

if is_message_index_circuit "$CIRCUIT"; then
  if [[ -z "$MESSAGE_INDEX" ]]; then
    echo "$CIRCUIT requires --message-index" >&2
    exit 1
  fi
  if ! [[ "$MESSAGE_INDEX" =~ ^[0-4]$ ]]; then
    echo "--message-index must be an integer in [0, 4]" >&2
    exit 1
  fi
fi

if [[ -z "$LAYOUT" ]]; then
  if [[ "$CIRCUIT" == "tally" ]]; then
    LAYOUT="recursive"
  else
    LAYOUT="recursive_with_poseidon"
  fi
fi

if [[ "$CIRCUIT" != "tally" ]]; then
  if [[ "$LAYOUT" != "recursive_with_poseidon" ]]; then
    echo "layout '$LAYOUT' is not compatible with native Stone AIR" >&2
    echo "native AMACI circuits use the Starknet Poseidon builtin; use --layout recursive_with_poseidon" >&2
    exit 1
  fi
else
  case "$LAYOUT" in
    plain|small|dex)
      echo "layout '$LAYOUT' does not provide the Bitwise builtin required by tally_votes_stone" >&2
      echo "use --layout recursive" >&2
      exit 1
      ;;
    all_cairo|all_cairo_stwo)
      echo "layout '$LAYOUT' is not compatible with the legacy Stone tally path" >&2
      echo "it requires add_mod/mul_mod AIR segments that this Cairo runner does not emit" >&2
      echo "use --layout recursive" >&2
      exit 1
      ;;
  esac
fi

if [[ -z "$INPUT_PATH" ]]; then
  case "$CIRCUIT" in
    tally|tally-native)
      INPUT_PATH="$ROOT_DIR/fixtures/tally-small/000000.json"
      ;;
  esac
fi
OUT_DIR="${OUT_DIR:-$ROOT_DIR/target/stone-air/$CIRCUIT}"

require_tool node
require_tool scarb
require_tool cairo1-run

PREPARE_CIRCUIT="$(prepare_circuit_name "$CIRCUIT")"
SOURCE_EXECUTABLE_NAME="$(source_executable_name "$CIRCUIT")"
STONE_PACKAGE_NAME="zkstark_amaci_$(printf '%s' "$CIRCUIT" | tr '-' '_')_stone"
STONE_EXECUTABLE_NAME="${SOURCE_EXECUTABLE_NAME}_stone"
STONE_ENTRY_MODULE="stone_entry"
STONE_ENTRY_FUNCTION="stone_main"
case "$CIRCUIT" in
  tally-native)
    STONE_MODULES=(native_tally_votes "$STONE_ENTRY_MODULE")
    ;;
  tally)
    STONE_MODULES=(
      hash_gates
      poseidon_bn254
      poseidon_constants
      public_output
      sha256_u256
      tally_votes
      types
      "$STONE_ENTRY_MODULE"
    )
    ;;
  process-messages-boundary-native)
    STONE_MODULES=(native_process_messages "$STONE_ENTRY_MODULE")
    ;;
  process-deactivate-boundary-native)
    STONE_MODULES=(native_process_deactivate "$STONE_ENTRY_MODULE")
    ;;
  add-new-key-native)
    STONE_MODULES=(
      add_new_key
      babyjub
      hash_gates
      poseidon_bn254
      poseidon_constants
      public_output
      sha256_u256
      types
      "$STONE_ENTRY_MODULE"
    )
    ;;
  process-message-*)
    STONE_MODULES=(
      babyjub
      hash_gates
      poseidon_bn254
      poseidon_constants
      process_messages
      public_output
      sha256_u256
      types
      "$STONE_ENTRY_MODULE"
    )
    ;;
  process-deactivate-*)
    STONE_MODULES=(
      babyjub
      hash_gates
      poseidon_bn254
      poseidon_constants
      process_deactivate
      public_output
      sha256_u256
      types
      "$STONE_ENTRY_MODULE"
    )
    ;;
  *)
    echo "unsupported circuit: $CIRCUIT" >&2
    exit 1
    ;;
esac

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
GENERATED_INPUT=false
if [[ -z "$INPUT_PATH" ]]; then
  FIXTURE_CIRCUIT="$(fixture_circuit_name "$CIRCUIT")"
  if [[ -z "$FIXTURE_CIRCUIT" ]]; then
    echo "$CIRCUIT requires --input" >&2
    exit 1
  fi
  INPUT_PATH="$OUT_DIR/$CIRCUIT-small-input.json"
  node "$ROOT_DIR/tools/write-small-fixture.mjs" --circuit "$FIXTURE_CIRCUIT" --out "$INPUT_PATH"
  GENERATED_INPUT=true
fi
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
STONE_PACKAGE_DIR="$OUT_DIR/cairo-stone-package"
EXECUTABLE_JSON="$STONE_PACKAGE_DIR/target/dev/$STONE_EXECUTABLE_NAME.executable.json"
PACKAGE_SIERRA_JSON="$STONE_PACKAGE_DIR/target/dev/$STONE_PACKAGE_NAME.sierra.json"
RUNNER_SIERRA_JSON="$OUT_DIR/$STONE_EXECUTABLE_NAME.cairo1-run.sierra.json"
CORELIB_DIR="$(detect_cairo_corelib_dir || true)"

if [[ -z "$CORELIB_DIR" ]]; then
  cat >&2 <<'EOF'
cairo1-run could not find a Cairo development corelib.

Set CAIRO_CORELIB_DIR to the corelib directory built with cairo-vm, for example:
  CAIRO_CORELIB_DIR=~/cairo-vm/cairo1-run/corelib npm run stone:air:tally -- --out-dir ~/zkstark-amaci-proofs/stone-tally-native

If that directory does not exist, run the cairo-vm dependency setup first:
  cd ~/cairo-vm/cairo1-run && make deps
EOF
  exit 1
fi

CORELIB_PARENT="$(cd "$CORELIB_DIR/.." && pwd)"

echo "==> Preparing $CIRCUIT input"
PREPARE_ARGS=(
  "$ROOT_DIR/tools/prepare-amaci-circuit-input.mjs"
  --circuit "$PREPARE_CIRCUIT"
  "$INPUT_PATH" \
  --out "$PREPARED_JSON" \
  --cairo-input-out "$CAIRO_INPUT_JSON" \
  --cairo-args-out "$SCARB_ARGS_JSON"
)
if [[ -n "$MESSAGE_INDEX" ]]; then
  PREPARE_ARGS+=(--message-index "$MESSAGE_INDEX")
fi
node "${PREPARE_ARGS[@]}"

echo "==> Converting args for cairo1-run proof mode"
node "$ROOT_DIR/tools/convert-cairo1-run-args.mjs" \
  "$SCARB_ARGS_JSON" \
  --out "$CAIRO1_ARGS_TXT" \
  --text

echo "==> Building minimal Stone Cairo package"
rm -rf "$STONE_PACKAGE_DIR"
mkdir -p "$STONE_PACKAGE_DIR/src"
{
  printf '[package]\n'
  printf 'name = "%s"\n' "$STONE_PACKAGE_NAME"
  printf 'version = "0.1.0"\n'
  printf 'edition = "2024_07"\n'
  printf '\n[cairo]\n'
  printf 'enable-gas = false\n'
  printf '\n[dependencies]\n'
  printf 'cairo_execute = "2.18.0"\n'
  printf '\n[lib]\n'
  printf 'sierra = true\n'
  printf 'casm = true\n'
  printf '\n[[target.executable]]\n'
  printf 'name = "%s"\n' "$STONE_EXECUTABLE_NAME"
  printf 'function = "%s::%s::%s"\n' "$STONE_PACKAGE_NAME" "$STONE_ENTRY_MODULE" "$STONE_ENTRY_FUNCTION"
} > "$STONE_PACKAGE_DIR/Scarb.toml"

{
  for module in "${STONE_MODULES[@]}"; do
    printf 'mod %s;\n' "$module"
  done
} > "$STONE_PACKAGE_DIR/src/lib.cairo"

for module in "${STONE_MODULES[@]}"; do
  if [[ "$module" == "$STONE_ENTRY_MODULE" ]]; then
    write_stone_wrapper "$CIRCUIT" "$STONE_PACKAGE_DIR/src/$module.cairo"
  else
    cp "$ROOT_DIR/cairo/src/$module.cairo" "$STONE_PACKAGE_DIR/src/$module.cairo"
  fi
done

(
  cd "$STONE_PACKAGE_DIR"
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
  --function "$STONE_PACKAGE_NAME::$STONE_ENTRY_MODULE::$STONE_ENTRY_FUNCTION" \
  --main-name "$STONE_PACKAGE_NAME::$STONE_ENTRY_MODULE::main" \
  --out "$RUNNER_SIERRA_JSON"

echo "==> Running cairo1-run proof mode for $CIRCUIT"
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
printf '  "circuit": "%s",\n' "$CIRCUIT" >> "$RUN_JSON"
printf '  "prepareCircuit": "%s",\n' "$PREPARE_CIRCUIT" >> "$RUN_JSON"
printf '  "sourceExecutable": "%s",\n' "$SOURCE_EXECUTABLE_NAME" >> "$RUN_JSON"
printf '  "stoneExecutable": "%s",\n' "$STONE_EXECUTABLE_NAME" >> "$RUN_JSON"
printf '  "executable": "%s",\n' "$EXECUTABLE_JSON" >> "$RUN_JSON"
printf '  "generatedInput": %s,\n' "$GENERATED_INPUT" >> "$RUN_JSON"
if [[ -n "$MESSAGE_INDEX" ]]; then
  printf '  "messageIndex": %s,\n' "$MESSAGE_INDEX" >> "$RUN_JSON"
fi
printf '  "stonePackageDir": "%s",\n' "$STONE_PACKAGE_DIR" >> "$RUN_JSON"
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
