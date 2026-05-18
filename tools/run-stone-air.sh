#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  tools/run-stone-air.sh --circuit <native-circuit> [--input <input.json>] [--out-dir <dir>] [--message-index <n>] [--layout <layout>] [--skip-cairo1-run]

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

Default layout:
  recursive_with_poseidon

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

Use --skip-cairo1-run to stop after building the Cairo1 runner Sierra and
cairo1-run args file. That mode is enough for Atlantic programFile/inputFile
submission and does not require local cairo1-run/corelib.
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
SKIP_CAIRO1_RUN=false

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
    --skip-cairo1-run|--program-input-only)
      SKIP_CAIRO1_RUN=true
      shift
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
    tally-native|add-new-key-native|process-messages-boundary-native|process-message-coord-key-native|process-message-ecdh-native|process-message-decrypt-native|process-message-signature-native|process-message-step-core-native|process-deactivate-boundary-native|process-deactivate-coord-key-native|process-deactivate-ecdh-command-native|process-deactivate-ecdh-leaf-native|process-deactivate-signature-native|process-deactivate-decrypt-current-native|process-deactivate-decrypt-new-native|process-deactivate-step-core-native) return 0 ;;
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

source_entry_path() {
  case "$1" in
    add-new-key-native) echo "native_add_new_key::add_new_key_native_main" ;;
    process-messages-boundary-native) echo "native_process_messages::process_messages_native_boundary_main" ;;
    process-message-coord-key-native) echo "native_process_message_components::process_message_coord_key_native_main" ;;
    process-message-ecdh-native) echo "native_process_message_components::process_message_ecdh_native_main" ;;
    process-message-decrypt-native) echo "native_process_message_components::process_message_decrypt_native_main" ;;
    process-message-signature-native) echo "native_process_message_components::process_message_signature_native_main" ;;
    process-message-step-core-native) echo "native_process_message_step_core::process_message_step_core_native_main" ;;
    process-deactivate-boundary-native) echo "native_process_deactivate::process_deactivate_native_boundary_main" ;;
    process-deactivate-coord-key-native) echo "native_process_deactivate_components::process_deactivate_coord_key_native_main" ;;
    process-deactivate-ecdh-command-native|process-deactivate-ecdh-leaf-native) echo "native_process_deactivate_components::process_deactivate_ecdh_native_main" ;;
    process-deactivate-signature-native) echo "native_process_deactivate_components::process_deactivate_signature_native_main" ;;
    process-deactivate-decrypt-current-native|process-deactivate-decrypt-new-native) echo "native_process_deactivate_components::process_deactivate_decrypt_native_main" ;;
    process-deactivate-step-core-native) echo "native_process_deactivate_step_core::process_deactivate_step_core_native_main" ;;
    *) echo "unsupported direct Stone circuit: $1" >&2; exit 1 ;;
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
use crate::native_add_new_key::{
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
use crate::native_process_message_components::{
    NativeProcessMessageCoordKeyPublicFields as FieldsType,
    NativeProcessMessageCoordKeyWitness as WitnessType,
    NativeProcessMessageCoordKeyPublicOutput as OutputType,
    process_message_coord_key_native_main as target_main,
};
EOF
      ;;
    process-message-ecdh-native)
      cat <<'EOF'
use crate::native_process_message_components::{
    NativeProcessMessageEcdhPublicFields as FieldsType,
    NativeProcessMessageEcdhWitness as WitnessType,
    NativeProcessMessageEcdhPublicOutput as OutputType,
    process_message_ecdh_native_main as target_main,
};
EOF
      ;;
    process-message-decrypt-native)
      cat <<'EOF'
use crate::native_process_message_components::{
    NativeProcessMessageDecryptPublicFields as FieldsType,
    NativeProcessMessageDecryptWitness as WitnessType,
    NativeProcessMessageDecryptPublicOutput as OutputType,
    process_message_decrypt_native_main as target_main,
};
EOF
      ;;
    process-message-signature-native)
      cat <<'EOF'
use crate::native_process_message_components::{
    NativeProcessMessageSignaturePublicFields as FieldsType,
    NativeProcessMessageSignatureWitness as WitnessType,
    NativeProcessMessageSignaturePublicOutput as OutputType,
    process_message_signature_native_main as target_main,
};
EOF
      ;;
    process-message-step-core-native)
      cat <<'EOF'
use crate::native_process_message_step_core::{
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
use crate::native_process_deactivate_components::{
    NativeProcessDeactivateCoordKeyPublicFields as FieldsType,
    NativeProcessDeactivateCoordKeyWitness as WitnessType,
    NativeProcessDeactivateCoordKeyPublicOutput as OutputType,
    process_deactivate_coord_key_native_main as target_main,
};
EOF
      ;;
    process-deactivate-ecdh-command-native|process-deactivate-ecdh-leaf-native)
      cat <<'EOF'
use crate::native_process_deactivate_components::{
    NativeProcessDeactivateEcdhPublicFields as FieldsType,
    NativeProcessDeactivateEcdhWitness as WitnessType,
    NativeProcessDeactivateEcdhPublicOutput as OutputType,
    process_deactivate_ecdh_native_main as target_main,
};
EOF
      ;;
    process-deactivate-signature-native)
      cat <<'EOF'
use crate::native_process_deactivate_components::{
    NativeProcessDeactivateSignaturePublicFields as FieldsType,
    NativeProcessDeactivateSignatureWitness as WitnessType,
    NativeProcessDeactivateSignaturePublicOutput as OutputType,
    process_deactivate_signature_native_main as target_main,
};
EOF
      ;;
    process-deactivate-decrypt-current-native|process-deactivate-decrypt-new-native)
      cat <<'EOF'
use crate::native_process_deactivate_components::{
    NativeProcessDeactivateDecryptPublicFields as FieldsType,
    NativeProcessDeactivateDecryptWitness as WitnessType,
    NativeProcessDeactivateDecryptPublicOutput as OutputType,
    process_deactivate_decrypt_native_main as target_main,
};
EOF
      ;;
    process-deactivate-step-core-native)
      cat <<'EOF'
use crate::native_process_deactivate_step_core::{
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

write_native_add_new_key_module() {
  local module_file="$1"

  cat > "$module_file" <<'EOF'
use core::hash::HashStateTrait;
use core::poseidon::PoseidonTrait;

const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b;
const DEACTIVATE_TREE_DEPTH: felt252 = 4;
const DEACTIVATE_TREE_LEAVES: u128 = 625;
const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
const ADD_NEW_KEY_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f4144445f4b45595f4e4154495645;
const STARKNET_POSEIDON_HASH_SCHEME: felt252 = 0x535441524b4e45545f504f534549444f4e;
const ADD_NEW_KEY_NATIVE_INPUT_HASH_DOMAIN: felt252 =
    0x414d4143495f4144445f4b45595f4e41544956455f494e505554;
const ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN: felt252 =
    0x414d4143495f4144445f4b45595f4e554c4c4946494552;
const ADD_NEW_KEY_NATIVE_DEACTIVATE_LEAF_DOMAIN: felt252 =
    0x414d4143495f4144445f4b45595f44454143545f4c454146;
const ADD_NEW_KEY_NATIVE_RERANDOMIZE_DOMAIN: felt252 =
    0x414d4143495f4144445f4b45595f524552414e44;
const FELT_TWO_POW_128: felt252 = 0x100000000000000000000000000000000;

#[derive(Copy, Drop, Serde)]
pub struct U256x2 {
    pub v0: u256,
    pub v1: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct U256x4 {
    pub v0: u256,
    pub v1: u256,
    pub v2: u256,
    pub v3: u256,
}

#[derive(Drop, Serde)]
pub struct NativeAddNewKeyWitness {
    pub coord_pub_key: U256x2,
    pub deactivate_index: u256,
    pub c1: U256x2,
    pub c2: U256x2,
    pub shared_key: U256x2,
    pub deactivate_leaf_path_0: U256x4,
    pub deactivate_leaf_path_1: U256x4,
    pub deactivate_leaf_path_2: U256x4,
    pub deactivate_leaf_path_3: U256x4,
    pub old_private_key: u256,
    pub new_pub_key: U256x2,
    pub poll_id: u256,
    pub d1: U256x2,
    pub d2: U256x2,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeAddNewKeyPublicFields {
    pub deactivate_root_hash: felt252,
    pub coord_pub_key_hash: felt252,
    pub nullifier: felt252,
    pub c1_hash: felt252,
    pub c2_hash: felt252,
    pub shared_key_hash: felt252,
    pub deactivate_leaf_hash: felt252,
    pub d1_hash: felt252,
    pub d2_hash: felt252,
    pub rerandomize_binding_hash: felt252,
    pub new_pub_key_hash: felt252,
    pub poll_id: felt252,
    pub input_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeAddNewKeyPublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub hash_scheme: felt252,
    pub state_tree_depth: felt252,
    pub deactivate_tree_depth: felt252,
    pub deactivate_root_hash: felt252,
    pub coord_pub_key_hash: felt252,
    pub nullifier: felt252,
    pub c1_hash: felt252,
    pub c2_hash: felt252,
    pub shared_key_hash: felt252,
    pub deactivate_leaf_hash: felt252,
    pub d1_hash: felt252,
    pub d2_hash: felt252,
    pub rerandomize_binding_hash: felt252,
    pub new_pub_key_hash: felt252,
    pub poll_id: felt252,
    pub input_hash: felt252,
}

fn assert_deactivate_index(value: u256) {
    assert(value.high == 0, 'BAD_DEACT_IDX_HIGH');
    assert(value.low < DEACTIVATE_TREE_LEAVES, 'BAD_DEACT_IDX');
}

fn felt_from_u128(value: u128) -> felt252 {
    value.into()
}

fn felt_from_u256(value: u256) -> felt252 {
    felt_from_u128(value.low) + felt_from_u128(value.high) * FELT_TWO_POW_128
}

fn native_hash_u256x2(value: U256x2) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(felt_from_u256(value.v0));
    state = state.update(felt_from_u256(value.v1));
    state.finalize()
}

fn native_hash5_values(v0: felt252, v1: felt252, v2: felt252, v3: felt252, v4: felt252) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(v0);
    state = state.update(v1);
    state = state.update(v2);
    state = state.update(v3);
    state = state.update(v4);
    state.finalize()
}

fn native_nullifier(old_private_key: u256, poll_id: u256) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN);
    state = state.update(felt_from_u256(old_private_key));
    state = state.update(felt_from_u256(poll_id));
    state.finalize()
}

fn native_deactivate_leaf_hash(
    c1_hash: felt252, c2_hash: felt252, shared_key_hash: felt252,
) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(ADD_NEW_KEY_NATIVE_DEACTIVATE_LEAF_DOMAIN);
    state = state.update(c1_hash);
    state = state.update(c2_hash);
    state = state.update(shared_key_hash);
    state.finalize()
}

fn native_rerandomize_binding_hash(
    coord_pub_key_hash: felt252,
    c1_hash: felt252,
    c2_hash: felt252,
    d1_hash: felt252,
    d2_hash: felt252,
) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(ADD_NEW_KEY_NATIVE_RERANDOMIZE_DOMAIN);
    state = state.update(coord_pub_key_hash);
    state = state.update(c1_hash);
    state = state.update(c2_hash);
    state = state.update(d1_hash);
    state = state.update(d2_hash);
    state.finalize()
}

fn native_path_hash(leaf: felt252, path_elements: U256x4, index: u128) -> felt252 {
    let p0 = felt_from_u256(path_elements.v0);
    let p1 = felt_from_u256(path_elements.v1);
    let p2 = felt_from_u256(path_elements.v2);
    let p3 = felt_from_u256(path_elements.v3);
    if index == 0 {
        native_hash5_values(leaf, p0, p1, p2, p3)
    } else if index == 1 {
        native_hash5_values(p0, leaf, p1, p2, p3)
    } else if index == 2 {
        native_hash5_values(p0, p1, leaf, p2, p3)
    } else if index == 3 {
        native_hash5_values(p0, p1, p2, leaf, p3)
    } else {
        assert(index == 4, 'BAD_PATH_INDEX');
        native_hash5_values(p0, p1, p2, p3, leaf)
    }
}

fn native_quinary_root_depth_4(
    leaf: felt252, path_0: U256x4, path_1: U256x4, path_2: U256x4, path_3: U256x4, index: u256,
) -> felt252 {
    assert_deactivate_index(index);
    let level_0_index = index.low % 5;
    let level_1_index = (index.low / 5) % 5;
    let level_2_index = (index.low / 25) % 5;
    let level_3_index = index.low / 125;
    let level_0 = native_path_hash(leaf, path_0, level_0_index);
    let level_1 = native_path_hash(level_0, path_1, level_1_index);
    let level_2 = native_path_hash(level_1, path_2, level_2_index);
    native_path_hash(level_2, path_3, level_3_index)
}

fn native_input_hash(fields: NativeAddNewKeyPublicFields) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(ADD_NEW_KEY_NATIVE_INPUT_HASH_DOMAIN);
    state = state.update(fields.deactivate_root_hash);
    state = state.update(fields.coord_pub_key_hash);
    state = state.update(fields.nullifier);
    state = state.update(fields.c1_hash);
    state = state.update(fields.c2_hash);
    state = state.update(fields.shared_key_hash);
    state = state.update(fields.deactivate_leaf_hash);
    state = state.update(fields.d1_hash);
    state = state.update(fields.d2_hash);
    state = state.update(fields.rerandomize_binding_hash);
    state = state.update(fields.new_pub_key_hash);
    state = state.update(fields.poll_id);
    state.finalize()
}

fn verify_native_add_new_key(fields: NativeAddNewKeyPublicFields, witness: NativeAddNewKeyWitness) {
    assert(native_hash_u256x2(witness.coord_pub_key) == fields.coord_pub_key_hash, 'N_COORD_KEY');
    assert(native_hash_u256x2(witness.new_pub_key) == fields.new_pub_key_hash, 'N_NEW_KEY');
    assert(native_nullifier(witness.old_private_key, witness.poll_id) == fields.nullifier, 'N_NULLIFIER');
    assert(native_hash_u256x2(witness.c1) == fields.c1_hash, 'N_C1');
    assert(native_hash_u256x2(witness.c2) == fields.c2_hash, 'N_C2');
    assert(native_hash_u256x2(witness.shared_key) == fields.shared_key_hash, 'N_SHARED');
    assert(
        native_deactivate_leaf_hash(fields.c1_hash, fields.c2_hash, fields.shared_key_hash)
            == fields.deactivate_leaf_hash,
        'N_DEACT_LEAF',
    );
    assert(native_hash_u256x2(witness.d1) == fields.d1_hash, 'N_D1');
    assert(native_hash_u256x2(witness.d2) == fields.d2_hash, 'N_D2');
    assert(
        native_rerandomize_binding_hash(
            fields.coord_pub_key_hash, fields.c1_hash, fields.c2_hash, fields.d1_hash, fields.d2_hash,
        ) == fields.rerandomize_binding_hash,
        'N_RERAND_BIND',
    );
    assert(witness.poll_id.high == 0, 'N_POLL_HIGH');
    assert(felt_from_u128(witness.poll_id.low) == fields.poll_id, 'N_POLL_ID');
    assert(native_input_hash(fields) == fields.input_hash, 'N_INPUT_HASH');

    let deactivate_root = native_quinary_root_depth_4(
        fields.deactivate_leaf_hash,
        witness.deactivate_leaf_path_0,
        witness.deactivate_leaf_path_1,
        witness.deactivate_leaf_path_2,
        witness.deactivate_leaf_path_3,
        witness.deactivate_index,
    );
    assert(deactivate_root == fields.deactivate_root_hash, 'N_DEACT_ROOT');
}

fn build_native_add_new_key_public_output(
    fields: NativeAddNewKeyPublicFields,
) -> NativeAddNewKeyPublicOutput {
    NativeAddNewKeyPublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: ADD_NEW_KEY_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        deactivate_tree_depth: DEACTIVATE_TREE_DEPTH,
        deactivate_root_hash: fields.deactivate_root_hash,
        coord_pub_key_hash: fields.coord_pub_key_hash,
        nullifier: fields.nullifier,
        c1_hash: fields.c1_hash,
        c2_hash: fields.c2_hash,
        shared_key_hash: fields.shared_key_hash,
        deactivate_leaf_hash: fields.deactivate_leaf_hash,
        d1_hash: fields.d1_hash,
        d2_hash: fields.d2_hash,
        rerandomize_binding_hash: fields.rerandomize_binding_hash,
        new_pub_key_hash: fields.new_pub_key_hash,
        poll_id: fields.poll_id,
        input_hash: fields.input_hash,
    }
}

pub fn add_new_key_native_main(
    fields: NativeAddNewKeyPublicFields, witness: NativeAddNewKeyWitness,
) -> NativeAddNewKeyPublicOutput {
    verify_native_add_new_key(fields, witness);
    build_native_add_new_key_public_output(fields)
}
EOF
}

write_stone_wrapper() {
  local circuit="$1"
  local wrapper_file="$2"

  {
    wrapper_imports "$circuit"
    cat <<'EOF'

#[executable]
pub fn stone_main(input: Array<felt252>) -> Array<felt252> {
    if input.len() == 0 {
        let mut unreachable_output = array![];
        unreachable_output.append(0);
        unreachable_output.append(0);
        unreachable_output.append(0);
        unreachable_output.append(0);
        unreachable_output.append(0);
        unreachable_output.append(0);
        unreachable_output.append(0);
        unreachable_output.append(0);
        unreachable_output.append(0);
        unreachable_output.append(0);
        unreachable_output.append(0);
        unreachable_output.append(0);
        unreachable_output.append(0);
        unreachable_output.append(0);
        unreachable_output.append(0);
        unreachable_output.append(0);
        return unreachable_output;
    }

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
}

if ! is_supported_circuit "$CIRCUIT"; then
  echo "--circuit must be one of the supported native circuits" >&2
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
  LAYOUT="recursive_with_poseidon"
fi

if [[ "$LAYOUT" != "recursive_with_poseidon" ]]; then
  echo "layout '$LAYOUT' is not compatible with native Stone AIR" >&2
  echo "native AMACI circuits use the Starknet Poseidon builtin; use --layout recursive_with_poseidon" >&2
  exit 1
fi

if [[ -z "$INPUT_PATH" ]]; then
  case "$CIRCUIT" in
    tally-native)
      INPUT_PATH="$ROOT_DIR/fixtures/tally-small/000000.json"
      ;;
  esac
fi
OUT_DIR="${OUT_DIR:-$ROOT_DIR/target/stone-air/$CIRCUIT}"

require_tool node
require_tool scarb
if [[ "$SKIP_CAIRO1_RUN" != "true" ]]; then
  require_tool cairo1-run
fi

PREPARE_CIRCUIT="$(prepare_circuit_name "$CIRCUIT")"
SOURCE_EXECUTABLE_NAME="$(source_executable_name "$CIRCUIT")"
STONE_PACKAGE_NAME="zkstark_amaci_$(printf '%s' "$CIRCUIT" | tr '-' '_')_stone"
STONE_EXECUTABLE_NAME="${SOURCE_EXECUTABLE_NAME}_stone"
STONE_ENTRY_MODULE="stone_entry"
STONE_ENTRY_FUNCTION="stone_main"
STONE_ENTRY_MODE="array-wrapper"
case "$CIRCUIT" in
  tally-native)
    STONE_MODULES=(native_tally_votes "$STONE_ENTRY_MODULE")
    ;;
  process-messages-boundary-native)
    STONE_MODULES=(native_process_messages "$STONE_ENTRY_MODULE")
    ;;
  process-deactivate-boundary-native)
    STONE_MODULES=(native_process_deactivate "$STONE_ENTRY_MODULE")
    ;;
  add-new-key-native)
    STONE_MODULES=(
      native_add_new_key
      "$STONE_ENTRY_MODULE"
    )
    ;;
  process-message-coord-key-native|process-message-ecdh-native|process-message-decrypt-native|process-message-signature-native)
    STONE_MODULES=(
      native_process_message_components
      "$STONE_ENTRY_MODULE"
    )
    ;;
  process-message-step-core-native)
    STONE_MODULES=(
      native_process_message_step_core
      "$STONE_ENTRY_MODULE"
    )
    ;;
  process-deactivate-coord-key-native|process-deactivate-ecdh-command-native|process-deactivate-ecdh-leaf-native|process-deactivate-signature-native|process-deactivate-decrypt-current-native|process-deactivate-decrypt-new-native)
    STONE_MODULES=(
      native_process_deactivate_components
      "$STONE_ENTRY_MODULE"
    )
    ;;
  process-deactivate-step-core-native)
    STONE_MODULES=(
      native_process_deactivate_step_core
      "$STONE_ENTRY_MODULE"
    )
    ;;
  *)
    echo "unsupported circuit: $CIRCUIT" >&2
    exit 1
    ;;
esac

if [[ "$STONE_ENTRY_MODE" == "executable-wrapper" || "$STONE_ENTRY_MODE" == "source-direct" ]]; then
  STONE_SOURCE_ENTRY_PATH="$(source_entry_path "$CIRCUIT")"
  STONE_SOURCE_ENTRY_MODULE="${STONE_SOURCE_ENTRY_PATH%%::*}"
  STONE_SOURCE_ENTRY_FUNCTION="${STONE_SOURCE_ENTRY_PATH##*::}"
  STONE_TARGET_FUNCTION="$STONE_PACKAGE_NAME::$STONE_SOURCE_ENTRY_PATH"
  if [[ "$STONE_ENTRY_MODE" == "source-direct" ]]; then
    STONE_EXPORT_FUNCTION="$STONE_TARGET_FUNCTION"
  else
    STONE_EXPORT_FUNCTION="$STONE_PACKAGE_NAME::$STONE_SOURCE_ENTRY_MODULE::__executable_wrapper__$STONE_SOURCE_ENTRY_FUNCTION"
  fi
  STONE_RUNNER_MAIN_NAME="$STONE_PACKAGE_NAME::$STONE_SOURCE_ENTRY_MODULE::main"
else
  STONE_SOURCE_ENTRY_PATH="$STONE_ENTRY_MODULE::$STONE_ENTRY_FUNCTION"
  STONE_TARGET_FUNCTION="$STONE_PACKAGE_NAME::$STONE_ENTRY_MODULE::$STONE_ENTRY_FUNCTION"
  STONE_EXPORT_FUNCTION="$STONE_TARGET_FUNCTION"
  STONE_RUNNER_MAIN_NAME="$STONE_PACKAGE_NAME::$STONE_ENTRY_MODULE::main"
fi

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
CORELIB_DIR=""
CORELIB_PARENT=""
if [[ "$SKIP_CAIRO1_RUN" != "true" ]]; then
  CORELIB_DIR="$(detect_cairo_corelib_dir || true)"
fi

if [[ "$SKIP_CAIRO1_RUN" != "true" && -z "$CORELIB_DIR" ]]; then
  cat >&2 <<'EOF'
cairo1-run could not find a Cairo development corelib.

Set CAIRO_CORELIB_DIR to the corelib directory built with cairo-vm, for example:
  CAIRO_CORELIB_DIR=~/cairo-vm/cairo1-run/corelib npm run stone:air:tally -- --out-dir ~/zkstark-amaci-proofs/stone-tally-native

If that directory does not exist, run the cairo-vm dependency setup first:
  cd ~/cairo-vm/cairo1-run && make deps
EOF
  exit 1
fi

if [[ -n "$CORELIB_DIR" ]]; then
  CORELIB_PARENT="$(cd "$CORELIB_DIR/.." && pwd)"
fi

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
CONVERT_ARGS=(
  "$ROOT_DIR/tools/convert-cairo1-run-args.mjs"
  "$SCARB_ARGS_JSON" \
  --out "$CAIRO1_ARGS_TXT" \
  --text
)
if [[ "$STONE_ENTRY_MODE" != "array-wrapper" ]]; then
  CONVERT_ARGS+=(--flat)
fi
node "${CONVERT_ARGS[@]}"

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
  printf 'function = "%s"\n' "$STONE_TARGET_FUNCTION"
} > "$STONE_PACKAGE_DIR/Scarb.toml"

{
  for module in "${STONE_MODULES[@]}"; do
    printf 'mod %s;\n' "$module"
  done
} > "$STONE_PACKAGE_DIR/src/lib.cairo"

for module in "${STONE_MODULES[@]}"; do
  if [[ "$module" == "$STONE_ENTRY_MODULE" ]]; then
    write_stone_wrapper "$CIRCUIT" "$STONE_PACKAGE_DIR/src/$module.cairo"
  elif [[ "$module" == "native_add_new_key" ]]; then
    write_native_add_new_key_module "$STONE_PACKAGE_DIR/src/$module.cairo"
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
  --function "$STONE_EXPORT_FUNCTION" \
  --main-name "$STONE_RUNNER_MAIN_NAME" \
  --out "$RUNNER_SIERRA_JSON"

AIR_GENERATED=false
if [[ "$SKIP_CAIRO1_RUN" == "true" ]]; then
  echo "==> Skipping cairo1-run proof mode for $CIRCUIT"
  echo "Atlantic program/input files are ready; local AIR trace files were not generated." | tee "$RUN_LOG"
else
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
  AIR_GENERATED=true
fi

printf '{\n' > "$RUN_JSON"
printf '  "circuit": "%s",\n' "$CIRCUIT" >> "$RUN_JSON"
printf '  "prepareCircuit": "%s",\n' "$PREPARE_CIRCUIT" >> "$RUN_JSON"
printf '  "sourceExecutable": "%s",\n' "$SOURCE_EXECUTABLE_NAME" >> "$RUN_JSON"
printf '  "stoneExecutable": "%s",\n' "$STONE_EXECUTABLE_NAME" >> "$RUN_JSON"
printf '  "stoneEntryMode": "%s",\n' "$STONE_ENTRY_MODE" >> "$RUN_JSON"
printf '  "stoneTargetFunction": "%s",\n' "$STONE_TARGET_FUNCTION" >> "$RUN_JSON"
printf '  "stoneExportFunction": "%s",\n' "$STONE_EXPORT_FUNCTION" >> "$RUN_JSON"
printf '  "stoneRunnerMainName": "%s",\n' "$STONE_RUNNER_MAIN_NAME" >> "$RUN_JSON"
printf '  "executable": "%s",\n' "$EXECUTABLE_JSON" >> "$RUN_JSON"
printf '  "generatedInput": %s,\n' "$GENERATED_INPUT" >> "$RUN_JSON"
if [[ -n "$MESSAGE_INDEX" ]]; then
  printf '  "messageIndex": %s,\n' "$MESSAGE_INDEX" >> "$RUN_JSON"
fi
printf '  "stonePackageDir": "%s",\n' "$STONE_PACKAGE_DIR" >> "$RUN_JSON"
printf '  "packageSierraJson": "%s",\n' "$PACKAGE_SIERRA_JSON" >> "$RUN_JSON"
printf '  "runnerSierraJson": "%s",\n' "$RUNNER_SIERRA_JSON" >> "$RUN_JSON"
printf '  "layout": "%s",\n' "$LAYOUT" >> "$RUN_JSON"
printf '  "airGenerated": %s,\n' "$AIR_GENERATED" >> "$RUN_JSON"
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
