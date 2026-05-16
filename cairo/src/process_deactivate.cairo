use core::poseidon::poseidon_hash_span;
use crate::babyjub::{
    BabyJubJubPoseidonSignatureWitness, BabyJubJubScalarMulWitness, assert_babyjub_add,
    babyjub_base8, verify_babyjub_poseidon_signature, verify_babyjub_scalar_mul,
};
use crate::hash_gates::{
    Hash10Claim, Hash13Claim, Hash2Claim, Hash5Claim, Sha256U256x8Claim, poseidon_hash10,
    poseidon_hash13, poseidon_hash2, poseidon_hash5, sha256_u256x8_mod_bn254,
};
use crate::poseidon_bn254::{PoseidonT4State, field_sub_mod, poseidon4_permutation, poseidon5_hash};
use crate::public_output::{
    ProcessDeactivateCoordKeyPublicFields, ProcessDeactivateCoordKeyPublicOutput,
    ProcessDeactivateDecryptPublicFields, ProcessDeactivateDecryptPublicOutput,
    ProcessDeactivateEcdhPublicFields, ProcessDeactivateEcdhPublicOutput,
    ProcessDeactivatePublicFields, ProcessDeactivatePublicOutput,
    ProcessDeactivateSignaturePublicFields, ProcessDeactivateSignaturePublicOutput,
    ProcessDeactivateStepCorePublicFields, ProcessDeactivateStepCorePublicOutput,
    ProcessDeactivateStepPublicFields, ProcessDeactivateStepPublicOutput,
    build_process_deactivate_coord_key_public_output,
    build_process_deactivate_decrypt_public_output, build_process_deactivate_ecdh_public_output,
    build_process_deactivate_public_output, build_process_deactivate_signature_public_output,
    build_process_deactivate_step_core_public_output, build_process_deactivate_step_public_output,
};
use crate::types::{
    U256x10, U256x2, U256x3, U256x4, U256x5, U256x7, U256x8, assert_u256_eq, is_zero,
    u256x10_first5, u256x10_second5, zero_u256,
};

pub const TWO_POW_32: u256 = 0x100000000;
pub const POSEIDON_DECRYPT_7_DOMAIN: u256 = 0x700000000000000000000000000000000;
pub const U128_TWO_POW_32: u128 = 0x100000000;
pub const U128_TWO_POW_64: u128 = 0x10000000000000000;
pub const U128_TWO_POW_96: u128 = 0x1000000000000000000000000;
pub const FELT_TWO_POW_128: felt252 = 0x100000000000000000000000000000000;
pub const STATE_TREE_LEAVES: u128 = 25;
pub const STATE_TREE_MAX_INDEX: u256 = 24;
pub const DEACTIVATE_TREE_LEAVES: u128 = 625;
pub const COORD_PRIV_KEY_HASH_DOMAIN: u256 = 0x414d4143495f434f4f52445f50524956;
pub const DEACTIVATE_ECDH_KIND_COMMAND: felt252 = 0;
pub const DEACTIVATE_ECDH_KIND_LEAF: felt252 = 1;
pub const DEACTIVATE_DECRYPT_KIND_CURRENT: felt252 = 0;
pub const DEACTIVATE_DECRYPT_KIND_NEW: felt252 = 1;
pub const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
pub const STARKNET_POSEIDON_HASH_SCHEME: felt252 = 0x535441524b4e45545f504f534549444f4e;
pub const PROCESS_DEACTIVATE_COORD_KEY_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f44454143545f434f4f52445f4e4154495645;
pub const PROCESS_DEACTIVATE_ECDH_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f44454143545f454344485f4e4154495645;
pub const PROCESS_DEACTIVATE_SIGNATURE_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f44454143545f5349475f4e4154495645;
pub const PROCESS_DEACTIVATE_DECRYPT_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f44454143545f4445435f4e4154495645;
pub const PROCESS_DEACTIVATE_STEP_CORE_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f44454143545f535445505f434f52455f4e4154495645;
pub const NATIVE_COORD_PRIV_KEY_HASH_DOMAIN: felt252 = 0x414d4143495f434f4f52445f50524956;
pub const NATIVE_DEACTIVATE_COMMAND_AUTH_DOMAIN: felt252 = 0x414d4143495f44454143545f41555448;
pub const NATIVE_DEACTIVATE_COMMAND_PLAINTEXT_DOMAIN: felt252 =
    0x414d4143495f44454143545f434d445f504c41494e;
pub const NATIVE_DEACTIVATE_COORD_KEY_BINDING_DOMAIN: felt252 =
    0x414d4143495f44454143545f434f4f52445f42494e44;
pub const NATIVE_DEACTIVATE_SHARED_KEY_DOMAIN: felt252 =
    0x414d4143495f44454143545f534841524544;
pub const NATIVE_DEACTIVATE_DECRYPT_BINDING_DOMAIN: felt252 =
    0x414d4143495f44454143545f4445435f42494e44;

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivateOneHashTranscript {
    pub state_leaf_hash: Hash10Claim,
    pub shared_key_hash: Hash2Claim,
    pub deactivate_leaf: Hash5Claim,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivateMessagesHashTranscript {
    pub coord_pub_key_hash: Hash2Claim,
    pub input_hash: Sha256U256x8Claim,
    pub current_deactivate_commitment: Hash2Claim,
    pub message_hash_0: Hash13Claim,
    pub message_hash_1: Hash13Claim,
    pub message_hash_2: Hash13Claim,
    pub message_hash_3: Hash13Claim,
    pub message_hash_4: Hash13Claim,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivateMessagesBoundaryWitness {
    pub coord_pub_key: U256x2,
    pub current_active_state_root: u256,
    pub current_deactivate_root: u256,
    pub batch_start_hash: u256,
    pub batch_end_hash: u256,
    pub current_state_root: u256,
    pub expected_poll_id: u256,
    pub msg_0: U256x10,
    pub msg_1: U256x10,
    pub msg_2: U256x10,
    pub msg_3: U256x10,
    pub msg_4: U256x10,
    pub enc_pub_key_0: U256x2,
    pub enc_pub_key_1: U256x2,
    pub enc_pub_key_2: U256x2,
    pub enc_pub_key_3: U256x2,
    pub enc_pub_key_4: U256x2,
    pub hashes: ProcessDeactivateMessagesHashTranscript,
}

#[derive(Drop, Serde)]
pub struct ProcessDeactivateMessagesStateTransitionWitness {
    pub coord_priv_key: u256,
    pub current_state_root: u256,
    pub current_active_state_root: u256,
    pub current_deactivate_root: u256,
    pub expected_poll_id: u256,
    pub deactivate_index_0: u256,
    pub process_one_0: ProcessDeactivateOneWitness,
    pub process_one_1: ProcessDeactivateOneWitness,
    pub process_one_2: ProcessDeactivateOneWitness,
    pub process_one_3: ProcessDeactivateOneWitness,
    pub process_one_4: ProcessDeactivateOneWitness,
}

#[derive(Drop, Serde)]
pub struct ProcessDeactivateMessagesStatefulWitness {
    pub boundary: ProcessDeactivateMessagesBoundaryWitness,
    pub state_transition: ProcessDeactivateMessagesStateTransitionWitness,
    pub coord_pub_key: BabyJubJubScalarMulWitness,
    pub command_0: ProcessDeactivateMessageCommandWitness,
    pub command_1: ProcessDeactivateMessageCommandWitness,
    pub command_2: ProcessDeactivateMessageCommandWitness,
    pub command_3: ProcessDeactivateMessageCommandWitness,
    pub command_4: ProcessDeactivateMessageCommandWitness,
    pub new_deactivate_commitment: Hash2Claim,
}

#[derive(Drop, Serde)]
pub struct ProcessDeactivateMessageStepWitness {
    pub coord_pub_key: U256x2,
    pub msg: U256x10,
    pub enc_pub_key: U256x2,
    pub coord_priv_key: u256,
    pub coord_pub_key_scalar_mul: BabyJubJubScalarMulWitness,
    pub coord_pub_key_hash: Hash2Claim,
    pub message_hash: Hash13Claim,
    pub command: ProcessDeactivateMessageCommandWitness,
    pub process_one: ProcessDeactivateOneWitness,
    pub current_deactivate_commitment: Hash2Claim,
    pub new_deactivate_commitment: Hash2Claim,
}

#[derive(Drop, Serde)]
pub struct ProcessDeactivateCoordKeyWitness {
    pub coord_priv_key: u256,
    pub coord_pub_key: U256x2,
    pub coord_pub_key_scalar_mul: BabyJubJubScalarMulWitness,
    pub coord_pub_key_hash: Hash2Claim,
    pub coord_priv_key_hash: Hash2Claim,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessDeactivateCoordKeyWitness {
    pub coord_priv_key: u256,
    pub coord_pub_key: U256x2,
}

#[derive(Drop, Serde)]
pub struct ProcessDeactivateEcdhWitness {
    pub coord_priv_key: u256,
    pub base: U256x2,
    pub ecdh: BabyJubJubScalarMulWitness,
    pub coord_priv_key_hash: Hash2Claim,
    pub base_hash: Hash2Claim,
    pub shared_key_hash: Hash2Claim,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessDeactivateEcdhWitness {
    pub coord_priv_key: u256,
    pub base: U256x2,
    pub shared_key: U256x2,
}

#[derive(Drop, Serde)]
pub struct ProcessDeactivateSignatureWitness {
    pub pub_key: U256x2,
    pub r8: U256x2,
    pub s: u256,
    pub packed_cmd: U256x3,
    pub signature: BabyJubJubPoseidonSignatureWitness,
    pub pub_key_hash: Hash2Claim,
    pub r8_hash: Hash2Claim,
    pub packed_cmd_hash: Hash5Claim,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessDeactivateSignatureWitness {
    pub pub_key: U256x2,
    pub r8: U256x2,
    pub s: u256,
    pub packed_cmd: U256x3,
    pub cmd_salt: u256,
}

#[derive(Drop, Serde)]
pub struct ProcessDeactivateDecryptWitness {
    pub coord_priv_key: u256,
    pub c1: U256x2,
    pub c2: U256x2,
    pub decrypt: ElGamalDecryptWitness,
    pub coord_priv_key_hash: Hash2Claim,
    pub c1_hash: Hash2Claim,
    pub c2_hash: Hash2Claim,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessDeactivateDecryptWitness {
    pub coord_priv_key: u256,
    pub c1: U256x2,
    pub c2: U256x2,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessDeactivateCoordKeyPublicFields {
    pub coord_pub_key_hash: felt252,
    pub coord_priv_key_hash: felt252,
    pub coord_key_binding_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessDeactivateEcdhPublicFields {
    pub message_index: felt252,
    pub ecdh_kind: felt252,
    pub coord_priv_key_hash: felt252,
    pub base_hash: felt252,
    pub shared_key_hash: felt252,
    pub shared_key_binding_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessDeactivateSignaturePublicFields {
    pub message_index: felt252,
    pub pub_key_hash: felt252,
    pub r8_hash: felt252,
    pub packed_cmd_hash: felt252,
    pub cmd_sig_s_hash: felt252,
    pub command_auth_hash: felt252,
    pub signature_valid: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessDeactivateDecryptPublicFields {
    pub message_index: felt252,
    pub decrypt_kind: felt252,
    pub coord_priv_key_hash: felt252,
    pub c1_hash: felt252,
    pub c2_hash: felt252,
    pub decrypt_is_odd: felt252,
    pub decrypt_binding_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessDeactivateStepCorePublicFields {
    pub message_index: felt252,
    pub deactivate_index: felt252,
    pub coord_priv_key_hash: felt252,
    pub previous_message_hash: felt252,
    pub next_message_hash: felt252,
    pub current_active_state_root_hash: felt252,
    pub current_deactivate_root_hash: felt252,
    pub new_active_state_root_hash: felt252,
    pub new_deactivate_root_hash: felt252,
    pub current_deactivate_commitment_hash: felt252,
    pub new_deactivate_commitment_hash: felt252,
    pub current_state_root_hash: felt252,
    pub expected_poll_id: felt252,
    pub enc_pub_key_hash: felt252,
    pub command_shared_key_hash: felt252,
    pub command_shared_key_binding_hash: felt252,
    pub signature_pub_key_hash: felt252,
    pub signature_r8_hash: felt252,
    pub packed_cmd_hash: felt252,
    pub cmd_sig_s_hash: felt252,
    pub command_auth_hash: felt252,
    pub command_plaintext_binding_hash: felt252,
    pub signature_valid: felt252,
    pub current_state_ciphertext_c1_hash: felt252,
    pub current_state_ciphertext_c2_hash: felt252,
    pub current_decrypt_is_odd: felt252,
    pub current_decrypt_binding_hash: felt252,
    pub new_state_ciphertext_c1_hash: felt252,
    pub new_state_ciphertext_c2_hash: felt252,
    pub new_decrypt_is_odd: felt252,
    pub new_decrypt_binding_hash: felt252,
    pub deactivate_pub_key_hash: felt252,
    pub deactivate_shared_key_hash: felt252,
    pub deactivate_shared_key_binding_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessDeactivateCoordKeyPublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub hash_scheme: felt252,
    pub state_tree_depth: felt252,
    pub deactivate_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub coord_pub_key_hash: felt252,
    pub coord_priv_key_hash: felt252,
    pub coord_key_binding_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessDeactivateEcdhPublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub hash_scheme: felt252,
    pub state_tree_depth: felt252,
    pub deactivate_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub message_index: felt252,
    pub ecdh_kind: felt252,
    pub coord_priv_key_hash: felt252,
    pub base_hash: felt252,
    pub shared_key_hash: felt252,
    pub shared_key_binding_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessDeactivateSignaturePublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub hash_scheme: felt252,
    pub state_tree_depth: felt252,
    pub deactivate_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub message_index: felt252,
    pub pub_key_hash: felt252,
    pub r8_hash: felt252,
    pub packed_cmd_hash: felt252,
    pub cmd_sig_s_hash: felt252,
    pub command_auth_hash: felt252,
    pub signature_valid: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessDeactivateDecryptPublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub hash_scheme: felt252,
    pub state_tree_depth: felt252,
    pub deactivate_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub message_index: felt252,
    pub decrypt_kind: felt252,
    pub coord_priv_key_hash: felt252,
    pub c1_hash: felt252,
    pub c2_hash: felt252,
    pub decrypt_is_odd: felt252,
    pub decrypt_binding_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessDeactivateStepCorePublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub hash_scheme: felt252,
    pub state_tree_depth: felt252,
    pub deactivate_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub message_index: felt252,
    pub deactivate_index: felt252,
    pub coord_priv_key_hash: felt252,
    pub previous_message_hash: felt252,
    pub next_message_hash: felt252,
    pub current_active_state_root_hash: felt252,
    pub current_deactivate_root_hash: felt252,
    pub new_active_state_root_hash: felt252,
    pub new_deactivate_root_hash: felt252,
    pub current_deactivate_commitment_hash: felt252,
    pub new_deactivate_commitment_hash: felt252,
    pub current_state_root_hash: felt252,
    pub expected_poll_id: felt252,
    pub enc_pub_key_hash: felt252,
    pub command_shared_key_hash: felt252,
    pub command_shared_key_binding_hash: felt252,
    pub signature_pub_key_hash: felt252,
    pub signature_r8_hash: felt252,
    pub packed_cmd_hash: felt252,
    pub cmd_sig_s_hash: felt252,
    pub command_auth_hash: felt252,
    pub command_plaintext_binding_hash: felt252,
    pub signature_valid: felt252,
    pub current_state_ciphertext_c1_hash: felt252,
    pub current_state_ciphertext_c2_hash: felt252,
    pub current_decrypt_is_odd: felt252,
    pub current_decrypt_binding_hash: felt252,
    pub new_state_ciphertext_c1_hash: felt252,
    pub new_state_ciphertext_c2_hash: felt252,
    pub new_decrypt_is_odd: felt252,
    pub new_decrypt_binding_hash: felt252,
    pub deactivate_pub_key_hash: felt252,
    pub deactivate_shared_key_hash: felt252,
    pub deactivate_shared_key_binding_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivateStepCoreWitness {
    pub is_empty_msg: u256,
    pub coord_priv_key: u256,
    pub msg: U256x10,
    pub enc_pub_key: U256x2,
    pub command_shared_key: U256x2,
    pub decrypted_command: U256x7,
    pub c1: U256x2,
    pub c2: U256x2,
    pub state_leaf: U256x10,
    pub state_leaf_path_0: U256x4,
    pub state_leaf_path_1: U256x4,
    pub active_state_leaf_path_0: U256x4,
    pub active_state_leaf_path_1: U256x4,
    pub current_active_state: u256,
    pub new_active_state: u256,
    pub cmd_state_index: u256,
    pub cmd_poll_id: u256,
    pub cmd_sig_r8: U256x2,
    pub cmd_sig_s: u256,
    pub packed_cmd: U256x3,
    pub deactivate_leaf_path_0: U256x4,
    pub deactivate_leaf_path_1: U256x4,
    pub deactivate_leaf_path_2: U256x4,
    pub deactivate_leaf_path_3: U256x4,
    pub current_decrypt_is_odd: u256,
    pub new_decrypt_is_odd: u256,
    pub signature_valid: u256,
    pub deactivate_shared_key_hash: u256,
    pub deactivate_shared_key: U256x2,
    pub deactivate_shared_key_hash_claim: Hash2Claim,
    pub coord_priv_key_hash: Hash2Claim,
    pub message_hash: Hash13Claim,
    pub current_deactivate_commitment: Hash2Claim,
    pub new_deactivate_commitment: Hash2Claim,
    pub enc_pub_key_hash: Hash2Claim,
    pub command_shared_key_hash: Hash2Claim,
    pub signature_pub_key_hash: Hash2Claim,
    pub signature_r8_hash: Hash2Claim,
    pub packed_cmd_hash: Hash5Claim,
    pub current_state_ciphertext_c1_hash: Hash2Claim,
    pub current_state_ciphertext_c2_hash: Hash2Claim,
    pub new_state_ciphertext_c1_hash: Hash2Claim,
    pub new_state_ciphertext_c2_hash: Hash2Claim,
    pub deactivate_pub_key_hash: Hash2Claim,
    pub state_leaf_hash: Hash10Claim,
    pub deactivate_leaf: Hash5Claim,
}

#[derive(Drop, Serde)]
pub struct ElGamalDecryptWitness {
    pub scalar_mul: BabyJubJubScalarMulWitness,
    pub decrypted_point: U256x2,
}

#[derive(Drop, Serde)]
pub struct ProcessDeactivateOneWitness {
    pub is_empty_msg: u256,
    pub coord_priv_key: u256,
    pub current_state_root: u256,
    pub c1: U256x2,
    pub c2: U256x2,
    pub current_active_state_root: u256,
    pub current_deactivate_root: u256,
    pub state_leaf: U256x10,
    pub state_leaf_path_0: U256x4,
    pub state_leaf_path_1: U256x4,
    pub active_state_leaf_path_0: U256x4,
    pub active_state_leaf_path_1: U256x4,
    pub current_active_state: u256,
    pub new_active_state: u256,
    pub cmd_state_index: u256,
    pub cmd_poll_id: u256,
    pub cmd_sig_r8: U256x2,
    pub cmd_sig_s: u256,
    pub packed_cmd: U256x3,
    pub expected_poll_id: u256,
    pub deactivate_index: u256,
    pub deactivate_leaf_path_0: U256x4,
    pub deactivate_leaf_path_1: U256x4,
    pub deactivate_leaf_path_2: U256x4,
    pub deactivate_leaf_path_3: U256x4,
    pub current_state_decrypt: ElGamalDecryptWitness,
    pub new_state_decrypt: ElGamalDecryptWitness,
    pub deactivate_ecdh: BabyJubJubScalarMulWitness,
    pub signature: BabyJubJubPoseidonSignatureWitness,
    pub hashes: ProcessDeactivateOneHashTranscript,
}

#[derive(Drop, Serde)]
pub struct ProcessDeactivateMessageCommandWitness {
    pub ecdh: BabyJubJubScalarMulWitness,
    pub decrypted_command: U256x7,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivateOneOutput {
    pub new_active_state_root: u256,
    pub new_deactivate_root: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivateMessagesStateOutput {
    pub new_active_state_root: u256,
    pub new_deactivate_root: u256,
}

fn assert_bool_u256(value: u256) {
    assert(value.high == 0, 'BOOL_HIGH');
    assert(value.low < 2, 'BOOL_RANGE');
}

fn bool_to_u256(value: bool) -> u256 {
    if value {
        1
    } else {
        0
    }
}

fn u256_bool(value: u256) -> bool {
    assert_bool_u256(value);
    value.low == 1
}

fn select_u256(selected: bool, if_false: u256, if_true: u256) -> u256 {
    if selected {
        if_true
    } else {
        if_false
    }
}

fn assert_deactivate_index(value: u256) {
    assert(value.high == 0, 'DEACT_IDX_HIGH');
    assert(value.low < DEACTIVATE_TREE_LEAVES, 'DEACT_IDX_RANGE');
}

fn assert_state_index(value: u256) {
    assert(value.high == 0, 'STATE_IDX_HIGH');
    assert(value.low < STATE_TREE_LEAVES, 'STATE_IDX_RANGE');
}

fn valid_state_index(value: u256) -> bool {
    value.high == 0 && value.low < STATE_TREE_LEAVES
}

fn unpack_command_data(packed_data: u256) -> U256x7 {
    U256x7 {
        v0: ((packed_data.high / U128_TWO_POW_64) % U128_TWO_POW_32).into(),
        v1: ((packed_data.high / U128_TWO_POW_32) % U128_TWO_POW_32).into(),
        v2: (packed_data.high % U128_TWO_POW_32).into(),
        v3: (packed_data.low / U128_TWO_POW_96).into(),
        v4: ((packed_data.low / U128_TWO_POW_64) % U128_TWO_POW_32).into(),
        v5: ((packed_data.low / U128_TWO_POW_32) % U128_TWO_POW_32).into(),
        v6: (packed_data.low % U128_TWO_POW_32).into(),
    }
}

fn poseidon_decrypt_initial_state(shared_key: U256x2) -> PoseidonT4State {
    poseidon4_permutation(
        PoseidonT4State {
            x0: zero_u256(), x1: shared_key.v0, x2: shared_key.v1, x3: POSEIDON_DECRYPT_7_DOMAIN,
        },
    )
}

fn poseidon_decrypt_next_state(
    state: PoseidonT4State, c0: u256, c1: u256, c2: u256,
) -> PoseidonT4State {
    poseidon4_permutation(PoseidonT4State { x0: state.x0, x1: c0, x2: c1, x3: c2 })
}

fn validate_poseidon_decryption(msg: U256x10, shared_key: U256x2, decrypted_command: U256x7) {
    let state_0 = poseidon_decrypt_initial_state(shared_key);
    assert_u256_eq(decrypted_command.v0, field_sub_mod(msg.v0, state_0.x1));
    assert_u256_eq(decrypted_command.v1, field_sub_mod(msg.v1, state_0.x2));
    assert_u256_eq(decrypted_command.v2, field_sub_mod(msg.v2, state_0.x3));

    let state_1 = poseidon_decrypt_next_state(state_0, msg.v0, msg.v1, msg.v2);
    assert_u256_eq(decrypted_command.v3, field_sub_mod(msg.v3, state_1.x1));
    assert_u256_eq(decrypted_command.v4, field_sub_mod(msg.v4, state_1.x2));
    assert_u256_eq(decrypted_command.v5, field_sub_mod(msg.v5, state_1.x3));

    let state_2 = poseidon_decrypt_next_state(state_1, msg.v3, msg.v4, msg.v5);
    assert_u256_eq(decrypted_command.v6, field_sub_mod(msg.v6, state_2.x1));
}

fn path_inputs(leaf: u256, path_elements: U256x4, index: u128) -> U256x5 {
    if index == 0 {
        U256x5 {
            v0: leaf,
            v1: path_elements.v0,
            v2: path_elements.v1,
            v3: path_elements.v2,
            v4: path_elements.v3,
        }
    } else if index == 1 {
        U256x5 {
            v0: path_elements.v0,
            v1: leaf,
            v2: path_elements.v1,
            v3: path_elements.v2,
            v4: path_elements.v3,
        }
    } else if index == 2 {
        U256x5 {
            v0: path_elements.v0,
            v1: path_elements.v1,
            v2: leaf,
            v3: path_elements.v2,
            v4: path_elements.v3,
        }
    } else if index == 3 {
        U256x5 {
            v0: path_elements.v0,
            v1: path_elements.v1,
            v2: path_elements.v2,
            v3: leaf,
            v4: path_elements.v3,
        }
    } else {
        assert(index == 4, 'BAD_PATH_INDEX');
        U256x5 {
            v0: path_elements.v0,
            v1: path_elements.v1,
            v2: path_elements.v2,
            v3: path_elements.v3,
            v4: leaf,
        }
    }
}

fn quinary_root_depth_2(leaf: u256, path_0: U256x4, path_1: U256x4, index: u256) -> u256 {
    assert_state_index(index);
    let level_0_index = index.low % 5;
    let level_1_index = index.low / 5;
    let level_0 = poseidon5_hash(path_inputs(leaf, path_0, level_0_index));
    poseidon5_hash(path_inputs(level_0, path_1, level_1_index))
}

fn quinary_root_depth_4(
    leaf: u256, path_0: U256x4, path_1: U256x4, path_2: U256x4, path_3: U256x4, index: u256,
) -> u256 {
    assert_deactivate_index(index);
    let level_0_index = index.low % 5;
    let level_1_index = (index.low / 5) % 5;
    let level_2_index = (index.low / 25) % 5;
    let level_3_index = index.low / 125;
    let level_0 = poseidon5_hash(path_inputs(leaf, path_0, level_0_index));
    let level_1 = poseidon5_hash(path_inputs(level_0, path_1, level_1_index));
    let level_2 = poseidon5_hash(path_inputs(level_1, path_2, level_2_index));
    poseidon5_hash(path_inputs(level_2, path_3, level_3_index))
}

fn is_odd_u256(value: u256) -> bool {
    value.low % 2 == 1
}

fn assert_elgamal_decrypt(
    witness: ElGamalDecryptWitness, coord_priv_key: u256, c1: U256x2, c2: U256x2,
) -> bool {
    let scalar_mul = witness.scalar_mul;
    let decrypted_point = witness.decrypted_point;
    assert_u256_eq(scalar_mul.scalar, coord_priv_key);
    assert_u256_eq(scalar_mul.base.v0, c1.v0);
    assert_u256_eq(scalar_mul.base.v1, c1.v1);
    let c1x = verify_babyjub_scalar_mul(scalar_mul);
    let c1x_inverse = U256x2 { v0: field_sub_mod(zero_u256(), c1x.v0), v1: c1x.v1 };
    assert_babyjub_add(c1x_inverse, c2, decrypted_point);
    is_odd_u256(decrypted_point.v0)
}

fn assert_deactivate_ecdh(
    witness: BabyJubJubScalarMulWitness, coord_priv_key: u256, pub_key: U256x2, claim: Hash2Claim,
) -> u256 {
    assert_u256_eq(witness.scalar, coord_priv_key);
    assert_u256_eq(witness.base.v0, pub_key.v0);
    assert_u256_eq(witness.base.v1, pub_key.v1);
    let shared_key = verify_babyjub_scalar_mul(witness);
    poseidon_hash2(claim, shared_key.v0, shared_key.v1)
}

fn process_deactivate_message_hash(
    claim: Hash13Claim, msg: U256x10, enc_pub_key: U256x2, prev_hash: u256,
) -> u256 {
    poseidon_hash13(
        claim, u256x10_first5(msg), u256x10_second5(msg), enc_pub_key.v0, enc_pub_key.v1, prev_hash,
    )
}

fn process_deactivate_message_hash_chain_step(
    msg: U256x10, enc_pub_key: U256x2, prev_hash: u256, claim: Hash13Claim,
) -> u256 {
    if is_zero(msg.v0) {
        prev_hash
    } else {
        let message_hash = process_deactivate_message_hash(claim, msg, enc_pub_key, prev_hash);
        message_hash
    }
}

fn verify_process_deactivate_boundary(
    fields: ProcessDeactivatePublicFields, witness: ProcessDeactivateMessagesBoundaryWitness,
) {
    let coord_pub_key_hash = poseidon_hash2(
        witness.hashes.coord_pub_key_hash, witness.coord_pub_key.v0, witness.coord_pub_key.v1,
    );
    assert_u256_eq(coord_pub_key_hash, fields.coord_pub_key_hash);

    let current_deactivate_commitment = poseidon_hash2(
        witness.hashes.current_deactivate_commitment,
        witness.current_active_state_root,
        witness.current_deactivate_root,
    );
    assert_u256_eq(current_deactivate_commitment, fields.current_deactivate_commitment);
    assert_u256_eq(witness.batch_start_hash, fields.batch_start_hash);
    assert_u256_eq(witness.batch_end_hash, fields.batch_end_hash);
    assert_u256_eq(witness.current_state_root, fields.current_state_root);
    assert_u256_eq(witness.expected_poll_id, fields.expected_poll_id);

    let input_hash = sha256_u256x8_mod_bn254(
        witness.hashes.input_hash,
        U256x8 {
            v0: fields.new_deactivate_root,
            v1: fields.coord_pub_key_hash,
            v2: fields.batch_start_hash,
            v3: fields.batch_end_hash,
            v4: fields.current_deactivate_commitment,
            v5: fields.new_deactivate_commitment,
            v6: fields.current_state_root,
            v7: fields.expected_poll_id,
        },
    );
    assert_u256_eq(input_hash, fields.input_hash);

    let hash_1 = process_deactivate_message_hash_chain_step(
        witness.msg_0,
        witness.enc_pub_key_0,
        witness.batch_start_hash,
        witness.hashes.message_hash_0,
    );
    let hash_2 = process_deactivate_message_hash_chain_step(
        witness.msg_1, witness.enc_pub_key_1, hash_1, witness.hashes.message_hash_1,
    );
    let hash_3 = process_deactivate_message_hash_chain_step(
        witness.msg_2, witness.enc_pub_key_2, hash_2, witness.hashes.message_hash_2,
    );
    let hash_4 = process_deactivate_message_hash_chain_step(
        witness.msg_3, witness.enc_pub_key_3, hash_3, witness.hashes.message_hash_3,
    );
    let hash_5 = process_deactivate_message_hash_chain_step(
        witness.msg_4, witness.enc_pub_key_4, hash_4, witness.hashes.message_hash_4,
    );
    assert_u256_eq(hash_5, witness.batch_end_hash);
}

fn assert_coord_pub_key_matches_private_key(
    coord_priv_key: u256, coord_pub_key: U256x2, witness: BabyJubJubScalarMulWitness,
) {
    let base8 = babyjub_base8();
    assert_u256_eq(witness.scalar, coord_priv_key);
    assert_u256_eq(witness.base.v0, base8.v0);
    assert_u256_eq(witness.base.v1, base8.v1);
    let derived_pub_key = verify_babyjub_scalar_mul(witness);
    assert_u256_eq(derived_pub_key.v0, coord_pub_key.v0);
    assert_u256_eq(derived_pub_key.v1, coord_pub_key.v1);
}

fn coord_priv_key_hash(claim: Hash2Claim, coord_priv_key: u256) -> u256 {
    poseidon_hash2(claim, coord_priv_key, COORD_PRIV_KEY_HASH_DOMAIN)
}

fn packed_cmd_hash(claim: Hash5Claim, packed_cmd: U256x3) -> u256 {
    poseidon_hash5(
        claim,
        U256x5 {
            v0: packed_cmd.v0,
            v1: packed_cmd.v1,
            v2: packed_cmd.v2,
            v3: zero_u256(),
            v4: zero_u256(),
        },
    )
}

fn assert_valid_deactivate_ecdh_kind(ecdh_kind: felt252) {
    assert(
        ecdh_kind == DEACTIVATE_ECDH_KIND_COMMAND || ecdh_kind == DEACTIVATE_ECDH_KIND_LEAF,
        'BAD_DEACT_ECDH_KIND',
    );
}

fn assert_valid_deactivate_decrypt_kind(decrypt_kind: felt252) {
    assert(
        decrypt_kind == DEACTIVATE_DECRYPT_KIND_CURRENT
            || decrypt_kind == DEACTIVATE_DECRYPT_KIND_NEW,
        'BAD_DEACT_DEC_KIND',
    );
}

fn assert_bool_felt(value: felt252) {
    assert(value == 0 || value == 1, 'BAD_BOOL_FELT');
}

fn bool_to_felt(value: bool) -> felt252 {
    if value {
        1
    } else {
        0
    }
}

fn felt_from_u128(value: u128) -> felt252 {
    value.into()
}

fn felt_from_u256(value: u256) -> felt252 {
    felt_from_u128(value.low) + felt_from_u128(value.high) * FELT_TWO_POW_128
}

fn small_felt_to_u256(value: felt252) -> u256 {
    let low: u128 = value.try_into().unwrap();
    u256 { low, high: 0 }
}

fn native_hash_u256(value: u256) -> felt252 {
    poseidon_hash_span([felt_from_u256(value)].span())
}

fn native_hash_u256x2(value: U256x2) -> felt252 {
    poseidon_hash_span([felt_from_u256(value.v0), felt_from_u256(value.v1)].span())
}

fn native_hash_u256x3(value: U256x3) -> felt252 {
    poseidon_hash_span(
        [felt_from_u256(value.v0), felt_from_u256(value.v1), felt_from_u256(value.v2)].span(),
    )
}

fn native_deactivate_command_auth_hash(
    pub_key_hash: felt252,
    r8_hash: felt252,
    packed_cmd_hash: felt252,
    cmd_sig_s_hash: felt252,
    cmd_salt: u256,
    signature_valid: felt252,
) -> felt252 {
    poseidon_hash_span(
        [
            NATIVE_DEACTIVATE_COMMAND_AUTH_DOMAIN,
            pub_key_hash,
            r8_hash,
            packed_cmd_hash,
            cmd_sig_s_hash,
            felt_from_u256(cmd_salt),
            signature_valid,
        ]
            .span(),
    )
}

fn native_deactivate_command_plaintext_binding_hash(
    next_message_hash: felt252,
    shared_key_hash: felt252,
    packed_cmd_hash: felt252,
    signature_pub_key_hash: felt252,
    signature_r8_hash: felt252,
    cmd_sig_s_hash: felt252,
    command_auth_hash: felt252,
) -> felt252 {
    poseidon_hash_span(
        [
            NATIVE_DEACTIVATE_COMMAND_PLAINTEXT_DOMAIN,
            next_message_hash,
            shared_key_hash,
            packed_cmd_hash,
            signature_pub_key_hash,
            signature_r8_hash,
            cmd_sig_s_hash,
            command_auth_hash,
        ]
            .span(),
    )
}

fn native_deactivate_coord_key_binding_hash(
    coord_pub_key_hash: felt252, coord_priv_key_hash: felt252,
) -> felt252 {
    poseidon_hash_span(
        [
            NATIVE_DEACTIVATE_COORD_KEY_BINDING_DOMAIN,
            coord_pub_key_hash,
            coord_priv_key_hash,
        ]
            .span(),
    )
}

fn native_deactivate_shared_key_binding_hash(
    ecdh_kind: felt252,
    coord_priv_key_hash: felt252,
    base_hash: felt252,
    shared_key_hash: felt252,
) -> felt252 {
    poseidon_hash_span(
        [
            NATIVE_DEACTIVATE_SHARED_KEY_DOMAIN,
            ecdh_kind,
            coord_priv_key_hash,
            base_hash,
            shared_key_hash,
        ]
            .span(),
    )
}

fn native_deactivate_decrypt_binding_hash(
    decrypt_kind: felt252,
    coord_priv_key_hash: felt252,
    c1_hash: felt252,
    c2_hash: felt252,
    decrypt_is_odd: felt252,
) -> felt252 {
    poseidon_hash_span(
        [
            NATIVE_DEACTIVATE_DECRYPT_BINDING_DOMAIN,
            decrypt_kind,
            coord_priv_key_hash,
            c1_hash,
            c2_hash,
            decrypt_is_odd,
        ]
            .span(),
    )
}

fn native_hash5_values(v0: felt252, v1: felt252, v2: felt252, v3: felt252, v4: felt252) -> felt252 {
    poseidon_hash_span([v0, v1, v2, v3, v4].span())
}

fn native_hash10_u256(value: U256x10) -> felt252 {
    poseidon_hash_span(
        [
            native_hash5_values(
                felt_from_u256(value.v0),
                felt_from_u256(value.v1),
                felt_from_u256(value.v2),
                felt_from_u256(value.v3),
                felt_from_u256(value.v4),
            ),
            native_hash5_values(
                felt_from_u256(value.v5),
                felt_from_u256(value.v6),
                felt_from_u256(value.v7),
                felt_from_u256(value.v8),
                felt_from_u256(value.v9),
            ),
        ]
            .span(),
    )
}

fn native_coord_priv_key_hash(coord_priv_key: u256) -> felt252 {
    poseidon_hash_span(
        [felt_from_u256(coord_priv_key), NATIVE_COORD_PRIV_KEY_HASH_DOMAIN].span(),
    )
}

fn native_deactivate_message_hash(
    message: U256x10, enc_pub_key: U256x2, previous_hash: felt252,
) -> felt252 {
    poseidon_hash_span(
        [
            felt_from_u256(message.v0),
            felt_from_u256(message.v1),
            felt_from_u256(message.v2),
            felt_from_u256(message.v3),
            felt_from_u256(message.v4),
            felt_from_u256(message.v5),
            felt_from_u256(message.v6),
            felt_from_u256(message.v7),
            felt_from_u256(message.v8),
            felt_from_u256(message.v9),
            felt_from_u256(enc_pub_key.v0),
            felt_from_u256(enc_pub_key.v1),
            previous_hash,
        ]
            .span(),
    )
}

fn native_deactivate_message_hash_or_empty(
    message: U256x10, enc_pub_key: U256x2, previous_hash: felt252,
) -> felt252 {
    if is_zero(message.v0) {
        previous_hash
    } else {
        native_deactivate_message_hash(message, enc_pub_key, previous_hash)
    }
}

fn native_commitment(left: felt252, right: felt252) -> felt252 {
    poseidon_hash_span([left, right].span())
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
        native_hash5_values(p0, p1, p2, p3, leaf)
    }
}

fn native_quinary_root_depth_2(
    leaf: felt252, path_0: U256x4, path_1: U256x4, index: u256,
) -> felt252 {
    let level_0_index = index.low % 5;
    let level_1_index = (index.low / 5) % 5;
    let level_0 = native_path_hash(leaf, path_0, level_0_index);
    native_path_hash(level_0, path_1, level_1_index)
}

fn native_quinary_root_depth_4(
    leaf: felt252,
    path_0: U256x4,
    path_1: U256x4,
    path_2: U256x4,
    path_3: U256x4,
    index: u256,
) -> felt252 {
    let level_0_index = index.low % 5;
    let level_1_index = (index.low / 5) % 5;
    let level_2_index = (index.low / 25) % 5;
    let level_3_index = (index.low / 125) % 5;
    let level_0 = native_path_hash(leaf, path_0, level_0_index);
    let level_1 = native_path_hash(level_0, path_1, level_1_index);
    let level_2 = native_path_hash(level_1, path_2, level_2_index);
    native_path_hash(level_2, path_3, level_3_index)
}

fn verify_native_process_deactivate_coord_key(
    fields: NativeProcessDeactivateCoordKeyPublicFields, witness: NativeProcessDeactivateCoordKeyWitness,
) {
    assert(native_hash_u256x2(witness.coord_pub_key) == fields.coord_pub_key_hash, 'N_COORD_KEY');
    assert(
        native_coord_priv_key_hash(witness.coord_priv_key) == fields.coord_priv_key_hash,
        'N_COORD_PRIV',
    );
    assert(
        native_deactivate_coord_key_binding_hash(
            fields.coord_pub_key_hash, fields.coord_priv_key_hash,
        ) == fields.coord_key_binding_hash,
        'N_COORD_BIND',
    );
}

fn verify_native_process_deactivate_ecdh(
    fields: NativeProcessDeactivateEcdhPublicFields, witness: NativeProcessDeactivateEcdhWitness,
) {
    assert_valid_deactivate_message_index(fields.message_index);
    assert_valid_deactivate_ecdh_kind(fields.ecdh_kind);
    assert(
        native_coord_priv_key_hash(witness.coord_priv_key) == fields.coord_priv_key_hash,
        'N_COORD_PRIV',
    );
    assert(native_hash_u256x2(witness.base) == fields.base_hash, 'N_BASE');
    assert(native_hash_u256x2(witness.shared_key) == fields.shared_key_hash, 'N_SHARED_KEY');
    assert(
        native_deactivate_shared_key_binding_hash(
            fields.ecdh_kind,
            fields.coord_priv_key_hash,
            fields.base_hash,
            fields.shared_key_hash,
        ) == fields.shared_key_binding_hash,
        'N_SHARED_BIND',
    );
}

fn verify_native_process_deactivate_signature(
    fields: NativeProcessDeactivateSignaturePublicFields, witness: NativeProcessDeactivateSignatureWitness,
) {
    assert_valid_deactivate_message_index(fields.message_index);
    assert_bool_felt(fields.signature_valid);
    assert(native_hash_u256x2(witness.pub_key) == fields.pub_key_hash, 'N_PUB_KEY');
    assert(native_hash_u256x2(witness.r8) == fields.r8_hash, 'N_R8');
    assert(native_hash_u256x3(witness.packed_cmd) == fields.packed_cmd_hash, 'N_CMD');
    assert(native_hash_u256(witness.s) == fields.cmd_sig_s_hash, 'N_SIG_S');
    assert(
        native_deactivate_command_auth_hash(
            fields.pub_key_hash,
            fields.r8_hash,
            fields.packed_cmd_hash,
            fields.cmd_sig_s_hash,
            witness.cmd_salt,
            fields.signature_valid,
        ) == fields.command_auth_hash,
        'N_CMD_AUTH',
    );
}

fn verify_native_process_deactivate_decrypt(
    fields: NativeProcessDeactivateDecryptPublicFields, witness: NativeProcessDeactivateDecryptWitness,
) {
    assert_valid_deactivate_message_index(fields.message_index);
    assert_valid_deactivate_decrypt_kind(fields.decrypt_kind);
    assert_bool_felt(fields.decrypt_is_odd);
    assert(
        native_coord_priv_key_hash(witness.coord_priv_key) == fields.coord_priv_key_hash,
        'N_COORD_PRIV',
    );
    assert(native_hash_u256x2(witness.c1) == fields.c1_hash, 'N_C1');
    assert(native_hash_u256x2(witness.c2) == fields.c2_hash, 'N_C2');
    assert(
        native_deactivate_decrypt_binding_hash(
            fields.decrypt_kind,
            fields.coord_priv_key_hash,
            fields.c1_hash,
            fields.c2_hash,
            fields.decrypt_is_odd,
        ) == fields.decrypt_binding_hash,
        'N_DECRYPT_BIND',
    );
}

fn verify_native_process_deactivate_step_core(
    fields: NativeProcessDeactivateStepCorePublicFields, witness: ProcessDeactivateStepCoreWitness,
) {
    assert_valid_deactivate_message_index(fields.message_index);
    let deactivate_index = small_felt_to_u256(fields.deactivate_index);
    let expected_poll_id = small_felt_to_u256(fields.expected_poll_id);
    assert_deactivate_index(deactivate_index);
    assert_bool_felt(fields.signature_valid);
    assert_bool_felt(fields.current_decrypt_is_odd);
    assert_bool_felt(fields.new_decrypt_is_odd);
    assert_bool_u256(witness.is_empty_msg);
    assert_u256_eq(witness.is_empty_msg, zero_u256());
    assert(!is_zero(witness.msg.v0), 'N_EMPTY_MSG');

    assert(
        native_coord_priv_key_hash(witness.coord_priv_key) == fields.coord_priv_key_hash,
        'N_COORD_PRIV',
    );
    assert(native_hash_u256x2(witness.enc_pub_key) == fields.enc_pub_key_hash, 'N_ENC_KEY');
    assert(
        native_hash_u256x2(witness.command_shared_key) == fields.command_shared_key_hash,
        'N_CMD_SHARED',
    );
    assert(
        native_deactivate_shared_key_binding_hash(
            0,
            fields.coord_priv_key_hash,
            fields.enc_pub_key_hash,
            fields.command_shared_key_hash,
        ) == fields.command_shared_key_binding_hash,
        'N_CMD_BIND',
    );
    assert(
        native_hash_u256x2(U256x2 { v0: witness.state_leaf.v0, v1: witness.state_leaf.v1 })
            == fields.signature_pub_key_hash,
        'N_SIG_PUB',
    );
    assert(native_hash_u256x2(witness.cmd_sig_r8) == fields.signature_r8_hash, 'N_R8');
    assert(native_hash_u256x3(witness.packed_cmd) == fields.packed_cmd_hash, 'N_CMD');
    assert(native_hash_u256(witness.cmd_sig_s) == fields.cmd_sig_s_hash, 'N_SIG_S');
    assert(
        native_deactivate_command_auth_hash(
            fields.signature_pub_key_hash,
            fields.signature_r8_hash,
            fields.packed_cmd_hash,
            fields.cmd_sig_s_hash,
            witness.decrypted_command.v3,
            fields.signature_valid,
        ) == fields.command_auth_hash,
        'N_CMD_AUTH',
    );
    assert(
        native_deactivate_command_plaintext_binding_hash(
            fields.next_message_hash,
            fields.command_shared_key_hash,
            fields.packed_cmd_hash,
            fields.signature_pub_key_hash,
            fields.signature_r8_hash,
            fields.cmd_sig_s_hash,
            fields.command_auth_hash,
        ) == fields.command_plaintext_binding_hash,
        'N_CMD_PLAIN',
    );
    assert(witness.signature_valid.high == 0, 'SIG_BOOL_HIGH');
    assert(felt_from_u128(witness.signature_valid.low) == fields.signature_valid, 'SIG_VALID');
    assert(
        native_hash_u256x2(U256x2 { v0: witness.state_leaf.v5, v1: witness.state_leaf.v6 })
            == fields.current_state_ciphertext_c1_hash,
        'N_CUR_C1',
    );
    assert(
        native_hash_u256x2(U256x2 { v0: witness.state_leaf.v7, v1: witness.state_leaf.v8 })
            == fields.current_state_ciphertext_c2_hash,
        'N_CUR_C2',
    );
    assert(witness.current_decrypt_is_odd.high == 0, 'CUR_DEC_HIGH');
    assert(
        felt_from_u128(witness.current_decrypt_is_odd.low) == fields.current_decrypt_is_odd,
        'CUR_DEC_ODD',
    );
    assert(
        native_deactivate_decrypt_binding_hash(
            0,
            fields.coord_priv_key_hash,
            fields.current_state_ciphertext_c1_hash,
            fields.current_state_ciphertext_c2_hash,
            fields.current_decrypt_is_odd,
        ) == fields.current_decrypt_binding_hash,
        'N_CUR_DEC_BIND',
    );
    assert(native_hash_u256x2(witness.c1) == fields.new_state_ciphertext_c1_hash, 'N_NEW_C1');
    assert(native_hash_u256x2(witness.c2) == fields.new_state_ciphertext_c2_hash, 'N_NEW_C2');
    assert(witness.new_decrypt_is_odd.high == 0, 'NEW_DEC_HIGH');
    assert(
        felt_from_u128(witness.new_decrypt_is_odd.low) == fields.new_decrypt_is_odd,
        'NEW_DEC_ODD',
    );
    assert(
        native_deactivate_decrypt_binding_hash(
            1,
            fields.coord_priv_key_hash,
            fields.new_state_ciphertext_c1_hash,
            fields.new_state_ciphertext_c2_hash,
            fields.new_decrypt_is_odd,
        ) == fields.new_decrypt_binding_hash,
        'N_NEW_DEC_BIND',
    );
    assert(
        native_hash_u256x2(U256x2 { v0: witness.state_leaf.v0, v1: witness.state_leaf.v1 })
            == fields.deactivate_pub_key_hash,
        'N_DEACT_PUB',
    );
    let deactivate_shared_key_hash = poseidon_hash2(
        witness.deactivate_shared_key_hash_claim,
        witness.deactivate_shared_key.v0,
        witness.deactivate_shared_key.v1,
    );
    assert_u256_eq(deactivate_shared_key_hash, witness.deactivate_shared_key_hash);
    assert(
        native_hash_u256x2(witness.deactivate_shared_key) == fields.deactivate_shared_key_hash,
        'N_DEACT_SHARED',
    );
    assert(
        native_deactivate_shared_key_binding_hash(
            1,
            fields.coord_priv_key_hash,
            fields.deactivate_pub_key_hash,
            fields.deactivate_shared_key_hash,
        ) == fields.deactivate_shared_key_binding_hash,
        'N_DEACT_BIND',
    );

    let next_message_hash = native_deactivate_message_hash_or_empty(
        witness.msg, witness.enc_pub_key, fields.previous_message_hash,
    );
    assert(next_message_hash == fields.next_message_hash, 'N_NEXT_MSG');

    validate_poseidon_decryption(witness.msg, witness.command_shared_key, witness.decrypted_command);
    assert_u256_eq(witness.packed_cmd.v0, witness.decrypted_command.v0);
    assert_u256_eq(witness.packed_cmd.v1, witness.decrypted_command.v1);
    assert_u256_eq(witness.packed_cmd.v2, witness.decrypted_command.v2);
    assert_u256_eq(witness.cmd_sig_r8.v0, witness.decrypted_command.v4);
    assert_u256_eq(witness.cmd_sig_r8.v1, witness.decrypted_command.v5);
    assert_u256_eq(witness.cmd_sig_s, witness.decrypted_command.v6);
    let unpacked = unpack_command_data(witness.packed_cmd.v0);
    assert_u256_eq(witness.cmd_poll_id, unpacked.v0);
    assert_u256_eq(witness.cmd_state_index, unpacked.v5);
    assert(witness.cmd_poll_id.high == 0, 'POLL_HIGH');
    assert(felt_from_u128(witness.cmd_poll_id.low) == fields.expected_poll_id, 'POLL_ID');

    let valid_poll_id = witness.cmd_poll_id == expected_poll_id;
    let signature_valid = u256_bool(witness.signature_valid);
    let current_decrypt_is_odd = u256_bool(witness.current_decrypt_is_odd);
    let valid = signature_valid && !current_decrypt_is_odd && valid_poll_id;
    let new_decrypt_is_odd = u256_bool(witness.new_decrypt_is_odd);
    assert_u256_eq(bool_to_u256(valid), bool_to_u256(!new_decrypt_is_odd));

    let state_index = select_u256(
        valid_state_index(witness.cmd_state_index), STATE_TREE_MAX_INDEX, witness.cmd_state_index,
    );
    let state_leaf_hash = native_hash10_u256(witness.state_leaf);
    let current_state_root = native_quinary_root_depth_2(
        state_leaf_hash, witness.state_leaf_path_0, witness.state_leaf_path_1, state_index,
    );
    assert(current_state_root == fields.current_state_root_hash, 'N_STATE_ROOT');

    assert(!is_zero(witness.new_active_state), 'NEW_ACTIVE_ZERO');
    let current_active_state_root = native_quinary_root_depth_2(
        felt_from_u256(witness.current_active_state),
        witness.active_state_leaf_path_0,
        witness.active_state_leaf_path_1,
        state_index,
    );
    assert(current_active_state_root == fields.current_active_state_root_hash, 'N_CUR_ACTIVE');
    let active_state_leaf = select_u256(valid, witness.current_active_state, witness.new_active_state);
    let new_active_state_root = native_quinary_root_depth_2(
        felt_from_u256(active_state_leaf),
        witness.active_state_leaf_path_0,
        witness.active_state_leaf_path_1,
        state_index,
    );
    assert(new_active_state_root == fields.new_active_state_root_hash, 'N_NEW_ACTIVE');

    let deactivate_leaf = native_hash5_values(
        felt_from_u256(witness.c1.v0),
        felt_from_u256(witness.c1.v1),
        felt_from_u256(witness.c2.v0),
        felt_from_u256(witness.c2.v1),
        fields.deactivate_shared_key_hash,
    );
    let current_deactivate_root = native_quinary_root_depth_4(
        0,
        witness.deactivate_leaf_path_0,
        witness.deactivate_leaf_path_1,
        witness.deactivate_leaf_path_2,
        witness.deactivate_leaf_path_3,
        deactivate_index,
    );
    assert(current_deactivate_root == fields.current_deactivate_root_hash, 'N_CUR_DEACT');
    let new_deactivate_leaf = if u256_bool(witness.is_empty_msg) {
        0
    } else {
        deactivate_leaf
    };
    let new_deactivate_root = native_quinary_root_depth_4(
        new_deactivate_leaf,
        witness.deactivate_leaf_path_0,
        witness.deactivate_leaf_path_1,
        witness.deactivate_leaf_path_2,
        witness.deactivate_leaf_path_3,
        deactivate_index,
    );
    assert(new_deactivate_root == fields.new_deactivate_root_hash, 'N_NEW_DEACT');

    let current_deactivate_commitment = native_commitment(
        current_active_state_root, current_deactivate_root,
    );
    assert(
        current_deactivate_commitment == fields.current_deactivate_commitment_hash,
        'N_CUR_COMMIT',
    );
    let new_deactivate_commitment = native_commitment(new_active_state_root, new_deactivate_root);
    assert(
        new_deactivate_commitment == fields.new_deactivate_commitment_hash,
        'N_NEW_COMMIT',
    );
}

fn verify_process_deactivate_coord_key(
    fields: ProcessDeactivateCoordKeyPublicFields, witness: ProcessDeactivateCoordKeyWitness,
) {
    assert_coord_pub_key_matches_private_key(
        witness.coord_priv_key, witness.coord_pub_key, witness.coord_pub_key_scalar_mul,
    );
    let coord_pub_key_hash = poseidon_hash2(
        witness.coord_pub_key_hash, witness.coord_pub_key.v0, witness.coord_pub_key.v1,
    );
    assert_u256_eq(coord_pub_key_hash, fields.coord_pub_key_hash);
    let private_hash = coord_priv_key_hash(witness.coord_priv_key_hash, witness.coord_priv_key);
    assert_u256_eq(private_hash, fields.coord_priv_key_hash);
}

fn verify_process_deactivate_ecdh(
    fields: ProcessDeactivateEcdhPublicFields, witness: ProcessDeactivateEcdhWitness,
) {
    assert_valid_deactivate_message_index(fields.message_index);
    assert_valid_deactivate_ecdh_kind(fields.ecdh_kind);
    let private_hash = coord_priv_key_hash(witness.coord_priv_key_hash, witness.coord_priv_key);
    assert_u256_eq(private_hash, fields.coord_priv_key_hash);
    let base_hash = poseidon_hash2(witness.base_hash, witness.base.v0, witness.base.v1);
    assert_u256_eq(base_hash, fields.base_hash);

    assert_u256_eq(witness.ecdh.scalar, witness.coord_priv_key);
    assert_u256_eq(witness.ecdh.base.v0, witness.base.v0);
    assert_u256_eq(witness.ecdh.base.v1, witness.base.v1);
    let shared_key = verify_babyjub_scalar_mul(witness.ecdh);
    let shared_key_hash = poseidon_hash2(witness.shared_key_hash, shared_key.v0, shared_key.v1);
    assert_u256_eq(shared_key_hash, fields.shared_key_hash);
}

fn verify_process_deactivate_signature(
    fields: ProcessDeactivateSignaturePublicFields, witness: ProcessDeactivateSignatureWitness,
) {
    assert_valid_deactivate_message_index(fields.message_index);
    assert_bool_u256(fields.signature_valid);
    let pub_key_hash = poseidon_hash2(witness.pub_key_hash, witness.pub_key.v0, witness.pub_key.v1);
    assert_u256_eq(pub_key_hash, fields.pub_key_hash);
    let r8_hash = poseidon_hash2(witness.r8_hash, witness.r8.v0, witness.r8.v1);
    assert_u256_eq(r8_hash, fields.r8_hash);
    let command_hash = packed_cmd_hash(witness.packed_cmd_hash, witness.packed_cmd);
    assert_u256_eq(command_hash, fields.packed_cmd_hash);
    assert_u256_eq(witness.s, fields.cmd_sig_s);
    let valid = verify_babyjub_poseidon_signature(
        witness.pub_key, witness.r8, witness.s, witness.packed_cmd, witness.signature,
    );
    assert_u256_eq(valid, fields.signature_valid);
}

fn verify_process_deactivate_decrypt(
    fields: ProcessDeactivateDecryptPublicFields, witness: ProcessDeactivateDecryptWitness,
) {
    assert_valid_deactivate_message_index(fields.message_index);
    assert_valid_deactivate_decrypt_kind(fields.decrypt_kind);
    assert_bool_u256(fields.decrypt_is_odd);
    let private_hash = coord_priv_key_hash(witness.coord_priv_key_hash, witness.coord_priv_key);
    assert_u256_eq(private_hash, fields.coord_priv_key_hash);
    let c1_hash = poseidon_hash2(witness.c1_hash, witness.c1.v0, witness.c1.v1);
    assert_u256_eq(c1_hash, fields.c1_hash);
    let c2_hash = poseidon_hash2(witness.c2_hash, witness.c2.v0, witness.c2.v1);
    assert_u256_eq(c2_hash, fields.c2_hash);
    let decrypt_is_odd = assert_elgamal_decrypt(
        witness.decrypt, witness.coord_priv_key, witness.c1, witness.c2,
    );
    assert_u256_eq(bool_to_u256(decrypt_is_odd), fields.decrypt_is_odd);
}

fn process_deactivate_one(witness: ProcessDeactivateOneWitness) -> ProcessDeactivateOneOutput {
    let is_empty_msg = u256_bool(witness.is_empty_msg);
    let pub_key = U256x2 { v0: witness.state_leaf.v0, v1: witness.state_leaf.v1 };
    let signature_valid = verify_babyjub_poseidon_signature(
        pub_key, witness.cmd_sig_r8, witness.cmd_sig_s, witness.packed_cmd, witness.signature,
    ) == 1;
    let current_decrypt_is_odd = assert_elgamal_decrypt(
        witness.current_state_decrypt,
        witness.coord_priv_key,
        U256x2 { v0: witness.state_leaf.v5, v1: witness.state_leaf.v6 },
        U256x2 { v0: witness.state_leaf.v7, v1: witness.state_leaf.v8 },
    );
    let valid_poll_id = witness.cmd_poll_id == witness.expected_poll_id;
    let valid = signature_valid && !current_decrypt_is_odd && valid_poll_id;

    let new_decrypt_is_odd = assert_elgamal_decrypt(
        witness.new_state_decrypt, witness.coord_priv_key, witness.c1, witness.c2,
    );
    assert_u256_eq(bool_to_u256(valid), bool_to_u256(!new_decrypt_is_odd));

    let state_index = select_u256(
        valid_state_index(witness.cmd_state_index), STATE_TREE_MAX_INDEX, witness.cmd_state_index,
    );
    let state_leaf_hash = poseidon_hash10(witness.hashes.state_leaf_hash, witness.state_leaf);
    let current_state_root = quinary_root_depth_2(
        state_leaf_hash, witness.state_leaf_path_0, witness.state_leaf_path_1, state_index,
    );
    assert_u256_eq(current_state_root, witness.current_state_root);

    let shared_key_hash = assert_deactivate_ecdh(
        witness.deactivate_ecdh, witness.coord_priv_key, pub_key, witness.hashes.shared_key_hash,
    );
    let deactivate_leaf = poseidon_hash5(
        witness.hashes.deactivate_leaf,
        U256x5 {
            v0: witness.c1.v0,
            v1: witness.c1.v1,
            v2: witness.c2.v0,
            v3: witness.c2.v1,
            v4: shared_key_hash,
        },
    );

    assert(!is_zero(witness.new_active_state), 'NEW_ACTIVE_ZERO');
    let current_active_state_root = quinary_root_depth_2(
        witness.current_active_state,
        witness.active_state_leaf_path_0,
        witness.active_state_leaf_path_1,
        state_index,
    );
    assert_u256_eq(current_active_state_root, witness.current_active_state_root);
    let active_state_leaf = select_u256(
        valid, witness.current_active_state, witness.new_active_state,
    );
    let new_active_state_root = quinary_root_depth_2(
        active_state_leaf,
        witness.active_state_leaf_path_0,
        witness.active_state_leaf_path_1,
        state_index,
    );

    let current_deactivate_root = quinary_root_depth_4(
        zero_u256(),
        witness.deactivate_leaf_path_0,
        witness.deactivate_leaf_path_1,
        witness.deactivate_leaf_path_2,
        witness.deactivate_leaf_path_3,
        witness.deactivate_index,
    );
    assert_u256_eq(current_deactivate_root, witness.current_deactivate_root);
    let new_deactivate_leaf = select_u256(is_empty_msg, deactivate_leaf, zero_u256());
    let new_deactivate_root = quinary_root_depth_4(
        new_deactivate_leaf,
        witness.deactivate_leaf_path_0,
        witness.deactivate_leaf_path_1,
        witness.deactivate_leaf_path_2,
        witness.deactivate_leaf_path_3,
        witness.deactivate_index,
    );

    ProcessDeactivateOneOutput { new_active_state_root, new_deactivate_root }
}

fn process_deactivate_messages_chain_step(
    process_one: ProcessDeactivateOneWitness,
    expected_coord_priv_key: u256,
    expected_current_state_root: u256,
    expected_active_state_root: u256,
    expected_deactivate_root: u256,
    expected_poll_id: u256,
    expected_deactivate_index: u256,
) -> ProcessDeactivateOneOutput {
    assert_u256_eq(process_one.coord_priv_key, expected_coord_priv_key);
    assert_u256_eq(process_one.current_state_root, expected_current_state_root);
    assert_u256_eq(process_one.current_active_state_root, expected_active_state_root);
    assert_u256_eq(process_one.current_deactivate_root, expected_deactivate_root);
    assert_u256_eq(process_one.expected_poll_id, expected_poll_id);
    assert_u256_eq(process_one.deactivate_index, expected_deactivate_index);
    process_deactivate_one(process_one)
}

fn process_deactivate_messages_bound_chain_step(
    msg: U256x10,
    enc_pub_key: U256x2,
    command: ProcessDeactivateMessageCommandWitness,
    process_one: ProcessDeactivateOneWitness,
    expected_coord_priv_key: u256,
    expected_current_state_root: u256,
    expected_active_state_root: u256,
    expected_deactivate_root: u256,
    expected_poll_id: u256,
    expected_deactivate_index: u256,
) -> ProcessDeactivateOneOutput {
    let empty = is_zero(msg.v0);
    assert_u256_eq(process_one.is_empty_msg, bool_to_u256(empty));
    if empty {
        assert_u256_eq(process_one.current_active_state_root, expected_active_state_root);
        assert_u256_eq(process_one.current_deactivate_root, expected_deactivate_root);
        ProcessDeactivateOneOutput {
            new_active_state_root: expected_active_state_root,
            new_deactivate_root: expected_deactivate_root,
        }
    } else {
        assert_u256_eq(command.ecdh.scalar, expected_coord_priv_key);
        assert_u256_eq(command.ecdh.base.v0, enc_pub_key.v0);
        assert_u256_eq(command.ecdh.base.v1, enc_pub_key.v1);
        let shared_key = verify_babyjub_scalar_mul(command.ecdh);
        validate_poseidon_decryption(msg, shared_key, command.decrypted_command);
        assert_u256_eq(process_one.packed_cmd.v0, command.decrypted_command.v0);
        assert_u256_eq(process_one.packed_cmd.v1, command.decrypted_command.v1);
        assert_u256_eq(process_one.packed_cmd.v2, command.decrypted_command.v2);
        assert_u256_eq(process_one.cmd_sig_r8.v0, command.decrypted_command.v4);
        assert_u256_eq(process_one.cmd_sig_r8.v1, command.decrypted_command.v5);
        assert_u256_eq(process_one.cmd_sig_s, command.decrypted_command.v6);
        let unpacked = unpack_command_data(process_one.packed_cmd.v0);
        assert_u256_eq(process_one.cmd_poll_id, unpacked.v0);
        assert_u256_eq(process_one.cmd_state_index, unpacked.v5);
        process_deactivate_messages_chain_step(
            process_one,
            expected_coord_priv_key,
            expected_current_state_root,
            expected_active_state_root,
            expected_deactivate_root,
            expected_poll_id,
            expected_deactivate_index,
        )
    }
}

fn process_deactivate_messages_state_transition(
    witness: ProcessDeactivateMessagesStateTransitionWitness,
) -> ProcessDeactivateMessagesStateOutput {
    let output_0 = process_deactivate_messages_chain_step(
        witness.process_one_0,
        witness.coord_priv_key,
        witness.current_state_root,
        witness.current_active_state_root,
        witness.current_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0,
    );
    let output_1 = process_deactivate_messages_chain_step(
        witness.process_one_1,
        witness.coord_priv_key,
        witness.current_state_root,
        output_0.new_active_state_root,
        output_0.new_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0 + 1,
    );
    let output_2 = process_deactivate_messages_chain_step(
        witness.process_one_2,
        witness.coord_priv_key,
        witness.current_state_root,
        output_1.new_active_state_root,
        output_1.new_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0 + 2,
    );
    let output_3 = process_deactivate_messages_chain_step(
        witness.process_one_3,
        witness.coord_priv_key,
        witness.current_state_root,
        output_2.new_active_state_root,
        output_2.new_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0 + 3,
    );
    let output_4 = process_deactivate_messages_chain_step(
        witness.process_one_4,
        witness.coord_priv_key,
        witness.current_state_root,
        output_3.new_active_state_root,
        output_3.new_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0 + 4,
    );
    ProcessDeactivateMessagesStateOutput {
        new_active_state_root: output_4.new_active_state_root,
        new_deactivate_root: output_4.new_deactivate_root,
    }
}

fn process_deactivate_messages_bound_state_transition(
    boundary: ProcessDeactivateMessagesBoundaryWitness,
    witness: ProcessDeactivateMessagesStateTransitionWitness,
    command_0: ProcessDeactivateMessageCommandWitness,
    command_1: ProcessDeactivateMessageCommandWitness,
    command_2: ProcessDeactivateMessageCommandWitness,
    command_3: ProcessDeactivateMessageCommandWitness,
    command_4: ProcessDeactivateMessageCommandWitness,
) -> ProcessDeactivateMessagesStateOutput {
    let output_0 = process_deactivate_messages_bound_chain_step(
        boundary.msg_0,
        boundary.enc_pub_key_0,
        command_0,
        witness.process_one_0,
        witness.coord_priv_key,
        witness.current_state_root,
        witness.current_active_state_root,
        witness.current_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0,
    );
    let output_1 = process_deactivate_messages_bound_chain_step(
        boundary.msg_1,
        boundary.enc_pub_key_1,
        command_1,
        witness.process_one_1,
        witness.coord_priv_key,
        witness.current_state_root,
        output_0.new_active_state_root,
        output_0.new_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0 + 1,
    );
    let output_2 = process_deactivate_messages_bound_chain_step(
        boundary.msg_2,
        boundary.enc_pub_key_2,
        command_2,
        witness.process_one_2,
        witness.coord_priv_key,
        witness.current_state_root,
        output_1.new_active_state_root,
        output_1.new_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0 + 2,
    );
    let output_3 = process_deactivate_messages_bound_chain_step(
        boundary.msg_3,
        boundary.enc_pub_key_3,
        command_3,
        witness.process_one_3,
        witness.coord_priv_key,
        witness.current_state_root,
        output_2.new_active_state_root,
        output_2.new_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0 + 3,
    );
    let output_4 = process_deactivate_messages_bound_chain_step(
        boundary.msg_4,
        boundary.enc_pub_key_4,
        command_4,
        witness.process_one_4,
        witness.coord_priv_key,
        witness.current_state_root,
        output_3.new_active_state_root,
        output_3.new_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0 + 4,
    );
    ProcessDeactivateMessagesStateOutput {
        new_active_state_root: output_4.new_active_state_root,
        new_deactivate_root: output_4.new_deactivate_root,
    }
}

fn assert_valid_deactivate_message_index(message_index: felt252) {
    assert(
        message_index == 0
            || message_index == 1
            || message_index == 2
            || message_index == 3
            || message_index == 4,
        'BAD_DEACT_MSG_INDEX',
    );
}

fn verify_process_deactivate_message_step(
    fields: ProcessDeactivateStepPublicFields, witness: ProcessDeactivateMessageStepWitness,
) {
    assert_valid_deactivate_message_index(fields.message_index);
    assert_deactivate_index(fields.deactivate_index);
    assert_coord_pub_key_matches_private_key(
        witness.coord_priv_key, witness.coord_pub_key, witness.coord_pub_key_scalar_mul,
    );
    let coord_pub_key_hash = poseidon_hash2(
        witness.coord_pub_key_hash, witness.coord_pub_key.v0, witness.coord_pub_key.v1,
    );
    assert_u256_eq(coord_pub_key_hash, fields.coord_pub_key_hash);

    let next_message_hash = process_deactivate_message_hash_chain_step(
        witness.msg, witness.enc_pub_key, fields.previous_message_hash, witness.message_hash,
    );
    assert_u256_eq(next_message_hash, fields.next_message_hash);

    assert_u256_eq(witness.process_one.coord_priv_key, witness.coord_priv_key);
    assert_u256_eq(witness.process_one.current_state_root, fields.current_state_root);
    assert_u256_eq(witness.process_one.current_active_state_root, fields.current_active_state_root);
    assert_u256_eq(witness.process_one.current_deactivate_root, fields.current_deactivate_root);
    assert_u256_eq(witness.process_one.expected_poll_id, fields.expected_poll_id);
    assert_u256_eq(witness.process_one.deactivate_index, fields.deactivate_index);

    let current_deactivate_commitment = poseidon_hash2(
        witness.current_deactivate_commitment,
        fields.current_active_state_root,
        fields.current_deactivate_root,
    );
    assert_u256_eq(current_deactivate_commitment, fields.current_deactivate_commitment);

    let output = process_deactivate_messages_bound_chain_step(
        witness.msg,
        witness.enc_pub_key,
        witness.command,
        witness.process_one,
        witness.coord_priv_key,
        fields.current_state_root,
        fields.current_active_state_root,
        fields.current_deactivate_root,
        fields.expected_poll_id,
        fields.deactivate_index,
    );
    assert_u256_eq(output.new_active_state_root, fields.new_active_state_root);
    assert_u256_eq(output.new_deactivate_root, fields.new_deactivate_root);

    let new_deactivate_commitment = poseidon_hash2(
        witness.new_deactivate_commitment, output.new_active_state_root, output.new_deactivate_root,
    );
    assert_u256_eq(new_deactivate_commitment, fields.new_deactivate_commitment);
}

fn verify_process_deactivate_step_core_claims(
    fields: ProcessDeactivateStepCorePublicFields, witness: ProcessDeactivateStepCoreWitness,
) {
    let private_hash = coord_priv_key_hash(witness.coord_priv_key_hash, witness.coord_priv_key);
    assert_u256_eq(private_hash, fields.coord_priv_key_hash);
    let enc_pub_key_hash = poseidon_hash2(
        witness.enc_pub_key_hash, witness.enc_pub_key.v0, witness.enc_pub_key.v1,
    );
    assert_u256_eq(enc_pub_key_hash, fields.enc_pub_key_hash);
    let command_shared_key_hash = poseidon_hash2(
        witness.command_shared_key_hash,
        witness.command_shared_key.v0,
        witness.command_shared_key.v1,
    );
    assert_u256_eq(command_shared_key_hash, fields.command_shared_key_hash);
    let signature_pub_key_hash = poseidon_hash2(
        witness.signature_pub_key_hash, witness.state_leaf.v0, witness.state_leaf.v1,
    );
    assert_u256_eq(signature_pub_key_hash, fields.signature_pub_key_hash);
    let signature_r8_hash = poseidon_hash2(
        witness.signature_r8_hash, witness.cmd_sig_r8.v0, witness.cmd_sig_r8.v1,
    );
    assert_u256_eq(signature_r8_hash, fields.signature_r8_hash);
    let command_hash = packed_cmd_hash(witness.packed_cmd_hash, witness.packed_cmd);
    assert_u256_eq(command_hash, fields.packed_cmd_hash);
    assert_u256_eq(witness.cmd_sig_s, fields.cmd_sig_s);
    assert_u256_eq(witness.signature_valid, fields.signature_valid);
    let current_c1_hash = poseidon_hash2(
        witness.current_state_ciphertext_c1_hash, witness.state_leaf.v5, witness.state_leaf.v6,
    );
    assert_u256_eq(current_c1_hash, fields.current_state_ciphertext_c1_hash);
    let current_c2_hash = poseidon_hash2(
        witness.current_state_ciphertext_c2_hash, witness.state_leaf.v7, witness.state_leaf.v8,
    );
    assert_u256_eq(current_c2_hash, fields.current_state_ciphertext_c2_hash);
    assert_u256_eq(witness.current_decrypt_is_odd, fields.current_decrypt_is_odd);
    let new_c1_hash = poseidon_hash2(
        witness.new_state_ciphertext_c1_hash, witness.c1.v0, witness.c1.v1,
    );
    assert_u256_eq(new_c1_hash, fields.new_state_ciphertext_c1_hash);
    let new_c2_hash = poseidon_hash2(
        witness.new_state_ciphertext_c2_hash, witness.c2.v0, witness.c2.v1,
    );
    assert_u256_eq(new_c2_hash, fields.new_state_ciphertext_c2_hash);
    assert_u256_eq(witness.new_decrypt_is_odd, fields.new_decrypt_is_odd);
    let deactivate_pub_key_hash = poseidon_hash2(
        witness.deactivate_pub_key_hash, witness.state_leaf.v0, witness.state_leaf.v1,
    );
    assert_u256_eq(deactivate_pub_key_hash, fields.deactivate_pub_key_hash);
    let deactivate_shared_key_hash = poseidon_hash2(
        witness.deactivate_shared_key_hash_claim,
        witness.deactivate_shared_key.v0,
        witness.deactivate_shared_key.v1,
    );
    assert_u256_eq(deactivate_shared_key_hash, witness.deactivate_shared_key_hash);
    assert_u256_eq(witness.deactivate_shared_key_hash, fields.deactivate_shared_key_hash);
}

fn verify_process_deactivate_step_core(
    fields: ProcessDeactivateStepCorePublicFields, witness: ProcessDeactivateStepCoreWitness,
) {
    assert_valid_deactivate_message_index(fields.message_index);
    assert_deactivate_index(fields.deactivate_index);
    assert_bool_u256(fields.signature_valid);
    assert_bool_u256(fields.current_decrypt_is_odd);
    assert_bool_u256(fields.new_decrypt_is_odd);
    assert_bool_u256(witness.is_empty_msg);
    verify_process_deactivate_step_core_claims(fields, witness);

    let next_message_hash = process_deactivate_message_hash_chain_step(
        witness.msg, witness.enc_pub_key, fields.previous_message_hash, witness.message_hash,
    );
    assert_u256_eq(next_message_hash, fields.next_message_hash);

    let current_deactivate_commitment = poseidon_hash2(
        witness.current_deactivate_commitment,
        fields.current_active_state_root,
        fields.current_deactivate_root,
    );
    assert_u256_eq(current_deactivate_commitment, fields.current_deactivate_commitment);

    if is_zero(witness.msg.v0) {
        assert_u256_eq(witness.is_empty_msg, 1);
        assert_u256_eq(fields.current_active_state_root, fields.new_active_state_root);
        assert_u256_eq(fields.current_deactivate_root, fields.new_deactivate_root);
    } else {
        assert_u256_eq(witness.is_empty_msg, zero_u256());
        validate_poseidon_decryption(
            witness.msg, witness.command_shared_key, witness.decrypted_command,
        );
        assert_u256_eq(witness.packed_cmd.v0, witness.decrypted_command.v0);
        assert_u256_eq(witness.packed_cmd.v1, witness.decrypted_command.v1);
        assert_u256_eq(witness.packed_cmd.v2, witness.decrypted_command.v2);
        assert_u256_eq(witness.cmd_sig_r8.v0, witness.decrypted_command.v4);
        assert_u256_eq(witness.cmd_sig_r8.v1, witness.decrypted_command.v5);
        assert_u256_eq(witness.cmd_sig_s, witness.decrypted_command.v6);
        let unpacked = unpack_command_data(witness.packed_cmd.v0);
        assert_u256_eq(witness.cmd_poll_id, unpacked.v0);
        assert_u256_eq(witness.cmd_state_index, unpacked.v5);

        let valid_poll_id = witness.cmd_poll_id == fields.expected_poll_id;
        let signature_valid = u256_bool(witness.signature_valid);
        let current_decrypt_is_odd = u256_bool(witness.current_decrypt_is_odd);
        let valid = signature_valid && !current_decrypt_is_odd && valid_poll_id;
        let new_decrypt_is_odd = u256_bool(witness.new_decrypt_is_odd);
        assert_u256_eq(bool_to_u256(valid), bool_to_u256(!new_decrypt_is_odd));

        let state_index = select_u256(
            valid_state_index(witness.cmd_state_index),
            STATE_TREE_MAX_INDEX,
            witness.cmd_state_index,
        );
        let state_leaf_hash = poseidon_hash10(witness.state_leaf_hash, witness.state_leaf);
        let current_state_root = quinary_root_depth_2(
            state_leaf_hash, witness.state_leaf_path_0, witness.state_leaf_path_1, state_index,
        );
        assert_u256_eq(current_state_root, fields.current_state_root);

        assert(!is_zero(witness.new_active_state), 'NEW_ACTIVE_ZERO');
        let current_active_state_root = quinary_root_depth_2(
            witness.current_active_state,
            witness.active_state_leaf_path_0,
            witness.active_state_leaf_path_1,
            state_index,
        );
        assert_u256_eq(current_active_state_root, fields.current_active_state_root);
        let active_state_leaf = select_u256(
            valid, witness.current_active_state, witness.new_active_state,
        );
        let new_active_state_root = quinary_root_depth_2(
            active_state_leaf,
            witness.active_state_leaf_path_0,
            witness.active_state_leaf_path_1,
            state_index,
        );
        assert_u256_eq(new_active_state_root, fields.new_active_state_root);

        let deactivate_leaf = poseidon_hash5(
            witness.deactivate_leaf,
            U256x5 {
                v0: witness.c1.v0,
                v1: witness.c1.v1,
                v2: witness.c2.v0,
                v3: witness.c2.v1,
                v4: fields.deactivate_shared_key_hash,
            },
        );
        let current_deactivate_root = quinary_root_depth_4(
            zero_u256(),
            witness.deactivate_leaf_path_0,
            witness.deactivate_leaf_path_1,
            witness.deactivate_leaf_path_2,
            witness.deactivate_leaf_path_3,
            fields.deactivate_index,
        );
        assert_u256_eq(current_deactivate_root, fields.current_deactivate_root);
        let new_deactivate_leaf = select_u256(
            u256_bool(witness.is_empty_msg), deactivate_leaf, zero_u256(),
        );
        let new_deactivate_root = quinary_root_depth_4(
            new_deactivate_leaf,
            witness.deactivate_leaf_path_0,
            witness.deactivate_leaf_path_1,
            witness.deactivate_leaf_path_2,
            witness.deactivate_leaf_path_3,
            fields.deactivate_index,
        );
        assert_u256_eq(new_deactivate_root, fields.new_deactivate_root);
    }

    let new_deactivate_commitment = poseidon_hash2(
        witness.new_deactivate_commitment, fields.new_active_state_root, fields.new_deactivate_root,
    );
    assert_u256_eq(new_deactivate_commitment, fields.new_deactivate_commitment);
}

#[executable]
pub fn process_deactivate_one_main(
    witness: ProcessDeactivateOneWitness,
) -> ProcessDeactivateOneOutput {
    process_deactivate_one(witness)
}

#[executable]
pub fn process_deactivate_messages_boundary_main(
    fields: ProcessDeactivatePublicFields, witness: ProcessDeactivateMessagesBoundaryWitness,
) -> ProcessDeactivatePublicOutput {
    verify_process_deactivate_boundary(fields, witness);
    build_process_deactivate_public_output(fields)
}

#[executable]
pub fn process_deactivate_message_step_main(
    fields: ProcessDeactivateStepPublicFields, witness: ProcessDeactivateMessageStepWitness,
) -> ProcessDeactivateStepPublicOutput {
    verify_process_deactivate_message_step(fields, witness);
    build_process_deactivate_step_public_output(fields)
}

#[executable]
pub fn process_deactivate_coord_key_main(
    fields: ProcessDeactivateCoordKeyPublicFields, witness: ProcessDeactivateCoordKeyWitness,
) -> ProcessDeactivateCoordKeyPublicOutput {
    verify_process_deactivate_coord_key(fields, witness);
    build_process_deactivate_coord_key_public_output(fields)
}

fn build_native_process_deactivate_coord_key_public_output(
    fields: NativeProcessDeactivateCoordKeyPublicFields,
) -> NativeProcessDeactivateCoordKeyPublicOutput {
    NativeProcessDeactivateCoordKeyPublicOutput {
        magic: crate::public_output::PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_DEACTIVATE_COORD_KEY_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        deactivate_tree_depth: 4,
        message_batch_size: 5,
        coord_pub_key_hash: fields.coord_pub_key_hash,
        coord_priv_key_hash: fields.coord_priv_key_hash,
        coord_key_binding_hash: fields.coord_key_binding_hash,
    }
}

#[executable]
pub fn process_deactivate_coord_key_native_main(
    fields: NativeProcessDeactivateCoordKeyPublicFields,
    witness: NativeProcessDeactivateCoordKeyWitness,
) -> NativeProcessDeactivateCoordKeyPublicOutput {
    verify_native_process_deactivate_coord_key(fields, witness);
    build_native_process_deactivate_coord_key_public_output(fields)
}

#[executable]
pub fn process_deactivate_ecdh_main(
    fields: ProcessDeactivateEcdhPublicFields, witness: ProcessDeactivateEcdhWitness,
) -> ProcessDeactivateEcdhPublicOutput {
    verify_process_deactivate_ecdh(fields, witness);
    build_process_deactivate_ecdh_public_output(fields)
}

fn build_native_process_deactivate_ecdh_public_output(
    fields: NativeProcessDeactivateEcdhPublicFields,
) -> NativeProcessDeactivateEcdhPublicOutput {
    NativeProcessDeactivateEcdhPublicOutput {
        magic: crate::public_output::PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_DEACTIVATE_ECDH_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        deactivate_tree_depth: 4,
        message_batch_size: 5,
        message_index: fields.message_index,
        ecdh_kind: fields.ecdh_kind,
        coord_priv_key_hash: fields.coord_priv_key_hash,
        base_hash: fields.base_hash,
        shared_key_hash: fields.shared_key_hash,
        shared_key_binding_hash: fields.shared_key_binding_hash,
    }
}

#[executable]
pub fn process_deactivate_ecdh_native_main(
    fields: NativeProcessDeactivateEcdhPublicFields, witness: NativeProcessDeactivateEcdhWitness,
) -> NativeProcessDeactivateEcdhPublicOutput {
    verify_native_process_deactivate_ecdh(fields, witness);
    build_native_process_deactivate_ecdh_public_output(fields)
}

#[executable]
pub fn process_deactivate_signature_main(
    fields: ProcessDeactivateSignaturePublicFields, witness: ProcessDeactivateSignatureWitness,
) -> ProcessDeactivateSignaturePublicOutput {
    verify_process_deactivate_signature(fields, witness);
    build_process_deactivate_signature_public_output(fields)
}

fn build_native_process_deactivate_signature_public_output(
    fields: NativeProcessDeactivateSignaturePublicFields,
) -> NativeProcessDeactivateSignaturePublicOutput {
    NativeProcessDeactivateSignaturePublicOutput {
        magic: crate::public_output::PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_DEACTIVATE_SIGNATURE_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        deactivate_tree_depth: 4,
        message_batch_size: 5,
        message_index: fields.message_index,
        pub_key_hash: fields.pub_key_hash,
        r8_hash: fields.r8_hash,
        packed_cmd_hash: fields.packed_cmd_hash,
        cmd_sig_s_hash: fields.cmd_sig_s_hash,
        command_auth_hash: fields.command_auth_hash,
        signature_valid: fields.signature_valid,
    }
}

#[executable]
pub fn process_deactivate_signature_native_main(
    fields: NativeProcessDeactivateSignaturePublicFields, witness: NativeProcessDeactivateSignatureWitness,
) -> NativeProcessDeactivateSignaturePublicOutput {
    verify_native_process_deactivate_signature(fields, witness);
    build_native_process_deactivate_signature_public_output(fields)
}

#[executable]
pub fn process_deactivate_decrypt_main(
    fields: ProcessDeactivateDecryptPublicFields, witness: ProcessDeactivateDecryptWitness,
) -> ProcessDeactivateDecryptPublicOutput {
    verify_process_deactivate_decrypt(fields, witness);
    build_process_deactivate_decrypt_public_output(fields)
}

fn build_native_process_deactivate_decrypt_public_output(
    fields: NativeProcessDeactivateDecryptPublicFields,
) -> NativeProcessDeactivateDecryptPublicOutput {
    NativeProcessDeactivateDecryptPublicOutput {
        magic: crate::public_output::PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_DEACTIVATE_DECRYPT_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        deactivate_tree_depth: 4,
        message_batch_size: 5,
        message_index: fields.message_index,
        decrypt_kind: fields.decrypt_kind,
        coord_priv_key_hash: fields.coord_priv_key_hash,
        c1_hash: fields.c1_hash,
        c2_hash: fields.c2_hash,
        decrypt_is_odd: fields.decrypt_is_odd,
        decrypt_binding_hash: fields.decrypt_binding_hash,
    }
}

#[executable]
pub fn process_deactivate_decrypt_native_main(
    fields: NativeProcessDeactivateDecryptPublicFields, witness: NativeProcessDeactivateDecryptWitness,
) -> NativeProcessDeactivateDecryptPublicOutput {
    verify_native_process_deactivate_decrypt(fields, witness);
    build_native_process_deactivate_decrypt_public_output(fields)
}

fn build_native_process_deactivate_step_core_public_output(
    fields: NativeProcessDeactivateStepCorePublicFields,
) -> NativeProcessDeactivateStepCorePublicOutput {
    NativeProcessDeactivateStepCorePublicOutput {
        magic: crate::public_output::PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_DEACTIVATE_STEP_CORE_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        deactivate_tree_depth: 4,
        message_batch_size: 5,
        message_index: fields.message_index,
        deactivate_index: fields.deactivate_index,
        coord_priv_key_hash: fields.coord_priv_key_hash,
        previous_message_hash: fields.previous_message_hash,
        next_message_hash: fields.next_message_hash,
        current_active_state_root_hash: fields.current_active_state_root_hash,
        current_deactivate_root_hash: fields.current_deactivate_root_hash,
        new_active_state_root_hash: fields.new_active_state_root_hash,
        new_deactivate_root_hash: fields.new_deactivate_root_hash,
        current_deactivate_commitment_hash: fields.current_deactivate_commitment_hash,
        new_deactivate_commitment_hash: fields.new_deactivate_commitment_hash,
        current_state_root_hash: fields.current_state_root_hash,
        expected_poll_id: fields.expected_poll_id,
        enc_pub_key_hash: fields.enc_pub_key_hash,
        command_shared_key_hash: fields.command_shared_key_hash,
        command_shared_key_binding_hash: fields.command_shared_key_binding_hash,
        signature_pub_key_hash: fields.signature_pub_key_hash,
        signature_r8_hash: fields.signature_r8_hash,
        packed_cmd_hash: fields.packed_cmd_hash,
        cmd_sig_s_hash: fields.cmd_sig_s_hash,
        command_auth_hash: fields.command_auth_hash,
        command_plaintext_binding_hash: fields.command_plaintext_binding_hash,
        signature_valid: fields.signature_valid,
        current_state_ciphertext_c1_hash: fields.current_state_ciphertext_c1_hash,
        current_state_ciphertext_c2_hash: fields.current_state_ciphertext_c2_hash,
        current_decrypt_is_odd: fields.current_decrypt_is_odd,
        current_decrypt_binding_hash: fields.current_decrypt_binding_hash,
        new_state_ciphertext_c1_hash: fields.new_state_ciphertext_c1_hash,
        new_state_ciphertext_c2_hash: fields.new_state_ciphertext_c2_hash,
        new_decrypt_is_odd: fields.new_decrypt_is_odd,
        new_decrypt_binding_hash: fields.new_decrypt_binding_hash,
        deactivate_pub_key_hash: fields.deactivate_pub_key_hash,
        deactivate_shared_key_hash: fields.deactivate_shared_key_hash,
        deactivate_shared_key_binding_hash: fields.deactivate_shared_key_binding_hash,
    }
}

#[executable]
pub fn process_deactivate_step_core_main(
    fields: ProcessDeactivateStepCorePublicFields, witness: ProcessDeactivateStepCoreWitness,
) -> ProcessDeactivateStepCorePublicOutput {
    verify_process_deactivate_step_core(fields, witness);
    build_process_deactivate_step_core_public_output(fields)
}

#[executable]
pub fn process_deactivate_step_core_native_main(
    fields: NativeProcessDeactivateStepCorePublicFields, witness: ProcessDeactivateStepCoreWitness,
) -> NativeProcessDeactivateStepCorePublicOutput {
    verify_native_process_deactivate_step_core(fields, witness);
    build_native_process_deactivate_step_core_public_output(fields)
}

#[executable]
pub fn process_deactivate_messages_state_transition_main(
    witness: ProcessDeactivateMessagesStateTransitionWitness,
) -> ProcessDeactivateMessagesStateOutput {
    process_deactivate_messages_state_transition(witness)
}

#[executable]
pub fn process_deactivate_messages_stateful_main(
    fields: ProcessDeactivatePublicFields, witness: ProcessDeactivateMessagesStatefulWitness,
) -> ProcessDeactivatePublicOutput {
    let boundary = witness.boundary;
    let state_transition = witness.state_transition;
    assert_coord_pub_key_matches_private_key(
        state_transition.coord_priv_key, boundary.coord_pub_key, witness.coord_pub_key,
    );
    verify_process_deactivate_boundary(fields, boundary);
    assert_u256_eq(state_transition.current_active_state_root, boundary.current_active_state_root);
    assert_u256_eq(state_transition.current_deactivate_root, boundary.current_deactivate_root);
    assert_u256_eq(state_transition.current_state_root, boundary.current_state_root);
    assert_u256_eq(state_transition.expected_poll_id, boundary.expected_poll_id);
    let output = process_deactivate_messages_bound_state_transition(
        boundary,
        state_transition,
        witness.command_0,
        witness.command_1,
        witness.command_2,
        witness.command_3,
        witness.command_4,
    );
    assert_u256_eq(output.new_deactivate_root, fields.new_deactivate_root);
    let new_deactivate_commitment = poseidon_hash2(
        witness.new_deactivate_commitment, output.new_active_state_root, output.new_deactivate_root,
    );
    assert_u256_eq(new_deactivate_commitment, fields.new_deactivate_commitment);
    build_process_deactivate_public_output(fields)
}
