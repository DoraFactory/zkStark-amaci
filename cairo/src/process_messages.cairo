use core::poseidon::poseidon_hash_span;
use crate::babyjub::{
    BabyJubJubPoseidonSignatureWitness, BabyJubJubScalarMulWitness, assert_babyjub_add,
    babyjub_base8, verify_babyjub_poseidon_signature, verify_babyjub_scalar_mul,
};
use crate::hash_gates::{
    Hash13Claim, Hash2Claim, Hash5Claim, Sha256U256x8Claim, poseidon_hash13, poseidon_hash2,
    poseidon_hash5, sha256_u256x8_mod_bn254,
};
use crate::poseidon_bn254::{
    POSEIDON5_ZERO_HASH, PoseidonT4State, field_sub_mod, poseidon2_hash, poseidon4_permutation,
    poseidon5_hash,
};
use crate::public_output::{
    ProcessMessageCoordKeyPublicFields, ProcessMessageCoordKeyPublicOutput,
    ProcessMessageEcdhPublicFields, ProcessMessageEcdhPublicOutput,
    ProcessMessageSignaturePublicFields, ProcessMessageSignaturePublicOutput,
    ProcessMessageStepCorePublicFields, ProcessMessageStepCorePublicOutput,
    ProcessMessageStepPublicFields, ProcessMessageStepPublicOutput, ProcessMessagesPublicFields,
    ProcessMessagesPublicOutput, build_process_message_coord_key_public_output,
    build_process_message_ecdh_public_output, build_process_message_signature_public_output,
    build_process_message_step_core_public_output, build_process_message_step_public_output,
    build_process_messages_public_output,
};
use crate::types::{
    U256x10, U256x2, U256x3, U256x4, U256x5, U256x7, U256x8, assert_u256_eq, is_zero,
    u256x10_first5, u256x10_second5, zero_u256,
};

pub const TWO_POW_32: u256 = 0x100000000;
pub const TWO_POW_64: u256 = 0x10000000000000000;
pub const POSEIDON_DECRYPT_7_DOMAIN: u256 = 0x700000000000000000000000000000000;
pub const U128_TWO_POW_32: u128 = 0x100000000;
pub const U128_TWO_POW_64: u128 = 0x10000000000000000;
pub const U128_TWO_POW_96: u128 = 0x1000000000000000000000000;
pub const CIRCOM_UINT32_TO_96_HIGH_FACTOR: u256 = 18446744073709552000;
pub const MAX_VOTE_OPTIONS: u256 = 5;
pub const MAX_SIGNUPS: u256 = 25;
pub const MAX_STATE_INDEX: u256 = 24;
pub const MAX_VALID_VOTE_WEIGHT: u256 = 147946756881789319005730692170996259609;
pub const COORD_PRIV_KEY_HASH_DOMAIN: u256 = 0x414d4143495f434f4f52445f50524956;
pub const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
pub const STARKNET_POSEIDON_HASH_SCHEME: felt252 = 0x535441524b4e45545f504f534549444f4e;
pub const PROCESS_MESSAGE_COORD_KEY_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f504d53475f434f4f52445f4e4154495645;
pub const PROCESS_MESSAGE_ECDH_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f504d53475f454344485f4e4154495645;
pub const PROCESS_MESSAGE_SIGNATURE_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f504d53475f5349475f4e4154495645;
pub const PROCESS_MESSAGE_STEP_CORE_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f504d53475f535445505f434f52455f4e4154495645;
pub const NATIVE_COORD_PRIV_KEY_HASH_DOMAIN: felt252 = 0x414d4143495f434f4f52445f50524956;

#[derive(Copy, Drop, Serde)]
pub struct ProcessMessagesHashTranscript {
    pub coord_pub_key_hash: Hash2Claim,
    pub input_hash: Sha256U256x8Claim,
    pub current_state_commitment: Hash2Claim,
    pub new_state_commitment: Hash2Claim,
    pub deactivate_commitment: Hash2Claim,
    pub message_hash_0: Hash13Claim,
    pub message_hash_1: Hash13Claim,
    pub message_hash_2: Hash13Claim,
    pub message_hash_3: Hash13Claim,
    pub message_hash_4: Hash13Claim,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessMessagesBoundaryWitness {
    pub is_quadratic_cost: u256,
    pub num_signups: u256,
    pub max_vote_options: u256,
    pub coord_pub_key: U256x2,
    pub current_state_root: u256,
    pub current_state_salt: u256,
    pub new_state_root: u256,
    pub new_state_salt: u256,
    pub active_state_root: u256,
    pub deactivate_root: u256,
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
    pub hashes: ProcessMessagesHashTranscript,
}

#[derive(Drop, Serde)]
pub struct ElGamalDecryptWitness {
    pub scalar_mul: BabyJubJubScalarMulWitness,
    pub decrypted_point: U256x2,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessOneStateTransitionWitness {
    pub is_quadratic_cost: u256,
    pub num_signups: u256,
    pub max_vote_options: u256,
    pub expected_poll_id: u256,
    pub is_signature_valid: u256,
    pub is_decryption_active: u256,
    pub msg: U256x10,
    pub shared_key: U256x2,
    pub decrypted_command: U256x7,
    pub packed_command: U256x3,
    pub cmd_salt: u256,
    pub cmd_sig_r8: U256x2,
    pub cmd_sig_s: u256,
    pub current_state_root: u256,
    pub active_state_root: u256,
    pub state_leaf: U256x10,
    pub state_leaf_path_0: U256x4,
    pub state_leaf_path_1: U256x4,
    pub active_state_leaf: u256,
    pub active_state_leaf_path_0: U256x4,
    pub active_state_leaf_path_1: U256x4,
    pub current_vote_weight: u256,
    pub current_vote_weight_path: U256x4,
    pub is_valid: u256,
    pub cmd_state_index: u256,
    pub cmd_vote_option_index: u256,
    pub cmd_new_vote_weight: u256,
    pub cmd_nonce: u256,
    pub cmd_poll_id: u256,
    pub cmd_new_pub_key: U256x2,
    pub new_balance: u256,
    pub new_sl_nonce: u256,
}

#[derive(Drop, Serde)]
pub struct ProcessMessagesStateTransitionWitness {
    pub current_state_root: u256,
    pub new_state_root: u256,
    pub coord_priv_key: u256,
    pub active_state_root: u256,
    pub state_decrypt_0: ElGamalDecryptWitness,
    pub state_decrypt_1: ElGamalDecryptWitness,
    pub state_decrypt_2: ElGamalDecryptWitness,
    pub state_decrypt_3: ElGamalDecryptWitness,
    pub state_decrypt_4: ElGamalDecryptWitness,
    pub process_one_0: ProcessOneStateTransitionWitness,
    pub process_one_1: ProcessOneStateTransitionWitness,
    pub process_one_2: ProcessOneStateTransitionWitness,
    pub process_one_3: ProcessOneStateTransitionWitness,
    pub process_one_4: ProcessOneStateTransitionWitness,
}

#[derive(Drop, Serde)]
pub struct ProcessMessagesStatefulWitness {
    pub boundary: ProcessMessagesBoundaryWitness,
    pub state_transition: ProcessMessagesStateTransitionWitness,
}

#[derive(Drop, Serde)]
pub struct ProcessOneWithEcdhWitness {
    pub ecdh: BabyJubJubScalarMulWitness,
    pub process_one: ProcessOneStateTransitionWitness,
}

#[derive(Drop, Serde)]
pub struct ProcessOneWithSignatureWitness {
    pub signature: BabyJubJubPoseidonSignatureWitness,
    pub process_one: ProcessOneStateTransitionWitness,
}

#[derive(Drop, Serde)]
pub struct ProcessOneWithEcdhSignatureWitness {
    pub ecdh: BabyJubJubScalarMulWitness,
    pub signature: BabyJubJubPoseidonSignatureWitness,
    pub process_one: ProcessOneStateTransitionWitness,
}

#[derive(Drop, Serde)]
pub struct ProcessMessageStepWithEcdhSignatureWitness {
    pub is_quadratic_cost: u256,
    pub num_signups: u256,
    pub max_vote_options: u256,
    pub coord_pub_key: U256x2,
    pub enc_pub_key: U256x2,
    pub msg: U256x10,
    pub coord_priv_key: u256,
    pub current_state_salt: u256,
    pub new_state_salt: u256,
    pub coord_pub_key_scalar_mul: BabyJubJubScalarMulWitness,
    pub coord_pub_key_hash: Hash2Claim,
    pub current_state_commitment: Hash2Claim,
    pub new_state_commitment: Hash2Claim,
    pub message_hash: Hash13Claim,
    pub state_decrypt: ElGamalDecryptWitness,
    pub ecdh: BabyJubJubScalarMulWitness,
    pub signature: BabyJubJubPoseidonSignatureWitness,
    pub process_one: ProcessOneStateTransitionWitness,
}

#[derive(Drop, Serde)]
pub struct ProcessMessageCoordKeyWitness {
    pub coord_priv_key: u256,
    pub coord_pub_key: U256x2,
    pub coord_pub_key_scalar_mul: BabyJubJubScalarMulWitness,
    pub coord_pub_key_hash: Hash2Claim,
    pub coord_priv_key_hash: Hash2Claim,
}

#[derive(Drop, Serde)]
pub struct ProcessMessageEcdhWitness {
    pub coord_priv_key: u256,
    pub enc_pub_key: U256x2,
    pub ecdh: BabyJubJubScalarMulWitness,
    pub coord_priv_key_hash: Hash2Claim,
    pub enc_pub_key_hash: Hash2Claim,
    pub shared_key_hash: Hash2Claim,
}

#[derive(Drop, Serde)]
pub struct ProcessMessageSignatureWitness {
    pub pub_key: U256x2,
    pub r8: U256x2,
    pub s: u256,
    pub packed_command: U256x3,
    pub signature: BabyJubJubPoseidonSignatureWitness,
    pub pub_key_hash: Hash2Claim,
    pub r8_hash: Hash2Claim,
    pub packed_command_hash: Hash5Claim,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageCoordKeyPublicFields {
    pub coord_pub_key_hash: felt252,
    pub coord_priv_key_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageEcdhPublicFields {
    pub message_index: felt252,
    pub coord_priv_key_hash: felt252,
    pub enc_pub_key_hash: felt252,
    pub shared_key_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageSignaturePublicFields {
    pub message_index: felt252,
    pub pub_key_hash: felt252,
    pub r8_hash: felt252,
    pub packed_command_hash: felt252,
    pub cmd_sig_s_hash: felt252,
    pub is_signature_valid: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageStepCorePublicFields {
    pub message_index: felt252,
    pub packed_vals_hash: felt252,
    pub coord_priv_key_hash: felt252,
    pub previous_message_hash: felt252,
    pub next_message_hash: felt252,
    pub current_state_root_hash: felt252,
    pub new_state_root_hash: felt252,
    pub current_state_commitment_hash: felt252,
    pub new_state_commitment_hash: felt252,
    pub active_state_root_hash: felt252,
    pub expected_poll_id: felt252,
    pub enc_pub_key_hash: felt252,
    pub shared_key_hash: felt252,
    pub signature_pub_key_hash: felt252,
    pub signature_r8_hash: felt252,
    pub packed_command_hash: felt252,
    pub cmd_sig_s_hash: felt252,
    pub is_signature_valid: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageCoordKeyPublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub hash_scheme: felt252,
    pub state_tree_depth: felt252,
    pub vote_option_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub coord_pub_key_hash: felt252,
    pub coord_priv_key_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageEcdhPublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub hash_scheme: felt252,
    pub state_tree_depth: felt252,
    pub vote_option_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub message_index: felt252,
    pub coord_priv_key_hash: felt252,
    pub enc_pub_key_hash: felt252,
    pub shared_key_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageSignaturePublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub hash_scheme: felt252,
    pub state_tree_depth: felt252,
    pub vote_option_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub message_index: felt252,
    pub pub_key_hash: felt252,
    pub r8_hash: felt252,
    pub packed_command_hash: felt252,
    pub cmd_sig_s_hash: felt252,
    pub is_signature_valid: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageStepCorePublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub hash_scheme: felt252,
    pub state_tree_depth: felt252,
    pub vote_option_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub message_index: felt252,
    pub packed_vals_hash: felt252,
    pub coord_priv_key_hash: felt252,
    pub previous_message_hash: felt252,
    pub next_message_hash: felt252,
    pub current_state_root_hash: felt252,
    pub new_state_root_hash: felt252,
    pub current_state_commitment_hash: felt252,
    pub new_state_commitment_hash: felt252,
    pub active_state_root_hash: felt252,
    pub expected_poll_id: felt252,
    pub enc_pub_key_hash: felt252,
    pub shared_key_hash: felt252,
    pub signature_pub_key_hash: felt252,
    pub signature_r8_hash: felt252,
    pub packed_command_hash: felt252,
    pub cmd_sig_s_hash: felt252,
    pub is_signature_valid: felt252,
}

#[derive(Drop, Serde)]
pub struct ProcessMessageStepCoreWitness {
    pub is_quadratic_cost: u256,
    pub num_signups: u256,
    pub max_vote_options: u256,
    pub enc_pub_key: U256x2,
    pub msg: U256x10,
    pub coord_priv_key: u256,
    pub current_state_salt: u256,
    pub new_state_salt: u256,
    pub coord_priv_key_hash: Hash2Claim,
    pub current_state_commitment: Hash2Claim,
    pub new_state_commitment: Hash2Claim,
    pub enc_pub_key_hash: Hash2Claim,
    pub shared_key_hash: Hash2Claim,
    pub signature_pub_key_hash: Hash2Claim,
    pub signature_r8_hash: Hash2Claim,
    pub packed_command_hash: Hash5Claim,
    pub message_hash: Hash13Claim,
    pub state_decrypt: ElGamalDecryptWitness,
    pub process_one: ProcessOneStateTransitionWitness,
}

#[derive(Drop, Serde)]
pub struct ProcessMessagesStatefulWithEcdhWitness {
    pub boundary: ProcessMessagesBoundaryWitness,
    pub state_transition: ProcessMessagesStateTransitionWitness,
    pub coord_priv_key: u256,
    pub coord_pub_key: BabyJubJubScalarMulWitness,
    pub ecdh_0: BabyJubJubScalarMulWitness,
    pub ecdh_1: BabyJubJubScalarMulWitness,
    pub ecdh_2: BabyJubJubScalarMulWitness,
    pub ecdh_3: BabyJubJubScalarMulWitness,
    pub ecdh_4: BabyJubJubScalarMulWitness,
}

#[derive(Drop, Serde)]
pub struct ProcessMessagesStatefulWithEcdhSignatureWitness {
    pub boundary: ProcessMessagesBoundaryWitness,
    pub state_transition: ProcessMessagesStateTransitionWitness,
    pub coord_priv_key: u256,
    pub coord_pub_key: BabyJubJubScalarMulWitness,
    pub ecdh_0: BabyJubJubScalarMulWitness,
    pub ecdh_1: BabyJubJubScalarMulWitness,
    pub ecdh_2: BabyJubJubScalarMulWitness,
    pub ecdh_3: BabyJubJubScalarMulWitness,
    pub ecdh_4: BabyJubJubScalarMulWitness,
    pub signature_0: BabyJubJubPoseidonSignatureWitness,
    pub signature_1: BabyJubJubPoseidonSignatureWitness,
    pub signature_2: BabyJubJubPoseidonSignatureWitness,
    pub signature_3: BabyJubJubPoseidonSignatureWitness,
    pub signature_4: BabyJubJubPoseidonSignatureWitness,
}

#[derive(Copy, Drop)]
struct ProcessOneValidation {
    is_valid: bool,
    new_balance: u256,
    new_sl_nonce: u256,
}

fn assert_u32(value: u256) {
    assert(value.high == 0, 'U32_HIGH');
    assert(value.low < U128_TWO_POW_32, 'U32_RANGE');
}

fn assert_state_index(value: u256) {
    assert(value.high == 0, 'STATE_IDX_HIGH');
    assert(value.low < 25, 'STATE_IDX_RANGE');
}

fn assert_vote_option_index(value: u256) {
    assert(value.high == 0, 'VO_IDX_HIGH');
    assert(value.low < 5, 'VO_IDX_RANGE');
}

fn is_valid_bool(value: u256) -> bool {
    assert_bool_u256(value);
    value.low == 1
}

fn select_u256(valid: bool, invalid_value: u256, valid_value: u256) -> u256 {
    if valid {
        valid_value
    } else {
        invalid_value
    }
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

fn process_one_cost(is_quadratic_cost: bool, vote_weight: u256) -> u256 {
    if is_quadratic_cost {
        vote_weight * vote_weight
    } else {
        vote_weight
    }
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

fn validate_poseidon_decryption(witness: ProcessOneStateTransitionWitness) {
    let state_0 = poseidon_decrypt_initial_state(witness.shared_key);
    assert_u256_eq(witness.decrypted_command.v0, field_sub_mod(witness.msg.v0, state_0.x1));
    assert_u256_eq(witness.decrypted_command.v1, field_sub_mod(witness.msg.v1, state_0.x2));
    assert_u256_eq(witness.decrypted_command.v2, field_sub_mod(witness.msg.v2, state_0.x3));

    let state_1 = poseidon_decrypt_next_state(
        state_0, witness.msg.v0, witness.msg.v1, witness.msg.v2,
    );
    assert_u256_eq(witness.decrypted_command.v3, field_sub_mod(witness.msg.v3, state_1.x1));
    assert_u256_eq(witness.decrypted_command.v4, field_sub_mod(witness.msg.v4, state_1.x2));
    assert_u256_eq(witness.decrypted_command.v5, field_sub_mod(witness.msg.v5, state_1.x3));

    let state_2 = poseidon_decrypt_next_state(
        state_1, witness.msg.v3, witness.msg.v4, witness.msg.v5,
    );
    assert_u256_eq(witness.decrypted_command.v6, field_sub_mod(witness.msg.v6, state_2.x1));
}

fn validate_packed_command(witness: ProcessOneStateTransitionWitness) {
    validate_poseidon_decryption(witness);
    assert_u256_eq(witness.packed_command.v0, witness.decrypted_command.v0);
    assert_u256_eq(witness.packed_command.v1, witness.decrypted_command.v1);
    assert_u256_eq(witness.packed_command.v2, witness.decrypted_command.v2);
    assert_u256_eq(witness.cmd_salt, witness.decrypted_command.v3);
    assert_u256_eq(witness.cmd_sig_r8.v0, witness.decrypted_command.v4);
    assert_u256_eq(witness.cmd_sig_r8.v1, witness.decrypted_command.v5);
    assert_u256_eq(witness.cmd_sig_s, witness.decrypted_command.v6);

    let unpacked = unpack_command_data(witness.packed_command.v0);
    let unpacked_vote_weight = unpacked.v3
        + unpacked.v2 * TWO_POW_32
        + unpacked.v1 * CIRCOM_UINT32_TO_96_HIGH_FACTOR;
    assert_u256_eq(witness.cmd_poll_id, unpacked.v0);
    assert_u256_eq(witness.cmd_new_vote_weight, unpacked_vote_weight);
    assert_u256_eq(witness.cmd_vote_option_index, unpacked.v4);
    assert_u256_eq(witness.cmd_state_index, unpacked.v5);
    assert_u256_eq(witness.cmd_nonce, unpacked.v6);
    assert_u256_eq(witness.cmd_new_pub_key.v0, witness.packed_command.v1);
    assert_u256_eq(witness.cmd_new_pub_key.v1, witness.packed_command.v2);
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

fn validate_process_one_command(witness: ProcessOneStateTransitionWitness) -> ProcessOneValidation {
    let is_quadratic_cost = u256_bool(witness.is_quadratic_cost);
    let is_signature_valid = u256_bool(witness.is_signature_valid);
    let is_decryption_active = u256_bool(witness.is_decryption_active);
    validate_packed_command(witness);
    assert_u32(witness.num_signups);
    assert_u32(witness.max_vote_options);
    assert_u32(witness.cmd_nonce);
    assert_u32(witness.cmd_poll_id);
    assert_u32(witness.expected_poll_id);
    assert(witness.num_signups <= MAX_SIGNUPS, 'BAD_NUM_SIGNUPS');
    assert(witness.max_vote_options <= MAX_VOTE_OPTIONS, 'BAD_MAX_VO');

    let valid_state_index = witness.cmd_state_index <= witness.num_signups
        && witness.cmd_state_index <= MAX_STATE_INDEX;
    let valid_vote_option_index = witness.cmd_vote_option_index < witness.max_vote_options;
    let valid_nonce = witness.cmd_nonce == witness.state_leaf.v4 + 1;
    let valid_poll_id = witness.cmd_poll_id == witness.expected_poll_id;
    let valid_vote_weight = witness.cmd_new_vote_weight <= MAX_VALID_VOTE_WEIGHT;
    let current_cost = process_one_cost(is_quadratic_cost, witness.current_vote_weight);
    let new_cost = process_one_cost(is_quadratic_cost, witness.cmd_new_vote_weight);
    let available_voice_credits = witness.state_leaf.v2 + current_cost;
    let sufficient_voice_credits = available_voice_credits >= new_cost;
    let message_valid = is_signature_valid
        && valid_state_index
        && valid_vote_option_index
        && valid_nonce
        && valid_poll_id
        && valid_vote_weight
        && sufficient_voice_credits;
    let state_leaf_active = is_zero(witness.active_state_leaf);
    let is_valid = message_valid && is_decryption_active && state_leaf_active;
    let is_valid_u256 = bool_to_u256(is_valid);
    assert_u256_eq(witness.is_valid, is_valid_u256);

    let computed_new_balance = if sufficient_voice_credits {
        available_voice_credits - new_cost
    } else {
        witness.new_balance
    };
    if is_valid {
        assert_u256_eq(witness.new_balance, computed_new_balance);
        assert_u256_eq(witness.new_sl_nonce, witness.cmd_nonce);
    }

    ProcessOneValidation {
        is_valid, new_balance: computed_new_balance, new_sl_nonce: witness.cmd_nonce,
    }
}

fn hash10_raw(inputs: U256x10) -> u256 {
    poseidon2_hash(poseidon5_hash(u256x10_first5(inputs)), poseidon5_hash(u256x10_second5(inputs)))
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

fn quinary_root_depth_1(leaf: u256, path: U256x4, index: u256) -> u256 {
    assert_vote_option_index(index);
    poseidon5_hash(path_inputs(leaf, path, index.low))
}

fn state_leaf_vote_root(state_leaf: U256x10) -> u256 {
    if is_zero(state_leaf.v3) {
        POSEIDON5_ZERO_HASH
    } else {
        state_leaf.v3
    }
}

fn process_one_state_transition(witness: ProcessOneStateTransitionWitness) -> u256 {
    let validation = validate_process_one_command(witness);
    let valid = validation.is_valid;
    let state_index = select_u256(valid, MAX_STATE_INDEX, witness.cmd_state_index);
    let vote_option_index = select_u256(valid, zero_u256(), witness.cmd_vote_option_index);
    assert_state_index(state_index);
    assert_vote_option_index(vote_option_index);

    let state_leaf_hash = hash10_raw(witness.state_leaf);
    let current_state_root = quinary_root_depth_2(
        state_leaf_hash, witness.state_leaf_path_0, witness.state_leaf_path_1, state_index,
    );
    assert_u256_eq(current_state_root, witness.current_state_root);

    let active_state_root = quinary_root_depth_2(
        witness.active_state_leaf,
        witness.active_state_leaf_path_0,
        witness.active_state_leaf_path_1,
        state_index,
    );
    assert_u256_eq(active_state_root, witness.active_state_root);

    let current_vote_root = quinary_root_depth_1(
        witness.current_vote_weight, witness.current_vote_weight_path, vote_option_index,
    );
    assert_u256_eq(current_vote_root, state_leaf_vote_root(witness.state_leaf));

    let updated_vote_weight = select_u256(
        valid, witness.current_vote_weight, witness.cmd_new_vote_weight,
    );
    let new_vote_option_root = quinary_root_depth_1(
        updated_vote_weight, witness.current_vote_weight_path, vote_option_index,
    );

    let new_state_leaf = U256x10 {
        v0: select_u256(valid, witness.state_leaf.v0, witness.cmd_new_pub_key.v0),
        v1: select_u256(valid, witness.state_leaf.v1, witness.cmd_new_pub_key.v1),
        v2: select_u256(valid, witness.state_leaf.v2, validation.new_balance),
        v3: select_u256(valid, witness.state_leaf.v3, new_vote_option_root),
        v4: select_u256(valid, witness.state_leaf.v4, validation.new_sl_nonce),
        v5: witness.state_leaf.v5,
        v6: witness.state_leaf.v6,
        v7: witness.state_leaf.v7,
        v8: witness.state_leaf.v8,
        v9: zero_u256(),
    };
    quinary_root_depth_2(
        hash10_raw(new_state_leaf),
        witness.state_leaf_path_0,
        witness.state_leaf_path_1,
        state_index,
    )
}

fn process_one_with_ecdh(witness: ProcessOneWithEcdhWitness) -> u256 {
    let process_one = witness.process_one;
    let shared_key = verify_babyjub_scalar_mul(witness.ecdh);
    assert_u256_eq(shared_key.v0, process_one.shared_key.v0);
    assert_u256_eq(shared_key.v1, process_one.shared_key.v1);
    process_one_state_transition(process_one)
}

fn assert_signature_matches_process_one(
    signature: BabyJubJubPoseidonSignatureWitness,
    pub_key: U256x2,
    cmd_sig_r8: U256x2,
    cmd_sig_s: u256,
    packed_command: U256x3,
    is_signature_valid: u256,
) {
    let signature_valid = verify_babyjub_poseidon_signature(
        pub_key, cmd_sig_r8, cmd_sig_s, packed_command, signature,
    );
    assert_u256_eq(is_signature_valid, signature_valid);
}

fn assert_signature_matches_process_one_if_nonempty(
    enc_pub_key: U256x2,
    signature: BabyJubJubPoseidonSignatureWitness,
    pub_key: U256x2,
    cmd_sig_r8: U256x2,
    cmd_sig_s: u256,
    packed_command: U256x3,
    is_signature_valid: u256,
) {
    if !is_zero(enc_pub_key.v0) {
        assert_signature_matches_process_one(
            signature, pub_key, cmd_sig_r8, cmd_sig_s, packed_command, is_signature_valid,
        );
    }
}

fn process_one_with_signature(witness: ProcessOneWithSignatureWitness) -> u256 {
    let process_one = witness.process_one;
    assert_signature_matches_process_one(
        witness.signature,
        U256x2 { v0: process_one.state_leaf.v0, v1: process_one.state_leaf.v1 },
        process_one.cmd_sig_r8,
        process_one.cmd_sig_s,
        process_one.packed_command,
        process_one.is_signature_valid,
    );
    process_one_state_transition(process_one)
}

fn process_one_with_ecdh_signature(witness: ProcessOneWithEcdhSignatureWitness) -> u256 {
    let process_one = witness.process_one;
    let shared_key = verify_babyjub_scalar_mul(witness.ecdh);
    assert_u256_eq(shared_key.v0, process_one.shared_key.v0);
    assert_u256_eq(shared_key.v1, process_one.shared_key.v1);
    assert_signature_matches_process_one(
        witness.signature,
        U256x2 { v0: process_one.state_leaf.v0, v1: process_one.state_leaf.v1 },
        process_one.cmd_sig_r8,
        process_one.cmd_sig_s,
        process_one.packed_command,
        process_one.is_signature_valid,
    );
    process_one_state_transition(process_one)
}

fn verify_process_message_step_with_ecdh_signature(
    fields: ProcessMessageStepPublicFields, witness: ProcessMessageStepWithEcdhSignatureWitness,
) {
    assert_valid_message_index(fields.message_index);
    assert_packed_step_vals(
        fields, witness.is_quadratic_cost, witness.num_signups, witness.max_vote_options,
    );
    assert_coord_pub_key_matches_private_key(
        witness.coord_priv_key, witness.coord_pub_key, witness.coord_pub_key_scalar_mul,
    );
    let coord_pub_key_hash = poseidon_hash2(
        witness.coord_pub_key_hash, witness.coord_pub_key.v0, witness.coord_pub_key.v1,
    );
    assert_u256_eq(coord_pub_key_hash, fields.coord_pub_key_hash);
    if fields.message_index == 4 {
        let current_state_commitment = poseidon_hash2(
            witness.current_state_commitment, fields.current_state_root, witness.current_state_salt,
        );
        assert_u256_eq(current_state_commitment, fields.current_state_commitment);
    }
    if fields.message_index == 0 {
        let new_state_commitment = poseidon_hash2(
            witness.new_state_commitment, fields.new_state_root, witness.new_state_salt,
        );
        assert_u256_eq(new_state_commitment, fields.new_state_commitment);
    }

    assert_u256_eq(witness.process_one.current_state_root, fields.current_state_root);
    assert_u256_eq(witness.process_one.active_state_root, fields.active_state_root);
    assert_u256_eq(witness.process_one.is_quadratic_cost, witness.is_quadratic_cost);
    assert_u256_eq(witness.process_one.num_signups, witness.num_signups);
    assert_u256_eq(witness.process_one.max_vote_options, witness.max_vote_options);
    assert_u256_eq(witness.process_one.expected_poll_id, fields.expected_poll_id);
    assert_message_matches(witness.msg, witness.process_one.msg);

    let next_message_hash = message_hash_or_empty(
        witness.message_hash, witness.msg, witness.enc_pub_key, fields.previous_message_hash,
    );
    assert_u256_eq(next_message_hash, fields.next_message_hash);

    if is_zero(witness.enc_pub_key.v0) {
        assert_u256_eq(witness.process_one.is_valid, zero_u256());
        assert_u256_eq(fields.current_state_root, fields.new_state_root);
    } else {
        assert_ecdh_matches_process_one(
            witness.coord_priv_key,
            witness.enc_pub_key,
            witness.ecdh,
            witness.process_one.shared_key,
        );
        assert_signature_matches_process_one(
            witness.signature,
            U256x2 { v0: witness.process_one.state_leaf.v0, v1: witness.process_one.state_leaf.v1 },
            witness.process_one.cmd_sig_r8,
            witness.process_one.cmd_sig_s,
            witness.process_one.packed_command,
            witness.process_one.is_signature_valid,
        );
        let new_state_root = process_one_chain_step(
            fields.current_state_root,
            witness.coord_priv_key,
            fields.active_state_root,
            witness.state_decrypt,
            witness.process_one,
        );
        assert_u256_eq(new_state_root, fields.new_state_root);
    }
}

fn coord_priv_key_hash(claim: Hash2Claim, coord_priv_key: u256) -> u256 {
    poseidon_hash2(claim, coord_priv_key, COORD_PRIV_KEY_HASH_DOMAIN)
}

fn packed_command_hash(claim: Hash5Claim, packed_command: U256x3) -> u256 {
    poseidon_hash5(
        claim,
        U256x5 {
            v0: packed_command.v0,
            v1: packed_command.v1,
            v2: packed_command.v2,
            v3: zero_u256(),
            v4: zero_u256(),
        },
    )
}

fn felt_from_u128(value: u128) -> felt252 {
    value.into()
}

fn native_hash_u256(value: u256) -> felt252 {
    poseidon_hash_span([felt_from_u128(value.low), felt_from_u128(value.high)].span())
}

fn native_hash_u256x2(value: U256x2) -> felt252 {
    poseidon_hash_span(
        [
            felt_from_u128(value.v0.low),
            felt_from_u128(value.v0.high),
            felt_from_u128(value.v1.low),
            felt_from_u128(value.v1.high),
        ]
            .span(),
    )
}

fn native_hash_u256x3(value: U256x3) -> felt252 {
    poseidon_hash_span(
        [
            felt_from_u128(value.v0.low),
            felt_from_u128(value.v0.high),
            felt_from_u128(value.v1.low),
            felt_from_u128(value.v1.high),
            felt_from_u128(value.v2.low),
            felt_from_u128(value.v2.high),
        ]
            .span(),
    )
}

fn native_coord_priv_key_hash(coord_priv_key: u256) -> felt252 {
    poseidon_hash_span(
        [
            felt_from_u128(coord_priv_key.low),
            felt_from_u128(coord_priv_key.high),
            NATIVE_COORD_PRIV_KEY_HASH_DOMAIN,
        ]
            .span(),
    )
}

fn verify_native_process_message_coord_key(
    fields: NativeProcessMessageCoordKeyPublicFields, witness: ProcessMessageCoordKeyWitness,
) {
    assert_coord_pub_key_matches_private_key(
        witness.coord_priv_key, witness.coord_pub_key, witness.coord_pub_key_scalar_mul,
    );
    assert(native_hash_u256x2(witness.coord_pub_key) == fields.coord_pub_key_hash, 'N_COORD_KEY');
    assert(
        native_coord_priv_key_hash(witness.coord_priv_key) == fields.coord_priv_key_hash,
        'N_COORD_PRIV',
    );
}

fn verify_native_process_message_ecdh(
    fields: NativeProcessMessageEcdhPublicFields, witness: ProcessMessageEcdhWitness,
) {
    assert_valid_message_index(fields.message_index);
    assert(
        native_coord_priv_key_hash(witness.coord_priv_key) == fields.coord_priv_key_hash,
        'N_COORD_PRIV',
    );
    assert(native_hash_u256x2(witness.enc_pub_key) == fields.enc_pub_key_hash, 'N_ENC_KEY');
    assert_u256_eq(witness.ecdh.scalar, witness.coord_priv_key);
    assert_u256_eq(witness.ecdh.base.v0, witness.enc_pub_key.v0);
    assert_u256_eq(witness.ecdh.base.v1, witness.enc_pub_key.v1);
    let shared_key = verify_babyjub_scalar_mul(witness.ecdh);
    assert(native_hash_u256x2(shared_key) == fields.shared_key_hash, 'N_SHARED_KEY');
}

fn verify_native_process_message_signature(
    fields: NativeProcessMessageSignaturePublicFields, witness: ProcessMessageSignatureWitness,
) {
    assert_valid_message_index(fields.message_index);
    assert(fields.is_signature_valid == 0 || fields.is_signature_valid == 1, 'BAD_SIG_BOOL');
    assert(native_hash_u256x2(witness.pub_key) == fields.pub_key_hash, 'N_PUB_KEY');
    assert(native_hash_u256x2(witness.r8) == fields.r8_hash, 'N_R8');
    assert(native_hash_u256x3(witness.packed_command) == fields.packed_command_hash, 'N_CMD');
    assert(native_hash_u256(witness.s) == fields.cmd_sig_s_hash, 'N_SIG_S');
    let valid = verify_babyjub_poseidon_signature(
        witness.pub_key, witness.r8, witness.s, witness.packed_command, witness.signature,
    );
    assert(valid.high == 0, 'SIG_BOOL_HIGH');
    assert(felt_from_u128(valid.low) == fields.is_signature_valid, 'SIG_VALID');
}

fn verify_native_process_message_step_core(
    fields: NativeProcessMessageStepCorePublicFields, witness: ProcessMessageStepCoreWitness,
) {
    assert_valid_message_index(fields.message_index);
    assert_bool_u256(witness.is_quadratic_cost);
    assert_u32(witness.num_signups);
    assert_u32(witness.max_vote_options);
    assert(witness.max_vote_options <= MAX_VOTE_OPTIONS, 'BAD_MAX_VO');
    assert(witness.num_signups <= MAX_SIGNUPS, 'BAD_NUM_SIGNUPS');
    assert(fields.is_signature_valid == 0 || fields.is_signature_valid == 1, 'BAD_SIG_BOOL');

    let packed_vals = witness.is_quadratic_cost * TWO_POW_64
        + witness.num_signups * TWO_POW_32
        + witness.max_vote_options;
    assert(native_hash_u256(packed_vals) == fields.packed_vals_hash, 'N_PACKED');
    assert(
        native_coord_priv_key_hash(witness.coord_priv_key) == fields.coord_priv_key_hash,
        'N_COORD_PRIV',
    );
    assert(native_hash_u256x2(witness.enc_pub_key) == fields.enc_pub_key_hash, 'N_ENC_KEY');
    assert(native_hash_u256x2(witness.process_one.shared_key) == fields.shared_key_hash, 'N_SHARED');
    assert(
        native_hash_u256x2(
            U256x2 { v0: witness.process_one.state_leaf.v0, v1: witness.process_one.state_leaf.v1 },
        ) == fields.signature_pub_key_hash,
        'N_SIG_PUB',
    );
    assert(native_hash_u256x2(witness.process_one.cmd_sig_r8) == fields.signature_r8_hash, 'N_R8');
    assert(
        native_hash_u256x3(witness.process_one.packed_command) == fields.packed_command_hash,
        'N_CMD',
    );
    assert(native_hash_u256(witness.process_one.cmd_sig_s) == fields.cmd_sig_s_hash, 'N_SIG_S');
    assert(witness.process_one.is_signature_valid.high == 0, 'SIG_BOOL_HIGH');
    assert(
        felt_from_u128(witness.process_one.is_signature_valid.low) == fields.is_signature_valid,
        'SIG_VALID',
    );

    let previous_message_hash = witness.message_hash.out.inputs.v4;
    assert(native_hash_u256(previous_message_hash) == fields.previous_message_hash, 'N_PREV_MSG');
    let next_message_hash = message_hash_or_empty(
        witness.message_hash, witness.msg, witness.enc_pub_key, previous_message_hash,
    );
    assert(native_hash_u256(next_message_hash) == fields.next_message_hash, 'N_NEXT_MSG');

    assert(native_hash_u256(witness.process_one.current_state_root) == fields.current_state_root_hash, 'N_CUR_ROOT');
    assert(native_hash_u256(witness.process_one.active_state_root) == fields.active_state_root_hash, 'N_ACTIVE');
    assert_u256_eq(witness.process_one.is_quadratic_cost, witness.is_quadratic_cost);
    assert_u256_eq(witness.process_one.num_signups, witness.num_signups);
    assert_u256_eq(witness.process_one.max_vote_options, witness.max_vote_options);
    assert(witness.process_one.expected_poll_id.high == 0, 'POLL_HIGH');
    assert(felt_from_u128(witness.process_one.expected_poll_id.low) == fields.expected_poll_id, 'POLL_ID');
    assert_message_matches(witness.msg, witness.process_one.msg);

    let computed_new_state_root = if is_zero(witness.enc_pub_key.v0) {
        assert_u256_eq(witness.process_one.is_valid, zero_u256());
        witness.process_one.current_state_root
    } else {
        process_one_chain_step(
            witness.process_one.current_state_root,
            witness.coord_priv_key,
            witness.process_one.active_state_root,
            witness.state_decrypt,
            witness.process_one,
        )
    };
    assert(native_hash_u256(computed_new_state_root) == fields.new_state_root_hash, 'N_NEW_ROOT');

    if fields.message_index == 4 {
        let current_state_commitment = poseidon_hash2(
            witness.current_state_commitment,
            witness.process_one.current_state_root,
            witness.current_state_salt,
        );
        assert(
            native_hash_u256(current_state_commitment) == fields.current_state_commitment_hash,
            'N_CUR_COMMIT',
        );
    }
    if fields.message_index == 0 {
        let new_state_commitment = poseidon_hash2(
            witness.new_state_commitment, computed_new_state_root, witness.new_state_salt,
        );
        assert(
            native_hash_u256(new_state_commitment) == fields.new_state_commitment_hash,
            'N_NEW_COMMIT',
        );
    }
}

fn verify_process_message_coord_key(
    fields: ProcessMessageCoordKeyPublicFields, witness: ProcessMessageCoordKeyWitness,
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

fn verify_process_message_ecdh(
    fields: ProcessMessageEcdhPublicFields, witness: ProcessMessageEcdhWitness,
) {
    assert_valid_message_index(fields.message_index);
    let private_hash = coord_priv_key_hash(witness.coord_priv_key_hash, witness.coord_priv_key);
    assert_u256_eq(private_hash, fields.coord_priv_key_hash);
    let enc_pub_key_hash = poseidon_hash2(
        witness.enc_pub_key_hash, witness.enc_pub_key.v0, witness.enc_pub_key.v1,
    );
    assert_u256_eq(enc_pub_key_hash, fields.enc_pub_key_hash);

    assert_u256_eq(witness.ecdh.scalar, witness.coord_priv_key);
    assert_u256_eq(witness.ecdh.base.v0, witness.enc_pub_key.v0);
    assert_u256_eq(witness.ecdh.base.v1, witness.enc_pub_key.v1);
    let shared_key = verify_babyjub_scalar_mul(witness.ecdh);
    let shared_key_hash = poseidon_hash2(witness.shared_key_hash, shared_key.v0, shared_key.v1);
    assert_u256_eq(shared_key_hash, fields.shared_key_hash);
}

fn verify_process_message_signature(
    fields: ProcessMessageSignaturePublicFields, witness: ProcessMessageSignatureWitness,
) {
    assert_valid_message_index(fields.message_index);
    assert_bool_u256(fields.is_signature_valid);
    let pub_key_hash = poseidon_hash2(witness.pub_key_hash, witness.pub_key.v0, witness.pub_key.v1);
    assert_u256_eq(pub_key_hash, fields.pub_key_hash);
    let r8_hash = poseidon_hash2(witness.r8_hash, witness.r8.v0, witness.r8.v1);
    assert_u256_eq(r8_hash, fields.r8_hash);
    let command_hash = packed_command_hash(witness.packed_command_hash, witness.packed_command);
    assert_u256_eq(command_hash, fields.packed_command_hash);
    assert_u256_eq(witness.s, fields.cmd_sig_s);
    let valid = verify_babyjub_poseidon_signature(
        witness.pub_key, witness.r8, witness.s, witness.packed_command, witness.signature,
    );
    assert_u256_eq(valid, fields.is_signature_valid);
}

fn assert_packed_core_vals(
    fields: ProcessMessageStepCorePublicFields,
    is_quadratic_cost: u256,
    num_signups: u256,
    max_vote_options: u256,
) {
    assert_bool_u256(is_quadratic_cost);
    assert_u32(num_signups);
    assert_u32(max_vote_options);
    assert(max_vote_options <= MAX_VOTE_OPTIONS, 'BAD_MAX_VO');
    assert(num_signups <= MAX_SIGNUPS, 'BAD_NUM_SIGNUPS');

    let packed_vals = is_quadratic_cost * TWO_POW_64 + num_signups * TWO_POW_32 + max_vote_options;
    assert_u256_eq(packed_vals, fields.packed_vals);
}

fn assert_process_message_step_core_claims(
    fields: ProcessMessageStepCorePublicFields,
    coord_priv_key: u256,
    coord_priv_key_hash_claim: Hash2Claim,
    enc_pub_key: U256x2,
    enc_pub_key_hash_claim: Hash2Claim,
    shared_key_hash_claim: Hash2Claim,
    signature_pub_key_hash_claim: Hash2Claim,
    signature_r8_hash_claim: Hash2Claim,
    packed_command_hash_claim: Hash5Claim,
    process_one: ProcessOneStateTransitionWitness,
) {
    let private_hash = coord_priv_key_hash(coord_priv_key_hash_claim, coord_priv_key);
    assert_u256_eq(private_hash, fields.coord_priv_key_hash);
    let enc_pub_key_hash = poseidon_hash2(enc_pub_key_hash_claim, enc_pub_key.v0, enc_pub_key.v1);
    assert_u256_eq(enc_pub_key_hash, fields.enc_pub_key_hash);
    let shared_key_hash = poseidon_hash2(
        shared_key_hash_claim, process_one.shared_key.v0, process_one.shared_key.v1,
    );
    assert_u256_eq(shared_key_hash, fields.shared_key_hash);
    let signature_pub_key_hash = poseidon_hash2(
        signature_pub_key_hash_claim, process_one.state_leaf.v0, process_one.state_leaf.v1,
    );
    assert_u256_eq(signature_pub_key_hash, fields.signature_pub_key_hash);
    let signature_r8_hash = poseidon_hash2(
        signature_r8_hash_claim, process_one.cmd_sig_r8.v0, process_one.cmd_sig_r8.v1,
    );
    assert_u256_eq(signature_r8_hash, fields.signature_r8_hash);
    let command_hash = packed_command_hash(packed_command_hash_claim, process_one.packed_command);
    assert_u256_eq(command_hash, fields.packed_command_hash);
    assert_u256_eq(process_one.cmd_sig_s, fields.cmd_sig_s);
    assert_u256_eq(process_one.is_signature_valid, fields.is_signature_valid);
}

fn verify_process_message_step_core(
    fields: ProcessMessageStepCorePublicFields, witness: ProcessMessageStepCoreWitness,
) {
    assert_valid_message_index(fields.message_index);
    assert_packed_core_vals(
        fields, witness.is_quadratic_cost, witness.num_signups, witness.max_vote_options,
    );
    assert_process_message_step_core_claims(
        fields,
        witness.coord_priv_key,
        witness.coord_priv_key_hash,
        witness.enc_pub_key,
        witness.enc_pub_key_hash,
        witness.shared_key_hash,
        witness.signature_pub_key_hash,
        witness.signature_r8_hash,
        witness.packed_command_hash,
        witness.process_one,
    );

    if fields.message_index == 4 {
        let current_state_commitment = poseidon_hash2(
            witness.current_state_commitment, fields.current_state_root, witness.current_state_salt,
        );
        assert_u256_eq(current_state_commitment, fields.current_state_commitment);
    }
    if fields.message_index == 0 {
        let new_state_commitment = poseidon_hash2(
            witness.new_state_commitment, fields.new_state_root, witness.new_state_salt,
        );
        assert_u256_eq(new_state_commitment, fields.new_state_commitment);
    }

    assert_u256_eq(witness.process_one.current_state_root, fields.current_state_root);
    assert_u256_eq(witness.process_one.active_state_root, fields.active_state_root);
    assert_u256_eq(witness.process_one.is_quadratic_cost, witness.is_quadratic_cost);
    assert_u256_eq(witness.process_one.num_signups, witness.num_signups);
    assert_u256_eq(witness.process_one.max_vote_options, witness.max_vote_options);
    assert_u256_eq(witness.process_one.expected_poll_id, fields.expected_poll_id);
    assert_message_matches(witness.msg, witness.process_one.msg);

    let next_message_hash = message_hash_or_empty(
        witness.message_hash, witness.msg, witness.enc_pub_key, fields.previous_message_hash,
    );
    assert_u256_eq(next_message_hash, fields.next_message_hash);

    if is_zero(witness.enc_pub_key.v0) {
        assert_u256_eq(witness.process_one.is_valid, zero_u256());
        assert_u256_eq(fields.current_state_root, fields.new_state_root);
    } else {
        let new_state_root = process_one_chain_step(
            fields.current_state_root,
            witness.coord_priv_key,
            fields.active_state_root,
            witness.state_decrypt,
            witness.process_one,
        );
        assert_u256_eq(new_state_root, fields.new_state_root);
    }
}

fn assert_ecdh_matches_process_one(
    coord_priv_key: u256,
    enc_pub_key: U256x2,
    ecdh: BabyJubJubScalarMulWitness,
    expected_shared_key: U256x2,
) {
    if !is_zero(enc_pub_key.v0) {
        assert_u256_eq(ecdh.scalar, coord_priv_key);
        assert_u256_eq(ecdh.base.v0, enc_pub_key.v0);
        assert_u256_eq(ecdh.base.v1, enc_pub_key.v1);
        let shared_key = verify_babyjub_scalar_mul(ecdh);
        assert_u256_eq(shared_key.v0, expected_shared_key.v0);
        assert_u256_eq(shared_key.v1, expected_shared_key.v1);
    }
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

fn process_one_chain_step(
    current_state_root: u256,
    coord_priv_key: u256,
    active_state_root: u256,
    state_decrypt: ElGamalDecryptWitness,
    process_one: ProcessOneStateTransitionWitness,
) -> u256 {
    assert_u256_eq(process_one.current_state_root, current_state_root);
    assert_u256_eq(process_one.active_state_root, active_state_root);
    let decryption_is_odd = assert_elgamal_decrypt(
        state_decrypt,
        coord_priv_key,
        U256x2 { v0: process_one.state_leaf.v5, v1: process_one.state_leaf.v6 },
        U256x2 { v0: process_one.state_leaf.v7, v1: process_one.state_leaf.v8 },
    );
    assert_u256_eq(process_one.is_decryption_active, bool_to_u256(!decryption_is_odd));
    process_one_state_transition(process_one)
}

fn process_one_bound_chain_step(
    current_state_root: u256,
    coord_priv_key: u256,
    active_state_root: u256,
    state_decrypt: ElGamalDecryptWitness,
    process_one: ProcessOneStateTransitionWitness,
    enc_pub_key: U256x2,
) -> u256 {
    assert_u256_eq(process_one.current_state_root, current_state_root);
    assert_u256_eq(process_one.active_state_root, active_state_root);
    if is_zero(enc_pub_key.v0) {
        assert_u256_eq(process_one.is_valid, zero_u256());
        current_state_root
    } else {
        let decryption_is_odd = assert_elgamal_decrypt(
            state_decrypt,
            coord_priv_key,
            U256x2 { v0: process_one.state_leaf.v5, v1: process_one.state_leaf.v6 },
            U256x2 { v0: process_one.state_leaf.v7, v1: process_one.state_leaf.v8 },
        );
        assert_u256_eq(process_one.is_decryption_active, bool_to_u256(!decryption_is_odd));
        process_one_state_transition(process_one)
    }
}

fn process_messages_state_transition(witness: ProcessMessagesStateTransitionWitness) -> u256 {
    let root_4 = process_one_chain_step(
        witness.current_state_root,
        witness.coord_priv_key,
        witness.active_state_root,
        witness.state_decrypt_4,
        witness.process_one_4,
    );
    let root_3 = process_one_chain_step(
        root_4,
        witness.coord_priv_key,
        witness.active_state_root,
        witness.state_decrypt_3,
        witness.process_one_3,
    );
    let root_2 = process_one_chain_step(
        root_3,
        witness.coord_priv_key,
        witness.active_state_root,
        witness.state_decrypt_2,
        witness.process_one_2,
    );
    let root_1 = process_one_chain_step(
        root_2,
        witness.coord_priv_key,
        witness.active_state_root,
        witness.state_decrypt_1,
        witness.process_one_1,
    );
    let root_0 = process_one_chain_step(
        root_1,
        witness.coord_priv_key,
        witness.active_state_root,
        witness.state_decrypt_0,
        witness.process_one_0,
    );
    assert_u256_eq(root_0, witness.new_state_root);
    root_0
}

fn process_messages_bound_state_transition(
    boundary: ProcessMessagesBoundaryWitness, witness: ProcessMessagesStateTransitionWitness,
) -> u256 {
    let root_4 = process_one_bound_chain_step(
        witness.current_state_root,
        witness.coord_priv_key,
        witness.active_state_root,
        witness.state_decrypt_4,
        witness.process_one_4,
        boundary.enc_pub_key_4,
    );
    let root_3 = process_one_bound_chain_step(
        root_4,
        witness.coord_priv_key,
        witness.active_state_root,
        witness.state_decrypt_3,
        witness.process_one_3,
        boundary.enc_pub_key_3,
    );
    let root_2 = process_one_bound_chain_step(
        root_3,
        witness.coord_priv_key,
        witness.active_state_root,
        witness.state_decrypt_2,
        witness.process_one_2,
        boundary.enc_pub_key_2,
    );
    let root_1 = process_one_bound_chain_step(
        root_2,
        witness.coord_priv_key,
        witness.active_state_root,
        witness.state_decrypt_1,
        witness.process_one_1,
        boundary.enc_pub_key_1,
    );
    let root_0 = process_one_bound_chain_step(
        root_1,
        witness.coord_priv_key,
        witness.active_state_root,
        witness.state_decrypt_0,
        witness.process_one_0,
        boundary.enc_pub_key_0,
    );
    assert_u256_eq(root_0, witness.new_state_root);
    root_0
}

fn assert_empty_message_transition(enc_pub_key: U256x2, process_one_is_valid: u256) {
    if is_zero(enc_pub_key.v0) {
        assert_u256_eq(process_one_is_valid, zero_u256());
    }
}

fn assert_process_one_boundary(
    boundary: ProcessMessagesBoundaryWitness,
    is_quadratic_cost: u256,
    num_signups: u256,
    max_vote_options: u256,
    expected_poll_id: u256,
) {
    assert_u256_eq(is_quadratic_cost, boundary.is_quadratic_cost);
    assert_u256_eq(num_signups, boundary.num_signups);
    assert_u256_eq(max_vote_options, boundary.max_vote_options);
    assert_u256_eq(expected_poll_id, boundary.expected_poll_id);
}

fn assert_message_matches(message: U256x10, process_one_msg: U256x10) {
    assert_u256_eq(process_one_msg.v0, message.v0);
    assert_u256_eq(process_one_msg.v1, message.v1);
    assert_u256_eq(process_one_msg.v2, message.v2);
    assert_u256_eq(process_one_msg.v3, message.v3);
    assert_u256_eq(process_one_msg.v4, message.v4);
    assert_u256_eq(process_one_msg.v5, message.v5);
    assert_u256_eq(process_one_msg.v6, message.v6);
    assert_u256_eq(process_one_msg.v7, message.v7);
    assert_u256_eq(process_one_msg.v8, message.v8);
    assert_u256_eq(process_one_msg.v9, message.v9);
}

fn assert_bool_u256(value: u256) {
    assert_u32(value);
    assert(value.low < 2, 'BOOL_RANGE');
}

fn assert_packed_vals(
    fields: ProcessMessagesPublicFields, witness: ProcessMessagesBoundaryWitness,
) {
    assert_bool_u256(witness.is_quadratic_cost);
    assert_u32(witness.num_signups);
    assert_u32(witness.max_vote_options);
    assert(witness.max_vote_options <= MAX_VOTE_OPTIONS, 'BAD_MAX_VO');
    assert(witness.num_signups <= MAX_SIGNUPS, 'BAD_NUM_SIGNUPS');

    let packed_vals = witness.is_quadratic_cost * TWO_POW_64
        + witness.num_signups * TWO_POW_32
        + witness.max_vote_options;
    assert_u256_eq(packed_vals, fields.packed_vals);
}

fn assert_packed_step_vals(
    fields: ProcessMessageStepPublicFields,
    is_quadratic_cost: u256,
    num_signups: u256,
    max_vote_options: u256,
) {
    assert_bool_u256(is_quadratic_cost);
    assert_u32(num_signups);
    assert_u32(max_vote_options);
    assert(max_vote_options <= MAX_VOTE_OPTIONS, 'BAD_MAX_VO');
    assert(num_signups <= MAX_SIGNUPS, 'BAD_NUM_SIGNUPS');

    let packed_vals = is_quadratic_cost * TWO_POW_64 + num_signups * TWO_POW_32 + max_vote_options;
    assert_u256_eq(packed_vals, fields.packed_vals);
}

fn assert_valid_message_index(message_index: felt252) {
    assert(
        message_index == 0
            || message_index == 1
            || message_index == 2
            || message_index == 3
            || message_index == 4,
        'BAD_MSG_INDEX',
    );
}

fn message_hash_or_empty(
    claim: Hash13Claim, msg: U256x10, enc_pub_key: U256x2, prev_hash: u256,
) -> u256 {
    if is_zero(enc_pub_key.v0) {
        prev_hash
    } else {
        let message_hash = poseidon_hash13(
            claim,
            u256x10_first5(msg),
            u256x10_second5(msg),
            enc_pub_key.v0,
            enc_pub_key.v1,
            prev_hash,
        );
        message_hash
    }
}

fn verify_process_messages_boundary(
    fields: ProcessMessagesPublicFields, witness: ProcessMessagesBoundaryWitness,
) {
    assert_packed_vals(fields, witness);

    let coord_pub_key_hash = poseidon_hash2(
        witness.hashes.coord_pub_key_hash, witness.coord_pub_key.v0, witness.coord_pub_key.v1,
    );
    assert_u256_eq(coord_pub_key_hash, fields.coord_pub_key_hash);

    let current_state_commitment = poseidon_hash2(
        witness.hashes.current_state_commitment,
        witness.current_state_root,
        witness.current_state_salt,
    );
    assert_u256_eq(current_state_commitment, fields.current_state_commitment);

    let new_state_commitment = poseidon_hash2(
        witness.hashes.new_state_commitment, witness.new_state_root, witness.new_state_salt,
    );
    assert_u256_eq(new_state_commitment, fields.new_state_commitment);

    let deactivate_commitment = poseidon_hash2(
        witness.hashes.deactivate_commitment, witness.active_state_root, witness.deactivate_root,
    );
    assert_u256_eq(deactivate_commitment, fields.deactivate_commitment);

    assert_u256_eq(witness.expected_poll_id, fields.expected_poll_id);

    let input_hash = sha256_u256x8_mod_bn254(
        witness.hashes.input_hash,
        U256x8 {
            v0: fields.packed_vals,
            v1: fields.coord_pub_key_hash,
            v2: fields.batch_start_hash,
            v3: fields.batch_end_hash,
            v4: fields.current_state_commitment,
            v5: fields.new_state_commitment,
            v6: fields.deactivate_commitment,
            v7: fields.expected_poll_id,
        },
    );
    assert_u256_eq(input_hash, fields.input_hash);

    let hash_1 = message_hash_or_empty(
        witness.hashes.message_hash_0,
        witness.msg_0,
        witness.enc_pub_key_0,
        fields.batch_start_hash,
    );
    let hash_2 = message_hash_or_empty(
        witness.hashes.message_hash_1, witness.msg_1, witness.enc_pub_key_1, hash_1,
    );
    let hash_3 = message_hash_or_empty(
        witness.hashes.message_hash_2, witness.msg_2, witness.enc_pub_key_2, hash_2,
    );
    let hash_4 = message_hash_or_empty(
        witness.hashes.message_hash_3, witness.msg_3, witness.enc_pub_key_3, hash_3,
    );
    let hash_5 = message_hash_or_empty(
        witness.hashes.message_hash_4, witness.msg_4, witness.enc_pub_key_4, hash_4,
    );
    assert_u256_eq(hash_5, fields.batch_end_hash);
}

fn verify_process_messages_stateful(
    fields: ProcessMessagesPublicFields, witness: ProcessMessagesStatefulWitness,
) {
    verify_process_messages_boundary(fields, witness.boundary);
    assert_u256_eq(
        witness.state_transition.current_state_root, witness.boundary.current_state_root,
    );
    assert_u256_eq(witness.state_transition.active_state_root, witness.boundary.active_state_root);
    assert_empty_message_transition(
        witness.boundary.enc_pub_key_0, witness.state_transition.process_one_0.is_valid,
    );
    assert_message_matches(witness.boundary.msg_0, witness.state_transition.process_one_0.msg);
    assert_process_one_boundary(
        witness.boundary,
        witness.state_transition.process_one_0.is_quadratic_cost,
        witness.state_transition.process_one_0.num_signups,
        witness.state_transition.process_one_0.max_vote_options,
        witness.state_transition.process_one_0.expected_poll_id,
    );
    assert_empty_message_transition(
        witness.boundary.enc_pub_key_1, witness.state_transition.process_one_1.is_valid,
    );
    assert_message_matches(witness.boundary.msg_1, witness.state_transition.process_one_1.msg);
    assert_process_one_boundary(
        witness.boundary,
        witness.state_transition.process_one_1.is_quadratic_cost,
        witness.state_transition.process_one_1.num_signups,
        witness.state_transition.process_one_1.max_vote_options,
        witness.state_transition.process_one_1.expected_poll_id,
    );
    assert_empty_message_transition(
        witness.boundary.enc_pub_key_2, witness.state_transition.process_one_2.is_valid,
    );
    assert_message_matches(witness.boundary.msg_2, witness.state_transition.process_one_2.msg);
    assert_process_one_boundary(
        witness.boundary,
        witness.state_transition.process_one_2.is_quadratic_cost,
        witness.state_transition.process_one_2.num_signups,
        witness.state_transition.process_one_2.max_vote_options,
        witness.state_transition.process_one_2.expected_poll_id,
    );
    assert_empty_message_transition(
        witness.boundary.enc_pub_key_3, witness.state_transition.process_one_3.is_valid,
    );
    assert_message_matches(witness.boundary.msg_3, witness.state_transition.process_one_3.msg);
    assert_process_one_boundary(
        witness.boundary,
        witness.state_transition.process_one_3.is_quadratic_cost,
        witness.state_transition.process_one_3.num_signups,
        witness.state_transition.process_one_3.max_vote_options,
        witness.state_transition.process_one_3.expected_poll_id,
    );
    assert_empty_message_transition(
        witness.boundary.enc_pub_key_4, witness.state_transition.process_one_4.is_valid,
    );
    assert_message_matches(witness.boundary.msg_4, witness.state_transition.process_one_4.msg);
    assert_process_one_boundary(
        witness.boundary,
        witness.state_transition.process_one_4.is_quadratic_cost,
        witness.state_transition.process_one_4.num_signups,
        witness.state_transition.process_one_4.max_vote_options,
        witness.state_transition.process_one_4.expected_poll_id,
    );
    let new_state_root = process_messages_bound_state_transition(
        witness.boundary, witness.state_transition,
    );
    assert_u256_eq(new_state_root, witness.boundary.new_state_root);
}

fn verify_process_messages_stateful_with_ecdh(
    fields: ProcessMessagesPublicFields, witness: ProcessMessagesStatefulWithEcdhWitness,
) {
    let boundary = witness.boundary;
    let state_transition = witness.state_transition;
    verify_process_messages_boundary(fields, boundary);
    assert_coord_pub_key_matches_private_key(
        witness.coord_priv_key, boundary.coord_pub_key, witness.coord_pub_key,
    );
    assert_u256_eq(state_transition.coord_priv_key, witness.coord_priv_key);
    assert_u256_eq(state_transition.current_state_root, boundary.current_state_root);
    assert_u256_eq(state_transition.active_state_root, boundary.active_state_root);

    assert_empty_message_transition(
        boundary.enc_pub_key_0, state_transition.process_one_0.is_valid,
    );
    assert_message_matches(boundary.msg_0, state_transition.process_one_0.msg);
    assert_process_one_boundary(
        boundary,
        state_transition.process_one_0.is_quadratic_cost,
        state_transition.process_one_0.num_signups,
        state_transition.process_one_0.max_vote_options,
        state_transition.process_one_0.expected_poll_id,
    );
    assert_ecdh_matches_process_one(
        witness.coord_priv_key,
        boundary.enc_pub_key_0,
        witness.ecdh_0,
        state_transition.process_one_0.shared_key,
    );

    assert_empty_message_transition(
        boundary.enc_pub_key_1, state_transition.process_one_1.is_valid,
    );
    assert_message_matches(boundary.msg_1, state_transition.process_one_1.msg);
    assert_process_one_boundary(
        boundary,
        state_transition.process_one_1.is_quadratic_cost,
        state_transition.process_one_1.num_signups,
        state_transition.process_one_1.max_vote_options,
        state_transition.process_one_1.expected_poll_id,
    );
    assert_ecdh_matches_process_one(
        witness.coord_priv_key,
        boundary.enc_pub_key_1,
        witness.ecdh_1,
        state_transition.process_one_1.shared_key,
    );

    assert_empty_message_transition(
        boundary.enc_pub_key_2, state_transition.process_one_2.is_valid,
    );
    assert_message_matches(boundary.msg_2, state_transition.process_one_2.msg);
    assert_process_one_boundary(
        boundary,
        state_transition.process_one_2.is_quadratic_cost,
        state_transition.process_one_2.num_signups,
        state_transition.process_one_2.max_vote_options,
        state_transition.process_one_2.expected_poll_id,
    );
    assert_ecdh_matches_process_one(
        witness.coord_priv_key,
        boundary.enc_pub_key_2,
        witness.ecdh_2,
        state_transition.process_one_2.shared_key,
    );

    assert_empty_message_transition(
        boundary.enc_pub_key_3, state_transition.process_one_3.is_valid,
    );
    assert_message_matches(boundary.msg_3, state_transition.process_one_3.msg);
    assert_process_one_boundary(
        boundary,
        state_transition.process_one_3.is_quadratic_cost,
        state_transition.process_one_3.num_signups,
        state_transition.process_one_3.max_vote_options,
        state_transition.process_one_3.expected_poll_id,
    );
    assert_ecdh_matches_process_one(
        witness.coord_priv_key,
        boundary.enc_pub_key_3,
        witness.ecdh_3,
        state_transition.process_one_3.shared_key,
    );

    assert_empty_message_transition(
        boundary.enc_pub_key_4, state_transition.process_one_4.is_valid,
    );
    assert_message_matches(boundary.msg_4, state_transition.process_one_4.msg);
    assert_process_one_boundary(
        boundary,
        state_transition.process_one_4.is_quadratic_cost,
        state_transition.process_one_4.num_signups,
        state_transition.process_one_4.max_vote_options,
        state_transition.process_one_4.expected_poll_id,
    );
    assert_ecdh_matches_process_one(
        witness.coord_priv_key,
        boundary.enc_pub_key_4,
        witness.ecdh_4,
        state_transition.process_one_4.shared_key,
    );

    let new_state_root = process_messages_bound_state_transition(boundary, state_transition);
    assert_u256_eq(new_state_root, boundary.new_state_root);
}

fn verify_process_messages_stateful_with_ecdh_signature(
    fields: ProcessMessagesPublicFields, witness: ProcessMessagesStatefulWithEcdhSignatureWitness,
) {
    let boundary = witness.boundary;
    let state_transition = witness.state_transition;
    verify_process_messages_boundary(fields, boundary);
    assert_coord_pub_key_matches_private_key(
        witness.coord_priv_key, boundary.coord_pub_key, witness.coord_pub_key,
    );
    assert_u256_eq(state_transition.coord_priv_key, witness.coord_priv_key);
    assert_u256_eq(state_transition.current_state_root, boundary.current_state_root);
    assert_u256_eq(state_transition.active_state_root, boundary.active_state_root);

    assert_empty_message_transition(
        boundary.enc_pub_key_0, state_transition.process_one_0.is_valid,
    );
    assert_message_matches(boundary.msg_0, state_transition.process_one_0.msg);
    assert_process_one_boundary(
        boundary,
        state_transition.process_one_0.is_quadratic_cost,
        state_transition.process_one_0.num_signups,
        state_transition.process_one_0.max_vote_options,
        state_transition.process_one_0.expected_poll_id,
    );
    assert_ecdh_matches_process_one(
        witness.coord_priv_key,
        boundary.enc_pub_key_0,
        witness.ecdh_0,
        state_transition.process_one_0.shared_key,
    );
    assert_signature_matches_process_one_if_nonempty(
        boundary.enc_pub_key_0,
        witness.signature_0,
        U256x2 {
            v0: state_transition.process_one_0.state_leaf.v0,
            v1: state_transition.process_one_0.state_leaf.v1,
        },
        state_transition.process_one_0.cmd_sig_r8,
        state_transition.process_one_0.cmd_sig_s,
        state_transition.process_one_0.packed_command,
        state_transition.process_one_0.is_signature_valid,
    );

    assert_empty_message_transition(
        boundary.enc_pub_key_1, state_transition.process_one_1.is_valid,
    );
    assert_message_matches(boundary.msg_1, state_transition.process_one_1.msg);
    assert_process_one_boundary(
        boundary,
        state_transition.process_one_1.is_quadratic_cost,
        state_transition.process_one_1.num_signups,
        state_transition.process_one_1.max_vote_options,
        state_transition.process_one_1.expected_poll_id,
    );
    assert_ecdh_matches_process_one(
        witness.coord_priv_key,
        boundary.enc_pub_key_1,
        witness.ecdh_1,
        state_transition.process_one_1.shared_key,
    );
    assert_signature_matches_process_one_if_nonempty(
        boundary.enc_pub_key_1,
        witness.signature_1,
        U256x2 {
            v0: state_transition.process_one_1.state_leaf.v0,
            v1: state_transition.process_one_1.state_leaf.v1,
        },
        state_transition.process_one_1.cmd_sig_r8,
        state_transition.process_one_1.cmd_sig_s,
        state_transition.process_one_1.packed_command,
        state_transition.process_one_1.is_signature_valid,
    );

    assert_empty_message_transition(
        boundary.enc_pub_key_2, state_transition.process_one_2.is_valid,
    );
    assert_message_matches(boundary.msg_2, state_transition.process_one_2.msg);
    assert_process_one_boundary(
        boundary,
        state_transition.process_one_2.is_quadratic_cost,
        state_transition.process_one_2.num_signups,
        state_transition.process_one_2.max_vote_options,
        state_transition.process_one_2.expected_poll_id,
    );
    assert_ecdh_matches_process_one(
        witness.coord_priv_key,
        boundary.enc_pub_key_2,
        witness.ecdh_2,
        state_transition.process_one_2.shared_key,
    );
    assert_signature_matches_process_one_if_nonempty(
        boundary.enc_pub_key_2,
        witness.signature_2,
        U256x2 {
            v0: state_transition.process_one_2.state_leaf.v0,
            v1: state_transition.process_one_2.state_leaf.v1,
        },
        state_transition.process_one_2.cmd_sig_r8,
        state_transition.process_one_2.cmd_sig_s,
        state_transition.process_one_2.packed_command,
        state_transition.process_one_2.is_signature_valid,
    );

    assert_empty_message_transition(
        boundary.enc_pub_key_3, state_transition.process_one_3.is_valid,
    );
    assert_message_matches(boundary.msg_3, state_transition.process_one_3.msg);
    assert_process_one_boundary(
        boundary,
        state_transition.process_one_3.is_quadratic_cost,
        state_transition.process_one_3.num_signups,
        state_transition.process_one_3.max_vote_options,
        state_transition.process_one_3.expected_poll_id,
    );
    assert_ecdh_matches_process_one(
        witness.coord_priv_key,
        boundary.enc_pub_key_3,
        witness.ecdh_3,
        state_transition.process_one_3.shared_key,
    );
    assert_signature_matches_process_one_if_nonempty(
        boundary.enc_pub_key_3,
        witness.signature_3,
        U256x2 {
            v0: state_transition.process_one_3.state_leaf.v0,
            v1: state_transition.process_one_3.state_leaf.v1,
        },
        state_transition.process_one_3.cmd_sig_r8,
        state_transition.process_one_3.cmd_sig_s,
        state_transition.process_one_3.packed_command,
        state_transition.process_one_3.is_signature_valid,
    );

    assert_empty_message_transition(
        boundary.enc_pub_key_4, state_transition.process_one_4.is_valid,
    );
    assert_message_matches(boundary.msg_4, state_transition.process_one_4.msg);
    assert_process_one_boundary(
        boundary,
        state_transition.process_one_4.is_quadratic_cost,
        state_transition.process_one_4.num_signups,
        state_transition.process_one_4.max_vote_options,
        state_transition.process_one_4.expected_poll_id,
    );
    assert_ecdh_matches_process_one(
        witness.coord_priv_key,
        boundary.enc_pub_key_4,
        witness.ecdh_4,
        state_transition.process_one_4.shared_key,
    );
    assert_signature_matches_process_one_if_nonempty(
        boundary.enc_pub_key_4,
        witness.signature_4,
        U256x2 {
            v0: state_transition.process_one_4.state_leaf.v0,
            v1: state_transition.process_one_4.state_leaf.v1,
        },
        state_transition.process_one_4.cmd_sig_r8,
        state_transition.process_one_4.cmd_sig_s,
        state_transition.process_one_4.packed_command,
        state_transition.process_one_4.is_signature_valid,
    );

    let new_state_root = process_messages_bound_state_transition(boundary, state_transition);
    assert_u256_eq(new_state_root, boundary.new_state_root);
}

#[executable]
pub fn process_messages_boundary_main(
    fields: ProcessMessagesPublicFields, witness: ProcessMessagesBoundaryWitness,
) -> ProcessMessagesPublicOutput {
    verify_process_messages_boundary(fields, witness);
    build_process_messages_public_output(fields)
}

#[executable]
pub fn process_one_state_transition_main(witness: ProcessOneStateTransitionWitness) -> u256 {
    process_one_state_transition(witness)
}

#[executable]
pub fn process_one_with_ecdh_main(witness: ProcessOneWithEcdhWitness) -> u256 {
    process_one_with_ecdh(witness)
}

#[executable]
pub fn process_one_with_signature_main(witness: ProcessOneWithSignatureWitness) -> u256 {
    process_one_with_signature(witness)
}

#[executable]
pub fn process_one_with_ecdh_signature_main(witness: ProcessOneWithEcdhSignatureWitness) -> u256 {
    process_one_with_ecdh_signature(witness)
}

#[executable]
pub fn process_message_step_with_ecdh_signature_main(
    fields: ProcessMessageStepPublicFields, witness: ProcessMessageStepWithEcdhSignatureWitness,
) -> ProcessMessageStepPublicOutput {
    verify_process_message_step_with_ecdh_signature(fields, witness);
    build_process_message_step_public_output(fields)
}

#[executable]
pub fn process_message_coord_key_main(
    fields: ProcessMessageCoordKeyPublicFields, witness: ProcessMessageCoordKeyWitness,
) -> ProcessMessageCoordKeyPublicOutput {
    verify_process_message_coord_key(fields, witness);
    build_process_message_coord_key_public_output(fields)
}

fn build_native_process_message_coord_key_public_output(
    fields: NativeProcessMessageCoordKeyPublicFields,
) -> NativeProcessMessageCoordKeyPublicOutput {
    NativeProcessMessageCoordKeyPublicOutput {
        magic: crate::public_output::PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_MESSAGE_COORD_KEY_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        vote_option_tree_depth: 1,
        message_batch_size: 5,
        coord_pub_key_hash: fields.coord_pub_key_hash,
        coord_priv_key_hash: fields.coord_priv_key_hash,
    }
}

#[executable]
pub fn process_message_coord_key_native_main(
    fields: NativeProcessMessageCoordKeyPublicFields, witness: ProcessMessageCoordKeyWitness,
) -> NativeProcessMessageCoordKeyPublicOutput {
    verify_native_process_message_coord_key(fields, witness);
    build_native_process_message_coord_key_public_output(fields)
}

#[executable]
pub fn process_message_ecdh_main(
    fields: ProcessMessageEcdhPublicFields, witness: ProcessMessageEcdhWitness,
) -> ProcessMessageEcdhPublicOutput {
    verify_process_message_ecdh(fields, witness);
    build_process_message_ecdh_public_output(fields)
}

fn build_native_process_message_ecdh_public_output(
    fields: NativeProcessMessageEcdhPublicFields,
) -> NativeProcessMessageEcdhPublicOutput {
    NativeProcessMessageEcdhPublicOutput {
        magic: crate::public_output::PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_MESSAGE_ECDH_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        vote_option_tree_depth: 1,
        message_batch_size: 5,
        message_index: fields.message_index,
        coord_priv_key_hash: fields.coord_priv_key_hash,
        enc_pub_key_hash: fields.enc_pub_key_hash,
        shared_key_hash: fields.shared_key_hash,
    }
}

#[executable]
pub fn process_message_ecdh_native_main(
    fields: NativeProcessMessageEcdhPublicFields, witness: ProcessMessageEcdhWitness,
) -> NativeProcessMessageEcdhPublicOutput {
    verify_native_process_message_ecdh(fields, witness);
    build_native_process_message_ecdh_public_output(fields)
}

#[executable]
pub fn process_message_signature_main(
    fields: ProcessMessageSignaturePublicFields, witness: ProcessMessageSignatureWitness,
) -> ProcessMessageSignaturePublicOutput {
    verify_process_message_signature(fields, witness);
    build_process_message_signature_public_output(fields)
}

fn build_native_process_message_signature_public_output(
    fields: NativeProcessMessageSignaturePublicFields,
) -> NativeProcessMessageSignaturePublicOutput {
    NativeProcessMessageSignaturePublicOutput {
        magic: crate::public_output::PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_MESSAGE_SIGNATURE_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        vote_option_tree_depth: 1,
        message_batch_size: 5,
        message_index: fields.message_index,
        pub_key_hash: fields.pub_key_hash,
        r8_hash: fields.r8_hash,
        packed_command_hash: fields.packed_command_hash,
        cmd_sig_s_hash: fields.cmd_sig_s_hash,
        is_signature_valid: fields.is_signature_valid,
    }
}

#[executable]
pub fn process_message_signature_native_main(
    fields: NativeProcessMessageSignaturePublicFields, witness: ProcessMessageSignatureWitness,
) -> NativeProcessMessageSignaturePublicOutput {
    verify_native_process_message_signature(fields, witness);
    build_native_process_message_signature_public_output(fields)
}

fn build_native_process_message_step_core_public_output(
    fields: NativeProcessMessageStepCorePublicFields,
) -> NativeProcessMessageStepCorePublicOutput {
    NativeProcessMessageStepCorePublicOutput {
        magic: crate::public_output::PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_MESSAGE_STEP_CORE_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        vote_option_tree_depth: 1,
        message_batch_size: 5,
        message_index: fields.message_index,
        packed_vals_hash: fields.packed_vals_hash,
        coord_priv_key_hash: fields.coord_priv_key_hash,
        previous_message_hash: fields.previous_message_hash,
        next_message_hash: fields.next_message_hash,
        current_state_root_hash: fields.current_state_root_hash,
        new_state_root_hash: fields.new_state_root_hash,
        current_state_commitment_hash: fields.current_state_commitment_hash,
        new_state_commitment_hash: fields.new_state_commitment_hash,
        active_state_root_hash: fields.active_state_root_hash,
        expected_poll_id: fields.expected_poll_id,
        enc_pub_key_hash: fields.enc_pub_key_hash,
        shared_key_hash: fields.shared_key_hash,
        signature_pub_key_hash: fields.signature_pub_key_hash,
        signature_r8_hash: fields.signature_r8_hash,
        packed_command_hash: fields.packed_command_hash,
        cmd_sig_s_hash: fields.cmd_sig_s_hash,
        is_signature_valid: fields.is_signature_valid,
    }
}

#[executable]
pub fn process_message_step_core_main(
    fields: ProcessMessageStepCorePublicFields, witness: ProcessMessageStepCoreWitness,
) -> ProcessMessageStepCorePublicOutput {
    verify_process_message_step_core(fields, witness);
    build_process_message_step_core_public_output(fields)
}

#[executable]
pub fn process_message_step_core_native_main(
    fields: NativeProcessMessageStepCorePublicFields, witness: ProcessMessageStepCoreWitness,
) -> NativeProcessMessageStepCorePublicOutput {
    verify_native_process_message_step_core(fields, witness);
    build_native_process_message_step_core_public_output(fields)
}

#[executable]
pub fn process_messages_state_transition_main(
    witness: ProcessMessagesStateTransitionWitness,
) -> u256 {
    process_messages_state_transition(witness)
}

#[executable]
pub fn process_messages_stateful_main(
    fields: ProcessMessagesPublicFields, witness: ProcessMessagesStatefulWitness,
) -> ProcessMessagesPublicOutput {
    verify_process_messages_stateful(fields, witness);
    build_process_messages_public_output(fields)
}

#[executable]
pub fn process_messages_stateful_with_ecdh_main(
    fields: ProcessMessagesPublicFields, witness: ProcessMessagesStatefulWithEcdhWitness,
) -> ProcessMessagesPublicOutput {
    verify_process_messages_stateful_with_ecdh(fields, witness);
    build_process_messages_public_output(fields)
}

#[executable]
pub fn process_messages_stateful_with_ecdh_signature_main(
    fields: ProcessMessagesPublicFields, witness: ProcessMessagesStatefulWithEcdhSignatureWitness,
) -> ProcessMessagesPublicOutput {
    verify_process_messages_stateful_with_ecdh_signature(fields, witness);
    build_process_messages_public_output(fields)
}
