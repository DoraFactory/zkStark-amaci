use core::hash::HashStateTrait;
use core::poseidon::PoseidonTrait;

const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b;
const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
const STARKNET_POSEIDON_HASH_SCHEME: felt252 = 0x535441524b4e45545f504f534549444f4e;
const PROCESS_MESSAGE_COORD_KEY_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f504d53475f434f4f52445f4e4154495645;
const PROCESS_MESSAGE_ECDH_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f504d53475f454344485f4e4154495645;
const PROCESS_MESSAGE_DECRYPT_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f504d53475f4445435f4e4154495645;
const PROCESS_MESSAGE_SIGNATURE_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f504d53475f5349475f4e4154495645;
const PROCESS_MESSAGE_STEP_CORE_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f504d53475f535445505f434f52455f4e4154495645;
const NATIVE_COORD_PRIV_KEY_HASH_DOMAIN: felt252 = 0x414d4143495f434f4f52445f50524956;
const NATIVE_COORD_KEY_BINDING_DOMAIN: felt252 =
    0x414d4143495f504d53475f434f4f52445f42494e44;
const NATIVE_COMMAND_AUTH_DOMAIN: felt252 = 0x414d4143495f504d53475f41555448;
const NATIVE_COMMAND_PLAINTEXT_DOMAIN: felt252 =
    0x414d4143495f504d53475f434d445f504c41494e;
const NATIVE_DECRYPT_BINDING_DOMAIN: felt252 =
    0x414d4143495f504d53475f4445435f42494e44;
const NATIVE_SHARED_KEY_DOMAIN: felt252 = 0x414d4143495f504d53475f534841524544;
const FELT_TWO_POW_128: felt252 = 0x100000000000000000000000000000000;
const TWO_POW_32: u256 = 0x100000000;
const TWO_POW_64: u256 = 0x10000000000000000;
const U128_TWO_POW_32: u128 = 0x100000000;
const U128_TWO_POW_64: u128 = 0x10000000000000000;
const U128_TWO_POW_96: u128 = 0x1000000000000000000000000;
const VOTE_WEIGHT_HIGH_FACTOR: u256 = 18446744073709552000;
const MAX_VOTE_OPTIONS: u256 = 5;
const MAX_SIGNUPS: u256 = 25;
const MAX_STATE_INDEX: u256 = 24;
const MAX_VALID_VOTE_WEIGHT: u256 = 147946756881789319005730692170996259609;

#[derive(Copy, Drop, Serde)]
pub struct U256x2 {
    pub v0: u256,
    pub v1: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct U256x3 {
    pub v0: u256,
    pub v1: u256,
    pub v2: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct U256x4 {
    pub v0: u256,
    pub v1: u256,
    pub v2: u256,
    pub v3: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct U256x7 {
    pub v0: u256,
    pub v1: u256,
    pub v2: u256,
    pub v3: u256,
    pub v4: u256,
    pub v5: u256,
    pub v6: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct U256x10 {
    pub v0: u256,
    pub v1: u256,
    pub v2: u256,
    pub v3: u256,
    pub v4: u256,
    pub v5: u256,
    pub v6: u256,
    pub v7: u256,
    pub v8: u256,
    pub v9: u256,
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

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageCoordKeyWitness {
    pub coord_priv_key: u256,
    pub coord_pub_key: U256x2,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageEcdhWitness {
    pub coord_priv_key: u256,
    pub enc_pub_key: U256x2,
    pub shared_key: U256x2,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageDecryptWitness {
    pub coord_priv_key: u256,
    pub c1: U256x2,
    pub c2: U256x2,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageSignatureWitness {
    pub pub_key: U256x2,
    pub r8: U256x2,
    pub s: u256,
    pub packed_command: U256x3,
    pub cmd_salt: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageCoordKeyPublicFields {
    pub coord_pub_key_hash: felt252,
    pub coord_priv_key_hash: felt252,
    pub coord_key_binding_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageEcdhPublicFields {
    pub message_index: felt252,
    pub coord_priv_key_hash: felt252,
    pub enc_pub_key_hash: felt252,
    pub shared_key_hash: felt252,
    pub shared_key_binding_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageDecryptPublicFields {
    pub message_index: felt252,
    pub coord_priv_key_hash: felt252,
    pub c1_hash: felt252,
    pub c2_hash: felt252,
    pub decrypt_is_odd: felt252,
    pub decrypt_binding_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageSignaturePublicFields {
    pub message_index: felt252,
    pub pub_key_hash: felt252,
    pub r8_hash: felt252,
    pub packed_command_hash: felt252,
    pub cmd_sig_s_hash: felt252,
    pub command_auth_hash: felt252,
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
    pub shared_key_binding_hash: felt252,
    pub state_ciphertext_c1_hash: felt252,
    pub state_ciphertext_c2_hash: felt252,
    pub state_decrypt_is_odd: felt252,
    pub state_decrypt_binding_hash: felt252,
    pub signature_pub_key_hash: felt252,
    pub signature_r8_hash: felt252,
    pub packed_command_hash: felt252,
    pub cmd_sig_s_hash: felt252,
    pub command_auth_hash: felt252,
    pub command_plaintext_binding_hash: felt252,
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
    pub coord_key_binding_hash: felt252,
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
    pub shared_key_binding_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessMessageDecryptPublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub hash_scheme: felt252,
    pub state_tree_depth: felt252,
    pub vote_option_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub message_index: felt252,
    pub coord_priv_key_hash: felt252,
    pub c1_hash: felt252,
    pub c2_hash: felt252,
    pub decrypt_is_odd: felt252,
    pub decrypt_binding_hash: felt252,
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
    pub command_auth_hash: felt252,
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
    pub shared_key_binding_hash: felt252,
    pub state_ciphertext_c1_hash: felt252,
    pub state_ciphertext_c2_hash: felt252,
    pub state_decrypt_is_odd: felt252,
    pub state_decrypt_binding_hash: felt252,
    pub signature_pub_key_hash: felt252,
    pub signature_r8_hash: felt252,
    pub packed_command_hash: felt252,
    pub cmd_sig_s_hash: felt252,
    pub command_auth_hash: felt252,
    pub command_plaintext_binding_hash: felt252,
    pub is_signature_valid: felt252,
}

#[derive(Drop, Serde)]
pub struct NativeProcessMessageStepCoreWitness {
    pub is_quadratic_cost: u256,
    pub num_signups: u256,
    pub max_vote_options: u256,
    pub enc_pub_key: U256x2,
    pub msg: U256x10,
    pub coord_priv_key: u256,
    pub current_state_salt: u256,
    pub new_state_salt: u256,
    pub process_one: ProcessOneStateTransitionWitness,
}

#[derive(Copy, Drop)]
struct ProcessOneValidation {
    is_valid: bool,
    new_balance: u256,
    new_sl_nonce: u256,
}

fn felt_from_u128(value: u128) -> felt252 {
    value.into()
}

fn felt_from_u256(value: u256) -> felt252 {
    felt_from_u128(value.low) + felt_from_u128(value.high) * FELT_TWO_POW_128
}

fn native_hash_values_1(v0: felt252) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(v0);
    state.finalize()
}

fn native_hash_values_2(v0: felt252, v1: felt252) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(v0);
    state = state.update(v1);
    state.finalize()
}

fn native_hash_values_3(v0: felt252, v1: felt252, v2: felt252) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(v0);
    state = state.update(v1);
    state = state.update(v2);
    state.finalize()
}

fn native_hash_values_4(v0: felt252, v1: felt252, v2: felt252, v3: felt252) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(v0);
    state = state.update(v1);
    state = state.update(v2);
    state = state.update(v3);
    state.finalize()
}

fn native_hash_values_5(
    v0: felt252, v1: felt252, v2: felt252, v3: felt252, v4: felt252,
) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(v0);
    state = state.update(v1);
    state = state.update(v2);
    state = state.update(v3);
    state = state.update(v4);
    state.finalize()
}

fn native_hash_values_7(
    v0: felt252,
    v1: felt252,
    v2: felt252,
    v3: felt252,
    v4: felt252,
    v5: felt252,
    v6: felt252,
) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(v0);
    state = state.update(v1);
    state = state.update(v2);
    state = state.update(v3);
    state = state.update(v4);
    state = state.update(v5);
    state = state.update(v6);
    state.finalize()
}

fn native_hash_values_8(
    v0: felt252,
    v1: felt252,
    v2: felt252,
    v3: felt252,
    v4: felt252,
    v5: felt252,
    v6: felt252,
    v7: felt252,
) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(v0);
    state = state.update(v1);
    state = state.update(v2);
    state = state.update(v3);
    state = state.update(v4);
    state = state.update(v5);
    state = state.update(v6);
    state = state.update(v7);
    state.finalize()
}

fn native_hash_values_13(
    v0: felt252,
    v1: felt252,
    v2: felt252,
    v3: felt252,
    v4: felt252,
    v5: felt252,
    v6: felt252,
    v7: felt252,
    v8: felt252,
    v9: felt252,
    v10: felt252,
    v11: felt252,
    v12: felt252,
) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(v0);
    state = state.update(v1);
    state = state.update(v2);
    state = state.update(v3);
    state = state.update(v4);
    state = state.update(v5);
    state = state.update(v6);
    state = state.update(v7);
    state = state.update(v8);
    state = state.update(v9);
    state = state.update(v10);
    state = state.update(v11);
    state = state.update(v12);
    state.finalize()
}

fn native_hash_u256(value: u256) -> felt252 {
    native_hash_values_1(felt_from_u256(value))
}

fn native_hash_u256x2(value: U256x2) -> felt252 {
    native_hash_values_2(felt_from_u256(value.v0), felt_from_u256(value.v1))
}

fn native_hash_u256x3(value: U256x3) -> felt252 {
    native_hash_values_3(
        felt_from_u256(value.v0), felt_from_u256(value.v1), felt_from_u256(value.v2),
    )
}

fn native_coord_priv_key_hash(coord_priv_key: u256) -> felt252 {
    native_hash_values_2(felt_from_u256(coord_priv_key), NATIVE_COORD_PRIV_KEY_HASH_DOMAIN)
}

fn native_coord_key_binding_hash(
    coord_pub_key_hash: felt252, coord_priv_key_hash: felt252,
) -> felt252 {
    native_hash_values_3(NATIVE_COORD_KEY_BINDING_DOMAIN, coord_pub_key_hash, coord_priv_key_hash)
}

fn native_shared_key_binding_hash(
    coord_priv_key_hash: felt252, enc_pub_key_hash: felt252, shared_key_hash: felt252,
) -> felt252 {
    native_hash_values_4(
        NATIVE_SHARED_KEY_DOMAIN, coord_priv_key_hash, enc_pub_key_hash, shared_key_hash,
    )
}

fn native_decrypt_binding_hash(
    coord_priv_key_hash: felt252,
    c1_hash: felt252,
    c2_hash: felt252,
    decrypt_is_odd: felt252,
) -> felt252 {
    native_hash_values_5(
        NATIVE_DECRYPT_BINDING_DOMAIN, coord_priv_key_hash, c1_hash, c2_hash, decrypt_is_odd,
    )
}

fn native_command_auth_hash(
    pub_key_hash: felt252,
    r8_hash: felt252,
    packed_command_hash: felt252,
    cmd_sig_s_hash: felt252,
    cmd_salt: u256,
    is_signature_valid: felt252,
) -> felt252 {
    native_hash_values_7(
        NATIVE_COMMAND_AUTH_DOMAIN,
        pub_key_hash,
        r8_hash,
        packed_command_hash,
        cmd_sig_s_hash,
        felt_from_u256(cmd_salt),
        is_signature_valid,
    )
}

fn zero_u256() -> u256 {
    0
}

fn is_zero(value: u256) -> bool {
    value.high == 0 && value.low == 0
}

fn assert_u256_eq(left: u256, right: u256) {
    assert(left.low == right.low, 'U256_LOW');
    assert(left.high == right.high, 'U256_HIGH');
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

fn assert_bool_u256(value: u256) {
    assert_u32(value);
    assert(value.low < 2, 'BOOL_RANGE');
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

fn validate_packed_command(witness: ProcessOneStateTransitionWitness) {
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
        + unpacked.v1 * VOTE_WEIGHT_HIGH_FACTOR;
    assert_u256_eq(witness.cmd_poll_id, unpacked.v0);
    assert_u256_eq(witness.cmd_new_vote_weight, unpacked_vote_weight);
    assert_u256_eq(witness.cmd_vote_option_index, unpacked.v4);
    assert_u256_eq(witness.cmd_state_index, unpacked.v5);
    assert_u256_eq(witness.cmd_nonce, unpacked.v6);
    assert_u256_eq(witness.cmd_new_pub_key.v0, witness.packed_command.v1);
    assert_u256_eq(witness.cmd_new_pub_key.v1, witness.packed_command.v2);
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

fn native_command_plaintext_binding_hash(
    next_message_hash: felt252,
    shared_key_hash: felt252,
    packed_command_hash: felt252,
    signature_pub_key_hash: felt252,
    signature_r8_hash: felt252,
    cmd_sig_s_hash: felt252,
    command_auth_hash: felt252,
) -> felt252 {
    native_hash_values_8(
        NATIVE_COMMAND_PLAINTEXT_DOMAIN,
        next_message_hash,
        shared_key_hash,
        packed_command_hash,
        signature_pub_key_hash,
        signature_r8_hash,
        cmd_sig_s_hash,
        command_auth_hash,
    )
}

fn native_hash5_values(v0: felt252, v1: felt252, v2: felt252, v3: felt252, v4: felt252) -> felt252 {
    native_hash_values_5(v0, v1, v2, v3, v4)
}

fn native_hash10_values(
    v0: felt252,
    v1: felt252,
    v2: felt252,
    v3: felt252,
    v4: felt252,
    v5: felt252,
    v6: felt252,
    v7: felt252,
    v8: felt252,
    v9: felt252,
) -> felt252 {
    native_hash_values_2(
        native_hash5_values(v0, v1, v2, v3, v4),
        native_hash5_values(v5, v6, v7, v8, v9),
    )
}

fn native_hash_state_leaf(value: U256x10, vote_root: felt252) -> felt252 {
    native_hash10_values(
        felt_from_u256(value.v0),
        felt_from_u256(value.v1),
        felt_from_u256(value.v2),
        vote_root,
        felt_from_u256(value.v4),
        felt_from_u256(value.v5),
        felt_from_u256(value.v6),
        felt_from_u256(value.v7),
        felt_from_u256(value.v8),
        felt_from_u256(value.v9),
    )
}

fn native_message_hash(message: U256x10, enc_pub_key: U256x2, previous_hash: felt252) -> felt252 {
    native_hash_values_13(
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
    )
}

fn native_message_hash_or_empty(
    message: U256x10, enc_pub_key: U256x2, previous_hash: felt252,
) -> felt252 {
    if is_zero(enc_pub_key.v0) {
        previous_hash
    } else {
        native_message_hash(message, enc_pub_key, previous_hash)
    }
}

fn native_felt_commitment(root: felt252, salt: u256) -> felt252 {
    native_hash_values_2(root, felt_from_u256(salt))
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

fn native_quinary_root_depth_1(leaf: felt252, path: U256x4, index: u256) -> felt252 {
    native_path_hash(leaf, path, index.low)
}

fn native_quinary_root_depth_2(
    leaf: felt252, path_0: U256x4, path_1: U256x4, index: u256,
) -> felt252 {
    let level_0_index = index.low % 5;
    let level_1_index = (index.low / 5) % 5;
    let level_0 = native_path_hash(leaf, path_0, level_0_index);
    native_path_hash(level_0, path_1, level_1_index)
}

fn native_zero_root_depth_1() -> felt252 {
    native_hash5_values(0, 0, 0, 0, 0)
}

fn native_process_message_roots(
    process_one: ProcessOneStateTransitionWitness,
) -> (felt252, felt252, felt252) {
    let valid = is_valid_bool(process_one.is_valid);
    let state_index = select_u256(valid, MAX_STATE_INDEX, process_one.cmd_state_index);
    let vote_option_index = select_u256(valid, zero_u256(), process_one.cmd_vote_option_index);
    assert_state_index(state_index);
    assert_vote_option_index(vote_option_index);

    let current_vote_root = native_quinary_root_depth_1(
        felt_from_u256(process_one.current_vote_weight),
        process_one.current_vote_weight_path,
        vote_option_index,
    );
    let current_leaf_vote_root = if is_zero(process_one.state_leaf.v3) {
        assert(current_vote_root == native_zero_root_depth_1(), 'N_VOTE_ZERO');
        0
    } else {
        current_vote_root
    };
    let current_state_leaf_hash = native_hash_state_leaf(
        process_one.state_leaf, current_leaf_vote_root,
    );
    let current_state_root = native_quinary_root_depth_2(
        current_state_leaf_hash,
        process_one.state_leaf_path_0,
        process_one.state_leaf_path_1,
        state_index,
    );
    let active_state_root = native_quinary_root_depth_2(
        felt_from_u256(process_one.active_state_leaf),
        process_one.active_state_leaf_path_0,
        process_one.active_state_leaf_path_1,
        state_index,
    );

    let updated_vote_weight = select_u256(
        valid, process_one.current_vote_weight, process_one.cmd_new_vote_weight,
    );
    let new_vote_option_root = native_quinary_root_depth_1(
        felt_from_u256(updated_vote_weight),
        process_one.current_vote_weight_path,
        vote_option_index,
    );
    let new_leaf_vote_root = if valid {
        new_vote_option_root
    } else {
        current_leaf_vote_root
    };
    let new_state_leaf_hash = native_hash10_values(
        felt_from_u256(select_u256(valid, process_one.state_leaf.v0, process_one.cmd_new_pub_key.v0)),
        felt_from_u256(select_u256(valid, process_one.state_leaf.v1, process_one.cmd_new_pub_key.v1)),
        felt_from_u256(select_u256(valid, process_one.state_leaf.v2, process_one.new_balance)),
        new_leaf_vote_root,
        felt_from_u256(select_u256(valid, process_one.state_leaf.v4, process_one.new_sl_nonce)),
        felt_from_u256(process_one.state_leaf.v5),
        felt_from_u256(process_one.state_leaf.v6),
        felt_from_u256(process_one.state_leaf.v7),
        felt_from_u256(process_one.state_leaf.v8),
        0,
    );
    let new_state_root = native_quinary_root_depth_2(
        new_state_leaf_hash,
        process_one.state_leaf_path_0,
        process_one.state_leaf_path_1,
        state_index,
    );
    (current_state_root, active_state_root, new_state_root)
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

fn assert_valid_message_index(message_index: felt252) {
    assert(
        message_index == 0
            || message_index == 1
            || message_index == 2,
        'BAD_MSG_INDEX',
    );
}

fn verify_native_process_message_coord_key(
    fields: NativeProcessMessageCoordKeyPublicFields, witness: NativeProcessMessageCoordKeyWitness,
) {
    assert(native_hash_u256x2(witness.coord_pub_key) == fields.coord_pub_key_hash, 'N_COORD_KEY');
    assert(
        native_coord_priv_key_hash(witness.coord_priv_key) == fields.coord_priv_key_hash,
        'N_COORD_PRIV',
    );
    assert(
        native_coord_key_binding_hash(fields.coord_pub_key_hash, fields.coord_priv_key_hash)
            == fields.coord_key_binding_hash,
        'N_COORD_BIND',
    );
}

fn verify_native_process_message_ecdh(
    fields: NativeProcessMessageEcdhPublicFields, witness: NativeProcessMessageEcdhWitness,
) {
    assert_valid_message_index(fields.message_index);
    assert(
        native_coord_priv_key_hash(witness.coord_priv_key) == fields.coord_priv_key_hash,
        'N_COORD_PRIV',
    );
    assert(native_hash_u256x2(witness.enc_pub_key) == fields.enc_pub_key_hash, 'N_ENC_KEY');
    assert(native_hash_u256x2(witness.shared_key) == fields.shared_key_hash, 'N_SHARED_KEY');
    assert(
        native_shared_key_binding_hash(
            fields.coord_priv_key_hash, fields.enc_pub_key_hash, fields.shared_key_hash,
        ) == fields.shared_key_binding_hash,
        'N_SHARED_BIND',
    );
}

fn verify_native_process_message_decrypt(
    fields: NativeProcessMessageDecryptPublicFields, witness: NativeProcessMessageDecryptWitness,
) {
    assert_valid_message_index(fields.message_index);
    assert(fields.decrypt_is_odd == 0 || fields.decrypt_is_odd == 1, 'BAD_DEC_BOOL');
    assert(
        native_coord_priv_key_hash(witness.coord_priv_key) == fields.coord_priv_key_hash,
        'N_COORD_PRIV',
    );
    assert(native_hash_u256x2(witness.c1) == fields.c1_hash, 'N_C1');
    assert(native_hash_u256x2(witness.c2) == fields.c2_hash, 'N_C2');
    assert(
        native_decrypt_binding_hash(
            fields.coord_priv_key_hash,
            fields.c1_hash,
            fields.c2_hash,
            fields.decrypt_is_odd,
        ) == fields.decrypt_binding_hash,
        'N_DECRYPT_BIND',
    );
}

fn verify_native_process_message_signature(
    fields: NativeProcessMessageSignaturePublicFields, witness: NativeProcessMessageSignatureWitness,
) {
    assert_valid_message_index(fields.message_index);
    assert(fields.is_signature_valid == 0 || fields.is_signature_valid == 1, 'BAD_SIG_BOOL');
    assert(native_hash_u256x2(witness.pub_key) == fields.pub_key_hash, 'N_PUB_KEY');
    assert(native_hash_u256x2(witness.r8) == fields.r8_hash, 'N_R8');
    assert(native_hash_u256x3(witness.packed_command) == fields.packed_command_hash, 'N_CMD');
    assert(native_hash_u256(witness.s) == fields.cmd_sig_s_hash, 'N_SIG_S');
    assert(
        native_command_auth_hash(
            fields.pub_key_hash,
            fields.r8_hash,
            fields.packed_command_hash,
            fields.cmd_sig_s_hash,
            witness.cmd_salt,
            fields.is_signature_valid,
        ) == fields.command_auth_hash,
        'N_CMD_AUTH',
    );
}

fn build_native_process_message_coord_key_public_output(
    fields: NativeProcessMessageCoordKeyPublicFields,
) -> NativeProcessMessageCoordKeyPublicOutput {
    NativeProcessMessageCoordKeyPublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_MESSAGE_COORD_KEY_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        vote_option_tree_depth: 1,
        message_batch_size: 3,
        coord_pub_key_hash: fields.coord_pub_key_hash,
        coord_priv_key_hash: fields.coord_priv_key_hash,
        coord_key_binding_hash: fields.coord_key_binding_hash,
    }
}

#[executable]
pub fn process_message_coord_key_native_main(
    fields: NativeProcessMessageCoordKeyPublicFields, witness: NativeProcessMessageCoordKeyWitness,
) -> NativeProcessMessageCoordKeyPublicOutput {
    verify_native_process_message_coord_key(fields, witness);
    build_native_process_message_coord_key_public_output(fields)
}

fn build_native_process_message_ecdh_public_output(
    fields: NativeProcessMessageEcdhPublicFields,
) -> NativeProcessMessageEcdhPublicOutput {
    NativeProcessMessageEcdhPublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_MESSAGE_ECDH_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        vote_option_tree_depth: 1,
        message_batch_size: 3,
        message_index: fields.message_index,
        coord_priv_key_hash: fields.coord_priv_key_hash,
        enc_pub_key_hash: fields.enc_pub_key_hash,
        shared_key_hash: fields.shared_key_hash,
        shared_key_binding_hash: fields.shared_key_binding_hash,
    }
}

#[executable]
pub fn process_message_ecdh_native_main(
    fields: NativeProcessMessageEcdhPublicFields, witness: NativeProcessMessageEcdhWitness,
) -> NativeProcessMessageEcdhPublicOutput {
    verify_native_process_message_ecdh(fields, witness);
    build_native_process_message_ecdh_public_output(fields)
}

fn build_native_process_message_decrypt_public_output(
    fields: NativeProcessMessageDecryptPublicFields,
) -> NativeProcessMessageDecryptPublicOutput {
    NativeProcessMessageDecryptPublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_MESSAGE_DECRYPT_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        vote_option_tree_depth: 1,
        message_batch_size: 3,
        message_index: fields.message_index,
        coord_priv_key_hash: fields.coord_priv_key_hash,
        c1_hash: fields.c1_hash,
        c2_hash: fields.c2_hash,
        decrypt_is_odd: fields.decrypt_is_odd,
        decrypt_binding_hash: fields.decrypt_binding_hash,
    }
}

#[executable]
pub fn process_message_decrypt_native_main(
    fields: NativeProcessMessageDecryptPublicFields, witness: NativeProcessMessageDecryptWitness,
) -> NativeProcessMessageDecryptPublicOutput {
    verify_native_process_message_decrypt(fields, witness);
    build_native_process_message_decrypt_public_output(fields)
}

fn build_native_process_message_signature_public_output(
    fields: NativeProcessMessageSignaturePublicFields,
) -> NativeProcessMessageSignaturePublicOutput {
    NativeProcessMessageSignaturePublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_MESSAGE_SIGNATURE_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        vote_option_tree_depth: 1,
        message_batch_size: 3,
        message_index: fields.message_index,
        pub_key_hash: fields.pub_key_hash,
        r8_hash: fields.r8_hash,
        packed_command_hash: fields.packed_command_hash,
        cmd_sig_s_hash: fields.cmd_sig_s_hash,
        command_auth_hash: fields.command_auth_hash,
        is_signature_valid: fields.is_signature_valid,
    }
}

#[executable]
pub fn process_message_signature_native_main(
    fields: NativeProcessMessageSignaturePublicFields, witness: NativeProcessMessageSignatureWitness,
) -> NativeProcessMessageSignaturePublicOutput {
    verify_native_process_message_signature(fields, witness);
    build_native_process_message_signature_public_output(fields)
}

fn verify_native_process_message_step_core(
    fields: NativeProcessMessageStepCorePublicFields, witness: NativeProcessMessageStepCoreWitness,
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
    assert(felt_from_u256(packed_vals) == fields.packed_vals_hash, 'N_PACKED');
    assert(
        native_coord_priv_key_hash(witness.coord_priv_key) == fields.coord_priv_key_hash,
        'N_COORD_PRIV',
    );
    assert(native_hash_u256x2(witness.enc_pub_key) == fields.enc_pub_key_hash, 'N_ENC_KEY');
    assert(native_hash_u256x2(witness.process_one.shared_key) == fields.shared_key_hash, 'N_SHARED');
    assert(
        native_shared_key_binding_hash(
            fields.coord_priv_key_hash, fields.enc_pub_key_hash, fields.shared_key_hash,
        ) == fields.shared_key_binding_hash,
        'N_SHARED_BIND',
    );
    assert(fields.state_decrypt_is_odd == 0 || fields.state_decrypt_is_odd == 1, 'BAD_DEC_BOOL');
    assert(
        native_hash_u256x2(
            U256x2 { v0: witness.process_one.state_leaf.v5, v1: witness.process_one.state_leaf.v6 },
        ) == fields.state_ciphertext_c1_hash,
        'N_STATE_C1',
    );
    assert(
        native_hash_u256x2(
            U256x2 { v0: witness.process_one.state_leaf.v7, v1: witness.process_one.state_leaf.v8 },
        ) == fields.state_ciphertext_c2_hash,
        'N_STATE_C2',
    );
    assert(
        native_decrypt_binding_hash(
            fields.coord_priv_key_hash,
            fields.state_ciphertext_c1_hash,
            fields.state_ciphertext_c2_hash,
            fields.state_decrypt_is_odd,
        ) == fields.state_decrypt_binding_hash,
        'N_STATE_DEC_BIND',
    );
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
    assert(
        native_command_auth_hash(
            fields.signature_pub_key_hash,
            fields.signature_r8_hash,
            fields.packed_command_hash,
            fields.cmd_sig_s_hash,
            witness.process_one.cmd_salt,
            fields.is_signature_valid,
        ) == fields.command_auth_hash,
        'N_CMD_AUTH',
    );
    assert(
        native_command_plaintext_binding_hash(
            fields.next_message_hash,
            fields.shared_key_hash,
            fields.packed_command_hash,
            fields.signature_pub_key_hash,
            fields.signature_r8_hash,
            fields.cmd_sig_s_hash,
            fields.command_auth_hash,
        ) == fields.command_plaintext_binding_hash,
        'N_CMD_PLAIN',
    );
    assert(witness.process_one.is_signature_valid.high == 0, 'SIG_BOOL_HIGH');
    assert(
        felt_from_u128(witness.process_one.is_signature_valid.low) == fields.is_signature_valid,
        'SIG_VALID',
    );

    let next_message_hash = native_message_hash_or_empty(
        witness.msg, witness.enc_pub_key, fields.previous_message_hash,
    );
    assert(next_message_hash == fields.next_message_hash, 'N_NEXT_MSG');

    let (native_current_state_root, native_active_state_root, native_new_state_root) =
        native_process_message_roots(witness.process_one);
    assert(native_current_state_root == fields.current_state_root_hash, 'N_CUR_ROOT');
    assert(native_active_state_root == fields.active_state_root_hash, 'N_ACTIVE');
    assert_u256_eq(witness.process_one.is_quadratic_cost, witness.is_quadratic_cost);
    assert_u256_eq(witness.process_one.num_signups, witness.num_signups);
    assert_u256_eq(witness.process_one.max_vote_options, witness.max_vote_options);
    assert(witness.process_one.expected_poll_id.high == 0, 'POLL_HIGH');
    assert(felt_from_u128(witness.process_one.expected_poll_id.low) == fields.expected_poll_id, 'POLL_ID');
    assert_message_matches(witness.msg, witness.process_one.msg);

    if is_zero(witness.enc_pub_key.v0) {
        assert_u256_eq(witness.process_one.is_valid, zero_u256());
    } else {
        assert(witness.process_one.is_decryption_active.high == 0, 'DEC_BOOL_HIGH');
        assert(
            felt_from_u128(witness.process_one.is_decryption_active.low)
                == 1 - fields.state_decrypt_is_odd,
            'DEC_ACTIVE',
        );
        let _validation = validate_process_one_command(witness.process_one);
    };
    assert(native_new_state_root == fields.new_state_root_hash, 'N_NEW_ROOT');

    if fields.message_index == 2 {
        let current_state_commitment = native_felt_commitment(
            native_current_state_root, witness.current_state_salt,
        );
        assert(current_state_commitment == fields.current_state_commitment_hash, 'N_CUR_COMMIT');
    }
    if fields.message_index == 0 {
        let new_state_commitment = native_felt_commitment(native_new_state_root, witness.new_state_salt);
        assert(new_state_commitment == fields.new_state_commitment_hash, 'N_NEW_COMMIT');
    }
}

fn build_native_process_message_step_core_public_output(
    fields: NativeProcessMessageStepCorePublicFields,
) -> NativeProcessMessageStepCorePublicOutput {
    NativeProcessMessageStepCorePublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_MESSAGE_STEP_CORE_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        vote_option_tree_depth: 1,
        message_batch_size: 3,
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
        shared_key_binding_hash: fields.shared_key_binding_hash,
        state_ciphertext_c1_hash: fields.state_ciphertext_c1_hash,
        state_ciphertext_c2_hash: fields.state_ciphertext_c2_hash,
        state_decrypt_is_odd: fields.state_decrypt_is_odd,
        state_decrypt_binding_hash: fields.state_decrypt_binding_hash,
        signature_pub_key_hash: fields.signature_pub_key_hash,
        signature_r8_hash: fields.signature_r8_hash,
        packed_command_hash: fields.packed_command_hash,
        cmd_sig_s_hash: fields.cmd_sig_s_hash,
        command_auth_hash: fields.command_auth_hash,
        command_plaintext_binding_hash: fields.command_plaintext_binding_hash,
        is_signature_valid: fields.is_signature_valid,
    }
}

#[executable]
pub fn process_message_step_core_native_main(
    fields: NativeProcessMessageStepCorePublicFields, witness: NativeProcessMessageStepCoreWitness,
) -> NativeProcessMessageStepCorePublicOutput {
    verify_native_process_message_step_core(fields, witness);
    build_native_process_message_step_core_public_output(fields)
}
