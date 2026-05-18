use core::hash::HashStateTrait;
use core::poseidon::PoseidonTrait;

const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b;
const DEACTIVATE_ECDH_KIND_COMMAND: felt252 = 0;
const DEACTIVATE_ECDH_KIND_LEAF: felt252 = 1;
const DEACTIVATE_DECRYPT_KIND_CURRENT: felt252 = 0;
const DEACTIVATE_DECRYPT_KIND_NEW: felt252 = 1;
const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
const STARKNET_POSEIDON_HASH_SCHEME: felt252 = 0x535441524b4e45545f504f534549444f4e;
const PROCESS_DEACTIVATE_COORD_KEY_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f44454143545f434f4f52445f4e4154495645;
const PROCESS_DEACTIVATE_ECDH_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f44454143545f454344485f4e4154495645;
const PROCESS_DEACTIVATE_SIGNATURE_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f44454143545f5349475f4e4154495645;
const PROCESS_DEACTIVATE_DECRYPT_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f44454143545f4445435f4e4154495645;
const PROCESS_DEACTIVATE_STEP_CORE_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f44454143545f535445505f434f52455f4e4154495645;
const NATIVE_COORD_PRIV_KEY_HASH_DOMAIN: felt252 = 0x414d4143495f434f4f52445f50524956;
const NATIVE_DEACTIVATE_COMMAND_AUTH_DOMAIN: felt252 = 0x414d4143495f44454143545f41555448;
const NATIVE_DEACTIVATE_COMMAND_PLAINTEXT_DOMAIN: felt252 =
    0x414d4143495f44454143545f434d445f504c41494e;
const NATIVE_DEACTIVATE_COORD_KEY_BINDING_DOMAIN: felt252 =
    0x414d4143495f44454143545f434f4f52445f42494e44;
const NATIVE_DEACTIVATE_SHARED_KEY_DOMAIN: felt252 =
    0x414d4143495f44454143545f534841524544;
const NATIVE_DEACTIVATE_DECRYPT_BINDING_DOMAIN: felt252 =
    0x414d4143495f44454143545f4445435f42494e44;
const FELT_TWO_POW_128: felt252 = 0x100000000000000000000000000000000;
const U128_TWO_POW_32: u128 = 0x100000000;
const U128_TWO_POW_64: u128 = 0x10000000000000000;
const U128_TWO_POW_96: u128 = 0x1000000000000000000000000;
const STATE_TREE_LEAVES: u128 = 25;
const STATE_TREE_MAX_INDEX: u256 = 24;
const DEACTIVATE_TREE_LEAVES: u128 = 625;

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
pub struct NativeProcessDeactivateCoordKeyWitness {
    pub coord_priv_key: u256,
    pub coord_pub_key: U256x2,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessDeactivateEcdhWitness {
    pub coord_priv_key: u256,
    pub base: U256x2,
    pub shared_key: U256x2,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeProcessDeactivateSignatureWitness {
    pub pub_key: U256x2,
    pub r8: U256x2,
    pub s: u256,
    pub packed_cmd: U256x3,
    pub cmd_salt: u256,
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

#[derive(Drop, Serde)]
pub struct NativeProcessDeactivateStepCoreWitness {
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
    pub deactivate_shared_key: U256x2,
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

fn native_hash_values_6(
    v0: felt252, v1: felt252, v2: felt252, v3: felt252, v4: felt252, v5: felt252,
) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(v0);
    state = state.update(v1);
    state = state.update(v2);
    state = state.update(v3);
    state = state.update(v4);
    state = state.update(v5);
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

fn native_deactivate_coord_key_binding_hash(
    coord_pub_key_hash: felt252, coord_priv_key_hash: felt252,
) -> felt252 {
    native_hash_values_3(
        NATIVE_DEACTIVATE_COORD_KEY_BINDING_DOMAIN, coord_pub_key_hash, coord_priv_key_hash,
    )
}

fn native_deactivate_shared_key_binding_hash(
    ecdh_kind: felt252,
    coord_priv_key_hash: felt252,
    base_hash: felt252,
    shared_key_hash: felt252,
) -> felt252 {
    native_hash_values_5(
        NATIVE_DEACTIVATE_SHARED_KEY_DOMAIN,
        ecdh_kind,
        coord_priv_key_hash,
        base_hash,
        shared_key_hash,
    )
}

fn native_deactivate_decrypt_binding_hash(
    decrypt_kind: felt252,
    coord_priv_key_hash: felt252,
    c1_hash: felt252,
    c2_hash: felt252,
    decrypt_is_odd: felt252,
) -> felt252 {
    native_hash_values_6(
        NATIVE_DEACTIVATE_DECRYPT_BINDING_DOMAIN,
        decrypt_kind,
        coord_priv_key_hash,
        c1_hash,
        c2_hash,
        decrypt_is_odd,
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
    native_hash_values_7(
        NATIVE_DEACTIVATE_COMMAND_AUTH_DOMAIN,
        pub_key_hash,
        r8_hash,
        packed_cmd_hash,
        cmd_sig_s_hash,
        felt_from_u256(cmd_salt),
        signature_valid,
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

fn small_felt_to_u256(value: felt252) -> u256 {
    let low: u128 = value.try_into().unwrap();
    u256 { low, high: 0 }
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
    native_hash_values_8(
        NATIVE_DEACTIVATE_COMMAND_PLAINTEXT_DOMAIN,
        next_message_hash,
        shared_key_hash,
        packed_cmd_hash,
        signature_pub_key_hash,
        signature_r8_hash,
        cmd_sig_s_hash,
        command_auth_hash,
    )
}

fn native_hash5_values(v0: felt252, v1: felt252, v2: felt252, v3: felt252, v4: felt252) -> felt252 {
    native_hash_values_5(v0, v1, v2, v3, v4)
}

fn native_hash10_u256(value: U256x10) -> felt252 {
    native_hash_values_2(
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
    )
}

fn native_deactivate_message_hash(
    message: U256x10, enc_pub_key: U256x2, previous_hash: felt252,
) -> felt252 {
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
    native_hash_values_2(left, right)
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

fn build_native_process_deactivate_coord_key_public_output(
    fields: NativeProcessDeactivateCoordKeyPublicFields,
) -> NativeProcessDeactivateCoordKeyPublicOutput {
    NativeProcessDeactivateCoordKeyPublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
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

fn build_native_process_deactivate_ecdh_public_output(
    fields: NativeProcessDeactivateEcdhPublicFields,
) -> NativeProcessDeactivateEcdhPublicOutput {
    NativeProcessDeactivateEcdhPublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
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

fn build_native_process_deactivate_signature_public_output(
    fields: NativeProcessDeactivateSignaturePublicFields,
) -> NativeProcessDeactivateSignaturePublicOutput {
    NativeProcessDeactivateSignaturePublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
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

fn build_native_process_deactivate_decrypt_public_output(
    fields: NativeProcessDeactivateDecryptPublicFields,
) -> NativeProcessDeactivateDecryptPublicOutput {
    NativeProcessDeactivateDecryptPublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
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

fn verify_native_process_deactivate_step_core(
    fields: NativeProcessDeactivateStepCorePublicFields, witness: NativeProcessDeactivateStepCoreWitness,
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
    assert_state_index(state_index);
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

fn build_native_process_deactivate_step_core_public_output(
    fields: NativeProcessDeactivateStepCorePublicFields,
) -> NativeProcessDeactivateStepCorePublicOutput {
    NativeProcessDeactivateStepCorePublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
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
pub fn process_deactivate_step_core_native_main(
    fields: NativeProcessDeactivateStepCorePublicFields, witness: NativeProcessDeactivateStepCoreWitness,
) -> NativeProcessDeactivateStepCorePublicOutput {
    verify_native_process_deactivate_step_core(fields, witness);
    build_native_process_deactivate_step_core_public_output(fields)
}
