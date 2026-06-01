use core::hash::HashStateTrait;
use core::poseidon::PoseidonTrait;
use crate::native_stark_crypto::{
    STARK_NATIVE_DEACTIVATE_SIGNATURE_DOMAIN, assert_stark_point_equals,
    stark_elgamal_decrypt_point_is_odd, stark_generator_mul, stark_scalar_mul,
    stark_verify_command_signature,
};

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
const NATIVE_COORD_PRIV_KEY_HASH_DOMAIN: felt252 = 0x414d4143495f434f4f52445f50524956;
const NATIVE_DEACTIVATE_COMMAND_AUTH_DOMAIN: felt252 = 0x414d4143495f44454143545f41555448;
const NATIVE_DEACTIVATE_COORD_KEY_BINDING_DOMAIN: felt252 =
    0x414d4143495f44454143545f434f4f52445f42494e44;
const NATIVE_DEACTIVATE_SHARED_KEY_DOMAIN: felt252 = 0x414d4143495f44454143545f534841524544;
const NATIVE_DEACTIVATE_DECRYPT_BINDING_DOMAIN: felt252 =
    0x414d4143495f44454143545f4445435f42494e44;
const PROCESS_DEACTIVATE_MESSAGE_BATCH_SIZE: felt252 = 3;
const FELT_TWO_POW_128: felt252 = 0x100000000000000000000000000000000;

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
    pub decrypted_point: U256x2,
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
    v0: felt252, v1: felt252, v2: felt252, v3: felt252, v4: felt252, v5: felt252, v6: felt252,
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
    ecdh_kind: felt252, coord_priv_key_hash: felt252, base_hash: felt252, shared_key_hash: felt252,
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

fn assert_valid_deactivate_message_index(message_index: felt252) {
    assert(message_index == 0 || message_index == 1 || message_index == 2, 'BAD_DEACT_MSG_INDEX');
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
    fields: NativeProcessDeactivateCoordKeyPublicFields,
    witness: NativeProcessDeactivateCoordKeyWitness,
) {
    let (coord_pub_key_x, coord_pub_key_y) = stark_generator_mul(witness.coord_priv_key);
    assert_stark_point_equals(
        coord_pub_key_x,
        coord_pub_key_y,
        witness.coord_pub_key.v0,
        witness.coord_pub_key.v1,
        'N_COORD_X',
        'N_COORD_Y',
    );
    assert(native_hash_u256x2(witness.coord_pub_key) == fields.coord_pub_key_hash, 'N_COORD_KEY');
    assert(
        native_coord_priv_key_hash(witness.coord_priv_key) == fields.coord_priv_key_hash,
        'N_COORD_PRIV',
    );
    assert(
        native_deactivate_coord_key_binding_hash(
            fields.coord_pub_key_hash, fields.coord_priv_key_hash,
        ) == fields
            .coord_key_binding_hash,
        'N_COORD_BIND',
    );
}

fn verify_native_process_deactivate_ecdh(
    fields: NativeProcessDeactivateEcdhPublicFields, witness: NativeProcessDeactivateEcdhWitness,
) {
    assert_valid_deactivate_message_index(fields.message_index);
    assert_valid_deactivate_ecdh_kind(fields.ecdh_kind);
    let (shared_key_x, shared_key_y) = stark_scalar_mul(
        witness.base.v0, witness.base.v1, witness.coord_priv_key,
    );
    assert_stark_point_equals(
        shared_key_x,
        shared_key_y,
        witness.shared_key.v0,
        witness.shared_key.v1,
        'N_SHARED_X',
        'N_SHARED_Y',
    );
    assert(
        native_coord_priv_key_hash(witness.coord_priv_key) == fields.coord_priv_key_hash,
        'N_COORD_PRIV',
    );
    assert(native_hash_u256x2(witness.base) == fields.base_hash, 'N_BASE');
    assert(native_hash_u256x2(witness.shared_key) == fields.shared_key_hash, 'N_SHARED_KEY');
    assert(
        native_deactivate_shared_key_binding_hash(
            fields.ecdh_kind, fields.coord_priv_key_hash, fields.base_hash, fields.shared_key_hash,
        ) == fields
            .shared_key_binding_hash,
        'N_SHARED_BIND',
    );
}

fn verify_native_process_deactivate_signature(
    fields: NativeProcessDeactivateSignaturePublicFields,
    witness: NativeProcessDeactivateSignatureWitness,
) {
    assert_valid_deactivate_message_index(fields.message_index);
    assert_bool_felt(fields.signature_valid);
    let signature_valid = stark_verify_command_signature(
        STARK_NATIVE_DEACTIVATE_SIGNATURE_DOMAIN,
        witness.pub_key.v0,
        witness.pub_key.v1,
        witness.r8.v0,
        witness.r8.v1,
        witness.s,
        witness.packed_cmd.v0,
        witness.packed_cmd.v1,
        witness.packed_cmd.v2,
        witness.cmd_salt,
    );
    assert(signature_valid == fields.signature_valid, 'N_SIG_VALID');
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
        ) == fields
            .command_auth_hash,
        'N_CMD_AUTH',
    );
}

fn verify_native_process_deactivate_decrypt(
    fields: NativeProcessDeactivateDecryptPublicFields,
    witness: NativeProcessDeactivateDecryptWitness,
) {
    assert_valid_deactivate_message_index(fields.message_index);
    assert_valid_deactivate_decrypt_kind(fields.decrypt_kind);
    assert_bool_felt(fields.decrypt_is_odd);
    let decrypt_is_odd = stark_elgamal_decrypt_point_is_odd(
        witness.coord_priv_key,
        witness.c1.v0,
        witness.c1.v1,
        witness.c2.v0,
        witness.c2.v1,
        witness.decrypted_point.v0,
        witness.decrypted_point.v1,
    );
    assert(decrypt_is_odd == fields.decrypt_is_odd, 'N_DEC_ODD');
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
        ) == fields
            .decrypt_binding_hash,
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
        message_batch_size: PROCESS_DEACTIVATE_MESSAGE_BATCH_SIZE,
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
        message_batch_size: PROCESS_DEACTIVATE_MESSAGE_BATCH_SIZE,
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
        message_batch_size: PROCESS_DEACTIVATE_MESSAGE_BATCH_SIZE,
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
    fields: NativeProcessDeactivateSignaturePublicFields,
    witness: NativeProcessDeactivateSignatureWitness,
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
        message_batch_size: PROCESS_DEACTIVATE_MESSAGE_BATCH_SIZE,
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
    fields: NativeProcessDeactivateDecryptPublicFields,
    witness: NativeProcessDeactivateDecryptWitness,
) -> NativeProcessDeactivateDecryptPublicOutput {
    verify_native_process_deactivate_decrypt(fields, witness);
    build_native_process_deactivate_decrypt_public_output(fields)
}
