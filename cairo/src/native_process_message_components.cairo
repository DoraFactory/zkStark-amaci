use core::hash::HashStateTrait;
use core::poseidon::PoseidonTrait;
use crate::native_stark_crypto::{
    STARK_NATIVE_COMMAND_SIGNATURE_DOMAIN, assert_stark_point_equals,
    stark_elgamal_decrypt_point_is_odd, stark_generator_mul, stark_scalar_mul,
    stark_verify_command_signature,
};

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
const NATIVE_COORD_PRIV_KEY_HASH_DOMAIN: felt252 = 0x414d4143495f434f4f52445f50524956;
const NATIVE_COORD_KEY_BINDING_DOMAIN: felt252 =
    0x414d4143495f504d53475f434f4f52445f42494e44;
const NATIVE_COMMAND_AUTH_DOMAIN: felt252 = 0x414d4143495f504d53475f41555448;
const NATIVE_DECRYPT_BINDING_DOMAIN: felt252 =
    0x414d4143495f504d53475f4445435f42494e44;
const NATIVE_SHARED_KEY_DOMAIN: felt252 = 0x414d4143495f504d53475f534841524544;
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
    pub decrypted_point: U256x2,
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
        native_coord_key_binding_hash(fields.coord_pub_key_hash, fields.coord_priv_key_hash)
            == fields.coord_key_binding_hash,
        'N_COORD_BIND',
    );
}

fn verify_native_process_message_ecdh(
    fields: NativeProcessMessageEcdhPublicFields, witness: NativeProcessMessageEcdhWitness,
) {
    assert_valid_message_index(fields.message_index);
    let (shared_key_x, shared_key_y) = stark_scalar_mul(
        witness.enc_pub_key.v0, witness.enc_pub_key.v1, witness.coord_priv_key,
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
    let decrypt_is_odd = stark_elgamal_decrypt_point_is_odd(
        witness.coord_priv_key, witness.c1.v0, witness.c1.v1, witness.c2.v0, witness.c2.v1,
        witness.decrypted_point.v0, witness.decrypted_point.v1,
    );
    assert(decrypt_is_odd == fields.decrypt_is_odd, 'N_DEC_ODD');
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
    let signature_valid = stark_verify_command_signature(
        STARK_NATIVE_COMMAND_SIGNATURE_DOMAIN,
        witness.pub_key.v0,
        witness.pub_key.v1,
        witness.r8.v0,
        witness.r8.v1,
        witness.s,
        witness.packed_command.v0,
        witness.packed_command.v1,
        witness.packed_command.v2,
        witness.cmd_salt,
    );
    assert(signature_valid == fields.is_signature_valid, 'N_SIG_VALID');
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
