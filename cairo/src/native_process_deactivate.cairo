use core::poseidon::poseidon_hash_span;

pub const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b;
pub const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
pub const PROCESS_DEACTIVATE_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f50524f434553535f44454143545f4e4154495645;
pub const STARKNET_POSEIDON_HASH_SCHEME: felt252 = 0x535441524b4e45545f504f534549444f4e;
pub const PROCESS_DEACTIVATE_NATIVE_INPUT_HASH_DOMAIN: felt252 =
    0x414d4143495f44454143545f4e41544956455f494e505554;

#[derive(Copy, Drop, Serde)]
pub struct Felt2 {
    pub v0: felt252,
    pub v1: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct Felt10 {
    pub v0: felt252,
    pub v1: felt252,
    pub v2: felt252,
    pub v3: felt252,
    pub v4: felt252,
    pub v5: felt252,
    pub v6: felt252,
    pub v7: felt252,
    pub v8: felt252,
    pub v9: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivateNativePublicFields {
    pub new_deactivate_root: felt252,
    pub coord_pub_key_hash: felt252,
    pub batch_start_hash: felt252,
    pub batch_end_hash: felt252,
    pub current_deactivate_commitment: felt252,
    pub new_deactivate_commitment: felt252,
    pub current_state_root: felt252,
    pub expected_poll_id: felt252,
    pub input_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivateNativeBoundaryWitness {
    pub coord_pub_key: Felt2,
    pub current_active_state_root: felt252,
    pub current_deactivate_root: felt252,
    pub new_active_state_root: felt252,
    pub msg_0: Felt10,
    pub msg_1: Felt10,
    pub msg_2: Felt10,
    pub msg_3: Felt10,
    pub msg_4: Felt10,
    pub enc_pub_key_0: Felt2,
    pub enc_pub_key_1: Felt2,
    pub enc_pub_key_2: Felt2,
    pub enc_pub_key_3: Felt2,
    pub enc_pub_key_4: Felt2,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivateNativePublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub hash_scheme: felt252,
    pub state_tree_depth: felt252,
    pub deactivate_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub new_deactivate_root: felt252,
    pub coord_pub_key_hash: felt252,
    pub batch_start_hash: felt252,
    pub batch_end_hash: felt252,
    pub current_deactivate_commitment: felt252,
    pub new_deactivate_commitment: felt252,
    pub current_state_root: felt252,
    pub expected_poll_id: felt252,
    pub input_hash: felt252,
}

fn hash2(left: felt252, right: felt252) -> felt252 {
    poseidon_hash_span([left, right].span())
}

fn message_hash(message: Felt10, enc_pub_key: Felt2, previous_hash: felt252) -> felt252 {
    poseidon_hash_span(
        [
            message.v0,
            message.v1,
            message.v2,
            message.v3,
            message.v4,
            message.v5,
            message.v6,
            message.v7,
            message.v8,
            message.v9,
            enc_pub_key.v0,
            enc_pub_key.v1,
            previous_hash,
        ]
            .span(),
    )
}

fn message_hash_or_empty(
    message: Felt10, enc_pub_key: Felt2, previous_hash: felt252,
) -> felt252 {
    if message.v0 == 0 {
        previous_hash
    } else {
        message_hash(message, enc_pub_key, previous_hash)
    }
}

fn input_hash(fields: ProcessDeactivateNativePublicFields) -> felt252 {
    poseidon_hash_span(
        [
            PROCESS_DEACTIVATE_NATIVE_INPUT_HASH_DOMAIN,
            fields.new_deactivate_root,
            fields.coord_pub_key_hash,
            fields.batch_start_hash,
            fields.batch_end_hash,
            fields.current_deactivate_commitment,
            fields.new_deactivate_commitment,
            fields.current_state_root,
            fields.expected_poll_id,
        ]
            .span(),
    )
}

fn verify_process_deactivate_native_boundary(
    fields: ProcessDeactivateNativePublicFields, witness: ProcessDeactivateNativeBoundaryWitness,
) {
    let coord_pub_key_hash = hash2(witness.coord_pub_key.v0, witness.coord_pub_key.v1);
    assert(coord_pub_key_hash == fields.coord_pub_key_hash, 'COORD_KEY_HASH');

    let current_deactivate_commitment = hash2(
        witness.current_active_state_root, witness.current_deactivate_root,
    );
    assert(
        current_deactivate_commitment == fields.current_deactivate_commitment, 'CURRENT_DEACT',
    );

    let new_deactivate_commitment = hash2(
        witness.new_active_state_root, fields.new_deactivate_root,
    );
    assert(new_deactivate_commitment == fields.new_deactivate_commitment, 'NEW_DEACT');
    assert(input_hash(fields) == fields.input_hash, 'INPUT_HASH');

    let hash_1 = message_hash_or_empty(
        witness.msg_0, witness.enc_pub_key_0, fields.batch_start_hash,
    );
    let hash_2 = message_hash_or_empty(witness.msg_1, witness.enc_pub_key_1, hash_1);
    let hash_3 = message_hash_or_empty(witness.msg_2, witness.enc_pub_key_2, hash_2);
    let hash_4 = message_hash_or_empty(witness.msg_3, witness.enc_pub_key_3, hash_3);
    let hash_5 = message_hash_or_empty(witness.msg_4, witness.enc_pub_key_4, hash_4);
    assert(hash_5 == fields.batch_end_hash, 'BATCH_END_HASH');
}

fn build_process_deactivate_native_public_output(
    fields: ProcessDeactivateNativePublicFields,
) -> ProcessDeactivateNativePublicOutput {
    ProcessDeactivateNativePublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_DEACTIVATE_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        deactivate_tree_depth: 4,
        message_batch_size: 5,
        new_deactivate_root: fields.new_deactivate_root,
        coord_pub_key_hash: fields.coord_pub_key_hash,
        batch_start_hash: fields.batch_start_hash,
        batch_end_hash: fields.batch_end_hash,
        current_deactivate_commitment: fields.current_deactivate_commitment,
        new_deactivate_commitment: fields.new_deactivate_commitment,
        current_state_root: fields.current_state_root,
        expected_poll_id: fields.expected_poll_id,
        input_hash: fields.input_hash,
    }
}

#[executable]
pub fn process_deactivate_native_boundary_main(
    fields: ProcessDeactivateNativePublicFields, witness: ProcessDeactivateNativeBoundaryWitness,
) -> ProcessDeactivateNativePublicOutput {
    verify_process_deactivate_native_boundary(fields, witness);
    build_process_deactivate_native_public_output(fields)
}
