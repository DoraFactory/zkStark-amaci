use core::poseidon::poseidon_hash_span;

pub const TREE_ARITY: u32 = 5;
pub const MAX_SIGNUPS: u32 = 25;
pub const MAX_VOTE_OPTIONS: u32 = 5;
pub const TWO_POW_32: felt252 = 0x100000000;
pub const TWO_POW_64: felt252 = 0x10000000000000000;
pub const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b;
pub const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
pub const PROCESS_MESSAGES_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f50524f434553535f4d53475f4e4154495645;
pub const STARKNET_POSEIDON_HASH_SCHEME: felt252 = 0x535441524b4e45545f504f534549444f4e;
pub const PROCESS_MESSAGES_NATIVE_INPUT_HASH_DOMAIN: felt252 =
    0x414d4143495f50524f434553535f4d53475f4e41544956455f494e505554;

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
pub struct ProcessMessagesNativePublicFields {
    pub packed_vals: felt252,
    pub coord_pub_key_hash: felt252,
    pub batch_start_hash: felt252,
    pub batch_end_hash: felt252,
    pub current_state_commitment: felt252,
    pub new_state_commitment: felt252,
    pub deactivate_commitment: felt252,
    pub expected_poll_id: felt252,
    pub input_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessMessagesNativeBoundaryWitness {
    pub is_quadratic_cost: u32,
    pub num_signups: u32,
    pub max_vote_options: u32,
    pub coord_pub_key: Felt2,
    pub current_state_root: felt252,
    pub current_state_salt: felt252,
    pub new_state_root: felt252,
    pub new_state_salt: felt252,
    pub active_state_root: felt252,
    pub deactivate_root: felt252,
    pub expected_poll_id: felt252,
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
pub struct ProcessMessagesNativePublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub hash_scheme: felt252,
    pub state_tree_depth: felt252,
    pub vote_option_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub packed_vals: felt252,
    pub coord_pub_key_hash: felt252,
    pub batch_start_hash: felt252,
    pub batch_end_hash: felt252,
    pub current_state_commitment: felt252,
    pub new_state_commitment: felt252,
    pub deactivate_commitment: felt252,
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
    if enc_pub_key.v0 == 0 {
        previous_hash
    } else {
        message_hash(message, enc_pub_key, previous_hash)
    }
}

fn input_hash(fields: ProcessMessagesNativePublicFields) -> felt252 {
    poseidon_hash_span(
        [
            PROCESS_MESSAGES_NATIVE_INPUT_HASH_DOMAIN,
            fields.packed_vals,
            fields.coord_pub_key_hash,
            fields.batch_start_hash,
            fields.batch_end_hash,
            fields.current_state_commitment,
            fields.new_state_commitment,
            fields.deactivate_commitment,
            fields.expected_poll_id,
        ]
            .span(),
    )
}

fn assert_packed_vals(
    fields: ProcessMessagesNativePublicFields, witness: ProcessMessagesNativeBoundaryWitness,
) {
    assert(witness.is_quadratic_cost == 0 || witness.is_quadratic_cost == 1, 'BAD_QUADRATIC');
    assert(witness.max_vote_options <= MAX_VOTE_OPTIONS, 'BAD_MAX_VO');
    assert(witness.num_signups <= MAX_SIGNUPS, 'BAD_NUM_SIGNUPS');

    let is_quadratic_cost: felt252 = witness.is_quadratic_cost.into();
    let num_signups: felt252 = witness.num_signups.into();
    let max_vote_options: felt252 = witness.max_vote_options.into();
    let packed_vals = is_quadratic_cost * TWO_POW_64 + num_signups * TWO_POW_32
        + max_vote_options;
    assert(packed_vals == fields.packed_vals, 'PACKED_VALS');
}

fn verify_process_messages_native_boundary(
    fields: ProcessMessagesNativePublicFields, witness: ProcessMessagesNativeBoundaryWitness,
) {
    assert_packed_vals(fields, witness);

    let coord_pub_key_hash = hash2(witness.coord_pub_key.v0, witness.coord_pub_key.v1);
    assert(coord_pub_key_hash == fields.coord_pub_key_hash, 'COORD_KEY_HASH');

    let current_state_commitment = hash2(
        witness.current_state_root, witness.current_state_salt,
    );
    assert(current_state_commitment == fields.current_state_commitment, 'CURRENT_STATE');

    let new_state_commitment = hash2(witness.new_state_root, witness.new_state_salt);
    assert(new_state_commitment == fields.new_state_commitment, 'NEW_STATE');

    let deactivate_commitment = hash2(witness.active_state_root, witness.deactivate_root);
    assert(deactivate_commitment == fields.deactivate_commitment, 'DEACTIVATE');
    assert(witness.expected_poll_id == fields.expected_poll_id, 'POLL_ID');
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

fn build_process_messages_native_public_output(
    fields: ProcessMessagesNativePublicFields,
) -> ProcessMessagesNativePublicOutput {
    ProcessMessagesNativePublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_MESSAGES_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        vote_option_tree_depth: 1,
        message_batch_size: TREE_ARITY.into(),
        packed_vals: fields.packed_vals,
        coord_pub_key_hash: fields.coord_pub_key_hash,
        batch_start_hash: fields.batch_start_hash,
        batch_end_hash: fields.batch_end_hash,
        current_state_commitment: fields.current_state_commitment,
        new_state_commitment: fields.new_state_commitment,
        deactivate_commitment: fields.deactivate_commitment,
        expected_poll_id: fields.expected_poll_id,
        input_hash: fields.input_hash,
    }
}

#[executable]
pub fn process_messages_native_boundary_main(
    fields: ProcessMessagesNativePublicFields, witness: ProcessMessagesNativeBoundaryWitness,
) -> ProcessMessagesNativePublicOutput {
    verify_process_messages_native_boundary(fields, witness);
    build_process_messages_native_public_output(fields)
}
