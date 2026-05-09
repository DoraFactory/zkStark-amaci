use crate::types::U256x2;

pub const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b;
pub const PUBLIC_OUTPUT_VERSION: felt252 = 1;
pub const TALLY_VOTES_CIRCUIT_ID: felt252 = 0x414d4143495f54414c4c595f564f544553;
pub const PROCESS_MESSAGES_CIRCUIT_ID: felt252 = 0x414d4143495f50524f434553535f4d45535341474553;
pub const ADD_NEW_KEY_CIRCUIT_ID: felt252 = 0x414d4143495f4144445f4e45575f4b4559;
pub const PROCESS_DEACTIVATE_CIRCUIT_ID: felt252 =
    0x414d4143495f50524f434553535f44454143544956415445;

#[derive(Copy, Drop, Serde)]
pub struct U256Split {
    pub low: u128,
    pub high: u128,
}

#[derive(Copy, Drop, Serde)]
pub struct TallyPublicFields {
    pub packed_vals: u256,
    pub state_commitment: u256,
    pub current_tally_commitment: u256,
    pub new_tally_commitment: u256,
    pub input_hash: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessMessagesPublicFields {
    pub packed_vals: u256,
    pub coord_pub_key_hash: u256,
    pub batch_start_hash: u256,
    pub batch_end_hash: u256,
    pub current_state_commitment: u256,
    pub new_state_commitment: u256,
    pub deactivate_commitment: u256,
    pub expected_poll_id: u256,
    pub input_hash: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct AddNewKeyPublicFields {
    pub deactivate_root: u256,
    pub coord_pub_key_hash: u256,
    pub nullifier: u256,
    pub d1: U256x2,
    pub d2: U256x2,
    pub new_pub_key_hash: u256,
    pub poll_id: u256,
    pub input_hash: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivatePublicFields {
    pub new_deactivate_root: u256,
    pub coord_pub_key_hash: u256,
    pub batch_start_hash: u256,
    pub batch_end_hash: u256,
    pub current_deactivate_commitment: u256,
    pub new_deactivate_commitment: u256,
    pub current_state_root: u256,
    pub expected_poll_id: u256,
    pub input_hash: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct TallyPublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub state_tree_depth: felt252,
    pub int_state_tree_depth: felt252,
    pub vote_option_tree_depth: felt252,
    pub packed_vals_low128: felt252,
    pub packed_vals_high128: felt252,
    pub state_commitment_low128: felt252,
    pub state_commitment_high128: felt252,
    pub current_tally_commitment_low128: felt252,
    pub current_tally_commitment_high128: felt252,
    pub new_tally_commitment_low128: felt252,
    pub new_tally_commitment_high128: felt252,
    pub input_hash_low128: felt252,
    pub input_hash_high128: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessMessagesPublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub state_tree_depth: felt252,
    pub vote_option_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub packed_vals_low128: felt252,
    pub packed_vals_high128: felt252,
    pub coord_pub_key_hash_low128: felt252,
    pub coord_pub_key_hash_high128: felt252,
    pub batch_start_hash_low128: felt252,
    pub batch_start_hash_high128: felt252,
    pub batch_end_hash_low128: felt252,
    pub batch_end_hash_high128: felt252,
    pub current_state_commitment_low128: felt252,
    pub current_state_commitment_high128: felt252,
    pub new_state_commitment_low128: felt252,
    pub new_state_commitment_high128: felt252,
    pub deactivate_commitment_low128: felt252,
    pub deactivate_commitment_high128: felt252,
    pub expected_poll_id_low128: felt252,
    pub expected_poll_id_high128: felt252,
    pub input_hash_low128: felt252,
    pub input_hash_high128: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct AddNewKeyPublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub state_tree_depth: felt252,
    pub deactivate_tree_depth: felt252,
    pub deactivate_root_low128: felt252,
    pub deactivate_root_high128: felt252,
    pub coord_pub_key_hash_low128: felt252,
    pub coord_pub_key_hash_high128: felt252,
    pub nullifier_low128: felt252,
    pub nullifier_high128: felt252,
    pub d1_x_low128: felt252,
    pub d1_x_high128: felt252,
    pub d1_y_low128: felt252,
    pub d1_y_high128: felt252,
    pub d2_x_low128: felt252,
    pub d2_x_high128: felt252,
    pub d2_y_low128: felt252,
    pub d2_y_high128: felt252,
    pub new_pub_key_hash_low128: felt252,
    pub new_pub_key_hash_high128: felt252,
    pub poll_id_low128: felt252,
    pub poll_id_high128: felt252,
    pub input_hash_low128: felt252,
    pub input_hash_high128: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivatePublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub state_tree_depth: felt252,
    pub deactivate_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub new_deactivate_root_low128: felt252,
    pub new_deactivate_root_high128: felt252,
    pub coord_pub_key_hash_low128: felt252,
    pub coord_pub_key_hash_high128: felt252,
    pub batch_start_hash_low128: felt252,
    pub batch_start_hash_high128: felt252,
    pub batch_end_hash_low128: felt252,
    pub batch_end_hash_high128: felt252,
    pub current_deactivate_commitment_low128: felt252,
    pub current_deactivate_commitment_high128: felt252,
    pub new_deactivate_commitment_low128: felt252,
    pub new_deactivate_commitment_high128: felt252,
    pub current_state_root_low128: felt252,
    pub current_state_root_high128: felt252,
    pub expected_poll_id_low128: felt252,
    pub expected_poll_id_high128: felt252,
    pub input_hash_low128: felt252,
    pub input_hash_high128: felt252,
}

pub fn split_u256(value: u256) -> U256Split {
    U256Split { low: value.low, high: value.high }
}

pub fn build_tally_public_output(fields: TallyPublicFields) -> TallyPublicOutput {
    let packed_vals = split_u256(fields.packed_vals);
    let state_commitment = split_u256(fields.state_commitment);
    let current_tally_commitment = split_u256(fields.current_tally_commitment);
    let new_tally_commitment = split_u256(fields.new_tally_commitment);
    let input_hash = split_u256(fields.input_hash);

    TallyPublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: PUBLIC_OUTPUT_VERSION,
        circuit_id: TALLY_VOTES_CIRCUIT_ID,
        state_tree_depth: 2,
        int_state_tree_depth: 1,
        vote_option_tree_depth: 1,
        packed_vals_low128: packed_vals.low.into(),
        packed_vals_high128: packed_vals.high.into(),
        state_commitment_low128: state_commitment.low.into(),
        state_commitment_high128: state_commitment.high.into(),
        current_tally_commitment_low128: current_tally_commitment.low.into(),
        current_tally_commitment_high128: current_tally_commitment.high.into(),
        new_tally_commitment_low128: new_tally_commitment.low.into(),
        new_tally_commitment_high128: new_tally_commitment.high.into(),
        input_hash_low128: input_hash.low.into(),
        input_hash_high128: input_hash.high.into(),
    }
}

pub fn build_process_messages_public_output(
    fields: ProcessMessagesPublicFields,
) -> ProcessMessagesPublicOutput {
    let packed_vals = split_u256(fields.packed_vals);
    let coord_pub_key_hash = split_u256(fields.coord_pub_key_hash);
    let batch_start_hash = split_u256(fields.batch_start_hash);
    let batch_end_hash = split_u256(fields.batch_end_hash);
    let current_state_commitment = split_u256(fields.current_state_commitment);
    let new_state_commitment = split_u256(fields.new_state_commitment);
    let deactivate_commitment = split_u256(fields.deactivate_commitment);
    let expected_poll_id = split_u256(fields.expected_poll_id);
    let input_hash = split_u256(fields.input_hash);

    ProcessMessagesPublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_MESSAGES_CIRCUIT_ID,
        state_tree_depth: 2,
        vote_option_tree_depth: 1,
        message_batch_size: 5,
        packed_vals_low128: packed_vals.low.into(),
        packed_vals_high128: packed_vals.high.into(),
        coord_pub_key_hash_low128: coord_pub_key_hash.low.into(),
        coord_pub_key_hash_high128: coord_pub_key_hash.high.into(),
        batch_start_hash_low128: batch_start_hash.low.into(),
        batch_start_hash_high128: batch_start_hash.high.into(),
        batch_end_hash_low128: batch_end_hash.low.into(),
        batch_end_hash_high128: batch_end_hash.high.into(),
        current_state_commitment_low128: current_state_commitment.low.into(),
        current_state_commitment_high128: current_state_commitment.high.into(),
        new_state_commitment_low128: new_state_commitment.low.into(),
        new_state_commitment_high128: new_state_commitment.high.into(),
        deactivate_commitment_low128: deactivate_commitment.low.into(),
        deactivate_commitment_high128: deactivate_commitment.high.into(),
        expected_poll_id_low128: expected_poll_id.low.into(),
        expected_poll_id_high128: expected_poll_id.high.into(),
        input_hash_low128: input_hash.low.into(),
        input_hash_high128: input_hash.high.into(),
    }
}

pub fn build_add_new_key_public_output(fields: AddNewKeyPublicFields) -> AddNewKeyPublicOutput {
    let deactivate_root = split_u256(fields.deactivate_root);
    let coord_pub_key_hash = split_u256(fields.coord_pub_key_hash);
    let nullifier = split_u256(fields.nullifier);
    let d1_x = split_u256(fields.d1.v0);
    let d1_y = split_u256(fields.d1.v1);
    let d2_x = split_u256(fields.d2.v0);
    let d2_y = split_u256(fields.d2.v1);
    let new_pub_key_hash = split_u256(fields.new_pub_key_hash);
    let poll_id = split_u256(fields.poll_id);
    let input_hash = split_u256(fields.input_hash);

    AddNewKeyPublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: PUBLIC_OUTPUT_VERSION,
        circuit_id: ADD_NEW_KEY_CIRCUIT_ID,
        state_tree_depth: 2,
        deactivate_tree_depth: 4,
        deactivate_root_low128: deactivate_root.low.into(),
        deactivate_root_high128: deactivate_root.high.into(),
        coord_pub_key_hash_low128: coord_pub_key_hash.low.into(),
        coord_pub_key_hash_high128: coord_pub_key_hash.high.into(),
        nullifier_low128: nullifier.low.into(),
        nullifier_high128: nullifier.high.into(),
        d1_x_low128: d1_x.low.into(),
        d1_x_high128: d1_x.high.into(),
        d1_y_low128: d1_y.low.into(),
        d1_y_high128: d1_y.high.into(),
        d2_x_low128: d2_x.low.into(),
        d2_x_high128: d2_x.high.into(),
        d2_y_low128: d2_y.low.into(),
        d2_y_high128: d2_y.high.into(),
        new_pub_key_hash_low128: new_pub_key_hash.low.into(),
        new_pub_key_hash_high128: new_pub_key_hash.high.into(),
        poll_id_low128: poll_id.low.into(),
        poll_id_high128: poll_id.high.into(),
        input_hash_low128: input_hash.low.into(),
        input_hash_high128: input_hash.high.into(),
    }
}

pub fn build_process_deactivate_public_output(
    fields: ProcessDeactivatePublicFields,
) -> ProcessDeactivatePublicOutput {
    let new_deactivate_root = split_u256(fields.new_deactivate_root);
    let coord_pub_key_hash = split_u256(fields.coord_pub_key_hash);
    let batch_start_hash = split_u256(fields.batch_start_hash);
    let batch_end_hash = split_u256(fields.batch_end_hash);
    let current_deactivate_commitment = split_u256(fields.current_deactivate_commitment);
    let new_deactivate_commitment = split_u256(fields.new_deactivate_commitment);
    let current_state_root = split_u256(fields.current_state_root);
    let expected_poll_id = split_u256(fields.expected_poll_id);
    let input_hash = split_u256(fields.input_hash);

    ProcessDeactivatePublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_DEACTIVATE_CIRCUIT_ID,
        state_tree_depth: 2,
        deactivate_tree_depth: 4,
        message_batch_size: 5,
        new_deactivate_root_low128: new_deactivate_root.low.into(),
        new_deactivate_root_high128: new_deactivate_root.high.into(),
        coord_pub_key_hash_low128: coord_pub_key_hash.low.into(),
        coord_pub_key_hash_high128: coord_pub_key_hash.high.into(),
        batch_start_hash_low128: batch_start_hash.low.into(),
        batch_start_hash_high128: batch_start_hash.high.into(),
        batch_end_hash_low128: batch_end_hash.low.into(),
        batch_end_hash_high128: batch_end_hash.high.into(),
        current_deactivate_commitment_low128: current_deactivate_commitment.low.into(),
        current_deactivate_commitment_high128: current_deactivate_commitment.high.into(),
        new_deactivate_commitment_low128: new_deactivate_commitment.low.into(),
        new_deactivate_commitment_high128: new_deactivate_commitment.high.into(),
        current_state_root_low128: current_state_root.low.into(),
        current_state_root_high128: current_state_root.high.into(),
        expected_poll_id_low128: expected_poll_id.low.into(),
        expected_poll_id_high128: expected_poll_id.high.into(),
        input_hash_low128: input_hash.low.into(),
        input_hash_high128: input_hash.high.into(),
    }
}
