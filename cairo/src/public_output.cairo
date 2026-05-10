use crate::types::U256x2;

pub const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b;
pub const PUBLIC_OUTPUT_VERSION: felt252 = 1;
pub const TALLY_VOTES_CIRCUIT_ID: felt252 = 0x414d4143495f54414c4c595f564f544553;
pub const PROCESS_MESSAGES_CIRCUIT_ID: felt252 = 0x414d4143495f50524f434553535f4d45535341474553;
pub const PROCESS_MESSAGE_STEP_CIRCUIT_ID: felt252 =
    0x414d4143495f50524f434553535f4d4553534147455f53544550;
pub const PROCESS_MESSAGE_COORD_KEY_CIRCUIT_ID: felt252 =
    0x414d4143495f50524f434553535f4d4553534147455f434f4f52445f4b4559;
pub const PROCESS_MESSAGE_ECDH_CIRCUIT_ID: felt252 =
    0x414d4143495f50524f434553535f4d4553534147455f45434448;
pub const PROCESS_MESSAGE_SIGNATURE_CIRCUIT_ID: felt252 =
    0x414d4143495f50524f434553535f4d4553534147455f534947;
pub const PROCESS_MESSAGE_STEP_CORE_CIRCUIT_ID: felt252 =
    0x414d4143495f50524f434553535f4d4553534147455f535445505f434f5245;
pub const ADD_NEW_KEY_CIRCUIT_ID: felt252 = 0x414d4143495f4144445f4e45575f4b4559;
pub const PROCESS_DEACTIVATE_CIRCUIT_ID: felt252 =
    0x414d4143495f50524f434553535f44454143544956415445;
pub const PROCESS_DEACTIVATE_STEP_CIRCUIT_ID: felt252 =
    0x414d4143495f50524f434553535f444541435449564154455f53544550;

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
pub struct ProcessMessageStepPublicFields {
    pub message_index: felt252,
    pub packed_vals: u256,
    pub coord_pub_key_hash: u256,
    pub previous_message_hash: u256,
    pub next_message_hash: u256,
    pub current_state_root: u256,
    pub new_state_root: u256,
    pub current_state_commitment: u256,
    pub new_state_commitment: u256,
    pub active_state_root: u256,
    pub expected_poll_id: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessMessageCoordKeyPublicFields {
    pub coord_pub_key_hash: u256,
    pub coord_priv_key_hash: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessMessageEcdhPublicFields {
    pub message_index: felt252,
    pub coord_priv_key_hash: u256,
    pub enc_pub_key_hash: u256,
    pub shared_key_hash: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessMessageSignaturePublicFields {
    pub message_index: felt252,
    pub pub_key_hash: u256,
    pub r8_hash: u256,
    pub packed_command_hash: u256,
    pub cmd_sig_s: u256,
    pub is_signature_valid: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessMessageStepCorePublicFields {
    pub message_index: felt252,
    pub packed_vals: u256,
    pub coord_pub_key_hash: u256,
    pub coord_priv_key_hash: u256,
    pub previous_message_hash: u256,
    pub next_message_hash: u256,
    pub current_state_root: u256,
    pub new_state_root: u256,
    pub current_state_commitment: u256,
    pub new_state_commitment: u256,
    pub active_state_root: u256,
    pub expected_poll_id: u256,
    pub enc_pub_key_hash: u256,
    pub shared_key_hash: u256,
    pub signature_pub_key_hash: u256,
    pub signature_r8_hash: u256,
    pub packed_command_hash: u256,
    pub cmd_sig_s: u256,
    pub is_signature_valid: u256,
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
pub struct ProcessDeactivateStepPublicFields {
    pub message_index: felt252,
    pub deactivate_index: u256,
    pub coord_pub_key_hash: u256,
    pub previous_message_hash: u256,
    pub next_message_hash: u256,
    pub current_active_state_root: u256,
    pub current_deactivate_root: u256,
    pub new_active_state_root: u256,
    pub new_deactivate_root: u256,
    pub current_deactivate_commitment: u256,
    pub new_deactivate_commitment: u256,
    pub current_state_root: u256,
    pub expected_poll_id: u256,
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
pub struct ProcessMessageStepPublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub state_tree_depth: felt252,
    pub vote_option_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub message_index: felt252,
    pub packed_vals_low128: felt252,
    pub packed_vals_high128: felt252,
    pub coord_pub_key_hash_low128: felt252,
    pub coord_pub_key_hash_high128: felt252,
    pub previous_message_hash_low128: felt252,
    pub previous_message_hash_high128: felt252,
    pub next_message_hash_low128: felt252,
    pub next_message_hash_high128: felt252,
    pub current_state_root_low128: felt252,
    pub current_state_root_high128: felt252,
    pub new_state_root_low128: felt252,
    pub new_state_root_high128: felt252,
    pub current_state_commitment_low128: felt252,
    pub current_state_commitment_high128: felt252,
    pub new_state_commitment_low128: felt252,
    pub new_state_commitment_high128: felt252,
    pub active_state_root_low128: felt252,
    pub active_state_root_high128: felt252,
    pub expected_poll_id_low128: felt252,
    pub expected_poll_id_high128: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessMessageCoordKeyPublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub state_tree_depth: felt252,
    pub vote_option_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub coord_pub_key_hash_low128: felt252,
    pub coord_pub_key_hash_high128: felt252,
    pub coord_priv_key_hash_low128: felt252,
    pub coord_priv_key_hash_high128: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessMessageEcdhPublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub state_tree_depth: felt252,
    pub vote_option_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub message_index: felt252,
    pub coord_priv_key_hash_low128: felt252,
    pub coord_priv_key_hash_high128: felt252,
    pub enc_pub_key_hash_low128: felt252,
    pub enc_pub_key_hash_high128: felt252,
    pub shared_key_hash_low128: felt252,
    pub shared_key_hash_high128: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessMessageSignaturePublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub state_tree_depth: felt252,
    pub vote_option_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub message_index: felt252,
    pub pub_key_hash_low128: felt252,
    pub pub_key_hash_high128: felt252,
    pub r8_hash_low128: felt252,
    pub r8_hash_high128: felt252,
    pub packed_command_hash_low128: felt252,
    pub packed_command_hash_high128: felt252,
    pub cmd_sig_s_low128: felt252,
    pub cmd_sig_s_high128: felt252,
    pub is_signature_valid_low128: felt252,
    pub is_signature_valid_high128: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessMessageStepCorePublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub state_tree_depth: felt252,
    pub vote_option_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub message_index: felt252,
    pub packed_vals_low128: felt252,
    pub packed_vals_high128: felt252,
    pub coord_pub_key_hash_low128: felt252,
    pub coord_pub_key_hash_high128: felt252,
    pub coord_priv_key_hash_low128: felt252,
    pub coord_priv_key_hash_high128: felt252,
    pub previous_message_hash_low128: felt252,
    pub previous_message_hash_high128: felt252,
    pub next_message_hash_low128: felt252,
    pub next_message_hash_high128: felt252,
    pub current_state_root_low128: felt252,
    pub current_state_root_high128: felt252,
    pub new_state_root_low128: felt252,
    pub new_state_root_high128: felt252,
    pub current_state_commitment_low128: felt252,
    pub current_state_commitment_high128: felt252,
    pub new_state_commitment_low128: felt252,
    pub new_state_commitment_high128: felt252,
    pub active_state_root_low128: felt252,
    pub active_state_root_high128: felt252,
    pub expected_poll_id_low128: felt252,
    pub expected_poll_id_high128: felt252,
    pub enc_pub_key_hash_low128: felt252,
    pub enc_pub_key_hash_high128: felt252,
    pub shared_key_hash_low128: felt252,
    pub shared_key_hash_high128: felt252,
    pub signature_pub_key_hash_low128: felt252,
    pub signature_pub_key_hash_high128: felt252,
    pub signature_r8_hash_low128: felt252,
    pub signature_r8_hash_high128: felt252,
    pub packed_command_hash_low128: felt252,
    pub packed_command_hash_high128: felt252,
    pub cmd_sig_s_low128: felt252,
    pub cmd_sig_s_high128: felt252,
    pub is_signature_valid_low128: felt252,
    pub is_signature_valid_high128: felt252,
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

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivateStepPublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub state_tree_depth: felt252,
    pub deactivate_tree_depth: felt252,
    pub message_batch_size: felt252,
    pub message_index: felt252,
    pub deactivate_index_low128: felt252,
    pub deactivate_index_high128: felt252,
    pub coord_pub_key_hash_low128: felt252,
    pub coord_pub_key_hash_high128: felt252,
    pub previous_message_hash_low128: felt252,
    pub previous_message_hash_high128: felt252,
    pub next_message_hash_low128: felt252,
    pub next_message_hash_high128: felt252,
    pub current_active_state_root_low128: felt252,
    pub current_active_state_root_high128: felt252,
    pub current_deactivate_root_low128: felt252,
    pub current_deactivate_root_high128: felt252,
    pub new_active_state_root_low128: felt252,
    pub new_active_state_root_high128: felt252,
    pub new_deactivate_root_low128: felt252,
    pub new_deactivate_root_high128: felt252,
    pub current_deactivate_commitment_low128: felt252,
    pub current_deactivate_commitment_high128: felt252,
    pub new_deactivate_commitment_low128: felt252,
    pub new_deactivate_commitment_high128: felt252,
    pub current_state_root_low128: felt252,
    pub current_state_root_high128: felt252,
    pub expected_poll_id_low128: felt252,
    pub expected_poll_id_high128: felt252,
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

pub fn build_process_message_step_public_output(
    fields: ProcessMessageStepPublicFields,
) -> ProcessMessageStepPublicOutput {
    let packed_vals = split_u256(fields.packed_vals);
    let coord_pub_key_hash = split_u256(fields.coord_pub_key_hash);
    let previous_message_hash = split_u256(fields.previous_message_hash);
    let next_message_hash = split_u256(fields.next_message_hash);
    let current_state_root = split_u256(fields.current_state_root);
    let new_state_root = split_u256(fields.new_state_root);
    let current_state_commitment = split_u256(fields.current_state_commitment);
    let new_state_commitment = split_u256(fields.new_state_commitment);
    let active_state_root = split_u256(fields.active_state_root);
    let expected_poll_id = split_u256(fields.expected_poll_id);

    ProcessMessageStepPublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_MESSAGE_STEP_CIRCUIT_ID,
        state_tree_depth: 2,
        vote_option_tree_depth: 1,
        message_batch_size: 5,
        message_index: fields.message_index,
        packed_vals_low128: packed_vals.low.into(),
        packed_vals_high128: packed_vals.high.into(),
        coord_pub_key_hash_low128: coord_pub_key_hash.low.into(),
        coord_pub_key_hash_high128: coord_pub_key_hash.high.into(),
        previous_message_hash_low128: previous_message_hash.low.into(),
        previous_message_hash_high128: previous_message_hash.high.into(),
        next_message_hash_low128: next_message_hash.low.into(),
        next_message_hash_high128: next_message_hash.high.into(),
        current_state_root_low128: current_state_root.low.into(),
        current_state_root_high128: current_state_root.high.into(),
        new_state_root_low128: new_state_root.low.into(),
        new_state_root_high128: new_state_root.high.into(),
        current_state_commitment_low128: current_state_commitment.low.into(),
        current_state_commitment_high128: current_state_commitment.high.into(),
        new_state_commitment_low128: new_state_commitment.low.into(),
        new_state_commitment_high128: new_state_commitment.high.into(),
        active_state_root_low128: active_state_root.low.into(),
        active_state_root_high128: active_state_root.high.into(),
        expected_poll_id_low128: expected_poll_id.low.into(),
        expected_poll_id_high128: expected_poll_id.high.into(),
    }
}

pub fn build_process_message_coord_key_public_output(
    fields: ProcessMessageCoordKeyPublicFields,
) -> ProcessMessageCoordKeyPublicOutput {
    let coord_pub_key_hash = split_u256(fields.coord_pub_key_hash);
    let coord_priv_key_hash = split_u256(fields.coord_priv_key_hash);

    ProcessMessageCoordKeyPublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_MESSAGE_COORD_KEY_CIRCUIT_ID,
        state_tree_depth: 2,
        vote_option_tree_depth: 1,
        message_batch_size: 5,
        coord_pub_key_hash_low128: coord_pub_key_hash.low.into(),
        coord_pub_key_hash_high128: coord_pub_key_hash.high.into(),
        coord_priv_key_hash_low128: coord_priv_key_hash.low.into(),
        coord_priv_key_hash_high128: coord_priv_key_hash.high.into(),
    }
}

pub fn build_process_message_ecdh_public_output(
    fields: ProcessMessageEcdhPublicFields,
) -> ProcessMessageEcdhPublicOutput {
    let coord_priv_key_hash = split_u256(fields.coord_priv_key_hash);
    let enc_pub_key_hash = split_u256(fields.enc_pub_key_hash);
    let shared_key_hash = split_u256(fields.shared_key_hash);

    ProcessMessageEcdhPublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_MESSAGE_ECDH_CIRCUIT_ID,
        state_tree_depth: 2,
        vote_option_tree_depth: 1,
        message_batch_size: 5,
        message_index: fields.message_index,
        coord_priv_key_hash_low128: coord_priv_key_hash.low.into(),
        coord_priv_key_hash_high128: coord_priv_key_hash.high.into(),
        enc_pub_key_hash_low128: enc_pub_key_hash.low.into(),
        enc_pub_key_hash_high128: enc_pub_key_hash.high.into(),
        shared_key_hash_low128: shared_key_hash.low.into(),
        shared_key_hash_high128: shared_key_hash.high.into(),
    }
}

pub fn build_process_message_signature_public_output(
    fields: ProcessMessageSignaturePublicFields,
) -> ProcessMessageSignaturePublicOutput {
    let pub_key_hash = split_u256(fields.pub_key_hash);
    let r8_hash = split_u256(fields.r8_hash);
    let packed_command_hash = split_u256(fields.packed_command_hash);
    let cmd_sig_s = split_u256(fields.cmd_sig_s);
    let is_signature_valid = split_u256(fields.is_signature_valid);

    ProcessMessageSignaturePublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_MESSAGE_SIGNATURE_CIRCUIT_ID,
        state_tree_depth: 2,
        vote_option_tree_depth: 1,
        message_batch_size: 5,
        message_index: fields.message_index,
        pub_key_hash_low128: pub_key_hash.low.into(),
        pub_key_hash_high128: pub_key_hash.high.into(),
        r8_hash_low128: r8_hash.low.into(),
        r8_hash_high128: r8_hash.high.into(),
        packed_command_hash_low128: packed_command_hash.low.into(),
        packed_command_hash_high128: packed_command_hash.high.into(),
        cmd_sig_s_low128: cmd_sig_s.low.into(),
        cmd_sig_s_high128: cmd_sig_s.high.into(),
        is_signature_valid_low128: is_signature_valid.low.into(),
        is_signature_valid_high128: is_signature_valid.high.into(),
    }
}

pub fn build_process_message_step_core_public_output(
    fields: ProcessMessageStepCorePublicFields,
) -> ProcessMessageStepCorePublicOutput {
    let packed_vals = split_u256(fields.packed_vals);
    let coord_pub_key_hash = split_u256(fields.coord_pub_key_hash);
    let coord_priv_key_hash = split_u256(fields.coord_priv_key_hash);
    let previous_message_hash = split_u256(fields.previous_message_hash);
    let next_message_hash = split_u256(fields.next_message_hash);
    let current_state_root = split_u256(fields.current_state_root);
    let new_state_root = split_u256(fields.new_state_root);
    let current_state_commitment = split_u256(fields.current_state_commitment);
    let new_state_commitment = split_u256(fields.new_state_commitment);
    let active_state_root = split_u256(fields.active_state_root);
    let expected_poll_id = split_u256(fields.expected_poll_id);
    let enc_pub_key_hash = split_u256(fields.enc_pub_key_hash);
    let shared_key_hash = split_u256(fields.shared_key_hash);
    let signature_pub_key_hash = split_u256(fields.signature_pub_key_hash);
    let signature_r8_hash = split_u256(fields.signature_r8_hash);
    let packed_command_hash = split_u256(fields.packed_command_hash);
    let cmd_sig_s = split_u256(fields.cmd_sig_s);
    let is_signature_valid = split_u256(fields.is_signature_valid);

    ProcessMessageStepCorePublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_MESSAGE_STEP_CORE_CIRCUIT_ID,
        state_tree_depth: 2,
        vote_option_tree_depth: 1,
        message_batch_size: 5,
        message_index: fields.message_index,
        packed_vals_low128: packed_vals.low.into(),
        packed_vals_high128: packed_vals.high.into(),
        coord_pub_key_hash_low128: coord_pub_key_hash.low.into(),
        coord_pub_key_hash_high128: coord_pub_key_hash.high.into(),
        coord_priv_key_hash_low128: coord_priv_key_hash.low.into(),
        coord_priv_key_hash_high128: coord_priv_key_hash.high.into(),
        previous_message_hash_low128: previous_message_hash.low.into(),
        previous_message_hash_high128: previous_message_hash.high.into(),
        next_message_hash_low128: next_message_hash.low.into(),
        next_message_hash_high128: next_message_hash.high.into(),
        current_state_root_low128: current_state_root.low.into(),
        current_state_root_high128: current_state_root.high.into(),
        new_state_root_low128: new_state_root.low.into(),
        new_state_root_high128: new_state_root.high.into(),
        current_state_commitment_low128: current_state_commitment.low.into(),
        current_state_commitment_high128: current_state_commitment.high.into(),
        new_state_commitment_low128: new_state_commitment.low.into(),
        new_state_commitment_high128: new_state_commitment.high.into(),
        active_state_root_low128: active_state_root.low.into(),
        active_state_root_high128: active_state_root.high.into(),
        expected_poll_id_low128: expected_poll_id.low.into(),
        expected_poll_id_high128: expected_poll_id.high.into(),
        enc_pub_key_hash_low128: enc_pub_key_hash.low.into(),
        enc_pub_key_hash_high128: enc_pub_key_hash.high.into(),
        shared_key_hash_low128: shared_key_hash.low.into(),
        shared_key_hash_high128: shared_key_hash.high.into(),
        signature_pub_key_hash_low128: signature_pub_key_hash.low.into(),
        signature_pub_key_hash_high128: signature_pub_key_hash.high.into(),
        signature_r8_hash_low128: signature_r8_hash.low.into(),
        signature_r8_hash_high128: signature_r8_hash.high.into(),
        packed_command_hash_low128: packed_command_hash.low.into(),
        packed_command_hash_high128: packed_command_hash.high.into(),
        cmd_sig_s_low128: cmd_sig_s.low.into(),
        cmd_sig_s_high128: cmd_sig_s.high.into(),
        is_signature_valid_low128: is_signature_valid.low.into(),
        is_signature_valid_high128: is_signature_valid.high.into(),
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

pub fn build_process_deactivate_step_public_output(
    fields: ProcessDeactivateStepPublicFields,
) -> ProcessDeactivateStepPublicOutput {
    let deactivate_index = split_u256(fields.deactivate_index);
    let coord_pub_key_hash = split_u256(fields.coord_pub_key_hash);
    let previous_message_hash = split_u256(fields.previous_message_hash);
    let next_message_hash = split_u256(fields.next_message_hash);
    let current_active_state_root = split_u256(fields.current_active_state_root);
    let current_deactivate_root = split_u256(fields.current_deactivate_root);
    let new_active_state_root = split_u256(fields.new_active_state_root);
    let new_deactivate_root = split_u256(fields.new_deactivate_root);
    let current_deactivate_commitment = split_u256(fields.current_deactivate_commitment);
    let new_deactivate_commitment = split_u256(fields.new_deactivate_commitment);
    let current_state_root = split_u256(fields.current_state_root);
    let expected_poll_id = split_u256(fields.expected_poll_id);

    ProcessDeactivateStepPublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: PUBLIC_OUTPUT_VERSION,
        circuit_id: PROCESS_DEACTIVATE_STEP_CIRCUIT_ID,
        state_tree_depth: 2,
        deactivate_tree_depth: 4,
        message_batch_size: 5,
        message_index: fields.message_index,
        deactivate_index_low128: deactivate_index.low.into(),
        deactivate_index_high128: deactivate_index.high.into(),
        coord_pub_key_hash_low128: coord_pub_key_hash.low.into(),
        coord_pub_key_hash_high128: coord_pub_key_hash.high.into(),
        previous_message_hash_low128: previous_message_hash.low.into(),
        previous_message_hash_high128: previous_message_hash.high.into(),
        next_message_hash_low128: next_message_hash.low.into(),
        next_message_hash_high128: next_message_hash.high.into(),
        current_active_state_root_low128: current_active_state_root.low.into(),
        current_active_state_root_high128: current_active_state_root.high.into(),
        current_deactivate_root_low128: current_deactivate_root.low.into(),
        current_deactivate_root_high128: current_deactivate_root.high.into(),
        new_active_state_root_low128: new_active_state_root.low.into(),
        new_active_state_root_high128: new_active_state_root.high.into(),
        new_deactivate_root_low128: new_deactivate_root.low.into(),
        new_deactivate_root_high128: new_deactivate_root.high.into(),
        current_deactivate_commitment_low128: current_deactivate_commitment.low.into(),
        current_deactivate_commitment_high128: current_deactivate_commitment.high.into(),
        new_deactivate_commitment_low128: new_deactivate_commitment.low.into(),
        new_deactivate_commitment_high128: new_deactivate_commitment.high.into(),
        current_state_root_low128: current_state_root.low.into(),
        current_state_root_high128: current_state_root.high.into(),
        expected_poll_id_low128: expected_poll_id.low.into(),
        expected_poll_id_high128: expected_poll_id.high.into(),
    }
}
