pub const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b;
pub const PUBLIC_OUTPUT_VERSION: felt252 = 1;
pub const TALLY_VOTES_CIRCUIT_ID: felt252 = 0x414d4143495f54414c4c595f564f544553;

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
