use core::hash::HashStateTrait;
use core::poseidon::PoseidonTrait;

pub const BATCH_SIZE: u32 = 5;
pub const TWO_POW_32: felt252 = 0x100000000;
pub const MAX_VOTES: felt252 = 1000000000000000000000000;
pub const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b;
pub const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
pub const TALLY_VOTES_NATIVE_CIRCUIT_ID: felt252 = 0x414d4143495f54414c4c595f4e4154495645;
pub const STARKNET_POSEIDON_HASH_SCHEME: felt252 = 0x535441524b4e45545f504f534549444f4e;
pub const TALLY_NATIVE_INPUT_HASH_DOMAIN: felt252 =
    0x414d4143495f54414c4c595f4e41544956455f494e505554;

#[derive(Copy, Drop, Serde)]
pub struct Felt4 {
    pub v0: felt252,
    pub v1: felt252,
    pub v2: felt252,
    pub v3: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct Felt5 {
    pub v0: felt252,
    pub v1: felt252,
    pub v2: felt252,
    pub v3: felt252,
    pub v4: felt252,
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
pub struct TallyNativePublicFields {
    pub packed_vals: felt252,
    pub state_commitment: felt252,
    pub current_tally_commitment: felt252,
    pub new_tally_commitment: felt252,
    pub input_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct TallyNativeWitness {
    pub state_root: felt252,
    pub state_salt: felt252,
    pub num_signups: u32,
    pub batch_num: u32,
    pub state_leaf_0: Felt10,
    pub state_leaf_1: Felt10,
    pub state_leaf_2: Felt10,
    pub state_leaf_3: Felt10,
    pub state_leaf_4: Felt10,
    pub state_path_elements: Felt4,
    pub votes_0: Felt5,
    pub votes_1: Felt5,
    pub votes_2: Felt5,
    pub votes_3: Felt5,
    pub votes_4: Felt5,
    pub current_results: Felt5,
    pub current_results_root_salt: felt252,
    pub new_results_root_salt: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct TallyNativePublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub hash_scheme: felt252,
    pub state_tree_depth: felt252,
    pub int_state_tree_depth: felt252,
    pub vote_option_tree_depth: felt252,
    pub packed_vals: felt252,
    pub state_commitment: felt252,
    pub current_tally_commitment: felt252,
    pub new_tally_commitment: felt252,
    pub input_hash: felt252,
}

fn assert_supported_batch_num(batch_num: u32) {
    assert(batch_num < 5, 'BATCH_RANGE');
}

fn hash2(left: felt252, right: felt252) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(left);
    state = state.update(right);
    state.finalize()
}

fn hash5(values: Felt5) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(values.v0);
    state = state.update(values.v1);
    state = state.update(values.v2);
    state = state.update(values.v3);
    state = state.update(values.v4);
    state.finalize()
}

fn hash10(values: Felt10) -> felt252 {
    hash2(
        hash5(Felt5 { v0: values.v0, v1: values.v1, v2: values.v2, v3: values.v3, v4: values.v4 }),
        hash5(Felt5 { v0: values.v5, v1: values.v6, v2: values.v7, v3: values.v8, v4: values.v9 }),
    )
}

fn state_path_inputs(state_subroot: felt252, path_elements: Felt4, batch_num: u32) -> Felt5 {
    if batch_num == 0 {
        Felt5 {
            v0: state_subroot,
            v1: path_elements.v0,
            v2: path_elements.v1,
            v3: path_elements.v2,
            v4: path_elements.v3,
        }
    } else if batch_num == 1 {
        Felt5 {
            v0: path_elements.v0,
            v1: state_subroot,
            v2: path_elements.v1,
            v3: path_elements.v2,
            v4: path_elements.v3,
        }
    } else if batch_num == 2 {
        Felt5 {
            v0: path_elements.v0,
            v1: path_elements.v1,
            v2: state_subroot,
            v3: path_elements.v2,
            v4: path_elements.v3,
        }
    } else if batch_num == 3 {
        Felt5 {
            v0: path_elements.v0,
            v1: path_elements.v1,
            v2: path_elements.v2,
            v3: state_subroot,
            v4: path_elements.v3,
        }
    } else {
        Felt5 {
            v0: path_elements.v0,
            v1: path_elements.v1,
            v2: path_elements.v2,
            v3: path_elements.v3,
            v4: state_subroot,
        }
    }
}

fn vote_root_field(state_leaf: Felt10) -> felt252 {
    state_leaf.v3
}

fn select_expected_vote_root(state_leaf: Felt10, zero_root: felt252) -> felt252 {
    if vote_root_field(state_leaf) == 0 {
        zero_root
    } else {
        vote_root_field(state_leaf)
    }
}

fn assert_vote_root_matches(state_leaf: Felt10, vote_root: felt252, zero_root: felt252) {
    assert(vote_root == select_expected_vote_root(state_leaf, zero_root), 'VOTE_ROOT_MISMATCH');
}

fn tally_vote(vote: felt252) -> felt252 {
    vote * (vote + MAX_VOTES)
}

fn tally_option(
    current: felt252,
    is_first_batch: bool,
    v0: felt252,
    v1: felt252,
    v2: felt252,
    v3: felt252,
    v4: felt252,
) -> felt252 {
    let base = if is_first_batch {
        0
    } else {
        current
    };
    base + tally_vote(v0) + tally_vote(v1) + tally_vote(v2) + tally_vote(v3) + tally_vote(v4)
}

fn compute_new_results(witness: TallyNativeWitness, is_first_batch: bool) -> Felt5 {
    Felt5 {
        v0: tally_option(
            witness.current_results.v0,
            is_first_batch,
            witness.votes_0.v0,
            witness.votes_1.v0,
            witness.votes_2.v0,
            witness.votes_3.v0,
            witness.votes_4.v0,
        ),
        v1: tally_option(
            witness.current_results.v1,
            is_first_batch,
            witness.votes_0.v1,
            witness.votes_1.v1,
            witness.votes_2.v1,
            witness.votes_3.v1,
            witness.votes_4.v1,
        ),
        v2: tally_option(
            witness.current_results.v2,
            is_first_batch,
            witness.votes_0.v2,
            witness.votes_1.v2,
            witness.votes_2.v2,
            witness.votes_3.v2,
            witness.votes_4.v2,
        ),
        v3: tally_option(
            witness.current_results.v3,
            is_first_batch,
            witness.votes_0.v3,
            witness.votes_1.v3,
            witness.votes_2.v3,
            witness.votes_3.v3,
            witness.votes_4.v3,
        ),
        v4: tally_option(
            witness.current_results.v4,
            is_first_batch,
            witness.votes_0.v4,
            witness.votes_1.v4,
            witness.votes_2.v4,
            witness.votes_3.v4,
            witness.votes_4.v4,
        ),
    }
}

fn input_hash(fields: TallyNativePublicFields) -> felt252 {
    hash5(
        Felt5 {
            v0: TALLY_NATIVE_INPUT_HASH_DOMAIN,
            v1: fields.packed_vals,
            v2: fields.state_commitment,
            v3: fields.current_tally_commitment,
            v4: fields.new_tally_commitment,
        },
    )
}

fn verify_tally_votes_native(fields: TallyNativePublicFields, witness: TallyNativeWitness) {
    let packed_vals = witness.num_signups.into() * TWO_POW_32 + witness.batch_num.into();
    assert(packed_vals == fields.packed_vals, 'PACKED_VALS');
    assert_supported_batch_num(witness.batch_num);

    let batch_start_index = witness.batch_num * BATCH_SIZE;
    assert(batch_start_index <= witness.num_signups, 'BAD_NUM_SIGNUPS');
    let is_first_batch = batch_start_index == 0;

    let zero_root = hash5(Felt5 { v0: 0, v1: 0, v2: 0, v3: 0, v4: 0 });
    let state_leaf_hash_0 = hash10(witness.state_leaf_0);
    let state_leaf_hash_1 = hash10(witness.state_leaf_1);
    let state_leaf_hash_2 = hash10(witness.state_leaf_2);
    let state_leaf_hash_3 = hash10(witness.state_leaf_3);
    let state_leaf_hash_4 = hash10(witness.state_leaf_4);
    let state_subroot = hash5(
        Felt5 {
            v0: state_leaf_hash_0,
            v1: state_leaf_hash_1,
            v2: state_leaf_hash_2,
            v3: state_leaf_hash_3,
            v4: state_leaf_hash_4,
        },
    );
    let state_root_from_path = hash5(
        state_path_inputs(state_subroot, witness.state_path_elements, witness.batch_num),
    );
    assert(state_root_from_path == witness.state_root, 'STATE_ROOT');

    let state_commitment = hash2(witness.state_root, witness.state_salt);
    assert(state_commitment == fields.state_commitment, 'STATE_COMMITMENT');

    let vote_root_0 = hash5(witness.votes_0);
    let vote_root_1 = hash5(witness.votes_1);
    let vote_root_2 = hash5(witness.votes_2);
    let vote_root_3 = hash5(witness.votes_3);
    let vote_root_4 = hash5(witness.votes_4);
    assert_vote_root_matches(witness.state_leaf_0, vote_root_0, zero_root);
    assert_vote_root_matches(witness.state_leaf_1, vote_root_1, zero_root);
    assert_vote_root_matches(witness.state_leaf_2, vote_root_2, zero_root);
    assert_vote_root_matches(witness.state_leaf_3, vote_root_3, zero_root);
    assert_vote_root_matches(witness.state_leaf_4, vote_root_4, zero_root);

    if is_first_batch {
        assert(fields.current_tally_commitment == 0, 'CURRENT_TALLY');
    } else {
        let current_results_root = hash5(witness.current_results);
        let current_tally_commitment = hash2(
            current_results_root, witness.current_results_root_salt,
        );
        assert(current_tally_commitment == fields.current_tally_commitment, 'CURRENT_TALLY');
    }

    let new_results = compute_new_results(witness, is_first_batch);
    let new_results_root = hash5(new_results);
    let new_tally_commitment = hash2(new_results_root, witness.new_results_root_salt);
    assert(new_tally_commitment == fields.new_tally_commitment, 'NEW_TALLY');
    assert(input_hash(fields) == fields.input_hash, 'INPUT_HASH');
}

fn build_tally_native_public_output(fields: TallyNativePublicFields) -> TallyNativePublicOutput {
    TallyNativePublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: TALLY_VOTES_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        int_state_tree_depth: 1,
        vote_option_tree_depth: 1,
        packed_vals: fields.packed_vals,
        state_commitment: fields.state_commitment,
        current_tally_commitment: fields.current_tally_commitment,
        new_tally_commitment: fields.new_tally_commitment,
        input_hash: fields.input_hash,
    }
}

#[executable]
pub fn main(
    fields: TallyNativePublicFields, witness: TallyNativeWitness,
) -> TallyNativePublicOutput {
    verify_tally_votes_native(fields, witness);
    build_tally_native_public_output(fields)
}
