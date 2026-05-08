use crate::hash_gates::{
    Hash10Claim, Hash2Claim, Hash5Claim, Sha256U256x4Claim, poseidon_hash10,
    poseidon_hash10_or_zero_cache, poseidon_hash2, poseidon_hash5, poseidon_hash5_or_zero_cache,
    sha256_u256x4_mod_bn254,
};
use crate::poseidon_bn254::{POSEIDON10_ZERO_HASH, POSEIDON5_ZERO_HASH};
use crate::public_output::{TallyPublicFields, TallyPublicOutput, build_tally_public_output};
use crate::types::{U256x10, U256x4, U256x5, assert_u256_eq, assert_vector5_eq, is_zero, zero_u256};

pub const BATCH_SIZE: u256 = 5;
pub const TWO_POW_32: u256 = 0x100000000;
pub const MAX_VOTES: u256 = 1000000000000000000000000;

#[derive(Copy, Drop, Serde)]
pub struct TallyHashTranscript {
    pub state_commitment: Hash2Claim,
    pub input_hash: Sha256U256x4Claim,
    pub state_leaf_0: Hash10Claim,
    pub state_leaf_1: Hash10Claim,
    pub state_leaf_2: Hash10Claim,
    pub state_leaf_3: Hash10Claim,
    pub state_leaf_4: Hash10Claim,
    pub state_subroot: Hash5Claim,
    pub state_root_from_path: Hash5Claim,
    pub vote_zero_root: Hash5Claim,
    pub vote_root_0: Hash5Claim,
    pub vote_root_1: Hash5Claim,
    pub vote_root_2: Hash5Claim,
    pub vote_root_3: Hash5Claim,
    pub vote_root_4: Hash5Claim,
    pub current_results_root: Hash5Claim,
    pub current_tally_commitment: Hash2Claim,
    pub new_results_root: Hash5Claim,
    pub new_tally_commitment: Hash2Claim,
}

#[derive(Copy, Drop, Serde)]
pub struct TallyWitness {
    pub state_root: u256,
    pub state_salt: u256,
    pub num_signups: u256,
    pub batch_num: u256,
    pub state_leaf_0: U256x10,
    pub state_leaf_1: U256x10,
    pub state_leaf_2: U256x10,
    pub state_leaf_3: U256x10,
    pub state_leaf_4: U256x10,
    pub state_path_elements: U256x4,
    pub votes_0: U256x5,
    pub votes_1: U256x5,
    pub votes_2: U256x5,
    pub votes_3: U256x5,
    pub votes_4: U256x5,
    pub current_results: U256x5,
    pub current_results_root_salt: u256,
    pub new_results_root_salt: u256,
    pub hashes: TallyHashTranscript,
}

fn assert_supported_batch_num(batch_num: u256) {
    assert(batch_num.high == 0, 'BATCH_HIGH');
    assert(batch_num.low < 5, 'BATCH_RANGE');
}

fn vote_root_field(state_leaf: U256x10) -> u256 {
    state_leaf.v3
}

fn select_expected_vote_root(state_leaf: U256x10, zero_root: u256) -> u256 {
    if is_zero(vote_root_field(state_leaf)) {
        zero_root
    } else {
        vote_root_field(state_leaf)
    }
}

fn assert_vote_root_matches(state_leaf: U256x10, vote_root: u256, zero_root: u256) {
    assert_u256_eq(vote_root, select_expected_vote_root(state_leaf, zero_root));
}

fn tally_vote(vote: u256) -> u256 {
    vote * (vote + MAX_VOTES)
}

fn current_result_base(is_first_batch: bool, current: u256) -> u256 {
    if is_first_batch {
        zero_u256()
    } else {
        current
    }
}

fn tally_option(
    current: u256, is_first_batch: bool, v0: u256, v1: u256, v2: u256, v3: u256, v4: u256,
) -> u256 {
    current_result_base(is_first_batch, current)
        + tally_vote(v0)
        + tally_vote(v1)
        + tally_vote(v2)
        + tally_vote(v3)
        + tally_vote(v4)
}

fn compute_new_results(witness: TallyWitness, is_first_batch: bool) -> U256x5 {
    U256x5 {
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

fn state_path_inputs(state_subroot: u256, path_elements: U256x4, batch_num: u256) -> U256x5 {
    if batch_num.low == 0 {
        U256x5 {
            v0: state_subroot,
            v1: path_elements.v0,
            v2: path_elements.v1,
            v3: path_elements.v2,
            v4: path_elements.v3,
        }
    } else if batch_num.low == 1 {
        U256x5 {
            v0: path_elements.v0,
            v1: state_subroot,
            v2: path_elements.v1,
            v3: path_elements.v2,
            v4: path_elements.v3,
        }
    } else if batch_num.low == 2 {
        U256x5 {
            v0: path_elements.v0,
            v1: path_elements.v1,
            v2: state_subroot,
            v3: path_elements.v2,
            v4: path_elements.v3,
        }
    } else if batch_num.low == 3 {
        U256x5 {
            v0: path_elements.v0,
            v1: path_elements.v1,
            v2: path_elements.v2,
            v3: state_subroot,
            v4: path_elements.v3,
        }
    } else {
        U256x5 {
            v0: path_elements.v0,
            v1: path_elements.v1,
            v2: path_elements.v2,
            v3: path_elements.v3,
            v4: state_subroot,
        }
    }
}

fn verify_tally_votes(fields: TallyPublicFields, witness: TallyWitness) {
    // packedVals = (numSignUps << 32) + batchNum.
    let packed_vals = witness.num_signups * TWO_POW_32 + witness.batch_num;
    assert_u256_eq(packed_vals, fields.packed_vals);
    assert_supported_batch_num(witness.batch_num);

    let batch_start_index = witness.batch_num * BATCH_SIZE;
    assert(batch_start_index <= witness.num_signups, 'BAD_NUM_SIGNUPS');
    let is_first_batch = is_zero(batch_start_index);

    let state_commitment = poseidon_hash2(
        witness.hashes.state_commitment, witness.state_root, witness.state_salt,
    );
    assert_u256_eq(state_commitment, fields.state_commitment);

    let input_hash = sha256_u256x4_mod_bn254(
        witness.hashes.input_hash,
        U256x4 {
            v0: fields.packed_vals,
            v1: fields.state_commitment,
            v2: fields.current_tally_commitment,
            v3: fields.new_tally_commitment,
        },
    );
    assert_u256_eq(input_hash, fields.input_hash);

    let zero_root = poseidon_hash5_or_zero_cache(
        witness.hashes.vote_zero_root,
        U256x5 { v0: 0, v1: 0, v2: 0, v3: 0, v4: 0 },
        POSEIDON5_ZERO_HASH,
    );
    let state_leaf_hash_0 = poseidon_hash10(witness.hashes.state_leaf_0, witness.state_leaf_0);
    let state_leaf_hash_1 = poseidon_hash10(witness.hashes.state_leaf_1, witness.state_leaf_1);
    let state_leaf_hash_2 = poseidon_hash10_or_zero_cache(
        witness.hashes.state_leaf_2,
        witness.state_leaf_2,
        POSEIDON5_ZERO_HASH,
        POSEIDON10_ZERO_HASH,
    );
    let state_leaf_hash_3 = poseidon_hash10_or_zero_cache(
        witness.hashes.state_leaf_3,
        witness.state_leaf_3,
        POSEIDON5_ZERO_HASH,
        POSEIDON10_ZERO_HASH,
    );
    let state_leaf_hash_4 = poseidon_hash10_or_zero_cache(
        witness.hashes.state_leaf_4,
        witness.state_leaf_4,
        POSEIDON5_ZERO_HASH,
        POSEIDON10_ZERO_HASH,
    );
    let state_subroot = poseidon_hash5(
        witness.hashes.state_subroot,
        U256x5 {
            v0: state_leaf_hash_0,
            v1: state_leaf_hash_1,
            v2: state_leaf_hash_2,
            v3: state_leaf_hash_3,
            v4: state_leaf_hash_4,
        },
    );
    let state_root_from_path = poseidon_hash5(
        witness.hashes.state_root_from_path,
        state_path_inputs(state_subroot, witness.state_path_elements, witness.batch_num),
    );
    assert_u256_eq(state_root_from_path, witness.state_root);

    let vote_root_0 = poseidon_hash5(witness.hashes.vote_root_0, witness.votes_0);
    let vote_root_1 = poseidon_hash5(witness.hashes.vote_root_1, witness.votes_1);
    let vote_root_2 = poseidon_hash5_or_zero_cache(
        witness.hashes.vote_root_2, witness.votes_2, zero_root,
    );
    let vote_root_3 = poseidon_hash5_or_zero_cache(
        witness.hashes.vote_root_3, witness.votes_3, zero_root,
    );
    let vote_root_4 = poseidon_hash5_or_zero_cache(
        witness.hashes.vote_root_4, witness.votes_4, zero_root,
    );
    assert_vote_root_matches(witness.state_leaf_0, vote_root_0, zero_root);
    assert_vote_root_matches(witness.state_leaf_1, vote_root_1, zero_root);
    assert_vote_root_matches(witness.state_leaf_2, vote_root_2, zero_root);
    assert_vote_root_matches(witness.state_leaf_3, vote_root_3, zero_root);
    assert_vote_root_matches(witness.state_leaf_4, vote_root_4, zero_root);

    if is_first_batch {
        assert_u256_eq(fields.current_tally_commitment, zero_u256());
    } else {
        let current_results_root = poseidon_hash5_or_zero_cache(
            witness.hashes.current_results_root, witness.current_results, zero_root,
        );
        let current_tally_commitment = poseidon_hash2(
            witness.hashes.current_tally_commitment,
            current_results_root,
            witness.current_results_root_salt,
        );
        assert_u256_eq(current_tally_commitment, fields.current_tally_commitment);
    }

    let new_results = compute_new_results(witness, is_first_batch);
    let new_results_root = poseidon_hash5(witness.hashes.new_results_root, new_results);
    let new_tally_commitment = poseidon_hash2(
        witness.hashes.new_tally_commitment, new_results_root, witness.new_results_root_salt,
    );
    assert_u256_eq(new_tally_commitment, fields.new_tally_commitment);
    assert_vector5_eq(new_results, witness.hashes.new_results_root.inputs);
}

#[executable]
pub fn main(fields: TallyPublicFields, witness: TallyWitness) -> TallyPublicOutput {
    verify_tally_votes(fields, witness);
    build_tally_public_output(fields)
}
