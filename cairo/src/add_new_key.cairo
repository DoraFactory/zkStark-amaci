use crate::babyjub::{
    BabyJubJubScalarMulWitness, assert_babyjub_add, babyjub_base8, verify_babyjub_scalar_mul,
};
use crate::hash_gates::{
    Hash2Claim, Hash5Claim, Sha256U256x9Claim, poseidon_hash2, poseidon_hash5,
    sha256_u256x9_mod_bn254,
};
use crate::poseidon_bn254::poseidon5_hash;
use crate::public_output::{
    AddNewKeyPublicFields, AddNewKeyPublicOutput, build_add_new_key_public_output,
};
use crate::types::{U256x2, U256x4, U256x5, U256x9, assert_u256_eq};

pub const DEACTIVATE_TREE_DEPTH: felt252 = 4;
pub const DEACTIVATE_TREE_LEAVES: u128 = 625;

#[derive(Copy, Drop, Serde)]
pub struct AddNewKeyHashTranscript {
    pub coord_pub_key_hash: Hash2Claim,
    pub new_pub_key_hash: Hash2Claim,
    pub nullifier: Hash2Claim,
    pub shared_key_hash: Hash2Claim,
    pub deactivate_leaf: Hash5Claim,
    pub input_hash: Sha256U256x9Claim,
}

#[derive(Drop, Serde)]
pub struct AddNewKeyWitness {
    pub coord_pub_key: U256x2,
    pub deactivate_index: u256,
    pub deactivate_leaf: u256,
    pub c1: U256x2,
    pub c2: U256x2,
    pub random_val: u256,
    pub deactivate_leaf_path_0: U256x4,
    pub deactivate_leaf_path_1: U256x4,
    pub deactivate_leaf_path_2: U256x4,
    pub deactivate_leaf_path_3: U256x4,
    pub old_private_key: u256,
    pub new_pub_key: U256x2,
    pub poll_id: u256,
    pub ecdh: BabyJubJubScalarMulWitness,
    pub random_base8: BabyJubJubScalarMulWitness,
    pub random_coord_pub_key: BabyJubJubScalarMulWitness,
    pub hashes: AddNewKeyHashTranscript,
}

fn assert_deactivate_index(value: u256) {
    assert(value.high == 0, 'BAD_DEACT_IDX_HIGH');
    assert(value.low < DEACTIVATE_TREE_LEAVES, 'BAD_DEACT_IDX');
}

fn path_inputs(leaf: u256, path_elements: U256x4, index: u128) -> U256x5 {
    if index == 0 {
        U256x5 {
            v0: leaf,
            v1: path_elements.v0,
            v2: path_elements.v1,
            v3: path_elements.v2,
            v4: path_elements.v3,
        }
    } else if index == 1 {
        U256x5 {
            v0: path_elements.v0,
            v1: leaf,
            v2: path_elements.v1,
            v3: path_elements.v2,
            v4: path_elements.v3,
        }
    } else if index == 2 {
        U256x5 {
            v0: path_elements.v0,
            v1: path_elements.v1,
            v2: leaf,
            v3: path_elements.v2,
            v4: path_elements.v3,
        }
    } else if index == 3 {
        U256x5 {
            v0: path_elements.v0,
            v1: path_elements.v1,
            v2: path_elements.v2,
            v3: leaf,
            v4: path_elements.v3,
        }
    } else {
        assert(index == 4, 'BAD_PATH_INDEX');
        U256x5 {
            v0: path_elements.v0,
            v1: path_elements.v1,
            v2: path_elements.v2,
            v3: path_elements.v3,
            v4: leaf,
        }
    }
}

fn quinary_root_depth_4(
    leaf: u256, path_0: U256x4, path_1: U256x4, path_2: U256x4, path_3: U256x4, index: u256,
) -> u256 {
    assert_deactivate_index(index);
    let level_0_index = index.low % 5;
    let level_1_index = (index.low / 5) % 5;
    let level_2_index = (index.low / 25) % 5;
    let level_3_index = index.low / 125;
    let level_0 = poseidon5_hash(path_inputs(leaf, path_0, level_0_index));
    let level_1 = poseidon5_hash(path_inputs(level_0, path_1, level_1_index));
    let level_2 = poseidon5_hash(path_inputs(level_1, path_2, level_2_index));
    poseidon5_hash(path_inputs(level_2, path_3, level_3_index))
}

fn assert_ecdh_shared_key(
    ecdh: BabyJubJubScalarMulWitness,
    old_private_key: u256,
    coord_pub_key: U256x2,
    claim: Hash2Claim,
) -> u256 {
    assert_u256_eq(ecdh.scalar, old_private_key);
    assert_u256_eq(ecdh.base.v0, coord_pub_key.v0);
    assert_u256_eq(ecdh.base.v1, coord_pub_key.v1);
    let shared_key = verify_babyjub_scalar_mul(ecdh);
    poseidon_hash2(claim, shared_key.v0, shared_key.v1)
}

fn assert_rerandomize(
    random_val: u256,
    coord_pub_key: U256x2,
    c1: U256x2,
    c2: U256x2,
    d1: U256x2,
    d2: U256x2,
    random_base8: BabyJubJubScalarMulWitness,
    random_coord_pub_key: BabyJubJubScalarMulWitness,
) {
    let base8 = babyjub_base8();
    assert_u256_eq(random_base8.scalar, random_val);
    assert_u256_eq(random_base8.base.v0, base8.v0);
    assert_u256_eq(random_base8.base.v1, base8.v1);
    let random_base8_point = verify_babyjub_scalar_mul(random_base8);
    assert_babyjub_add(random_base8_point, c1, d1);

    assert_u256_eq(random_coord_pub_key.scalar, random_val);
    assert_u256_eq(random_coord_pub_key.base.v0, coord_pub_key.v0);
    assert_u256_eq(random_coord_pub_key.base.v1, coord_pub_key.v1);
    let random_coord_pub_key_point = verify_babyjub_scalar_mul(random_coord_pub_key);
    assert_babyjub_add(random_coord_pub_key_point, c2, d2);
}

fn verify_add_new_key(fields: AddNewKeyPublicFields, witness: AddNewKeyWitness) {
    let coord_pub_key_hash = poseidon_hash2(
        witness.hashes.coord_pub_key_hash, witness.coord_pub_key.v0, witness.coord_pub_key.v1,
    );
    assert_u256_eq(coord_pub_key_hash, fields.coord_pub_key_hash);

    let new_pub_key_hash = poseidon_hash2(
        witness.hashes.new_pub_key_hash, witness.new_pub_key.v0, witness.new_pub_key.v1,
    );
    assert_u256_eq(new_pub_key_hash, fields.new_pub_key_hash);

    let nullifier = poseidon_hash2(
        witness.hashes.nullifier, witness.old_private_key, witness.poll_id,
    );
    assert_u256_eq(nullifier, fields.nullifier);

    let shared_key_hash = assert_ecdh_shared_key(
        witness.ecdh,
        witness.old_private_key,
        witness.coord_pub_key,
        witness.hashes.shared_key_hash,
    );
    let deactivate_leaf = poseidon_hash5(
        witness.hashes.deactivate_leaf,
        U256x5 {
            v0: witness.c1.v0,
            v1: witness.c1.v1,
            v2: witness.c2.v0,
            v3: witness.c2.v1,
            v4: shared_key_hash,
        },
    );
    assert_u256_eq(deactivate_leaf, witness.deactivate_leaf);

    let deactivate_root = quinary_root_depth_4(
        witness.deactivate_leaf,
        witness.deactivate_leaf_path_0,
        witness.deactivate_leaf_path_1,
        witness.deactivate_leaf_path_2,
        witness.deactivate_leaf_path_3,
        witness.deactivate_index,
    );
    assert_u256_eq(deactivate_root, fields.deactivate_root);

    assert_rerandomize(
        witness.random_val,
        witness.coord_pub_key,
        witness.c1,
        witness.c2,
        fields.d1,
        fields.d2,
        witness.random_base8,
        witness.random_coord_pub_key,
    );
    assert_u256_eq(witness.poll_id, fields.poll_id);

    let input_hash = sha256_u256x9_mod_bn254(
        witness.hashes.input_hash,
        U256x9 {
            v0: fields.deactivate_root,
            v1: fields.coord_pub_key_hash,
            v2: fields.nullifier,
            v3: fields.d1.v0,
            v4: fields.d1.v1,
            v5: fields.d2.v0,
            v6: fields.d2.v1,
            v7: fields.new_pub_key_hash,
            v8: fields.poll_id,
        },
    );
    assert_u256_eq(input_hash, fields.input_hash);
}

#[executable]
pub fn add_new_key_main(
    fields: AddNewKeyPublicFields, witness: AddNewKeyWitness,
) -> AddNewKeyPublicOutput {
    verify_add_new_key(fields, witness);
    build_add_new_key_public_output(fields)
}
