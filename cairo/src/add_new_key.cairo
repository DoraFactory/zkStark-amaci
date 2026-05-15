use core::poseidon::poseidon_hash_span;
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
pub const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
pub const ADD_NEW_KEY_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f4144445f4b45595f4e4154495645;
pub const STARKNET_POSEIDON_HASH_SCHEME: felt252 = 0x535441524b4e45545f504f534549444f4e;
pub const ADD_NEW_KEY_NATIVE_INPUT_HASH_DOMAIN: felt252 =
    0x414d4143495f4144445f4b45595f4e41544956455f494e505554;
pub const ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN: felt252 =
    0x414d4143495f4144445f4b45595f4e554c4c4946494552;

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

#[derive(Drop, Serde)]
pub struct NativeAddNewKeyWitness {
    pub legacy: AddNewKeyWitness,
    pub d1: U256x2,
    pub d2: U256x2,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeAddNewKeyPublicFields {
    pub deactivate_root_hash: felt252,
    pub coord_pub_key_hash: felt252,
    pub nullifier: felt252,
    pub d1_hash: felt252,
    pub d2_hash: felt252,
    pub new_pub_key_hash: felt252,
    pub poll_id: felt252,
    pub input_hash: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeAddNewKeyPublicOutput {
    pub magic: felt252,
    pub version: felt252,
    pub circuit_id: felt252,
    pub hash_scheme: felt252,
    pub state_tree_depth: felt252,
    pub deactivate_tree_depth: felt252,
    pub deactivate_root_hash: felt252,
    pub coord_pub_key_hash: felt252,
    pub nullifier: felt252,
    pub d1_hash: felt252,
    pub d2_hash: felt252,
    pub new_pub_key_hash: felt252,
    pub poll_id: felt252,
    pub input_hash: felt252,
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

fn felt_from_u128(value: u128) -> felt252 {
    value.into()
}

fn native_hash_u256(value: u256) -> felt252 {
    poseidon_hash_span([felt_from_u128(value.low), felt_from_u128(value.high)].span())
}

fn native_hash_u256x2(value: U256x2) -> felt252 {
    poseidon_hash_span(
        [
            felt_from_u128(value.v0.low),
            felt_from_u128(value.v0.high),
            felt_from_u128(value.v1.low),
            felt_from_u128(value.v1.high),
        ]
            .span(),
    )
}

fn native_nullifier(old_private_key: u256, poll_id: u256) -> felt252 {
    poseidon_hash_span(
        [
            ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN,
            felt_from_u128(old_private_key.low),
            felt_from_u128(old_private_key.high),
            felt_from_u128(poll_id.low),
            felt_from_u128(poll_id.high),
        ]
            .span(),
    )
}

fn native_input_hash(fields: NativeAddNewKeyPublicFields) -> felt252 {
    poseidon_hash_span(
        [
            ADD_NEW_KEY_NATIVE_INPUT_HASH_DOMAIN,
            fields.deactivate_root_hash,
            fields.coord_pub_key_hash,
            fields.nullifier,
            fields.d1_hash,
            fields.d2_hash,
            fields.new_pub_key_hash,
            fields.poll_id,
        ]
            .span(),
    )
}

fn verify_native_add_new_key(fields: NativeAddNewKeyPublicFields, witness: NativeAddNewKeyWitness) {
    let legacy = witness.legacy;
    assert(native_hash_u256x2(legacy.coord_pub_key) == fields.coord_pub_key_hash, 'N_COORD_KEY');
    assert(native_hash_u256x2(legacy.new_pub_key) == fields.new_pub_key_hash, 'N_NEW_KEY');
    assert(native_nullifier(legacy.old_private_key, legacy.poll_id) == fields.nullifier, 'N_NULLIFIER');
    assert(native_hash_u256x2(witness.d1) == fields.d1_hash, 'N_D1');
    assert(native_hash_u256x2(witness.d2) == fields.d2_hash, 'N_D2');
    assert(legacy.poll_id.high == 0, 'N_POLL_HIGH');
    assert(felt_from_u128(legacy.poll_id.low) == fields.poll_id, 'N_POLL_ID');
    assert(native_input_hash(fields) == fields.input_hash, 'N_INPUT_HASH');

    assert_u256_eq(legacy.ecdh.scalar, legacy.old_private_key);
    assert_u256_eq(legacy.ecdh.base.v0, legacy.coord_pub_key.v0);
    assert_u256_eq(legacy.ecdh.base.v1, legacy.coord_pub_key.v1);
    let shared_key = verify_babyjub_scalar_mul(legacy.ecdh);
    let shared_key_hash = poseidon_hash2(
        legacy.hashes.shared_key_hash, shared_key.v0, shared_key.v1,
    );
    let deactivate_leaf = poseidon_hash5(
        legacy.hashes.deactivate_leaf,
        U256x5 {
            v0: legacy.c1.v0,
            v1: legacy.c1.v1,
            v2: legacy.c2.v0,
            v3: legacy.c2.v1,
            v4: shared_key_hash,
        },
    );
    assert_u256_eq(deactivate_leaf, legacy.deactivate_leaf);
    let deactivate_root = quinary_root_depth_4(
        legacy.deactivate_leaf,
        legacy.deactivate_leaf_path_0,
        legacy.deactivate_leaf_path_1,
        legacy.deactivate_leaf_path_2,
        legacy.deactivate_leaf_path_3,
        legacy.deactivate_index,
    );
    assert(native_hash_u256(deactivate_root) == fields.deactivate_root_hash, 'N_DEACT_ROOT');

    assert_rerandomize(
        legacy.random_val,
        legacy.coord_pub_key,
        legacy.c1,
        legacy.c2,
        witness.d1,
        witness.d2,
        legacy.random_base8,
        legacy.random_coord_pub_key,
    );
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

fn build_native_add_new_key_public_output(
    fields: NativeAddNewKeyPublicFields,
) -> NativeAddNewKeyPublicOutput {
    NativeAddNewKeyPublicOutput {
        magic: crate::public_output::PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: ADD_NEW_KEY_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        deactivate_tree_depth: DEACTIVATE_TREE_DEPTH,
        deactivate_root_hash: fields.deactivate_root_hash,
        coord_pub_key_hash: fields.coord_pub_key_hash,
        nullifier: fields.nullifier,
        d1_hash: fields.d1_hash,
        d2_hash: fields.d2_hash,
        new_pub_key_hash: fields.new_pub_key_hash,
        poll_id: fields.poll_id,
        input_hash: fields.input_hash,
    }
}

#[executable]
pub fn add_new_key_native_main(
    fields: NativeAddNewKeyPublicFields, witness: NativeAddNewKeyWitness,
) -> NativeAddNewKeyPublicOutput {
    verify_native_add_new_key(fields, witness);
    build_native_add_new_key_public_output(fields)
}
