use core::hash::HashStateTrait;
use core::poseidon::PoseidonTrait;

const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b;
const DEACTIVATE_TREE_DEPTH: felt252 = 4;
const DEACTIVATE_TREE_LEAVES: u128 = 625;
const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
const ADD_NEW_KEY_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f4144445f4b45595f4e4154495645;
const STARKNET_POSEIDON_HASH_SCHEME: felt252 = 0x535441524b4e45545f504f534549444f4e;
const ADD_NEW_KEY_NATIVE_INPUT_HASH_DOMAIN: felt252 =
    0x414d4143495f4144445f4b45595f4e41544956455f494e505554;
const ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN: felt252 =
    0x414d4143495f4144445f4b45595f4e554c4c4946494552;
const ADD_NEW_KEY_NATIVE_DEACTIVATE_LEAF_DOMAIN: felt252 =
    0x414d4143495f4144445f4b45595f44454143545f4c454146;
const ADD_NEW_KEY_NATIVE_RERANDOMIZE_DOMAIN: felt252 =
    0x414d4143495f4144445f4b45595f524552414e44;
const FELT_TWO_POW_128: felt252 = 0x100000000000000000000000000000000;

#[derive(Copy, Drop, Serde)]
pub struct U256x2 {
    pub v0: u256,
    pub v1: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct U256x4 {
    pub v0: u256,
    pub v1: u256,
    pub v2: u256,
    pub v3: u256,
}

#[derive(Drop, Serde)]
pub struct NativeAddNewKeyWitness {
    pub coord_pub_key: U256x2,
    pub deactivate_index: u256,
    pub c1: U256x2,
    pub c2: U256x2,
    pub shared_key: U256x2,
    pub deactivate_leaf_path_0: U256x4,
    pub deactivate_leaf_path_1: U256x4,
    pub deactivate_leaf_path_2: U256x4,
    pub deactivate_leaf_path_3: U256x4,
    pub old_private_key: u256,
    pub new_pub_key: U256x2,
    pub poll_id: u256,
    pub d1: U256x2,
    pub d2: U256x2,
}

#[derive(Copy, Drop, Serde)]
pub struct NativeAddNewKeyPublicFields {
    pub deactivate_root_hash: felt252,
    pub coord_pub_key_hash: felt252,
    pub nullifier: felt252,
    pub c1_hash: felt252,
    pub c2_hash: felt252,
    pub shared_key_hash: felt252,
    pub deactivate_leaf_hash: felt252,
    pub d1_hash: felt252,
    pub d2_hash: felt252,
    pub rerandomize_binding_hash: felt252,
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
    pub c1_hash: felt252,
    pub c2_hash: felt252,
    pub shared_key_hash: felt252,
    pub deactivate_leaf_hash: felt252,
    pub d1_hash: felt252,
    pub d2_hash: felt252,
    pub rerandomize_binding_hash: felt252,
    pub new_pub_key_hash: felt252,
    pub poll_id: felt252,
    pub input_hash: felt252,
}

fn assert_deactivate_index(value: u256) {
    assert(value.high == 0, 'BAD_DEACT_IDX_HIGH');
    assert(value.low < DEACTIVATE_TREE_LEAVES, 'BAD_DEACT_IDX');
}

fn felt_from_u128(value: u128) -> felt252 {
    value.into()
}

fn felt_from_u256(value: u256) -> felt252 {
    felt_from_u128(value.low) + felt_from_u128(value.high) * FELT_TWO_POW_128
}

fn native_hash_u256x2(value: U256x2) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(felt_from_u256(value.v0));
    state = state.update(felt_from_u256(value.v1));
    state.finalize()
}

fn native_hash5_values(v0: felt252, v1: felt252, v2: felt252, v3: felt252, v4: felt252) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(v0);
    state = state.update(v1);
    state = state.update(v2);
    state = state.update(v3);
    state = state.update(v4);
    state.finalize()
}

fn native_nullifier(old_private_key: u256, poll_id: u256) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN);
    state = state.update(felt_from_u256(old_private_key));
    state = state.update(felt_from_u256(poll_id));
    state.finalize()
}

fn native_deactivate_leaf_hash(
    c1_hash: felt252, c2_hash: felt252, shared_key_hash: felt252,
) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(ADD_NEW_KEY_NATIVE_DEACTIVATE_LEAF_DOMAIN);
    state = state.update(c1_hash);
    state = state.update(c2_hash);
    state = state.update(shared_key_hash);
    state.finalize()
}

fn native_rerandomize_binding_hash(
    coord_pub_key_hash: felt252,
    c1_hash: felt252,
    c2_hash: felt252,
    d1_hash: felt252,
    d2_hash: felt252,
) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(ADD_NEW_KEY_NATIVE_RERANDOMIZE_DOMAIN);
    state = state.update(coord_pub_key_hash);
    state = state.update(c1_hash);
    state = state.update(c2_hash);
    state = state.update(d1_hash);
    state = state.update(d2_hash);
    state.finalize()
}

fn native_path_hash(leaf: felt252, path_elements: U256x4, index: u128) -> felt252 {
    let p0 = felt_from_u256(path_elements.v0);
    let p1 = felt_from_u256(path_elements.v1);
    let p2 = felt_from_u256(path_elements.v2);
    let p3 = felt_from_u256(path_elements.v3);
    if index == 0 {
        native_hash5_values(leaf, p0, p1, p2, p3)
    } else if index == 1 {
        native_hash5_values(p0, leaf, p1, p2, p3)
    } else if index == 2 {
        native_hash5_values(p0, p1, leaf, p2, p3)
    } else if index == 3 {
        native_hash5_values(p0, p1, p2, leaf, p3)
    } else {
        assert(index == 4, 'BAD_PATH_INDEX');
        native_hash5_values(p0, p1, p2, p3, leaf)
    }
}

fn native_quinary_root_depth_4(
    leaf: felt252, path_0: U256x4, path_1: U256x4, path_2: U256x4, path_3: U256x4, index: u256,
) -> felt252 {
    assert_deactivate_index(index);
    let level_0_index = index.low % 5;
    let level_1_index = (index.low / 5) % 5;
    let level_2_index = (index.low / 25) % 5;
    let level_3_index = index.low / 125;
    let level_0 = native_path_hash(leaf, path_0, level_0_index);
    let level_1 = native_path_hash(level_0, path_1, level_1_index);
    let level_2 = native_path_hash(level_1, path_2, level_2_index);
    native_path_hash(level_2, path_3, level_3_index)
}

fn native_input_hash(fields: NativeAddNewKeyPublicFields) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(ADD_NEW_KEY_NATIVE_INPUT_HASH_DOMAIN);
    state = state.update(fields.deactivate_root_hash);
    state = state.update(fields.coord_pub_key_hash);
    state = state.update(fields.nullifier);
    state = state.update(fields.c1_hash);
    state = state.update(fields.c2_hash);
    state = state.update(fields.shared_key_hash);
    state = state.update(fields.deactivate_leaf_hash);
    state = state.update(fields.d1_hash);
    state = state.update(fields.d2_hash);
    state = state.update(fields.rerandomize_binding_hash);
    state = state.update(fields.new_pub_key_hash);
    state = state.update(fields.poll_id);
    state.finalize()
}

fn verify_native_add_new_key(fields: NativeAddNewKeyPublicFields, witness: NativeAddNewKeyWitness) {
    assert(native_hash_u256x2(witness.coord_pub_key) == fields.coord_pub_key_hash, 'N_COORD_KEY');
    assert(native_hash_u256x2(witness.new_pub_key) == fields.new_pub_key_hash, 'N_NEW_KEY');
    assert(native_nullifier(witness.old_private_key, witness.poll_id) == fields.nullifier, 'N_NULLIFIER');
    assert(native_hash_u256x2(witness.c1) == fields.c1_hash, 'N_C1');
    assert(native_hash_u256x2(witness.c2) == fields.c2_hash, 'N_C2');
    assert(native_hash_u256x2(witness.shared_key) == fields.shared_key_hash, 'N_SHARED');
    assert(
        native_deactivate_leaf_hash(fields.c1_hash, fields.c2_hash, fields.shared_key_hash)
            == fields.deactivate_leaf_hash,
        'N_DEACT_LEAF',
    );
    assert(native_hash_u256x2(witness.d1) == fields.d1_hash, 'N_D1');
    assert(native_hash_u256x2(witness.d2) == fields.d2_hash, 'N_D2');
    assert(
        native_rerandomize_binding_hash(
            fields.coord_pub_key_hash, fields.c1_hash, fields.c2_hash, fields.d1_hash, fields.d2_hash,
        ) == fields.rerandomize_binding_hash,
        'N_RERAND_BIND',
    );
    assert(witness.poll_id.high == 0, 'N_POLL_HIGH');
    assert(felt_from_u128(witness.poll_id.low) == fields.poll_id, 'N_POLL_ID');
    assert(native_input_hash(fields) == fields.input_hash, 'N_INPUT_HASH');

    let deactivate_root = native_quinary_root_depth_4(
        fields.deactivate_leaf_hash,
        witness.deactivate_leaf_path_0,
        witness.deactivate_leaf_path_1,
        witness.deactivate_leaf_path_2,
        witness.deactivate_leaf_path_3,
        witness.deactivate_index,
    );
    assert(deactivate_root == fields.deactivate_root_hash, 'N_DEACT_ROOT');
}

fn build_native_add_new_key_public_output(
    fields: NativeAddNewKeyPublicFields,
) -> NativeAddNewKeyPublicOutput {
    NativeAddNewKeyPublicOutput {
        magic: PUBLIC_OUTPUT_MAGIC,
        version: NATIVE_PUBLIC_OUTPUT_VERSION,
        circuit_id: ADD_NEW_KEY_NATIVE_CIRCUIT_ID,
        hash_scheme: STARKNET_POSEIDON_HASH_SCHEME,
        state_tree_depth: 2,
        deactivate_tree_depth: DEACTIVATE_TREE_DEPTH,
        deactivate_root_hash: fields.deactivate_root_hash,
        coord_pub_key_hash: fields.coord_pub_key_hash,
        nullifier: fields.nullifier,
        c1_hash: fields.c1_hash,
        c2_hash: fields.c2_hash,
        shared_key_hash: fields.shared_key_hash,
        deactivate_leaf_hash: fields.deactivate_leaf_hash,
        d1_hash: fields.d1_hash,
        d2_hash: fields.d2_hash,
        rerandomize_binding_hash: fields.rerandomize_binding_hash,
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
