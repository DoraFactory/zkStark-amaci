use crate::babyjub::{
    BabyJubJubPoseidonSignatureWitness, BabyJubJubScalarMulWitness, assert_babyjub_add,
    babyjub_base8, verify_babyjub_poseidon_signature, verify_babyjub_scalar_mul,
};
use crate::hash_gates::{
    Hash10Claim, Hash13Claim, Hash2Claim, Hash5Claim, Sha256U256x8Claim, poseidon_hash10,
    poseidon_hash13, poseidon_hash2, poseidon_hash5, sha256_u256x8_mod_bn254,
};
use crate::poseidon_bn254::{PoseidonT4State, field_sub_mod, poseidon4_permutation, poseidon5_hash};
use crate::public_output::{
    ProcessDeactivatePublicFields, ProcessDeactivatePublicOutput, ProcessDeactivateStepPublicFields,
    ProcessDeactivateStepPublicOutput, build_process_deactivate_public_output,
    build_process_deactivate_step_public_output,
};
use crate::types::{
    U256x10, U256x2, U256x3, U256x4, U256x5, U256x7, U256x8, assert_u256_eq, is_zero,
    u256x10_first5, u256x10_second5, zero_u256,
};

pub const TWO_POW_32: u256 = 0x100000000;
pub const POSEIDON_DECRYPT_7_DOMAIN: u256 = 0x700000000000000000000000000000000;
pub const U128_TWO_POW_32: u128 = 0x100000000;
pub const U128_TWO_POW_64: u128 = 0x10000000000000000;
pub const U128_TWO_POW_96: u128 = 0x1000000000000000000000000;
pub const STATE_TREE_LEAVES: u128 = 25;
pub const STATE_TREE_MAX_INDEX: u256 = 24;
pub const DEACTIVATE_TREE_LEAVES: u128 = 625;

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivateOneHashTranscript {
    pub state_leaf_hash: Hash10Claim,
    pub shared_key_hash: Hash2Claim,
    pub deactivate_leaf: Hash5Claim,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivateMessagesHashTranscript {
    pub coord_pub_key_hash: Hash2Claim,
    pub input_hash: Sha256U256x8Claim,
    pub current_deactivate_commitment: Hash2Claim,
    pub message_hash_0: Hash13Claim,
    pub message_hash_1: Hash13Claim,
    pub message_hash_2: Hash13Claim,
    pub message_hash_3: Hash13Claim,
    pub message_hash_4: Hash13Claim,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivateMessagesBoundaryWitness {
    pub coord_pub_key: U256x2,
    pub current_active_state_root: u256,
    pub current_deactivate_root: u256,
    pub batch_start_hash: u256,
    pub batch_end_hash: u256,
    pub current_state_root: u256,
    pub expected_poll_id: u256,
    pub msg_0: U256x10,
    pub msg_1: U256x10,
    pub msg_2: U256x10,
    pub msg_3: U256x10,
    pub msg_4: U256x10,
    pub enc_pub_key_0: U256x2,
    pub enc_pub_key_1: U256x2,
    pub enc_pub_key_2: U256x2,
    pub enc_pub_key_3: U256x2,
    pub enc_pub_key_4: U256x2,
    pub hashes: ProcessDeactivateMessagesHashTranscript,
}

#[derive(Drop, Serde)]
pub struct ProcessDeactivateMessagesStateTransitionWitness {
    pub coord_priv_key: u256,
    pub current_state_root: u256,
    pub current_active_state_root: u256,
    pub current_deactivate_root: u256,
    pub expected_poll_id: u256,
    pub deactivate_index_0: u256,
    pub process_one_0: ProcessDeactivateOneWitness,
    pub process_one_1: ProcessDeactivateOneWitness,
    pub process_one_2: ProcessDeactivateOneWitness,
    pub process_one_3: ProcessDeactivateOneWitness,
    pub process_one_4: ProcessDeactivateOneWitness,
}

#[derive(Drop, Serde)]
pub struct ProcessDeactivateMessagesStatefulWitness {
    pub boundary: ProcessDeactivateMessagesBoundaryWitness,
    pub state_transition: ProcessDeactivateMessagesStateTransitionWitness,
    pub coord_pub_key: BabyJubJubScalarMulWitness,
    pub command_0: ProcessDeactivateMessageCommandWitness,
    pub command_1: ProcessDeactivateMessageCommandWitness,
    pub command_2: ProcessDeactivateMessageCommandWitness,
    pub command_3: ProcessDeactivateMessageCommandWitness,
    pub command_4: ProcessDeactivateMessageCommandWitness,
    pub new_deactivate_commitment: Hash2Claim,
}

#[derive(Drop, Serde)]
pub struct ProcessDeactivateMessageStepWitness {
    pub coord_pub_key: U256x2,
    pub msg: U256x10,
    pub enc_pub_key: U256x2,
    pub coord_priv_key: u256,
    pub coord_pub_key_scalar_mul: BabyJubJubScalarMulWitness,
    pub coord_pub_key_hash: Hash2Claim,
    pub message_hash: Hash13Claim,
    pub command: ProcessDeactivateMessageCommandWitness,
    pub process_one: ProcessDeactivateOneWitness,
    pub current_deactivate_commitment: Hash2Claim,
    pub new_deactivate_commitment: Hash2Claim,
}

#[derive(Drop, Serde)]
pub struct ElGamalDecryptWitness {
    pub scalar_mul: BabyJubJubScalarMulWitness,
    pub decrypted_point: U256x2,
}

#[derive(Drop, Serde)]
pub struct ProcessDeactivateOneWitness {
    pub is_empty_msg: u256,
    pub coord_priv_key: u256,
    pub current_state_root: u256,
    pub c1: U256x2,
    pub c2: U256x2,
    pub current_active_state_root: u256,
    pub current_deactivate_root: u256,
    pub state_leaf: U256x10,
    pub state_leaf_path_0: U256x4,
    pub state_leaf_path_1: U256x4,
    pub active_state_leaf_path_0: U256x4,
    pub active_state_leaf_path_1: U256x4,
    pub current_active_state: u256,
    pub new_active_state: u256,
    pub cmd_state_index: u256,
    pub cmd_poll_id: u256,
    pub cmd_sig_r8: U256x2,
    pub cmd_sig_s: u256,
    pub packed_cmd: U256x3,
    pub expected_poll_id: u256,
    pub deactivate_index: u256,
    pub deactivate_leaf_path_0: U256x4,
    pub deactivate_leaf_path_1: U256x4,
    pub deactivate_leaf_path_2: U256x4,
    pub deactivate_leaf_path_3: U256x4,
    pub current_state_decrypt: ElGamalDecryptWitness,
    pub new_state_decrypt: ElGamalDecryptWitness,
    pub deactivate_ecdh: BabyJubJubScalarMulWitness,
    pub signature: BabyJubJubPoseidonSignatureWitness,
    pub hashes: ProcessDeactivateOneHashTranscript,
}

#[derive(Drop, Serde)]
pub struct ProcessDeactivateMessageCommandWitness {
    pub ecdh: BabyJubJubScalarMulWitness,
    pub decrypted_command: U256x7,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivateOneOutput {
    pub new_active_state_root: u256,
    pub new_deactivate_root: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct ProcessDeactivateMessagesStateOutput {
    pub new_active_state_root: u256,
    pub new_deactivate_root: u256,
}

fn assert_bool_u256(value: u256) {
    assert(value.high == 0, 'BOOL_HIGH');
    assert(value.low < 2, 'BOOL_RANGE');
}

fn bool_to_u256(value: bool) -> u256 {
    if value {
        1
    } else {
        0
    }
}

fn u256_bool(value: u256) -> bool {
    assert_bool_u256(value);
    value.low == 1
}

fn select_u256(selected: bool, if_false: u256, if_true: u256) -> u256 {
    if selected {
        if_true
    } else {
        if_false
    }
}

fn assert_deactivate_index(value: u256) {
    assert(value.high == 0, 'DEACT_IDX_HIGH');
    assert(value.low < DEACTIVATE_TREE_LEAVES, 'DEACT_IDX_RANGE');
}

fn assert_state_index(value: u256) {
    assert(value.high == 0, 'STATE_IDX_HIGH');
    assert(value.low < STATE_TREE_LEAVES, 'STATE_IDX_RANGE');
}

fn valid_state_index(value: u256) -> bool {
    value.high == 0 && value.low < STATE_TREE_LEAVES
}

fn unpack_command_data(packed_data: u256) -> U256x7 {
    U256x7 {
        v0: ((packed_data.high / U128_TWO_POW_64) % U128_TWO_POW_32).into(),
        v1: ((packed_data.high / U128_TWO_POW_32) % U128_TWO_POW_32).into(),
        v2: (packed_data.high % U128_TWO_POW_32).into(),
        v3: (packed_data.low / U128_TWO_POW_96).into(),
        v4: ((packed_data.low / U128_TWO_POW_64) % U128_TWO_POW_32).into(),
        v5: ((packed_data.low / U128_TWO_POW_32) % U128_TWO_POW_32).into(),
        v6: (packed_data.low % U128_TWO_POW_32).into(),
    }
}

fn poseidon_decrypt_initial_state(shared_key: U256x2) -> PoseidonT4State {
    poseidon4_permutation(
        PoseidonT4State {
            x0: zero_u256(), x1: shared_key.v0, x2: shared_key.v1, x3: POSEIDON_DECRYPT_7_DOMAIN,
        },
    )
}

fn poseidon_decrypt_next_state(
    state: PoseidonT4State, c0: u256, c1: u256, c2: u256,
) -> PoseidonT4State {
    poseidon4_permutation(PoseidonT4State { x0: state.x0, x1: c0, x2: c1, x3: c2 })
}

fn validate_poseidon_decryption(msg: U256x10, shared_key: U256x2, decrypted_command: U256x7) {
    let state_0 = poseidon_decrypt_initial_state(shared_key);
    assert_u256_eq(decrypted_command.v0, field_sub_mod(msg.v0, state_0.x1));
    assert_u256_eq(decrypted_command.v1, field_sub_mod(msg.v1, state_0.x2));
    assert_u256_eq(decrypted_command.v2, field_sub_mod(msg.v2, state_0.x3));

    let state_1 = poseidon_decrypt_next_state(state_0, msg.v0, msg.v1, msg.v2);
    assert_u256_eq(decrypted_command.v3, field_sub_mod(msg.v3, state_1.x1));
    assert_u256_eq(decrypted_command.v4, field_sub_mod(msg.v4, state_1.x2));
    assert_u256_eq(decrypted_command.v5, field_sub_mod(msg.v5, state_1.x3));

    let state_2 = poseidon_decrypt_next_state(state_1, msg.v3, msg.v4, msg.v5);
    assert_u256_eq(decrypted_command.v6, field_sub_mod(msg.v6, state_2.x1));
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

fn quinary_root_depth_2(leaf: u256, path_0: U256x4, path_1: U256x4, index: u256) -> u256 {
    assert_state_index(index);
    let level_0_index = index.low % 5;
    let level_1_index = index.low / 5;
    let level_0 = poseidon5_hash(path_inputs(leaf, path_0, level_0_index));
    poseidon5_hash(path_inputs(level_0, path_1, level_1_index))
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

fn is_odd_u256(value: u256) -> bool {
    value.low % 2 == 1
}

fn assert_elgamal_decrypt(
    witness: ElGamalDecryptWitness, coord_priv_key: u256, c1: U256x2, c2: U256x2,
) -> bool {
    let scalar_mul = witness.scalar_mul;
    let decrypted_point = witness.decrypted_point;
    assert_u256_eq(scalar_mul.scalar, coord_priv_key);
    assert_u256_eq(scalar_mul.base.v0, c1.v0);
    assert_u256_eq(scalar_mul.base.v1, c1.v1);
    let c1x = verify_babyjub_scalar_mul(scalar_mul);
    let c1x_inverse = U256x2 { v0: field_sub_mod(zero_u256(), c1x.v0), v1: c1x.v1 };
    assert_babyjub_add(c1x_inverse, c2, decrypted_point);
    is_odd_u256(decrypted_point.v0)
}

fn assert_deactivate_ecdh(
    witness: BabyJubJubScalarMulWitness, coord_priv_key: u256, pub_key: U256x2, claim: Hash2Claim,
) -> u256 {
    assert_u256_eq(witness.scalar, coord_priv_key);
    assert_u256_eq(witness.base.v0, pub_key.v0);
    assert_u256_eq(witness.base.v1, pub_key.v1);
    let shared_key = verify_babyjub_scalar_mul(witness);
    poseidon_hash2(claim, shared_key.v0, shared_key.v1)
}

fn process_deactivate_message_hash(
    claim: Hash13Claim, msg: U256x10, enc_pub_key: U256x2, prev_hash: u256,
) -> u256 {
    poseidon_hash13(
        claim, u256x10_first5(msg), u256x10_second5(msg), enc_pub_key.v0, enc_pub_key.v1, prev_hash,
    )
}

fn process_deactivate_message_hash_chain_step(
    msg: U256x10, enc_pub_key: U256x2, prev_hash: u256, claim: Hash13Claim,
) -> u256 {
    if is_zero(msg.v0) {
        prev_hash
    } else {
        let message_hash = process_deactivate_message_hash(claim, msg, enc_pub_key, prev_hash);
        message_hash
    }
}

fn verify_process_deactivate_boundary(
    fields: ProcessDeactivatePublicFields, witness: ProcessDeactivateMessagesBoundaryWitness,
) {
    let coord_pub_key_hash = poseidon_hash2(
        witness.hashes.coord_pub_key_hash, witness.coord_pub_key.v0, witness.coord_pub_key.v1,
    );
    assert_u256_eq(coord_pub_key_hash, fields.coord_pub_key_hash);

    let current_deactivate_commitment = poseidon_hash2(
        witness.hashes.current_deactivate_commitment,
        witness.current_active_state_root,
        witness.current_deactivate_root,
    );
    assert_u256_eq(current_deactivate_commitment, fields.current_deactivate_commitment);
    assert_u256_eq(witness.batch_start_hash, fields.batch_start_hash);
    assert_u256_eq(witness.batch_end_hash, fields.batch_end_hash);
    assert_u256_eq(witness.current_state_root, fields.current_state_root);
    assert_u256_eq(witness.expected_poll_id, fields.expected_poll_id);

    let input_hash = sha256_u256x8_mod_bn254(
        witness.hashes.input_hash,
        U256x8 {
            v0: fields.new_deactivate_root,
            v1: fields.coord_pub_key_hash,
            v2: fields.batch_start_hash,
            v3: fields.batch_end_hash,
            v4: fields.current_deactivate_commitment,
            v5: fields.new_deactivate_commitment,
            v6: fields.current_state_root,
            v7: fields.expected_poll_id,
        },
    );
    assert_u256_eq(input_hash, fields.input_hash);

    let hash_1 = process_deactivate_message_hash_chain_step(
        witness.msg_0,
        witness.enc_pub_key_0,
        witness.batch_start_hash,
        witness.hashes.message_hash_0,
    );
    let hash_2 = process_deactivate_message_hash_chain_step(
        witness.msg_1, witness.enc_pub_key_1, hash_1, witness.hashes.message_hash_1,
    );
    let hash_3 = process_deactivate_message_hash_chain_step(
        witness.msg_2, witness.enc_pub_key_2, hash_2, witness.hashes.message_hash_2,
    );
    let hash_4 = process_deactivate_message_hash_chain_step(
        witness.msg_3, witness.enc_pub_key_3, hash_3, witness.hashes.message_hash_3,
    );
    let hash_5 = process_deactivate_message_hash_chain_step(
        witness.msg_4, witness.enc_pub_key_4, hash_4, witness.hashes.message_hash_4,
    );
    assert_u256_eq(hash_5, witness.batch_end_hash);
}

fn assert_coord_pub_key_matches_private_key(
    coord_priv_key: u256, coord_pub_key: U256x2, witness: BabyJubJubScalarMulWitness,
) {
    let base8 = babyjub_base8();
    assert_u256_eq(witness.scalar, coord_priv_key);
    assert_u256_eq(witness.base.v0, base8.v0);
    assert_u256_eq(witness.base.v1, base8.v1);
    let derived_pub_key = verify_babyjub_scalar_mul(witness);
    assert_u256_eq(derived_pub_key.v0, coord_pub_key.v0);
    assert_u256_eq(derived_pub_key.v1, coord_pub_key.v1);
}

fn process_deactivate_one(witness: ProcessDeactivateOneWitness) -> ProcessDeactivateOneOutput {
    let is_empty_msg = u256_bool(witness.is_empty_msg);
    let pub_key = U256x2 { v0: witness.state_leaf.v0, v1: witness.state_leaf.v1 };
    let signature_valid = verify_babyjub_poseidon_signature(
        pub_key, witness.cmd_sig_r8, witness.cmd_sig_s, witness.packed_cmd, witness.signature,
    ) == 1;
    let current_decrypt_is_odd = assert_elgamal_decrypt(
        witness.current_state_decrypt,
        witness.coord_priv_key,
        U256x2 { v0: witness.state_leaf.v5, v1: witness.state_leaf.v6 },
        U256x2 { v0: witness.state_leaf.v7, v1: witness.state_leaf.v8 },
    );
    let valid_poll_id = witness.cmd_poll_id == witness.expected_poll_id;
    let valid = signature_valid && !current_decrypt_is_odd && valid_poll_id;

    let new_decrypt_is_odd = assert_elgamal_decrypt(
        witness.new_state_decrypt, witness.coord_priv_key, witness.c1, witness.c2,
    );
    assert_u256_eq(bool_to_u256(valid), bool_to_u256(!new_decrypt_is_odd));

    let state_index = select_u256(
        valid_state_index(witness.cmd_state_index), STATE_TREE_MAX_INDEX, witness.cmd_state_index,
    );
    let state_leaf_hash = poseidon_hash10(witness.hashes.state_leaf_hash, witness.state_leaf);
    let current_state_root = quinary_root_depth_2(
        state_leaf_hash, witness.state_leaf_path_0, witness.state_leaf_path_1, state_index,
    );
    assert_u256_eq(current_state_root, witness.current_state_root);

    let shared_key_hash = assert_deactivate_ecdh(
        witness.deactivate_ecdh, witness.coord_priv_key, pub_key, witness.hashes.shared_key_hash,
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

    assert(!is_zero(witness.new_active_state), 'NEW_ACTIVE_ZERO');
    let current_active_state_root = quinary_root_depth_2(
        witness.current_active_state,
        witness.active_state_leaf_path_0,
        witness.active_state_leaf_path_1,
        state_index,
    );
    assert_u256_eq(current_active_state_root, witness.current_active_state_root);
    let active_state_leaf = select_u256(
        valid, witness.current_active_state, witness.new_active_state,
    );
    let new_active_state_root = quinary_root_depth_2(
        active_state_leaf,
        witness.active_state_leaf_path_0,
        witness.active_state_leaf_path_1,
        state_index,
    );

    let current_deactivate_root = quinary_root_depth_4(
        zero_u256(),
        witness.deactivate_leaf_path_0,
        witness.deactivate_leaf_path_1,
        witness.deactivate_leaf_path_2,
        witness.deactivate_leaf_path_3,
        witness.deactivate_index,
    );
    assert_u256_eq(current_deactivate_root, witness.current_deactivate_root);
    let new_deactivate_leaf = select_u256(is_empty_msg, deactivate_leaf, zero_u256());
    let new_deactivate_root = quinary_root_depth_4(
        new_deactivate_leaf,
        witness.deactivate_leaf_path_0,
        witness.deactivate_leaf_path_1,
        witness.deactivate_leaf_path_2,
        witness.deactivate_leaf_path_3,
        witness.deactivate_index,
    );

    ProcessDeactivateOneOutput { new_active_state_root, new_deactivate_root }
}

fn process_deactivate_messages_chain_step(
    process_one: ProcessDeactivateOneWitness,
    expected_coord_priv_key: u256,
    expected_current_state_root: u256,
    expected_active_state_root: u256,
    expected_deactivate_root: u256,
    expected_poll_id: u256,
    expected_deactivate_index: u256,
) -> ProcessDeactivateOneOutput {
    assert_u256_eq(process_one.coord_priv_key, expected_coord_priv_key);
    assert_u256_eq(process_one.current_state_root, expected_current_state_root);
    assert_u256_eq(process_one.current_active_state_root, expected_active_state_root);
    assert_u256_eq(process_one.current_deactivate_root, expected_deactivate_root);
    assert_u256_eq(process_one.expected_poll_id, expected_poll_id);
    assert_u256_eq(process_one.deactivate_index, expected_deactivate_index);
    process_deactivate_one(process_one)
}

fn process_deactivate_messages_bound_chain_step(
    msg: U256x10,
    enc_pub_key: U256x2,
    command: ProcessDeactivateMessageCommandWitness,
    process_one: ProcessDeactivateOneWitness,
    expected_coord_priv_key: u256,
    expected_current_state_root: u256,
    expected_active_state_root: u256,
    expected_deactivate_root: u256,
    expected_poll_id: u256,
    expected_deactivate_index: u256,
) -> ProcessDeactivateOneOutput {
    let empty = is_zero(msg.v0);
    assert_u256_eq(process_one.is_empty_msg, bool_to_u256(empty));
    if empty {
        assert_u256_eq(process_one.current_active_state_root, expected_active_state_root);
        assert_u256_eq(process_one.current_deactivate_root, expected_deactivate_root);
        ProcessDeactivateOneOutput {
            new_active_state_root: expected_active_state_root,
            new_deactivate_root: expected_deactivate_root,
        }
    } else {
        assert_u256_eq(command.ecdh.scalar, expected_coord_priv_key);
        assert_u256_eq(command.ecdh.base.v0, enc_pub_key.v0);
        assert_u256_eq(command.ecdh.base.v1, enc_pub_key.v1);
        let shared_key = verify_babyjub_scalar_mul(command.ecdh);
        validate_poseidon_decryption(msg, shared_key, command.decrypted_command);
        assert_u256_eq(process_one.packed_cmd.v0, command.decrypted_command.v0);
        assert_u256_eq(process_one.packed_cmd.v1, command.decrypted_command.v1);
        assert_u256_eq(process_one.packed_cmd.v2, command.decrypted_command.v2);
        assert_u256_eq(process_one.cmd_sig_r8.v0, command.decrypted_command.v4);
        assert_u256_eq(process_one.cmd_sig_r8.v1, command.decrypted_command.v5);
        assert_u256_eq(process_one.cmd_sig_s, command.decrypted_command.v6);
        let unpacked = unpack_command_data(process_one.packed_cmd.v0);
        assert_u256_eq(process_one.cmd_poll_id, unpacked.v0);
        assert_u256_eq(process_one.cmd_state_index, unpacked.v5);
        process_deactivate_messages_chain_step(
            process_one,
            expected_coord_priv_key,
            expected_current_state_root,
            expected_active_state_root,
            expected_deactivate_root,
            expected_poll_id,
            expected_deactivate_index,
        )
    }
}

fn process_deactivate_messages_state_transition(
    witness: ProcessDeactivateMessagesStateTransitionWitness,
) -> ProcessDeactivateMessagesStateOutput {
    let output_0 = process_deactivate_messages_chain_step(
        witness.process_one_0,
        witness.coord_priv_key,
        witness.current_state_root,
        witness.current_active_state_root,
        witness.current_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0,
    );
    let output_1 = process_deactivate_messages_chain_step(
        witness.process_one_1,
        witness.coord_priv_key,
        witness.current_state_root,
        output_0.new_active_state_root,
        output_0.new_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0 + 1,
    );
    let output_2 = process_deactivate_messages_chain_step(
        witness.process_one_2,
        witness.coord_priv_key,
        witness.current_state_root,
        output_1.new_active_state_root,
        output_1.new_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0 + 2,
    );
    let output_3 = process_deactivate_messages_chain_step(
        witness.process_one_3,
        witness.coord_priv_key,
        witness.current_state_root,
        output_2.new_active_state_root,
        output_2.new_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0 + 3,
    );
    let output_4 = process_deactivate_messages_chain_step(
        witness.process_one_4,
        witness.coord_priv_key,
        witness.current_state_root,
        output_3.new_active_state_root,
        output_3.new_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0 + 4,
    );
    ProcessDeactivateMessagesStateOutput {
        new_active_state_root: output_4.new_active_state_root,
        new_deactivate_root: output_4.new_deactivate_root,
    }
}

fn process_deactivate_messages_bound_state_transition(
    boundary: ProcessDeactivateMessagesBoundaryWitness,
    witness: ProcessDeactivateMessagesStateTransitionWitness,
    command_0: ProcessDeactivateMessageCommandWitness,
    command_1: ProcessDeactivateMessageCommandWitness,
    command_2: ProcessDeactivateMessageCommandWitness,
    command_3: ProcessDeactivateMessageCommandWitness,
    command_4: ProcessDeactivateMessageCommandWitness,
) -> ProcessDeactivateMessagesStateOutput {
    let output_0 = process_deactivate_messages_bound_chain_step(
        boundary.msg_0,
        boundary.enc_pub_key_0,
        command_0,
        witness.process_one_0,
        witness.coord_priv_key,
        witness.current_state_root,
        witness.current_active_state_root,
        witness.current_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0,
    );
    let output_1 = process_deactivate_messages_bound_chain_step(
        boundary.msg_1,
        boundary.enc_pub_key_1,
        command_1,
        witness.process_one_1,
        witness.coord_priv_key,
        witness.current_state_root,
        output_0.new_active_state_root,
        output_0.new_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0 + 1,
    );
    let output_2 = process_deactivate_messages_bound_chain_step(
        boundary.msg_2,
        boundary.enc_pub_key_2,
        command_2,
        witness.process_one_2,
        witness.coord_priv_key,
        witness.current_state_root,
        output_1.new_active_state_root,
        output_1.new_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0 + 2,
    );
    let output_3 = process_deactivate_messages_bound_chain_step(
        boundary.msg_3,
        boundary.enc_pub_key_3,
        command_3,
        witness.process_one_3,
        witness.coord_priv_key,
        witness.current_state_root,
        output_2.new_active_state_root,
        output_2.new_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0 + 3,
    );
    let output_4 = process_deactivate_messages_bound_chain_step(
        boundary.msg_4,
        boundary.enc_pub_key_4,
        command_4,
        witness.process_one_4,
        witness.coord_priv_key,
        witness.current_state_root,
        output_3.new_active_state_root,
        output_3.new_deactivate_root,
        witness.expected_poll_id,
        witness.deactivate_index_0 + 4,
    );
    ProcessDeactivateMessagesStateOutput {
        new_active_state_root: output_4.new_active_state_root,
        new_deactivate_root: output_4.new_deactivate_root,
    }
}

fn assert_valid_deactivate_message_index(message_index: felt252) {
    assert(
        message_index == 0
            || message_index == 1
            || message_index == 2
            || message_index == 3
            || message_index == 4,
        'BAD_DEACT_MSG_INDEX',
    );
}

fn verify_process_deactivate_message_step(
    fields: ProcessDeactivateStepPublicFields, witness: ProcessDeactivateMessageStepWitness,
) {
    assert_valid_deactivate_message_index(fields.message_index);
    assert_deactivate_index(fields.deactivate_index);
    assert_coord_pub_key_matches_private_key(
        witness.coord_priv_key, witness.coord_pub_key, witness.coord_pub_key_scalar_mul,
    );
    let coord_pub_key_hash = poseidon_hash2(
        witness.coord_pub_key_hash, witness.coord_pub_key.v0, witness.coord_pub_key.v1,
    );
    assert_u256_eq(coord_pub_key_hash, fields.coord_pub_key_hash);

    let next_message_hash = process_deactivate_message_hash_chain_step(
        witness.msg, witness.enc_pub_key, fields.previous_message_hash, witness.message_hash,
    );
    assert_u256_eq(next_message_hash, fields.next_message_hash);

    assert_u256_eq(witness.process_one.coord_priv_key, witness.coord_priv_key);
    assert_u256_eq(witness.process_one.current_state_root, fields.current_state_root);
    assert_u256_eq(witness.process_one.current_active_state_root, fields.current_active_state_root);
    assert_u256_eq(witness.process_one.current_deactivate_root, fields.current_deactivate_root);
    assert_u256_eq(witness.process_one.expected_poll_id, fields.expected_poll_id);
    assert_u256_eq(witness.process_one.deactivate_index, fields.deactivate_index);

    let current_deactivate_commitment = poseidon_hash2(
        witness.current_deactivate_commitment,
        fields.current_active_state_root,
        fields.current_deactivate_root,
    );
    assert_u256_eq(current_deactivate_commitment, fields.current_deactivate_commitment);

    let output = process_deactivate_messages_bound_chain_step(
        witness.msg,
        witness.enc_pub_key,
        witness.command,
        witness.process_one,
        witness.coord_priv_key,
        fields.current_state_root,
        fields.current_active_state_root,
        fields.current_deactivate_root,
        fields.expected_poll_id,
        fields.deactivate_index,
    );
    assert_u256_eq(output.new_active_state_root, fields.new_active_state_root);
    assert_u256_eq(output.new_deactivate_root, fields.new_deactivate_root);

    let new_deactivate_commitment = poseidon_hash2(
        witness.new_deactivate_commitment, output.new_active_state_root, output.new_deactivate_root,
    );
    assert_u256_eq(new_deactivate_commitment, fields.new_deactivate_commitment);
}

#[executable]
pub fn process_deactivate_one_main(
    witness: ProcessDeactivateOneWitness,
) -> ProcessDeactivateOneOutput {
    process_deactivate_one(witness)
}

#[executable]
pub fn process_deactivate_messages_boundary_main(
    fields: ProcessDeactivatePublicFields, witness: ProcessDeactivateMessagesBoundaryWitness,
) -> ProcessDeactivatePublicOutput {
    verify_process_deactivate_boundary(fields, witness);
    build_process_deactivate_public_output(fields)
}

#[executable]
pub fn process_deactivate_message_step_main(
    fields: ProcessDeactivateStepPublicFields, witness: ProcessDeactivateMessageStepWitness,
) -> ProcessDeactivateStepPublicOutput {
    verify_process_deactivate_message_step(fields, witness);
    build_process_deactivate_step_public_output(fields)
}

#[executable]
pub fn process_deactivate_messages_state_transition_main(
    witness: ProcessDeactivateMessagesStateTransitionWitness,
) -> ProcessDeactivateMessagesStateOutput {
    process_deactivate_messages_state_transition(witness)
}

#[executable]
pub fn process_deactivate_messages_stateful_main(
    fields: ProcessDeactivatePublicFields, witness: ProcessDeactivateMessagesStatefulWitness,
) -> ProcessDeactivatePublicOutput {
    let boundary = witness.boundary;
    let state_transition = witness.state_transition;
    assert_coord_pub_key_matches_private_key(
        state_transition.coord_priv_key, boundary.coord_pub_key, witness.coord_pub_key,
    );
    verify_process_deactivate_boundary(fields, boundary);
    assert_u256_eq(state_transition.current_active_state_root, boundary.current_active_state_root);
    assert_u256_eq(state_transition.current_deactivate_root, boundary.current_deactivate_root);
    assert_u256_eq(state_transition.current_state_root, boundary.current_state_root);
    assert_u256_eq(state_transition.expected_poll_id, boundary.expected_poll_id);
    let output = process_deactivate_messages_bound_state_transition(
        boundary,
        state_transition,
        witness.command_0,
        witness.command_1,
        witness.command_2,
        witness.command_3,
        witness.command_4,
    );
    assert_u256_eq(output.new_deactivate_root, fields.new_deactivate_root);
    let new_deactivate_commitment = poseidon_hash2(
        witness.new_deactivate_commitment, output.new_active_state_root, output.new_deactivate_root,
    );
    assert_u256_eq(new_deactivate_commitment, fields.new_deactivate_commitment);
    build_process_deactivate_public_output(fields)
}
