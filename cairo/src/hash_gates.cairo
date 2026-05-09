use crate::poseidon_bn254::{poseidon2_hash, poseidon5_hash};
use crate::sha256_u256::{
    compute_sha256_u256x4_mod_bn254, compute_sha256_u256x7_mod_bn254,
    compute_sha256_u256x8_mod_bn254, compute_sha256_u256x9_mod_bn254,
};
use crate::types::{
    U256x10, U256x4, U256x5, U256x7, U256x8, U256x9, assert_u256_eq, is_zero, u256x10_first5,
    u256x10_second5,
};

#[derive(Copy, Drop, Serde)]
pub struct Hash2Claim {
    pub in0: u256,
    pub in1: u256,
    pub out: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct Hash5Claim {
    pub inputs: U256x5,
    pub out: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct Hash10Claim {
    pub first: Hash5Claim,
    pub second: Hash5Claim,
    pub out: Hash2Claim,
}

#[derive(Copy, Drop, Serde)]
pub struct Hash13Claim {
    pub first: Hash5Claim,
    pub second: Hash5Claim,
    pub out: Hash5Claim,
}

#[derive(Copy, Drop, Serde)]
pub struct Sha256U256x4Claim {
    pub inputs: U256x4,
    pub out: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct Sha256U256x7Claim {
    pub inputs: U256x7,
    pub out: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct Sha256U256x8Claim {
    pub inputs: U256x8,
    pub out: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct Sha256U256x9Claim {
    pub inputs: U256x9,
    pub out: u256,
}

// Circom-compatible Poseidon T3. The claim output is kept only as a
// compatibility assertion against the generated witness.
pub fn poseidon_hash2(claim: Hash2Claim, in0: u256, in1: u256) -> u256 {
    assert_u256_eq(claim.in0, in0);
    assert_u256_eq(claim.in1, in1);
    let computed = poseidon2_hash(in0, in1);
    assert_u256_eq(claim.out, computed);
    computed
}

// Circom-compatible Poseidon T6 / Hasher5. The claim output is kept only as a
// compatibility assertion against the generated witness.
pub fn poseidon_hash5(claim: Hash5Claim, inputs: U256x5) -> u256 {
    assert_poseidon5_preimage(claim, inputs);
    let computed = poseidon5_hash(inputs);
    assert_u256_eq(claim.out, computed);
    computed
}

// AMACI Hasher10:
// HashLeftRight(Hasher5(inputs[0..4]), Hasher5(inputs[5..9])).
pub fn poseidon_hash10(claim: Hash10Claim, inputs: U256x10) -> u256 {
    let first = poseidon_hash5(claim.first, u256x10_first5(inputs));
    let second = poseidon_hash5(claim.second, u256x10_second5(inputs));
    poseidon_hash2(claim.out, first, second)
}

// AMACI MessageHasher / Hasher13:
// Hasher5(Hasher5(inputs[0..4]), Hasher5(inputs[5..9]), inputs[10], inputs[11], inputs[12]).
pub fn poseidon_hash13(
    claim: Hash13Claim,
    first_inputs: U256x5,
    second_inputs: U256x5,
    in10: u256,
    in11: u256,
    in12: u256,
) -> u256 {
    let first = poseidon_hash5(claim.first, first_inputs);
    let second = poseidon_hash5(claim.second, second_inputs);
    poseidon_hash5(claim.out, U256x5 { v0: first, v1: second, v2: in10, v3: in11, v4: in12 })
}

fn assert_poseidon5_preimage(claim: Hash5Claim, inputs: U256x5) {
    assert_u256_eq(claim.inputs.v0, inputs.v0);
    assert_u256_eq(claim.inputs.v1, inputs.v1);
    assert_u256_eq(claim.inputs.v2, inputs.v2);
    assert_u256_eq(claim.inputs.v3, inputs.v3);
    assert_u256_eq(claim.inputs.v4, inputs.v4);
}

fn is_zero_vector5(inputs: U256x5) -> bool {
    is_zero(inputs.v0)
        && is_zero(inputs.v1)
        && is_zero(inputs.v2)
        && is_zero(inputs.v3)
        && is_zero(inputs.v4)
}

fn is_zero_vector10(inputs: U256x10) -> bool {
    is_zero_vector5(u256x10_first5(inputs)) && is_zero_vector5(u256x10_second5(inputs))
}

pub fn poseidon_hash5_or_zero_cache(claim: Hash5Claim, inputs: U256x5, zero_hash: u256) -> u256 {
    assert_poseidon5_preimage(claim, inputs);
    if is_zero_vector5(inputs) {
        assert_u256_eq(claim.out, zero_hash);
        zero_hash
    } else {
        let computed = poseidon5_hash(inputs);
        assert_u256_eq(claim.out, computed);
        computed
    }
}

pub fn poseidon_hash10_or_zero_cache(
    claim: Hash10Claim, inputs: U256x10, zero5_hash: u256, zero10_hash: u256,
) -> u256 {
    if is_zero_vector10(inputs) {
        assert_poseidon5_preimage(claim.first, u256x10_first5(inputs));
        assert_poseidon5_preimage(claim.second, u256x10_second5(inputs));
        assert_u256_eq(claim.first.out, zero5_hash);
        assert_u256_eq(claim.second.out, zero5_hash);
        assert_u256_eq(claim.out.in0, zero5_hash);
        assert_u256_eq(claim.out.in1, zero5_hash);
        assert_u256_eq(claim.out.out, zero10_hash);
        zero10_hash
    } else {
        poseidon_hash10(claim, inputs)
    }
}

// Circom SHA-256 input hasher:
// sha256([packedVals, stateCommitment, currentTallyCommitment,
// newTallyCommitment]) mod BN254 scalar field. The claim is kept only as a
// compatibility assertion against the generated witness.
pub fn sha256_u256x4_mod_bn254(claim: Sha256U256x4Claim, inputs: U256x4) -> u256 {
    assert_u256_eq(claim.inputs.v0, inputs.v0);
    assert_u256_eq(claim.inputs.v1, inputs.v1);
    assert_u256_eq(claim.inputs.v2, inputs.v2);
    assert_u256_eq(claim.inputs.v3, inputs.v3);
    let computed = compute_sha256_u256x4_mod_bn254(inputs);
    assert_u256_eq(claim.out, computed);
    computed
}

// Legacy ProcessMessages SHA-256 input hasher without poll id:
// sha256([
//   packedVals, coordPubKeyHash, batchStartHash, batchEndHash,
//   currentStateCommitment, newStateCommitment, deactivateCommitment
// ]) mod BN254 scalar field.
pub fn sha256_u256x7_mod_bn254(claim: Sha256U256x7Claim, inputs: U256x7) -> u256 {
    assert_u256_eq(claim.inputs.v0, inputs.v0);
    assert_u256_eq(claim.inputs.v1, inputs.v1);
    assert_u256_eq(claim.inputs.v2, inputs.v2);
    assert_u256_eq(claim.inputs.v3, inputs.v3);
    assert_u256_eq(claim.inputs.v4, inputs.v4);
    assert_u256_eq(claim.inputs.v5, inputs.v5);
    assert_u256_eq(claim.inputs.v6, inputs.v6);
    let computed = compute_sha256_u256x7_mod_bn254(inputs);
    assert_u256_eq(claim.out, computed);
    computed
}

// Current AMACI ProcessMessages SHA-256 input hasher:
// sha256([
//   packedVals, coordPubKeyHash, batchStartHash, batchEndHash,
//   currentStateCommitment, newStateCommitment, deactivateCommitment, expectedPollId
// ]) mod BN254 scalar field.
pub fn sha256_u256x8_mod_bn254(claim: Sha256U256x8Claim, inputs: U256x8) -> u256 {
    assert_u256_eq(claim.inputs.v0, inputs.v0);
    assert_u256_eq(claim.inputs.v1, inputs.v1);
    assert_u256_eq(claim.inputs.v2, inputs.v2);
    assert_u256_eq(claim.inputs.v3, inputs.v3);
    assert_u256_eq(claim.inputs.v4, inputs.v4);
    assert_u256_eq(claim.inputs.v5, inputs.v5);
    assert_u256_eq(claim.inputs.v6, inputs.v6);
    assert_u256_eq(claim.inputs.v7, inputs.v7);
    let computed = compute_sha256_u256x8_mod_bn254(inputs);
    assert_u256_eq(claim.out, computed);
    computed
}

// AMACI AddNewKey SHA-256 input hasher:
// sha256([
//   deactivateRoot, coordPubKeyHash, nullifier, d1[0], d1[1],
//   d2[0], d2[1], newPubKeyHash, pollId
// ]) mod BN254 scalar field.
pub fn sha256_u256x9_mod_bn254(claim: Sha256U256x9Claim, inputs: U256x9) -> u256 {
    assert_u256_eq(claim.inputs.v0, inputs.v0);
    assert_u256_eq(claim.inputs.v1, inputs.v1);
    assert_u256_eq(claim.inputs.v2, inputs.v2);
    assert_u256_eq(claim.inputs.v3, inputs.v3);
    assert_u256_eq(claim.inputs.v4, inputs.v4);
    assert_u256_eq(claim.inputs.v5, inputs.v5);
    assert_u256_eq(claim.inputs.v6, inputs.v6);
    assert_u256_eq(claim.inputs.v7, inputs.v7);
    assert_u256_eq(claim.inputs.v8, inputs.v8);
    let computed = compute_sha256_u256x9_mod_bn254(inputs);
    assert_u256_eq(claim.out, computed);
    computed
}
