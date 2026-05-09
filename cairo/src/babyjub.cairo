use crate::poseidon_bn254::{
    PoseidonT4State, field_add_mod, field_mul_mod, field_sub_mod, poseidon4_permutation,
    poseidon5_hash,
};
use crate::types::{U256x2, U256x3, U256x5, assert_u256_eq, is_zero, zero_u256};

pub const BABYJUB_A: u256 = 168700;
pub const BABYJUB_D: u256 = 168696;
pub const BABYJUB_BASE8_X: u256 =
    5299619240641551281634865583518297030282874472190772894086521144482721001553;
pub const BABYJUB_BASE8_Y: u256 =
    16950150798460657717958625567821834550301663161624707787222815936182638968203;
pub const BABYJUB_SUBGROUP_ORDER: u256 =
    2736030358979909402780800718157159386076813972158567259200215660948447373041;
pub const BABYJUB_SCALAR_BITS: usize = 253;
pub const BABYJUB_SIGNATURE_HASH_BITS: usize = 254;

#[derive(Copy, Drop, Serde)]
pub struct BabyJubJubScalarMulStep {
    pub bit: u256,
    pub sum: U256x2,
    pub next_acc: U256x2,
    pub next_exp: U256x2,
}

#[derive(Drop, Serde)]
pub struct BabyJubJubScalarMulWitness {
    pub scalar: u256,
    pub base: U256x2,
    pub expected: U256x2,
    pub steps: Array<BabyJubJubScalarMulStep>,
}

#[derive(Drop, Serde)]
pub struct BabyJubJubPoseidonSignatureWitness {
    pub pub_key_x2: U256x2,
    pub pub_key_x4: U256x2,
    pub pub_key_x8: U256x2,
    pub s_base8: BabyJubJubScalarMulWitness,
    pub h_pub_key_x8: BabyJubJubScalarMulWitness,
    pub right: U256x2,
}

fn one_u256() -> u256 {
    1
}

fn two_u256() -> u256 {
    2
}

fn identity_point() -> U256x2 {
    U256x2 { v0: zero_u256(), v1: one_u256() }
}

pub fn babyjub_base8() -> U256x2 {
    U256x2 { v0: BABYJUB_BASE8_X, v1: BABYJUB_BASE8_Y }
}

fn assert_bool_u256(value: u256) {
    assert(value.high == 0, 'BJJ_BOOL_HIGH');
    assert(value.low < 2, 'BJJ_BOOL_RANGE');
}

fn bit_is_one(value: u256) -> bool {
    assert_bool_u256(value);
    value.low == 1
}

fn select_u256(selected: bool, if_zero: u256, if_one: u256) -> u256 {
    if selected {
        if_one
    } else {
        if_zero
    }
}

fn select_point(selected: bool, if_zero: U256x2, if_one: U256x2) -> U256x2 {
    U256x2 {
        v0: select_u256(selected, if_zero.v0, if_one.v0),
        v1: select_u256(selected, if_zero.v1, if_one.v1),
    }
}

fn assert_point_eq(left: U256x2, right: U256x2) {
    assert_u256_eq(left.v0, right.v0);
    assert_u256_eq(left.v1, right.v1);
}

fn point_eq(left: U256x2, right: U256x2) -> bool {
    left.v0 == right.v0 && left.v1 == right.v1
}

fn assert_babyjub_on_curve(point: U256x2) {
    let x2 = field_mul_mod(point.v0, point.v0);
    let y2 = field_mul_mod(point.v1, point.v1);
    let lhs = field_add_mod(field_mul_mod(BABYJUB_A, x2), y2);
    let rhs = field_add_mod(one_u256(), field_mul_mod(BABYJUB_D, field_mul_mod(x2, y2)));
    assert_u256_eq(lhs, rhs);
}

pub fn assert_babyjub_add(left: U256x2, right: U256x2, out: U256x2) {
    let beta = field_mul_mod(left.v0, right.v1);
    let gamma = field_mul_mod(left.v1, right.v0);
    let delta = field_mul_mod(
        field_sub_mod(left.v1, field_mul_mod(BABYJUB_A, left.v0)),
        field_add_mod(right.v0, right.v1),
    );
    let tau = field_mul_mod(beta, gamma);
    let dtau = field_mul_mod(BABYJUB_D, tau);

    let x_denominator = field_add_mod(one_u256(), dtau);
    let x_numerator = field_add_mod(beta, gamma);
    assert_u256_eq(field_mul_mod(x_denominator, out.v0), x_numerator);

    let y_denominator = field_sub_mod(one_u256(), dtau);
    let y_numerator = field_sub_mod(field_add_mod(delta, field_mul_mod(BABYJUB_A, beta)), gamma);
    assert_u256_eq(field_mul_mod(y_denominator, out.v1), y_numerator);
    assert_babyjub_on_curve(out);
}

fn verify_babyjub_scalar_mul_with_bits(
    witness: BabyJubJubScalarMulWitness, bit_length: usize,
) -> U256x2 {
    let scalar = witness.scalar;
    let base = witness.base;
    let expected = witness.expected;
    let steps = witness.steps;
    assert(steps.len() == bit_length, 'BAD_BJJ_STEPS');
    assert_babyjub_on_curve(base);

    let mut acc = identity_point();
    let mut exp = base;
    let mut reconstructed = zero_u256();
    let mut power = one_u256();
    let mut i: usize = 0;
    while i < bit_length {
        let step = *steps.at(i);
        let bit_one = bit_is_one(step.bit);
        assert_babyjub_add(acc, exp, step.sum);
        assert_babyjub_add(exp, exp, step.next_exp);
        assert_point_eq(step.next_acc, select_point(bit_one, acc, step.sum));

        reconstructed += step.bit * power;
        power *= two_u256();
        acc = step.next_acc;
        exp = step.next_exp;
        i += 1;
    }

    assert_u256_eq(reconstructed, scalar);
    assert_point_eq(acc, expected);
    expected
}

pub fn verify_babyjub_scalar_mul(witness: BabyJubJubScalarMulWitness) -> U256x2 {
    verify_babyjub_scalar_mul_with_bits(witness, BABYJUB_SCALAR_BITS)
}

fn poseidon3_hash(inputs: U256x3) -> u256 {
    poseidon4_permutation(
        PoseidonT4State { x0: zero_u256(), x1: inputs.v0, x2: inputs.v1, x3: inputs.v2 },
    )
        .x0
}

pub fn verify_babyjub_poseidon_signature(
    pub_key: U256x2,
    r8: U256x2,
    s: u256,
    preimage: U256x3,
    witness: BabyJubJubPoseidonSignatureWitness,
) -> u256 {
    assert_babyjub_add(pub_key, pub_key, witness.pub_key_x2);
    assert_babyjub_add(witness.pub_key_x2, witness.pub_key_x2, witness.pub_key_x4);
    assert_babyjub_add(witness.pub_key_x4, witness.pub_key_x4, witness.pub_key_x8);

    let base8 = babyjub_base8();
    assert_u256_eq(witness.s_base8.scalar, s);
    assert_u256_eq(witness.s_base8.base.v0, base8.v0);
    assert_u256_eq(witness.s_base8.base.v1, base8.v1);
    let left = verify_babyjub_scalar_mul_with_bits(witness.s_base8, BABYJUB_SCALAR_BITS);

    let message_hash = poseidon3_hash(preimage);
    let h = poseidon5_hash(
        U256x5 { v0: r8.v0, v1: r8.v1, v2: pub_key.v0, v3: pub_key.v1, v4: message_hash },
    );
    assert_u256_eq(witness.h_pub_key_x8.scalar, h);
    assert_u256_eq(witness.h_pub_key_x8.base.v0, witness.pub_key_x8.v0);
    assert_u256_eq(witness.h_pub_key_x8.base.v1, witness.pub_key_x8.v1);
    let right_2 = verify_babyjub_scalar_mul_with_bits(
        witness.h_pub_key_x8, BABYJUB_SIGNATURE_HASH_BITS,
    );
    assert_babyjub_add(r8, right_2, witness.right);

    if point_eq(left, witness.right)
        && !is_zero(witness.pub_key_x8.v0)
        && s < BABYJUB_SUBGROUP_ORDER {
        1
    } else {
        0
    }
}

#[executable]
pub fn ecdh_shared_key_main(witness: BabyJubJubScalarMulWitness) -> U256x2 {
    verify_babyjub_scalar_mul(witness)
}

#[executable]
pub fn verify_signature_main(
    pub_key: U256x2,
    r8: U256x2,
    s: u256,
    preimage: U256x3,
    witness: BabyJubJubPoseidonSignatureWitness,
) -> u256 {
    verify_babyjub_poseidon_signature(pub_key, r8, s, preimage, witness)
}
