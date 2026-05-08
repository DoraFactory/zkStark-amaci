use core::math::u256_mul_mod_n;
use core::zeroable::NonZero;
use crate::poseidon_constants::{
    POSEIDON_T3_WIDTH, POSEIDON_T6_WIDTH, poseidon_t3_c, poseidon_t3_m, poseidon_t6_c,
    poseidon_t6_m,
};
use crate::types::U256x5;

pub const BN254_SCALAR_FIELD: u256 =
    0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
pub const POSEIDON_FULL_ROUNDS: u32 = 8;
pub const POSEIDON_T3_PARTIAL_ROUNDS: u32 = 57;
pub const POSEIDON_T6_PARTIAL_ROUNDS: u32 = 60;
pub const POSEIDON5_ZERO_HASH: u256 =
    0x2066be41bebe6caf7e079360abe14fbf9118c62eabc42e2fe75e342b160a95bc;
pub const POSEIDON10_ZERO_HASH: u256 =
    0x26318ec8cdeef483522c15e9b226314ae39b86cde2a430dabf6ed19791917c47;

#[derive(Copy, Drop)]
pub struct PoseidonT3State {
    pub x0: u256,
    pub x1: u256,
    pub x2: u256,
}

#[derive(Copy, Drop)]
pub struct PoseidonT6State {
    pub x0: u256,
    pub x1: u256,
    pub x2: u256,
    pub x3: u256,
    pub x4: u256,
    pub x5: u256,
}

pub fn poseidon2_initial_state(left: u256, right: u256) -> PoseidonT3State {
    PoseidonT3State { x0: 0, x1: left, x2: right }
}

pub fn poseidon5_initial_state(inputs: U256x5) -> PoseidonT6State {
    PoseidonT6State {
        x0: 0, x1: inputs.v0, x2: inputs.v1, x3: inputs.v2, x4: inputs.v3, x5: inputs.v4,
    }
}

pub fn poseidon2_round_constant(idx: u32) -> u256 {
    poseidon_t3_c(idx)
}

pub fn poseidon5_round_constant(idx: u32) -> u256 {
    poseidon_t6_c(idx)
}

pub fn poseidon2_mds(row: u32, col: u32) -> u256 {
    poseidon_t3_m(row, col)
}

pub fn poseidon5_mds(row: u32, col: u32) -> u256 {
    poseidon_t6_m(row, col)
}

fn bn254_modulus() -> NonZero<u256> {
    BN254_SCALAR_FIELD.try_into().unwrap()
}

fn field_ge(left: u256, right: u256) -> bool {
    if left.high > right.high {
        true
    } else if left.high < right.high {
        false
    } else {
        left.low >= right.low
    }
}

fn field_reduce_once(value: u256) -> u256 {
    if field_ge(value, BN254_SCALAR_FIELD) {
        value - BN254_SCALAR_FIELD
    } else {
        value
    }
}

fn field_add(left: u256, right: u256) -> u256 {
    field_reduce_once(left + right)
}

fn field_mul(left: u256, right: u256) -> u256 {
    u256_mul_mod_n(left, right, bn254_modulus())
}

fn field_pow5(value: u256) -> u256 {
    let x2 = field_mul(value, value);
    let x4 = field_mul(x2, x2);
    field_mul(x4, value)
}

fn poseidon_is_full_round(round: u32, partial_rounds: u32) -> bool {
    round < 4 || round >= 4 + partial_rounds
}

fn poseidon2_add_constants(state: PoseidonT3State, round: u32) -> PoseidonT3State {
    let offset = round * POSEIDON_T3_WIDTH;
    PoseidonT3State {
        x0: field_add(state.x0, poseidon2_round_constant(offset)),
        x1: field_add(state.x1, poseidon2_round_constant(offset + 1)),
        x2: field_add(state.x2, poseidon2_round_constant(offset + 2)),
    }
}

fn poseidon2_sbox(state: PoseidonT3State, round: u32) -> PoseidonT3State {
    if poseidon_is_full_round(round, POSEIDON_T3_PARTIAL_ROUNDS) {
        PoseidonT3State {
            x0: field_pow5(state.x0), x1: field_pow5(state.x1), x2: field_pow5(state.x2),
        }
    } else {
        PoseidonT3State { x0: field_pow5(state.x0), x1: state.x1, x2: state.x2 }
    }
}

fn poseidon2_mds_mix(state: PoseidonT3State) -> PoseidonT3State {
    PoseidonT3State {
        x0: field_add(
            field_add(
                field_mul(poseidon2_mds(0, 0), state.x0), field_mul(poseidon2_mds(0, 1), state.x1),
            ),
            field_mul(poseidon2_mds(0, 2), state.x2),
        ),
        x1: field_add(
            field_add(
                field_mul(poseidon2_mds(1, 0), state.x0), field_mul(poseidon2_mds(1, 1), state.x1),
            ),
            field_mul(poseidon2_mds(1, 2), state.x2),
        ),
        x2: field_add(
            field_add(
                field_mul(poseidon2_mds(2, 0), state.x0), field_mul(poseidon2_mds(2, 1), state.x1),
            ),
            field_mul(poseidon2_mds(2, 2), state.x2),
        ),
    }
}

fn poseidon2_round(state: PoseidonT3State, round: u32) -> PoseidonT3State {
    poseidon2_mds_mix(poseidon2_sbox(poseidon2_add_constants(state, round), round))
}

pub fn poseidon2_permutation(state: PoseidonT3State) -> PoseidonT3State {
    let mut state = state;
    let mut round = 0;
    while round < POSEIDON_FULL_ROUNDS + POSEIDON_T3_PARTIAL_ROUNDS {
        state = poseidon2_round(state, round);
        round += 1;
    }
    state
}

pub fn poseidon2_hash(left: u256, right: u256) -> u256 {
    poseidon2_permutation(poseidon2_initial_state(left, right)).x0
}

fn poseidon5_add_constants(state: PoseidonT6State, round: u32) -> PoseidonT6State {
    let offset = round * POSEIDON_T6_WIDTH;
    PoseidonT6State {
        x0: field_add(state.x0, poseidon5_round_constant(offset)),
        x1: field_add(state.x1, poseidon5_round_constant(offset + 1)),
        x2: field_add(state.x2, poseidon5_round_constant(offset + 2)),
        x3: field_add(state.x3, poseidon5_round_constant(offset + 3)),
        x4: field_add(state.x4, poseidon5_round_constant(offset + 4)),
        x5: field_add(state.x5, poseidon5_round_constant(offset + 5)),
    }
}

fn poseidon5_sbox(state: PoseidonT6State, round: u32) -> PoseidonT6State {
    if poseidon_is_full_round(round, POSEIDON_T6_PARTIAL_ROUNDS) {
        PoseidonT6State {
            x0: field_pow5(state.x0),
            x1: field_pow5(state.x1),
            x2: field_pow5(state.x2),
            x3: field_pow5(state.x3),
            x4: field_pow5(state.x4),
            x5: field_pow5(state.x5),
        }
    } else {
        PoseidonT6State {
            x0: field_pow5(state.x0),
            x1: state.x1,
            x2: state.x2,
            x3: state.x3,
            x4: state.x4,
            x5: state.x5,
        }
    }
}

fn poseidon5_row_mix(row: u32, x0: u256, x1: u256, x2: u256, x3: u256, x4: u256, x5: u256) -> u256 {
    let acc = field_mul(poseidon5_mds(row, 0), x0);
    let acc = field_add(acc, field_mul(poseidon5_mds(row, 1), x1));
    let acc = field_add(acc, field_mul(poseidon5_mds(row, 2), x2));
    let acc = field_add(acc, field_mul(poseidon5_mds(row, 3), x3));
    let acc = field_add(acc, field_mul(poseidon5_mds(row, 4), x4));
    field_add(acc, field_mul(poseidon5_mds(row, 5), x5))
}

fn poseidon5_mds_mix(state: PoseidonT6State) -> PoseidonT6State {
    PoseidonT6State {
        x0: poseidon5_row_mix(0, state.x0, state.x1, state.x2, state.x3, state.x4, state.x5),
        x1: poseidon5_row_mix(1, state.x0, state.x1, state.x2, state.x3, state.x4, state.x5),
        x2: poseidon5_row_mix(2, state.x0, state.x1, state.x2, state.x3, state.x4, state.x5),
        x3: poseidon5_row_mix(3, state.x0, state.x1, state.x2, state.x3, state.x4, state.x5),
        x4: poseidon5_row_mix(4, state.x0, state.x1, state.x2, state.x3, state.x4, state.x5),
        x5: poseidon5_row_mix(5, state.x0, state.x1, state.x2, state.x3, state.x4, state.x5),
    }
}

fn poseidon5_round(state: PoseidonT6State, round: u32) -> PoseidonT6State {
    poseidon5_mds_mix(poseidon5_sbox(poseidon5_add_constants(state, round), round))
}

pub fn poseidon5_permutation(state: PoseidonT6State) -> PoseidonT6State {
    let mut state = state;
    let mut round = 0;
    while round < POSEIDON_FULL_ROUNDS + POSEIDON_T6_PARTIAL_ROUNDS {
        state = poseidon5_round(state, round);
        round += 1;
    }
    state
}

pub fn poseidon5_hash(inputs: U256x5) -> u256 {
    poseidon5_permutation(poseidon5_initial_state(inputs)).x0
}

pub fn poseidon10_hash(first: U256x5, second: U256x5) -> u256 {
    poseidon2_hash(poseidon5_hash(first), poseidon5_hash(second))
}

#[cfg(test)]
mod tests {
    use crate::types::U256x5;
    use super::{poseidon10_hash, poseidon2_hash, poseidon5_hash};

    #[test]
    fn poseidon2_matches_js_vectors() {
        assert(
            poseidon2_hash(
                0, 0,
            ) == 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864,
            'POSEIDON2_ZERO_MISMATCH',
        );
        assert(
            poseidon2_hash(
                1, 2,
            ) == 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a,
            'POSEIDON2_SMALL_MISMATCH',
        );
        assert(
            poseidon2_hash(
                1234567890, 987654321,
            ) == 0x05a3f9de3ac5791f4e4a60e78451ce7d44fb3a2f4a7fe1ee1c0caf466ef182c9,
            'POSEIDON2_BIG_MISMATCH',
        );
    }

    #[test]
    fn poseidon5_matches_js_vectors() {
        assert(
            poseidon5_hash(
                U256x5 { v0: 0, v1: 0, v2: 0, v3: 0, v4: 0 },
            ) == 0x2066be41bebe6caf7e079360abe14fbf9118c62eabc42e2fe75e342b160a95bc,
            'POSEIDON5_ZERO_MISMATCH',
        );
        assert(
            poseidon5_hash(
                U256x5 { v0: 1, v1: 2, v2: 3, v3: 4, v4: 5 },
            ) == 0x0dab9449e4a1398a15224c0b15a49d598b2174d305a316c918125f8feeb123c0,
            'POSEIDON5_SMALL_MISMATCH',
        );
        assert(
            poseidon5_hash(
                U256x5 { v0: 0, v1: 6, v2: 4, v3: 0, v4: 0 },
            ) == 0x2ba1aa2c0bf80f573bd22203133e6f61f2c3a81d648a939d1706caf41cc82ee7,
            'POSEIDON5_VOTES_MISMATCH',
        );
    }

    #[test]
    fn poseidon10_matches_js_vectors() {
        assert(
            poseidon10_hash(
                U256x5 { v0: 0, v1: 0, v2: 0, v3: 0, v4: 0 },
                U256x5 { v0: 0, v1: 0, v2: 0, v3: 0, v4: 0 },
            ) == 0x26318ec8cdeef483522c15e9b226314ae39b86cde2a430dabf6ed19791917c47,
            'POSEIDON10_ZERO_MISMATCH',
        );
        assert(
            poseidon10_hash(
                U256x5 { v0: 1, v1: 2, v2: 3, v3: 4, v4: 5 },
                U256x5 { v0: 6, v1: 7, v2: 8, v3: 9, v4: 10 },
            ) == 0x2fced9e89dce10b4e288020d0371def7985f8122bc3366b76385aa35b9b82367,
            'POSEIDON10_SMALL_MISMATCH',
        );
    }
}
