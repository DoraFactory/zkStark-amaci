use core::num::traits::WrappingAdd;
use crate::poseidon_bn254::BN254_SCALAR_FIELD;
use crate::types::{U256x4, U256x7, U256x8, U256x9};

pub const U128_TWO_POW_32: u128 = 0x100000000;
pub const U128_TWO_POW_64: u128 = 0x10000000000000000;
pub const U128_TWO_POW_96: u128 = 0x1000000000000000000000000;
pub const SHA256_U256X4_INPUT_BITS: u32 = 1024;
pub const SHA256_U256X7_INPUT_BITS: u32 = 1792;
pub const SHA256_U256X8_INPUT_BITS: u32 = 2048;
pub const SHA256_U256X9_INPUT_BITS: u32 = 2304;

#[derive(Copy, Drop)]
struct Sha256State {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    h5: u32,
    h6: u32,
    h7: u32,
}

fn initial_state() -> Sha256State {
    Sha256State {
        h0: 0x6a09e667,
        h1: 0xbb67ae85,
        h2: 0x3c6ef372,
        h3: 0xa54ff53a,
        h4: 0x510e527f,
        h5: 0x9b05688c,
        h6: 0x1f83d9ab,
        h7: 0x5be0cd19,
    }
}

fn sha256_k_constants() -> Array<u32> {
    array![
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ]
}

fn rotr_with(value: u32, low_modulus: u32, high_multiplier: u32) -> u32 {
    let right = value / low_modulus;
    let left = (value % low_modulus) * high_multiplier;
    left + right
}

fn rotr2(value: u32) -> u32 {
    rotr_with(value, 0x4, 0x40000000)
}

fn rotr6(value: u32) -> u32 {
    rotr_with(value, 0x40, 0x4000000)
}

fn rotr7(value: u32) -> u32 {
    rotr_with(value, 0x80, 0x2000000)
}

fn rotr11(value: u32) -> u32 {
    rotr_with(value, 0x800, 0x200000)
}

fn rotr13(value: u32) -> u32 {
    rotr_with(value, 0x2000, 0x80000)
}

fn rotr17(value: u32) -> u32 {
    rotr_with(value, 0x20000, 0x8000)
}

fn rotr18(value: u32) -> u32 {
    rotr_with(value, 0x40000, 0x4000)
}

fn rotr19(value: u32) -> u32 {
    rotr_with(value, 0x80000, 0x2000)
}

fn rotr22(value: u32) -> u32 {
    rotr_with(value, 0x400000, 0x400)
}

fn rotr25(value: u32) -> u32 {
    rotr_with(value, 0x2000000, 0x80)
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((~x) & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn big_sigma0(x: u32) -> u32 {
    rotr2(x) ^ rotr13(x) ^ rotr22(x)
}

fn big_sigma1(x: u32) -> u32 {
    rotr6(x) ^ rotr11(x) ^ rotr25(x)
}

fn small_sigma0(x: u32) -> u32 {
    rotr7(x) ^ rotr18(x) ^ (x / 0x8)
}

fn small_sigma1(x: u32) -> u32 {
    rotr17(x) ^ rotr19(x) ^ (x / 0x400)
}

fn add4(a: u32, b: u32, c: u32, d: u32) -> u32 {
    a.wrapping_add(b).wrapping_add(c).wrapping_add(d)
}

fn add5(a: u32, b: u32, c: u32, d: u32, e: u32) -> u32 {
    a.wrapping_add(b).wrapping_add(c).wrapping_add(d).wrapping_add(e)
}

fn compress_block(state: Sha256State, message: @Array<u32>, offset: usize) -> Sha256State {
    let mut w = array![];
    let mut i: usize = 0;
    while i < 16 {
        w.append(*message.at(offset + i));
        i += 1;
    }

    while i < 64 {
        let next = add4(
            small_sigma1(*w.at(i - 2)), *w.at(i - 7), small_sigma0(*w.at(i - 15)), *w.at(i - 16),
        );
        w.append(next);
        i += 1;
    }

    let k = sha256_k_constants();
    let mut a = state.h0;
    let mut b = state.h1;
    let mut c = state.h2;
    let mut d = state.h3;
    let mut e = state.h4;
    let mut f = state.h5;
    let mut g = state.h6;
    let mut h = state.h7;

    let mut round: usize = 0;
    while round < 64 {
        let t1 = add5(h, big_sigma1(e), ch(e, f, g), *k.at(round), *w.at(round));
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        round += 1;
    }

    Sha256State {
        h0: state.h0.wrapping_add(a),
        h1: state.h1.wrapping_add(b),
        h2: state.h2.wrapping_add(c),
        h3: state.h3.wrapping_add(d),
        h4: state.h4.wrapping_add(e),
        h5: state.h5.wrapping_add(f),
        h6: state.h6.wrapping_add(g),
        h7: state.h7.wrapping_add(h),
    }
}

fn u128_word_0(value: u128) -> u32 {
    (value / U128_TWO_POW_96).try_into().unwrap()
}

fn u128_word_1(value: u128) -> u32 {
    ((value / U128_TWO_POW_64) % U128_TWO_POW_32).try_into().unwrap()
}

fn u128_word_2(value: u128) -> u32 {
    ((value / U128_TWO_POW_32) % U128_TWO_POW_32).try_into().unwrap()
}

fn u128_word_3(value: u128) -> u32 {
    (value % U128_TWO_POW_32).try_into().unwrap()
}

fn append_u128_be_words(ref words: Array<u32>, value: u128) {
    words.append(u128_word_0(value));
    words.append(u128_word_1(value));
    words.append(u128_word_2(value));
    words.append(u128_word_3(value));
}

fn append_u256_be_words(ref words: Array<u32>, value: u256) {
    append_u128_be_words(ref words, value.high);
    append_u128_be_words(ref words, value.low);
}

fn build_padded_words_x4(inputs: U256x4) -> Array<u32> {
    let mut words = array![];
    append_u256_be_words(ref words, inputs.v0);
    append_u256_be_words(ref words, inputs.v1);
    append_u256_be_words(ref words, inputs.v2);
    append_u256_be_words(ref words, inputs.v3);
    words.append(0x80000000);

    let mut padding_zeros: usize = 0;
    while padding_zeros < 14 {
        words.append(0);
        padding_zeros += 1;
    }

    words.append(SHA256_U256X4_INPUT_BITS);
    words
}

fn build_padded_words_x7(inputs: U256x7) -> Array<u32> {
    let mut words = array![];
    append_u256_be_words(ref words, inputs.v0);
    append_u256_be_words(ref words, inputs.v1);
    append_u256_be_words(ref words, inputs.v2);
    append_u256_be_words(ref words, inputs.v3);
    append_u256_be_words(ref words, inputs.v4);
    append_u256_be_words(ref words, inputs.v5);
    append_u256_be_words(ref words, inputs.v6);
    words.append(0x80000000);

    let mut padding_zeros: usize = 0;
    while padding_zeros < 6 {
        words.append(0);
        padding_zeros += 1;
    }

    words.append(SHA256_U256X7_INPUT_BITS);
    words
}

fn build_padded_words_x8(inputs: U256x8) -> Array<u32> {
    let mut words = array![];
    append_u256_be_words(ref words, inputs.v0);
    append_u256_be_words(ref words, inputs.v1);
    append_u256_be_words(ref words, inputs.v2);
    append_u256_be_words(ref words, inputs.v3);
    append_u256_be_words(ref words, inputs.v4);
    append_u256_be_words(ref words, inputs.v5);
    append_u256_be_words(ref words, inputs.v6);
    append_u256_be_words(ref words, inputs.v7);
    words.append(0x80000000);

    let mut padding_zeros: usize = 0;
    while padding_zeros < 14 {
        words.append(0);
        padding_zeros += 1;
    }

    words.append(SHA256_U256X8_INPUT_BITS);
    words
}

fn build_padded_words_x9(inputs: U256x9) -> Array<u32> {
    let mut words = array![];
    append_u256_be_words(ref words, inputs.v0);
    append_u256_be_words(ref words, inputs.v1);
    append_u256_be_words(ref words, inputs.v2);
    append_u256_be_words(ref words, inputs.v3);
    append_u256_be_words(ref words, inputs.v4);
    append_u256_be_words(ref words, inputs.v5);
    append_u256_be_words(ref words, inputs.v6);
    append_u256_be_words(ref words, inputs.v7);
    append_u256_be_words(ref words, inputs.v8);
    words.append(0x80000000);

    let mut padding_zeros: usize = 0;
    while padding_zeros < 6 {
        words.append(0);
        padding_zeros += 1;
    }

    words.append(SHA256_U256X9_INPUT_BITS);
    words
}

fn digest_to_u256(state: Sha256State) -> u256 {
    let mut value: u256 = 0;
    value = append_digest_word(value, state.h0);
    value = append_digest_word(value, state.h1);
    value = append_digest_word(value, state.h2);
    value = append_digest_word(value, state.h3);
    value = append_digest_word(value, state.h4);
    value = append_digest_word(value, state.h5);
    value = append_digest_word(value, state.h6);
    append_digest_word(value, state.h7)
}

fn append_digest_word(value: u256, word: u32) -> u256 {
    value * U128_TWO_POW_32.into() + word.into()
}

fn u256_ge(left: u256, right: u256) -> bool {
    if left.high > right.high {
        true
    } else if left.high < right.high {
        false
    } else {
        left.low >= right.low
    }
}

fn reduce_bn254_once(value: u256) -> u256 {
    if u256_ge(value, BN254_SCALAR_FIELD) {
        value - BN254_SCALAR_FIELD
    } else {
        value
    }
}

fn reduce_bn254(value: u256) -> u256 {
    let value = reduce_bn254_once(value);
    let value = reduce_bn254_once(value);
    let value = reduce_bn254_once(value);
    let value = reduce_bn254_once(value);
    let value = reduce_bn254_once(value);
    reduce_bn254_once(value)
}

pub fn compute_sha256_u256x4_mod_bn254(inputs: U256x4) -> u256 {
    let words = build_padded_words_x4(inputs);
    let state = compress_block(initial_state(), @words, 0);
    let state = compress_block(state, @words, 16);
    let state = compress_block(state, @words, 32);
    reduce_bn254(digest_to_u256(state))
}

pub fn compute_sha256_u256x7_mod_bn254(inputs: U256x7) -> u256 {
    let words = build_padded_words_x7(inputs);
    let state = compress_block(initial_state(), @words, 0);
    let state = compress_block(state, @words, 16);
    let state = compress_block(state, @words, 32);
    let state = compress_block(state, @words, 48);
    reduce_bn254(digest_to_u256(state))
}

pub fn compute_sha256_u256x8_mod_bn254(inputs: U256x8) -> u256 {
    let words = build_padded_words_x8(inputs);
    let state = compress_block(initial_state(), @words, 0);
    let state = compress_block(state, @words, 16);
    let state = compress_block(state, @words, 32);
    let state = compress_block(state, @words, 48);
    let state = compress_block(state, @words, 64);
    reduce_bn254(digest_to_u256(state))
}

pub fn compute_sha256_u256x9_mod_bn254(inputs: U256x9) -> u256 {
    let words = build_padded_words_x9(inputs);
    let state = compress_block(initial_state(), @words, 0);
    let state = compress_block(state, @words, 16);
    let state = compress_block(state, @words, 32);
    let state = compress_block(state, @words, 48);
    let state = compress_block(state, @words, 64);
    reduce_bn254(digest_to_u256(state))
}

#[cfg(test)]
mod tests {
    use crate::types::{U256x4, U256x7, U256x8, U256x9};
    use super::{
        compute_sha256_u256x4_mod_bn254, compute_sha256_u256x7_mod_bn254,
        compute_sha256_u256x8_mod_bn254, compute_sha256_u256x9_mod_bn254,
    };

    #[test]
    fn sha256_u256x4_mod_bn254_matches_js_vector() {
        let actual = compute_sha256_u256x4_mod_bn254(U256x4 { v0: 5, v1: 6, v2: 7, v3: 8 });
        assert(
            actual == 0x2561da7b644157407533e1abe2704eb69c60920d2ea96789914b3a88acb780a0,
            'SHA256_MOD_VECTOR_MISMATCH',
        );
    }

    #[test]
    fn sha256_u256x7_mod_bn254_matches_js_vector() {
        let actual = compute_sha256_u256x7_mod_bn254(
            U256x7 { v0: 5, v1: 6, v2: 7, v3: 8, v4: 9, v5: 10, v6: 11 },
        );
        assert(
            actual == 0x1795a324a7038b468cc1f7fc3bf8e41187de0adeeffa83f63cfe9e79ba96490e,
            'SHA256_X7_VECTOR_MISMATCH',
        );
    }

    #[test]
    fn sha256_u256x8_mod_bn254_matches_js_vector() {
        let actual = compute_sha256_u256x8_mod_bn254(
            U256x8 { v0: 5, v1: 6, v2: 7, v3: 8, v4: 9, v5: 10, v6: 11, v7: 12 },
        );
        assert(
            actual == 0x251acb98f9ae4edb51928cb69c74ca6a5348026e965b7e7f7bff49cda99d51c3,
            'SHA256_X8_VECTOR_MISMATCH',
        );
    }

    #[test]
    fn sha256_u256x9_mod_bn254_matches_js_vector() {
        let actual = compute_sha256_u256x9_mod_bn254(
            U256x9 { v0: 5, v1: 6, v2: 7, v3: 8, v4: 9, v5: 10, v6: 11, v7: 12, v8: 13 },
        );
        assert(
            actual == 0x0695885c48fd459864236258fa4b6476f28b81d71e8d84a3e6c5356526275b07,
            'SHA256_X9_VECTOR_MISMATCH',
        );
    }
}
