#[derive(Copy, Drop, Serde)]
pub struct U256x4 {
    pub v0: u256,
    pub v1: u256,
    pub v2: u256,
    pub v3: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct U256x5 {
    pub v0: u256,
    pub v1: u256,
    pub v2: u256,
    pub v3: u256,
    pub v4: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct U256x10 {
    pub v0: u256,
    pub v1: u256,
    pub v2: u256,
    pub v3: u256,
    pub v4: u256,
    pub v5: u256,
    pub v6: u256,
    pub v7: u256,
    pub v8: u256,
    pub v9: u256,
}

pub fn zero_u256() -> u256 {
    0
}

pub fn is_zero(value: u256) -> bool {
    value.low == 0 && value.high == 0
}

pub fn assert_u256_eq(left: u256, right: u256) {
    assert(left.low == right.low, 'U256_LOW_MISMATCH');
    assert(left.high == right.high, 'U256_HIGH_MISMATCH');
}

pub fn assert_vector5_eq(left: U256x5, right: U256x5) {
    assert_u256_eq(left.v0, right.v0);
    assert_u256_eq(left.v1, right.v1);
    assert_u256_eq(left.v2, right.v2);
    assert_u256_eq(left.v3, right.v3);
    assert_u256_eq(left.v4, right.v4);
}

pub fn u256x10_first5(value: U256x10) -> U256x5 {
    U256x5 { v0: value.v0, v1: value.v1, v2: value.v2, v3: value.v3, v4: value.v4 }
}

pub fn u256x10_second5(value: U256x10) -> U256x5 {
    U256x5 { v0: value.v5, v1: value.v6, v2: value.v7, v3: value.v8, v4: value.v9 }
}
