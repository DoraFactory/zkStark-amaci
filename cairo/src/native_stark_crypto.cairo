use core::ec::{EcPoint, EcPointTrait, EcStateTrait, stark_curve};
use core::hash::HashStateTrait;
use core::poseidon::PoseidonTrait;
use core::traits::{Into, TryInto};

pub const STARK_NATIVE_COMMAND_SIGNATURE_DOMAIN: felt252 = 0x414d4143495f535441524b5f434d445f534947;
pub const STARK_NATIVE_DEACTIVATE_SIGNATURE_DOMAIN: felt252 =
    0x414d4143495f535441524b5f44454143545f534947;
pub const STARK_NATIVE_COMMAND_STREAM_DOMAIN: felt252 =
    0x414d4143495f535441524b5f434d445f53545245414d;
pub const STARK_NATIVE_DEACTIVATE_STREAM_DOMAIN: felt252 =
    0x414d4143495f535441524b5f44454143545f53545245414d;

fn felt_from_u256_checked(value: u256) -> felt252 {
    let value_felt: felt252 = value.try_into().unwrap();
    value_felt
}

fn u256_from_felt(value: felt252) -> u256 {
    value.into()
}

fn point_from_u256(x: u256, y: u256) -> NonZero<EcPoint> {
    EcPointTrait::new_nz(felt_from_u256_checked(x), felt_from_u256_checked(y)).unwrap()
}

fn point_to_coords(point: NonZero<EcPoint>) -> (felt252, felt252) {
    point.coordinates()
}

fn generator_point() -> NonZero<EcPoint> {
    EcPointTrait::new_nz(stark_curve::GEN_X, stark_curve::GEN_Y).unwrap()
}

pub fn stark_private_key_felt(private_key: u256) -> felt252 {
    felt_from_u256_checked(private_key)
}

pub fn stark_point_hash_inputs(x: u256, y: u256) -> (felt252, felt252) {
    (felt_from_u256_checked(x), felt_from_u256_checked(y))
}

pub fn stark_generator_mul(private_key: u256) -> (felt252, felt252) {
    let mut state = EcStateTrait::init();
    state.add_mul(stark_private_key_felt(private_key), generator_point());
    point_to_coords(state.finalize_nz().unwrap())
}

pub fn stark_scalar_mul(base_x: u256, base_y: u256, scalar: u256) -> (felt252, felt252) {
    let base = point_from_u256(base_x, base_y);
    let mut state = EcStateTrait::init();
    state.add_mul(stark_private_key_felt(scalar), base);
    point_to_coords(state.finalize_nz().unwrap())
}

pub fn assert_stark_point_valid(x: u256, y: u256) {
    let _point = point_from_u256(x, y);
}

pub fn stark_point_add(
    left_x: u256, left_y: u256, right_x: u256, right_y: u256,
) -> (felt252, felt252) {
    let left: EcPoint = point_from_u256(left_x, left_y).into();
    let right: EcPoint = point_from_u256(right_x, right_y).into();
    let result = left + right;
    let result_nz: NonZero<EcPoint> = result.try_into().unwrap();
    point_to_coords(result_nz)
}

pub fn stark_elgamal_rerandomize(
    coord_pub_key_x: u256,
    coord_pub_key_y: u256,
    c1_x: u256,
    c1_y: u256,
    c2_x: u256,
    c2_y: u256,
    random_val: u256,
) -> (felt252, felt252, felt252, felt252) {
    let (random_base_x, random_base_y) = stark_generator_mul(random_val);
    let (random_coord_x, random_coord_y) = stark_scalar_mul(
        coord_pub_key_x, coord_pub_key_y, random_val,
    );
    let (d1_x, d1_y) = stark_point_add(
        c1_x, c1_y, u256_from_felt(random_base_x), u256_from_felt(random_base_y),
    );
    let (d2_x, d2_y) = stark_point_add(
        c2_x, c2_y, u256_from_felt(random_coord_x), u256_from_felt(random_coord_y),
    );
    (d1_x, d1_y, d2_x, d2_y)
}

pub fn assert_stark_point_equals(
    actual_x: felt252,
    actual_y: felt252,
    expected_x: u256,
    expected_y: u256,
    err_x: felt252,
    err_y: felt252,
) {
    assert(actual_x == felt_from_u256_checked(expected_x), err_x);
    assert(actual_y == felt_from_u256_checked(expected_y), err_y);
}

pub fn stark_elgamal_decrypt_point_is_odd(
    private_key: u256,
    c1_x: u256,
    c1_y: u256,
    c2_x: u256,
    c2_y: u256,
    decrypted_x: u256,
    decrypted_y: u256,
) -> felt252 {
    let (shared_x, shared_y) = stark_scalar_mul(c1_x, c1_y, private_key);
    let (recomposed_x, recomposed_y) = stark_point_add(
        decrypted_x, decrypted_y, u256_from_felt(shared_x), u256_from_felt(shared_y),
    );
    assert(recomposed_x == felt_from_u256_checked(c2_x), 'N_DEC_C2_X');
    assert(recomposed_y == felt_from_u256_checked(c2_y), 'N_DEC_C2_Y');
    if decrypted_x.low & 1 == 0 {
        0
    } else {
        1
    }
}

pub fn stark_command_signature_hash(
    domain: felt252, packed_0: u256, packed_1: u256, packed_2: u256, cmd_salt: u256,
) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(domain);
    state = state.update(felt_from_u256_checked(packed_0));
    state = state.update(felt_from_u256_checked(packed_1));
    state = state.update(felt_from_u256_checked(packed_2));
    state = state.update(felt_from_u256_checked(cmd_salt));
    state.finalize()
}

fn stark_poseidon_stream_value(
    domain: felt252, shared_key_x: u256, shared_key_y: u256, nonce: u256, index: felt252,
) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(domain);
    state = state.update(felt_from_u256_checked(shared_key_x));
    state = state.update(felt_from_u256_checked(shared_key_y));
    state = state.update(felt_from_u256_checked(nonce));
    state = state.update(index);
    state.finalize()
}

fn assert_decrypted_value(
    ciphertext: u256, stream: felt252, expected_plaintext: u256, err: felt252,
) {
    assert(
        felt_from_u256_checked(ciphertext) - stream == felt_from_u256_checked(expected_plaintext),
        err,
    );
}

pub fn assert_stark_poseidon_decrypt7(
    domain: felt252,
    shared_key_x: u256,
    shared_key_y: u256,
    nonce: u256,
    msg_0: u256,
    msg_1: u256,
    msg_2: u256,
    msg_3: u256,
    msg_4: u256,
    msg_5: u256,
    msg_6: u256,
    msg_7: u256,
    msg_8: u256,
    msg_9: u256,
    plain_0: u256,
    plain_1: u256,
    plain_2: u256,
    plain_3: u256,
    plain_4: u256,
    plain_5: u256,
    plain_6: u256,
) {
    assert_decrypted_value(
        msg_0,
        stark_poseidon_stream_value(domain, shared_key_x, shared_key_y, nonce, 0),
        plain_0,
        'N_CMD_DEC_0',
    );
    assert_decrypted_value(
        msg_1,
        stark_poseidon_stream_value(domain, shared_key_x, shared_key_y, nonce, 1),
        plain_1,
        'N_CMD_DEC_1',
    );
    assert_decrypted_value(
        msg_2,
        stark_poseidon_stream_value(domain, shared_key_x, shared_key_y, nonce, 2),
        plain_2,
        'N_CMD_DEC_2',
    );
    assert_decrypted_value(
        msg_3,
        stark_poseidon_stream_value(domain, shared_key_x, shared_key_y, nonce, 3),
        plain_3,
        'N_CMD_DEC_3',
    );
    assert_decrypted_value(
        msg_4,
        stark_poseidon_stream_value(domain, shared_key_x, shared_key_y, nonce, 4),
        plain_4,
        'N_CMD_DEC_4',
    );
    assert_decrypted_value(
        msg_5,
        stark_poseidon_stream_value(domain, shared_key_x, shared_key_y, nonce, 5),
        plain_5,
        'N_CMD_DEC_5',
    );
    assert_decrypted_value(
        msg_6,
        stark_poseidon_stream_value(domain, shared_key_x, shared_key_y, nonce, 6),
        plain_6,
        'N_CMD_DEC_6',
    );
    assert(
        felt_from_u256_checked(msg_7)
            - stark_poseidon_stream_value(domain, shared_key_x, shared_key_y, nonce, 7) == 0,
        'N_CMD_PAD_7',
    );
    assert(
        felt_from_u256_checked(msg_8)
            - stark_poseidon_stream_value(domain, shared_key_x, shared_key_y, nonce, 8) == 0,
        'N_CMD_PAD_8',
    );
    assert(felt_from_u256_checked(msg_9) == 0, 'N_CMD_PAD_9');
}

pub fn stark_verify_command_signature(
    domain: felt252,
    pub_key_x: u256,
    pub_key_y: u256,
    signature_r_x: u256,
    signature_r_y: u256,
    signature_s: u256,
    packed_0: u256,
    packed_1: u256,
    packed_2: u256,
    cmd_salt: u256,
) -> felt252 {
    assert_stark_point_valid(pub_key_x, pub_key_y);
    assert_stark_point_valid(signature_r_x, signature_r_y);
    let message_hash = stark_command_signature_hash(domain, packed_0, packed_1, packed_2, cmd_salt);
    let (left_x, left_y) = stark_scalar_mul(signature_r_x, signature_r_y, signature_s);
    let (message_x, message_y) = stark_generator_mul(u256_from_felt(message_hash));
    let (pub_r_x, pub_r_y) = stark_scalar_mul(pub_key_x, pub_key_y, signature_r_x);
    let (right_x, right_y) = stark_point_add(
        u256_from_felt(message_x),
        u256_from_felt(message_y),
        u256_from_felt(pub_r_x),
        u256_from_felt(pub_r_y),
    );
    if left_x == right_x && left_y == right_y {
        1
    } else {
        0
    }
}
